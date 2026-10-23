//go:build darwin || linux

package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootfsImageCacheQuotaEvictsOnlyUnreferencedUnleasedImages(t *testing.T) {
	stateDir := t.TempDir()
	cacheDir := filepath.Join(stateDir, "images")
	if err := ensureRootfsImageCacheDirectories(cacheDir); err != nil {
		t.Fatal(err)
	}
	referenced := writeCacheImage(t, cacheDir, "referenced", 4)
	workloadDisk := writeCacheImage(t, cacheDir, "workload", 4)
	leased := writeCacheImage(t, cacheDir, "leased", 4)
	evictable := writeCacheImage(t, cacheDir, "evictable", 4)
	store, err := openStateStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.create("referenced", "image", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	state.Rootfs = referenced
	state.WorkloadDisk = workloadDisk
	state.WorkloadSourceType = "tar"
	state.WorkloadSourceRef = "uploaded-tar"
	state.WorkloadSourceDigest = "sha256:" + strings.Repeat("a", 64)
	state.WorkloadPlatform = "linux/amd64"
	if err := store.save(state); err != nil {
		t.Fatal(err)
	}
	lock, err := lockImageCache(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := createRootfsImageLease(cacheDir, leased)
	if err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	err = enforceRootfsImageCacheQuotaLocked(cacheDir, "", 0, 12)
	lockErr := lock.Close()
	if err != nil || lockErr != nil {
		t.Fatalf("enforce cache quota = %v; close lock = %v", err, lockErr)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{referenced, workloadDisk, leased} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("protected image %q was removed: %v", path, err)
		}
	}
	if _, err := os.Stat(evictable); !os.IsNotExist(err) {
		t.Fatalf("unreferenced image still exists after quota GC: err=%v", err)
	}
}

func TestRootfsImageCacheQuotaFailsWhenAllSpaceIsReferenced(t *testing.T) {
	stateDir := t.TempDir()
	cacheDir := filepath.Join(stateDir, "images")
	if err := ensureRootfsImageCacheDirectories(cacheDir); err != nil {
		t.Fatal(err)
	}
	image := writeCacheImage(t, cacheDir, "in-use", 8)
	store, err := openStateStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.create("in-use", "image", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	state.Rootfs = image
	if err := store.save(state); err != nil {
		t.Fatal(err)
	}
	lock, err := lockImageCache(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	err = enforceRootfsImageCacheQuotaLocked(cacheDir, "", 1, 8)
	_ = lock.Close()
	if err == nil || !strings.Contains(err.Error(), "quota of 8 bytes is exhausted") {
		t.Fatalf("quota exhaustion error = %v", err)
	}
	if _, err := os.Stat(image); err != nil {
		t.Fatalf("referenced image was removed after failed quota check: %v", err)
	}
}

func TestRootfsImageCacheGCRemovesOnlyAbandonedBuildDirectories(t *testing.T) {
	stateDir := t.TempDir()
	cacheDir := filepath.Join(stateDir, "images")
	if err := ensureRootfsImageCacheDirectories(cacheDir); err != nil {
		t.Fatal(err)
	}
	activeDir := filepath.Join(cacheDir, ".rootfs-build-active")
	staleDir := filepath.Join(cacheDir, ".rootfs-build-stale")
	for _, path := range []string{activeDir, staleDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	activeLock, err := os.OpenFile(filepath.Join(activeDir, ".build.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := tryLockImageCacheLease(activeLock)
	if err != nil || !locked {
		t.Fatalf("lock active build = (%t, %v)", locked, err)
	}
	staleLock, err := os.OpenFile(filepath.Join(staleDir, ".build.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = staleLock.Close()
	lock, err := lockImageCache(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	err = cleanupStaleRootfsBuildsLocked(cacheDir)
	_ = lock.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(activeDir); err != nil {
		t.Fatalf("active build directory was removed: %v", err)
	}
	if _, err := os.Stat(staleDir); !os.IsNotExist(err) {
		t.Fatalf("abandoned build directory remains: %v", err)
	}
	_ = unlockImageCacheLease(activeLock)
	_ = activeLock.Close()
}

func TestEnsureRootfsImageCacheDirectoriesReclaimsAbandonedBuildsOnPreparationStartup(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "images")
	staleDir := filepath.Join(cacheDir, ".rootfs-build-crashed")
	activeDir := filepath.Join(cacheDir, ".rootfs-build-active")
	recentDir := filepath.Join(cacheDir, ".rootfs-build-recent")
	for _, dir := range []string{staleDir, activeDir, recentDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(staleDir, time.Now().Add(-10*time.Minute), time.Now().Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(activeDir, ".build.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	activeLock, err := os.OpenFile(filepath.Join(activeDir, ".build.lock"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := tryLockImageCacheLease(activeLock)
	if err != nil || !locked {
		t.Fatalf("lock active build = (%t, %v)", locked, err)
	}
	defer func() {
		_ = unlockImageCacheLease(activeLock)
		_ = activeLock.Close()
	}()

	if err := ensureRootfsImageCacheDirectories(cacheDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staleDir); !os.IsNotExist(err) {
		t.Fatalf("abandoned build directory remains after cache initialization: %v", err)
	}
	for _, dir := range []string{activeDir, recentDir} {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("active/recent build directory %q was removed: %v", dir, err)
		}
	}
}

func TestRootfsPreparationLockGCRemovesOnlyStaleUnreferencedLocks(t *testing.T) {
	stateDir := t.TempDir()
	cacheDir := filepath.Join(stateDir, "images")
	if err := ensureRootfsImageCacheDirectories(cacheDir); err != nil {
		t.Fatal(err)
	}
	staleDigest := strings.Repeat("a", 64)
	activeDigest := strings.Repeat("b", 64)
	imageDigest := strings.Repeat("c", 64)
	stalePath := filepath.Join(cacheDir, ".rootfs-preparation-"+staleDigest+".lock")
	if err := os.WriteFile(stalePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	activeRelease, err := lockRootfsImagePreparation(t.Context(), cacheDir, activeDigest)
	if err != nil {
		t.Fatal(err)
	}
	defer activeRelease()
	imagePath := filepath.Join(cacheDir, imageDigest+".ext4")
	if err := os.WriteFile(imagePath, []byte("immutable"), 0o400); err != nil {
		t.Fatal(err)
	}
	imageLockPath := filepath.Join(cacheDir, ".rootfs-preparation-"+imageDigest+".lock")
	if err := os.WriteFile(imageLockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cacheLock, err := lockImageCache(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	err = cleanupStaleRootfsPreparationLocksLocked(cacheDir)
	closeErr := cacheLock.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("cleanup preparation locks = %v; release cache lock = %v", err, closeErr)
	}
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("stale lock was not removed: %v", err)
	}
	for _, path := range []string{
		filepath.Join(cacheDir, ".rootfs-preparation-"+activeDigest+".lock"), imageLockPath,
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("active or referenced lock %q was removed: %v", path, err)
		}
	}
}

func writeCacheImage(t *testing.T, cacheDir, name string, size int) string {
	t.Helper()
	path := filepath.Join(cacheDir, name+".ext4")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}
