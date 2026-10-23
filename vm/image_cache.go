package vm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type preparedRootfsImage struct {
	Path  string
	Lease *rootfsImageLease
}

type rootfsImageLease struct {
	path string
	file *os.File
	once sync.Once
	err  error
}

func (lease *rootfsImageLease) Release() error {
	if lease == nil {
		return nil
	}
	lease.once.Do(func() {
		unlockErr := unlockImageCacheLease(lease.file)
		closeErr := lease.file.Close()
		removeErr := os.Remove(lease.path)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		switch {
		case unlockErr != nil:
			lease.err = unlockErr
		case closeErr != nil:
			lease.err = closeErr
		case removeErr != nil:
			lease.err = removeErr
		}
	})
	return lease.err
}

func ensureRootfsImageCacheDirectories(cacheDir string) error {
	if err := ensurePrivateDirectory(cacheDir); err != nil {
		return err
	}
	leasesDir := filepath.Join(cacheDir, "leases")
	if err := os.MkdirAll(leasesDir, 0o700); err != nil {
		return fmt.Errorf("create rootfs image cache leases directory: %w", err)
	}
	info, err := os.Lstat(leasesDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			err = fmt.Errorf("not a real directory")
		}
		return fmt.Errorf("inspect rootfs image cache leases directory: %w", err)
	}
	if err := os.Chmod(leasesDir, 0o700); err != nil {
		return fmt.Errorf("secure rootfs image cache leases directory: %w", err)
	}
	cacheLock, err := lockImageCache(cacheDir)
	if err != nil {
		return fmt.Errorf("lock rootfs image cache during staging recovery: %w", err)
	}
	cleanupErr := cleanupStaleRootfsBuildsLocked(cacheDir)
	closeErr := cacheLock.Close()
	if cleanupErr != nil {
		return cleanupErr
	}
	if closeErr != nil {
		return fmt.Errorf("unlock rootfs image cache after staging recovery: %w", closeErr)
	}
	return nil
}

func acquireCachedRootfsImage(cacheDir, imagePath string, maxBytes int64) (*rootfsImageLease, bool, error) {
	lock, err := lockImageCache(cacheDir)
	if err != nil {
		return nil, false, fmt.Errorf("lock rootfs image cache: %w", err)
	}
	defer lock.Close()
	info, err := os.Lstat(imagePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect cached rootfs image %q: %w", imagePath, err)
	}
	if err := validateCachedRootfsImage(imagePath, info); err != nil {
		return nil, false, err
	}
	if err := enforceRootfsImageCacheQuotaLocked(cacheDir, imagePath, 0, maxBytes); err != nil {
		return nil, false, err
	}
	lease, err := createRootfsImageLease(cacheDir, imagePath)
	if err != nil {
		return nil, false, err
	}
	return lease, true, nil
}

func validateCachedRootfsImage(imagePath string, info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 {
		return fmt.Errorf("cached rootfs image %q is not a non-empty regular file", imagePath)
	}
	if info.Mode().Perm() != 0o400 {
		return fmt.Errorf("cached rootfs image %q has mode %#o; expected immutable mode 0400", imagePath, info.Mode().Perm())
	}
	return nil
}

func createRootfsImageLease(cacheDir, imagePath string) (*rootfsImageLease, error) {
	identifier, err := newSandboxID()
	if err != nil {
		return nil, fmt.Errorf("create rootfs image cache lease ID: %w", err)
	}
	leasesDir := filepath.Join(cacheDir, "leases")
	leasePath := filepath.Join(leasesDir, filepath.Base(imagePath)+"--"+identifier+".lease")
	file, err := os.OpenFile(leasePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create rootfs image cache lease: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(leasePath)
		return nil, fmt.Errorf("secure rootfs image cache lease: %w", err)
	}
	locked, err := tryLockImageCacheLease(file)
	if err != nil || !locked {
		_ = file.Close()
		_ = os.Remove(leasePath)
		if err == nil {
			err = fmt.Errorf("new rootfs image cache lease is already locked")
		}
		return nil, fmt.Errorf("lock rootfs image cache lease: %w", err)
	}
	if _, err := file.WriteString(imagePath); err != nil {
		_ = unlockImageCacheLease(file)
		_ = file.Close()
		_ = os.Remove(leasePath)
		return nil, fmt.Errorf("write rootfs image cache lease: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = unlockImageCacheLease(file)
		_ = file.Close()
		_ = os.Remove(leasePath)
		return nil, fmt.Errorf("sync rootfs image cache lease: %w", err)
	}
	return &rootfsImageLease{path: leasePath, file: file}, nil
}

func publishRootfsImage(cacheDir, stagedImage, imagePath string, imageSize, maxBytes int64) (*rootfsImageLease, error) {
	lock, err := lockImageCache(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("lock rootfs image cache: %w", err)
	}
	defer lock.Close()
	if info, err := os.Lstat(imagePath); err == nil {
		if err := validateCachedRootfsImage(imagePath, info); err != nil {
			return nil, err
		}
		if err := enforceRootfsImageCacheQuotaLocked(cacheDir, imagePath, 0, maxBytes); err != nil {
			return nil, err
		}
		lease, err := createRootfsImageLease(cacheDir, imagePath)
		if err != nil {
			return nil, err
		}
		return lease, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect cached rootfs image %q: %w", imagePath, err)
	}
	if err := enforceRootfsImageCacheQuotaLocked(cacheDir, "", imageSize, maxBytes); err != nil {
		return nil, err
	}
	if err := os.Rename(stagedImage, imagePath); err != nil {
		return nil, fmt.Errorf("publish rootfs image %q: %w", imagePath, err)
	}
	if err := os.Chmod(imagePath, 0o400); err != nil {
		return nil, fmt.Errorf("make rootfs base image immutable: %w", err)
	}
	directory, err := os.Open(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("open rootfs image cache for sync: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("sync rootfs image cache: %w", err)
	}
	if err := directory.Close(); err != nil {
		return nil, fmt.Errorf("close rootfs image cache: %w", err)
	}
	lease, err := createRootfsImageLease(cacheDir, imagePath)
	if err != nil {
		return nil, err
	}
	return lease, nil
}

func enforceRootfsImageCacheQuotaLocked(cacheDir, protectedImage string, incomingBytes, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = defaultRootfsImageCacheMaxBytes
	}
	if incomingBytes < 0 || incomingBytes > maxBytes {
		return fmt.Errorf("rootfs image cache quota is %d bytes; image requires %d bytes", maxBytes, incomingBytes)
	}
	if err := cleanupStaleRootfsBuildsLocked(cacheDir); err != nil {
		return err
	}
	store, err := openStateStore(filepath.Dir(cacheDir))
	if err != nil {
		return fmt.Errorf("open state store for rootfs image cache GC: %w", err)
	}
	states, err := store.list()
	if err != nil {
		return fmt.Errorf("read sandbox references for rootfs image cache GC: %w", err)
	}
	referenced := make(map[string]struct{}, len(states)*2)
	for _, state := range states {
		for _, imagePath := range []string{state.Rootfs, state.WorkloadDisk} {
			if imagePath == "" {
				continue
			}
			absolute, err := filepath.Abs(imagePath)
			if err != nil {
				return fmt.Errorf("resolve sandbox image reference: %w", err)
			}
			referenced[filepath.Clean(absolute)] = struct{}{}
		}
	}
	activeLeases, err := activeRootfsImageLeases(cacheDir)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return fmt.Errorf("list rootfs image cache: %w", err)
	}
	type candidate struct {
		path    string
		name    string
		size    int64
		modTime time.Time
	}
	var candidates []candidate
	var total int64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".ext4") {
			continue
		}
		path := filepath.Join(cacheDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect rootfs image cache entry %q: %w", path, err)
		}
		if err := validateCachedRootfsImage(path, info); err != nil {
			return err
		}
		if info.Size() > int64(^uint64(0)>>1)-total {
			return fmt.Errorf("rootfs image cache size overflows signed 64-bit range")
		}
		total += info.Size()
		_, isReferenced := referenced[filepath.Clean(path)]
		_, isLeased := activeLeases[entry.Name()]
		if !isReferenced && !isLeased && path != protectedImage {
			candidates = append(candidates, candidate{path: path, name: entry.Name(), size: info.Size(), modTime: info.ModTime()})
		}
	}
	if total <= maxBytes-incomingBytes {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modTime.Equal(candidates[j].modTime) {
			return candidates[i].name < candidates[j].name
		}
		return candidates[i].modTime.Before(candidates[j].modTime)
	})
	for _, candidate := range candidates {
		if total <= maxBytes-incomingBytes {
			break
		}
		if err := os.Remove(candidate.path); err != nil {
			return fmt.Errorf("evict unreferenced rootfs image %q: %w", candidate.path, err)
		}
		total -= candidate.size
	}
	if err := cleanupStaleRootfsPreparationLocksLocked(cacheDir); err != nil {
		return err
	}
	if total > maxBytes-incomingBytes {
		return fmt.Errorf("rootfs image cache quota of %d bytes is exhausted by referenced or leased images (%d bytes in use)", maxBytes, total+incomingBytes)
	}
	return nil
}

func cleanupStaleRootfsBuildsLocked(cacheDir string) error {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return fmt.Errorf("list rootfs build staging directories: %w", err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".rootfs-build-") {
			continue
		}
		stagingDir := filepath.Join(cacheDir, entry.Name())
		info, err := os.Lstat(stagingDir)
		if err != nil {
			return fmt.Errorf("inspect rootfs build staging directory %q: %w", stagingDir, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("rootfs build staging path %q is not a real directory", stagingDir)
		}
		lockPath := filepath.Join(stagingDir, ".build.lock")
		lockInfo, err := os.Lstat(lockPath)
		if errors.Is(err, os.ErrNotExist) {
			if time.Since(info.ModTime()) < 5*time.Minute {
				continue
			}
			if err := os.RemoveAll(stagingDir); err != nil {
				return fmt.Errorf("remove abandoned rootfs build staging directory %q: %w", stagingDir, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect rootfs build lock %q: %w", lockPath, err)
		}
		if !lockInfo.Mode().IsRegular() || lockInfo.Mode()&os.ModeSymlink != 0 || lockInfo.Mode().Perm() != 0o600 {
			return fmt.Errorf("rootfs build lock %q is not a private regular file", lockPath)
		}
		file, err := os.OpenFile(lockPath, os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("open rootfs build lock %q: %w", lockPath, err)
		}
		lockAcquired, lockErr := tryLockImageCacheLease(file)
		if lockErr != nil {
			_ = file.Close()
			return fmt.Errorf("check rootfs build lock %q: %w", lockPath, lockErr)
		}
		if !lockAcquired {
			_ = file.Close()
			continue
		}
		_ = unlockImageCacheLease(file)
		_ = file.Close()
		if err := os.RemoveAll(stagingDir); err != nil {
			return fmt.Errorf("remove abandoned rootfs build staging directory %q: %w", stagingDir, err)
		}
	}
	return nil
}

func activeRootfsImageLeases(cacheDir string) (map[string]struct{}, error) {
	leasesDir := filepath.Join(cacheDir, "leases")
	entries, err := os.ReadDir(leasesDir)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]struct{}{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list rootfs image cache leases: %w", err)
	}
	active := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".lease") {
			return nil, fmt.Errorf("unexpected entry in rootfs image cache leases: %q", entry.Name())
		}
		leasePath := filepath.Join(leasesDir, entry.Name())
		info, err := os.Lstat(leasePath)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			if err == nil {
				err = fmt.Errorf("lease is not a private regular file")
			}
			return nil, fmt.Errorf("inspect rootfs image cache lease %q: %w", leasePath, err)
		}
		file, err := os.OpenFile(leasePath, os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open rootfs image cache lease %q: %w", leasePath, err)
		}
		lockAcquired, lockErr := tryLockImageCacheLease(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("check rootfs image cache lease %q: %w", leasePath, lockErr)
		}
		if !lockAcquired {
			base := strings.TrimSuffix(entry.Name(), ".lease")
			imageName, _, ok := strings.Cut(base, "--")
			if !ok || !strings.HasSuffix(imageName, ".ext4") {
				_ = file.Close()
				return nil, fmt.Errorf("malformed rootfs image cache lease name %q", entry.Name())
			}
			active[imageName] = struct{}{}
			_ = file.Close()
			continue
		}
		_ = unlockImageCacheLease(file)
		_ = file.Close()
		if err := os.Remove(leasePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("remove stale rootfs image cache lease %q: %w", leasePath, err)
		}
	}
	return active, nil
}
