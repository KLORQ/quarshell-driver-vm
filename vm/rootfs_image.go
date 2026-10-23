package vm

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/moby/go-archive"
)

const (
	rootfsImageMinBytes        = uint64(512 << 20)
	rootfsImageMinHeadroom     = uint64(256 << 20)
	rootfsExpandedMaxBytes     = int64(32 << 30)
	rootfsImageSizeGranularity = uint64(1 << 20)
	rootfsImageFormatVersion   = "quarshell-rootfs-ext4-v3"
)

// prepareRootfsImage unpacks a staged archive into a private temporary tree,
// formats it as ext4, then atomically publishes it under a content-addressed
// name. formatterPath is injectable for unit tests; an empty value resolves
// mke2fs or mkfs.ext4 from PATH.
func prepareRootfsImage(ctx context.Context, archivePath, cacheDir, formatterPath string, maxArchiveBytes int64) (string, error) {
	return prepareRootfsImageWithGuest(ctx, archivePath, cacheDir, formatterPath, maxArchiveBytes, "")
}

func prepareRootfsImageWithGuest(ctx context.Context, archivePath, cacheDir, formatterPath string, maxArchiveBytes int64, guestAgentPath string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("open rootfs archive %q: %w", archivePath, err)
	}
	defer archiveFile.Close()
	return prepareRootfsImageFileWithGuest(ctx, archiveFile, archivePath, cacheDir, formatterPath, maxArchiveBytes, guestAgentPath)
}

// prepareRootfsImageFileWithGuest consumes the already-open archive descriptor
// supplied by rootfs staging validation. It deliberately does not reopen the
// path, so an attacker cannot replace the validated archive between checks.
func prepareRootfsImageFileWithGuest(ctx context.Context, archiveFile *os.File, archivePath, cacheDir, formatterPath string, maxArchiveBytes int64, guestAgentPath string) (string, error) {
	prepared, err := prepareRootfsImageFileWithGuestLease(ctx, archiveFile, archivePath, cacheDir, formatterPath, maxArchiveBytes, guestAgentPath, defaultRootfsImageCacheMaxBytes)
	if err != nil {
		return "", err
	}
	if err := prepared.Lease.Release(); err != nil {
		return "", fmt.Errorf("release rootfs image cache lease: %w", err)
	}
	return prepared.Path, nil
}

func prepareRootfsImageFileWithGuestLease(ctx context.Context, archiveFile *os.File, archivePath, cacheDir, formatterPath string, maxArchiveBytes int64, guestAgentPath string, cacheMaxBytes int64) (preparedRootfsImage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if maxArchiveBytes <= 0 {
		maxArchiveBytes = defaultRootfsTarMaxBytes
	}
	if archiveFile == nil {
		return preparedRootfsImage{}, fmt.Errorf("rootfs archive file is required")
	}
	if err := ctx.Err(); err != nil {
		return preparedRootfsImage{}, err
	}
	archiveInfo, err := archiveFile.Stat()
	if err != nil || !archiveInfo.Mode().IsRegular() {
		if err == nil {
			err = fmt.Errorf("not a regular file")
		}
		return preparedRootfsImage{}, fmt.Errorf("inspect rootfs archive %q: %w", archivePath, err)
	}
	if archiveInfo.Size() > maxArchiveBytes {
		return preparedRootfsImage{}, fmt.Errorf("rootfs archive %q is %d bytes, exceeding the %d byte limit", archivePath, archiveInfo.Size(), maxArchiveBytes)
	}
	if _, err := archiveFile.Seek(0, io.SeekStart); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("rewind rootfs archive %q before hashing: %w", archivePath, err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, &contextReader{ctx: ctx, reader: archiveFile}); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("hash rootfs archive %q: %w", archivePath, err)
	}
	if _, err := archiveFile.Seek(0, io.SeekStart); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("rewind rootfs archive %q: %w", archivePath, err)
	}
	guestDigest, err := validateGuestAgent(guestAgentPath)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	return prepareRootfsImageFromSource(ctx, cacheDir, formatterPath, guestAgentPath, string(hasher.Sum(nil)), guestDigest, cacheMaxBytes, func(rootfsDir string) error {
		return unpackRootfsArchive(ctx, archiveFile, archivePath, rootfsDir)
	})
}

func prepareRootfsTarWorkloadDisk(ctx context.Context, archiveFile *os.File, archivePath, cacheDir, formatterPath, guestAgentPath string, maxArchiveBytes, cacheMaxBytes int64) (preparedRootfsImage, string, error) {
	if archiveFile == nil {
		return preparedRootfsImage{}, "", fmt.Errorf("workload rootfs archive is required")
	}
	info, err := archiveFile.Stat()
	if err != nil {
		return preparedRootfsImage{}, "", fmt.Errorf("inspect workload rootfs archive: %w", err)
	}
	if info.Size() <= 0 || info.Size() > maxArchiveBytes {
		return preparedRootfsImage{}, "", fmt.Errorf("workload rootfs archive size %d is outside allowed range", info.Size())
	}
	digest, err := digestOpenFile(archiveFile)
	if err != nil {
		return preparedRootfsImage{}, "", fmt.Errorf("identify workload rootfs archive: %w", err)
	}
	guestDigest, err := validateGuestAgent(guestAgentPath)
	if err != nil {
		return preparedRootfsImage{}, "", err
	}
	identity := "tar-workload-disk-v1:" + digest
	prepared, err := prepareRootfsImageFromSource(ctx, cacheDir, formatterPath, "", identity, guestDigest, cacheMaxBytes, func(rootfsDir string) error {
		workloadRoot := filepath.Join(rootfsDir, "image-rootfs")
		if err := os.MkdirAll(workloadRoot, 0o700); err != nil {
			return fmt.Errorf("create workload rootfs staging directory: %w", err)
		}
		if _, err := archiveFile.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind workload rootfs archive: %w", err)
		}
		if err := unpackRootfsArchive(ctx, archiveFile, archivePath, workloadRoot); err != nil {
			return err
		}
		return installGuestRuntime(workloadRoot, guestAgentPath)
	})
	if err != nil {
		return preparedRootfsImage{}, "", err
	}
	return prepared, digest, nil
}

func prepareRootfsImageFromSource(ctx context.Context, cacheDir, formatterPath, guestAgentPath, sourceIdentity string, guestDigest []byte, cacheMaxBytes int64, populate func(string) error, guestUMOCIPath ...string) (preparedRootfsImage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return preparedRootfsImage{}, err
	}
	keyInput := append([]byte(rootfsImageFormatVersion+"\x00"), sourceIdentity...)
	keyInput = append(keyInput, 0)
	keyInput = append(keyInput, guestDigest...)
	guestInitDigest := sha256.Sum256([]byte(guestInitScript))
	keyInput = append(keyInput, guestInitDigest[:]...)
	guestUMOCIDigest := []byte(nil)
	if len(guestUMOCIPath) > 0 && guestUMOCIPath[0] != "" {
		var validateErr error
		guestUMOCIDigest, validateErr = validateGuestAgent(guestUMOCIPath[0])
		if validateErr != nil {
			return preparedRootfsImage{}, fmt.Errorf("validate guest umoci: %w", validateErr)
		}
		keyInput = append(keyInput, guestUMOCIDigest...)
	}
	key := sha256.Sum256(keyInput)
	digest := hex.EncodeToString(key[:])
	if err := ensureRootfsImageCacheDirectories(cacheDir); err != nil {
		return preparedRootfsImage{}, err
	}
	imagePath := filepath.Join(cacheDir, digest+".ext4")
	unlockPreparation, err := lockRootfsImagePreparation(ctx, cacheDir, digest)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	defer unlockPreparation()
	if err := ctx.Err(); err != nil {
		return preparedRootfsImage{}, err
	}
	if lease, cached, err := acquireCachedRootfsImage(cacheDir, imagePath, cacheMaxBytes); err != nil {
		return preparedRootfsImage{}, err
	} else if cached {
		return preparedRootfsImage{Path: imagePath, Lease: lease}, nil
	}
	if formatterPath == "" {
		resolvedFormatter, err := resolveExt4Formatter()
		if err != nil {
			return preparedRootfsImage{}, err
		}
		formatterPath = resolvedFormatter
	}
	staging, err := os.MkdirTemp(cacheDir, ".rootfs-build-*")
	if err != nil {
		return preparedRootfsImage{}, fmt.Errorf("create rootfs build staging directory: %w", err)
	}
	buildLock, err := os.OpenFile(filepath.Join(staging, ".build.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		_ = os.RemoveAll(staging)
		return preparedRootfsImage{}, fmt.Errorf("create rootfs build lock: %w", err)
	}
	locked, err := tryLockImageCacheLease(buildLock)
	if err != nil || !locked {
		_ = buildLock.Close()
		_ = os.RemoveAll(staging)
		if err == nil {
			err = fmt.Errorf("new rootfs build lock is already held")
		}
		return preparedRootfsImage{}, fmt.Errorf("lock rootfs build staging directory: %w", err)
	}
	defer func() {
		_ = unlockImageCacheLease(buildLock)
		_ = buildLock.Close()
		_ = os.RemoveAll(staging)
	}()
	if err := os.Chmod(staging, 0o700); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("secure rootfs build staging directory: %w", err)
	}
	rootfsDir := filepath.Join(staging, "rootfs")
	if err := os.Mkdir(rootfsDir, 0o700); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("create unpacked rootfs directory: %w", err)
	}
	if populate == nil {
		return preparedRootfsImage{}, fmt.Errorf("rootfs source importer is required")
	}
	if err := populate(rootfsDir); err != nil {
		return preparedRootfsImage{}, err
	}
	if guestAgentPath != "" {
		var umociPath string
		if len(guestUMOCIPath) > 0 {
			umociPath = guestUMOCIPath[0]
		}
		if err := installGuestRuntime(rootfsDir, guestAgentPath, umociPath); err != nil {
			return preparedRootfsImage{}, err
		}
	}
	// The host staging directory starts private (0700), but that mode becomes
	// the root directory mode in the guest ext4 image. Sandboxed users must be
	// able to traverse the guest root after the overlay is mounted.
	if err := os.Chmod(rootfsDir, 0o755); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("set guest rootfs directory permissions: %w", err)
	}
	imageSize, err := rootfsImageSize(rootfsDir)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	stagingImage := filepath.Join(staging, "rootfs.ext4")
	image, err := os.OpenFile(stagingImage, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return preparedRootfsImage{}, fmt.Errorf("create staged rootfs image: %w", err)
	}
	if err := image.Truncate(int64(imageSize)); err != nil {
		_ = image.Close()
		return preparedRootfsImage{}, fmt.Errorf("size staged rootfs image: %w", err)
	}
	if err := image.Close(); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("close staged rootfs image: %w", err)
	}
	if err := formatExt4Image(ctx, formatterPath, rootfsDir, stagingImage); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("format ext4 rootfs: %w", err)
	}
	if err := os.Chmod(stagingImage, 0o400); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("make rootfs base image read-only: %w", err)
	}
	lease, err := publishRootfsImage(cacheDir, stagingImage, imagePath, int64(imageSize), cacheMaxBytes)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	return preparedRootfsImage{Path: imagePath, Lease: lease}, nil
}

// lockRootfsImagePreparation serializes builds for the same content identity
// across driver processes. Waiting is cancellable so a deleted sandbox does
// not leave an image preparation queued behind another caller.
func lockRootfsImagePreparation(ctx context.Context, cacheDir, digest string) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	path := filepath.Join(cacheDir, ".rootfs-preparation-"+digest+".lock")
	for {
		// Serialize opening the per-image lock with cache GC. The exclusive
		// per-image lock is acquired before releasing the cache lock, so GC
		// cannot unlink an inode while another process is about to lock it.
		cacheLock, err := lockImageCache(cacheDir)
		if err != nil {
			return nil, fmt.Errorf("lock rootfs image cache while acquiring preparation lock: %w", err)
		}
		if info, statErr := os.Lstat(path); statErr == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
				_ = cacheLock.Close()
				return nil, fmt.Errorf("rootfs preparation lock %q is not a private regular file", path)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			_ = cacheLock.Close()
			return nil, fmt.Errorf("inspect rootfs preparation lock %q: %w", path, statErr)
		}
		file, openErr := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if openErr != nil {
			_ = cacheLock.Close()
			return nil, fmt.Errorf("open rootfs preparation lock %q: %w", path, openErr)
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			_ = cacheLock.Close()
			return nil, fmt.Errorf("secure rootfs preparation lock: %w", err)
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			_ = file.Close()
			_ = cacheLock.Close()
			if statErr == nil {
				statErr = fmt.Errorf("not a private regular file")
			}
			return nil, fmt.Errorf("validate rootfs preparation lock: %w", statErr)
		}
		locked, err := tryLockImageCacheLease(file)
		if err != nil {
			_ = file.Close()
			_ = cacheLock.Close()
			return nil, fmt.Errorf("lock rootfs preparation: %w", err)
		}
		cacheCloseErr := cacheLock.Close()
		if cacheCloseErr != nil {
			if locked {
				_ = unlockImageCacheLease(file)
			}
			_ = file.Close()
			return nil, fmt.Errorf("release rootfs cache lock: %w", cacheCloseErr)
		}
		if locked {
			return func() {
				_ = unlockImageCacheLease(file)
				_ = file.Close()
			}, nil
		}
		_ = file.Close()
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// cleanupStaleRootfsPreparationLocksLocked removes per-image lock metadata
// only when the cache lock is held, no builder owns the image lock, and the
// corresponding immutable image has already been evicted.
func cleanupStaleRootfsPreparationLocksLocked(cacheDir string) error {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return fmt.Errorf("list rootfs preparation locks: %w", err)
	}
	const prefix, suffix = ".rootfs-preparation-", ".lock"
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		digest := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != digest {
			return fmt.Errorf("invalid rootfs preparation lock name %q", name)
		}
		path := filepath.Join(cacheDir, name)
		imagePath := filepath.Join(cacheDir, digest+".ext4")
		if _, err := os.Lstat(imagePath); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect image for preparation lock %q: %w", name, err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("inspect rootfs preparation lock %q: %w", path, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("rootfs preparation lock %q is not a private regular file", path)
		}
		file, err := os.OpenFile(path, os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("open rootfs preparation lock %q: %w", path, err)
		}
		locked, lockErr := tryLockImageCacheLease(file)
		if lockErr != nil {
			_ = file.Close()
			return fmt.Errorf("check rootfs preparation lock %q: %w", path, lockErr)
		}
		if !locked {
			_ = file.Close()
			continue
		}
		removeErr := os.Remove(path)
		unlockErr := unlockImageCacheLease(file)
		closeErr := file.Close()
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("remove stale rootfs preparation lock %q: %w", path, removeErr)
		}
		if unlockErr != nil {
			return fmt.Errorf("unlock stale rootfs preparation lock %q: %w", path, unlockErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close stale rootfs preparation lock %q: %w", path, closeErr)
		}
	}
	return nil
}

func unpackRootfsArchive(ctx context.Context, archiveFile *os.File, archivePath, rootfsDir string) error {
	var decompressed io.Reader
	var compressed io.Closer
	buffered := bufio.NewReader(&contextReader{ctx: ctx, reader: archiveFile})
	magic, peekErr := buffered.Peek(2)
	if peekErr != nil && !errors.Is(peekErr, io.EOF) {
		return fmt.Errorf("read rootfs archive header: %w", peekErr)
	}
	decompressed = buffered
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gzipReader, err := gzip.NewReader(buffered)
		if err != nil {
			return fmt.Errorf("open gzip rootfs archive: %w", err)
		}
		decompressed = gzipReader
		compressed = gzipReader
	}
	bounded := &boundedReader{reader: decompressed, limit: rootfsExpandedMaxBytes}
	unpackErr := archive.UntarUncompressed(bounded, rootfsDir, &archive.TarOptions{
		NoLchown:             true,
		NoOverwriteDirNonDir: true,
	})
	if unpackErr == nil {
		if _, drainErr := io.Copy(io.Discard, bounded); drainErr != nil {
			unpackErr = fmt.Errorf("verify expanded rootfs archive stream: %w", drainErr)
		}
	}
	var closeErr error
	if compressed != nil {
		closeErr = compressed.Close()
	}
	if unpackErr != nil {
		return fmt.Errorf("safely unpack rootfs archive %q: %w", archivePath, unpackErr)
	}
	if closeErr != nil {
		return fmt.Errorf("finish rootfs archive decompression: %w", closeErr)
	}
	if bounded.exceeded {
		return fmt.Errorf("expanded rootfs archive exceeds %d byte limit", rootfsExpandedMaxBytes)
	}
	return nil
}

func validateGuestAgent(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect VM guest agent %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 || info.Size() <= 0 || info.Size() > 128<<20 {
		return nil, fmt.Errorf("VM guest agent %q must be a non-empty executable regular file no larger than 128 MiB", path)
	}
	file, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("VM guest agent %q is not an ELF executable: %w", path, err)
	}
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		_ = file.Close()
		return nil, fmt.Errorf("VM guest agent %q is not an executable ELF image", path)
	}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			_ = file.Close()
			return nil, fmt.Errorf("VM guest agent %q must be statically linked", path)
		}
	}
	if file.Machine != hostGuestELFMachine() {
		_ = file.Close()
		return nil, fmt.Errorf("VM guest agent %q has an architecture incompatible with host %s/%s", path, runtime.GOOS, runtime.GOARCH)
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	hasher := sha256.New()
	input, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(hasher, input); err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("hash VM guest agent: %w", err)
	}
	if err := input.Close(); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func hostGuestELFMachine() elf.Machine {
	switch runtime.GOARCH {
	case "amd64":
		return elf.EM_X86_64
	case "arm64":
		return elf.EM_AARCH64
	default:
		return elf.EM_NONE
	}
}

func installGuestRuntime(rootfsDir, guestAgentPath string, guestUMOCIPath ...string) error {
	for _, mountpoint := range []string{"proc", "sys", "dev", "run", "tmp", "overlay", "lower", "newroot", "image"} {
		if err := os.MkdirAll(filepath.Join(rootfsDir, mountpoint), 0o755); err != nil {
			return fmt.Errorf("create guest mountpoint %q: %w", mountpoint, err)
		}
	}
	destination := filepath.Join(rootfsDir, "opt", "cautem", "bin", "guest-agent")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create guest agent directory: %w", err)
	}
	if err := copyRegularFile(guestAgentPath, destination, 0o755); err != nil {
		return fmt.Errorf("install guest agent: %w", err)
	}
	if len(guestUMOCIPath) > 0 && guestUMOCIPath[0] != "" {
		umociDigest, err := validateGuestAgent(guestUMOCIPath[0])
		if err != nil {
			return fmt.Errorf("validate guest umoci: %w", err)
		}
		_ = umociDigest
		umociDestination := filepath.Join(rootfsDir, "opt", "cautem", "bin", "umoci")
		if err := copyRegularFile(guestUMOCIPath[0], umociDestination, 0o755); err != nil {
			return fmt.Errorf("install guest umoci: %w", err)
		}
	}
	initPath := filepath.Join(rootfsDir, "opt", "cautem", "vm-init")
	if err := os.WriteFile(initPath, []byte(guestInitScript), 0o755); err != nil {
		return fmt.Errorf("install guest VM init: %w", err)
	}
	return nil
}

func copyRegularFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	return os.Chmod(destination, mode)
}

const guestInitScript = `#!/bin/sh
set -eu
export LC_ALL=C
mkdir -p /proc /sys /dev /run /tmp /overlay /lower /newroot /image
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mount -o remount,ro / 2>/dev/null || true
mkdir -p /overlay /lower /newroot
mount -t ext4 -o rw /dev/vdb /overlay
if [ "${CAUTEM_VM_INIT_MODE:-sandbox}" = "image-prep" ] || [ -f /overlay/config/cautem-image/source ]; then
  # Match OpenShell's prep layout: a temporary ext4 disk is both the payload
  # staging area and the prepared image output. Never expose registry
  # credentials to this guest. Publish only after extraction succeeds.
  payload_dir=/overlay/config/cautem-image
  prep_log="$payload_dir/prep.log"
  exec >>"$prep_log" 2>&1
  trap 'prep_status=$?; printf "image-prep exit status=%s\n" "$prep_status"; sync' EXIT
  source="$(cat "$payload_dir/source" 2>/dev/null || true)"
  printf 'image-prep source=%s payload=%s\n' "$source" "$payload_dir"
  if [ -z "$source" ]; then
    echo "FATAL: image-prep payload source metadata not found" >&2
    exit 1
  fi
  rm -rf /overlay/image-rootfs /overlay/image-rootfs.partial
  mkdir -p /overlay/image-rootfs.partial
  case "$source" in
    tar-rootfs-v1)
      if [ ! -f "$payload_dir/rootfs.tar" ]; then
        echo "FATAL: image-prep rootfs tar not found" >&2
        exit 1
      fi
      echo "image-prep extracting rootfs.tar"
      tar -xpf "$payload_dir/rootfs.tar" -C /overlay/image-rootfs.partial
      echo "image-prep rootfs.tar extraction complete"
      ;;
    tar-rootfs-gzip-v1)
      if [ ! -f "$payload_dir/rootfs.tar.gz" ]; then
        echo "FATAL: compressed image-prep rootfs tar not found" >&2
        exit 1
      fi
      echo "image-prep extracting rootfs.tar.gz"
      tar -xzpf "$payload_dir/rootfs.tar.gz" -C /overlay/image-rootfs.partial
      echo "image-prep rootfs.tar.gz extraction complete"
      ;;
    oci-layout-v1)
      if [ ! -x /opt/cautem/bin/umoci ]; then
        echo "FATAL: umoci not found in VM bootstrap image" >&2
        exit 1
      fi
      /opt/cautem/bin/umoci raw unpack \
        --image "$payload_dir/oci:cautem" \
        /overlay/image-rootfs.partial
      echo "image-prep OCI extraction complete"
      ;;
    *)
      echo "FATAL: unknown image-prep payload source: $source" >&2
      exit 1
      ;;
  esac
  expanded_bytes="$(du --apparent-size -s -B1 /overlay/image-rootfs.partial 2>/dev/null | awk 'NR == 1 {print $1}')"
  case "$expanded_bytes" in
    ''|*[!0-9]*)
      expanded_kib="$(du -sk /overlay/image-rootfs.partial | awk 'NR == 1 {print $1}')"
      expanded_bytes=$((expanded_kib * 1024))
      ;;
  esac
  case "$expanded_bytes" in
    ''|*[!0-9]*) echo "FATAL: unable to measure prepared rootfs size" >&2; exit 1 ;;
  esac
  if [ "$expanded_bytes" -gt "${CAUTEM_VM_IMAGE_PREP_MAX_BYTES:-34493956096}" ]; then
    echo "FATAL: prepared rootfs exceeds the configured size limit" >&2
    exit 1
  fi
  for mountpoint in proc sys dev run tmp overlay lower newroot image; do
    mkdir -p "/overlay/image-rootfs.partial/$mountpoint"
  done
  mkdir -p /overlay/image-rootfs.partial/opt/cautem/bin
  cp /opt/cautem/bin/guest-agent /overlay/image-rootfs.partial/opt/cautem/bin/guest-agent
  chmod 0755 /overlay/image-rootfs.partial/opt/cautem/bin/guest-agent
  chmod 0755 /overlay/image-rootfs.partial
  mv /overlay/image-rootfs.partial /overlay/image-rootfs
  rm -rf "$payload_dir"
  sync
  umount /overlay
  mkdir -p /image-prep-check
  mount -t ext4 -o ro /dev/vdb /image-prep-check
  if [ ! -d /image-prep-check/image-rootfs ] || [ ! -x /image-prep-check/image-rootfs/opt/cautem/bin/guest-agent ]; then
    echo "FATAL: prepared image-rootfs did not persist on /dev/vdb" >&2
    ls -la /image-prep-check >&2 || true
    exit 1
  fi
  umount /image-prep-check
  exit 0
fi
mkdir -p /overlay/upper /overlay/work
if [ "${CAUTEM_VM_IMAGE_DISK:-}" = "1" ]; then
  # The prepared image is synced and unmounted before publication. It is
  # immutable thereafter, so skip journal replay on its read-only virtio disk.
  if ! mount -t ext4 -o ro,noload /dev/vdc /image; then
    echo "FATAL: failed to mount immutable workload image /dev/vdc on /image" >&2
    ls -ld /image /dev/vdc >&2 || true
    cat /proc/mounts >&2 || true
    dmesg | tail -40 >&2 || true
    exit 1
  fi
  mount --bind /image/image-rootfs /lower
else
  mount --bind / /lower
fi
mount -o remount,bind,ro /lower 2>/dev/null || true
mount -t overlay overlay -o lowerdir=/lower,upperdir=/overlay/upper,workdir=/overlay/work /newroot
configured_uid=${CAUTEM_VM_SANDBOX_UID:-}
configured_gid=${CAUTEM_VM_SANDBOX_GID:-}
sandbox_uid=${configured_uid:-1000}
sandbox_gid=${configured_gid:-$sandbox_uid}
mkdir -p /newroot/etc
reconcile_account_file() {
  account_file=$1
  account_line=$2
  account_name=$3
  account_tmp="$account_file.cautem-tmp"
  if [ -f "$account_file" ]; then
    awk -F: -v OFS=: -v name="$account_name" -v line="$account_line" '
      BEGIN { found=0 }
      $1 == name { print line; found=1; next }
      { print }
      END { if (!found) print line }
    ' "$account_file" > "$account_tmp"
  else
    printf '%s\n' "$account_line" > "$account_tmp"
  fi
  if [ -f "$account_file" ]; then
    account_mode=$(stat -c '%a' "$account_file")
    chmod "$account_mode" "$account_tmp"
  fi
  mv "$account_tmp" "$account_file"
}
reconcile_account_file /newroot/etc/group "sandbox:x:$sandbox_gid:" sandbox
reconcile_account_file /newroot/etc/gshadow 'sandbox:!::' sandbox
reconcile_account_file /newroot/etc/passwd "sandbox:x:$sandbox_uid:$sandbox_gid:OpenShell Sandbox:/sandbox:/bin/bash" sandbox
reconcile_account_file /newroot/etc/shadow 'sandbox:!:20123:0:99999:7:::' sandbox
for path in proc sys dev run tmp; do
  mkdir -p "/newroot/$path"
  mount --rbind "/$path" "/newroot/$path"
done
mkdir -p /newroot/sandbox /newroot/workspace
if [ -n "${CAUTEM_VM_SERVICE_DATA_DISK:-}" ]; then
  mkdir -p /newroot/var/lib/docker-test
  mount -t ext4 -o rw "$CAUTEM_VM_SERVICE_DATA_DISK" /newroot/var/lib/docker-test
  chmod 0700 /newroot/var/lib/docker-test
fi
mkdir -p /newroot/.oldroot
mount --make-rprivate / 2>/dev/null || true
cd /newroot
pivot_root . .oldroot
cd /
umount -l /.oldroot 2>/dev/null || true
guest_uid=1000
guest_gid=1000
if [ -r /etc/passwd ]; then
  while IFS=: read -r name password uid gid rest; do
    if [ "$name" = sandbox ]; then guest_uid=${uid:-1000}; guest_gid=${gid:-$guest_uid}; break; fi
  done < /etc/passwd
fi
configured_uid=${CAUTEM_VM_SANDBOX_UID:-}
configured_gid=${CAUTEM_VM_SANDBOX_GID:-}
case "$configured_uid" in
  ''|*[!0-9]*) ;;
  *) guest_uid=$configured_uid ;;
esac
case "$configured_gid" in
  ''|*[!0-9]*)
    if [ -n "$configured_uid" ]; then guest_gid=$guest_uid; fi
    ;;
  *) guest_gid=$configured_gid ;;
esac
unset CAUTEM_VM_SANDBOX_UID CAUTEM_VM_SANDBOX_GID
chown "$guest_uid:$guest_gid" /sandbox 2>/dev/null || true
mount --bind /sandbox /workspace
export CAUTEM_VM_UID="$guest_uid" CAUTEM_VM_GID="$guest_gid"
if [ -d /opt/cautem/init.d ]; then
  for dropin in /opt/cautem/init.d/*; do
    [ -f "$dropin" ] || continue
    dropin_name=${dropin##*/}
    "/opt/cautem/init.d/$dropin_name"
  done
fi
exec /opt/cautem/bin/guest-agent
`

type boundedReader struct {
	reader   io.Reader
	limit    int64
	read     int64
	exceeded bool
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func (r *boundedReader) Read(buffer []byte) (int, error) {
	if r.read >= r.limit {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			r.exceeded = true
			return 0, fmt.Errorf("expanded rootfs archive exceeds %d byte limit", r.limit)
		}
		return 0, err
	}
	remaining := r.limit - r.read
	if int64(len(buffer)) > remaining {
		buffer = buffer[:remaining]
	}
	n, err := r.reader.Read(buffer)
	r.read += int64(n)
	return n, err
}

func ensurePrivateDirectory(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("VM rootfs image cache directory is unset")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve VM rootfs image cache directory: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return fmt.Errorf("create VM rootfs image cache %q: %w", absolute, err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return fmt.Errorf("inspect VM rootfs image cache %q: %w", absolute, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("VM rootfs image cache %q must be a real directory", absolute)
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return fmt.Errorf("secure VM rootfs image cache %q: %w", absolute, err)
	}
	return nil
}

func resolveExt4Formatter() (string, error) {
	names := []string{"mke2fs", "mkfs.ext4"}
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	for _, root := range []string{"/opt/homebrew/opt/e2fsprogs", "/usr/local/opt/e2fsprogs"} {
		for _, directory := range []string{"sbin", "bin"} {
			for _, name := range names {
				candidate := filepath.Join(root, directory, name)
				if path, err := exec.LookPath(candidate); err == nil {
					return path, nil
				}
			}
		}
	}
	return "", fmt.Errorf("ext4 formatter unavailable: install e2fsprogs (mke2fs or mkfs.ext4)")
}

func rootfsImageSize(rootfs string) (uint64, error) {
	var used uint64 = 4096
	err := filepath.WalkDir(rootfs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			if info.Size() > 0 {
				used += uint64(info.Size())
			}
		} else if info.IsDir() {
			used += 4096
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("measure unpacked rootfs: %w", err)
	}
	headroom := used / 4
	if headroom < rootfsImageMinHeadroom {
		headroom = rootfsImageMinHeadroom
	}
	size := used + headroom
	if size < rootfsImageMinBytes {
		size = rootfsImageMinBytes
	}
	return (size + rootfsImageSizeGranularity - 1) / rootfsImageSizeGranularity * rootfsImageSizeGranularity, nil
}

// WriteGuestInit writes the embedded VM init script into root.
func WriteGuestInit(root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	initDir := filepath.Join(root, "opt", "cautem")
	if err := os.MkdirAll(initDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(initDir, "vm-init"), []byte(guestInitScript), 0o755)
}
