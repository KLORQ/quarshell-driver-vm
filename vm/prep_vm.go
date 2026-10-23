//go:build darwin || linux

package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

const (
	guestImagePrepCacheVersion = "quarshell-workload-prep-vm-v1"
	guestImagePrepTimeout      = 15 * time.Minute
	guestImagePrepHeadroom     = uint64(1 << 30)
	guestImagePayloadDir       = "quarshell-image"
)

func prepareRootfsTarWorkloadDiskInGuest(ctx context.Context, archiveFile *os.File, archivePath, cacheDir, formatterPath, guestAgentPath, guestUMOCIPath, bootstrapDisk string, host HostConfig, maxArchiveBytes, cacheMaxBytes int64) (preparedRootfsImage, string, error) {
	if archiveFile == nil {
		return preparedRootfsImage{}, "", fmt.Errorf("workload rootfs archive is required")
	}
	info, err := archiveFile.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxArchiveBytes {
		if err == nil {
			err = fmt.Errorf("archive is not a regular file or is outside the allowed size range")
		}
		return preparedRootfsImage{}, "", fmt.Errorf("inspect workload rootfs archive: %w", err)
	}
	digest, err := digestOpenFile(archiveFile)
	if err != nil {
		return preparedRootfsImage{}, "", fmt.Errorf("identify workload rootfs archive: %w", err)
	}
	compressed := false
	var magic [2]byte
	if _, err := archiveFile.ReadAt(magic[:], 0); err != nil && !errors.Is(err, io.EOF) {
		return preparedRootfsImage{}, "", fmt.Errorf("read workload archive format: %w", err)
	}
	compressed = magic[0] == 0x1f && magic[1] == 0x8b
	identity := "tar-workload-prep-v1:" + digest
	prepared, err := prepareWorkloadDiskInGuest(ctx, cacheDir, formatterPath, guestAgentPath, guestUMOCIPath, bootstrapDisk, host, identity, info.Size(), cacheMaxBytes, func(payloadDir string) (int64, error) {
		name := "rootfs.tar"
		source := "tar-rootfs-v1"
		if compressed {
			name = "rootfs.tar.gz"
			source = "tar-rootfs-gzip-v1"
		}
		if err := writePrivateFile(filepath.Join(payloadDir, "source"), []byte(source)); err != nil {
			return 0, err
		}
		if _, err := archiveFile.Seek(0, io.SeekStart); err != nil {
			return 0, fmt.Errorf("rewind workload archive: %w", err)
		}
		out, err := os.OpenFile(filepath.Join(payloadDir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return 0, fmt.Errorf("create staged workload archive: %w", err)
		}
		written, copyErr := io.Copy(out, &contextReader{ctx: ctx, reader: archiveFile})
		if copyErr == nil {
			copyErr = out.Sync()
		}
		closeErr := out.Close()
		if copyErr != nil {
			return 0, fmt.Errorf("stage workload archive: %w", copyErr)
		}
		if closeErr != nil {
			return 0, fmt.Errorf("close staged workload archive: %w", closeErr)
		}
		return written, nil
	})
	if err != nil {
		return preparedRootfsImage{}, "", err
	}
	return prepared, digest, nil
}

func prepareOCIWorkloadDiskInGuest(ctx context.Context, resolved resolvedOCIImage, cacheDir, formatterPath, guestAgentPath, guestUMOCIPath, bootstrapDisk string, host HostConfig, cacheMaxBytes int64) (preparedRootfsImage, error) {
	manifestDigest, err := resolved.Image.Digest()
	if err != nil {
		return preparedRootfsImage{}, fmt.Errorf("identify OCI workload for guest prep: %w", err)
	}
	identity := "oci-workload-prep-v1:" + resolved.cacheIdentity()
	prepared, err := prepareWorkloadDiskInGuest(ctx, cacheDir, formatterPath, guestAgentPath, guestUMOCIPath, bootstrapDisk, host, identity, 0, cacheMaxBytes, func(payloadDir string) (int64, error) {
		if err := writePrivateFile(filepath.Join(payloadDir, "source"), []byte("oci-layout-v1")); err != nil {
			return 0, err
		}
		if err := writePrivateFile(filepath.Join(payloadDir, "identity"), []byte(manifestDigest.String())); err != nil {
			return 0, err
		}
		layoutDir := filepath.Join(payloadDir, "oci")
		ociLayout, err := layout.Write(layoutDir, empty.Index)
		if err != nil {
			return 0, fmt.Errorf("create staged OCI layout: %w", err)
		}
		if err := ociLayout.AppendImage(resolved.Image, layout.WithAnnotations(map[string]string{"org.opencontainers.image.ref.name": "quarshell"})); err != nil {
			return 0, fmt.Errorf("stage verified OCI image layout: %w", err)
		}
		return directorySize(layoutDir)
	})
	if err != nil {
		return preparedRootfsImage{}, err
	}
	return prepared, nil
}

func prepareWorkloadDiskInGuest(ctx context.Context, cacheDir, formatterPath, guestAgentPath, guestUMOCIPath, bootstrapDisk string, host HostConfig, sourceIdentity string, compressedSize int64, cacheMaxBytes int64, stagePayload func(string) (int64, error)) (preparedRootfsImage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(bootstrapDisk) == "" || stagePayload == nil {
		return preparedRootfsImage{}, fmt.Errorf("bootstrap disk and workload payload are required for guest image preparation")
	}
	if err := ctx.Err(); err != nil {
		return preparedRootfsImage{}, err
	}
	guestDigest, err := validateGuestAgent(guestAgentPath)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	umociDigest, err := validateGuestAgent(guestUMOCIPath)
	if err != nil {
		return preparedRootfsImage{}, fmt.Errorf("validate pinned guest umoci: %w", err)
	}
	bootstrapInfo, err := os.Lstat(bootstrapDisk)
	if err != nil || !bootstrapInfo.Mode().IsRegular() || bootstrapInfo.Mode()&os.ModeSymlink != 0 || bootstrapInfo.Mode().Perm()&0o222 != 0 || bootstrapInfo.Size() == 0 {
		if err == nil {
			err = fmt.Errorf("bootstrap disk is not a non-empty regular file")
		}
		return preparedRootfsImage{}, fmt.Errorf("inspect bootstrap disk for image preparation: %w", err)
	}
	bootstrapIdentity := filepath.Base(bootstrapDisk)
	keyInput := []byte(guestImagePrepCacheVersion + "\x00" + sourceIdentity + "\x00" + bootstrapIdentity)
	keyInput = append(keyInput, 0)
	keyInput = append(keyInput, guestDigest...)
	keyInput = append(keyInput, umociDigest...)
	guestInitDigest := sha256.Sum256([]byte(guestInitScript))
	keyInput = append(keyInput, guestInitDigest[:]...)
	key := sha256.Sum256(keyInput)
	cacheKey := hex.EncodeToString(key[:])
	if err := ensureRootfsImageCacheDirectories(cacheDir); err != nil {
		return preparedRootfsImage{}, err
	}
	imagePath := filepath.Join(cacheDir, cacheKey+".ext4")
	unlock, err := lockRootfsImagePreparation(ctx, cacheDir, cacheKey)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return preparedRootfsImage{}, err
	}
	if lease, cached, err := acquireCachedRootfsImage(cacheDir, imagePath, cacheMaxBytes); err != nil {
		return preparedRootfsImage{}, err
	} else if cached {
		return preparedRootfsImage{Path: imagePath, Lease: lease}, nil
	}
	if formatterPath == "" {
		formatterPath, err = resolveExt4Formatter()
		if err != nil {
			return preparedRootfsImage{}, err
		}
	}
	staging, err := os.MkdirTemp(cacheDir, ".guest-prep-*")
	if err != nil {
		return preparedRootfsImage{}, fmt.Errorf("create guest image-prep staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o700); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("secure guest image-prep staging directory: %w", err)
	}
	payloadDir := filepath.Join(staging, "overlay", "config", guestImagePayloadDir)
	if err := os.MkdirAll(payloadDir, 0o700); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("create guest image-prep payload directory: %w", err)
	}
	payloadSize, err := stagePayload(payloadDir)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	if payloadSize < 0 {
		return preparedRootfsImage{}, fmt.Errorf("guest image-prep payload size is invalid")
	}
	if compressedSize > int64(payloadSize) {
		payloadSize = compressedSize
	}
	// Bound the guest's writable disk by the validated maximum expanded rootfs
	// plus the staged input and ext4 metadata headroom. The file is sparse.
	imageSize := uint64(rootfsExpandedMaxBytes) + uint64(payloadSize) + guestImagePrepHeadroom
	if imageSize < rootfsImageMinBytes {
		imageSize = rootfsImageMinBytes
	}
	if cacheMaxBytes > 0 && imageSize > uint64(cacheMaxBytes) {
		return preparedRootfsImage{}, fmt.Errorf("guest image-prep disk size %d exceeds image cache limit %d", imageSize, cacheMaxBytes)
	}
	stagedImage := filepath.Join(staging, "workload.ext4")
	image, err := os.OpenFile(stagedImage, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return preparedRootfsImage{}, fmt.Errorf("create guest image-prep disk: %w", err)
	}
	if err := image.Truncate(int64(imageSize)); err != nil {
		_ = image.Close()
		return preparedRootfsImage{}, fmt.Errorf("size guest image-prep disk: %w", err)
	}
	if err := image.Close(); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("close guest image-prep disk: %w", err)
	}
	if err := formatExt4Image(ctx, formatterPath, filepath.Join(staging, "overlay"), stagedImage); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("format guest image-prep disk: %w", err)
	}
	runPrep := host.imagePrepRunner
	if runPrep == nil {
		runPrep = runGuestImagePrepVM
	}
	if err := runPrep(ctx, host, bootstrapDisk, stagedImage, staging); err != nil {
		return preparedRootfsImage{}, err
	}
	verify := host.imagePrepVerifier
	if verify == nil {
		verify = func(path, formatter string) error {
			return verifyPreparedWorkloadExt4WithAgent(path, formatter, guestAgentPath)
		}
	}
	if err := verify(stagedImage, formatterPath); err != nil {
		console, _ := readBoundedFile(filepath.Join(staging, "image-prep-console.log"), 16<<10)
		return preparedRootfsImage{}, fmt.Errorf("guest image-prep did not produce a valid workload rootfs: %w; console tail:\n%s", err, console)
	}
	if err := os.Chmod(stagedImage, 0o400); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("make prepared workload image immutable: %w", err)
	}
	lease, err := publishRootfsImage(cacheDir, stagedImage, imagePath, int64(imageSize), cacheMaxBytes)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	return preparedRootfsImage{Path: imagePath, Lease: lease}, nil
}

func runGuestImagePrepVM(ctx context.Context, host HostConfig, bootstrapDisk, prepDisk, runDir string) error {
	worker, err := workerPath(host.WorkerPath)
	if err != nil {
		return fmt.Errorf("resolve image-prep VM worker: %w", err)
	}
	isolationFunc := host.workerIsolation
	if isolationFunc == nil {
		isolationFunc = workerIsolationForChild
	}
	isolation, err := isolationFunc()
	if err != nil {
		return fmt.Errorf("prepare image-prep worker isolation: %w", err)
	}
	controlDir, err := os.MkdirTemp("/tmp", "cp-")
	if err != nil {
		return fmt.Errorf("create image-prep worker socket directory: %w", err)
	}
	defer os.RemoveAll(controlDir)
	controlSocket := filepath.Join(controlDir, "w.sock")
	consolePath := filepath.Join(runDir, "image-prep-console.log")
	console, err := os.OpenFile(consolePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create image-prep console log: %w", err)
	}
	defer console.Close()
	launch := KrunLaunchConfig{
		RootDisk: bootstrapDisk, OverlayDisk: prepDisk,
		VCPUs: host.VCPUs, MemoryMiB: host.MemoryMiB,
		KrunLogLevel: configuredKrunLogLevel(host),
		WorkDir:      "/", ExecPath: "/opt/quarshell/vm-init",
		Env: []string{
			"QUARSHELL_VM_INIT_MODE=image-prep",
			"QUARSHELL_VM_IMAGE_PREP_MAX_BYTES=" + strconv.FormatInt(rootfsExpandedMaxBytes+(128<<20), 10),
		}, ConsolePath: consolePath,
	}
	config, err := workerConfigJSON(workerConfig{RuntimeDir: host.RuntimeDir, ControlSocket: controlSocket, Isolation: isolation, WatchParentLiveness: true, Launch: launch})
	if err != nil {
		return err
	}
	command := exec.Command(worker)
	command.Stdin = strings.NewReader(string(config))
	command.Stdout = console
	command.Stderr = console
	command.Env = workerEnvironment(host.RuntimeDir)
	processAttributes := host.workerProcessAttributes
	if processAttributes == nil {
		processAttributes = workerProcessAttributes
	}
	command.SysProcAttr = processAttributes()
	parentLiveness, err := startWorkerWithParentLiveness(command)
	if err != nil {
		return fmt.Errorf("start image-prep VM worker: %w", err)
	}
	defer parentLiveness.Close()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer func() {
		select {
		case <-done:
		default:
			_, _ = workerControl(context.Background(), controlSocket, "stop")
			_ = killWorkerProcessGroup(command)
		}
	}()
	workerCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		workerCtx, cancel = context.WithTimeout(ctx, guestImagePrepTimeout)
		defer cancel()
	}
	if err := waitForWorkerOrExit(workerCtx, controlSocket, done); err != nil {
		return imagePrepWorkerError(err, consolePath)
	}
	select {
	case err := <-done:
		if err != nil {
			return imagePrepWorkerError(fmt.Errorf("worker exited: %w", err), consolePath)
		}
		return nil
	case <-workerCtx.Done():
		_, _ = workerControl(context.Background(), controlSocket, "stop")
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				return imagePrepWorkerError(fmt.Errorf("worker stopped after timeout: %w", err), consolePath)
			}
		case <-time.After(workerStopTimeout):
			_ = killWorkerProcessGroup(command)
		}
		return imagePrepWorkerError(workerCtx.Err(), consolePath)
	}
}

func imagePrepWorkerError(err error, consolePath string) error {
	console, _ := readBoundedFile(consolePath, 16<<10)
	return fmt.Errorf("image-prep VM failed: %w; console tail:\n%s", err, console)
}

func verifyPreparedWorkloadExt4WithAgent(imagePath, formatterPath, guestAgentPath string) error {
	debugfs := ""
	if formatterPath != "" {
		candidate := filepath.Join(filepath.Dir(formatterPath), "debugfs")
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			debugfs = candidate
		}
	}
	if debugfs == "" {
		var err error
		debugfs, err = exec.LookPath("debugfs")
		if err != nil {
			return fmt.Errorf("debugfs verifier unavailable: install e2fsprogs")
		}
	}
	for _, path := range []string{"/image-rootfs", "/image-rootfs/opt/quarshell/bin/guest-agent"} {
		output, err := exec.Command(debugfs, "-R", "stat "+path, imagePath).CombinedOutput()
		if err != nil {
			return fmt.Errorf("debugfs stat %s: %w: %s", path, err, strings.TrimSpace(string(output)))
		}
		text := string(output)
		if !strings.Contains(text, "Inode:") {
			rootListing, _ := exec.Command(debugfs, "-R", "ls -l /", imagePath).CombinedOutput()
			payloadListing, _ := exec.Command(debugfs, "-R", "ls -l /config/quarshell-image", imagePath).CombinedOutput()
			prepLog, _ := exec.Command(debugfs, "-R", "cat /config/quarshell-image/prep.log", imagePath).CombinedOutput()
			return fmt.Errorf("ext4 image is missing %s: %s; root listing: %s; payload listing: %s; image-prep log: %s", path, strings.TrimSpace(text), strings.TrimSpace(string(rootListing)), strings.TrimSpace(string(payloadListing)), strings.TrimSpace(string(prepLog)))
		}
		if path == "/image-rootfs" && !strings.Contains(text, "Type: directory") {
			return fmt.Errorf("ext4 path %s is not a directory: %s", path, strings.TrimSpace(text))
		}
		if strings.HasSuffix(path, "guest-agent") && !strings.Contains(text, "Type: regular ") {
			return fmt.Errorf("ext4 path %s is not a regular file: %s", path, strings.TrimSpace(text))
		}
	}
	if guestAgentPath != "" {
		expectedDigest, err := validateGuestAgent(guestAgentPath)
		if err != nil {
			return fmt.Errorf("validate expected guest agent: %w", err)
		}
		tempDir, err := os.MkdirTemp("/tmp", "cv-")
		if err != nil {
			return fmt.Errorf("create guest agent verification directory: %w", err)
		}
		defer os.RemoveAll(tempDir)
		dumped := filepath.Join(tempDir, "guest-agent")
		if output, err := exec.Command(debugfs, "-R", "dump /image-rootfs/opt/quarshell/bin/guest-agent "+dumped, imagePath).CombinedOutput(); err != nil {
			return fmt.Errorf("extract guest agent from prepared ext4: %w: %s", err, strings.TrimSpace(string(output)))
		}
		actualDigest, err := hashRegularFile(dumped)
		if err != nil {
			return fmt.Errorf("hash guest agent from prepared ext4: %w", err)
		}
		if !bytes.Equal(expectedDigest, actualDigest) {
			return fmt.Errorf("prepared guest agent digest does not match the pinned runtime")
		}
	}
	return nil
}

func hashRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			err = fmt.Errorf("not a regular file")
		}
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func directorySize(root string) (int64, error) {
	var size int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			if info.Size() > int64(^uint64(0)>>1)-size {
				return fmt.Errorf("OCI payload size overflow")
			}
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func writePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readBoundedFile(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > limit {
		if _, err := file.Seek(-limit, io.SeekEnd); err != nil {
			return "", err
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
