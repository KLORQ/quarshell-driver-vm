package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	overlayTemplateVersion = "v1"
	defaultOverlaySize     = uint64(4 << 30)
)

func prepareOverlayTemplate(ctx context.Context, cacheDir, formatterPath string, sizeBytes uint64) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if sizeBytes == 0 {
		sizeBytes = defaultOverlaySize
	}
	if sizeBytes < 64<<20 {
		return "", fmt.Errorf("VM overlay image size %d is below the 64 MiB minimum", sizeBytes)
	}
	if err := ensurePrivateDirectory(cacheDir); err != nil {
		return "", err
	}
	path := filepath.Join(cacheDir, fmt.Sprintf("overlay-%s-%d.ext4", overlayTemplateVersion, sizeBytes))
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Size() != int64(sizeBytes) || info.Mode().Perm()&0o222 != 0 {
			return "", fmt.Errorf("cached overlay template %q is invalid", path)
		}
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect cached overlay template %q: %w", path, err)
	}
	if formatterPath == "" {
		var err error
		formatterPath, err = resolveExt4Formatter()
		if err != nil {
			return "", err
		}
	}
	staging, err := os.MkdirTemp(cacheDir, ".overlay-build-*")
	if err != nil {
		return "", fmt.Errorf("create overlay build staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	root := filepath.Join(staging, "root")
	for _, dir := range []string{"upper", "work", "config"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			return "", fmt.Errorf("create overlay %s directory: %w", dir, err)
		}
	}
	if err := os.Chmod(root, 0o755); err != nil {
		return "", fmt.Errorf("set overlay root directory permissions: %w", err)
	}
	if err := os.Chmod(filepath.Join(root, "upper"), 0o755); err != nil {
		return "", fmt.Errorf("set overlay upper directory permissions: %w", err)
	}
	imagePath := filepath.Join(staging, "overlay.ext4")
	image, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return "", fmt.Errorf("create staged overlay image: %w", err)
	}
	if err := image.Truncate(int64(sizeBytes)); err != nil {
		_ = image.Close()
		return "", fmt.Errorf("size staged overlay image: %w", err)
	}
	if err := image.Close(); err != nil {
		return "", fmt.Errorf("close staged overlay image: %w", err)
	}
	if err := formatExt4Image(ctx, formatterPath, root, imagePath); err != nil {
		return "", err
	}
	if err := os.Chmod(imagePath, 0o400); err != nil {
		return "", fmt.Errorf("make overlay template read-only: %w", err)
	}
	if err := os.Rename(imagePath, path); err != nil {
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() && info.Size() == int64(sizeBytes) && info.Mode().Perm()&0o222 == 0 {
			return path, nil
		}
		return "", fmt.Errorf("publish overlay template %q: %w", path, err)
	}
	directory, err := os.Open(cacheDir)
	if err != nil {
		return "", fmt.Errorf("open overlay cache for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return "", fmt.Errorf("sync overlay cache: %w", err)
	}
	return path, nil
}

func createSandboxOverlay(templatePath, overlayPath string) error {
	if templatePath == "" || overlayPath == "" || !filepath.IsAbs(templatePath) || !filepath.IsAbs(overlayPath) {
		return fmt.Errorf("VM overlay template and destination paths must be non-empty absolute paths")
	}
	templateInfo, err := os.Lstat(templatePath)
	if err != nil {
		return fmt.Errorf("inspect overlay template %q: %w", templatePath, err)
	}
	if !templateInfo.Mode().IsRegular() || templateInfo.Size() == 0 || templateInfo.Mode().Perm()&0o222 != 0 {
		return fmt.Errorf("overlay template %q must be a non-empty immutable regular file", templatePath)
	}
	if _, err := os.Lstat(overlayPath); err == nil {
		return fmt.Errorf("overlay destination %q already exists", overlayPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect overlay destination %q: %w", overlayPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(overlayPath), 0o700); err != nil {
		return fmt.Errorf("create overlay parent directory: %w", err)
	}
	staging, err := os.MkdirTemp(filepath.Dir(overlayPath), ".overlay-clone-*")
	if err != nil {
		return fmt.Errorf("create overlay clone staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	stagedOverlay := filepath.Join(staging, "overlay.ext4")
	if err := cloneSparseFile(templatePath, stagedOverlay); err != nil {
		return err
	}
	if err := os.Chmod(stagedOverlay, 0o600); err != nil {
		return fmt.Errorf("secure staged sandbox overlay: %w", err)
	}
	info, err := os.Lstat(stagedOverlay)
	if err != nil || !info.Mode().IsRegular() || info.Size() != templateInfo.Size() {
		if err != nil {
			return fmt.Errorf("verify sandbox overlay: %w", err)
		}
		return fmt.Errorf("sandbox overlay size %d does not match template size %d", info.Size(), templateInfo.Size())
	}
	if err := os.Link(stagedOverlay, overlayPath); err != nil {
		return fmt.Errorf("publish sandbox overlay %q: %w", overlayPath, err)
	}
	return nil
}

func createSandboxOverlayWithDropins(ctx context.Context, formatterPath string, sizeBytes uint64, overlayPath string, dropins []GuestInitDropin) error {
	if overlayPath == "" || !filepath.IsAbs(overlayPath) {
		return fmt.Errorf("VM overlay destination path must be an absolute path")
	}
	if sizeBytes < 64<<20 {
		return fmt.Errorf("VM overlay image size %d is below the 64 MiB minimum", sizeBytes)
	}
	if err := validateExtensionLaunchPlan(&ExtensionLaunchPlan{GuestInitDropins: dropins}); err != nil {
		return err
	}
	if _, err := os.Lstat(overlayPath); err == nil {
		return fmt.Errorf("VM overlay destination %q already exists", overlayPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect overlay destination %q: %w", overlayPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(overlayPath), 0o700); err != nil {
		return fmt.Errorf("create overlay parent directory: %w", err)
	}
	staging, err := os.MkdirTemp(filepath.Dir(overlayPath), ".overlay-dropins-*")
	if err != nil {
		return fmt.Errorf("create overlay drop-in staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	root := filepath.Join(staging, "root")
	for _, directory := range []string{"upper", "work", "config"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			return fmt.Errorf("create overlay %s directory: %w", directory, err)
		}
	}
	if len(dropins) > 0 {
		initDir := filepath.Join(root, "upper", "opt", "quarshell", "init.d")
		if err := os.MkdirAll(initDir, 0o755); err != nil {
			return fmt.Errorf("create guest init drop-in directory: %w", err)
		}
		for _, dropin := range dropins {
			path := filepath.Join(initDir, dropin.Name)
			if err := os.WriteFile(path, dropin.Contents, 0o755); err != nil {
				return fmt.Errorf("stage guest init drop-in %q: %w", dropin.Name, err)
			}
			if err := os.Chmod(path, 0o755); err != nil {
				return fmt.Errorf("set guest init drop-in %q executable: %w", dropin.Name, err)
			}
		}
	}
	if err := os.Chmod(root, 0o755); err != nil {
		return fmt.Errorf("set overlay root directory permissions: %w", err)
	}
	stagedImage := filepath.Join(staging, "overlay.ext4")
	image, err := os.OpenFile(stagedImage, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create staged overlay image: %w", err)
	}
	if err := image.Truncate(int64(sizeBytes)); err != nil {
		_ = image.Close()
		return fmt.Errorf("size staged overlay image: %w", err)
	}
	if err := image.Close(); err != nil {
		return fmt.Errorf("close staged overlay image: %w", err)
	}
	if err := formatExt4Image(ctx, formatterPath, root, stagedImage); err != nil {
		return err
	}
	if err := os.Chmod(stagedImage, 0o600); err != nil {
		return fmt.Errorf("secure staged sandbox overlay: %w", err)
	}
	if err := os.Link(stagedImage, overlayPath); err != nil {
		return fmt.Errorf("publish sandbox overlay %q: %w", overlayPath, err)
	}
	return nil
}

func formatExt4Image(ctx context.Context, formatterPath, sourceDir, imagePath string) error {
	if formatterPath == "" {
		var err error
		formatterPath, err = resolveExt4Formatter()
		if err != nil {
			return err
		}
	}
	relaxedEntries, err := relaxExt4SourceModes(sourceDir)
	if err != nil {
		return fmt.Errorf("prepare ext4 source permissions: %w", err)
	}
	restoreSource := func() error { return restoreExt4SourceModes(sourceDir, relaxedEntries) }
	output, err := runFormatterCommand(ctx, formatterPath,
		"-q", "-F", "-t", "ext4", "-E", "root_owner=0:0", "-d", sourceDir, imagePath,
	)
	if err != nil {
		restoreErr := restoreSource()
		return errors.Join(fmt.Errorf("format ext4 image with %q: %w: %s", formatterPath, err, strings.TrimSpace(string(output))), restoreErr)
	}
	if err := restoreExt4ImageModes(ctx, imagePath, relaxedEntries); err != nil {
		restoreErr := restoreSource()
		return errors.Join(fmt.Errorf("restore ext4 source permission modes: %w", err), restoreErr)
	}
	if err := restoreSource(); err != nil {
		return fmt.Errorf("restore ext4 source permissions: %w", err)
	}
	image, err := os.OpenFile(imagePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open formatted ext4 image: %w", err)
	}
	if err := image.Sync(); err != nil {
		_ = image.Close()
		return fmt.Errorf("sync formatted ext4 image: %w", err)
	}
	if err := image.Close(); err != nil {
		return fmt.Errorf("close formatted ext4 image: %w", err)
	}
	return nil
}

type ext4SourceMode struct {
	path string
	mode os.FileMode
	dir  bool
}

func relaxExt4SourceModes(sourceDir string) ([]ext4SourceMode, error) {
	var relaxed []ext4SourceMode
	err := filepath.WalkDir(sourceDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == sourceDir {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		mode := info.Mode()
		needsRead := mode.IsRegular() && mode.Perm()&0o400 == 0
		needsTraverse := mode.IsDir() && mode.Perm()&0o500 != 0o500
		if !needsRead && !needsTraverse {
			return nil
		}
		relative, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		if strings.ContainsAny(relative, "\r\n") {
			return fmt.Errorf("ext4 source path contains a line break: %q", relative)
		}
		relaxedMode := mode | 0o400
		if mode.IsDir() {
			relaxedMode = mode | 0o700
		}
		if err := os.Chmod(path, relaxedMode); err != nil {
			return err
		}
		relaxed = append(relaxed, ext4SourceMode{path: filepath.ToSlash(relative), mode: mode, dir: mode.IsDir()})
		return nil
	})
	if err != nil {
		_ = restoreExt4SourceModes(sourceDir, relaxed)
		return nil, err
	}
	return relaxed, nil
}

func restoreExt4SourceModes(sourceDir string, modes []ext4SourceMode) error {
	var result error
	for index := len(modes) - 1; index >= 0; index-- {
		entry := modes[index]
		if err := os.Chmod(filepath.Join(sourceDir, filepath.FromSlash(entry.path)), entry.mode); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func restoreExt4ImageModes(ctx context.Context, imagePath string, modes []ext4SourceMode) error {
	if len(modes) == 0 {
		return nil
	}
	debugfsPath, err := exec.LookPath("debugfs")
	if err != nil {
		return fmt.Errorf("debugfs is required to restore restrictive ext4 source modes: %w", err)
	}
	commands, err := os.CreateTemp(filepath.Dir(imagePath), ".ext4-mode-restore-*.cmd")
	if err != nil {
		return err
	}
	commandPath := commands.Name()
	defer os.Remove(commandPath)
	if err := commands.Chmod(0o600); err != nil {
		_ = commands.Close()
		return err
	}
	for _, entry := range modes {
		mode := uint32(entry.mode.Perm())
		if entry.dir {
			mode |= 0o040000
		} else {
			mode |= 0o100000
		}
		if entry.mode&os.ModeSetuid != 0 {
			mode |= 0o4000
		}
		if entry.mode&os.ModeSetgid != 0 {
			mode |= 0o2000
		}
		if entry.mode&os.ModeSticky != 0 {
			mode |= 0o1000
		}
		name := strings.ReplaceAll(entry.path, `\`, `\\`)
		name = strings.ReplaceAll(name, `"`, `\"`)
		if _, err := fmt.Fprintf(commands, "set_inode_field \"/%s\" mode %#o\n", name, mode); err != nil {
			_ = commands.Close()
			return err
		}
	}
	if err := commands.Close(); err != nil {
		return err
	}
	output, err := runFormatterCommand(ctx, debugfsPath, "-w", "-f", commandPath, imagePath)
	if err != nil {
		return fmt.Errorf("debugfs restore modes: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func cloneSparseFile(source, destination string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("cp", "-c", source, destination)
	case "linux":
		command = exec.Command("cp", "--reflink=auto", "--sparse=always", source, destination)
	default:
		return fmt.Errorf("sparse overlay clone is unsupported on %s", runtime.GOOS)
	}
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	cloneErr := fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	_ = os.Remove(destination)
	if copyErr := copySparseFile(source, destination); copyErr != nil {
		return fmt.Errorf("clone overlay template %q to %q failed (%v); sparse copy failed: %w", source, destination, cloneErr, copyErr)
	}
	return nil
}

func copySparseFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open source image: %w", err)
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() {
		if err == nil {
			err = fmt.Errorf("not a regular file")
		}
		return fmt.Errorf("inspect source image: %w", err)
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create sparse destination: %w", err)
	}
	defer output.Close()
	const blockSize = 1 << 20
	buffer := make([]byte, blockSize)
	for offset := int64(0); offset < info.Size(); {
		length := int64(len(buffer))
		if remaining := info.Size() - offset; remaining < length {
			length = remaining
		}
		read, readErr := input.ReadAt(buffer[:length], offset)
		if read > 0 && !zeroBlock(buffer[:read]) {
			written, writeErr := output.WriteAt(buffer[:read], offset)
			if writeErr != nil {
				return fmt.Errorf("write sparse image at offset %d: %w", offset, writeErr)
			}
			if written != read {
				return fmt.Errorf("write sparse image at offset %d: %w", offset, io.ErrShortWrite)
			}
		}
		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("read source image at offset %d: %w", offset, readErr)
		}
		if read != int(length) {
			return fmt.Errorf("read source image at offset %d: %w", offset, io.ErrUnexpectedEOF)
		}
		offset += int64(read)
	}
	if err := output.Truncate(info.Size()); err != nil {
		return fmt.Errorf("size sparse image: %w", err)
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("sync sparse image: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close sparse image: %w", err)
	}
	return nil
}

func zeroBlock(block []byte) bool {
	for _, value := range block {
		if value != 0 {
			return false
		}
	}
	return true
}
