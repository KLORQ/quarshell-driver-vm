package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateRootfsTarPath enforces the compatibility staging boundary: a
// rootfs archive must be a regular file exactly one request directory below a
// configured staging root and stay within the configured upload limit.
func validateRootfsTarPath(raw, stagingDir string, maxBytes int64) (string, error) {
	file, path, err := openRootfsTar(raw, stagingDir, maxBytes)
	if err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close rootfs tar %q after validation: %w", path, err)
	}
	return path, nil
}

// openRootfsTar resolves the staged archive using a descriptor rooted at the
// configured staging directory. The returned file pins the object inspected
// here, so a rename or symlink replacement cannot redirect the later import.
func openRootfsTar(raw, stagingDir string, maxBytes int64) (*os.File, string, error) {
	if raw == "" {
		return nil, "", fmt.Errorf("rootfs tar path is empty")
	}
	if maxBytes <= 0 {
		return nil, "", fmt.Errorf("rootfs tar maximum size must be positive")
	}
	root, err := filepath.Abs(stagingDir)
	if err != nil {
		return nil, "", fmt.Errorf("resolve rootfs tar staging directory: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, "", fmt.Errorf("rootfs tar staging directory is unavailable at %q: %w", stagingDir, err)
	}
	path, err := filepath.Abs(raw)
	if err != nil {
		return nil, "", fmt.Errorf("resolve rootfs tar path: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, "", fmt.Errorf("rootfs tar request directory is unavailable: %w", err)
	}
	path = filepath.Join(parent, filepath.Base(path))
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || hasParentTraversal(relative) {
		return nil, "", fmt.Errorf("rootfs tar path %q is outside staging directory %q", path, root)
	}
	components := strings.Split(filepath.ToSlash(relative), "/")
	if len(components) != 2 {
		return nil, "", fmt.Errorf("rootfs tar path %q must be inside a request subdirectory of staging directory %q", path, root)
	}
	file, err := openRootfsArchive(root, components[0], components[1])
	if err != nil {
		return nil, "", fmt.Errorf("open rootfs tar %q without following staging symlinks: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("inspect rootfs tar %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, "", fmt.Errorf("rootfs tar path %q is not a regular file", path)
	}
	if info.Size() > maxBytes {
		_ = file.Close()
		return nil, "", fmt.Errorf("rootfs tar %q is %d bytes, exceeding the %d byte limit", path, info.Size(), maxBytes)
	}
	return file, path, nil
}

func hasParentTraversal(path string) bool {
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		if component == ".." {
			return true
		}
	}
	return false
}
