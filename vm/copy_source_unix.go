//go:build darwin || linux

package vm

import (
	"fmt"
	"io"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

func readCopySource(path string, maxBytes int64) ([]byte, fs.FileMode, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open VM copy-to source without following symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, 0, fmt.Errorf("inspect VM copy-to source: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 || stat.Size > maxBytes {
		return nil, 0, fmt.Errorf("vm copy-to source must be a regular file no larger than %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read VM copy-to source: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, 0, fmt.Errorf("vm copy-to source must be a regular file no larger than %d bytes", maxBytes)
	}
	return data, fs.FileMode(stat.Mode).Perm(), nil
}
