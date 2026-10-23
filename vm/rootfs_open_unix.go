//go:build darwin || linux

package vm

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openRootfsArchive(root, requestDir, fileName string) (*os.File, error) {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open staging directory: %w", err)
	}
	defer unix.Close(rootFD)

	dirFD, err := unix.Openat(rootFD, requestDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open request directory without following symlinks: %w", err)
	}
	defer unix.Close(dirFD)

	fd, err := unix.Openat(dirFD, fileName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open archive without following symlinks: %w", err)
	}
	return os.NewFile(uintptr(fd), fileName), nil
}
