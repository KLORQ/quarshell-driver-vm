//go:build linux

package vm

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	kvmGetAPIVersion = 0xAE00
	kvmAPIVersion    = 12
)

func checkKVMDevice(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("KVM device path is empty")
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("libkrun requires read/write access to KVM device %q: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect KVM device %q: %w", path, err)
	}
	if !isKVMCharacterDevice(info) {
		return fmt.Errorf("KVM device %q is not a character device", path)
	}
	// KVM_GET_API_VERSION is an _IO ioctl and requires a zero third
	// argument. IoctlGetInt passes a pointer, which the KVM driver rejects
	// with EINVAL even when /dev/kvm is usable.
	version, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(kvmGetAPIVersion), 0)
	if errno != 0 {
		return fmt.Errorf("query KVM API on %q: %w", path, errno)
	}
	if int(version) != kvmAPIVersion {
		return fmt.Errorf("KVM device %q reports API version %d; libkrun requires version %d", path, version, kvmAPIVersion)
	}
	return nil
}

func isKVMCharacterDevice(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice != 0
}
