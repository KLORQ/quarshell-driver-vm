//go:build unix

package vm

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func copyOCIXattrs(source, destination *os.File) error {
	if source == nil || destination == nil {
		return fmt.Errorf("xattr source and destination files are required")
	}
	sourceFD := int(source.Fd())
	size, err := unix.Flistxattr(sourceFD, nil)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	if err != nil {
		return err
	}
	if size == 0 {
		return nil
	}
	namesBuffer := make([]byte, size)
	actual, err := unix.Flistxattr(sourceFD, namesBuffer)
	if err != nil {
		return err
	}
	if actual > len(namesBuffer) {
		return fmt.Errorf("xattr name list grew while reading")
	}
	namesBuffer = namesBuffer[:actual]
	for len(namesBuffer) > 0 {
		separator := strings.IndexByte(string(namesBuffer), 0)
		if separator <= 0 {
			return fmt.Errorf("malformed xattr name list")
		}
		name := string(namesBuffer[:separator])
		namesBuffer = namesBuffer[separator+1:]
		valueSize, err := unix.Fgetxattr(sourceFD, name, nil)
		if err != nil {
			return fmt.Errorf("read xattr %q size: %w", name, err)
		}
		value := make([]byte, valueSize)
		actualValue, err := unix.Fgetxattr(sourceFD, name, value)
		if err != nil {
			return fmt.Errorf("read xattr %q: %w", name, err)
		}
		if actualValue > len(value) {
			return fmt.Errorf("xattr %q grew while reading", name)
		}
		if err := unix.Fsetxattr(int(destination.Fd()), name, value[:actualValue], 0); err != nil {
			return fmt.Errorf("write xattr %q: %w", name, err)
		}
	}
	return nil
}
