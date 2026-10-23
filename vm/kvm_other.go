//go:build !linux

package vm

import "fmt"

func checkKVMDevice(path string) error {
	return fmt.Errorf("KVM device %q can only be validated on a Linux host", path)
}
