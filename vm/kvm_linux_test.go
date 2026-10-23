//go:build linux

package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckKVMDeviceRejectsRegularFileAndNonKVMCharacterDevice(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "kvm")
	if err := os.WriteFile(regular, []byte("not a device"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkKVMDevice(regular); err == nil || !strings.Contains(err.Error(), "not a character device") {
		t.Fatalf("checkKVMDevice(regular file) error = %v; want character-device rejection", err)
	}

	if err := checkKVMDevice("/dev/null"); err == nil || !strings.Contains(err.Error(), "query KVM API") {
		t.Fatalf("checkKVMDevice(/dev/null) error = %v; want KVM ioctl rejection", err)
	}
}
