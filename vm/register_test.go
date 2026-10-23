package vm

import (
	"testing"

	"github.com/KLORQ/quarshell-driver/driver"
)

func TestVMBackendRegistersFromItsOwnModule(t *testing.T) {
	info, ok := driver.RegisteredBackendInfo("vm")
	if !ok {
		t.Fatal("VM backend was not registered by importing the VM module")
	}
	if info.ID != "vm" || info.Version == "" || info.ConfigSchemaVersion == "" || info.Capabilities == nil {
		t.Fatalf("incomplete VM backend metadata: %+v", info)
	}
	if hasValidator, err := driver.ValidateRegisteredBackendConfig("vm", map[string]any{"unknown": true}); !hasValidator || err == nil {
		t.Fatalf("unknown VM config was not rejected: validator=%t err=%v", hasValidator, err)
	}
}
