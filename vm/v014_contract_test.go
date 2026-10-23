//go:build darwin || linux

package vm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These cases translate OpenShell's validate_vm_sandbox_* tests in
// crates/openshell-driver-vm/src/driver.rs (pinned upstream commit
// 77c5ff6e20c98b3674616ecf35b2464f2b8e57ca). Runtime provisioning remains a
// separate unimplemented contract.
func TestCompatVMConfigValidationContract(t *testing.T) {
	tests := []struct {
		name, config, want string
	}{
		{
			name:   "unknown driver config field",
			config: `{"gpu_device_id":["0000:2d:00.0"]}`,
			want:   "unknown field",
		},
		{
			name:   "empty GPU device IDs",
			config: `{"gpu_device_ids":[]}`,
			want:   "non-empty list",
		},
		{
			name:   "invalid config shape",
			config: `{"gpu_device_ids":"0000:2d:00.0"}`,
			want:   "invalid vm driver_config",
		},
		{
			name:   "null config shape",
			config: `null`,
			want:   "must be an object",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New().createSandbox(context.Background(), vmCreateSpec{
				Name:             "contract-sandbox",
				Image:            "cautem-sandbox:local",
				GPU:              true,
				DriverConfigJSON: tt.config,
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Create() error = %v; want error containing %q", err, tt.want)
			}
		})
	}
}

func TestCompatVMRejectsGPUBeforeRootfsOrStateSideEffects(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	missingTar := filepath.Join(root, "missing-rootfs.tar")
	d := NewWithHostConfig(HostConfig{StateDir: stateDir, RootfsTarDir: root})
	_, err := d.createSandbox(context.Background(), vmCreateSpec{
		Name: "gpu-without-vfio", Image: "cautem-sandbox:local", GPU: true,
		DriverConfigJSON: `{"gpu_device_ids":["0000:2d:00.0"],"rootfs_tar_path":"` + missingTar + `"}`,
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported spec fields: gpu") {
		t.Fatalf("Create() error = %v; want fail-closed unsupported GPU preflight", err)
	}
	if _, statErr := os.Stat(missingTar); !os.IsNotExist(statErr) {
		t.Fatalf("missing rootfs tar unexpectedly changed: stat error=%v", statErr)
	}
	if _, statErr := os.Stat(stateDir); !os.IsNotExist(statErr) {
		t.Fatalf("GPU request allocated VM state before rejection: stat error=%v", statErr)
	}
}

func TestCompatVMRejectsGPUDeviceIDsWithoutGPURequest(t *testing.T) {
	_, err := New().createSandbox(context.Background(), vmCreateSpec{
		Name:             "contract-sandbox",
		Image:            "cautem-sandbox:local",
		DriverConfigJSON: `{"gpu_device_ids":["0000:2d:00.0"]}`,
	})
	if err == nil || !strings.Contains(err.Error(), "requires a GPU request") {
		t.Fatalf("Create() error = %v; want GPU request requirement", err)
	}
}

func TestCompatVMRejectsMultipleGPUDeviceIDs(t *testing.T) {
	_, err := New().createSandbox(context.Background(), vmCreateSpec{
		Name:             "contract-sandbox",
		Image:            "cautem-sandbox:local",
		GPU:              true,
		DriverConfigJSON: `{"gpu_device_ids":["0000:2d:00.0","0000:31:00.0"]}`,
	})
	if err == nil || !strings.Contains(err.Error(), "at most one gpu_device_ids") {
		t.Fatalf("Create() error = %v; want at most one GPU device ID", err)
	}
}

func TestCompatVMRejectsPathUnsafeSandboxNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../escape", "/tmp/escape", "nested/path", "nested\\path", "bad\nid", "bad id", "unicodé", strings.Repeat("a", 129)} {
		t.Run(name, func(t *testing.T) {
			_, err := New().createSandbox(context.Background(), vmCreateSpec{Name: name, Image: "cautem-sandbox:local"})
			if err == nil || (!strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "unsafe")) {
				t.Fatalf("Create(%q) error = %v; want invalid/unsafe sandbox name", name, err)
			}
		})
	}
}

func TestCompatVMDriverConfigAcceptsSingleGPUAndRootfsPath(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{"gpu_device_ids":["0000:2d:00.0"],"rootfs_tar_path":"/var/lib/cautem/rootfs.tar"}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() error = %v", err)
	}
	if config.GPUDeviceIDs == nil || len(*config.GPUDeviceIDs) != 1 || (*config.GPUDeviceIDs)[0] != "0000:2d:00.0" {
		t.Fatalf("GPU device IDs = %v; want one PCI device ID", config.GPUDeviceIDs)
	}
	if config.RootfsTarPath != "/var/lib/cautem/rootfs.tar" {
		t.Fatalf("rootfs_tar_path = %q; want configured path", config.RootfsTarPath)
	}
}

func TestVMDriverConfigValidatesHostRelayEndpointTLSContract(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{"grpc_endpoint":"gateway.internal:7443","rootfs_tar_path":"/var/lib/cautem/rootfs.tar"}`)
	if err != nil || config.GRPCEndpoint != "gateway.internal:7443" {
		t.Fatalf("ParseSandboxDriverConfig() = %+v, %v", config, err)
	}
	for _, raw := range []string{
		`{"grpc_endpoint":"https://gateway.internal:7443"}`,
		`{"grpc_endpoint":"http://gateway.internal:7443","guest_tls_ca":"/tls/ca.pem","guest_tls_cert":"/tls/cert.pem","guest_tls_key":"/tls/key.pem"}`,
		`{"grpc_endpoint":"grpc://gateway.internal:7443"}`,
		`{"grpc_endpoint":"user:secret@gateway.internal:7443"}`,
	} {
		if _, err := ParseSandboxDriverConfig(raw); err == nil {
			t.Errorf("ParseSandboxDriverConfig(%s) accepted invalid relay config", raw)
		}
	}
}
