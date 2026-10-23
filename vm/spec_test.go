//go:build darwin || linux

package vm

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-driver/driver"
)

func TestValidateSupportedSpecRejectsUnimplementedCapabilities(t *testing.T) {
	tests := []struct {
		name  string
		field string
		set   func(*vmCreateSpec)
	}{
		{"workspace", "workspace", func(spec *vmCreateSpec) { spec.Workspace = "/workspace" }},
		{"gateway identity", "gateway_id", func(spec *vmCreateSpec) { spec.GatewayID = "gateway" }},
		{"mount override", "i_know", func(spec *vmCreateSpec) { spec.IKnow = true }},
		{"hardening override", "no_harden", func(spec *vmCreateSpec) { spec.NoHarden = true }},
		{"display mode", "display_mode", func(spec *vmCreateSpec) { spec.DisplayMode = "novnc" }},
		{"display port", "display_port", func(spec *vmCreateSpec) { spec.DisplayPort = 5900 }},
		{"display password", "display_password", func(spec *vmCreateSpec) { spec.DisplayPassword = "secret" }},
		{"labels", "labels", func(spec *vmCreateSpec) { spec.Labels = map[string]string{"team": "test"} }},
		{"extra hosts", "extra_hosts", func(spec *vmCreateSpec) { spec.ExtraHosts = []string{"host:127.0.0.1"} }},
		{"GPU", "gpu", func(spec *vmCreateSpec) { spec.GPU = true }},
		{"GPU count", "gpu", func(spec *vmCreateSpec) { spec.GPUCount = 1 }},
		{"CDI devices", "gpu", func(spec *vmCreateSpec) { spec.CDIDevices = []string{"nvidia.com/gpu=0"} }},
		{"PID limit", "pids_limit", func(spec *vmCreateSpec) { spec.PidsLimit = 128 }},
		{"proxy image", "proxy_image", func(spec *vmCreateSpec) { spec.ProxyImage = "proxy:latest" }},
		{"published ports", "publish_ports", func(spec *vmCreateSpec) { spec.PublishPorts = []driver.PortPublish{{Host: 8080, Guest: 80}} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := vmCreateSpec{Name: "sandbox", Image: "fixture:latest"}
			tt.set(&spec)
			err := validateSupportedSpec(spec)
			if err == nil || !strings.Contains(err.Error(), "unsupported spec fields: "+tt.field) {
				t.Fatalf("validateSupportedSpec() error = %v, want unsupported field %q", err, tt.field)
			}
		})
	}
}

func TestValidateResourceLimitsRejectsValuesThatWouldBeChanged(t *testing.T) {
	tests := []struct {
		name      string
		cpu       float64
		memory    int64
		wantError string
	}{
		{name: "negative cpu", cpu: -0.5, wantError: "CPU limit must be finite and non-negative"},
		{name: "nan cpu", cpu: math.NaN(), wantError: "CPU limit must be finite and non-negative"},
		{name: "infinite cpu", cpu: math.Inf(1), wantError: "CPU limit must be finite and non-negative"},
		{name: "cpu rounds above uint8", cpu: 255.01, wantError: "exceeds libkrun maximum"},
		{name: "negative memory", memory: -1, wantError: "memory limit must be non-negative"},
		{name: "memory exceeds uint32 mebibytes", memory: int64(^uint32(0))*(1<<20) + 1, wantError: "memory limit exceeds libkrun maximum"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResourceLimits(tt.cpu, tt.memory)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validateResourceLimits(%v, %d) error = %v, want %q", tt.cpu, tt.memory, err, tt.wantError)
			}
		})
	}
}

func TestValidateResourceLimitsAllowsDefaultsAndRepresentableValues(t *testing.T) {
	for _, tt := range []struct {
		cpu    float64
		memory int64
	}{{0, 0}, {0.1, 1}, {255, int64(^uint32(0)) * (1 << 20)}} {
		if err := validateResourceLimits(tt.cpu, tt.memory); err != nil {
			t.Errorf("validateResourceLimits(%v, %d) error = %v", tt.cpu, tt.memory, err)
		}
	}
}

func TestValidateSupportedSpecAllowsImplementedFields(t *testing.T) {
	spec := vmCreateSpec{
		Name: "sandbox", Image: "fixture:latest", Command: []string{"/bin/sh"},
		Env: []string{"LANG=C"}, CPU: 2, MemoryBytes: 1 << 30,
		DriverConfigJSON: `{"rootfs_tar_path":"/var/lib/cautem/rootfs.tar"}`,
		ProxyBin:         "/usr/bin/cautem", PolicyPath: "/var/lib/cautem/policy.yaml", ProxyPort: 3128,
		InitBin: "/usr/bin/cautem-init", SupervisorBin: "/usr/bin/cautem-supervisor",
		EnableSSH: true, SSHBin: "/usr/bin/cautem-sshd", PersistVolume: true,
	}
	if err := validateSupportedSpec(spec); err != nil {
		t.Fatalf("validateSupportedSpec() error = %v", err)
	}
}

func TestValidateSupportedSpecAllowsPolicyBrokerFields(t *testing.T) {
	spec := vmCreateSpec{
		Name: "sandbox", ProxyBin: "/usr/bin/cautem", PolicyPath: "/var/lib/cautem/policy.yaml",
		ProxyEnv: []string{"CAUTEM_SANDBOX_TOKEN=secret"}, ProxyPort: 3128,
	}
	if err := validateSupportedSpec(spec); err != nil {
		t.Fatalf("validateSupportedSpec() rejected policy broker fields: %v", err)
	}
}

func TestGuestOverlayWorkspaceMapsToVMWithoutHostMount(t *testing.T) {
	request := driver.BackendCreateRequest{
		SandboxID: "workspace-vm", Name: "workspace-vm",
		Workspace: driver.WorkspaceTarget{Kind: driver.WorkspaceGuestOverlay, ID: "team-a", Persist: true},
		Labels:    map[string]string{driver.WorkspaceLabel: "team-a", driver.GatewayIDLabel: "gateway-1"},
		Workload: driver.WorkloadSpec{
			Image: "alpine:3.22", Command: []string{"/bin/sh"}, TTY: true, AwaitMainProcessAttachment: true,
		},
		Network: driver.NetworkSpec{GatewayID: "gateway-1", GatewayURL: "https://gateway.internal"},
	}
	spec, err := vmSpecFromBackendRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Workspace != "" || !spec.PersistVolume || !spec.TTY || !spec.AwaitMainProcessAttachment {
		t.Fatalf("guest overlay became host workspace settings: %+v", spec)
	}
	if err := New().validateCreateSpec(spec); err != nil {
		t.Fatalf("guest overlay VM spec rejected: %v", err)
	}
}

func TestValidateNetworkBrokerSpecRequiresPairedConfigAndSafeEnvironment(t *testing.T) {
	for _, spec := range []vmCreateSpec{
		{ProxyBin: "/usr/bin/cautem"},
		{PolicyPath: "/var/lib/cautem/policy.yaml"},
		{ProxyEnv: []string{"TOKEN=secret"}},
		{ProxyPort: 3128},
	} {
		if err := validateNetworkBrokerSpec(spec); err == nil || !strings.Contains(err.Error(), "requires both proxy_bin and policy_path") {
			t.Errorf("validateNetworkBrokerSpec(%+v) error = %v", spec, err)
		}
	}
	if err := validateNetworkBrokerEnvironment([]string{"LD_PRELOAD=/tmp/evil.so"}); err == nil || !strings.Contains(err.Error(), "dynamic loader") {
		t.Fatalf("unsafe broker environment error = %v", err)
	}
	if err := validateNetworkBrokerEnvironment([]string{"TOKEN=one", "TOKEN=two"}); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate broker environment error = %v", err)
	}
	if err := validateNetworkBrokerEnvironment([]string{"CAUTEM_HOST_PARENT_LIVENESS=0"}); err == nil || !strings.Contains(err.Error(), "lifecycle controls") {
		t.Fatalf("parent-liveness override error = %v", err)
	}
}

func TestValidateNetworkBrokerSpecAcceptsPrivatePolicyAndExecutable(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "cautem")
	if err := os.WriteFile(binary, []byte("proxy executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := vmCreateSpec{ProxyBin: binary, PolicyPath: policy, ProxyEnv: []string{"TOKEN=secret"}}
	if err := validateNetworkBrokerSpec(spec); err != nil {
		t.Fatalf("validateNetworkBrokerSpec() error = %v", err)
	}
	spec.ProxyPort = 65536
	if err := validateNetworkBrokerSpec(spec); err == nil || !strings.Contains(err.Error(), "between 1 and 65535") {
		t.Fatalf("invalid proxy port error = %v", err)
	}
}

func TestTokenAwareStartDoesNotRequireOptionalSSHAssets(t *testing.T) {
	spec := vmLaunchSpec{
		vmCreateSpec: vmCreateSpec{ProxyBin: "/usr/bin/quarshell-proxy", PolicyPath: "/etc/quarshell/policy.yaml"},
		User:         "sandbox",
	}
	spec.SupervisorBin = "/usr/bin/cautem-supervisor"
	if err := validateTokenAwareLaunchSpec(spec); err != nil {
		t.Fatalf("token-aware start rejected a VM without optional SSH assets: %v", err)
	}
	spec.SupervisorBin = ""
	if err := validateTokenAwareLaunchSpec(spec); err == nil {
		t.Fatal("token-aware start accepted a missing guest supervisor")
	}
}

func TestValidateGuestRuntimeAssetsRequiresCompleteSupervisorAndSSHContracts(t *testing.T) {
	dir := t.TempDir()
	makeExecutable := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("binary"), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	proxy := makeExecutable("cautem")
	init := makeExecutable("cautem-init")
	supervisor := makeExecutable("cautem-supervisor")
	sshd := makeExecutable("cautem-sshd")
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := vmCreateSpec{ProxyBin: proxy, PolicyPath: policy, InitBin: init}
	if err := validateGuestRuntimeAssets(base); err == nil || !strings.Contains(err.Error(), "requires supervisor_bin or SSH relay") {
		t.Fatalf("unused init asset error = %v", err)
	}
	base.SupervisorBin = supervisor
	if err := validateGuestRuntimeAssets(base); err != nil {
		t.Fatalf("complete supervisor assets rejected: %v", err)
	}
	base.EnableSSH = true
	if err := validateGuestRuntimeAssets(base); err == nil || !strings.Contains(err.Error(), "both ssh=true and ssh_bin") {
		t.Fatalf("incomplete SSH config error = %v", err)
	}
	base.SSHBin = sshd
	if err := validateGuestRuntimeAssets(base); err != nil {
		t.Fatalf("complete SSH assets rejected: %v", err)
	}
	base.Name = "sandbox"
	base.Command = []string{"/bin/sh", "-c", "sleep infinity"}
	base.DriverConfigJSON = `{"rootfs_tar_path":"/var/lib/cautem/rootfs.tar"}`
	base.MainProcessRestartPolicy = "on-failure"
	if err := New().validateCreateSpec(base); err != nil {
		t.Fatalf("complete supervisor/SSH VM spec with restart policy rejected: %v", err)
	}
	base.SupervisorBin = ""
	if err := New().validateCreateSpec(base); err == nil || !strings.Contains(err.Error(), "restart policy requires supervisor_bin") {
		t.Fatalf("restart policy without supervisor error = %v", err)
	}
	base.MainProcessRestartPolicy = "sometimes"
	if err := New().validateCreateSpec(base); err == nil || !strings.Contains(err.Error(), "must be never, on-failure, or always") {
		t.Fatalf("invalid restart policy error = %v", err)
	}
}

func TestValidateSpecAllowsRootfsTarWithImageSelector(t *testing.T) {
	d := NewWithHostConfig(HostConfig{DefaultImage: "registry.example/team/default:stable"})
	spec := vmCreateSpec{
		Name:             "sandbox",
		Image:            "registry.example/team/requested:stable",
		DriverConfigJSON: `{"rootfs_tar_path":"/var/lib/cautem/rootfs.tar"}`,
	}
	if err := d.validateCreateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec() rejected OpenShell rootfs tar and image combination: %v", err)
	}

	// Without an explicit image the operator default remains available as the
	// existing fallback for rootfs tar requests.
	spec.Image = ""
	if err := d.validateCreateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec() rejected rootfs tar with configured default image: %v", err)
	}
}

func TestValidateGatewayRuntimePassesCompleteHostPreflight(t *testing.T) {
	root := t.TempDir()
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lib, fw, err := libKrunLibraryNames(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{lib, fw} {
		if err := os.WriteFile(filepath.Join(runtimeDir, name), []byte("runtime"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	worker := filepath.Join(root, "worker")
	guest := filepath.Join(root, "guest")
	for _, path := range []string{worker, guest} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	d := NewWithHostConfig(HostConfig{RuntimeDir: runtimeDir, KVMDevice: "/dev/null", WorkerPath: worker, GuestAgentPath: guest,
		WorkerTeamID: "CAUTEMTEAM",
		workerSignatureVerifier: func(path, teamID string) error {
			if path != worker || teamID != "CAUTEMTEAM" {
				return fmt.Errorf("unexpected signature verification inputs %q/%q", path, teamID)
			}
			return nil
		},
		kvmDeviceCheck:  func(string) error { return nil },
		workerIsolation: func() (workerIsolationConfig, error) { return workerIsolationConfig{NoHostMounts: true}, nil },
	})
	if err := d.ValidateRuntimeContract(context.Background()); err != nil {
		t.Fatalf("ValidateRuntimeContract() error = %v; want successful host preflight", err)
	}
}

func TestValidateGatewayWorkerTrustRequiresConfiguredIdentity(t *testing.T) {
	worker := filepath.Join(t.TempDir(), "worker")
	called := false
	verify := func(path, teamID string) error {
		called = true
		if path != worker || teamID != "TEAM123" {
			return fmt.Errorf("unexpected verification request")
		}
		return nil
	}
	if err := validateGatewayWorkerTrust(worker, HostConfig{workerSignatureVerifier: verify}); err == nil || !strings.Contains(err.Error(), "CAUTEM_VM_WORKER_SHA256") {
		t.Fatalf("missing trusted worker identity error = %v", err)
	}
	if called {
		t.Fatal("signature verifier ran without a configured trusted Team ID")
	}
	if err := validateGatewayWorkerTrust(worker, HostConfig{WorkerTeamID: " TEAM123 ", workerSignatureVerifier: verify}); err != nil {
		t.Fatalf("valid worker signature was rejected: %v", err)
	}
	if !called {
		t.Fatal("configured worker signature verifier was not called")
	}
}

func TestValidateGatewayWorkerSHA256TrustRequiresAdHocSignatureAndExactDigest(t *testing.T) {
	worker := filepath.Join(t.TempDir(), "worker")
	content := []byte("ad-hoc signed VM worker fixture")
	if err := os.WriteFile(worker, content, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	verified := false
	host := HostConfig{
		WorkerSHA256: digest,
		workerAdHocSignatureVerifier: func(path string) error {
			verified = path == worker
			if !verified {
				return fmt.Errorf("unexpected worker path %q", path)
			}
			return nil
		},
	}
	if err := validateGatewayWorkerTrust(worker, host); err != nil {
		t.Fatalf("pinned ad-hoc worker rejected: %v", err)
	}
	if !verified {
		t.Fatal("ad-hoc worker signature was not verified")
	}
	if err := os.WriteFile(worker, []byte("replaced worker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateGatewayWorkerTrust(worker, host); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("replacement worker digest error = %v, want hash pin rejection", err)
	}
	if err := validateGatewayWorkerTrust(worker, HostConfig{WorkerSHA256: "ABC", workerAdHocSignatureVerifier: func(string) error { return nil }}); err == nil || !strings.Contains(err.Error(), "lowercase hexadecimal") {
		t.Fatalf("malformed worker hash error = %v", err)
	}
}

func TestValidateSpecAcceptsOCIReferencesWithoutRootfsUpload(t *testing.T) {
	d := New()
	spec := vmCreateSpec{Name: "registry-image", Image: "registry.example/team/sandbox:stable"}
	if err := d.validateCreateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec() rejected registry image: %v", err)
	}
	spec.Image = "https://registry.example/team/sandbox:stable"
	if err := d.validateCreateSpec(spec); err == nil || !strings.Contains(err.Error(), "invalid OCI image reference") {
		t.Fatalf("ValidateSpec() invalid image reference error = %v", err)
	}
}

func TestValidateSpecUsesConfiguredDefaultImage(t *testing.T) {
	d := NewWithHostConfig(HostConfig{DefaultImage: "registry.example/team/sandbox:stable"})
	if err := d.validateCreateSpec(vmCreateSpec{Name: "default-image"}); err != nil {
		t.Fatalf("ValidateSpec() rejected configured default image: %v", err)
	}
	if err := d.validateCreateSpec(vmCreateSpec{Name: "explicit-image", Image: "registry.example/team/requested:v2"}); err != nil {
		t.Fatalf("ValidateSpec() rejected explicit image: %v", err)
	}
	d.host.DefaultImage = "not an OCI image reference"
	if err := d.validateCreateSpec(vmCreateSpec{Name: "invalid-default"}); err == nil || !strings.Contains(err.Error(), "invalid OCI image reference") {
		t.Fatalf("ValidateSpec() invalid default image error = %v", err)
	}
}
