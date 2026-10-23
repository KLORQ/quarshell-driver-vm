//go:build darwin || linux

package vm

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/isolation"
)

func TestValidateNetworkBrokerConfigRequiresPrivatePolicyAndSafeEnvironment(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "quarshell")
	if err := os.WriteFile(binary, []byte("proxy executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp("/tmp", "vm-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := networkBrokerConfig{
		Binary: binary, Policy: policy, Socket: filepath.Join(socketDir, "proxy.sock"),
		SSHSocket: filepath.Join(socketDir, "ssh.sock"), ControlSocket: filepath.Join(socketDir, "control.sock"),
		LogDir: filepath.Join(dir, "logs"), ProxyEnv: []string{"QUARSHELL_SANDBOX_TOKEN=secret"},
	}
	if _, err := validateNetworkBrokerConfig(config); err != nil {
		t.Fatalf("validateNetworkBrokerConfig() error = %v", err)
	}
	config.ProxyEnv = []string{"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib"}
	if _, err := validateNetworkBrokerConfig(config); err == nil || !strings.Contains(err.Error(), "dynamic loader") {
		t.Fatalf("unsafe environment error = %v", err)
	}
	config.ProxyEnv = []string{
		"QUARSHELL_SANDBOX_TOKEN=secret",
		"HTTPS_PROXY=https://proxy.example.test:8443",
		"https_proxy=https://proxy.example.test:8443",
		"NO_PROXY=localhost,.internal.test",
		"QUARSHELL_PROXY_AUTH_FILE=/etc/quarshell/proxy-auth",
		"QUARSHELL_PROXY_CA_BUNDLE=/etc/quarshell/proxy-ca.pem",
		"QUARSHELL_PROXY_CONNECT_BY_HOSTNAME=true",
		"OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET=tcp:192.0.2.10:8081",
	}
	environment, err := networkBrokerProcessEnvironment(config)
	if err != nil {
		t.Fatalf("networkBrokerProcessEnvironment() error = %v", err)
	}
	if !containsEnv(environment, "QUARSHELL_SSH_SOCKET="+config.SSHSocket) || !containsEnv(environment, "QUARSHELL_SUPERVISOR_CONTROL_SOCKET="+config.ControlSocket) {
		t.Fatalf("proxy relay socket configuration missing: %q", environment)
	}
	if containsEnv(environment, "HOME=") || containsEnv(environment, "QUARSHELL_VM_CONTROL_TOKEN=") {
		t.Fatalf("host ambient environment leaked to proxy: %q", environment)
	}
	for _, expected := range []string{
		"HTTPS_PROXY=https://proxy.example.test:8443", "https_proxy=https://proxy.example.test:8443",
		"NO_PROXY=localhost,.internal.test", "QUARSHELL_PROXY_AUTH_FILE=/etc/quarshell/proxy-auth",
		"QUARSHELL_PROXY_CA_BUNDLE=/etc/quarshell/proxy-ca.pem",
		"QUARSHELL_PROXY_CONNECT_BY_HOSTNAME=true",
		"OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET=tcp:192.0.2.10:8081",
	} {
		if !containsEnv(environment, expected) {
			t.Errorf("host broker environment missing operator proxy setting %q: %q", expected, environment)
		}
	}
	config.ProxyEnv = []string{"QUARSHELL_SANDBOX_TOKEN=secret", "QUARSHELL_SSH_SOCKET=/tmp/attacker.sock"}
	if _, err := validateNetworkBrokerConfig(config); err == nil || !strings.Contains(err.Error(), "cannot override") {
		t.Fatalf("proxy SSH socket override error = %v", err)
	}
	config.ProxyEnv = []string{"QUARSHELL_SANDBOX_TOKEN=secret"}
	config.Socket = filepath.Join(socketDir, strings.Repeat("x", 100)+".sock")
	if _, err := validateNetworkBrokerConfig(config); err == nil || !strings.Contains(err.Error(), "socket path limit") {
		t.Fatalf("long socket path error = %v", err)
	}
	missingSocketRoot := filepath.Join(t.TempDir(), "lazy-socket-root")
	if err := validateNetworkBrokerSocketDirectory(missingSocketRoot, missingSocketRoot); err != nil {
		t.Fatalf("validateNetworkBrokerSocketDirectory() rejected the expected lazy socket root: %v", err)
	}
	if _, err := os.Lstat(missingSocketRoot); !os.IsNotExist(err) {
		t.Fatalf("socket directory validation created the missing root: %v", err)
	}
	if err := validateNetworkBrokerSocketDirectory(missingSocketRoot, filepath.Join(missingSocketRoot, "different")); err == nil {
		t.Fatal("validation allowed a missing non-worker socket directory")
	}
}

func TestWaitForProxyControlSocketDoesNotConsumeAConnection(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "vm-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "ctl.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			accepted <- struct{}{}
		}
	}()
	process := &networkBrokerProcess{done: make(chan struct{})}
	if err := waitForProxyControlSocket(process, socket, time.Second); err != nil {
		t.Fatalf("waitForProxyControlSocket() error = %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("control socket readiness check consumed an incoming connection")
	default:
	}
}

func TestWorkerNetworkBrokerConfigContainsOnlySocketReferences(t *testing.T) {
	full := &networkBrokerConfig{
		Binary: "/opt/quarshell/quarshell", Policy: "/private/policy.yaml",
		Socket: "/private/broker.sock", SSHSocket: "/private/ssh.sock",
		ControlSocket: "/private/control.sock", LogDir: "/private/logs",
		ProxyEnv: []string{"QUARSHELL_GATEWAY_TOKEN=secret-value"},
	}
	worker := workerNetworkBrokerConfig(full)
	if worker == nil {
		t.Fatal("worker broker config is nil")
	}
	if worker.Socket != full.Socket || worker.SSHSocket != full.SSHSocket || worker.ControlSocket != full.ControlSocket {
		t.Fatalf("worker socket refs = %+v", worker)
	}
	if worker.Binary != "" || worker.Policy != "" || worker.LogDir != "" || len(worker.ProxyEnv) != 0 {
		t.Fatalf("worker config retained host broker settings or credentials: %+v", worker)
	}
	if workerNetworkBrokerConfig(nil) != nil {
		t.Fatal("nil broker config must stay nil")
	}
}

func TestPrepareBrokerCredentialMovesBearerIntoPrivateFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := networkBrokerConfig{LogDir: filepath.Join(dir, "sandbox")}
	filtered, path, err := prepareBrokerCredential(config, []string{
		"QUARSHELL_SANDBOX_TOKEN=secret-token",
		"QUARSHELL_GATEWAY_URL=https://gateway.example.test",
	})
	if err != nil {
		t.Fatalf("prepareBrokerCredential() error = %v", err)
	}
	if containsEnv(filtered, "QUARSHELL_SANDBOX_TOKEN=secret-token") || !containsEnv(filtered, "QUARSHELL_SANDBOX_TOKEN_FILE="+path) {
		t.Fatalf("broker environment did not replace bearer with file reference: %q", filtered)
	}
	if containsEnv(filtered, "QUARSHELL_SANDBOX_TOKEN_FILE=") && !containsEnv(filtered, "QUARSHELL_SANDBOX_TOKEN_FILE="+path) {
		t.Fatalf("broker environment contains a different auth file path: %q", filtered)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "secret-token\n" {
		t.Fatalf("auth file contents = %q, err = %v", data, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("auth file metadata = %#v, err = %v", info, err)
	}
	removeBrokerCredential(path)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("auth file remains after cleanup: %v", err)
	}
}

func TestPrepareBrokerCredentialWritesDescriptorBoundAuthBundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	descriptor := isolation.Descriptor{
		Version: isolation.DescriptorVersion, BackendName: "quarshell/vm", SandboxID: "sandbox-a",
		SessionID: "11111111-1111-4111-8111-111111111111", Generation: "g0000000000000001",
		RootfsDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RuntimeDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Payload:       json.RawMessage(`{"worker_id":"sandbox-a"}`),
	}
	encodedDescriptor, err := isolation.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptorPath := filepath.Join(dir, "isolation-descriptor.json")
	if err := os.WriteFile(descriptorPath, encodedDescriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	config := networkBrokerConfig{LogDir: filepath.Join(dir, "state")}
	environment, bundlePath, err := prepareBrokerCredential(config, []string{
		"QUARSHELL_SANDBOX_TOKEN=signed.jwt.value",
		"QUARSHELL_SANDBOX_PROTOCOL_TOKEN=sandbox.jwt.value",
		"QUARSHELL_GATEWAY_TOKEN_EXPIRES_AT=2000000000",
		"QUARSHELL_SANDBOX_TOKEN_EXPIRES_AT=2000000000",
		"QUARSHELL_AUTH_EPOCH=4",
		"QUARSHELL_SESSION_ROTATION=2",
		"QUARSHELL_RUNTIME_GENERATION=g0000000000000002",
		"QUARSHELL_SANDBOX=sandbox-a",
		"QUARSHELL_ADMITTED_ISOLATION_BACKEND=quarshell/vm",
		"QUARSHELL_ISOLATION_DESCRIPTOR_PATH=" + descriptorPath,
	})
	if err != nil {
		t.Fatalf("prepareBrokerCredential() error = %v", err)
	}
	if !containsEnv(environment, "QUARSHELL_SUPERVISOR_AUTH_BUNDLE_FILE="+bundlePath) || !containsEnv(environment, "QUARSHELL_ISOLATION_DESCRIPTOR_PATH="+descriptorPath) {
		t.Fatalf("host supervisor environment is missing auth/descriptor references: %q", environment)
	}
	if containsEnv(environment, "QUARSHELL_SANDBOX_TOKEN=signed.jwt.value") {
		t.Fatal("raw Gateway bearer remains in process environment")
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := isolation.DecodeHostAuthBundle(data, descriptor)
	if err != nil || bundle.GatewayToken != "signed.jwt.value" || bundle.SandboxToken != "sandbox.jwt.value" || bundle.AuthEpoch != 4 || bundle.SessionRotation != 2 {
		t.Fatalf("auth bundle = %+v, err = %v", bundle, err)
	}
	zeroExpiryEnvironment := []string{
		"QUARSHELL_SANDBOX_TOKEN=gateway.jwt.value",
		"QUARSHELL_SANDBOX_PROTOCOL_TOKEN=sandbox.jwt.value",
		"QUARSHELL_GATEWAY_TOKEN_EXPIRES_AT=0",
		"QUARSHELL_SANDBOX_TOKEN_EXPIRES_AT=0",
		"QUARSHELL_AUTH_EPOCH=4",
		"QUARSHELL_SESSION_ROTATION=2",
		"QUARSHELL_RUNTIME_GENERATION=g0000000000000002",
		"QUARSHELL_SANDBOX=sandbox-a",
		"QUARSHELL_ADMITTED_ISOLATION_BACKEND=quarshell/vm",
		"QUARSHELL_ISOLATION_DESCRIPTOR_PATH=" + descriptorPath,
	}
	_, zeroExpiryPath, err := prepareBrokerCredential(networkBrokerConfig{LogDir: filepath.Join(dir, "zero-expiry-state")}, zeroExpiryEnvironment)
	if err != nil {
		t.Fatalf("prepareBrokerCredential() rejected OpenShell zero expiry: %v", err)
	}
	zeroExpiryData, err := os.ReadFile(zeroExpiryPath)
	if err != nil {
		t.Fatal(err)
	}
	zeroExpiryBundle, err := isolation.DecodeHostAuthBundle(zeroExpiryData, descriptor)
	if err != nil || zeroExpiryBundle.GatewayExpiresAt != 0 || zeroExpiryBundle.SandboxExpiresAt != 0 {
		t.Fatalf("zero-expiry auth bundle = %+v, err = %v", zeroExpiryBundle, err)
	}
	for _, testCase := range []struct {
		name   string
		mutate func([]string) []string
	}{
		{name: "missing paired expiry", mutate: func(environment []string) []string {
			filtered := environment[:0]
			for _, entry := range environment {
				if !strings.HasPrefix(entry, "QUARSHELL_GATEWAY_TOKEN_EXPIRES_AT=") {
					filtered = append(filtered, entry)
				}
			}
			return filtered
		}},
		{name: "expiry exceeds signed bundle range", mutate: func(environment []string) []string {
			for index, entry := range environment {
				if strings.HasPrefix(entry, "QUARSHELL_GATEWAY_TOKEN_EXPIRES_AT=") {
					environment[index] = "QUARSHELL_GATEWAY_TOKEN_EXPIRES_AT=9223372036854775808"
				}
			}
			return environment
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			environment := append([]string(nil), zeroExpiryEnvironment...)
			_, _, err := prepareBrokerCredential(networkBrokerConfig{LogDir: filepath.Join(dir, "invalid-"+strings.ReplaceAll(testCase.name, " ", "-"))}, testCase.mutate(environment))
			if err == nil {
				t.Fatal("prepareBrokerCredential() accepted invalid credential expiry metadata")
			}
		})
	}
	info, err := os.Lstat(bundlePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("auth bundle mode = %v, err = %v", info.Mode().Perm(), err)
	}
}

func TestWithSupervisorTokenReplacesConfiguredValueWithoutMutatingInput(t *testing.T) {
	input := []string{"QUARSHELL_SANDBOX_TOKEN=stale", "QUARSHELL_GATEWAY_URL=https://gateway.example"}
	got := withSupervisorToken(input, "fresh")
	if len(input) != 2 || input[0] != "QUARSHELL_SANDBOX_TOKEN=stale" {
		t.Fatalf("input environment mutated: %q", input)
	}
	if len(got) != 2 || got[0] != "QUARSHELL_GATEWAY_URL=https://gateway.example" || got[1] != "QUARSHELL_SANDBOX_TOKEN=fresh" {
		t.Fatalf("supervisor environment = %q", got)
	}
}

func TestPrepareBrokerCredentialRejectsUnsafeStalePath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := networkBrokerConfig{LogDir: dir}
	path := filepath.Join(dir, "supervisor-auth.token")
	if err := os.Symlink(filepath.Join(dir, "outside"), path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareBrokerCredential(config, []string{"QUARSHELL_SANDBOX_TOKEN=secret"}); err == nil {
		t.Fatal("prepareBrokerCredential() accepted stale symlink")
	}
}

func TestValidateWorkerNetworkBrokerRequiresHostListeningMapping(t *testing.T) {
	config := workerConfig{
		NetworkBroker: &networkBrokerConfig{Socket: "/tmp/broker.sock"},
		Launch: KrunLaunchConfig{
			VsockPorts: []KrunVsockPort{{Port: networkBrokerVsockPort, Socket: "/tmp/broker.sock", Listen: true}},
			Env:        []string{"QUARSHELL_VM_NETWORK_BROKER_PORT=5501", "QUARSHELL_VM_NETWORK_PROXY_PORT=3128"},
		},
	}
	if err := validateWorkerNetworkBroker(config); err != nil {
		t.Fatalf("valid network broker config rejected: %v", err)
	}
	config.Launch.VsockPorts = append(config.Launch.VsockPorts, KrunVsockPort{Port: 5504, Socket: "/tmp/unexpected.sock"})
	if err := validateWorkerNetworkBroker(config); err == nil || !strings.Contains(err.Error(), "unrecognized vsock port mapping 5504") {
		t.Fatalf("unexpected guest-to-host vsock mapping error = %v", err)
	}
	config.Launch.VsockPorts = config.Launch.VsockPorts[:1]
	config.Launch.VsockPorts[0].Listen = false
	if err := validateWorkerNetworkBroker(config); err == nil || !strings.Contains(err.Error(), "host-listening") {
		t.Fatalf("guest-initiated broker mapping error = %v", err)
	}
	config.Launch.VsockPorts[0].Listen = true
	config.Launch.Env = []string{"QUARSHELL_VM_NETWORK_BROKER_PORT=5501"}
	if err := validateWorkerNetworkBroker(config); err == nil || !strings.Contains(err.Error(), "guest proxy port") {
		t.Fatalf("missing proxy port error = %v", err)
	}
}

func TestValidateWorkerRelayMappingsRequireExpectedVsockDirection(t *testing.T) {
	config := workerConfig{
		NetworkBroker: &networkBrokerConfig{
			Socket: "/tmp/quarshell-vm/proxy-vsock.sock", SSHSocket: "/tmp/quarshell-vm/ssh.sock",
			ControlSocket: "/tmp/quarshell-vm/control.sock",
		},
		Launch: KrunLaunchConfig{
			VsockPorts: []KrunVsockPort{
				{Port: networkBrokerVsockPort, Socket: "/tmp/quarshell-vm/proxy-vsock.sock", Listen: true},
				{Port: sshRelayVsockPort, Socket: "/tmp/quarshell-vm/ssh.sock", Listen: true},
				{Port: supervisorControlPort, Socket: "/tmp/quarshell-vm/control.sock", Listen: true},
			},
			Env: []string{
				"QUARSHELL_VM_NETWORK_BROKER_PORT=5501", "QUARSHELL_VM_NETWORK_PROXY_PORT=3128",
				"QUARSHELL_VM_SSH_RELAY_PORT=5502", "QUARSHELL_VM_SUPERVISOR_CONTROL_PORT=5503",
				"QUARSHELL_VM_SUPERVISOR_ENABLED=1",
			},
		},
	}
	if err := validateWorkerNetworkBroker(config); err != nil {
		t.Fatalf("complete SSH and supervisor relay mappings rejected: %v", err)
	}
	config.Launch.VsockPorts[1].Listen = false
	if err := validateWorkerNetworkBroker(config); err == nil || !strings.Contains(err.Error(), "host-listening SSH relay") {
		t.Fatalf("guest-initiated SSH mapping error = %v", err)
	}
	config.Launch.VsockPorts[1].Listen = true
	config.Launch.VsockPorts[2].Listen = false
	if err := validateWorkerNetworkBroker(config); err == nil || !strings.Contains(err.Error(), "host-listening supervisor control") {
		t.Fatalf("guest-initiated control mapping error = %v", err)
	}
}

func TestNetworkBrokerEnvironmentDoesNotInheritHostSecretsOrLoaderOverrides(t *testing.T) {
	env := networkBrokerEnvironment([]string{"TOKEN_GRANTS={}", "QUARSHELL_SANDBOX_TOKEN=secret"})
	if len(env) != 3 || env[0] != "PATH=/usr/bin:/bin" || env[1] != "QUARSHELL_SANDBOX_TOKEN=secret" || env[2] != "TOKEN_GRANTS={}" {
		t.Fatalf("network broker environment = %q", env)
	}
}

func containsEnv(environment []string, expected string) bool {
	for _, entry := range environment {
		if entry == expected {
			return true
		}
	}
	return false
}
