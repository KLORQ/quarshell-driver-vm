//go:build darwin || linux

package vm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver/driver"
)

func TestRuntimeLaunchCredentialsRequireUpstreamVerificationKeySet(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	credentials := driver.RuntimeLaunchCredentials{
		SandboxID:         "sandbox-a",
		RuntimeGeneration: "g0000000000000001", SessionID: "11111111-1111-4111-8111-111111111111",
		GatewayID: "openshell", VerificationKeys: []driver.RuntimeVerificationKey{{KeyID: "key-1", PublicKeyPEM: publicPEM}},
		GatewayToken: "gateway.jwt", GatewayExpiresAt: time.Now().Add(time.Minute),
		SandboxToken: "sandbox.jwt", SandboxExpiresAt: time.Now().Add(time.Minute),
		CredentialEpoch: 1, SessionRotation: 1,
	}
	if !validRuntimeLaunchCredentials(credentials) {
		t.Fatal("valid OpenShell launch authentication was rejected")
	}
	noExpiry := credentials
	noExpiry.GatewayExpiresAt = time.Time{}
	noExpiry.SandboxExpiresAt = time.Time{}
	if !validRuntimeLaunchCredentials(noExpiry) {
		t.Fatal("OpenShell zero-expiry credentials were rejected")
	}
	tooLate := credentials
	tooLate.GatewayExpiresAt = time.Now().Add(-time.Minute)
	if validRuntimeLaunchCredentials(tooLate) {
		t.Fatal("expired Gateway credential was accepted")
	}
	projected := withSupervisorCredentials(nil, noExpiry)
	if !containsEnv(projected, "QUARSHELL_GATEWAY_TOKEN_EXPIRES_AT=0") || !containsEnv(projected, "QUARSHELL_SANDBOX_TOKEN_EXPIRES_AT=0") {
		t.Fatalf("zero credential expiry was not preserved: %q", projected)
	}
	for _, mutate := range []func(*driver.RuntimeLaunchCredentials){
		func(value *driver.RuntimeLaunchCredentials) { value.GatewayID = "" },
		func(value *driver.RuntimeLaunchCredentials) { value.SandboxID = "" },
		func(value *driver.RuntimeLaunchCredentials) { value.VerificationKeys = nil },
		func(value *driver.RuntimeLaunchCredentials) {
			value.VerificationKeys[0].PublicKeyPEM = []byte("not PEM")
		},
		func(value *driver.RuntimeLaunchCredentials) {
			value.VerificationKeys = append(value.VerificationKeys, value.VerificationKeys[0])
		},
	} {
		invalid := credentials
		invalid.VerificationKeys = cloneRuntimeVerificationKeys(credentials.VerificationKeys)
		mutate(&invalid)
		if validRuntimeLaunchCredentials(invalid) {
			t.Fatalf("invalid launch authentication was accepted: %+v", invalid)
		}
	}
}

func TestWithProxySandboxIDReplacesCallerValue(t *testing.T) {
	got := withGatewaySandboxID([]string{"KEEP=value", "QUARSHELL_SANDBOX=runtime", "QUARSHELL_GATEWAY_SANDBOX_ID=untrusted", "QUARSHELL_GATEWAY_SANDBOX_ID=duplicate"}, "gateway-sandbox")
	if want := []string{"KEEP=value", "QUARSHELL_SANDBOX=runtime", "QUARSHELL_GATEWAY_SANDBOX_ID=gateway-sandbox"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("withGatewaySandboxID() = %#v, want %#v", got, want)
	}
	if got := withGatewaySandboxID([]string{"KEEP=value", "QUARSHELL_SANDBOX=runtime", "QUARSHELL_GATEWAY_SANDBOX_ID=untrusted"}, ""); !reflect.DeepEqual(got, []string{"KEEP=value", "QUARSHELL_SANDBOX=runtime"}) {
		t.Fatalf("withGatewaySandboxID(empty) = %#v, want caller Gateway sandbox removal", got)
	}
}

func TestCloneVMLaunchSpecPreservesGatewayNetworkAndDeepCopiesInputs(t *testing.T) {
	original := vmCreateSpec{
		Name: "sandbox", Image: "alpine:3.22", Workspace: "workspace",
		GatewayURL: "https://gateway.example:7443", Command: []string{"/bin/sh"},
		Env: []string{"A=B"}, ProxyEnv: []string{"QUARSHELL_GATEWAY_URL=https://gateway.example:7443"},
		ExtraHosts:   []string{"host.quarshell.internal:192.0.2.1"},
		PublishPorts: []driver.PortPublish{{Host: 8080, Guest: 80}},
		Labels:       map[string]string{"team": "vm"},
	}
	cloned := cloneVMLaunchSpec(original)
	if cloned.GatewayURL != original.GatewayURL || cloned.Image != original.Image || cloned.Workspace != original.Workspace {
		t.Fatalf("launch spec lost create fields: %+v", cloned.vmCreateSpec)
	}
	if len(cloned.PublishPorts) != 1 || cloned.PublishPorts[0] != original.PublishPorts[0] || cloned.Labels["team"] != "vm" {
		t.Fatalf("launch spec lost network or labels: %+v", cloned.vmCreateSpec)
	}
	cloned.Command[0] = "mutated"
	cloned.Env[0] = "mutated"
	cloned.ProxyEnv[0] = "mutated"
	cloned.ExtraHosts[0] = "mutated"
	cloned.PublishPorts[0].Host = 1
	cloned.Labels["team"] = "mutated"
	if original.Command[0] != "/bin/sh" || original.Env[0] != "A=B" || original.ProxyEnv[0] != "QUARSHELL_GATEWAY_URL=https://gateway.example:7443" || original.ExtraHosts[0] != "host.quarshell.internal:192.0.2.1" || original.PublishPorts[0].Host != 8080 || original.Labels["team"] != "vm" {
		t.Fatal("launch spec clone aliases mutable create inputs")
	}
}

func TestSupervisorEnvironmentCarriesOnlySandboxJWTToGuestBoundary(t *testing.T) {
	credentials := driver.RuntimeLaunchCredentials{
		SandboxID: "sandbox-a", GatewayID: "gw-a", GatewayToken: "gateway-secret", SandboxToken: "sandbox-secret",
		RuntimeGeneration: "g0000000000000001", CredentialEpoch: 2,
	}
	env := withSupervisorBoundaryKeys([]string{"QUARSHELL_GATEWAY_ID=wrong"}, credentials.GatewayID, credentials.SandboxID)
	env = withSandboxSessionCredentials(env, credentials)
	joined := strings.Join(env, "\n")
	for _, expected := range []string{"QUARSHELL_GATEWAY_ID=gw-a", "QUARSHELL_GATEWAY_SANDBOX_ID=sandbox-a", "QUARSHELL_SANDBOX_PROTOCOL_TOKEN=sandbox-secret", "QUARSHELL_RUNTIME_GENERATION=g0000000000000001", "QUARSHELL_AUTH_EPOCH=2"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("guest supervisor environment missing %q", expected)
		}
	}
	if strings.Contains(joined, "gateway-secret") || strings.Contains(joined, "QUARSHELL_GATEWAY_ID=wrong") {
		t.Fatal("Gateway bearer or stale Gateway identity leaked into guest environment")
	}
}

func TestProxyUsesControlPlaneSandboxIDInsteadOfRuntimeUUID(t *testing.T) {
	env := withGatewaySandboxID([]string{"QUARSHELL_SANDBOX=runtime-uuid"}, "sandbox-name")
	if !containsEnv(env, "QUARSHELL_GATEWAY_SANDBOX_ID=sandbox-name") || !containsEnv(env, "QUARSHELL_SANDBOX=runtime-uuid") {
		t.Fatalf("proxy sandbox identity = %q; want control-plane sandbox identity", env)
	}
}

func TestRecordMainProcessExitPersistsCanonicalTerminalResult(t *testing.T) {
	stateRoot := t.TempDir()
	store, err := openStateStore(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.create("terminal-result", "fixture:latest", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	state.Status = "running"
	if err := store.save(state); err != nil {
		t.Fatal(err)
	}
	d := NewWithHostConfig(HostConfig{StateDir: stateRoot})
	if err := d.RecordMainProcessExit(context.Background(), core.ID(state.ID), "instance-1", 0); err != nil {
		t.Fatal(err)
	}
	if err := d.RecordMainProcessExit(context.Background(), core.ID(state.ID), "instance-1", 0); err != nil {
		t.Fatalf("idempotent exit report: %v", err)
	}
	if err := d.RecordMainProcessExit(context.Background(), core.ID(state.ID), "instance-2", 7); err == nil {
		t.Fatal("conflicting terminal report was accepted")
	}
	recorded, err := store.load(state.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.Status != "completed" || recorded.MainProcessExitCode == nil || *recorded.MainProcessExitCode != 0 || recorded.MainProcessInstanceID != "instance-1" {
		t.Fatalf("durable VM terminal result = %+v", recorded)
	}
}

func TestVMStartExecCopyLogsStopDeleteLifecycle(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "vm-life-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	stateRoot := filepath.Join(root, "state")
	store, err := openStateStore(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.create("lifecycle", "fixture:latest", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	state.LifecycleExtensions = []string{"recording"}
	imageDir := filepath.Join(stateRoot, "images")
	if err := os.MkdirAll(imageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state.Rootfs = filepath.Join(imageDir, "fixture.ext4")
	if err := writeFakeExt4Fixture(state.Rootfs, 0o400); err != nil {
		t.Fatal(err)
	}
	state.WorkloadDisk = filepath.Join(imageDir, "workload.ext4")
	state.WorkloadSourceType = "tar"
	state.WorkloadSourceRef = "uploaded-tar"
	state.WorkloadSourceDigest = "sha256:" + strings.Repeat("a", 64)
	state.WorkloadPlatform = "linux/" + runtime.GOARCH
	if err := writeFakeExt4Fixture(state.WorkloadDisk, 0o400); err != nil {
		t.Fatal(err)
	}
	assetDir := filepath.Join(stateRoot, "sandboxes", state.ID)
	if err := os.MkdirAll(assetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := createControlToken(assetDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "overlay.ext4"), []byte("fake overlay"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.save(state); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(root, "libkrun")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	libName, fwName, err := libKrunLibraryNames(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{libName, fwName} {
		if err := os.WriteFile(filepath.Join(runtimeDir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kvmDevice := "/dev/kvm"
	if runtime.GOOS == "linux" {
		// The lifecycle is driven by a fake worker, so a writable fixture is
		// sufficient for the host preflight without requiring KVM hardware.
		kvmDevice = filepath.Join(root, "kvm-fixture")
		if err := os.WriteFile(kvmDevice, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	workerPath := filepath.Join(root, "fake-worker")
	workerScript := "#!/bin/sh\nQUARSHELL_TEST_VM_WORKER=1 QUARSHELL_EXPECTED_VM_ROOT_DISK=" + shellQuote(state.Rootfs) + " QUARSHELL_EXPECTED_VM_IMAGE_DISK=" + shellQuote(state.WorkloadDisk) + " QUARSHELL_EXPECTED_VM_OVERLAY_DISK=" + shellQuote(filepath.Join(assetDir, "overlay.ext4")) + " exec " + shellQuote(executable) + " -test.run='^TestFakeVMWorker$'\n"
	if err := os.WriteFile(workerPath, []byte(workerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	var extensionCalls []string
	extension := &recordingLifecycleExtension{name: "recording", calls: &extensionCalls, configure: func(plan *ExtensionLaunchPlan) error {
		plan.Environment = append(plan.Environment, "RECORDING_EXTENSION_CONFIGURED=1")
		return nil
	}}
	d := NewWithHostConfig(HostConfig{
		StateDir: stateRoot, RuntimeDir: runtimeDir, WorkerPath: workerPath, KVMDevice: kvmDevice,
		LifecycleExtensions: []LifecycleExtension{extension},
		kvmDeviceCheck: func(path string) error {
			if path != kvmDevice {
				return fmt.Errorf("unexpected KVM device path %q", path)
			}
			return nil // The fake worker exercises lifecycle protocol, not KVM hardware.
		},
		workerIsolation: func() (workerIsolationConfig, error) {
			return workerIsolationConfig{NoHostMounts: true}, nil
		},
		workerProcessAttributes: func() *syscall.SysProcAttr {
			return &syscall.SysProcAttr{Setsid: true}
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Start(ctx, core.ID(state.ID)); err == nil || !strings.Contains(err.Error(), "workload spec is unavailable") {
		t.Fatalf("Start() without restored workload error = %v, want fail-closed workload error", err)
	}
	if err := d.restoreLaunchSpec(ctx, core.ID(state.ID), vmCreateSpec{Name: state.Name, Command: []string{"true"}, MainProcessRestartPolicy: "always"}); err == nil || !strings.Contains(err.Error(), "restart policy requires supervisor_bin") {
		t.Fatalf("RestoreLaunchSpec() accepted restart without supervisor: %v", err)
	}
	launchSpec := vmCreateSpec{Name: state.Name, Command: []string{"/bin/sh", "-c", "sleep infinity"}, Env: []string{"TOKEN=not-persisted"}}
	if err := d.restoreLaunchSpec(ctx, core.ID(state.ID), launchSpec); err != nil {
		t.Fatalf("RestoreLaunchSpec() error = %v", err)
	}
	launchSpec.Command[0] = "mutated"
	if got := d.launchSpecs[state.ID].Command[0]; got != "/bin/sh" {
		t.Fatalf("RestoreLaunchSpec() retained caller-owned command slice: %q", got)
	}
	if err := d.restoreLaunchSpec(ctx, core.ID(state.ID), vmCreateSpec{Name: "other", Command: []string{"true"}}); err == nil {
		t.Fatal("RestoreLaunchSpec() accepted a mismatched sandbox name")
	}
	if err := d.Start(ctx, core.ID(state.ID)); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := d.Inspect(cleanupCtx, state.ID); err != nil {
			return // The normal test path already deleted the sandbox.
		}
		_ = d.Stop(cleanupCtx, core.ID(state.ID))
		_ = d.Delete(cleanupCtx, core.ID(state.ID))
	})
	if err := d.restoreLaunchSpec(ctx, core.ID(state.ID), vmCreateSpec{Name: state.Name, Command: []string{"true"}}); err == nil {
		t.Fatal("RestoreLaunchSpec() replaced a running sandbox workload")
	}
	recovered := NewWithHostConfig(d.host)
	restoreFailure := fmt.Errorf("restore hook failed")
	extension.restoreErr = restoreFailure
	if err := recovered.restoreLaunchSpec(ctx, core.ID(state.ID), vmCreateSpec{
		Name: state.Name, Command: []string{"/bin/sh", "-c", "sleep infinity"}, Env: []string{"TOKEN=not-persisted"},
	}); !errors.Is(err, restoreFailure) {
		t.Fatalf("RestoreLaunchSpec() error = %v, want restore hook failure", err)
	}
	if !containsString(extensionCalls, "recording:failed:restore-failed") {
		t.Fatalf("failed restore did not clean extension resources: %v", extensionCalls)
	}
	extension.restoreErr = nil
	if err := recovered.restoreLaunchSpec(ctx, core.ID(state.ID), vmCreateSpec{
		Name: state.Name, Command: []string{"/bin/sh", "-c", "sleep infinity"}, Env: []string{"TOKEN=not-persisted"},
	}); err != nil {
		t.Fatalf("RestoreLaunchSpec() could not hydrate a running sandbox after driver restart: %v", err)
	}
	if got := recovered.launchSpecs[state.ID].Command[0]; got != "/bin/sh" {
		t.Fatalf("restored running workload command = %q", got)
	}
	if err := recovered.Start(ctx, core.ID(state.ID)); err != nil {
		t.Fatalf("Start() could not adopt restored running sandbox: %v", err)
	}
	if !containsString(extensionCalls, "recording:before-restore") || !containsString(extensionCalls, "recording:after-restore") {
		t.Fatalf("extension restore hooks were not called: %v", extensionCalls)
	}
	info, err := d.Inspect(ctx, state.ID)
	if err != nil || info.Status != "running" || info.WorkloadUID != 1000 || info.WorkloadGID != 1001 {
		var workerLogs strings.Builder
		_ = d.Logs(ctx, core.ID(state.ID), false, &workerLogs)
		_, _, consolePath := workerSocketPaths(store.root, state.ID)
		workerLog, _ := os.ReadFile(consolePath + ".worker")
		t.Fatalf("Inspect after Start = (%+v, %v); logs: %s; worker: %s", info, err, workerLogs.String(), workerLog)
	}
	result, err := d.Exec(ctx, core.ID(state.ID), driver.ExecRequest{Argv: []string{"echo", "test"}, Stdin: []byte("fixture-input")})
	if err != nil || result.ExitCode != 0 || string(result.Stdout) != "fixture-exec" {
		t.Fatalf("Exec() = (%+v, %v)", result, err)
	}
	source := filepath.Join(root, "source.txt")
	if err := os.WriteFile(source, []byte("upload"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyTo(ctx, core.ID(state.ID), source, "/workspace/source.txt"); err != nil {
		t.Fatalf("CopyTo() error = %v", err)
	}
	destination := filepath.Join(root, "download.txt")
	if err := d.CopyFrom(ctx, core.ID(state.ID), "/workspace/result.txt", destination); err != nil {
		t.Fatalf("CopyFrom() error = %v", err)
	}
	if payload, err := os.ReadFile(destination); err != nil || string(payload) != "fixture-download" {
		t.Fatalf("CopyFrom() payload = (%q, %v)", payload, err)
	}
	_, _, consolePath := workerSocketPaths(stateRoot, state.ID)
	if err := os.WriteFile(consolePath, []byte("console-output"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	if err := d.Logs(ctx, core.ID(state.ID), false, &logs); err != nil || !strings.Contains(logs.String(), "console-output") {
		t.Fatalf("Logs() = (%q, %v)", logs.String(), err)
	}
	if err := os.WriteFile(consolePath+".worker", []byte("worker-initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	followCtx, cancelFollow := context.WithCancel(ctx)
	var followedLogs strings.Builder
	followDone := make(chan error, 1)
	go func() { followDone <- d.Logs(followCtx, core.ID(state.ID), true, &followedLogs) }()
	time.Sleep(150 * time.Millisecond)
	workerLog, err := os.OpenFile(consolePath+".worker", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		cancelFollow()
		t.Fatal(err)
	}
	if _, err := workerLog.WriteString("worker-follow-update"); err != nil {
		_ = workerLog.Close()
		cancelFollow()
		t.Fatal(err)
	}
	_ = workerLog.Close()
	time.Sleep(250 * time.Millisecond)
	cancelFollow()
	if err := <-followDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("follow Logs() error = %v, want context cancellation", err)
	}
	if !strings.Contains(followedLogs.String(), "worker-follow-update") {
		t.Fatalf("follow Logs() missed appended worker log: %q", followedLogs.String())
	}
	if err := os.Remove(consolePath); err != nil {
		t.Fatal(err)
	}
	var workerOnlyLogs strings.Builder
	if err := d.Logs(ctx, core.ID(state.ID), false, &workerOnlyLogs); err != nil || !strings.Contains(workerOnlyLogs.String(), "worker-initial") {
		t.Fatalf("Logs() with only worker log = (%q, %v)", workerOnlyLogs.String(), err)
	}
	singleFollowCtx, cancelSingleFollow := context.WithCancel(ctx)
	singleFollowDone := make(chan error, 1)
	go func() { singleFollowDone <- d.Logs(singleFollowCtx, core.ID(state.ID), true, io.Discard) }()
	time.Sleep(100 * time.Millisecond)
	cancelSingleFollow()
	if err := <-singleFollowDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("single-source follow Logs() error = %v, want context cancellation", err)
	}
	if err := d.Stop(ctx, core.ID(state.ID)); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if !containsString(extensionCalls, "recording:configure") || !containsString(extensionCalls, "recording:before") || !containsString(extensionCalls, "recording:failed:stopped") {
		t.Fatalf("extension lifecycle calls before delete = %v", extensionCalls)
	}
	info, err = d.Inspect(ctx, state.ID)
	if err != nil || info.Status != "stopped" {
		t.Fatalf("Inspect after Stop = (%+v, %v)", info, err)
	}
	if err := d.Delete(ctx, core.ID(state.ID)); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if !containsString(extensionCalls, "recording:delete") {
		t.Fatalf("extension delete hook was not called: %v", extensionCalls)
	}
}

func TestFakeVMWorker(t *testing.T) {
	if os.Getenv("QUARSHELL_TEST_VM_WORKER") != "1" {
		return
	}
	var config workerConfig
	if err := json.NewDecoder(os.Stdin).Decode(&config); err != nil {
		t.Fatalf("read worker configuration: %v", err)
	}
	if expected := os.Getenv("QUARSHELL_EXPECTED_VM_IMAGE_DISK"); expected != "" && config.Launch.ImageDisk != expected {
		t.Fatalf("worker image disk = %q; want %q", config.Launch.ImageDisk, expected)
	}
	if expected := os.Getenv("QUARSHELL_EXPECTED_VM_ROOT_DISK"); expected != "" && config.Launch.RootDisk != expected {
		t.Fatalf("worker bootstrap disk = %q; want %q", config.Launch.RootDisk, expected)
	}
	if expected := os.Getenv("QUARSHELL_EXPECTED_VM_OVERLAY_DISK"); expected != "" && config.Launch.OverlayDisk != expected {
		t.Fatalf("worker writable overlay disk = %q; want %q", config.Launch.OverlayDisk, expected)
	}
	if config.Launch.RootDisk == config.Launch.ImageDisk || config.Launch.OverlayDisk == config.Launch.RootDisk || config.Launch.OverlayDisk == config.Launch.ImageDisk {
		t.Fatalf("worker disk ordering aliases disk paths: bootstrap=%q workload=%q overlay=%q", config.Launch.RootDisk, config.Launch.ImageDisk, config.Launch.OverlayDisk)
	}
	var expectedToken string
	for _, value := range config.Launch.Env {
		if strings.HasPrefix(value, "QUARSHELL_VM_CONTROL_TOKEN=") {
			expectedToken = strings.TrimPrefix(value, "QUARSHELL_VM_CONTROL_TOKEN=")
		}
	}
	if len(expectedToken) != 64 {
		t.Fatal("worker launch is missing per-sandbox guest control token")
	}
	var tokenMu sync.Mutex
	workerListener, ready, _, err := startWorkerControl(config.ControlSocket)
	if err != nil {
		t.Fatalf("start fake worker control: %v", err)
	}
	defer func() {
		_ = workerListener.Close()
		_ = os.Remove(config.ControlSocket)
	}()
	guestListener, err := net.Listen("unix", config.Launch.VsockSocket)
	if err != nil {
		t.Fatalf("listen fake guest control: %v", err)
	}
	defer func() {
		_ = guestListener.Close()
		_ = os.Remove(config.Launch.VsockSocket)
	}()
	close(ready)
	shutdown := make(chan struct{})
	go func() {
		for {
			connection, err := guestListener.Accept()
			if err != nil {
				return
			}
			go func(connection net.Conn) {
				defer connection.Close()
				frame, err := readFrame(connection)
				if err != nil {
					return
				}
				var request controlRequest
				if err := json.Unmarshal(frame, &request); err != nil {
					return
				}
				response := controlResponse{Version: 1}
				tokenMu.Lock()
				currentToken := expectedToken
				if request.Operation == "rotate-token" {
					if request.AuthToken != currentToken || len(request.NextAuthToken) != 64 || request.RotationID == "" {
						response.Error = "host sent invalid guest control token rotation"
					} else {
						expectedToken = request.NextAuthToken
					}
				} else if request.AuthToken != currentToken {
					response.Error = "host sent invalid guest control token"
				}
				tokenMu.Unlock()
				switch request.Operation {
				case "start-workload":
					response.WorkloadUID, response.WorkloadGID = 1000, 1001
					response.SessionID = request.SessionID
				case "exec":
					response.Stdout = []byte("fixture-exec")
				case "copy-from":
					response.Data = []byte("fixture-download")
				case "shutdown":
					defer func() { close(shutdown) }()
				}
				encoded, _ := json.Marshal(response)
				_ = writeFrame(connection, encoded)
			}(connection)
		}
	}()
	<-shutdown
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func TestValidateSandboxArtifactsChecksOptionalWorkloadDisk(t *testing.T) {
	root := t.TempDir()
	imageDir := filepath.Join(root, "images")
	if err := os.MkdirAll(imageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootDisk := filepath.Join(imageDir, "bootstrap.ext4")
	workloadDisk := filepath.Join(imageDir, "workload.ext4")
	for _, path := range []string{rootDisk, workloadDisk} {
		if err := writeFakeExt4Fixture(path, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	overlay := filepath.Join(root, "sandboxes", "sandbox", "overlay.ext4")
	if err := os.MkdirAll(filepath.Dir(overlay), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, []byte("private overlay fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := sandboxState{Rootfs: rootDisk, WorkloadDisk: workloadDisk}
	if err := validateSandboxArtifacts(root, state, overlay); err != nil {
		t.Fatalf("valid separate disks rejected: %v", err)
	}
	if err := os.Remove(workloadDisk); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workloadDisk, []byte("truncated ext4"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := validateSandboxArtifacts(root, state, overlay); err == nil || !strings.Contains(err.Error(), "ext4 superblock") {
		t.Fatalf("truncated workload disk validation error = %v; want ext4 superblock failure", err)
	}
	if err := os.Remove(workloadDisk); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workloadDisk, make([]byte, 4096), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := validateSandboxArtifacts(root, state, overlay); err == nil || !strings.Contains(err.Error(), "invalid ext4 superblock magic") {
		t.Fatalf("replaced workload disk validation error = %v; want invalid ext4 magic", err)
	}
	if err := writeFakeExt4Fixture(workloadDisk, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(workloadDisk); err != nil {
		t.Fatal(err)
	}
	if err := validateSandboxArtifacts(root, state, overlay); err == nil || !strings.Contains(err.Error(), "inspect VM workload disk image") {
		t.Fatalf("missing workload disk validation error = %v", err)
	}
	if err := writeFakeExt4Fixture(workloadDisk, 0o400); err != nil {
		t.Fatal(err)
	}

	state.WorkloadDisk = filepath.Join(root, "outside.ext4")
	if err := os.WriteFile(state.WorkloadDisk, []byte("outside"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := validateSandboxArtifacts(root, state, overlay); err == nil || !strings.Contains(err.Error(), "outside the private image cache") {
		t.Fatalf("outside workload disk validation error = %v", err)
	}

	state.WorkloadDisk = rootDisk
	if err := validateSandboxArtifacts(root, state, overlay); err == nil || !strings.Contains(err.Error(), "must be distinct") {
		t.Fatalf("duplicate disk validation error = %v", err)
	}
}

func writeFakeExt4Fixture(path string, mode os.FileMode) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	image := make([]byte, 4096)
	image[1024+0x38], image[1024+0x39] = 0x53, 0xef
	return os.WriteFile(path, image, mode)
}

func TestWatchWorkerDoesNotActOnReplacementProcessHandle(t *testing.T) {
	driver := NewWithHostConfig(HostConfig{StateDir: t.TempDir()})
	oldWorker := &exec.Cmd{}
	newWorker := &exec.Cmd{}
	driver.workers["sandbox"] = newWorker
	driver.workerDone["sandbox"] = make(chan error)
	done := make(chan error)
	close(done)

	driver.watchWorker("sandbox", t.TempDir(), oldWorker, done)

	if driver.workers["sandbox"] != newWorker {
		t.Fatal("old worker watcher removed or replaced the current worker handle")
	}
}
