//go:build darwin || linux

package vm

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/crypto/ssh"
)

// TestLiveMicroVMLifecycle exercises the full host-to-guest path. It is opt-in
// because it needs a native libkrun runtime and an ext4/overlayfs-capable guest.
func TestLiveMicroVMLifecycle(t *testing.T) {
	if os.Getenv("QUARSHELL_VM_ACCEPTANCE") != "1" {
		t.Skip("set QUARSHELL_VM_ACCEPTANCE=1 and configure the MicroVM runtime to run live acceptance")
	}
	rootfsTar := strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_ROOTFS_TAR"))
	if rootfsTar == "" {
		t.Fatal("QUARSHELL_VM_TEST_ROOTFS_TAR is required for live MicroVM acceptance")
	}
	guestAgent := strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_GUEST_AGENT"))
	if guestAgent == "" {
		t.Fatal("QUARSHELL_VM_TEST_GUEST_AGENT is required for live MicroVM acceptance")
	}
	initBin := requireLiveAsset(t, "QUARSHELL_VM_TEST_INIT_BIN")
	supervisorBin := requireLiveAsset(t, "QUARSHELL_VM_TEST_SUPERVISOR_BIN")
	sshBin := requireLiveAsset(t, "QUARSHELL_VM_TEST_SSH_BIN")
	securityProbe := requireLiveAsset(t, "QUARSHELL_VM_TEST_SECURITY_PROBE")
	runtimeDir := strings.TrimSpace(os.Getenv("OPENSHELL_VM_RUNTIME_DIR"))
	if runtimeDir == "" {
		t.Fatal("OPENSHELL_VM_RUNTIME_DIR is required for live MicroVM acceptance")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("live MicroVM acceptance is unsupported on %s", runtime.GOOS)
	}

	formatter := strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_E2FS_FORMATTER"))
	if formatter == "" {
		var err error
		formatter, err = resolveExt4Formatter()
		if err != nil {
			t.Fatal(err)
		}
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	bootstrapRegistry := newTestOCIRegistry(t)
	bootstrapPlatform := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	bootstrapRegistry.publishImageIndex(t, []testOCILayerBlob{testOCILayerFromArchive(t, rootfsTar)}, bootstrapPlatform)
	host := HostConfig{
		RuntimeDir: runtimeDir, StateDir: stateDir, RootfsTarDir: filepath.Dir(filepath.Dir(rootfsTar)),
		BootstrapImage: strings.TrimPrefix(bootstrapRegistry.server.URL, "http://") + "/agent:latest",
		KVMDevice:      strings.TrimSpace(os.Getenv("QUARSHELL_KVM_DEVICE")),
		FormatterPath:  formatter, OverlaySizeBytes: 64 << 20,
		GuestAgentPath: guestAgent, WorkerPath: strings.TrimSpace(os.Getenv("QUARSHELL_VM_WORKER")),
		VCPUs: 2, MemoryMiB: 1024,
		// The live KVM lane exercises guest-initiated vsock-to-Unix control
		// connections. Keep libkrun trace output enabled there so failures at
		// the host socket boundary are diagnosable from the Actions log.
		KrunLogLevel:        uint32Pointer(krunLogLevelTrace),
		LifecycleExtensions: []LifecycleExtension{liveGuestInitExtension{}},
	}
	host = normalizeHostConfig(host)
	if _, err := ProbeHost(host); err != nil {
		t.Fatalf("probe live MicroVM host: %v", err)
	}
	driverConfig, err := json.Marshal(SandboxDriverConfig{RootfsTarPath: rootfsTar})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	forwardEchoHelper := buildLiveForwardEchoHelper(t, ctx)
	proxyHTTPProbe := buildLiveProxyHTTPProbe(t, ctx)
	proxyHTTPSProbe := proxyHTTPProbe
	upstreamRequests := make(chan string, 8)
	tlsWorkload := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "local-upstream-ok")
	}))
	defer tlsWorkload.Close()
	upstreamAuthHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("live-user:live-pass"))
	upstreamProxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Proxy-Authorization") != upstreamAuthHeader {
			t.Errorf("upstream proxy received missing or incorrect authentication")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		if request.Method != http.MethodConnect {
			select {
			case upstreamRequests <- request.URL.String():
			default:
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "local-upstream-ok")
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("local upstream proxy does not support CONNECT hijacking")
			return
		}
		connection, buffered, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack local upstream proxy CONNECT: %v", err)
			return
		}
		defer connection.Close()
		target, err := net.DialTimeout("tcp", tlsWorkload.Listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Errorf("dial local TLS workload: %v", err)
			return
		}
		defer target.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			t.Errorf("accept local upstream CONNECT: %v", err)
			return
		}
		if err := buffered.Flush(); err != nil {
			t.Errorf("flush local upstream CONNECT: %v", err)
			return
		}
		select {
		case upstreamRequests <- request.Host:
		default:
		}
		copyDone := make(chan struct{}, 1)
		go func() { _, _ = io.Copy(target, buffered); _ = target.Close(); copyDone <- struct{}{} }()
		_, _ = io.Copy(connection, target)
		_ = connection.Close()
		<-copyDone
	}))
	defer upstreamProxy.Close()
	proxyBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve live policy proxy fixture: %v", err)
	}
	policyDir := filepath.Join(t.TempDir(), "policy")
	if err := os.Mkdir(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(policyDir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("# quarshell-policy-revision: 1\nversion: 1\nlandlock:\n  compatibility: best_effort\nprocess:\n  run_as_user: '1000'\n  run_as_group: '1000'\nnetwork_policies: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	proxyCABundle := newTestProxyCABundle(t)
	proxyAuthPath := filepath.Join(policyDir, "upstream-proxy-auth")
	if err := os.WriteFile(proxyAuthPath, []byte("live-user:live-pass\n"), 0o600); err != nil {
		t.Fatalf("write upstream proxy auth fixture: %v", err)
	}
	proxyCAPath := filepath.Join(policyDir, "corporate-proxy-ca.pem")
	if err := os.WriteFile(proxyCAPath, proxyCABundle, 0o600); err != nil {
		t.Fatal(err)
	}
	upstreamCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstreamProxy.Certificate().Raw})
	proxyCABundle = append(proxyCABundle, upstreamCA...)
	workloadCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsWorkload.Certificate().Raw})
	proxyCABundle = append(proxyCABundle, workloadCA...)
	if err := os.WriteFile(proxyCAPath, proxyCABundle, 0o600); err != nil {
		t.Fatal(err)
	}
	controlEventsPath := filepath.Join(policyDir, "supervisor-events.log")
	controlDetailsPath := filepath.Join(policyDir, "supervisor-details.jsonl")
	controlDiagnosticsPath := filepath.Join(policyDir, "supervisor-diagnostics.log")
	brokerPIDPath := filepath.Join(policyDir, "broker.pid")
	policyAckPath := filepath.Join(policyDir, "policy-ack")
	brokerSpec := vmCreateSpec{
		ProxyBin: proxyBinary, PolicyPath: policyPath,
		ProxyEnv: []string{
			"HTTP_PROXY=" + upstreamProxy.URL,
			"HTTPS_PROXY=" + upstreamProxy.URL,
			"QUARSHELL_PROXY_CA_BUNDLE=" + proxyCAPath,
			"QUARSHELL_PROXY_AUTH_FILE=" + proxyAuthPath,
			"QUARSHELL_EGRESS_CA_BUNDLE=" + proxyCAPath,
			"QUARSHELL_VM_TEST_POLICY_PROXY_HELPER=1",
			"QUARSHELL_VM_TEST_BROKER_PID_FILE=" + brokerPIDPath,
			"QUARSHELL_VM_TEST_POLICY_ACK_FILE=" + policyAckPath,
			"QUARSHELL_VM_TEST_CONTROL_EVENTS=" + controlEventsPath,
			"QUARSHELL_VM_TEST_CONTROL_DETAILS=" + controlDetailsPath,
			"QUARSHELL_VM_TEST_CONTROL_DIAGNOSTICS=" + controlDiagnosticsPath,
		},
		InitBin: initBin, SupervisorBin: supervisorBin, EnableSSH: true, SSHBin: sshBin,
	}
	if os.Getenv("QUARSHELL_VM_TEST_GATEWAY_CREDENTIALS_ONLY") == "1" {
		proxyCLI := strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_PROXY_CLI"))
		if proxyCLI == "" {
			t.Fatal("QUARSHELL_VM_TEST_PROXY_CLI is required for paired Gateway credential acceptance")
		}
		assertLiveGatewayCredentialLaunch(t, ctx, host, rootfsTar, initBin, supervisorBin, sshBin, proxyCLI, policyPath)
		return
	}
	first := newLiveAcceptanceDriver(host)
	mainTTYCommand := []string{"/bin/sh", "-c", "if [ ! -e /sandbox/.restart-once ]; then touch /sandbox/.restart-once; exit 7; fi; if [ ! -e /sandbox/canonical-identity ]; then printf '%s:%s\\n' \"$(id -u)\" \"$(id -g)\" > /sandbox/canonical-identity; sync; fi; printf 'main-ready\\n'; printf '%s\\n' \"$$\" > /sandbox/main-tty-pid; while IFS= read -r line; do printf 'main-tty:%s:%s\\n' \"$line\" \"$(stty size)\"; done"}
	handle, err := first.createSandbox(ctx, vmCreateSpec{
		Name: "live-microvm-acceptance", Image: "alpine:3.22",
		Labels:                   liveGuestInitExtensionLabels(),
		DriverConfigJSON:         string(driverConfig),
		Command:                  mainTTYCommand,
		TTY:                      true,
		MainProcessRestartPolicy: "on-failure",
		ProxyBin:                 brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
		InitBin: brokerSpec.InitBin, SupervisorBin: brokerSpec.SupervisorBin,
		EnableSSH: brokerSpec.EnableSSH, SSHBin: brokerSpec.SSHBin,
	})
	if err != nil {
		t.Fatalf("create live MicroVM: %v", err)
	}
	registerLiveSandboxCleanup(t, host, handle.ID)
	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	vmEvents, err := first.WatchPlatformEvents(watchCtx, driver.PlatformEventWatchRequest{SandboxID: handle.ID})
	if err != nil {
		t.Fatalf("watch live VM lifecycle: %v", err)
	}
	assertLiveVMPlatformState(t, vmEvents, "created")
	if err := first.Start(ctx, handle.ID); err != nil {
		var logs bytes.Buffer
		_ = first.Logs(context.Background(), handle.ID, false, &logs)
		store, _ := openStateStore(host.StateDir)
		_, _, consolePath := workerSocketPaths(store.root, string(handle.ID))
		workerLog, _ := os.ReadFile(consolePath + ".worker")
		controlEvents, _ := os.ReadFile(controlEventsPath)
		controlDiagnostics, _ := os.ReadFile(controlDiagnosticsPath)
		t.Fatalf("start live MicroVM: %v; console: %s; worker: %s; supervisor control events: %s; supervisor control diagnostics: %s", err, logs.String(), workerLog, controlEvents, controlDiagnostics)
	}
	assertLiveVMPlatformState(t, vmEvents, "running")
	firstMainPID := assertLiveMainProcessTTY(t, ctx, first, handle.ID, "first")
	initialRuntimeGeneration := assertLiveIsolationDescriptor(t, host.StateDir, handle.ID)
	initialControlCert, initialControlIdentity := liveVMControlClientIdentity(t, host.StateDir, handle.ID)
	if !strings.HasSuffix(initialControlIdentity, "/generation/"+initialRuntimeGeneration) {
		t.Fatalf("initial mTLS client identity=%q does not bind runtime generation %q", initialControlIdentity, initialRuntimeGeneration)
	}
	assertLiveSupervisorCredentialConsumed(t, ctx, first, host.StateDir, handle.ID)
	assertLiveGuestProxyCAInstalled(t, ctx, first, handle.ID, proxyCABundle)
	assertLiveGuestInitExtension(t, ctx, first, handle.ID)
	assertLiveWorkloadIdentity(t, ctx, first, handle.ID)
	assertLiveGuestResources(t, ctx, first, handle.ID, host.VCPUs, host.MemoryMiB)
	assertLiveHostLoopbackIsolation(t, ctx, first, handle.ID, "tcp4", "127.0.0.1")
	assertLiveHostLoopbackIsolation(t, ctx, first, handle.ID, "tcp6", "::1")
	assertLiveGuestNetworkBoundaries(t, ctx, first, handle.ID, securityProbe)
	assertLiveNetworkBroker(t, ctx, first, handle.ID, "policy-probe.invalid", proxyHTTPProbe)
	assertLivePolicyRevisionUpdate(t, ctx, first, handle.ID, policyPath, policyAckPath, proxyHTTPSProbe, upstreamProxy.URL, upstreamRequests)
	assertLiveGuestExec(t, ctx, first, handle.ID)
	assertLiveGuestCopy(t, ctx, first, handle.ID)
	assertLiveSupervisorReady(t, ctx, controlEventsPath)
	assertLiveSupervisorRestarted(t, ctx, controlEventsPath)
	if err := first.EnsureSSHDaemon(ctx, handle.ID); err != nil {
		t.Fatalf("ensure live guest SSH daemon: %v", err)
	}
	assertLiveSSHRelay(t, ctx, first, handle.ID, forwardEchoHelper)
	assertLiveOpenShellMainSubsystem(t, ctx, first, handle.ID)
	if err := first.WaitProxyReady(ctx, handle.Name); err != nil {
		t.Fatalf("wait for live VM policy proxy readiness: %v", err)
	}
	if info, err := first.Inspect(ctx, handle.Name); err != nil || info.Status != "running" {
		t.Fatalf("inspect live MicroVM: info=%+v err=%v", info, err)
	}
	if infos, err := first.List(ctx); err != nil || len(infos) != 1 || infos[0].ID != handle.ID {
		t.Fatalf("list live MicroVM: infos=%+v err=%v", infos, err)
	}
	if err := first.Logs(ctx, handle.ID, false, &bytes.Buffer{}); err != nil {
		t.Fatalf("read live MicroVM logs: %v", err)
	}

	// Recover the running worker through a fresh driver instance, as happens
	// after a Gateway/compute process restart.
	recovered := newLiveAcceptanceDriver(host)
	if err := recovered.restoreLaunchSpec(ctx, handle.ID, vmCreateSpec{
		Name: handle.Name, Labels: liveGuestInitExtensionLabels(), Command: mainTTYCommand,
		TTY: true, MainProcessRestartPolicy: "on-failure", ProxyBin: brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath,
		ProxyEnv: brokerSpec.ProxyEnv, InitBin: brokerSpec.InitBin, SupervisorBin: brokerSpec.SupervisorBin,
		EnableSSH: brokerSpec.EnableSSH, SSHBin: brokerSpec.SSHBin,
	}); err != nil {
		t.Fatalf("restore workload spec for live worker adoption: %v", err)
	}
	if err := recovered.Start(ctx, handle.ID); err != nil {
		t.Fatalf("recover live MicroVM worker: %v", err)
	}
	reattachedMainPID := assertLiveMainProcessTTY(t, ctx, recovered, handle.ID, "second")
	if firstMainPID != reattachedMainPID {
		t.Fatalf("reattached canonical VM main process changed PID from %s to %s", firstMainPID, reattachedMainPID)
	}
	if recoveredGeneration := assertLiveIsolationDescriptor(t, host.StateDir, handle.ID); recoveredGeneration != initialRuntimeGeneration {
		t.Fatalf("adopting the running VM changed runtime generation from %q to %q", initialRuntimeGeneration, recoveredGeneration)
	}
	if digest, identity := liveVMControlClientIdentity(t, host.StateDir, handle.ID); digest != initialControlCert || identity != initialControlIdentity {
		t.Fatalf("adopting the running VM changed its live mTLS identity: digest=%x identity=%q", digest, identity)
	}
	t.Log("recovered existing live MicroVM worker")
	assertLiveGuestExec(t, ctx, recovered, handle.ID)
	assertLiveWorkloadIdentity(t, ctx, recovered, handle.ID)
	assertLiveGuestCopy(t, ctx, recovered, handle.ID)
	assertLiveSSHRelay(t, ctx, recovered, handle.ID, forwardEchoHelper)
	if err := recovered.Stop(ctx, handle.ID); err != nil {
		t.Fatalf("stop live MicroVM: %v", err)
	}
	assertLiveVMPlatformState(t, vmEvents, "stopped")
	t.Log("stopped recovered live MicroVM worker")
	if err := os.Remove(controlEventsPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("reset supervisor acceptance events before restart: %v", err)
	}
	if err := recovered.restoreLaunchSpec(ctx, handle.ID, vmCreateSpec{
		Name: handle.Name, Labels: liveGuestInitExtensionLabels(), Command: []string{"/bin/sh", "-c", "printf '%s:%s\\n' \"$(id -u)\" \"$(id -g)\" >> /sandbox/restart-identity; sync; printf 'main-ready\\n'; printf '%s\\n' \"$$\" > /sandbox/main-tty-pid; while IFS= read -r line; do printf 'main-tty:%s\\n' \"$line\"; done"}, TTY: true, MainProcessRestartPolicy: "on-failure",
		ProxyBin: brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
		InitBin: brokerSpec.InitBin, SupervisorBin: brokerSpec.SupervisorBin,
		EnableSSH: brokerSpec.EnableSSH, SSHBin: brokerSpec.SSHBin,
	}); err != nil {
		t.Fatalf("restore stopped workload spec: %v", err)
	}
	if err := recovered.Start(ctx, handle.ID); err != nil {
		var logs bytes.Buffer
		_ = recovered.Logs(context.Background(), handle.ID, false, &logs)
		store, _ := openStateStore(host.StateDir)
		_, _, consolePath := workerSocketPaths(store.root, string(handle.ID))
		workerLog, _ := os.ReadFile(consolePath + ".worker")
		t.Fatalf("restart live MicroVM: %v; console: %s; worker: %s", err, logs.String(), workerLog)
	}
	t.Log("restarted live MicroVM after explicit stop")
	restartedGeneration := assertLiveIsolationDescriptor(t, host.StateDir, handle.ID)
	if restartedGeneration == initialRuntimeGeneration {
		t.Fatalf("explicit VM restart reused runtime generation %q", restartedGeneration)
	}
	restartedControlCert, restartedControlIdentity := liveVMControlClientIdentity(t, host.StateDir, handle.ID)
	if restartedControlCert == initialControlCert || restartedControlIdentity == initialControlIdentity || !strings.HasSuffix(restartedControlIdentity, "/generation/"+restartedGeneration) {
		t.Fatalf("explicit VM restart did not rotate the mTLS client identity: digest=%x identity=%q generation=%q", restartedControlCert, restartedControlIdentity, restartedGeneration)
	}
	t.Log("live supervisor mTLS identity remained stable during worker adoption and rotated on explicit restart; the guest re-established its control connection")
	assertLiveWorkloadIdentity(t, ctx, recovered, handle.ID)
	assertLiveRestartWorkloadIdentity(t, ctx, recovered, handle.ID)
	assertLiveNetworkBroker(t, ctx, recovered, handle.ID, "blocked-probe.invalid", proxyHTTPProbe)
	assertLiveGuestExec(t, ctx, recovered, handle.ID)
	assertLiveGuestCopy(t, ctx, recovered, handle.ID)
	assertLiveSupervisorReady(t, ctx, controlEventsPath)
	assertLiveSSHRelay(t, ctx, recovered, handle.ID, forwardEchoHelper)

	// Kill only the broker while the guest is live. The worker watcher must
	// terminate the VM process group and persist stopped state before recovery.
	brokerPID := liveTestBrokerPID(t, brokerPIDPath)
	brokerProcess, err := os.FindProcess(brokerPID)
	if err != nil {
		t.Fatalf("find live policy broker process %d: %v", brokerPID, err)
	}
	if err := brokerProcess.Kill(); err != nil {
		t.Fatalf("kill live policy broker process %d: %v", brokerPID, err)
	}
	waitForLiveVMStoppedState(t, ctx, host.StateDir, string(handle.ID))
	t.Logf("live broker loss stopped worker group and persisted stopped state (broker pid %d)", brokerPID)

	active := newLiveAcceptanceDriver(host)
	if err := active.restoreLaunchSpec(ctx, handle.ID, vmCreateSpec{
		Name: handle.Name, Labels: liveGuestInitExtensionLabels(), Command: []string{"/bin/sh", "-c", "while :; do sleep 1; done"}, MainProcessRestartPolicy: "on-failure",
		ProxyBin: brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
		InitBin: initBin, SupervisorBin: supervisorBin, EnableSSH: true, SSHBin: sshBin,
	}); err != nil {
		t.Fatalf("restore workload after live broker loss: %v", err)
	}
	if err := os.Remove(brokerPIDPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove stale broker PID before live broker recovery: %v", err)
	}
	if err := active.Start(ctx, handle.ID); err != nil {
		t.Fatalf("restart MicroVM after live broker loss: %v", err)
	}
	_ = liveTestBrokerPID(t, brokerPIDPath)
	assertLiveNetworkBroker(t, ctx, active, handle.ID, "blocked-probe.invalid", proxyHTTPProbe)
	assertLiveGuestExec(t, ctx, active, handle.ID)

	// Simulate a host worker crash, including its broker/relay child processes.
	// The next driver instance must discard stale sockets and relaunch from the
	// durable rootfs/overlay state after the control plane restores its spec.
	active.mu.Lock()
	worker := active.workers[string(handle.ID)]
	active.mu.Unlock()
	if worker == nil || worker.Process == nil {
		t.Fatal("running MicroVM has no worker process to crash for recovery acceptance")
	}
	if err := killVMWorkerProcessGroupForAcceptance(worker.Process.Pid); err != nil {
		t.Fatalf("kill live VM worker process group: %v", err)
	}
	waitForLiveVMStoppedState(t, ctx, host.StateDir, string(handle.ID))

	afterCrash := newLiveAcceptanceDriver(host)
	if err := afterCrash.restoreLaunchSpec(ctx, handle.ID, vmCreateSpec{
		Name: handle.Name, Labels: liveGuestInitExtensionLabels(), Command: []string{"/bin/sh", "-c", "while :; do sleep 1; done"}, MainProcessRestartPolicy: "on-failure",
		ProxyBin: brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
		InitBin: initBin, SupervisorBin: supervisorBin, EnableSSH: true, SSHBin: sshBin,
	}); err != nil {
		t.Fatalf("restore workload after worker crash: %v", err)
	}
	if err := afterCrash.Start(ctx, handle.ID); err != nil {
		t.Fatalf("restart MicroVM after worker crash: %v", err)
	}
	assertLiveGuestExec(t, ctx, afterCrash, handle.ID)
	assertLiveGuestCopy(t, ctx, afterCrash, handle.ID)
	assertLiveNetworkBroker(t, ctx, afterCrash, handle.ID, "blocked-probe.invalid", proxyHTTPProbe)
	assertLiveSSHRelay(t, ctx, afterCrash, handle.ID, forwardEchoHelper)
	if err := afterCrash.Delete(ctx, handle.ID); err != nil {
		t.Fatalf("delete live MicroVM: %v", err)
	}
	assertLiveOCIImageRuntime(t, ctx, host, rootfsTar)

	// Natural completion of the canonical workload must terminate the guest VM
	// instead of leaving an idle guest agent that Gateway could mistake as live.
	terminal := newLiveAcceptanceDriver(host)
	terminalHandle, err := terminal.createSandbox(ctx, vmCreateSpec{
		Name: "live-microvm-main-exit", Image: "alpine:3.22",
		DriverConfigJSON: string(driverConfig), Command: []string{"/bin/sh", "-c", "exit 0"},
	})
	if err != nil {
		t.Fatalf("create terminal-exit MicroVM: %v", err)
	}
	registerLiveSandboxCleanup(t, host, terminalHandle.ID)
	if err := terminal.Start(ctx, terminalHandle.ID); err != nil {
		t.Fatalf("start terminal-exit MicroVM: %v", err)
	}
	waitForLiveVMStoppedState(t, ctx, host.StateDir, string(terminalHandle.ID))
	terminalState, err := openStateStore(host.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := terminalState.load(string(terminalHandle.ID))
	if err != nil || state.Status != "stopped" {
		t.Fatalf("natural guest workload exit state=%+v err=%v; want stopped VM", state, err)
	}
	t.Log("live natural main-process exit powered off the guest and stopped the VM worker")

	signalHandle, err := terminal.createSandbox(ctx, vmCreateSpec{
		Name: "live-microvm-main-process-signal", Image: "alpine:3.22",
		DriverConfigJSON: string(driverConfig), Labels: liveGuestInitExtensionLabels(),
		Command: []string{"/bin/sh", "-c", "exec sleep 30"}, MainProcessRestartPolicy: "never",
		InitBin: initBin, SupervisorBin: supervisorBin,
		ProxyBin: brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
	})
	if err != nil {
		t.Fatalf("create main-process signal MicroVM: %v", err)
	}
	registerLiveSandboxCleanup(t, host, signalHandle.ID)
	if err := terminal.Start(ctx, signalHandle.ID); err != nil {
		t.Fatalf("start main-process signal MicroVM: %v", err)
	}
	if err := terminal.SignalMainProcess(ctx, signalHandle.ID, driver.ExecSignalKill); err != nil {
		t.Fatalf("send KILL to canonical main process: %v", err)
	}
	waitForSupervisorExitCode(t, ctx, controlDetailsPath, 137)
	waitForLiveVMStoppedState(t, ctx, host.StateDir, string(signalHandle.ID))
	t.Log("live canonical process KILL reached the workload process group, was reported as exit 137, and powered off the guest")

	awaitHandle, err := terminal.createSandbox(ctx, vmCreateSpec{
		Name: "live-microvm-await-main-attachment", Image: "alpine:3.22",
		DriverConfigJSON: string(driverConfig), Labels: liveGuestInitExtensionLabels(),
		Command: []string{"/bin/sh", "-c", "printf 'late-main-attachment\\n'; exit 7"},
		TTY:     true, AwaitMainProcessAttachment: true, InitBin: initBin, SupervisorBin: supervisorBin,
		ProxyBin: brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
	})
	if err != nil {
		t.Fatalf("create await-attachment MicroVM: %v", err)
	}
	registerLiveSandboxCleanup(t, host, awaitHandle.ID)
	if err := terminal.Start(ctx, awaitHandle.ID); err != nil {
		t.Fatalf("start await-attachment MicroVM: %v", err)
	}
	// Let the short main process finish before opening its retained terminal.
	time.Sleep(500 * time.Millisecond)
	terminalState, err = openStateStore(host.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err = terminalState.load(string(awaitHandle.ID))
	if err != nil || state.Status != "running" {
		t.Fatalf("VM state before declared main-process attachment=%+v err=%v; want running", state, err)
	}
	mainTerminal, err := terminal.OpenMainProcessTTY(ctx, awaitHandle.ID, 101, 41)
	if err != nil {
		t.Fatalf("open late main-process TTY attachment: %v", err)
	}
	mainOutput, err := io.ReadAll(mainTerminal)
	if err != nil {
		t.Fatalf("read late main-process TTY output: %v", err)
	}
	if !strings.Contains(string(mainOutput), "late-main-attachment") {
		t.Fatalf("late main-process TTY output=%q; expected retained output", mainOutput)
	}
	if err := mainTerminal.Close(); err != nil {
		t.Fatalf("close late main-process TTY attachment: %v", err)
	}
	waitForLiveVMStoppedState(t, ctx, host.StateDir, string(awaitHandle.ID))
	state, err = terminalState.load(string(awaitHandle.ID))
	if err != nil || state.Status != "stopped" {
		t.Fatalf("VM state after main-process terminal delivery=%+v err=%v; want stopped", state, err)
	}
	t.Log("live short main process retained output and exit until a late TTY attachment closed")

	pipeHandle, err := terminal.createSandbox(ctx, vmCreateSpec{
		Name: "live-microvm-await-main-pipe-attachment", Image: "alpine:3.22",
		DriverConfigJSON:           string(driverConfig),
		Command:                    []string{"/bin/sh", "-c", "printf 'late-pipe-stdout\\n'; printf 'late-pipe-stderr\\n' >&2; exit 9"},
		AwaitMainProcessAttachment: true,
		ProxyBin:                   brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
	})
	if err != nil {
		t.Fatalf("create await-pipe-attachment MicroVM: %v", err)
	}
	registerLiveSandboxCleanup(t, host, pipeHandle.ID)
	if err := terminal.Start(ctx, pipeHandle.ID); err != nil {
		t.Fatalf("start await-pipe-attachment MicroVM: %v", err)
	}
	pipeState, err := openStateStore(host.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err = pipeState.load(string(pipeHandle.ID))
	if err != nil || state.Status != "running" {
		t.Fatalf("VM state before non-TTY main-process attachment=%+v err=%v", state, err)
	}
	mainStream, err := terminal.OpenMainProcessStream(ctx, pipeHandle.ID)
	if err != nil {
		t.Fatalf("open late main-process pipe attachment: %v", err)
	}
	var pipeStdout, pipeStderr []byte
	pipeExit := -1
	for pipeExit < 0 {
		output, readErr := mainStream.ReadOutput()
		if readErr != nil {
			_ = mainStream.Close()
			t.Fatalf("read late main-process pipe output: %v", readErr)
		}
		pipeStdout = append(pipeStdout, output.Stdout...)
		pipeStderr = append(pipeStderr, output.Stderr...)
		if output.Exited {
			pipeExit = output.ExitCode
		}
	}
	if err := mainStream.Close(); err != nil {
		t.Fatalf("close late main-process pipe attachment: %v", err)
	}
	if !strings.Contains(string(pipeStdout), "late-pipe-stdout") || !strings.Contains(string(pipeStderr), "late-pipe-stderr") || pipeExit != 9 {
		t.Fatalf("late pipe attach stdout=%q stderr=%q exit=%d", pipeStdout, pipeStderr, pipeExit)
	}
	waitForLiveVMStoppedState(t, ctx, host.StateDir, string(pipeHandle.ID))
	t.Log("live non-TTY main process replayed separate stdout/stderr and exit status to a late attachment")

	restartHandle, err := terminal.createSandbox(ctx, vmCreateSpec{
		Name: "live-microvm-terminal-explicit-restart", Image: "alpine:3.22",
		DriverConfigJSON: string(driverConfig), Command: []string{"/bin/sh", "-c", "while :; do sleep 1; done"},
	})
	if err != nil {
		t.Fatalf("create terminal-restart MicroVM: %v", err)
	}
	registerLiveSandboxCleanup(t, host, restartHandle.ID)
	if err := terminal.Start(ctx, restartHandle.ID); err != nil {
		t.Fatalf("start terminal-restart MicroVM: %v", err)
	}
	if err := terminal.RecordMainProcessExit(ctx, restartHandle.ID, "live-supervisor-instance", 0); err != nil {
		t.Fatalf("persist live terminal result: %v", err)
	}
	if err := terminal.Start(ctx, restartHandle.ID); err != nil {
		t.Fatalf("explicitly restart terminal MicroVM: %v", err)
	}
	terminalState, err = openStateStore(host.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err = terminalState.load(string(restartHandle.ID))
	if err != nil || state.Status != "running" || state.MainProcessExitCode != nil || state.MainProcessInstanceID != "" {
		t.Fatalf("explicit restart state=%+v err=%v; want running state with cleared terminal result", state, err)
	}
	if err := terminal.Stop(ctx, restartHandle.ID); err != nil {
		t.Fatalf("stop restarted terminal MicroVM: %v", err)
	}
	t.Log("live explicit Start closed the previous terminal VM worker, booted a fresh worker, and cleared its exit result")

	proxyCLI := strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_PROXY_CLI"))
	if proxyCLI == "" {
		t.Fatal("QUARSHELL_VM_TEST_PROXY_CLI is required for paired Gateway credential acceptance")
	}
	assertLiveGatewayCredentialLaunch(t, ctx, host, rootfsTar, initBin, supervisorBin, sshBin, proxyCLI, policyPath)
}

func waitForSupervisorExitCode(t *testing.T, ctx context.Context, path string, want int32) {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				var request supervisorControlTestRequest
				if json.Unmarshal([]byte(line), &request) == nil && request.Operation == "report_main_process_exit" && request.ExitCode == want {
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("supervisor did not report canonical process exit %d: %v", want, ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertLiveIsolationDescriptor(t *testing.T, stateDir string, id core.ID) string {
	t.Helper()
	store, err := openStateStore(stateDir)
	if err != nil {
		t.Fatalf("open live VM state store for isolation descriptor: %v", err)
	}
	state, err := store.load(string(id))
	if err != nil {
		t.Fatalf("load live VM state for isolation descriptor: %v", err)
	}
	sandboxDir := filepath.Join(store.root, "sandboxes", state.ID)
	if _, err := readVMIsolationDescriptor(sandboxDir, state); err != nil {
		t.Fatalf("read live VM isolation descriptor: %v", err)
	}
	return state.RuntimeGeneration
}

func liveVMControlClientIdentity(t *testing.T, stateDir string, id core.ID) ([32]byte, string) {
	t.Helper()
	store, err := openStateStore(stateDir)
	if err != nil {
		t.Fatalf("open live VM state store for client identity: %v", err)
	}
	state, err := store.load(string(id))
	if err != nil {
		t.Fatalf("load live VM state for client identity: %v", err)
	}
	path := filepath.Join(store.root, "sandboxes", state.ID, "supervisor-control", "client.crt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read live VM mTLS client certificate: %v", err)
	}
	certificate, err := parseVMControlCertificate(data)
	if err != nil || len(certificate.URIs) != 1 {
		t.Fatalf("parse live VM mTLS client identity: certificate=%v err=%v", certificate, err)
	}
	return sha256.Sum256(data), certificate.URIs[0].String()
}

func assertLiveSupervisorCredentialConsumed(t *testing.T, ctx context.Context, d *Driver, stateDir string, id core.ID) {
	t.Helper()
	store, err := openStateStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, string(id))
	_, err = d.exchangeControl(ctx, string(id), guestSocket, controlRequest{Operation: "copy-from", Path: guestControlCredentialDir + "/client.key"})
	if err == nil {
		t.Fatal("guest supervisor client private-key file remains available after workload startup")
	}
	result, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", "test \"$(id -u)\" != 0; test ! -r /run/quarshell/supervisor-control-private/ca.pem; test ! -r /run/quarshell/supervisor-control-private/client.crt; test ! -e /run/quarshell/supervisor-control-private/client.key"}, NoLoginShell: true})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("workload can access supervisor credential directory: result=%+v err=%v", result, err)
	}
}

func assertLiveOCIImageRuntime(t *testing.T, ctx context.Context, host HostConfig, rootfsTar string) {
	t.Helper()
	registry := newTestOCIRegistry(t)
	const registryUsername = "live-acceptance"
	const registryPassword = "test-only-registry-secret"
	registry.requireBasicAuth(registryUsername, registryPassword)
	dockerConfigDir := filepath.Join(t.TempDir(), "docker-config")
	if err := os.Mkdir(dockerConfigDir, 0o700); err != nil {
		t.Fatalf("create isolated Docker credential config: %v", err)
	}
	registryHost := strings.TrimPrefix(registry.server.URL, "http://")
	helperMarker := configureTestDockerCredentialHelper(t, registryHost, registryUsername, registryPassword)
	dockerConfig, err := json.Marshal(map[string]any{
		"credHelpers": map[string]string{registryHost: "test"},
	})
	if err != nil {
		t.Fatalf("marshal isolated Docker credential config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dockerConfigDir, "config.json"), dockerConfig, 0o600); err != nil {
		t.Fatalf("write isolated Docker credential config: %v", err)
	}
	t.Setenv("DOCKER_CONFIG", dockerConfigDir)
	platform, err := vmOCIPlatform()
	if err != nil {
		t.Fatal(err)
	}
	baseLayer := testOCILayerFromArchive(t, rootfsTar)
	appLayer := testOCILayer(t, []rootfsTarEntry{
		{name: "opt", kind: tar.TypeDir, mode: 0o755},
		{name: "opt/app", kind: tar.TypeDir, mode: 0o755},
	})
	workload := "printf '%s|%s|%s' \"$(pwd)\" \"$(id -u)\" \"$OCI_LIVE_EXPECTED\" > /tmp/oci-live-config; printf '%s\\n' \"$OCI_LIVE_EXPECTED\" >> /sandbox/.oci-overlay-restart; sync; while :; do sleep 1; done"
	registry.publishImageIndexWithConfig(t, []testOCILayerBlob{baseLayer, appLayer}, platform, v1.Config{
		Entrypoint: []string{"/bin/sh", "-c"}, Cmd: []string{workload},
		Env: []string{"OCI_LIVE_EXPECTED=from-pinned-image"}, WorkingDir: "/opt/app", User: "1000:1000",
	})
	imageRef := registryHost + "/agent:latest"
	sandbox := newLiveAcceptanceDriver(host)
	handle, err := sandbox.createSandbox(ctx, vmCreateSpec{Name: "live-oci-image-acceptance", Image: imageRef, Labels: liveGuestInitExtensionLabels()})
	if err != nil {
		t.Fatalf("create live OCI-backed MicroVM: %v", err)
	}
	helperCalls, err := os.ReadFile(helperMarker)
	if err != nil || !strings.Contains(string(helperCalls), registryHost) {
		t.Fatalf("live OCI credential helper was not called for %q: calls=%q err=%v", registryHost, helperCalls, err)
	}
	store, err := openStateStore(host.StateDir)
	if err != nil {
		t.Fatalf("open live OCI state: %v", err)
	}
	state, err := store.load(string(handle.ID))
	if err != nil || state.WorkloadDisk == "" || state.WorkloadSourceType != "oci" || state.WorkloadSourceDigest == "" {
		t.Fatalf("live OCI source identity = %+v err=%v", state, err)
	}
	durableState, err := json.Marshal(state)
	if err != nil || bytes.Contains(durableState, []byte(registryPassword)) || bytes.Contains(durableState, []byte("from-pinned-image")) {
		t.Fatalf("live OCI durable state contains registry credentials or image environment: state=%s err=%v", durableState, err)
	}
	t.Log("live OCI private registry authentication succeeded through a Docker credential helper; credentials and image env are absent from durable state")
	t.Logf("live OCI workload disk prepared in bootstrap VM for %s from platform manifest %s", state.WorkloadPlatform, state.WorkloadSourceDigest)
	registerLiveSandboxCleanup(t, host, handle.ID)
	if err := sandbox.Start(ctx, handle.ID); err != nil {
		t.Fatalf("start live OCI-backed MicroVM: %v", err)
	}
	assertLiveOCIWorkloadConfig(t, ctx, sandbox, handle.ID, "from-pinned-image")
	assertLiveGuestInitExtension(t, ctx, sandbox, handle.ID)
	assertLiveOCIOverlay(t, ctx, sandbox, handle.ID, []string{"from-pinned-image"})
	if err := sandbox.Stop(ctx, handle.ID); err != nil {
		t.Fatalf("stop live OCI-backed MicroVM: %v", err)
	}
	registry.publishImageIndexWithConfig(t, []testOCILayerBlob{baseLayer, appLayer}, platform, v1.Config{
		Entrypoint: []string{"/bin/sh", "-c"}, Cmd: []string{workload},
		Env: []string{"OCI_LIVE_EXPECTED=from-moved-tag"}, WorkingDir: "/opt/app", User: "1000:1000",
	})
	if err := sandbox.restoreLaunchSpec(ctx, handle.ID, vmCreateSpec{Name: handle.Name, Labels: liveGuestInitExtensionLabels()}); err != nil {
		t.Fatalf("restore live OCI workload from pinned manifest digest: %v", err)
	}
	if err := sandbox.Start(ctx, handle.ID); err != nil {
		t.Fatalf("restart live OCI-backed MicroVM after tag move: %v", err)
	}
	assertLiveOCIWorkloadConfig(t, ctx, sandbox, handle.ID, "from-pinned-image")
	assertLiveOCIOverlay(t, ctx, sandbox, handle.ID, []string{"from-pinned-image", "from-pinned-image"})
	t.Logf("live OCI recovery used pinned workload manifest %s after the image tag moved", state.WorkloadSourceDigest)
	if err := sandbox.Delete(ctx, handle.ID); err != nil {
		t.Fatalf("delete live OCI-backed MicroVM: %v", err)
	}
}

type liveGuestInitExtension struct{}

func (liveGuestInitExtension) Name() string { return "live-guest-init" }
func (liveGuestInitExtension) Activation() ExtensionActivation {
	return ExtensionActivation{RequestKey: "live-guest-init"}
}
func (liveGuestInitExtension) Descriptor() ExtensionDescriptor {
	return ExtensionDescriptor{Name: "live-guest-init", RequiredBackendFeatures: []string{BackendFeatureGuestInitDropins}}
}
func (liveGuestInitExtension) ConfigureLaunch(_ context.Context, _ vmCreateSpec, _ string, plan *ExtensionLaunchPlan) error {
	plan.GuestInitDropins = append(plan.GuestInitDropins, GuestInitDropin{
		Name: "00-live-acceptance.sh", Contents: []byte("#!/bin/sh\nprintf 'guest-init-ok\\n' > /sandbox/.live-guest-init\n"),
	})
	return nil
}

func liveGuestInitExtensionLabels() map[string]string {
	return map[string]string{SandboxExtensionLabelPrefix + "live-guest-init": "enabled"}
}

func assertLiveGuestInitExtension(t *testing.T, ctx context.Context, sandbox *Driver, id core.ID) {
	t.Helper()
	result, err := sandbox.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/cat", "/sandbox/.live-guest-init"}, NoLoginShell: true})
	if err != nil || result.ExitCode != 0 || string(result.Stdout) != "guest-init-ok\n" {
		t.Fatalf("live guest-init extension marker = exit %d stdout %q err=%v", result.ExitCode, result.Stdout, err)
	}
}

func assertLiveOCIOverlay(t *testing.T, ctx context.Context, sandbox *Driver, id core.ID, expected []string) {
	t.Helper()
	result, err := sandbox.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/cat", "/sandbox/.oci-overlay-restart"}, NoLoginShell: true})
	want := strings.Join(expected, "\n") + "\n"
	if err != nil || result.ExitCode != 0 || string(result.Stdout) != want {
		t.Fatalf("live OCI overlay marker = exit %d stdout %q err=%v; want %q", result.ExitCode, result.Stdout, err, want)
	}
}

func assertLiveOCIWorkloadConfig(t *testing.T, ctx context.Context, sandbox *Driver, id core.ID, expectedEnv string) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		result, err := sandbox.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/cat", "/tmp/oci-live-config"}, NoLoginShell: true})
		if err == nil && result.ExitCode == 0 {
			want := "/opt/app|1000|" + expectedEnv
			if got := string(result.Stdout); got != want {
				t.Fatalf("live OCI workload config = %q, want %q", got, want)
			}
			terminal, err := sandbox.Exec(ctx, id, driver.ExecRequest{
				Argv:         []string{"/bin/sh", "-c", `printf '%s|%s' "$PWD" "$OCI_LIVE_EXPECTED"`},
				NoLoginShell: true, TTY: true,
			})
			if err != nil || terminal.ExitCode != 0 || string(terminal.Stdout) != "/opt/app|"+expectedEnv {
				t.Fatalf("live OCI TTY exec config = exit %d stdout %q err=%v", terminal.ExitCode, terminal.Stdout, err)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for live OCI workload config: %v", ctx.Err())
		case <-deadline.C:
			t.Fatalf("live OCI workload did not publish config marker: result=%+v err=%v", result, err)
		case <-ticker.C:
		}
	}
}

func newLiveAcceptanceDriver(host HostConfig) *Driver {
	driver := NewWithHostConfig(host)
	driver.ociNameOptions = []name.Option{name.Insecure}
	return driver
}

func registerLiveSandboxCleanup(t *testing.T, host HostConfig, id core.ID) {
	t.Helper()
	t.Cleanup(func() {
		if t.Failed() {
			captureLiveConsoleTail(t, host, id)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := newLiveAcceptanceDriver(host).Delete(ctx, id); err != nil {
			t.Errorf("delete live acceptance sandbox %s during cleanup: %v", id, err)
		}
	})
}

func captureLiveConsoleTail(t *testing.T, host HostConfig, id core.ID) {
	t.Helper()
	artifactDir := strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_ARTIFACT_DIR"))
	if artifactDir == "" {
		return
	}
	_, _, consolePath := workerSocketPaths(host.StateDir, string(id))
	data, err := os.ReadFile(consolePath)
	if err != nil {
		workerLog, workerErr := os.ReadFile(consolePath + ".worker")
		if workerErr != nil {
			t.Logf("could not capture VM console or worker log artifacts: console=%v worker=%v", err, workerErr)
			return
		}
		data = workerLog
	}
	const maxTailBytes = 64 << 10
	if len(data) > maxTailBytes {
		data = data[len(data)-maxTailBytes:]
	}
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Logf("could not create VM acceptance artifact directory: %v", err)
		return
	}
	path := filepath.Join(artifactDir, "console-tail-"+string(id)+".log")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Logf("could not write VM console tail artifact: %v", err)
	}
}

func assertLiveHostLoopbackIsolation(t *testing.T, ctx context.Context, d *Driver, id core.ID, network, host string) {
	t.Helper()
	listener, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen on host %s loopback for isolation check: %v", network, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		accepted <- struct{}{}
		const body = "host-loopback-reached\n"
		_, _ = fmt.Fprintf(connection, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}()
	endpoint := "http://" + net.JoinHostPort(host, fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port))
	result, err := d.Exec(ctx, id, driver.ExecRequest{
		Argv: []string{"/bin/sh", "-c", `wget -T 3 -q -O - "$1"`, "vm-loopback-isolation", endpoint},
		Env:  []string{"NO_PROXY=*", "no_proxy=*"},
	})
	if err != nil {
		t.Fatalf("probe host %s loopback from guest: %v", network, err)
	}
	if result.ExitCode == 0 || strings.Contains(string(result.Stdout), "host-loopback-reached") {
		t.Fatalf("guest reached host %s loopback: exit=%d stdout=%q stderr=%q", network, result.ExitCode, result.Stdout, result.Stderr)
	}
	select {
	case <-accepted:
		t.Fatalf("guest connected to host %s loopback listener", network)
	default:
	}
}

func assertLiveGuestNetworkBoundaries(t *testing.T, ctx context.Context, d *Driver, id core.ID, probePath string) {
	t.Helper()
	const guestProbePath = "/sandbox/.quarshell-vm-security-probe"
	if err := d.CopyTo(ctx, id, probePath, guestProbePath); err != nil {
		t.Fatalf("copy guest network security probe: %v", err)
	}
	if _, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/chmod", "0700", guestProbePath}}); err != nil {
		t.Fatalf("make guest network security probe executable: %v", err)
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := d.Exec(probeCtx, id, driver.ExecRequest{Argv: []string{guestProbePath, "raw"}})
	if err != nil {
		t.Fatalf("run live raw-socket egress probe: %v", err)
	}
	if raw.ExitCode != 0 || !strings.Contains(string(raw.Stdout), "raw-egress-denied:") {
		t.Fatalf("live raw-socket egress probe = exit %d stdout %q stderr %q", raw.ExitCode, raw.Stdout, raw.Stderr)
	}
	t.Logf("live raw ICMP probe denied egress: %s", strings.TrimSpace(string(raw.Stdout)))

	vsock, err := d.Exec(probeCtx, id, driver.ExecRequest{Argv: []string{guestProbePath, "vsock", "5504"}})
	if err != nil {
		t.Fatalf("run live unmapped-vsock probe: %v", err)
	}
	if vsock.ExitCode != 0 || !strings.Contains(string(vsock.Stdout), "unmapped-vsock-denied: port=5504") {
		t.Fatalf("live unmapped-vsock probe = exit %d stdout %q stderr %q", vsock.ExitCode, vsock.Stdout, vsock.Stderr)
	}
	t.Logf("live guest-to-host vsock probe denied unmapped port: %s", strings.TrimSpace(string(vsock.Stdout)))
}

func assertLiveGuestResources(t *testing.T, ctx context.Context, d *Driver, id core.ID, wantCPUs uint8, wantMemoryMiB uint32) {
	t.Helper()
	result, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{
		"/bin/sh", "-c",
		`awk '/^processor[[:space:]]*:/ {cpus++} END {printf "%d ", cpus+0}' /proc/cpuinfo; awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo`,
	}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("read live guest CPU/memory limits: result=%+v err=%v", result, err)
	}
	values := strings.Fields(string(result.Stdout))
	if len(values) != 2 {
		t.Fatalf("live guest resource probe output = %q, want CPU count and memory KiB", result.Stdout)
	}
	cpus, cpuErr := strconv.ParseUint(values[0], 10, 8)
	memoryKiB, memoryErr := strconv.ParseUint(values[1], 10, 32)
	if cpuErr != nil || memoryErr != nil {
		t.Fatalf("parse live guest resource probe output %q: cpu error=%v memory error=%v", result.Stdout, cpuErr, memoryErr)
	}
	wantMinMemoryKiB := uint64(wantMemoryMiB) * 1024 * 3 / 4
	wantMaxMemoryKiB := uint64(wantMemoryMiB) * 1024
	if uint8(cpus) != wantCPUs || memoryKiB < wantMinMemoryKiB || memoryKiB > wantMaxMemoryKiB {
		t.Fatalf("live guest resources = %d vCPU, %d MiB visible memory; want %d vCPU and between %d and %d MiB", cpus, memoryKiB/1024, wantCPUs, wantMinMemoryKiB/1024, wantMaxMemoryKiB/1024)
	}
	t.Logf("guest sees %d vCPU and %d MiB memory (configured %d MiB)", cpus, memoryKiB/1024, wantMemoryMiB)
}

func waitForLiveVMStoppedState(t *testing.T, ctx context.Context, stateDir, id string) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		store, err := openStateStore(stateDir)
		if err != nil {
			t.Fatalf("open state while waiting for crashed worker: %v", err)
		}
		state, err := store.load(id)
		if err != nil {
			t.Fatalf("read state while waiting for crashed worker: %v", err)
		}
		if state.Status == "stopped" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("worker crash did not update durable state: status=%q: %v", state.Status, ctx.Err())
		case <-ticker.C:
		}
	}
}

func liveTestBrokerPID(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read live policy broker PID: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 || pid == os.Getpid() {
		t.Fatalf("invalid live policy broker PID %q: %v", data, err)
	}
	return pid
}

func assertLiveSupervisorRestarted(t *testing.T, ctx context.Context, eventPath string) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	for {
		data, err := os.ReadFile(eventPath)
		if err == nil && strings.Count(string(data), "begin\n") >= 2 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("live supervisor did not restart on failure: events=%q: %v", data, ctx.Err())
		case <-timeout.C:
			t.Fatalf("live supervisor did not start a second process instance: events=%q", data)
		case <-ticker.C:
		}
	}
}

func requireLiveAsset(t *testing.T, variable string) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(variable))
	if path == "" {
		t.Fatalf("%s is required for live MicroVM supervisor/SSH acceptance", variable)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s must name an executable regular file: %q", variable, path)
	}
	return path
}

func assertLiveSupervisorReady(t *testing.T, ctx context.Context, eventPath string) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	for {
		data, err := os.ReadFile(eventPath)
		if err == nil && strings.Contains(string(data), "begin") && strings.Contains(string(data), "process_event") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("live supervisor did not complete its begin handshake: events=%q: %v", data, ctx.Err())
		case <-timeout.C:
			t.Fatalf("live supervisor did not complete its begin handshake: events=%q", data)
		case <-ticker.C:
		}
	}
}

func assertLiveSSHRelay(t *testing.T, ctx context.Context, d *Driver, id core.ID, forwardEchoHelper string) {
	t.Helper()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		t.Fatalf("open VM state for SSH acceptance: %v", err)
	}
	workerSocket, _, _ := workerSocketPaths(store.root, string(id))
	path := sshRelaySocketPath(workerSocket, string(id))
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		t.Fatalf("connect to live VM SSH relay socket: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	clientConfig := &ssh.ClientConfig{
		User: "acceptance", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second,
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, "vm-acceptance", clientConfig)
	if err != nil {
		t.Fatalf("complete SSH handshake through live vsock relay: %v", err)
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("open SSH session through live vsock relay: %v", err)
	}
	defer session.Close()
	output, err := session.Output("printf 'ssh-live-ok\\n'")
	if err != nil || !strings.Contains(string(output), "ssh-live-ok") {
		t.Fatalf("run command through live SSH relay: output=%q err=%v", output, err)
	}
	assertLiveSSHDirectTCPForward(t, ctx, client, d, id, forwardEchoHelper)
}

func assertLiveOpenShellMainSubsystem(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		t.Fatalf("open VM state for main subsystem acceptance: %v", err)
	}
	workerSocket, _, _ := workerSocketPaths(store.root, string(id))
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sshRelaySocketPath(workerSocket, string(id)))
	if err != nil {
		t.Fatalf("connect to VM SSH relay for openshell-main: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, "vm-main-acceptance", &ssh.ClientConfig{
		User: "acceptance", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("complete SSH handshake for openshell-main: %v", err)
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("request PTY for openshell-main: %v", err)
	}
	if err := session.RequestSubsystem("openshell-main"); err != nil {
		t.Fatalf("request openshell-main: %v", err)
	}
	if _, err := io.WriteString(stdin, "from-ssh-subsystem\n"); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if scanner.Text() == "main-tty:from-ssh-subsystem:24 80" {
			t.Log("openshell-main relayed canonical PTY output, stdin and terminal dimensions")
			return
		}
	}
	t.Fatalf("openshell-main did not return canonical input echo: scanner err=%v", scanner.Err())
}

func assertLiveSSHDirectTCPForward(t *testing.T, ctx context.Context, client *ssh.Client, d *Driver, id core.ID, helper string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve guest TCP forward port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	guestPath := "/sandbox/.quarshell-forward-echo"
	if err := d.CopyTo(ctx, id, helper, guestPath); err != nil {
		t.Fatalf("copy direct-tcpip echo fixture into guest: %v", err)
	}
	start := fmt.Sprintf("%s %d >/sandbox/.quarshell-forward-echo.log 2>&1 &", guestPath, port)
	if result, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", start}, NoLoginShell: true}); err != nil || result.ExitCode != 0 {
		t.Fatalf("start guest direct-tcpip echo fixture: result=%+v err=%v", result, err)
	}
	var forwarded net.Conn
	dialDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(dialDeadline) {
		connection, dialErr := client.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if dialErr == nil {
			forwarded = connection
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("connect through guest direct-tcpip forward: %v", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if forwarded == nil {
		t.Fatalf("SSH direct-tcpip could not reach guest loopback port %d", port)
	}
	defer forwarded.Close()
	_ = forwarded.SetDeadline(time.Now().Add(10 * time.Second))
	want := []byte("vm-port-forward-live")
	if _, err := forwarded.Write(want); err != nil {
		t.Fatalf("write through guest direct-tcpip forward: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(forwarded, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("guest direct-tcpip echo=%q err=%v, want %q", got, err, want)
	}
}

func buildLiveForwardEchoHelper(t *testing.T, ctx context.Context) string {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "forward-echo.go")
	output := filepath.Join(dir, "forward-echo")
	const program = `package main
import ("io"; "net"; "os")
func main() {
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", os.Args[1]))
	if err != nil { os.Exit(2) }
	defer listener.Close()
	connection, err := listener.Accept()
	if err != nil { os.Exit(3) }
	defer connection.Close()
	_, _ = io.Copy(connection, connection)
}`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatalf("write direct-tcpip echo helper: %v", err)
	}
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", output, source)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0", "GOWORK=off")
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build guest direct-tcpip echo helper: %v: %s", err, combined)
	}
	return output
}

func assertLiveNetworkBroker(t *testing.T, ctx context.Context, sandbox *Driver, id core.ID, host, probePath string) {
	t.Helper()
	if err := sandbox.CopyTo(ctx, id, probePath, "/sandbox/proxy-http-probe"); err != nil {
		t.Fatalf("copy live HTTP proxy probe into guest: %v", err)
	}
	result, err := sandbox.Exec(ctx, id, driver.ExecRequest{
		Argv: []string{"/sandbox/proxy-http-probe", host},
		Env:  []string{"HTTP_PROXY=http://127.0.0.1:1", "NO_PROXY=*"},
	})
	if err != nil {
		t.Fatalf("request through live VM policy broker: %v", err)
	}
	response := string(result.Stdout) + string(result.Stderr)
	if result.ExitCode != 0 || !strings.Contains(response, "HTTP 403") {
		t.Fatalf("live VM policy broker did not deny %s: exit=%d stdout=%q stderr=%q", host, result.ExitCode, result.Stdout, result.Stderr)
	}
}

func buildLiveProxyHTTPProbe(t *testing.T, ctx context.Context) string {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "proxy-http-probe.go")
	output := filepath.Join(dir, "proxy-http-probe")
	program := `package main
import (
  "context"
  "crypto/tls"
  "fmt"
  "io"
  "net/http"
  "os"
  "time"
)
func main() {
  scheme, host := "http", ""
  if len(os.Args) == 2 { host = os.Args[1] } else if len(os.Args) == 3 { scheme, host = os.Args[1], os.Args[2] } else { fmt.Fprintln(os.Stderr, "usage: proxy-http-probe [SCHEME] HOST"); os.Exit(2) }
  ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second); defer cancel()
  req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/", nil)
  if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(2) }
  response, err := (&http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}).Do(req)
  if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
  defer response.Body.Close()
  _, _ = io.Copy(io.Discard, response.Body)
	  fmt.Printf("HTTP %d\n", response.StatusCode)
}`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatalf("write guest HTTP proxy probe: %v", err)
	}
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", output, source)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0", "GOWORK=off")
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build guest HTTP proxy probe: %v: %s", err, combined)
	}
	return output
}

func assertLivePolicyRevisionUpdate(t *testing.T, ctx context.Context, sandbox *Driver, id core.ID, policyPath, ackPath, probePath, upstreamProxyURL string, upstreamRequests <-chan string) {
	t.Helper()
	if err := sandbox.CopyTo(ctx, id, probePath, "/sandbox/proxy-https-probe"); err != nil {
		t.Fatalf("copy live HTTPS proxy probe into guest: %v", err)
	}
	if !strings.HasPrefix(upstreamProxyURL, "https://") {
		t.Fatalf("local upstream proxy URL must use HTTPS, got %q", upstreamProxyURL)
	}
	// httptest's stable local certificate includes example.com; the test HTTPS
	// proxy tunnels that host to its local TLS server rather than the internet.
	probeHost := "example.com"
	policyDocument := []byte(fmt.Sprintf("# quarshell-policy-revision: 2\nversion: 1\nlandlock:\n  compatibility: best_effort\nprocess:\n  run_as_user: '1000'\n  run_as_group: '1000'\nnetwork_policies:\n  live-acceptance:\n    endpoints:\n      - host: %s\n        port: 443\n        tls: skip\n", probeHost))
	updatedPath := policyPath + ".next"
	if err := os.WriteFile(updatedPath, policyDocument, 0o600); err != nil {
		t.Fatalf("write next live policy revision: %v", err)
	}
	if err := os.Rename(updatedPath, policyPath); err != nil {
		t.Fatalf("atomically publish live policy revision: %v", err)
	}
	waitForLivePolicyAck(t, ctx, ackPath, 2)
	t.Log("live policy broker acknowledged revision 2")

	allowed, err := sandbox.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/sandbox/proxy-https-probe", "https", probeHost}})
	if err != nil {
		t.Fatalf("request through newly allowed live policy endpoint: %v", err)
	}
	allowedOutput := string(allowed.Stdout) + string(allowed.Stderr)
	if allowed.ExitCode != 0 || !strings.Contains(allowedOutput, "HTTP 200") {
		t.Fatalf("revision 2 did not complete an allowed egress request: exit=%d stdout=%q stderr=%q", allowed.ExitCode, allowed.Stdout, allowed.Stderr)
	}
	select {
	case requestURL := <-upstreamRequests:
		upstreamHost, upstreamPort, splitErr := net.SplitHostPort(requestURL)
		if splitErr != nil || upstreamPort != "443" || net.ParseIP(upstreamHost) == nil {
			t.Fatalf("allowed egress reached unexpected upstream CONNECT target %q", requestURL)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("allowed guest request never reached the working local upstream proxy")
	}
	t.Logf("revision 2 allowed a live guest request through the local upstream proxy: %s", strings.TrimSpace(allowedOutput))
	policyDocument = []byte("# quarshell-policy-revision: 3\nversion: 1\nlandlock:\n  compatibility: best_effort\nprocess:\n  run_as_user: '1000'\n  run_as_group: '1000'\nnetwork_policies: {}\n")
	if err := os.WriteFile(updatedPath, policyDocument, 0o600); err != nil {
		t.Fatalf("write policy revocation revision: %v", err)
	}
	if err := os.Rename(updatedPath, policyPath); err != nil {
		t.Fatalf("atomically publish policy revocation revision: %v", err)
	}
	waitForLivePolicyAck(t, ctx, ackPath, 3)
	revoked, err := sandbox.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/sandbox/proxy-https-probe", "https", probeHost}})
	if err != nil {
		t.Fatalf("request through revoked live policy endpoint: %v", err)
	}
	revokedOutput := string(revoked.Stdout) + string(revoked.Stderr)
	if revoked.ExitCode == 0 || !strings.Contains(revokedOutput, "Forbidden") {
		t.Fatalf("revision 3 did not revoke the working upstream endpoint: exit=%d stdout=%q stderr=%q", revoked.ExitCode, revoked.Stdout, revoked.Stderr)
	}
	select {
	case requestURL := <-upstreamRequests:
		t.Fatalf("revoked HTTPS endpoint unexpectedly reached upstream proxy at %q", requestURL)
	case <-time.After(100 * time.Millisecond):
	}
	t.Log("live policy revision 3 revoked the previously allowed endpoint")
	assertLiveNetworkBroker(t, ctx, sandbox, id, "blocked-probe.invalid", probePath)
}

func waitForLivePolicyAck(t *testing.T, ctx context.Context, ackPath string, wantRevision int) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(ackPath)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 2 {
				revision, parseErr := strconv.Atoi(fields[0])
				if parseErr == nil && revision == wantRevision {
					if fields[1] != "loaded" {
						t.Fatalf("live policy revision %d was not loaded: %q", wantRevision, data)
					}
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("live policy broker did not acknowledge revision %d: last ack=%q: %v", wantRevision, data, ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertLiveGuestCopy(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "upload.txt")
	if err := os.WriteFile(source, []byte("microvm-copy-roundtrip"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyTo(ctx, id, source, "/workspace/upload.txt"); err != nil {
		t.Fatalf("copy file into live guest: %v", err)
	}
	destination := filepath.Join(root, "download.txt")
	if err := d.CopyFrom(ctx, id, "/workspace/upload.txt", destination); err != nil {
		t.Fatalf("copy file from live guest: %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != "microvm-copy-roundtrip" {
		t.Fatalf("live guest copy roundtrip = %q err=%v", data, err)
	}
}

func assertLiveGuestProxyCAInstalled(t *testing.T, ctx context.Context, d *Driver, id core.ID, expected []byte) {
	t.Helper()
	root := t.TempDir()
	var certificates [][]byte
	remaining := bytes.TrimSpace(expected)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("configured proxy CA bundle contains invalid PEM")
		}
		certificates = append(certificates, pem.EncodeToMemory(block))
		remaining = bytes.TrimSpace(rest)
	}
	for index, certificate := range certificates {
		installedPath := filepath.Join(root, fmt.Sprintf("installed-ca-%04d.pem", index+1))
		guestPath := fmt.Sprintf("%s/ca-%04d.crt", guestProxyCADir, index+1)
		if err := d.CopyFrom(ctx, id, guestPath, installedPath); err != nil {
			t.Fatalf("copy installed corporate proxy CA %d from live guest: %v", index+1, err)
		}
		installed, err := os.ReadFile(installedPath)
		if err != nil || !bytes.Equal(installed, certificate) {
			t.Fatalf("live guest installed CA %d differs from configured bundle: bytes=%d err=%v", index+1, len(installed), err)
		}
	}
	if len(certificates) == 0 {
		t.Fatal("configured proxy CA bundle has no certificates")
	}
	mode, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{
		"/bin/sh", "-c", "stat -c '%u:%g:%a' '" + guestProxyCADir + "/ca-0001.crt'",
	}})
	if err != nil || mode.ExitCode != 0 || strings.TrimSpace(string(mode.Stdout)) != "0:0:644" {
		t.Fatalf("live guest proxy CA ownership/mode = %q exit=%d err=%v", mode.Stdout, mode.ExitCode, err)
	}
	bundlePath := filepath.Join(root, "system-ca-bundle.pem")
	if err := d.CopyFrom(ctx, id, "/etc/ssl/certs/ca-certificates.crt", bundlePath); err != nil {
		t.Fatalf("copy guest system trust bundle: %v", err)
	}
	trustBundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("live guest system trust bundle does not contain configured CA: bytes=%d err=%v", len(trustBundle), err)
	}
	for index, certificate := range certificates {
		if !bytes.Contains(trustBundle, certificate) {
			t.Fatalf("live guest system trust bundle does not contain configured CA %d: bytes=%d", index+1, len(trustBundle))
		}
	}
	t.Log("live guest installed corporate proxy CA as root-owned 0644 and included it in system trust bundle")
}

func assertLiveMainProcessTTY(t *testing.T, ctx context.Context, d *Driver, id core.ID, payload string) string {
	t.Helper()
	terminal, err := d.OpenMainProcessTTY(ctx, id, 101, 41)
	if err != nil {
		t.Fatalf("open canonical VM main-process TTY: %v", err)
	}
	defer terminal.Close()
	lines := make(chan string, 16)
	readErr := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(terminal)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
		readErr <- scanner.Err()
	}()
	if _, err := io.WriteString(terminal, payload+"\n"); err != nil {
		t.Fatalf("write canonical VM main-process TTY: %v", err)
	}
	want := "main-tty:" + payload + ":41 101"
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case line := <-lines:
			if line == want {
				result, execErr := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/cat", "/sandbox/main-tty-pid"}, NoLoginShell: true})
				if execErr != nil || result.ExitCode != 0 {
					t.Fatalf("read canonical VM main-process PID: result=%+v err=%v", result, execErr)
				}
				pid := strings.TrimSpace(string(result.Stdout))
				if pid == "" {
					t.Fatal("canonical VM main-process PID marker is empty")
				}
				return pid
			}
		case err := <-readErr:
			t.Fatalf("read canonical VM main-process TTY before %q: %v", want, err)
		case <-deadline.C:
			t.Fatalf("canonical VM main-process TTY did not return %q", want)
		case <-ctx.Done():
			t.Fatalf("context ended while waiting for canonical VM main-process TTY: %v", ctx.Err())
		}
	}
}

func assertLiveGuestExec(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	profile := filepath.Join(t.TempDir(), "profile")
	if err := os.WriteFile(profile, []byte("export QUARSHELL_VM_LOGIN_PROFILE=loaded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyTo(ctx, id, profile, "/workspace/.profile"); err != nil {
		t.Fatalf("install live guest login profile: %v", err)
	}
	result, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", `printf '%s' "${QUARSHELL_VM_LOGIN_PROFILE-unset}"`}})
	if err != nil {
		t.Fatalf("execute in live guest: %v", err)
	}
	if result.ExitCode != 0 || string(result.Stdout) != "loaded" {
		t.Fatalf("live guest exec result = exit %d stdout %q stderr %q", result.ExitCode, result.Stdout, result.Stderr)
	}
	result, err = d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", `printf '%s' "${QUARSHELL_VM_LOGIN_PROFILE-unset}"`}, NoLoginShell: true})
	if err != nil || result.ExitCode != 0 || string(result.Stdout) != "unset" {
		t.Fatalf("live guest no-login-shell result = exit %d stdout %q stderr %q err=%v", result.ExitCode, result.Stdout, result.Stderr, err)
	}
	result, err = d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", "printf 'guest-live-ok\\n'"}})
	if err != nil || result.ExitCode != 0 || !bytes.Contains(result.Stdout, []byte("guest-live-ok")) {
		t.Fatalf("live guest command result = exit %d stdout %q stderr %q err=%v", result.ExitCode, result.Stdout, result.Stderr, err)
	}
	streamCtx, streamCancel := context.WithTimeout(ctx, 10*time.Second)
	streamSession, err := d.OpenExecStream(streamCtx, id, driver.ExecTerminalRequest{
		Argv:    []string{"/bin/sh", "-c", "read value; printf 'stream-out:%s' \"$value\"; printf 'stream-err:%s' \"$value\" >&2; exit 11"},
		WorkDir: "/sandbox", NoLoginShell: true,
	})
	if err != nil {
		streamCancel()
		t.Fatalf("open live non-TTY guest exec stream: %v", err)
	}
	if _, err := streamSession.Write([]byte("live-input\n")); err != nil {
		streamCancel()
		_ = streamSession.Close()
		t.Fatalf("write live non-TTY exec stdin: %v", err)
	}
	if err := streamSession.CloseStdin(); err != nil {
		streamCancel()
		_ = streamSession.Close()
		t.Fatalf("half-close live non-TTY exec stdin: %v", err)
	}
	var streamStdout, streamStderr strings.Builder
	streamExit := -1
	for streamExit < 0 {
		output, readErr := streamSession.ReadOutput()
		if readErr != nil {
			streamCancel()
			_ = streamSession.Close()
			t.Fatalf("read live non-TTY exec output: %v", readErr)
		}
		streamStdout.Write(output.Stdout)
		streamStderr.Write(output.Stderr)
		if output.Exited {
			streamExit = output.ExitCode
		}
	}
	streamCancel()
	_ = streamSession.Close()
	if !strings.Contains(streamStdout.String(), "stream-out:live-input") || !strings.Contains(streamStderr.String(), "stream-err:live-input") || streamExit != 11 {
		t.Fatalf("live non-TTY exec stdout=%q stderr=%q exit=%d", streamStdout.String(), streamStderr.String(), streamExit)
	}
	assertLiveGuestArchiveTransfer(t, ctx, d, id)
	marker := "/sandbox/exec-timeout-must-stop"
	if _, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/rm", "-f", marker}}); err != nil {
		t.Fatalf("clear live guest exec timeout marker: %v", err)
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, timeoutErr := d.Exec(timeoutCtx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", "sleep 1; touch " + marker}})
	cancel()
	if timeoutErr == nil {
		t.Fatal("live guest exec ignored its context deadline")
	}
	time.Sleep(1100 * time.Millisecond)
	result, err = d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", "test ! -e " + marker}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("live guest exec process survived caller timeout: exit=%d err=%v", result.ExitCode, err)
	}
	assertLiveExecTerminal(t, ctx, d, id)
}

func assertLiveGuestArchiveTransfer(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	entries := []struct {
		header *tar.Header
		body   string
	}{
		{header: &tar.Header{Name: "bundle/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{header: &tar.Header{Name: "bundle/nested/", Typeflag: tar.TypeDir, Mode: 0o750}},
		{header: &tar.Header{Name: "bundle/nested/payload.txt", Typeflag: tar.TypeReg, Mode: 0o640, Size: int64(len("live-directory-transfer"))}, body: "live-directory-transfer"},
		{header: &tar.Header{Name: "bundle/payload.link", Typeflag: tar.TypeSymlink, Linkname: "nested/payload.txt", Mode: 0o777}},
	}
	for _, entry := range entries {
		if err := writer.WriteHeader(entry.header); err != nil {
			t.Fatalf("write live transfer tar header: %v", err)
		}
		if entry.body != "" {
			if _, err := io.WriteString(writer, entry.body); err != nil {
				t.Fatalf("write live transfer tar entry: %v", err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("finish live transfer archive: %v", err)
	}

	streamCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	upload, err := d.OpenExecStream(streamCtx, id, driver.ExecTerminalRequest{
		Argv: []string{"/bin/sh", "-c", "mkdir -p /sandbox/.live-transfer-in && tar -xf - -C /sandbox/.live-transfer-in"}, WorkDir: "/sandbox", NoLoginShell: true,
	})
	if err != nil {
		cancel()
		t.Fatalf("open live directory upload stream: %v", err)
	}
	if _, err := upload.Write(archive.Bytes()); err != nil {
		cancel()
		_ = upload.Close()
		t.Fatalf("stream live directory upload: %v", err)
	}
	if err := upload.CloseStdin(); err != nil {
		cancel()
		_ = upload.Close()
		t.Fatalf("finish live directory upload: %v", err)
	}
	var uploadStderr strings.Builder
	uploadExit := -1
	for uploadExit < 0 {
		output, err := upload.ReadOutput()
		if err != nil {
			cancel()
			_ = upload.Close()
			t.Fatalf("read live directory upload result: %v", err)
		}
		uploadStderr.Write(output.Stderr)
		if output.Exited {
			uploadExit = output.ExitCode
		}
	}
	cancel()
	_ = upload.Close()
	if uploadExit != 0 {
		t.Fatalf("live directory upload exit=%d stderr=%q", uploadExit, uploadStderr.String())
	}

	downloadCtx, cancelDownload := context.WithTimeout(ctx, 10*time.Second)
	download, err := d.OpenExecStream(downloadCtx, id, driver.ExecTerminalRequest{
		Argv: []string{"tar", "-cf", "-", "-C", "/sandbox/.live-transfer-in", "bundle"}, WorkDir: "/sandbox", NoLoginShell: true,
	})
	if err != nil {
		cancelDownload()
		t.Fatalf("open live directory download stream: %v", err)
	}
	_ = download.CloseStdin()
	var downloaded bytes.Buffer
	var downloadStderr strings.Builder
	downloadExit := -1
	for downloadExit < 0 {
		output, err := download.ReadOutput()
		if err != nil {
			cancelDownload()
			_ = download.Close()
			t.Fatalf("read live directory download: %v", err)
		}
		_, _ = downloaded.Write(output.Stdout)
		downloadStderr.Write(output.Stderr)
		if output.Exited {
			downloadExit = output.ExitCode
		}
	}
	cancelDownload()
	_ = download.Close()
	if downloadExit != 0 {
		t.Fatalf("live directory download exit=%d stderr=%q", downloadExit, downloadStderr.String())
	}
	reader := tar.NewReader(bytes.NewReader(downloaded.Bytes()))
	var payload string
	var linkTarget string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("parse live directory download archive: %v", err)
		}
		switch header.Name {
		case "bundle/nested/payload.txt":
			contents, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("read downloaded payload: %v", err)
			}
			payload = string(contents)
		case "bundle/payload.link":
			if header.Typeflag != tar.TypeSymlink {
				t.Fatalf("downloaded symlink type=%d, want %d", header.Typeflag, tar.TypeSymlink)
			}
			linkTarget = header.Linkname
		}
	}
	if payload != "live-directory-transfer" || linkTarget != "nested/payload.txt" {
		t.Fatalf("live directory transfer returned payload=%q symlink=%q", payload, linkTarget)
	}
	t.Log("live VM directory archive upload/download preserved nested content and symlink target")
}

func assertLiveVMPlatformState(t *testing.T, events <-chan driver.PlatformEventResult, want string) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case result, open := <-events:
			if !open {
				t.Fatalf("VM platform event stream closed before state %q", want)
			}
			if result.Err != nil {
				t.Fatalf("VM platform event stream error: %v", result.Err)
			}
			if result.Event.Metadata["status"] == want {
				t.Logf("live VM platform watch reported state %q", want)
				return
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for live VM platform state %q", want)
		}
	}
}

func assertLiveWorkloadIdentity(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var result driver.ExecResult
	var err error
	for {
		result, err = d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", "set -eu; actual=$(id -u):$(id -g); canonical=$(cat /sandbox/canonical-identity); owner=$(stat -c %u:%g /sandbox/canonical-identity); test \"$actual\" = 1000:1000; test \"$canonical\" = \"$actual\"; test \"$owner\" = \"$actual\"; printf 'identity=%s owner=%s\\n' \"$actual\" \"$owner\""}, NoLoginShell: true})
		if err == nil && result.ExitCode == 0 && bytes.Contains(result.Stdout, []byte("identity=1000:1000 owner=1000:1000")) {
			break
		}
		if time.Now().After(deadline) {
			diagnostic, diagnosticErr := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", "id; ls -ld /sandbox /workspace 2>&1; ls -la /sandbox /workspace 2>&1"}, NoLoginShell: true})
			var logs bytes.Buffer
			_ = d.Logs(context.Background(), id, false, &logs)
			t.Fatalf("live workload identity does not match canonical process and persistent file owner: result=%+v err=%v diagnostics=%q diagnostic-error=%v logs=%q", result, err, append(diagnostic.Stdout, diagnostic.Stderr...), diagnosticErr, logs.String())
		}
		select {
		case <-ctx.Done():
			t.Fatalf("live workload identity readiness context ended: %v", ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	info, inspectErr := d.Inspect(ctx, string(id))
	if inspectErr != nil || info.WorkloadUID != 1000 || info.WorkloadGID != 1000 {
		t.Fatalf("live VM persisted workload identity=%d:%d err=%v, want observed 1000:1000", info.WorkloadUID, info.WorkloadGID, inspectErr)
	}
	t.Logf("live policy identity matched canonical process and /sandbox file ownership: %s", strings.TrimSpace(string(result.Stdout)))
}

func assertLiveRestartWorkloadIdentity(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	result, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", "set -eu; actual=$(id -u):$(id -g); recorded=$(tail -n1 /sandbox/restart-identity); owner=$(stat -c %u:%g /sandbox/restart-identity); test \"$actual\" = 1000:1000; test \"$recorded\" = \"$actual\"; test \"$owner\" = \"$actual\"; printf 'restart-identity=%s owner=%s\\n' \"$recorded\" \"$owner\""}, NoLoginShell: true})
	if err != nil || result.ExitCode != 0 || !bytes.Contains(result.Stdout, []byte("restart-identity=1000:1000 owner=1000:1000")) {
		t.Fatalf("live stop/start workload identity did not persist on /sandbox: result=%+v err=%v", result, err)
	}
	t.Logf("live stop/start workload identity and persistent /sandbox owner: %s", strings.TrimSpace(string(result.Stdout)))
}

func assertLiveExecTerminal(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	session, err := d.OpenExecTerminal(ctx, id, driver.ExecTerminalRequest{
		Argv:         []string{"/bin/sh", "-c", "stty size; IFS= read -r line; stty size"},
		NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatalf("open live guest exec terminal: %v", err)
	}
	defer session.Close()
	terminalOutput := bufio.NewReader(session)
	var initialOutput strings.Builder
	for !strings.Contains(initialOutput.String(), "24 80") {
		line, err := terminalOutput.ReadString('\n')
		initialOutput.WriteString(line)
		if err != nil {
			t.Fatalf("read live guest initial terminal size from %q: %v", initialOutput.String(), err)
		}
		if initialOutput.Len() > 4096 {
			t.Fatalf("live guest did not report initial terminal dimensions: %q", initialOutput.String())
		}
	}
	if err := session.Resize(ctx, 101, 41); err != nil {
		t.Fatalf("resize live guest exec terminal: %v", err)
	}
	if _, err := io.WriteString(session, "resize-check\n"); err != nil {
		t.Fatalf("write live guest exec terminal input: %v", err)
	}
	output, err := io.ReadAll(terminalOutput)
	if err != nil {
		t.Fatalf("read live guest exec terminal output: %v", err)
	}
	if exitCode, err := session.Wait(ctx); err != nil || exitCode != 0 {
		t.Fatalf("wait for live guest exec terminal: exit %d err=%v", exitCode, err)
	}
	if !bytes.Contains(output, []byte("41 101")) {
		t.Fatalf("live guest terminal did not apply initial and resized dimensions: %q", output)
	}

	result, err := d.Exec(ctx, id, driver.ExecRequest{
		Argv:         []string{"/bin/sh", "-c", "if [ -t 0 ] && [ -t 1 ]; then printf 'tty-exec-ok'; else exit 33; fi"},
		NoLoginShell: true, TTY: true,
	})
	if err != nil || result.ExitCode != 0 || !bytes.Contains(result.Stdout, []byte("tty-exec-ok")) {
		t.Fatalf("live guest TTY exec result = exit %d stdout %q err=%v", result.ExitCode, result.Stdout, err)
	}
	assertLiveExecTerminalReattach(t, ctx, d, id)
	assertLivePTYInterrupt(t, ctx, d, id)
}

func assertLiveExecTerminalReattach(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	session, err := d.OpenExecTerminal(ctx, id, driver.ExecTerminalRequest{
		Argv:         []string{"/bin/sh", "-c", "printf 'attach-ready\\n'; IFS= read -r line; printf 'received:%s' \"$line\""},
		NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatalf("open live retained terminal: %v", err)
	}
	identity, ok := session.(driver.ExecTerminalSessionID)
	if !ok || identity.SessionID() == "" {
		t.Fatal("live terminal has no stable session ID")
	}
	firstOutput := bufio.NewReader(session)
	var initial strings.Builder
	for !strings.Contains(initial.String(), "attach-ready") {
		line, readErr := firstOutput.ReadString('\n')
		initial.WriteString(line)
		if readErr != nil {
			t.Fatalf("read initial retained terminal output %q: %v", initial.String(), readErr)
		}
		if initial.Len() > 4096 {
			t.Fatalf("retained terminal did not produce readiness marker: %q", initial.String())
		}
	}
	if err := session.Close(); err != nil {
		t.Fatalf("detach live retained terminal: %v", err)
	}
	reattacher := newLiveAcceptanceDriver(d.host)
	var attached driver.ExecTerminalSession
	for attempt := 0; attempt < 10; attempt++ {
		attached, err = reattacher.AttachExecTerminal(ctx, id, identity.SessionID())
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("reattach to live retained terminal: %v", err)
	}
	defer attached.Close()
	if _, err := io.WriteString(attached, "reattached-input\n"); err != nil {
		t.Fatalf("write to reattached terminal: %v", err)
	}
	output, err := io.ReadAll(attached)
	if err != nil {
		t.Fatalf("read reattached terminal output: %v", err)
	}
	code, err := attached.Wait(ctx)
	if err != nil || code != 0 || !bytes.Contains(output, []byte("received:reattached-input")) {
		t.Fatalf("reattached terminal result = exit %d output %q err=%v", code, output, err)
	}

	retained, err := d.OpenExecTerminal(ctx, id, driver.ExecTerminalRequest{
		Argv: []string{"/bin/sleep", "30"}, NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatalf("open live terminal for detached termination: %v", err)
	}
	retainedID, ok := retained.(driver.ExecTerminalSessionID)
	if !ok {
		t.Fatal("live terminal has no stable ID for detached termination")
	}
	if err := retained.Close(); err != nil {
		t.Fatalf("detach terminal before termination: %v", err)
	}
	if err := reattacher.TerminateExecTerminal(ctx, id, retainedID.SessionID()); err != nil {
		t.Fatalf("terminate detached live terminal: %v", err)
	}
	terminated, err := reattacher.AttachExecTerminal(ctx, id, retainedID.SessionID())
	if err != nil {
		t.Fatalf("attach to terminated live terminal result: %v", err)
	}
	defer terminated.Close()
	_, err = io.Copy(io.Discard, terminated)
	if err != nil {
		t.Fatalf("drain terminated live terminal: %v", err)
	}
	if code, err := terminated.Wait(ctx); err != nil || code != 128+int(syscall.SIGTERM) {
		t.Fatalf("detached live terminal termination = exit %d err=%v", code, err)
	}
}

func assertLivePTYInterrupt(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	session, err := d.OpenExecTerminal(ctx, id, driver.ExecTerminalRequest{
		Argv:         []string{"/bin/sh", "-c", "trap 'printf interrupted; exit 42' INT; printf 'ready\\n'; while :; do sleep 1; done"},
		NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatalf("open live guest interrupt terminal: %v", err)
	}
	defer session.Close()
	terminalOutput := bufio.NewReader(session)
	var readyOutput strings.Builder
	for !strings.Contains(readyOutput.String(), "ready") {
		line, err := terminalOutput.ReadString('\n')
		readyOutput.WriteString(line)
		if err != nil {
			t.Fatalf("read live guest interrupt readiness from %q: %v", readyOutput.String(), err)
		}
		if readyOutput.Len() > 4096 {
			t.Fatalf("live guest interrupt command did not become ready: %q", readyOutput.String())
		}
	}
	if _, err := session.Write([]byte{3}); err != nil {
		t.Fatalf("send live guest terminal interrupt: %v", err)
	}
	output, err := io.ReadAll(terminalOutput)
	if err != nil {
		t.Fatalf("read live guest output after terminal interrupt: %v", err)
	}
	exitCode, err := session.Wait(ctx)
	if err != nil || exitCode != 42 || !bytes.Contains(output, []byte("interrupted")) {
		t.Fatalf("live guest terminal interrupt = exit %d output %q err=%v; want trap exit 42", exitCode, output, err)
	}
	assertLivePTYSignal(t, ctx, d, id)
}

func assertLivePTYSignal(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	session, err := d.OpenExecTerminal(ctx, id, driver.ExecTerminalRequest{
		Argv:         []string{"/bin/sh", "-c", "trap 'printf terminated; exit 43' TERM; printf 'ready\\n'; while :; do sleep 1; done"},
		NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatalf("open live guest signal terminal: %v", err)
	}
	defer session.Close()
	terminalOutput := bufio.NewReader(session)
	var readyOutput strings.Builder
	for !strings.Contains(readyOutput.String(), "ready") {
		line, err := terminalOutput.ReadString('\n')
		readyOutput.WriteString(line)
		if err != nil {
			t.Fatalf("read live guest signal readiness from %q: %v", readyOutput.String(), err)
		}
		if readyOutput.Len() > 4096 {
			t.Fatalf("live guest signal command did not become ready: %q", readyOutput.String())
		}
	}
	signaler, ok := session.(driver.ExecTerminalSignaler)
	if !ok {
		t.Fatal("live guest terminal does not expose process-group signaling")
	}
	if err := signaler.Signal(ctx, driver.ExecSignalTerminate); err != nil {
		t.Fatalf("signal live guest process group with TERM: %v", err)
	}
	output, err := io.ReadAll(terminalOutput)
	if err != nil {
		t.Fatalf("read live guest signal output: %v", err)
	}
	exitCode, err := session.Wait(ctx)
	if err != nil || exitCode != 43 || !bytes.Contains(output, []byte("terminated")) {
		t.Fatalf("live guest TERM signal = exit %d output %q err=%v; want trap exit 43", exitCode, output, err)
	}
}
