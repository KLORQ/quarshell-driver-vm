package vm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-core/isolation"
	"github.com/KLORQ/quarshell-driver-vm/vmguest"
	"github.com/KLORQ/quarshell-driver/driver"
	corepolicy "github.com/KLORQ/quarshell-policy/corepolicy"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	defaultVMStartupTimeout             = 2 * time.Minute
	workerStopTimeout                   = 10 * time.Second
	guestSupervisorControlCredentialDir = "/run/quarshell/supervisor-control-private"
)

func (d *Driver) Start(ctx context.Context, id core.ID) error {
	return d.start(ctx, id, driver.RuntimeLaunchCredentials{})
}

// StartWithToken starts a VM generation with a transient Gateway supervisor
// bearer. The bearer is consumed by the host proxy's private token file and is
// never included in durable sandbox state or the VM worker configuration.
func (d *Driver) StartWithToken(ctx context.Context, id core.ID, token string) error {
	if strings.TrimSpace(token) == "" || token != strings.TrimSpace(token) || strings.ContainsAny(token, "\r\n\x00") {
		return fmt.Errorf("vm driver: StartWithToken requires a valid non-empty sandbox bearer")
	}
	return d.start(ctx, id, driver.RuntimeLaunchCredentials{GatewayToken: token})
}

// StartWithCredentials starts a VM with the complete OpenShell supervisor
// credential pair. Credentials are only projected into the broker's private
// mode-0600 auth bundle for this launch.
func (d *Driver) StartWithCredentials(ctx context.Context, id core.ID, credentials driver.RuntimeLaunchCredentials) error {
	if !validRuntimeLaunchCredentials(credentials) {
		return fmt.Errorf("vm driver: StartWithCredentials requires paired tokens, valid expiry metadata, positive auth epoch, and session rotation")
	}
	return d.start(ctx, id, credentials)
}

func validRuntimeLaunchCredentials(credentials driver.RuntimeLaunchCredentials) bool {
	for _, token := range []string{credentials.GatewayToken, credentials.SandboxToken} {
		if strings.TrimSpace(token) == "" || token != strings.TrimSpace(token) || strings.ContainsAny(token, "\r\n\x00") {
			return false
		}
	}
	now := time.Now()
	if credentials.SandboxID == "" || strings.TrimSpace(credentials.SandboxID) != credentials.SandboxID || strings.ContainsAny(credentials.SandboxID, " \t\r\n") || credentials.GatewayID == "" || strings.TrimSpace(credentials.GatewayID) != credentials.GatewayID || strings.ContainsAny(credentials.GatewayID, " \t\r\n") || len(credentials.VerificationKeys) == 0 || len(credentials.VerificationKeys) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(credentials.VerificationKeys))
	for _, key := range credentials.VerificationKeys {
		if key.KeyID == "" || strings.TrimSpace(key.KeyID) != key.KeyID || strings.ContainsAny(key.KeyID, " \t\r\n") || len(key.PublicKeyPEM) == 0 {
			return false
		}
		if _, exists := seen[key.KeyID]; exists {
			return false
		}
		seen[key.KeyID] = struct{}{}
		block, rest := pem.Decode(key.PublicKeyPEM)
		if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
			return false
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		publicKey, ok := parsed.(ed25519.PublicKey)
		if err != nil || !ok || len(publicKey) != ed25519.PublicKeySize {
			return false
		}
	}
	validExpiry := func(expiresAt time.Time) bool { return expiresAt.IsZero() || expiresAt.After(now) }
	return validOpenShellRuntimeGeneration(credentials.RuntimeGeneration) && canonicalNonNilUUID(credentials.SessionID) && validExpiry(credentials.GatewayExpiresAt) && validExpiry(credentials.SandboxExpiresAt) && credentials.CredentialEpoch > 0 && credentials.SessionRotation > 0
}

func validOpenShellRuntimeGeneration(value string) bool {
	if len(value) == 0 || len(value) > 64 || strings.ToLower(value) != value {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func environmentValue(entries []string, key string) string {
	prefix := key + "="
	for i := len(entries) - 1; i >= 0; i-- {
		if strings.HasPrefix(entries[i], prefix) {
			return strings.TrimPrefix(entries[i], prefix)
		}
	}
	return ""
}

func (d *Driver) start(ctx context.Context, id core.ID, credentials driver.RuntimeLaunchCredentials) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: Start requires a driver and context")
	}
	if d.lifecycleExtensionsErr != nil {
		return fmt.Errorf("vm driver lifecycle extensions: %w", d.lifecycleExtensionsErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	state, err := store.load(string(id))
	if err != nil {
		return err
	}
	recovered, err := d.recoverWorker(ctx, store, state)
	if err != nil {
		return err
	}
	if recovered && credentials.GatewayToken == "" {
		_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
		if err := d.rotateGuestControlToken(ctx, state.ID, guestSocket); err != nil {
			return err
		}
		d.finishRestore(ctx, state.ID, state.LifecycleExtensions)
		return nil
	}
	if recovered {
		if err := d.stopLocked(ctx, store, state); err != nil {
			return fmt.Errorf("replace recovered VM runtime credentials: %w", err)
		}
		state, err = store.load(string(id))
		if err != nil {
			return err
		}
	}
	if state.Status == "running" {
		_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, pingErr := d.exchangeControl(pingCtx, state.ID, guestSocket, controlRequest{Operation: "ping"})
		cancel()
		if pingErr == nil {
			if credentials.GatewayToken == "" {
				if err := d.rotateGuestControlToken(ctx, state.ID, guestSocket); err != nil {
					return err
				}
				d.finishRestore(ctx, state.ID, state.LifecycleExtensions)
				return nil
			}
			if err := d.stopLocked(ctx, store, state); err != nil {
				return fmt.Errorf("replace running VM runtime credentials: %w", err)
			}
			state, err = store.load(string(id))
			if err != nil {
				return err
			}
		}
		state.Status = "stopped"
		state.UpdatedAt = time.Now().UTC()
		if err := store.save(state); err != nil {
			return fmt.Errorf("repair stale VM state: %w", err)
		}
	}
	if state.Status != "created" && state.Status != "stopped" && state.Status != "completed" && state.Status != "error" {
		return fmt.Errorf("vm driver: sandbox %q cannot start from status %q", state.Name, state.Status)
	}
	launchSpec, configured := d.launchSpecs[state.ID]
	if !configured || len(launchSpec.Command) == 0 {
		return fmt.Errorf("vm driver: sandbox %q workload spec is unavailable; restore it from the durable control-plane spec before starting", state.Name)
	}
	if credentials.GatewayToken != "" {
		if err := validateTokenAwareLaunchSpec(launchSpec); err != nil {
			return err
		}
		if credentials.SandboxToken != "" {
			launchSpec.ProxyEnv = withSupervisorCredentials(launchSpec.ProxyEnv, credentials)
			launchSpec.GatewaySandboxID = credentials.SandboxID
			launchSpec.GatewayID = credentials.GatewayID
			launchSpec.VerificationKeys = cloneRuntimeVerificationKeys(credentials.VerificationKeys)
			launchSpec.Env = withSupervisorBoundaryKeys(launchSpec.Env, credentials.GatewayID, credentials.SandboxID)
			launchSpec.Env = withSandboxSessionCredentials(launchSpec.Env, credentials)
		} else {
			launchSpec.ProxyEnv = withSupervisorToken(launchSpec.ProxyEnv, credentials.GatewayToken)
		}
	}
	if _, err := probeHost(runtime.GOOS, runtime.GOARCH, d.host); err != nil {
		return fmt.Errorf("vm driver host preflight: %w", err)
	}
	if err := d.startLocked(ctx, store, state, launchSpec); err != nil {
		return err
	}
	d.finishRestore(ctx, state.ID, state.LifecycleExtensions)
	return nil
}

func withSandboxSessionCredentials(entries []string, credentials driver.RuntimeLaunchCredentials) []string {
	for _, key := range []string{"QUARSHELL_SANDBOX_PROTOCOL_TOKEN", "QUARSHELL_RUNTIME_GENERATION", "QUARSHELL_AUTH_EPOCH"} {
		entries = withoutEnvironmentKey(entries, key)
	}
	return append(entries,
		"QUARSHELL_SANDBOX_PROTOCOL_TOKEN="+credentials.SandboxToken,
		"QUARSHELL_RUNTIME_GENERATION="+credentials.RuntimeGeneration,
		"QUARSHELL_AUTH_EPOCH="+strconv.FormatUint(credentials.CredentialEpoch, 10),
	)
}

func cloneRuntimeVerificationKeys(keys []driver.RuntimeVerificationKey) []driver.RuntimeVerificationKey {
	cloned := make([]driver.RuntimeVerificationKey, len(keys))
	for i, key := range keys {
		cloned[i] = driver.RuntimeVerificationKey{KeyID: key.KeyID, PublicKeyPEM: bytes.Clone(key.PublicKeyPEM)}
	}
	return cloned
}

func withSupervisorBoundaryKeys(entries []string, gatewayID, sandboxID string) []string {
	entries = withoutEnvironmentKey(entries, "QUARSHELL_GATEWAY_ID")
	entries = withoutEnvironmentKey(entries, "QUARSHELL_GATEWAY_VERIFICATION_KEYS_FILE")
	entries = withoutEnvironmentKey(entries, "QUARSHELL_GATEWAY_SANDBOX_ID")
	return append(entries,
		"QUARSHELL_GATEWAY_ID="+gatewayID,
		"QUARSHELL_GATEWAY_VERIFICATION_KEYS_FILE=/run/quarshell/supervisor-control-private/gateway-verification-keys.json",
		"QUARSHELL_GATEWAY_SANDBOX_ID="+sandboxID,
	)
}

func validateTokenAwareLaunchSpec(spec vmLaunchSpec) error {
	if spec.ProxyBin == "" || spec.PolicyPath == "" || spec.SupervisorBin == "" {
		return fmt.Errorf("vm driver: token-aware start requires host proxy, policy, and guest supervisor assets")
	}
	return nil
}

func withoutEnvironmentKey(entries []string, key string) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		name, _, _ := strings.Cut(entry, "=")
		if name != key {
			out = append(out, entry)
		}
	}
	return out
}

func withSupervisorToken(entries []string, token string) []string {
	environment := withoutEnvironmentKey(entries, "QUARSHELL_SANDBOX_TOKEN")
	return append(environment, "QUARSHELL_SANDBOX_TOKEN="+token)
}

func withGatewaySandboxID(entries []string, sandboxID string) []string {
	environment := withoutEnvironmentKey(entries, "QUARSHELL_GATEWAY_SANDBOX_ID")
	if sandboxID == "" {
		return environment
	}
	return append(environment, "QUARSHELL_GATEWAY_SANDBOX_ID="+sandboxID)
}

func withSupervisorCredentials(entries []string, credentials driver.RuntimeLaunchCredentials) []string {
	keys := []string{
		"QUARSHELL_SANDBOX_TOKEN", "QUARSHELL_SANDBOX_PROTOCOL_TOKEN",
		"QUARSHELL_GATEWAY_TOKEN_EXPIRES_AT", "QUARSHELL_SANDBOX_TOKEN_EXPIRES_AT",
		"QUARSHELL_AUTH_EPOCH", "QUARSHELL_SESSION_ROTATION",
		"QUARSHELL_RUNTIME_GENERATION",
		"QUARSHELL_SESSION_ID",
	}
	for _, key := range keys {
		entries = withoutEnvironmentKey(entries, key)
	}
	return append(entries,
		"QUARSHELL_SANDBOX_TOKEN="+credentials.GatewayToken,
		"QUARSHELL_SANDBOX_PROTOCOL_TOKEN="+credentials.SandboxToken,
		"QUARSHELL_GATEWAY_TOKEN_EXPIRES_AT="+strconv.FormatInt(credentialExpiryUnix(credentials.GatewayExpiresAt), 10),
		"QUARSHELL_SANDBOX_TOKEN_EXPIRES_AT="+strconv.FormatInt(credentialExpiryUnix(credentials.SandboxExpiresAt), 10),
		"QUARSHELL_AUTH_EPOCH="+strconv.FormatUint(credentials.CredentialEpoch, 10),
		"QUARSHELL_SESSION_ROTATION="+strconv.FormatUint(credentials.SessionRotation, 10),
		"QUARSHELL_RUNTIME_GENERATION="+credentials.RuntimeGeneration,
		"QUARSHELL_SESSION_ID="+credentials.SessionID,
	)
}

func credentialExpiryUnix(expiresAt time.Time) int64 {
	if expiresAt.IsZero() {
		return 0
	}
	return expiresAt.Unix()
}

func (d *Driver) finishRestore(ctx context.Context, id string, names []string) {
	restore, ok := d.pendingRestores[id]
	if !ok {
		return
	}
	delete(d.pendingRestores, id)
	restore.Status = "running"
	d.lifecycleExtensions.AfterRestore(ctx, restore, names)
}

func (d *Driver) startLocked(ctx context.Context, store *stateStore, state sandboxState, launchSpec vmLaunchSpec) (startErr error) {
	spec := launchSpec.vmCreateSpec
	driverConfig, err := ParseSandboxDriverConfig(spec.DriverConfigJSON)
	if err != nil {
		return err
	}
	if driverConfig.GuestTLSCA == "" {
		driverConfig.GuestTLSCA = d.host.GuestTLSCA
	}
	sandboxDir := filepath.Join(store.root, "sandboxes", state.ID)
	extensionPlan := &ExtensionLaunchPlan{}
	if err := d.lifecycleExtensions.ConfigureLaunch(ctx, spec, sandboxDir, extensionPlan); err != nil {
		return err
	}
	if err := d.lifecycleExtensions.BeforeLaunch(ctx, spec, sandboxDir, state.LifecycleExtensions, extensionPlan); err != nil {
		d.lifecycleExtensions.AfterLaunchFailed(context.Background(), sandboxDir, state.LifecycleExtensions, LaunchAbortBeforeLaunchFailed)
		return err
	}
	dropinsDigest, err := guestInitDropinsDigest(extensionPlan.GuestInitDropins)
	if err != nil {
		return err
	}
	if dropinsDigest != state.LifecycleDropinsDigest {
		return fmt.Errorf("vm driver: launch guest init drop-ins do not match the durable sandbox overlay")
	}
	worker, err := workerPath(d.host.WorkerPath)
	if err != nil {
		return err
	}
	overlayPath := filepath.Join(store.root, "sandboxes", state.ID, "overlay.ext4")
	if err := validateSandboxArtifacts(store.root, state, overlayPath); err != nil {
		return err
	}
	workerControlPath, guestSocket, consolePath := workerSocketPaths(store.root, state.ID)
	brokerSocket := networkBrokerSocketPath(workerControlPath, state.ID)
	brokerVsockSocket := networkBrokerVsockSocketPath(workerControlPath, state.ID)
	sshSocket := sshRelaySocketPath(workerControlPath, state.ID)
	supervisorSocket := supervisorControlSocketPath(workerControlPath, state.ID)
	supervisorProxySocket := supervisorProxySocketPath(workerControlPath, state.ID)
	if err := validateWorkerSocket(workerControlPath); err != nil {
		return err
	}
	for _, socket := range []string{workerControlPath, guestSocket, brokerSocket, brokerVsockSocket, sshSocket, supervisorSocket, supervisorProxySocket} {
		if err := removeStaleUnixSocket(socket); err != nil {
			return err
		}
	}
	controlToken, err := readControlToken(filepath.Join(store.root, "sandboxes", state.ID))
	if err != nil {
		return err
	}
	console, err := os.OpenFile(consolePath+".worker", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open VM console log: %w", err)
	}
	if err := console.Chmod(0o600); err != nil {
		_ = console.Close()
		return fmt.Errorf("secure VM console log: %w", err)
	}
	launch := KrunLaunchConfig{
		RootDisk: state.Rootfs, OverlayDisk: overlayPath, ImageDisk: state.WorkloadDisk, ServiceDataDisk: state.ServiceDataDisk,
		VCPUs: state.VCPUs, MemoryMiB: state.MemoryMiB, WorkDir: "/",
		KrunLogLevel: configuredKrunLogLevel(d.host),
		ExecPath:     "/bin/sh", Args: []string{"/opt/quarshell/vm-init"},
		Env:         []string{"QUARSHELL_VM_CONTROL_TOKEN=" + controlToken},
		ConsolePath: consolePath, VsockPort: guestControlPort, VsockSocket: guestSocket,
	}
	if d.host.SandboxUID != nil {
		launch.Env = append(launch.Env, "QUARSHELL_VM_SANDBOX_UID="+strconv.FormatUint(uint64(*d.host.SandboxUID), 10))
	}
	if d.host.SandboxGID != nil {
		launch.Env = append(launch.Env, "QUARSHELL_VM_SANDBOX_GID="+strconv.FormatUint(uint64(*d.host.SandboxGID), 10))
	}
	if state.WorkloadDisk != "" {
		launch.Env = append(launch.Env, "QUARSHELL_VM_IMAGE_DISK=1")
	}
	if state.ServiceDataDisk != "" {
		device := "/dev/vdc"
		if state.WorkloadDisk != "" {
			device = "/dev/vdd"
		}
		launch.Env = append(launch.Env, "QUARSHELL_VM_SERVICE_DATA_DISK="+device)
	}
	var proxyCABundle []byte
	var controlIdentity *vmControlIdentity
	var isolationDescriptor []byte
	var brokerConfig *networkBrokerConfig
	if spec.ProxyBin != "" {
		proxyCABundlePEM, err := guestProxyCABundle(spec.ProxyEnv)
		if err != nil {
			_ = console.Close()
			return err
		}
		proxyCABundle = []byte(proxyCABundlePEM)
		proxyPort := vmGuestProxyPort(spec.ProxyPort)
		launch.Env = append(launch.Env,
			"QUARSHELL_VM_NETWORK_BROKER_PORT="+strconv.Itoa(int(networkBrokerVsockPort)),
			"QUARSHELL_VM_NETWORK_PROXY_PORT="+strconv.Itoa(proxyPort),
		)
		launch.VsockPorts = append(launch.VsockPorts, KrunVsockPort{Port: networkBrokerVsockPort, Socket: brokerVsockSocket, Listen: true})
		proxyEnv := append([]string(nil), spec.ProxyEnv...)
		endpoint := resolveSupervisorGatewayEndpoint(d.host.GRPCEndpoint, driverConfig.GRPCEndpoint)
		endpoint = resolveSupervisorGatewayEndpoint(endpoint, spec.GatewayURL)
		gatewayURL := strings.TrimSpace(spec.GatewayURL)
		if gatewayURL == "" {
			gatewayURL = endpoint
		}
		proxyEnv = withoutEnvironmentKey(proxyEnv, "QUARSHELL_GATEWAY_URL")
		proxyEnv = withoutEnvironmentKey(proxyEnv, "QUARSHELL_SANDBOX")
		if gatewayURL != "" {
			proxyEnv = append(proxyEnv, "QUARSHELL_GATEWAY_URL="+gatewayURL)
		}
		proxySandboxID := launchSpec.GatewaySandboxID
		if proxySandboxID == "" {
			proxySandboxID = state.ID
		}
		proxyEnv = withGatewaySandboxID(proxyEnv, proxySandboxID)
		proxyEnv = append(proxyEnv, "QUARSHELL_SANDBOX="+state.ID)
		if endpoint != "" {
			proxyEnv = append(proxyEnv, "QUARSHELL_GATEWAY_GRPC_ENDPOINT="+endpoint)
		}
		if driverConfig.GuestTLSCA != "" {
			proxyEnv = append(proxyEnv, "QUARSHELL_GUEST_TLS_CA="+driverConfig.GuestTLSCA)
		}
		if driverConfig.GuestTLSCert != "" {
			proxyEnv = append(proxyEnv, "QUARSHELL_GUEST_TLS_CERT="+driverConfig.GuestTLSCert)
		}
		if driverConfig.GuestTLSKey != "" {
			proxyEnv = append(proxyEnv, "QUARSHELL_GUEST_TLS_KEY="+driverConfig.GuestTLSKey)
		}
		brokerConfig = &networkBrokerConfig{
			Binary: spec.ProxyBin, Policy: spec.PolicyPath,
			Socket: brokerSocket, LogDir: filepath.Join(store.root, "sandboxes", state.ID),
			ProxyEnv: proxyEnv,
		}
		if spec.SupervisorBin != "" {
			runtimePaths := []string{worker, d.host.GuestAgentPath, spec.SupervisorBin, spec.InitBin}
			if spec.SSHBin != "" {
				runtimePaths = append(runtimePaths, spec.SSHBin)
			}
			runtimeDigest, err := vmRuntimeDigest(runtimePaths...)
			if err != nil {
				_ = console.Close()
				return err
			}
			identity, err := createVMControlIdentity(filepath.Join(store.root, "sandboxes", state.ID, "supervisor-control"), state.ID, state.RootfsSourceDigest, runtimeDigest, environmentValue(spec.ProxyEnv, "QUARSHELL_RUNTIME_GENERATION"), environmentValue(spec.ProxyEnv, "QUARSHELL_SESSION_ID"))
			if err != nil {
				_ = console.Close()
				return err
			}
			state.RuntimeGeneration = identity.Generation
			state.RuntimeSessionID = identity.SessionID
			state.RuntimeDigest = runtimeDigest
			state.UpdatedAt = time.Now().UTC()
			if err := store.save(state); err != nil {
				_ = console.Close()
				return fmt.Errorf("persist VM runtime generation before launch: %w", err)
			}
			descriptor, err := buildVMIsolationDescriptor(state, identity)
			if err != nil {
				_ = console.Close()
				return fmt.Errorf("build VM isolation descriptor: %w", err)
			}
			isolationDescriptor = descriptor
			if err := writeVMIsolationDescriptor(sandboxDir, descriptor); err != nil {
				_ = console.Close()
				return fmt.Errorf("publish VM isolation descriptor: %w", err)
			}
			if _, err := readVMIsolationDescriptor(sandboxDir, state); err != nil {
				_ = console.Close()
				return fmt.Errorf("verify published VM isolation descriptor: %w", err)
			}
			controlIdentity = &identity
			proxyEnv = append(proxyEnv,
				"QUARSHELL_SUPERVISOR_CONTROL_SERVER_CA="+identity.CAPath,
				"QUARSHELL_SUPERVISOR_CONTROL_SERVER_CERT="+identity.ServerCertPath,
				"QUARSHELL_SUPERVISOR_CONTROL_SERVER_KEY="+identity.ServerKeyPath,
				"QUARSHELL_SUPERVISOR_CONTROL_EXPECTED_CLIENT_IDENTITY="+identity.ExpectedClientIdentity,
				"QUARSHELL_ISOLATION_DESCRIPTOR_PATH="+filepath.Join(sandboxDir, vmIsolationDescriptorFile),
				"QUARSHELL_ADMITTED_ISOLATION_BACKEND=quarshell/vm",
			)
			brokerConfig.ProxyEnv = proxyEnv
			launch.Env = append(launch.Env,
				"QUARSHELL_VM_SUPERVISOR_ENABLED=1",
				"QUARSHELL_VM_SUPERVISOR_CONTROL_PORT="+strconv.Itoa(int(supervisorControlPort)),
			)
			launch.VsockPorts = append(launch.VsockPorts, KrunVsockPort{Port: supervisorControlPort, Socket: supervisorSocket, Listen: true})
			brokerConfig.ControlSocket = supervisorProxySocket
		}
		if spec.EnableSSH {
			launch.Env = append(launch.Env, "QUARSHELL_VM_SSH_RELAY_PORT="+strconv.Itoa(int(sshRelayVsockPort)))
			launch.VsockPorts = append(launch.VsockPorts, KrunVsockPort{Port: sshRelayVsockPort, Socket: sshSocket, Listen: true})
			brokerConfig.SSHSocket = sshSocket
		}
	}
	// Keep the policy proxy and its Gateway credentials in the host driver
	// process tree, outside the VM worker. The worker receives only local
	// socket paths needed to configure libkrun's vsock mappings.
	var brokerProcess *networkBrokerProcess
	if brokerConfig != nil {
		brokerProcess, err = startNetworkBroker(brokerConfig)
		if err != nil {
			_ = console.Close()
			return fmt.Errorf("start host VM policy broker: %w", err)
		}
	}
	brokerStarted := false
	var supervisorForwardCancel context.CancelFunc
	defer func() {
		if !brokerStarted {
			if supervisorForwardCancel != nil {
				supervisorForwardCancel()
				delete(d.supervisorForwarders, state.ID)
			}
			stopNetworkBroker(brokerProcess)
		}
	}()
	workerBrokerConfig := workerNetworkBrokerConfig(brokerConfig)
	if workerBrokerConfig != nil && brokerConfig != nil && brokerConfig.ControlSocket != "" {
		workerBrokerConfig.ControlSocket = supervisorSocket
	}
	if workerBrokerConfig != nil && brokerConfig != nil && brokerConfig.Socket != "" {
		workerBrokerConfig.Socket = brokerVsockSocket
	}
	isolationFunc := d.host.workerIsolation
	if isolationFunc == nil {
		isolationFunc = workerIsolationForChild
	}
	workerIsolation, err := isolationFunc()
	if err != nil {
		_ = console.Close()
		return fmt.Errorf("prepare VM worker isolation: %w", err)
	}
	config, err := workerConfigJSON(workerConfig{RuntimeDir: d.host.RuntimeDir, ControlSocket: workerControlPath, Isolation: workerIsolation, WatchParentLiveness: true, NetworkBroker: workerBrokerConfig, Launch: launch})
	if err != nil {
		_ = console.Close()
		return err
	}
	command := exec.Command(worker)
	command.Stdin = bytes.NewReader(config)
	command.Stdout = console
	command.Stderr = console
	command.Env = workerEnvironment(d.host.RuntimeDir)
	processAttributes := d.host.workerProcessAttributes
	if processAttributes == nil {
		processAttributes = workerProcessAttributes
	}
	command.SysProcAttr = processAttributes()
	launchSpec.Env = append(launchSpec.Env, extensionPlan.Environment...)
	parentLiveness, err := startWorkerWithParentLiveness(command)
	if err != nil {
		d.lifecycleExtensions.AfterLaunchFailed(context.Background(), sandboxDir, state.LifecycleExtensions, LaunchAbortLauncherSpawnFailed)
		_ = console.Close()
		return fmt.Errorf("start libkrun worker: %w", err)
	}
	_ = console.Close()
	d.workers[state.ID] = command
	d.workerLiveness[state.ID] = parentLiveness
	done := make(chan error, 1)
	d.workerDone[state.ID] = done
	go func() {
		done <- command.Wait()
		close(done)
	}()
	started := false
	defer func() {
		if started {
			brokerStarted = true
			d.brokers[state.ID] = brokerProcess
			if brokerProcess != nil {
				go watchHostNetworkBroker(brokerProcess, command)
			}
			go d.watchWorker(state.ID, store.root, command, done)
			return
		}
		d.lifecycleExtensions.AfterLaunchFailed(context.Background(), sandboxDir, state.LifecycleExtensions, LaunchAbortLauncherSpawnFailed)
		if startErr != nil {
			forceStopWorker(workerControlPath)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = killWorkerProcessGroup(command)
				<-done
			}
			delete(d.workers, state.ID)
			delete(d.workerDone, state.ID)
			d.closeWorkerLiveness(state.ID)
		}
	}()

	startupCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		startupCtx, cancel = context.WithTimeout(ctx, defaultVMStartupTimeout)
		defer cancel()
	}
	if err := waitForWorkerOrExit(startupCtx, workerControlPath, done); err != nil {
		return err
	}
	if err := d.waitForGuestOrExit(startupCtx, state.ID, guestSocket, done); err != nil {
		return err
	}
	if brokerConfig != nil {
		forwardCtx, cancel := context.WithCancel(context.Background())
		supervisorForwardCancel = cancel
		d.supervisorForwarders[state.ID] = cancel
		go forwardNetworkProxy(forwardCtx, brokerVsockSocket, brokerConfig.Socket)
		if brokerConfig.ControlSocket != "" {
			go forwardSupervisorControl(forwardCtx, supervisorSocket, brokerConfig.ControlSocket)
		}
	}
	if len(proxyCABundle) > 0 {
		if _, err := d.exchangeControl(startupCtx, state.ID, guestSocket, controlRequest{
			Operation: "install-proxy-ca", Data: proxyCABundle,
		}); err != nil {
			return fmt.Errorf("install corporate proxy CA in guest trust store: %w", err)
		}
	}
	if spec.SupervisorBin != "" || spec.EnableSSH {
		if err := d.installGuestRuntimeAssets(startupCtx, state.ID, guestSocket, launchSpec, controlIdentity); err != nil {
			return err
		}
	}
	if spec.EnableSSH {
		if _, err := d.exchangeControl(startupCtx, state.ID, guestSocket, controlRequest{Operation: "start-ssh"}); err != nil {
			return fmt.Errorf("start guest SSH relay: %w", err)
		}
	}
	mainProcessTTYSessionID, err := newTerminalSessionID()
	if err != nil {
		return err
	}
	startResponse, err := d.exchangeControl(startupCtx, state.ID, guestSocket, controlRequest{
		Operation: "start-workload", Argv: launchSpec.Command,
		Env: launchSpec.Env, RestartPolicy: launchSpec.MainProcessRestartPolicy,
		WorkDir: launchSpec.WorkDir, User: launchSpec.User, TTY: spec.TTY,
		AwaitMainProcessAttachment: spec.AwaitMainProcessAttachment,
		SessionID:                  mainProcessTTYSessionID, Columns: defaultTerminalColumns, Rows: defaultTerminalRows,
	})
	if err != nil {
		return fmt.Errorf("start guest workload: %w", err)
	}
	if startResponse.WorkloadUID == 0 || startResponse.WorkloadGID == 0 {
		return fmt.Errorf("start guest workload: guest did not report a non-root workload identity")
	}
	if startResponse.SessionID != mainProcessTTYSessionID {
		return fmt.Errorf("start guest workload: guest did not retain the requested canonical process session")
	}
	if spec.PolicyPath != "" {
		if err := validateVMPolicyWorkloadIdentity(spec.PolicyPath, startResponse.WorkloadUID, startResponse.WorkloadGID); err != nil {
			return fmt.Errorf("start guest workload: %w", err)
		}
	}
	if spec.SupervisorBin != "" {
		if launchSpec.GatewayID != "" && len(launchSpec.VerificationKeys) > 0 {
			identityDigest := vmWorkloadIdentityDigest(startResponse.WorkloadUID, startResponse.WorkloadGID)
			sandboxContext := isolation.SandboxContext{
				SandboxID: state.ID, SessionID: state.RuntimeSessionID, Generation: state.RuntimeGeneration,
				RootfsDigest: state.RootfsSourceDigest, RuntimeDigest: state.RuntimeDigest,
				WorkloadUID: startResponse.WorkloadUID, WorkloadGID: startResponse.WorkloadGID,
				IdentitySource: vmIdentitySource, IdentityDigest: identityDigest,
			}
			backend := &vmIsolationBackend{
				driver: d, state: state, sandboxDir: sandboxDir, guestSocket: guestSocket,
				descriptor: isolationDescriptor, worker: command, broker: brokerProcess,
				brokerSocket: brokerSocket, workloadUID: startResponse.WorkloadUID,
				workloadGID: startResponse.WorkloadGID, controlID: controlIdentity,
				proxyEnabled: spec.ProxyBin != "" && spec.PolicyPath != "",
			}
			registry := isolation.NewRegistry()
			if err := registry.Register(backend); err != nil {
				return fmt.Errorf("register VM isolation backend: %w", err)
			}
			attached, err := registry.Attach(startupCtx, isolationDescriptor, vmIsolationBackendName, sandboxContext)
			if err != nil {
				return fmt.Errorf("attach and confirm VM isolation backend: %w", err)
			}
			if err := attached.Start(startupCtx); err != nil {
				return fmt.Errorf("start workload through confirmed VM isolation backend: %w", err)
			}
			if err := attached.Close(context.WithoutCancel(startupCtx)); err != nil {
				return fmt.Errorf("close VM isolation attach handle: %w", err)
			}
		} else if _, err := d.exchangeControl(startupCtx, state.ID, guestSocket, controlRequest{Operation: "confirm-workload"}); err != nil {
			return fmt.Errorf("confirm guest workload behind VM isolation boundary: %w", err)
		}
	}
	if err := d.rotateGuestControlToken(startupCtx, state.ID, guestSocket); err != nil {
		return fmt.Errorf("rotate guest control token after startup: %w", err)
	}
	state.Status = "running"
	state.MainProcessTTYSessionID = mainProcessTTYSessionID
	state.MainProcessSessionID = mainProcessTTYSessionID
	state.MainProcessTTY = spec.TTY
	state.WorkloadUID = startResponse.WorkloadUID
	state.WorkloadGID = startResponse.WorkloadGID
	state.MainProcessExitCode = nil
	state.MainProcessInstanceID = ""
	state.UpdatedAt = time.Now().UTC()
	if err := store.save(state); err != nil {
		return fmt.Errorf("persist running VM state: %w", err)
	}
	started = true
	return nil
}

// RecordMainProcessExit persists the exit reported by the authenticated
// sandbox supervisor. The report may arrive just before the guest powers off;
// watchWorker then preserves this terminal outcome instead of downgrading it
// to an operator stop.
func (d *Driver) RecordMainProcessExit(ctx context.Context, id core.ID, instanceID string, exitCode int32) error {
	if d == nil || ctx == nil || strings.TrimSpace(instanceID) == "" {
		return fmt.Errorf("vm driver: RecordMainProcessExit requires a driver, context, and instance ID")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	state, err := store.load(string(id))
	if err != nil {
		return err
	}
	if state.MainProcessExitCode != nil {
		if state.MainProcessInstanceID != instanceID || *state.MainProcessExitCode != exitCode {
			return fmt.Errorf("vm driver: conflicting main process exit result")
		}
		return nil
	}
	if state.Status != "running" && state.Status != "stopped" {
		return fmt.Errorf("vm driver: cannot record main process exit while sandbox is %q", state.Status)
	}
	code := exitCode
	state.MainProcessExitCode = &code
	state.MainProcessInstanceID = instanceID
	if state.Status == "running" {
		if exitCode == 0 {
			state.Status = "completed"
		} else {
			state.Status = "error"
		}
	}
	state.UpdatedAt = time.Now().UTC()
	return store.save(state)
}

// WaitMainProcess waits for the authenticated supervisor's durable canonical
// process result. The VM worker may already have powered off by the time the
// Gateway finishes delivering retained terminal output.
func (d *Driver) WaitMainProcess(ctx context.Context, id core.ID) (int, error) {
	if d == nil || ctx == nil {
		return 0, fmt.Errorf("vm driver: WaitMainProcess requires a driver and context")
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return 0, err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, loadErr := store.load(string(id))
		if loadErr != nil {
			return 0, loadErr
		}
		if state.MainProcessExitCode != nil {
			return int(*state.MainProcessExitCode), nil
		}
		if state.Status == "stopped" || state.Status == "deleted" {
			return 0, fmt.Errorf("vm driver: sandbox stopped before the main process reported an exit status")
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

var _ driver.MainProcessWaiter = (*Driver)(nil)

// SignalMainProcess sends a placement-neutral signal to the canonical guest
// workload process group over the authenticated supervisor control channel.
func (d *Driver) SignalMainProcess(ctx context.Context, id core.ID, signal driver.ExecProcessSignal) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: SignalMainProcess requires a driver and context")
	}
	if !validExecProcessSignal(signal) {
		return fmt.Errorf("vm driver: unsupported main-process signal %q", signal)
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	state, err := store.load(string(id))
	if err != nil {
		return err
	}
	if state.Status != "running" {
		return fmt.Errorf("vm driver: sandbox %q is %s", state.Name, state.Status)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	_, err = d.exchangeControl(ctx, state.ID, guestSocket, controlRequest{Operation: "signal-main-process", Signal: string(signal)})
	return err
}

var _ driver.MainProcessSignaler = (*Driver)(nil)

func (d *Driver) installGuestRuntimeAssets(ctx context.Context, id, guestSocket string, spec vmLaunchSpec, controlIdentity *vmControlIdentity) error {
	assets := make([]struct {
		host  string
		guest string
	}, 0, 4)
	if spec.SupervisorBin != "" {
		assets = append(assets, struct{ host, guest string }{spec.SupervisorBin, guestSupervisorBinary})
	}
	if spec.InitBin != "" {
		assets = append(assets, struct{ host, guest string }{spec.InitBin, guestInitBinary})
	}
	if spec.PolicyPath != "" && (spec.SupervisorBin != "" || spec.EnableSSH) {
		assets = append(assets, struct{ host, guest string }{spec.PolicyPath, guestPolicyFile})
	}
	if spec.EnableSSH {
		assets = append(assets, struct{ host, guest string }{spec.SSHBin, guestSSHBinary})
	}
	for _, asset := range assets {
		path, err := filepath.Abs(asset.host)
		if err != nil || filepath.Clean(path) != path {
			return fmt.Errorf("resolve guest runtime asset %q: invalid path", asset.host)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("guest runtime asset %q must be a regular file", asset.host)
		}
		if info.Size() <= 0 || info.Size() > controlFrameMax/2 {
			return fmt.Errorf("guest runtime asset %q exceeds the VM control transfer limit", asset.host)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read guest runtime asset %q: %w", asset.host, err)
		}
		mode := uint32(0o600)
		if info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		if _, err := d.exchangeControl(ctx, id, guestSocket, controlRequest{
			Operation: "copy-to", Path: asset.guest, Data: data, Mode: mode,
		}); err != nil {
			return fmt.Errorf("install guest runtime asset %q: %w", asset.guest, err)
		}
		if asset.guest == guestPolicyFile {
			installed, err := d.exchangeControl(ctx, id, guestSocket, controlRequest{Operation: "copy-from", Path: asset.guest})
			if err != nil {
				return fmt.Errorf("verify installed guest policy: %w", err)
			}
			if !bytes.Equal(installed.Data, data) {
				return fmt.Errorf("verify installed guest policy: guest content does not match host policy %q", path)
			}
		}
	}
	if controlIdentity != nil {
		for _, credential := range []struct {
			path string
			data []byte
		}{
			{guestControlCredentialDir + "/ca.pem", controlIdentity.ClientCA},
			{guestControlCredentialDir + "/client.crt", controlIdentity.ClientCert},
			{guestControlCredentialDir + "/client.key", controlIdentity.ClientKey},
		} {
			if _, err := d.exchangeControl(ctx, id, guestSocket, controlRequest{Operation: "copy-control-credential", Path: credential.path, Data: credential.data, Mode: 0o600}); err != nil {
				return fmt.Errorf("install private guest control credential: %w", err)
			}
		}
	}
	if spec.GatewayID != "" || len(spec.VerificationKeys) > 0 {
		if spec.GatewayID == "" || len(spec.VerificationKeys) == 0 || controlIdentity == nil {
			return fmt.Errorf("install guest Gateway verification keys: incomplete boundary authentication configuration")
		}
		keys := make([]struct {
			KeyID        string `json:"key_id"`
			PublicKeyPEM string `json:"public_key_pem"`
		}, 0, len(spec.VerificationKeys))
		for _, key := range spec.VerificationKeys {
			keys = append(keys, struct {
				KeyID        string `json:"key_id"`
				PublicKeyPEM string `json:"public_key_pem"`
			}{KeyID: key.KeyID, PublicKeyPEM: string(key.PublicKeyPEM)})
		}
		encoded, err := json.Marshal(keys)
		if err != nil {
			return fmt.Errorf("encode guest Gateway verification keys: %w", err)
		}
		if _, err := d.exchangeControl(ctx, id, guestSocket, controlRequest{
			Operation: "copy-control-credential",
			Path:      vmguest.SupervisorControlCredentialDir + "/gateway-verification-keys.json",
			Data:      encoded,
			Mode:      0o600,
		}); err != nil {
			return fmt.Errorf("install guest Gateway verification keys: %w", err)
		}
	}
	return nil
}

// RestoreLaunchSpec installs a durable control-plane workload spec after the
// Gateway process or compute driver has restarted. Runtime env/argv remain
// process-local and are never written to VM state.
func (d *Driver) restoreLaunchSpec(ctx context.Context, id core.ID, spec vmCreateSpec) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: RestoreLaunchSpec requires a driver and context")
	}
	if d.lifecycleExtensionsErr != nil {
		return fmt.Errorf("vm driver lifecycle extensions: %w", d.lifecycleExtensionsErr)
	}
	if err := d.lifecycleExtensions.ValidateActivationLabels(spec); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMainProcessRestartPolicy(spec); err != nil {
		return err
	}
	if err := validateNetworkBrokerSpec(spec); err != nil {
		return err
	}
	if _, err := ParseSandboxDriverConfig(spec.DriverConfigJSON); err != nil {
		return err
	}
	if err := validateGuestRuntimeAssets(spec); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	state, err := store.load(string(id))
	if err != nil {
		return err
	}
	activeExtensionNames := d.lifecycleExtensions.ActiveNames(spec)
	if !reflect.DeepEqual(activeExtensionNames, state.LifecycleExtensions) {
		return fmt.Errorf("vm driver: restored lifecycle extension selection does not match durable sandbox state")
	}
	if spec.Name != "" && spec.Name != state.Name {
		return fmt.Errorf("vm driver: restored workload name does not match sandbox state")
	}
	requestedSpec := cloneVMLaunchSpec(spec)
	if state.Status == "running" {
		if previous, configured := d.launchSpecInputs[state.ID]; configured && reflect.DeepEqual(previous, requestedSpec) {
			return nil
		}
		if _, configured := d.launchSpecs[state.ID]; configured {
			return fmt.Errorf("vm driver: cannot replace workload spec for running sandbox %q", state.Name)
		}
	}
	launchSpec := cloneVMLaunchSpec(spec)
	imageSource := state.workloadImageSource()
	if imageSource.Type == "oci" || imageSource.Type == "local-oci" {
		platform, err := v1.ParsePlatform(imageSource.Platform)
		if err != nil {
			return fmt.Errorf("vm driver: restore OCI workload platform: %w", err)
		}
		if platform == nil {
			return fmt.Errorf("vm driver: restore OCI workload platform is empty")
		}
		var imageConfig v1.Config
		if imageSource.Type == "local-oci" {
			imageConfig, err = resolveLocalOCIImageConfig(ctx, imageSource.Reference, imageSource.ManifestDigest, *platform, d.localImageEngines)
		} else {
			var resolved resolvedOCIImage
			resolved, err = resolveOCIImageAtDigestWithOptions(ctx, imageSource.Reference, imageSource.Digest, *platform, d.ociNameOptions, nil)
			imageConfig = resolved.ImageConfig
		}
		if err != nil {
			return fmt.Errorf("vm driver: restore OCI image config by pinned identity: %w", err)
		}
		launchSpec, err = applyOCIImageConfig(launchSpec, imageConfig)
		if err != nil {
			return fmt.Errorf("vm driver: restore OCI image config: %w", err)
		}
	} else if len(launchSpec.Command) == 0 {
		launchSpec.Command = defaultVMCommand()
	}
	restore := ExtensionRestoreContext{
		SandboxID: state.ID, SandboxName: state.Name, Status: state.Status,
		StateDir: filepath.Join(store.root, "sandboxes", state.ID),
	}
	restorePrepared := false
	defer func() {
		if !restorePrepared {
			d.lifecycleExtensions.AfterLaunchFailed(context.Background(), restore.StateDir, state.LifecycleExtensions, LaunchAbortRestoreFailed)
		}
	}()
	extensionPlan := &ExtensionLaunchPlan{}
	if err := d.lifecycleExtensions.ConfigureLaunch(ctx, spec, restore.StateDir, extensionPlan); err != nil {
		return err
	}
	dropinsDigest, err := guestInitDropinsDigest(extensionPlan.GuestInitDropins)
	if err != nil {
		return err
	}
	if dropinsDigest != state.LifecycleDropinsDigest {
		return fmt.Errorf("vm driver: restored lifecycle guest init drop-ins do not match durable sandbox state")
	}
	if err := d.lifecycleExtensions.BeforeRestore(ctx, restore, state.LifecycleExtensions); err != nil {
		return err
	}
	launchSpec.Env = append(launchSpec.Env, extensionPlan.Environment...)
	d.launchSpecs[state.ID] = launchSpec
	d.launchSpecInputs[state.ID] = requestedSpec
	d.pendingRestores[state.ID] = restore
	restorePrepared = true
	return nil
}

func validateSandboxArtifacts(root string, state sandboxState, overlayPath string) error {
	imageDir := filepath.Join(root, "images")
	if err := validateCachedDiskReference(imageDir, state.Rootfs, "rootfs"); err != nil {
		return err
	}
	if state.WorkloadDisk != "" {
		if filepath.Clean(state.WorkloadDisk) == filepath.Clean(state.Rootfs) {
			return fmt.Errorf("VM workload disk must be distinct from the bootstrap rootfs")
		}
		if err := validateCachedDiskReference(imageDir, state.WorkloadDisk, "workload"); err != nil {
			return err
		}
	}
	if state.ServiceDataDisk != "" {
		serviceDir := filepath.Join(root, "sandboxes", state.ID)
		relative, relErr := filepath.Rel(serviceDir, state.ServiceDataDisk)
		if relErr != nil || relative != "service-data.ext4" {
			return fmt.Errorf("VM state service data disk is outside its private sandbox directory")
		}
		serviceInfo, statErr := os.Lstat(state.ServiceDataDisk)
		if statErr != nil || !serviceInfo.Mode().IsRegular() || serviceInfo.Mode().Perm() != 0o600 || serviceInfo.Size() < 64<<20 {
			return fmt.Errorf("VM service data disk must be a private mode 0600 ext4 image of at least 64 MiB")
		}
		const ext4MagicOffset = 1024 + 0x38
		var magic [2]byte
		file, openErr := os.Open(state.ServiceDataDisk)
		if openErr != nil {
			return fmt.Errorf("open VM service data disk: %w", openErr)
		}
		_, readErr := file.ReadAt(magic[:], ext4MagicOffset)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || magic != [2]byte{0x53, 0xef} {
			return fmt.Errorf("VM service data disk has an invalid ext4 superblock")
		}
	}
	overlayInfo, err := os.Lstat(overlayPath)
	if err != nil {
		return fmt.Errorf("inspect VM overlay image: %w", err)
	}
	if !overlayInfo.Mode().IsRegular() || overlayInfo.Size() == 0 || overlayInfo.Mode().Perm() != 0o600 {
		return fmt.Errorf("VM overlay image must be a private mode 0600 regular file")
	}
	return nil
}

func validateCachedDiskReference(imageDir, imagePath, label string) error {
	imageRelative, err := filepath.Rel(imageDir, imagePath)
	if imagePath == "" || err != nil || filepath.IsAbs(imageRelative) || imageRelative == "." || strings.Contains(filepath.ToSlash(imageRelative), "/") || strings.HasPrefix(imageRelative, "..") || filepath.Ext(imageRelative) != ".ext4" {
		return fmt.Errorf("VM state %s disk path is outside the private image cache", label)
	}
	imageInfo, err := os.Lstat(imagePath)
	if err != nil {
		return fmt.Errorf("inspect VM %s disk image: %w", label, err)
	}
	if !imageInfo.Mode().IsRegular() || imageInfo.Size() == 0 || imageInfo.Mode().Perm()&0o222 != 0 {
		return fmt.Errorf("VM %s disk image must be a non-empty immutable regular file", label)
	}
	// ext4 stores its superblock at byte offset 1024 and the filesystem magic
	// at offset 0x38 within the superblock. Catch truncated or replaced cache
	// files before passing them to libkrun; otherwise the failure is deferred
	// to guest boot and is much harder to diagnose.
	const ext4MagicOffset = 1024 + 0x38
	var magic [2]byte
	file, err := os.Open(imagePath)
	if err != nil {
		return fmt.Errorf("open VM %s disk image: %w", label, err)
	}
	_, readErr := file.ReadAt(magic[:], ext4MagicOffset)
	closeErr := file.Close()
	if readErr != nil {
		return fmt.Errorf("VM %s disk image has no complete ext4 superblock: %w", label, readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close VM %s disk image: %w", label, closeErr)
	}
	if magic != [2]byte{0x53, 0xef} {
		return fmt.Errorf("VM %s disk image has invalid ext4 superblock magic", label)
	}
	return nil
}

func waitForWorkerOrExit(ctx context.Context, socket string, done <-chan error) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := workerControl(ctx, socket, "status")
		if err == nil && response.Ready {
			return nil
		}
		select {
		case workerErr := <-done:
			if workerErr == nil {
				workerErr = fmt.Errorf("worker exited without an error")
			}
			return fmt.Errorf("libkrun worker exited before ready: %w", workerErr)
		case <-ctx.Done():
			return fmt.Errorf("wait for libkrun worker: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (d *Driver) waitForGuestOrExit(ctx context.Context, id, socket string, done <-chan error) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := d.exchangeControl(ctx, id, socket, controlRequest{Operation: "ping"})
		if err == nil {
			return nil
		}
		select {
		case workerErr := <-done:
			if workerErr == nil {
				workerErr = fmt.Errorf("worker exited without an error")
			}
			return fmt.Errorf("libkrun worker exited before guest agent was ready: %w", workerErr)
		case <-ctx.Done():
			return fmt.Errorf("wait for guest control agent: %w (last error: %v)", ctx.Err(), err)
		case <-ticker.C:
		}
	}
}

func (d *Driver) recoverWorker(ctx context.Context, store *stateStore, state sandboxState) (bool, error) {
	workerSocketPath, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	if state.Status == "completed" || state.Status == "error" {
		// A terminal result is authoritative even if the supervisor has not yet
		// powered off the guest. Explicit Start must wait for the previous worker
		// to disappear before booting a fresh generation.
		forceStopWorker(workerSocketPath)
		if command := d.workers[state.ID]; command != nil && command.Process != nil {
			_ = killWorkerProcessGroup(command)
		}
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			probeCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			_, probeErr := workerControl(probeCtx, workerSocketPath, "status")
			cancel()
			if probeErr != nil {
				return false, nil
			}
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-deadline.C:
				return false, fmt.Errorf("vm driver: terminal worker %q did not stop before explicit start", state.Name)
			case <-ticker.C:
			}
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	status, err := workerControl(probeCtx, workerSocketPath, "status")
	cancel()
	if err != nil {
		return false, nil
	}
	startupCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var timeout context.CancelFunc
		startupCtx, timeout = context.WithTimeout(ctx, defaultVMStartupTimeout)
		defer timeout()
	}
	if err := d.waitForExistingGuest(startupCtx, state.ID, guestSocket); err != nil {
		return false, fmt.Errorf("recover VM worker (ready=%t): %w", status.Ready, err)
	}
	if state.Status != "running" {
		state.Status = "running"
		state.UpdatedAt = time.Now().UTC()
		if err := store.save(state); err != nil {
			return false, fmt.Errorf("persist recovered VM state: %w", err)
		}
	}
	return true, nil
}

func (d *Driver) waitForExistingGuest(ctx context.Context, id, socket string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := d.exchangeControl(ctx, id, socket, controlRequest{Operation: "ping"}); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type guestControlLiveness struct {
	grace            time.Duration
	unavailableSince time.Time
}

func (l *guestControlLiveness) observe(now time.Time, probeErr error) bool {
	if probeErr == nil {
		l.unavailableSince = time.Time{}
		return false
	}
	if l.unavailableSince.IsZero() {
		l.unavailableSince = now
	}
	return now.Sub(l.unavailableSince) >= l.grace
}

func (d *Driver) watchWorker(id, root string, command *exec.Cmd, done <-chan error) {
	_, guestSocket, _ := workerSocketPaths(root, id)
	probeTicker := time.NewTicker(250 * time.Millisecond)
	defer probeTicker.Stop()
	liveness := guestControlLiveness{grace: 2 * time.Second}
	for {
		select {
		case <-done:
			goto workerExited
		case <-probeTicker.C:
			probeCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			_, probeErr := d.exchangeControl(probeCtx, id, guestSocket, controlRequest{Operation: "ping"})
			cancel()
			if liveness.observe(time.Now(), probeErr) {
				// Some KVM/libkrun combinations leave the worker process alive
				// after the guest has powered itself off. A sustained loss of the
				// authenticated guest control endpoint is the host-visible proof
				// that the VM can no longer serve work; reap that worker so durable
				// lifecycle state converges to stopped.
				_ = killWorkerProcessGroup(command)
				<-done
				goto workerExited
			}
		}
	}

workerExited:
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.workers[id] != command {
		return
	}
	d.stopNetworkBroker(id)
	_ = killWorkerProcessGroup(command)
	delete(d.workers, id)
	delete(d.workerDone, id)
	d.closeWorkerLiveness(id)
	store, err := openStateStore(root)
	if err != nil {
		return
	}
	state, err := store.load(id)
	if err != nil || state.Status != "running" {
		return
	}
	state.Status = "stopped"
	state.UpdatedAt = time.Now().UTC()
	_ = store.save(state)
	d.lifecycleExtensions.AfterLaunchFailed(context.Background(), filepath.Join(root, "sandboxes", state.ID), state.LifecycleExtensions, LaunchAbortProcessExited)
}

func (d *Driver) stopNetworkBroker(id string) {
	if cancel := d.supervisorForwarders[id]; cancel != nil {
		cancel()
		delete(d.supervisorForwarders, id)
	}
	if process := d.brokers[id]; process != nil {
		stopNetworkBroker(process)
		delete(d.brokers, id)
	}
}

func (d *Driver) closeWorkerLiveness(id string) {
	if file := d.workerLiveness[id]; file != nil {
		_ = file.Close()
		delete(d.workerLiveness, id)
	}
}

func (d *Driver) Stop(ctx context.Context, id core.ID) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: Stop requires a driver and context")
	}
	if d.lifecycleExtensionsErr != nil {
		return fmt.Errorf("vm driver lifecycle extensions: %w", d.lifecycleExtensionsErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	state, err := store.load(string(id))
	if err != nil {
		return err
	}
	if _, err := d.lifecycleExtensions.ActiveByNames(state.LifecycleExtensions); err != nil {
		return err
	}
	return d.stopLocked(ctx, store, state)
}

func (d *Driver) stopLocked(ctx context.Context, store *stateStore, state sandboxState) error {
	if state.Status != "running" {
		d.stopNetworkBroker(state.ID)
		if state.Status == "created" {
			state.Status = "stopped"
			state.UpdatedAt = time.Now().UTC()
			return store.save(state)
		}
		return nil
	}
	workerControlPath, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	workerPID := 0
	if command := d.workers[state.ID]; command != nil && command.Process != nil {
		workerPID = command.Process.Pid
	} else if response, err := workerControl(ctx, workerControlPath, "status"); err == nil {
		workerPID = response.PID
	}
	// Guest poweroff is best-effort: libkrun can fail to observe an orderly
	// shutdown on some KVM hosts. Bound the graceful phase even when the caller
	// has a much longer request deadline, then terminate the worker below.
	shutdownCtx, cancelShutdown := context.WithTimeout(ctx, workerStopTimeout)
	defer cancelShutdown()
	if _, err := d.exchangeControl(shutdownCtx, state.ID, guestSocket, controlRequest{Operation: "stop-workload"}); err != nil {
		return fmt.Errorf("stop guest workload: %w", err)
	}
	if _, err := d.exchangeControl(shutdownCtx, state.ID, guestSocket, controlRequest{Operation: "shutdown"}); err != nil {
		return fmt.Errorf("request guest shutdown: %w", err)
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := workerControl(shutdownCtx, workerControlPath, "status"); err != nil {
			_ = killProcessGroup(workerPID)
			if err := d.waitForWorkerExit(state.ID, workerPID, workerControlPath); err != nil {
				return fmt.Errorf("wait for stopped VM worker: %w", err)
			}
			d.stopNetworkBroker(state.ID)
			state.Status = "stopped"
			state.UpdatedAt = time.Now().UTC()
			if err := store.save(state); err != nil {
				return fmt.Errorf("persist stopped VM state: %w", err)
			}
			d.lifecycleExtensions.AfterLaunchFailed(context.Background(), filepath.Join(store.root, "sandboxes", state.ID), state.LifecycleExtensions, LaunchAbortStopped)
			return nil
		}
		select {
		case <-shutdownCtx.Done():
			if workerPID <= 0 {
				return fmt.Errorf("force stop VM worker after guest shutdown timeout: worker PID is unavailable")
			}
			if err := killProcessGroup(workerPID); err != nil {
				return fmt.Errorf("force stop VM worker after guest shutdown timeout: %w", err)
			}
			if err := d.waitForWorkerExit(state.ID, workerPID, workerControlPath); err != nil {
				return fmt.Errorf("wait for forcibly stopped VM worker: %w", err)
			}
			d.stopNetworkBroker(state.ID)
			state.Status = "stopped"
			state.UpdatedAt = time.Now().UTC()
			if err := store.save(state); err != nil {
				return fmt.Errorf("persist stopped VM state after forced shutdown: %w", err)
			}
			d.lifecycleExtensions.AfterLaunchFailed(context.Background(), filepath.Join(store.root, "sandboxes", state.ID), state.LifecycleExtensions, LaunchAbortStopped)
			return nil
		case <-ticker.C:
		}
	}
}

// waitForWorkerExit waits for the exact worker launched by this driver. A
// recovered worker has no local exec.Cmd, so its control socket is polled
// until it disappears. The caller holds d.mu to keep a later Start from
// replacing the worker handle while cleanup is in progress.
func (d *Driver) waitForWorkerExit(id string, pid int, controlSocket string) error {
	if command := d.workers[id]; command != nil && command.Process != nil && command.Process.Pid == pid {
		if done := d.workerDone[id]; done != nil {
			timer := time.NewTimer(workerStopTimeout)
			defer timer.Stop()
			select {
			case <-done:
				delete(d.workers, id)
				delete(d.workerDone, id)
				d.closeWorkerLiveness(id)
				return nil
			case <-timer.C:
				return fmt.Errorf("worker process %d did not exit", pid)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), workerStopTimeout)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := workerControl(ctx, controlSocket, "status"); err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("worker control socket remained available after process %d was killed", pid)
		case <-ticker.C:
		}
	}
}

func forceStopWorker(socket string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = workerControl(ctx, socket, "stop")
}

// validateVMPolicyWorkloadIdentity mirrors OpenShell v0.1.4: the VM owns one
// immutable non-root account, so policy selectors may be omitted, name that
// account, or assert its resolved numeric ID. They cannot choose another UID
// or GID after the guest image and overlay have established ownership.
func validateVMPolicyWorkloadIdentity(policyPath string, uid, gid uint32) error {
	document, err := corepolicy.Load(policyPath)
	if err != nil {
		return fmt.Errorf("load workload identity policy: %w", err)
	}
	if document.Process == nil {
		return nil
	}
	for _, selector := range []struct {
		field string
		value string
		want  uint32
	}{
		{field: "run_as_user", value: document.Process.RunAsUser, want: uid},
		{field: "run_as_group", value: document.Process.RunAsGroup, want: gid},
	} {
		if selector.value == "" || selector.value == "sandbox" {
			continue
		}
		value, parseErr := strconv.ParseUint(selector.value, 10, 32)
		if parseErr == nil && uint32(value) == selector.want {
			continue
		}
		return fmt.Errorf("VM %s %q conflicts with resolved workload identity %d:%d; omit the selector or use the driver-owned identity", selector.field, selector.value, uid, gid)
	}
	return nil
}

func (d *Driver) Exec(ctx context.Context, id core.ID, request driver.ExecRequest) (driver.ExecResult, error) {
	if d == nil || ctx == nil {
		return driver.ExecResult{}, fmt.Errorf("vm driver: Exec requires a driver and context")
	}
	if len(request.Argv) == 0 {
		return driver.ExecResult{}, fmt.Errorf("vm exec: argv is empty")
	}
	if request.TTY {
		return d.execWithTerminal(ctx, id, request)
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return driver.ExecResult{}, err
	}
	state, err := store.load(string(id))
	if err != nil {
		return driver.ExecResult{}, err
	}
	if state.Status != "running" {
		return driver.ExecResult{}, fmt.Errorf("vm exec: sandbox %q is %s", state.Name, state.Status)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	d.mu.Lock()
	launchSpec := d.launchSpecs[state.ID]
	d.mu.Unlock()
	workdir := strings.TrimSpace(request.WorkDir)
	if workdir == "" {
		workdir = launchSpec.WorkDir
	}
	if workdir == "" {
		workdir = "/sandbox"
	}
	env, err := mergeLaunchEnvironment(launchSpec.Env, request.Env)
	if err != nil {
		return driver.ExecResult{}, err
	}
	response, err := d.exchangeControl(ctx, state.ID, guestSocket, controlRequest{
		Operation: "exec", Argv: request.Argv, Env: env, WorkDir: workdir,
		User: launchSpec.User, Stdin: request.Stdin, NoLoginShell: request.NoLoginShell,
	})
	if err != nil {
		return driver.ExecResult{}, err
	}
	return driver.ExecResult{ExitCode: response.ExitCode, Stdout: response.Stdout, Stderr: response.Stderr, OutputTruncated: response.OutputTruncated}, nil
}

func (d *Driver) Logs(ctx context.Context, id core.ID, follow bool, writer io.Writer) error {
	if d == nil || ctx == nil || writer == nil {
		return fmt.Errorf("vm driver: Logs requires a driver, context, and writer")
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	if _, err := store.load(string(id)); err != nil {
		return err
	}
	_, _, consolePath := workerSocketPaths(store.root, string(id))
	files := make([]*os.File, 0, 2)
	for _, source := range []struct{ path, name string }{{consolePath, "console"}, {consolePath + ".worker", "worker"}} {
		file, err := os.Open(source.path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			for _, opened := range files {
				_ = opened.Close()
			}
			return fmt.Errorf("open VM %s log: %w", source.name, err)
		}
		files = append(files, file)
	}
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	if len(files) == 0 {
		return nil
	}
	if !follow {
		for _, file := range files {
			if err := streamFile(ctx, file, false, writer); err != nil {
				return err
			}
		}
		return nil
	}
	var outputMu sync.Mutex
	lockedWriter := logLockedWriter{mu: &outputMu, writer: writer}
	followCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(files))
	for _, file := range files {
		go func(file *os.File) { results <- streamFile(followCtx, file, true, lockedWriter) }(file)
	}
	firstErr := <-results
	cancel()
	var secondErr error
	for range files[1:] {
		err := <-results
		if secondErr == nil || errors.Is(secondErr, context.Canceled) {
			secondErr = err
		}
	}
	if firstErr != nil && !errors.Is(firstErr, context.Canceled) {
		return firstErr
	}
	if secondErr != nil && !errors.Is(secondErr, context.Canceled) {
		return secondErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if firstErr != nil {
		return firstErr
	}
	return secondErr
}

type logLockedWriter struct {
	mu     *sync.Mutex
	writer io.Writer
}

func (writer logLockedWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.writer.Write(data)
}

func streamFile(ctx context.Context, file *os.File, follow bool, writer io.Writer) error {
	buffer := make([]byte, 32*1024)
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			if _, err := writer.Write(buffer[:count]); err != nil {
				return err
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if errors.Is(readErr, io.EOF) {
			if !follow {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
}

func (d *Driver) CopyTo(ctx context.Context, id core.ID, source, destination string) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: CopyTo requires a driver and context")
	}
	data, mode, err := readCopySource(source, controlFrameMax/2)
	if err != nil {
		return err
	}
	return d.copyControl(ctx, id, controlRequest{Operation: "copy-to", Path: destination, Data: data, Mode: uint32(mode.Perm())})
}

func (d *Driver) CopyFrom(ctx context.Context, id core.ID, source, destination string) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: CopyFrom requires a driver and context")
	}
	response, err := d.copyControlRequest(ctx, id, controlRequest{Operation: "copy-from", Path: source})
	if err != nil {
		return err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".quarshell-copy-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(response.Data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, destination)
}

func (d *Driver) copyControl(ctx context.Context, id core.ID, request controlRequest) error {
	_, err := d.copyControlRequest(ctx, id, request)
	return err
}

func (d *Driver) copyControlRequest(ctx context.Context, id core.ID, request controlRequest) (controlResponse, error) {
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return controlResponse{}, err
	}
	state, err := store.load(string(id))
	if err != nil {
		return controlResponse{}, err
	}
	if state.Status != "running" {
		return controlResponse{}, fmt.Errorf("vm copy: sandbox %q is %s", state.Name, state.Status)
	}
	_, socket, _ := workerSocketPaths(store.root, state.ID)
	return d.exchangeControl(ctx, state.ID, socket, request)
}

func (d *Driver) exchangeControl(ctx context.Context, id, socket string, request controlRequest) (controlResponse, error) {
	if d == nil || ctx == nil {
		return controlResponse{}, fmt.Errorf("VM control exchange requires a driver and context")
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return controlResponse{}, err
	}
	sandboxDir := filepath.Join(store.root, "sandboxes", id)
	d.rotationMu.Lock()
	if err := d.completePendingControlTokenRotation(ctx, sandboxDir, socket); err != nil {
		d.rotationMu.Unlock()
		return controlResponse{}, err
	}
	token, err := readControlToken(sandboxDir)
	d.rotationMu.Unlock()
	if err != nil {
		return controlResponse{}, err
	}
	request.AuthToken = token
	response, err := exchangeControl(ctx, socket, request)
	if !isGuestControlUnauthorized(err) || ctx.Err() != nil {
		return response, err
	}
	d.rotationMu.Lock()
	defer d.rotationMu.Unlock()
	if err := d.completePendingControlTokenRotation(ctx, sandboxDir, socket); err != nil {
		return controlResponse{}, err
	}
	token, err = readControlToken(sandboxDir)
	if err != nil {
		return controlResponse{}, err
	}
	request.AuthToken = token
	return exchangeControl(ctx, socket, request)
}

func isGuestControlUnauthorized(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), "unauthorized guest control request")
}

func (d *Driver) rotateGuestControlToken(ctx context.Context, id, socket string) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("VM control token rotation requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	sandboxDir := filepath.Join(store.root, "sandboxes", id)
	d.rotationMu.Lock()
	defer d.rotationMu.Unlock()
	if err := d.completePendingControlTokenRotation(ctx, sandboxDir, socket); err != nil {
		return err
	}
	rotation, err := newControlTokenRotation()
	if err != nil {
		return err
	}
	if err := writePendingControlTokenRotation(sandboxDir, rotation); err != nil {
		return err
	}
	return d.completePendingControlTokenRotation(ctx, sandboxDir, socket)
}

func (d *Driver) completePendingControlTokenRotation(ctx context.Context, sandboxDir, socket string) error {
	rotation, pending, err := readPendingControlTokenRotation(sandboxDir)
	if err != nil || !pending {
		return err
	}
	current, err := readControlToken(sandboxDir)
	if err != nil {
		return err
	}
	if current == rotation.NextToken {
		return removePendingControlTokenRotation(sandboxDir)
	}
	_, err = exchangeControl(ctx, socket, controlRequest{
		Operation: "rotate-token", AuthToken: current,
		NextAuthToken: rotation.NextToken, RotationID: rotation.RotationID,
	})
	if err != nil {
		return fmt.Errorf("request guest control token rotation: %w", err)
	}
	if err := replaceControlToken(sandboxDir, rotation.NextToken); err != nil {
		return err
	}
	return removePendingControlTokenRotation(sandboxDir)
}

func (d *Driver) EnsureSSHDaemon(ctx context.Context, id core.ID) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: EnsureSSHDaemon requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := d.Inspect(ctx, string(id)); err != nil {
		return err
	}
	d.mu.Lock()
	launchSpec, ok := d.launchSpecs[string(id)]
	d.mu.Unlock()
	if !ok || !launchSpec.EnableSSH {
		return driver.ErrSSHDisabled
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	state, err := store.load(string(id))
	if err != nil {
		return err
	}
	if state.Status != "running" {
		return fmt.Errorf("vm driver: sandbox %q is %s", state.Name, state.Status)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	_, err = d.exchangeControl(ctx, state.ID, guestSocket, controlRequest{Operation: "start-ssh"})
	if err != nil {
		return fmt.Errorf("start guest SSH relay: %w", err)
	}
	return nil
}

// WaitProxyReady implements driver.ProxyReadiness for the worker-owned
// per-VM policy proxy. Worker startup already waits for /healthz; this method
// lets Gateway use the same readiness contract as container sidecars.
func (d *Driver) WaitProxyReady(ctx context.Context, sandboxName string) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: WaitProxyReady requires a driver and context")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	states, err := store.list()
	if err != nil {
		return err
	}
	var state sandboxState
	for _, candidate := range states {
		if candidate.Name == sandboxName {
			state = candidate
			break
		}
	}
	if state.ID == "" {
		return fmt.Errorf("vm driver: sandbox %q not found while checking policy proxy", sandboxName)
	}
	d.mu.Lock()
	launchSpec, configured := d.launchSpecs[state.ID]
	d.mu.Unlock()
	if !configured || launchSpec.ProxyBin == "" {
		return fmt.Errorf("vm driver: sandbox %q has no policy proxy", sandboxName)
	}
	workerSocketPath, _, _ := workerSocketPaths(store.root, state.ID)
	socket := networkBrokerSocketPath(workerSocketPath, state.ID)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := checkNetworkBrokerHealth(ctx, socket); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for VM policy proxy: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (d *Driver) refreshState(store *stateStore, state sandboxState) sandboxState {
	if state.Status != "running" {
		return state
	}
	workerSocketPath, _, _ := workerSocketPaths(store.root, state.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if response, err := workerControl(ctx, workerSocketPath, "status"); err == nil && response.Ready {
		return state
	}
	state.Status = "stopped"
	state.UpdatedAt = time.Now().UTC()
	_ = store.save(state)
	return state
}

func specVCPUs(cpu float64, defaultValue uint8) uint8 {
	if cpu <= 0 {
		return defaultValue
	}
	if cpu > 255 {
		return 255
	}
	value := uint8(cpu)
	if float64(value) < cpu {
		value++
	}
	return value
}

func specMemoryMiB(bytes int64, defaultValue uint32) uint32 {
	if bytes <= 0 {
		return defaultValue
	}
	const mebibyte = int64(1 << 20)
	value := bytes / mebibyte
	if bytes%mebibyte != 0 {
		value++
	}
	if value > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}

func resolveSupervisorGatewayEndpoint(configured, gatewayURL string) string {
	if configured = strings.TrimSpace(configured); configured != "" {
		return configured
	}
	return strings.TrimSpace(gatewayURL)
}
