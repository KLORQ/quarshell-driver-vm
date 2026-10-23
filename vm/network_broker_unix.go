//go:build darwin || linux

package vm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/KLORQ/quarshell-core/isolation"
)

const networkBrokerWait = 20 * time.Second

type networkBrokerProcess struct {
	command        *exec.Cmd
	processGroupID int
	credentialPath string
	done           chan struct{}
	mu             sync.Mutex
	err            error
	stopping       atomic.Bool
	liveness       *os.File
}

func networkBrokerIsolationPID(process *networkBrokerProcess) (int, error) {
	if process == nil || process.command == nil || process.command.Process == nil {
		return 0, fmt.Errorf("broker process handle is missing")
	}
	if err := processIsAlive(process.command.Process); err != nil {
		return 0, err
	}
	if process.liveness == nil {
		return 0, fmt.Errorf("broker parent-liveness channel is unavailable")
	}
	return process.command.Process.Pid, nil
}

func startNetworkBroker(config *networkBrokerConfig) (*networkBrokerProcess, error) {
	if config == nil {
		return nil, nil
	}
	validated, err := validateNetworkBrokerConfig(*config)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Dir(validated.Socket)); err != nil {
		return nil, fmt.Errorf("secure policy proxy socket directory: %w", err)
	}
	if err := ensurePrivateDirectory(validated.LogDir); err != nil {
		return nil, fmt.Errorf("secure policy proxy log directory: %w", err)
	}
	if err := removeStaleUnixSocket(validated.Socket); err != nil {
		return nil, fmt.Errorf("prepare policy proxy socket: %w", err)
	}
	proxyEnv, err := networkBrokerProcessEnvironment(validated)
	if err != nil {
		return nil, err
	}
	proxyEnv, credentialPath, err := prepareBrokerCredential(validated, proxyEnv)
	if err != nil {
		return nil, err
	}
	command := exec.Command(validated.Binary,
		"proxy", "--listen", "unix://"+validated.Socket,
		"--policy", validated.Policy,
		"--log-dir", validated.LogDir,
		"--gateway-host-mode",
	)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	livenessRead, livenessWrite, err := os.Pipe()
	if err != nil {
		removeBrokerCredential(credentialPath)
		return nil, fmt.Errorf("create host broker parent-liveness pipe: %w", err)
	}
	command.Stdin = livenessRead
	command.Env = append(proxyEnv, "QUARSHELL_HOST_PARENT_LIVENESS=1")
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		_ = livenessRead.Close()
		_ = livenessWrite.Close()
		removeBrokerCredential(credentialPath)
		return nil, fmt.Errorf("start VM policy proxy: %w", err)
	}
	_ = livenessRead.Close()
	process := &networkBrokerProcess{command: command, processGroupID: command.Process.Pid, credentialPath: credentialPath, done: make(chan struct{}), liveness: livenessWrite}
	go func() {
		process.mu.Lock()
		process.err = command.Wait()
		process.mu.Unlock()
		close(process.done)
	}()
	if err := waitForNetworkBroker(process, validated.Socket, networkBrokerWait); err != nil {
		stopNetworkBroker(process)
		return nil, err
	}
	if validated.ControlSocket != "" {
		if err := waitForProxyControlSocket(process, validated.ControlSocket, networkBrokerWait); err != nil {
			stopNetworkBroker(process)
			return nil, err
		}
	}
	return process, nil
}

func networkBrokerProcessEnvironment(config networkBrokerConfig) ([]string, error) {
	entries := append([]string(nil), config.ProxyEnv...)
	if config.SSHSocket != "" {
		entries = append(entries, "QUARSHELL_SSH_SOCKET="+config.SSHSocket)
	}
	if config.ControlSocket != "" {
		entries = append(entries, "QUARSHELL_SUPERVISOR_CONTROL_SOCKET="+config.ControlSocket)
	}
	return networkBrokerEnvironmentChecked(entries)
}

func waitForProxyControlSocket(process *networkBrokerProcess, socket string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Lstat(socket)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		if err == nil {
			return fmt.Errorf("VM supervisor control endpoint is not a Unix socket")
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect VM supervisor control socket: %w", err)
		}
		select {
		case <-process.done:
			exitErr := process.wait()
			if exitErr == nil {
				exitErr = fmt.Errorf("proxy exited without an error")
			}
			return fmt.Errorf("VM supervisor control socket unavailable because proxy exited: %w", exitErr)
		case <-ctx.Done():
			return fmt.Errorf("VM supervisor control socket did not become ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func validateNetworkBrokerConfig(config networkBrokerConfig) (networkBrokerConfig, error) {
	binary, err := validateExecutablePath(config.Binary)
	if err != nil {
		return config, fmt.Errorf("VM policy proxy: %w", err)
	}
	config.Binary = binary
	if config.Policy == "" || !filepath.IsAbs(config.Policy) || filepath.Clean(config.Policy) != config.Policy {
		return config, fmt.Errorf("VM policy proxy path must be a clean absolute path")
	}
	policyInfo, err := os.Lstat(config.Policy)
	if err != nil {
		return config, fmt.Errorf("inspect VM policy file: %w", err)
	}
	if !policyInfo.Mode().IsRegular() || policyInfo.Mode()&os.ModeSymlink != 0 || policyInfo.Size() == 0 || policyInfo.Size() > 4<<20 || policyInfo.Mode().Perm()&0o022 != 0 {
		return config, fmt.Errorf("VM policy file must be a non-empty regular file no larger than 4 MiB and not writable by group or others")
	}
	policyDir, err := os.Lstat(filepath.Dir(config.Policy))
	if err != nil || !policyDir.IsDir() || policyDir.Mode()&os.ModeSymlink != 0 || policyDir.Mode().Perm()&0o077 != 0 || !networkPathOwnedByCurrentUser(policyDir) {
		return config, fmt.Errorf("VM policy directory must be a private directory owned by the current user")
	}
	if config.Socket == "" || !filepath.IsAbs(config.Socket) || filepath.Clean(config.Socket) != config.Socket || len(config.Socket) > 96 {
		return config, fmt.Errorf("VM policy proxy socket must be a clean absolute path within the Unix socket path limit")
	}
	if err := validateNetworkBrokerSocketDirectory(filepath.Dir(config.Socket), workerSocketRoot()); err != nil {
		return config, err
	}
	for name, path := range map[string]string{"SSH relay": config.SSHSocket, "supervisor control": config.ControlSocket} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 96 || strings.IndexByte(path, 0) >= 0) {
			return config, fmt.Errorf("VM %s socket must be a clean absolute path within the Unix socket path limit", name)
		}
		if path != "" && filepath.Dir(path) != filepath.Dir(config.Socket) {
			return config, fmt.Errorf("VM %s socket must share the private policy proxy socket directory", name)
		}
	}
	if config.LogDir == "" || !filepath.IsAbs(config.LogDir) {
		return config, fmt.Errorf("VM policy proxy log directory must be absolute")
	}
	for _, entry := range config.ProxyEnv {
		key, _, _ := strings.Cut(entry, "=")
		if key == "QUARSHELL_SSH_SOCKET" || key == "QUARSHELL_SUPERVISOR_CONTROL_SOCKET" || key == "QUARSHELL_SANDBOX_TOKEN_FILE" {
			return config, fmt.Errorf("VM policy proxy environment cannot override driver-owned setting %s", key)
		}
	}
	if _, err := networkBrokerProcessEnvironment(config); err != nil {
		return config, err
	}
	return config, nil
}

func waitForNetworkBroker(process *networkBrokerProcess, socket string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := checkNetworkBrokerHealth(ctx, socket); err == nil {
			return nil
		}
		select {
		case <-process.done:
			err := process.wait()
			if err == nil {
				err = fmt.Errorf("proxy exited without an error")
			}
			return fmt.Errorf("VM policy proxy exited before readiness: %w", err)
		case <-ctx.Done():
			return fmt.Errorf("VM policy proxy did not become ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func checkNetworkBrokerHealth(ctx context.Context, socket string) error {
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := io.WriteString(connection, "GET /healthz HTTP/1.1\r\nHost: proxy\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy health check returned %s", response.Status)
	}
	return nil
}

func stopNetworkBroker(process *networkBrokerProcess) {
	if process == nil || process.command == nil || process.command.Process == nil {
		return
	}
	process.stopping.Store(true)
	if process.liveness != nil {
		_ = process.liveness.Close()
		process.liveness = nil
	}
	_ = process.command.Process.Signal(syscall.SIGTERM)
	select {
	case <-process.done:
	case <-time.After(2 * time.Second):
		if process.processGroupID > 0 {
			_ = syscall.Kill(-process.processGroupID, syscall.SIGKILL)
		} else {
			_ = process.command.Process.Kill()
		}
		<-process.done
	}
	removeBrokerCredential(process.credentialPath)
	process.credentialPath = ""
}

func watchHostNetworkBroker(process *networkBrokerProcess, worker *exec.Cmd) {
	if process == nil || worker == nil {
		return
	}
	<-process.done
	if process.stopping.Load() {
		return
	}
	err := process.wait()
	if err == nil {
		err = fmt.Errorf("exited without an error")
	}
	removeBrokerCredential(process.credentialPath)
	fmt.Fprintf(os.Stderr, "VM policy broker stopped unexpectedly: %v\n", err)
	if worker.Process == nil || worker.Process.Pid <= 0 {
		return
	}
	if err := syscall.Kill(-worker.Process.Pid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		fmt.Fprintf(os.Stderr, "failed to stop VM worker after policy broker loss: %v\n", err)
		return
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	<-timer.C
	if err := syscall.Kill(-worker.Process.Pid, 0); err == nil {
		if killErr := syscall.Kill(-worker.Process.Pid, syscall.SIGKILL); killErr != nil && killErr != syscall.ESRCH {
			fmt.Fprintf(os.Stderr, "failed to force-stop VM worker after policy broker loss: %v\n", killErr)
		}
	}
}

func prepareBrokerCredential(config networkBrokerConfig, environment []string) ([]string, string, error) {
	const tokenKey = "QUARSHELL_SANDBOX_TOKEN"
	const sandboxTokenKey = "QUARSHELL_SANDBOX_PROTOCOL_TOKEN"
	const gatewayExpiryKey = "QUARSHELL_GATEWAY_TOKEN_EXPIRES_AT"
	const sandboxExpiryKey = "QUARSHELL_SANDBOX_TOKEN_EXPIRES_AT"
	const authEpochKey = "QUARSHELL_AUTH_EPOCH"
	const sessionRotationKey = "QUARSHELL_SESSION_ROTATION"
	const runtimeGenerationKey = "QUARSHELL_RUNTIME_GENERATION"
	const descriptorKey = "QUARSHELL_ISOLATION_DESCRIPTOR_PATH"
	const sandboxKey = "QUARSHELL_SANDBOX"
	token := ""
	sandboxToken := ""
	var gatewayExpiry, sandboxExpiry, authEpoch, sessionRotation uint64
	var gatewayExpirySeen, sandboxExpirySeen, authEpochSeen, sessionRotationSeen bool
	runtimeGeneration := ""
	descriptorPath := ""
	sandbox := ""
	filtered := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		switch key {
		case tokenKey:
			token = value
		case sandboxTokenKey:
			sandboxToken = value
		case gatewayExpiryKey, sandboxExpiryKey, authEpochKey, sessionRotationKey:
			parsed, parseErr := strconv.ParseUint(value, 10, 64)
			if parseErr != nil {
				return nil, "", fmt.Errorf("invalid host supervisor credential metadata %s", key)
			}
			switch key {
			case gatewayExpiryKey:
				gatewayExpiry = parsed
				gatewayExpirySeen = true
			case sandboxExpiryKey:
				sandboxExpiry = parsed
				sandboxExpirySeen = true
			case authEpochKey:
				authEpoch = parsed
				authEpochSeen = true
			default:
				sessionRotation = parsed
				sessionRotationSeen = true
			}
		case runtimeGenerationKey:
			runtimeGeneration = value
		case descriptorKey:
			descriptorPath = value
			filtered = append(filtered, entry)
		case sandboxKey:
			sandbox = value
			filtered = append(filtered, entry)
		default:
			filtered = append(filtered, entry)
		}
	}
	path := filepath.Join(config.LogDir, "supervisor-auth.token")
	credentialEnv := "QUARSHELL_SANDBOX_TOKEN_FILE="
	credentialData := []byte(token + "\n")
	if descriptorPath != "" && token != "" {
		if sandbox == "" {
			return nil, "", fmt.Errorf("VM supervisor auth bundle requires a bearer and sandbox identity")
		}
		if sandboxToken == "" || runtimeGeneration == "" || !gatewayExpirySeen || !sandboxExpirySeen || !authEpochSeen || !sessionRotationSeen || authEpoch == 0 || sessionRotation == 0 {
			return nil, "", fmt.Errorf("VM supervisor auth bundle is missing paired tokens or session metadata")
		}
		if gatewayExpiry > uint64(^uint64(0)>>1) || sandboxExpiry > uint64(^uint64(0)>>1) {
			return nil, "", fmt.Errorf("VM supervisor auth bundle has out-of-range token expiry")
		}
		descriptor, err := readHostBootstrapDescriptor(descriptorPath)
		if err != nil {
			return nil, "", err
		}
		if descriptor.SandboxID != sandbox {
			return nil, "", fmt.Errorf("VM supervisor auth bundle sandbox does not match isolation descriptor")
		}
		bundle := isolation.HostAuthBundle{
			SessionID: descriptor.SessionID, RuntimeGeneration: runtimeGeneration,
			SessionRotation: sessionRotation, AuthEpoch: authEpoch,
			GatewayToken: token, GatewayExpiresAt: int64(gatewayExpiry),
			SandboxToken: sandboxToken, SandboxExpiresAt: int64(sandboxExpiry),
		}
		credentialData, err = isolation.EncodeHostAuthBundle(bundle, descriptor)
		if err != nil {
			return nil, "", err
		}
		path = filepath.Join(config.LogDir, "supervisor-auth.bundle.json")
		credentialEnv = "QUARSHELL_SUPERVISOR_AUTH_BUNDLE_FILE="
	}
	if token == "" {
		if sandboxToken != "" || runtimeGeneration != "" || gatewayExpirySeen || sandboxExpirySeen || authEpochSeen || sessionRotationSeen {
			return nil, "", fmt.Errorf("VM supervisor credential metadata requires a Gateway bearer")
		}
		for _, stale := range []string{path, filepath.Join(config.LogDir, "supervisor-auth.bundle.json")} {
			if err := removeBrokerCredentialChecked(stale); err != nil {
				return nil, "", err
			}
		}
		return filtered, "", nil
	}
	if err := ensurePrivateDirectory(config.LogDir); err != nil {
		return nil, "", fmt.Errorf("secure host supervisor auth directory: %w", err)
	}
	if err := validateBrokerCredentialPath(path); err != nil {
		return nil, "", err
	}
	if credentialEnv == "QUARSHELL_SUPERVISOR_AUTH_BUNDLE_FILE=" {
		if err := removeBrokerCredentialChecked(filepath.Join(config.LogDir, "supervisor-auth.token")); err != nil {
			return nil, "", err
		}
	}
	if err := writeAtomicPrivateFile(config.LogDir, path, ".supervisor-auth-*", credentialData); err != nil {
		return nil, "", fmt.Errorf("write private host supervisor auth bundle: %w", err)
	}
	filtered = append(filtered, credentialEnv+path)
	return filtered, path, nil
}

func readHostBootstrapDescriptor(path string) (isolation.Descriptor, error) {
	var descriptor isolation.Descriptor
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return descriptor, fmt.Errorf("VM isolation descriptor path must be a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > isolation.MaxDescriptorBytes {
		return descriptor, fmt.Errorf("VM isolation descriptor must be a private regular mode-0600 file")
	}
	file, err := os.Open(path)
	if err != nil {
		return descriptor, fmt.Errorf("open VM isolation descriptor for auth bundle: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Mode().Perm() != 0o600 {
		return descriptor, fmt.Errorf("VM isolation descriptor changed while creating auth bundle")
	}
	raw, err := io.ReadAll(io.LimitReader(file, isolation.MaxDescriptorBytes+1))
	if err != nil || len(raw) > isolation.MaxDescriptorBytes {
		return descriptor, fmt.Errorf("read VM isolation descriptor for auth bundle: invalid size or read failure")
	}
	descriptor, err = isolation.DecodeDescriptor(raw)
	if err != nil {
		return isolation.Descriptor{}, fmt.Errorf("decode VM isolation descriptor for auth bundle: %w", err)
	}
	return descriptor, nil
}

func validateBrokerCredentialPath(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing host supervisor auth token: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || !networkPathOwnedByCurrentUser(info) {
		return fmt.Errorf("existing host supervisor auth token must be a private regular file owned by the current user")
	}
	return nil
}

func removeBrokerCredential(path string) {
	if path != "" {
		_ = removeBrokerCredentialChecked(path)
	}
}

func removeBrokerCredentialChecked(path string) error {
	if path == "" {
		return nil
	}
	if err := validateBrokerCredentialPath(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove host supervisor auth token: %w", err)
	}
	return nil
}

func networkBrokerEnvironment(entries []string) []string {
	environment, _ := networkBrokerEnvironmentChecked(entries)
	return environment
}

func networkBrokerEnvironmentChecked(entries []string) ([]string, error) {
	if err := validateNetworkBrokerEnvironment(entries); err != nil {
		return nil, err
	}
	values := map[string]string{"PATH": "/usr/bin:/bin"}
	for _, entry := range entries {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment, nil
}

func networkPathOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

func validateNetworkBrokerSocketDirectory(path, lazyWorkerRoot string) error {
	socketDir, err := os.Lstat(path)
	if os.IsNotExist(err) && path == lazyWorkerRoot {
		// The socket root is created lazily by the worker control listener, but
		// the policy broker starts first. startNetworkBroker creates this one
		// fixed per-UID directory with mode 0700 before binding any socket.
		return nil
	}
	if err != nil || !socketDir.IsDir() || socketDir.Mode()&os.ModeSymlink != 0 || socketDir.Mode().Perm()&0o077 != 0 || !networkPathOwnedByCurrentUser(socketDir) {
		return fmt.Errorf("VM policy proxy socket directory must be private and owned by the current user")
	}
	return nil
}

func (process *networkBrokerProcess) wait() error {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.err
}
