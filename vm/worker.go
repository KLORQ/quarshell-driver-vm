package vm

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/defaults"
)

const networkBrokerVsockPort = uint32(5501)

func vmGuestProxyPort(requested int) int {
	if requested == 0 {
		return defaults.ProxyPort
	}
	return requested
}

type workerConfig struct {
	RuntimeDir          string                `json:"runtime_dir"`
	ControlSocket       string                `json:"control_socket"`
	Isolation           workerIsolationConfig `json:"isolation"`
	ProbeIsolation      bool                  `json:"probe_isolation,omitempty"`
	WatchParentLiveness bool                  `json:"watch_parent_liveness,omitempty"`
	NetworkBroker       *networkBrokerConfig  `json:"network_broker,omitempty"`
	Launch              KrunLaunchConfig      `json:"launch"`
}

type workerIsolationConfig struct {
	HostMountNamespace string `json:"host_mount_namespace,omitempty"`
	HostUserNamespace  string `json:"host_user_namespace,omitempty"`
	NoHostMounts       bool   `json:"no_host_mounts,omitempty"`
}

type networkBrokerConfig struct {
	Binary        string   `json:"binary"`
	Policy        string   `json:"policy"`
	Socket        string   `json:"socket"`
	SSHSocket     string   `json:"ssh_socket,omitempty"`
	ControlSocket string   `json:"control_socket,omitempty"`
	LogDir        string   `json:"log_dir"`
	ProxyEnv      []string `json:"proxy_env,omitempty"`
}

// workerNetworkBrokerConfig returns only socket references required to bind
// the VM's vsock ports. Executable paths, policy paths, credentials, and
// environment values stay in the host driver and never cross worker stdin.
func workerNetworkBrokerConfig(config *networkBrokerConfig) *networkBrokerConfig {
	if config == nil {
		return nil
	}
	return &networkBrokerConfig{
		Socket: config.Socket, SSHSocket: config.SSHSocket,
		ControlSocket: config.ControlSocket,
	}
}

type workerControlRequest struct {
	Operation string `json:"operation"`
}

type workerControlResponse struct {
	Ready bool   `json:"ready"`
	PID   int    `json:"pid,omitempty"`
	Error string `json:"error,omitempty"`
}

// RunWorkerFromStdin is the entry point used by cmd/quarshell-vm-worker. Worker
// configuration travels over stdin so secrets and guest settings are not
// exposed in process arguments or persisted in sandbox metadata.
func RunWorkerFromStdin() error {
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(os.Stdin, (1<<20)+1)))
	decoder.DisallowUnknownFields()
	var config workerConfig
	if err := decoder.Decode(&config); err != nil {
		return fmt.Errorf("decode VM worker config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("VM worker config must contain exactly one JSON object")
	}
	if config.ProbeIsolation {
		if config.RuntimeDir != "" || config.ControlSocket != "" || config.NetworkBroker != nil {
			return fmt.Errorf("VM worker isolation probe must not include runtime or broker settings")
		}
		return prepareWorkerIsolation(config.Isolation)
	}
	if config.RuntimeDir == "" || config.ControlSocket == "" {
		return fmt.Errorf("VM worker requires runtime directory and control socket")
	}
	if err := validateWorkerNetworkBroker(config); err != nil {
		return err
	}
	return runWorker(config)
}

func validateWorkerNetworkBroker(config workerConfig) error {
	var brokerPortMappings []KrunVsockPort
	for _, mapping := range config.Launch.VsockPorts {
		switch mapping.Port {
		case networkBrokerVsockPort, sshRelayVsockPort, supervisorControlPort:
		default:
			return fmt.Errorf("VM worker has an unrecognized vsock port mapping %d", mapping.Port)
		}
		if mapping.Port == networkBrokerVsockPort {
			brokerPortMappings = append(brokerPortMappings, mapping)
		}
	}
	if config.NetworkBroker == nil {
		if len(brokerPortMappings) != 0 {
			return fmt.Errorf("VM worker has a policy broker vsock mapping without a broker process")
		}
		for _, mapping := range config.Launch.VsockPorts {
			if mapping.Port == sshRelayVsockPort || mapping.Port == supervisorControlPort {
				return fmt.Errorf("VM worker has relay vsock mappings without a broker process")
			}
		}
		for _, entry := range config.Launch.Env {
			if strings.HasPrefix(entry, "QUARSHELL_VM_NETWORK_BROKER_PORT=") || strings.HasPrefix(entry, "QUARSHELL_VM_NETWORK_PROXY_PORT=") || strings.HasPrefix(entry, "QUARSHELL_VM_SSH_RELAY_PORT=") || strings.HasPrefix(entry, "QUARSHELL_VM_SUPERVISOR_CONTROL_PORT=") {
				return fmt.Errorf("VM worker has network proxy settings without a broker process")
			}
		}
		return nil
	}
	if len(brokerPortMappings) != 1 || brokerPortMappings[0].Socket != config.NetworkBroker.Socket || !brokerPortMappings[0].Listen {
		return fmt.Errorf("VM worker requires one host-listening broker vsock mapping")
	}
	brokerPortCount, proxyPortCount := 0, 0
	proxyPortValue := vmGuestProxyPortFromLaunch(config.Launch.Env)
	if proxyPortValue == 0 {
		return fmt.Errorf("VM worker launch environment is missing a valid guest proxy port")
	}
	for _, entry := range config.Launch.Env {
		if entry == fmt.Sprintf("QUARSHELL_VM_NETWORK_BROKER_PORT=%d", networkBrokerVsockPort) {
			brokerPortCount++
		}
		if entry == fmt.Sprintf("QUARSHELL_VM_NETWORK_PROXY_PORT=%d", proxyPortValue) {
			proxyPortCount++
		}
	}
	if brokerPortCount != 1 || proxyPortCount != 1 {
		return fmt.Errorf("VM worker launch environment is missing network proxy settings")
	}
	if err := validateWorkerRelayMapping(config.Launch.VsockPorts, config.Launch.Env, config.NetworkBroker); err != nil {
		return err
	}
	return nil
}

const (
	sshRelayVsockPort     = uint32(5502)
	supervisorControlPort = uint32(5503)
	guestSSHBinary        = "/quarshell/quarshell-sshd"
	guestInitBinary       = "/quarshell/quarshell-init"
	guestPolicyFile       = "/quarshell/policy.yaml"
	guestSupervisorBinary = "/quarshell/quarshell-supervisor"
)

func validateWorkerRelayMapping(mappings []KrunVsockPort, environment []string, broker *networkBrokerConfig) error {
	find := func(port uint32) []KrunVsockPort {
		var found []KrunVsockPort
		for _, mapping := range mappings {
			if mapping.Port == port {
				found = append(found, mapping)
			}
		}
		return found
	}
	countEnv := func(prefix, expected string) int {
		count := 0
		for _, entry := range environment {
			if strings.HasPrefix(entry, prefix) {
				if entry == expected {
					count++
				} else {
					return -100
				}
			}
		}
		return count
	}
	if broker.SSHSocket == "" {
		if len(find(sshRelayVsockPort)) != 0 || countEnv("QUARSHELL_VM_SSH_RELAY_PORT=", "QUARSHELL_VM_SSH_RELAY_PORT="+strconv.Itoa(int(sshRelayVsockPort))) != 0 {
			return fmt.Errorf("VM worker has SSH relay settings without a host relay socket")
		}
	} else {
		found := find(sshRelayVsockPort)
		if len(found) != 1 || found[0].Socket != broker.SSHSocket || !found[0].Listen || countEnv("QUARSHELL_VM_SSH_RELAY_PORT=", "QUARSHELL_VM_SSH_RELAY_PORT="+strconv.Itoa(int(sshRelayVsockPort))) != 1 {
			return fmt.Errorf("VM worker requires one host-listening SSH relay vsock mapping")
		}
	}
	if broker.ControlSocket == "" {
		if len(find(supervisorControlPort)) != 0 || countEnv("QUARSHELL_VM_SUPERVISOR_CONTROL_PORT=", "QUARSHELL_VM_SUPERVISOR_CONTROL_PORT="+strconv.Itoa(int(supervisorControlPort))) != 0 || countEnv("QUARSHELL_VM_SUPERVISOR_ENABLED=", "QUARSHELL_VM_SUPERVISOR_ENABLED=1") != 0 {
			return fmt.Errorf("VM worker has supervisor control settings without a host control socket")
		}
	} else {
		found := find(supervisorControlPort)
		if len(found) != 1 || found[0].Socket != broker.ControlSocket || !found[0].Listen || countEnv("QUARSHELL_VM_SUPERVISOR_CONTROL_PORT=", "QUARSHELL_VM_SUPERVISOR_CONTROL_PORT="+strconv.Itoa(int(supervisorControlPort))) != 1 || countEnv("QUARSHELL_VM_SUPERVISOR_ENABLED=", "QUARSHELL_VM_SUPERVISOR_ENABLED=1") != 1 {
			return fmt.Errorf("VM worker requires one host-listening supervisor control vsock mapping")
		}
	}
	return nil
}

func vmGuestProxyPortFromLaunch(environment []string) int {
	var port int
	count := 0
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key != "QUARSHELL_VM_NETWORK_PROXY_PORT" {
			continue
		}
		parsed, err := strconv.Atoi(value)
		count++
		if err == nil && parsed > 0 && parsed <= 65535 {
			port = parsed
		} else {
			return 0
		}
	}
	if count != 1 {
		return 0
	}
	return port
}

func startWorkerControl(path string) (net.Listener, chan struct{}, chan struct{}, error) {
	if !filepath.IsAbs(path) {
		return nil, nil, nil, fmt.Errorf("worker control socket path must be absolute")
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, nil, nil, fmt.Errorf("secure worker socket directory: %w", err)
	}
	if err := removeStaleUnixSocket(path); err != nil {
		return nil, nil, nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listen on worker control socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, nil, nil, fmt.Errorf("secure worker control socket: %w", err)
	}
	ready := make(chan struct{})
	stop := make(chan struct{}, 1)
	go serveWorkerControl(listener, ready, stop)
	return listener, ready, stop, nil
}

func serveWorkerControl(listener net.Listener, ready, stop chan struct{}) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func(connection net.Conn) {
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			var request workerControlRequest
			if err := json.NewDecoder(io.LimitReader(connection, 4096)).Decode(&request); err != nil {
				_ = json.NewEncoder(connection).Encode(workerControlResponse{Error: "invalid worker control request"})
				return
			}
			response := workerControlResponse{PID: os.Getpid()}
			select {
			case <-ready:
				response.Ready = true
			default:
			}
			_ = json.NewEncoder(connection).Encode(response)
			if request.Operation == "stop" {
				select {
				case stop <- struct{}{}:
				default:
				}
			}
		}(connection)
	}
}

func workerControl(ctx context.Context, path, operation string) (workerControlResponse, error) {
	var response workerControlResponse
	if ctx == nil {
		return response, fmt.Errorf("worker control context is nil")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return response, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := json.NewEncoder(connection).Encode(workerControlRequest{Operation: operation}); err != nil {
		return response, err
	}
	if err := json.NewDecoder(io.LimitReader(connection, 4096)).Decode(&response); err != nil {
		return response, err
	}
	if response.Error != "" {
		return response, fmt.Errorf("worker control: %s", response.Error)
	}
	return response, nil
}

func workerSocketPaths(stateStoreRoot, id string) (string, string, string) {
	root := filepath.Join(stateStoreRoot, "sandboxes", id)
	// macOS sockaddr_un has a short sun_path. State roots may be nested under
	// long per-user cache paths, so keep UDS endpoints under a short private
	// system temp directory while leaving persistent console data beside state.
	socketRoot := workerSocketRoot()
	return filepath.Join(socketRoot, id+"-worker.sock"), filepath.Join(socketRoot, id+"-guest.sock"), filepath.Join(root, "console.log")
}

func workerSocketRoot() string {
	return filepath.Join("/tmp", fmt.Sprintf("quarshell-vm-%d", os.Getuid()))
}

func sshRelaySocketPath(workerSocket, id string) string {
	return filepath.Join(filepath.Dir(workerSocket), id+"-ssh.sock")
}

func supervisorControlSocketPath(workerSocket, id string) string {
	return filepath.Join(filepath.Dir(workerSocket), id+"-control.sock")
}

func supervisorProxySocketPath(workerSocket, id string) string {
	return filepath.Join(filepath.Dir(workerSocket), id+"-control-proxy.sock")
}

func networkBrokerSocketPath(workerSocket, id string) string {
	return filepath.Join(filepath.Dir(workerSocket), id+"-proxy.sock")
}

func networkBrokerVsockSocketPath(workerSocket, id string) string {
	return filepath.Join(filepath.Dir(workerSocket), id+"-proxy-vsock.sock")
}

func workerPath(configured string) (string, error) {
	if configured != "" {
		return validateExecutablePath(configured)
	}
	if discovered, err := exec.LookPath("quarshell-vm-worker"); err == nil {
		return validateExecutablePath(discovered)
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve Gateway executable for VM worker: %w", err)
	}
	sibling := filepath.Join(filepath.Dir(executable), "quarshell-vm-worker")
	return validateExecutablePath(sibling)
}

func validateExecutablePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("VM worker executable %q unavailable: %w", absolute, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("VM worker executable %q must be an executable regular file", absolute)
	}
	return absolute, nil
}

func workerConfigJSON(config workerConfig) ([]byte, error) {
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode VM worker config: %w", err)
	}
	return append(encoded, '\n'), nil
}

func validateWorkerSocket(path string) error {
	if path == "" || !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("invalid VM worker control socket path")
	}
	return nil
}
