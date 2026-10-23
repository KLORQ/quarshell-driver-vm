//go:build linux

package vmguest

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	sshRelaySocketPath         = "/quarshell/ssh/sshd.sock"
	supervisorControlPath      = "/run/quarshell/supervisor-control.sock"
	guestSSHSocket             = "/quarshell/ssh/sshd.sock"
	guestSSHBinary             = "/quarshell/quarshell-sshd"
	guestInitBinary            = "/quarshell/quarshell-init"
	guestPolicyFile            = "/quarshell/policy.yaml"
	guestSupervisorBinary      = "/quarshell/quarshell-supervisor"
	sshRelayConnections        = 64
	supervisorRelayConnections = 128
)

type relayConfiguration struct {
	sshPort     uint32
	controlPort uint32
	supervisor  bool
}

func relayConfigurationFromEnvironment() (relayConfiguration, error) {
	var config relayConfiguration
	for name, destination := range map[string]*uint32{
		"QUARSHELL_VM_SSH_RELAY_PORT":          &config.sshPort,
		"QUARSHELL_VM_SUPERVISOR_CONTROL_PORT": &config.controlPort,
	} {
		value := strings.TrimSpace(os.Getenv(name))
		_ = os.Unsetenv(name)
		if value == "" {
			continue
		}
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return relayConfiguration{}, fmt.Errorf("%s is invalid", name)
		}
		*destination = uint32(port)
	}
	enabled := strings.TrimSpace(os.Getenv("QUARSHELL_VM_SUPERVISOR_ENABLED"))
	_ = os.Unsetenv("QUARSHELL_VM_SUPERVISOR_ENABLED")
	config.supervisor = enabled == "1"
	if enabled != "" && enabled != "1" {
		return relayConfiguration{}, fmt.Errorf("guest supervisor setting is invalid")
	}
	if config.supervisor != (config.controlPort != 0) {
		return relayConfiguration{}, fmt.Errorf("guest supervisor and relay control settings must be configured together")
	}
	return config, nil
}

func startSSHRelayBridge(port uint32) error {
	listener, err := listenVsock(port)
	if err != nil {
		return err
	}
	go serveVsockUnixBridge(listener, sshRelaySocketPath, sshRelayConnections)
	return nil
}

func startSupervisorControlBridge(port uint32) (string, error) {
	if err := os.MkdirAll(filepath.Dir(supervisorControlPath), 0o700); err != nil {
		return "", fmt.Errorf("create guest supervisor control directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(supervisorControlPath), 0o700); err != nil {
		return "", fmt.Errorf("secure guest supervisor control directory: %w", err)
	}
	if info, err := os.Lstat(supervisorControlPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return "", fmt.Errorf("guest supervisor control path exists and is not a socket")
		}
		if err := os.Remove(supervisorControlPath); err != nil {
			return "", fmt.Errorf("remove stale guest supervisor control socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	listener, err := net.Listen("unix", supervisorControlPath)
	if err != nil {
		return "", fmt.Errorf("listen on guest supervisor control socket: %w", err)
	}
	if err := os.Chmod(supervisorControlPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(supervisorControlPath)
		return "", fmt.Errorf("secure guest supervisor control socket: %w", err)
	}
	vsock, err := listenVsock(port)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(supervisorControlPath)
		return "", fmt.Errorf("listen on guest supervisor control vsock port %d: %w", port, err)
	}
	fmt.Fprintf(os.Stderr, "quarshell-init: supervisor control bridge listening on %s via host vsock port %d\n", supervisorControlPath, port)
	go serveUnixVsockBridge(listener, vsock, port, supervisorRelayConnections)
	return supervisorControlPath, nil
}

func listenVsock(port uint32) (net.Listener, error) {
	if port == 0 || port > 65535 {
		return nil, fmt.Errorf("guest relay vsock port is out of range")
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("create guest relay vsock listener: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind guest relay vsock port %d: %w", port, err)
	}
	if err := unix.Listen(fd, 64); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("listen on guest relay vsock port %d: %w", port, err)
	}
	return &vsockListener{fd: fd}, nil
}

type vsockListener struct {
	fd   int
	once sync.Once
}

func (listener *vsockListener) Accept() (net.Conn, error) {
	for {
		fd, _, err := unix.Accept4(listener.fd, unix.SOCK_CLOEXEC)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		return &guestVsockConn{File: os.NewFile(uintptr(fd), "guest-relay-vsock")}, nil
	}
}

func (listener *vsockListener) Close() error {
	var closeErr error
	listener.once.Do(func() { closeErr = unix.Close(listener.fd) })
	return closeErr
}

func (listener *vsockListener) Addr() net.Addr { return guestVsockAddr("guest-relay-listener") }

func serveVsockUnixBridge(listener net.Listener, socket string, limit int) {
	semaphore := make(chan struct{}, limit)
	for {
		upstream, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				downstream, dialErr := (&net.Dialer{Timeout: 5 * time.Second}).Dial("unix", socket)
				if dialErr != nil {
					_ = upstream.Close()
					return
				}
				bridgeRelayConnections(downstream, upstream)
			}()
		default:
			_ = upstream.Close()
		}
	}
}

func serveUnixVsockBridge(listener, vsock net.Listener, port uint32, limit int) {
	semaphore := make(chan struct{}, limit)
	for {
		local, err := listener.Accept()
		if err != nil {
			return
		}
		fmt.Fprintf(os.Stderr, "quarshell-init: supervisor control bridge accepted a local connection for vsock port %d\n", port)
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				fmt.Fprintf(os.Stderr, "quarshell-init: accepting host vsock connection for supervisor control port %d\n", port)
				upstream, acceptErr := vsock.Accept()
				if acceptErr != nil {
					fmt.Fprintf(os.Stderr, "quarshell-init: accept host vsock connection for supervisor control port %d: %v\n", port, acceptErr)
					_ = local.Close()
					return
				}
				fmt.Fprintf(os.Stderr, "quarshell-init: supervisor control bridge accepted host vsock port %d\n", port)
				bridgeSupervisorControlConnections(local, upstream)
				fmt.Fprintf(os.Stderr, "quarshell-init: supervisor control bridge closed for host vsock port %d\n", port)
			}()
		default:
			fmt.Fprintf(os.Stderr, "quarshell-init: supervisor control bridge rejected a connection at its %d-connection limit\n", limit)
			_ = local.Close()
		}
	}
}

func bridgeSupervisorControlConnections(local, upstream net.Conn) {
	defer local.Close()
	defer upstream.Close()
	type relayResult struct {
		direction string
		bytes     int64
		err       error
	}
	done := make(chan relayResult, 2)
	go func() {
		count, err := io.Copy(local, upstream)
		_ = closeRelayWrite(local)
		done <- relayResult{direction: "host-to-guest", bytes: count, err: err}
	}()
	go func() {
		count, err := io.Copy(upstream, local)
		_ = closeRelayWrite(upstream)
		done <- relayResult{direction: "guest-to-host", bytes: count, err: err}
	}()
	for range 2 {
		result := <-done
		fmt.Fprintf(os.Stderr, "quarshell-init: supervisor control bridge %s finished after %d bytes: %v\n", result.direction, result.bytes, result.err)
	}
}

func bridgeRelayConnections(left, right net.Conn) {
	defer left.Close()
	defer right.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(left, right)
		_ = closeRelayWrite(left)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(right, left)
		_ = closeRelayWrite(right)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeRelayWrite(connection net.Conn) error {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	if file, ok := connection.(*guestVsockConn); ok {
		return unix.Shutdown(int(file.Fd()), unix.SHUT_WR)
	}
	return nil
}

var _ net.Listener = (*vsockListener)(nil)
