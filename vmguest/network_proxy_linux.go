//go:build linux

package vmguest

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const networkProxyConnections = 128

func networkProxyConfigurationFromEnvironment() (proxyPort uint32, brokerPort uint32, err error) {
	proxyValue := strings.TrimSpace(os.Getenv("CAUTEM_VM_NETWORK_PROXY_PORT"))
	brokerValue := strings.TrimSpace(os.Getenv("CAUTEM_VM_NETWORK_BROKER_PORT"))
	_ = os.Unsetenv("CAUTEM_VM_NETWORK_PROXY_PORT")
	_ = os.Unsetenv("CAUTEM_VM_NETWORK_BROKER_PORT")
	if proxyValue == "" && brokerValue == "" {
		return 0, 0, nil
	}
	if proxyValue == "" || brokerValue == "" {
		return 0, 0, fmt.Errorf("network proxy requires both guest and host vsock ports")
	}
	proxyNumber, parseErr := strconv.ParseUint(proxyValue, 10, 16)
	if parseErr != nil || proxyNumber == 0 {
		return 0, 0, fmt.Errorf("guest network proxy port is invalid")
	}
	brokerNumber, parseErr := strconv.ParseUint(brokerValue, 10, 16)
	if parseErr != nil || brokerNumber == 0 {
		return 0, 0, fmt.Errorf("host network broker port is invalid")
	}
	return uint32(proxyNumber), uint32(brokerNumber), nil
}

func startNetworkProxyBridge(proxyPort uint32) (net.Listener, error) {
	if proxyPort == 0 || proxyPort > 65535 {
		return nil, fmt.Errorf("guest network proxy port is out of range")
	}
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(proxyPort))))
}

func serveNetworkProxyBridge(listener net.Listener, brokerPort uint32) {
	semaphore := make(chan struct{}, networkProxyConnections)
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				bridgeNetworkProxyConnection(client, brokerPort)
			}()
		default:
			_ = client.Close()
		}
	}
}

func bridgeNetworkProxyConnection(client net.Conn, brokerPort uint32) {
	defer client.Close()
	broker, err := connectHostBroker(brokerPort)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cautem-init: connect host network broker on vsock port %d: %v\n", brokerPort, err)
		return
	}
	defer broker.Close()
	done := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(broker, client)
		_ = broker.CloseWrite()
		_ = closeWrite(client)
		done <- copyErr
	}()
	_, readErr := io.Copy(client, broker)
	_ = closeWrite(client)
	if readErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cautem-init: read host network broker response: %v\n", readErr)
		_ = client.Close()
		_ = broker.Close()
	}
	writeErr := <-done
	if writeErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cautem-init: forward guest proxy request to host broker: %v\n", writeErr)
		_ = client.Close()
		_ = broker.Close()
	}
}

func closeWrite(connection net.Conn) error {
	if halfCloser, ok := connection.(interface{ CloseWrite() error }); ok {
		return halfCloser.CloseWrite()
	}
	return nil
}

func connectHostBroker(port uint32) (*vsockConnection, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("create host broker vsock: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("connect host broker vsock: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set host broker vsock non-blocking: %w", err)
	}
	return &vsockConnection{fd: fd}, nil
}

type vsockConnection struct {
	fd   int
	once sync.Once
}

func (connection *vsockConnection) Read(payload []byte) (int, error) {
	for {
		count, err := unix.Read(connection.fd, payload)
		if count > 0 {
			return count, nil
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			if err := waitVsock(connection.fd, unix.POLLIN); err != nil {
				return 0, err
			}
			continue
		}
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
}

func (connection *vsockConnection) Write(payload []byte) (int, error) {
	for {
		count, err := unix.Write(connection.fd, payload)
		if count > 0 {
			return count, nil
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			if err := waitVsock(connection.fd, unix.POLLOUT); err != nil {
				return 0, err
			}
			continue
		}
		if err != nil {
			return 0, err
		}
		return 0, io.ErrShortWrite
	}
}

func (connection *vsockConnection) Close() error {
	var closeErr error
	connection.once.Do(func() { closeErr = unix.Close(connection.fd) })
	return closeErr
}

func (connection *vsockConnection) CloseWrite() error {
	return unix.Shutdown(connection.fd, unix.SHUT_WR)
}

func (*vsockConnection) LocalAddr() net.Addr                { return guestVsockAddr("guest") }
func (*vsockConnection) RemoteAddr() net.Addr               { return guestVsockAddr("host") }
func (*vsockConnection) SetDeadline(_ time.Time) error      { return nil }
func (*vsockConnection) SetReadDeadline(_ time.Time) error  { return nil }
func (*vsockConnection) SetWriteDeadline(_ time.Time) error { return nil }

func waitVsock(fd int, events int16) error {
	for {
		pollFDs := []unix.PollFd{{Fd: int32(fd), Events: events}}
		_, err := unix.Poll(pollFDs, -1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if pollFDs[0].Revents&events != 0 {
			return nil
		}
		if pollFDs[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return fmt.Errorf("host broker vsock closed")
		}
	}
}
