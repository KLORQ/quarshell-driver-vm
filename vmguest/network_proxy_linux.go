//go:build linux

package vmguest

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
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

func serveNetworkProxyBridge(listener, broker net.Listener) {
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
				bridgeNetworkProxyConnection(client, broker)
			}()
		default:
			_ = client.Close()
		}
	}
}

func bridgeNetworkProxyConnection(client net.Conn, broker net.Listener) {
	defer client.Close()
	upstream, err := broker.Accept()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cautem-init: accept host network broker vsock connection: %v\n", err)
		return
	}
	defer upstream.Close()
	done := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(upstream, client)
		_ = closeWrite(upstream)
		_ = closeWrite(client)
		done <- copyErr
	}()
	_, readErr := io.Copy(client, upstream)
	_ = closeWrite(client)
	if readErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cautem-init: read host network broker response: %v\n", readErr)
		_ = client.Close()
		_ = upstream.Close()
	}
	writeErr := <-done
	if writeErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cautem-init: forward guest proxy request to host broker: %v\n", writeErr)
		_ = client.Close()
		_ = upstream.Close()
	}
}

func startNetworkBrokerVsock(port uint32) (net.Listener, error) { return listenVsock(port) }

func closeWrite(connection net.Conn) error {
	if halfCloser, ok := connection.(interface{ CloseWrite() error }); ok {
		return halfCloser.CloseWrite()
	}
	return nil
}
