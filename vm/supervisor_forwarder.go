//go:build darwin || linux

package vm

import (
	"context"
	"io"
	"net"
	"time"
)

const supervisorForwardRetry = 100 * time.Millisecond
const networkProxyForwarders = 32

// forwardNetworkProxy keeps worker-side vsock streams available for guest
// proxy requests. It waits for request bytes before connecting to the host
// proxy so idle VM bridges do not consume proxy handler goroutines.
func forwardNetworkProxy(ctx context.Context, workerSocket, proxySocket string) {
	for range networkProxyForwarders {
		go forwardNetworkProxyWorker(ctx, workerSocket, proxySocket)
	}
	<-ctx.Done()
}

func forwardNetworkProxyWorker(ctx context.Context, workerSocket, proxySocket string) {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	for ctx.Err() == nil {
		worker, err := dialer.DialContext(ctx, "unix", workerSocket)
		if err != nil {
			if !waitSupervisorForwardRetry(ctx) {
				return
			}
			continue
		}
		stopClose := context.AfterFunc(ctx, func() { _ = worker.Close() })
		initial := make([]byte, 32*1024)
		count, readErr := worker.Read(initial)
		if count == 0 {
			stopClose()
			_ = worker.Close()
			if !waitSupervisorForwardRetry(ctx) {
				return
			}
			continue
		}
		proxy, dialErr := dialer.DialContext(ctx, "unix", proxySocket)
		if dialErr != nil {
			stopClose()
			_ = worker.Close()
			if !waitSupervisorForwardRetry(ctx) {
				return
			}
			continue
		}
		stopProxyClose := context.AfterFunc(ctx, func() {
			_ = worker.Close()
			_ = proxy.Close()
		})
		if err := writeForwardBytes(proxy, initial[:count]); err == nil {
			bridgeForwardPrefetched(worker, proxy, readErr)
		}
		stopClose()
		stopProxyClose()
		_ = worker.Close()
		_ = proxy.Close()
	}
}

func writeForwardBytes(destination net.Conn, payload []byte) error {
	for len(payload) > 0 {
		count, err := destination.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[count:]
	}
	return nil
}

func bridgeForwardPrefetched(worker, proxy net.Conn, initialErr error) {
	done := make(chan struct{}, 2)
	go func() {
		if initialErr == nil {
			_, _ = io.Copy(proxy, worker)
		}
		if closer, ok := proxy.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(worker, proxy)
		if closer, ok := worker.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// forwardSupervisorControl connects libkrun's worker-namespace Unix listener
// to the host proxy's mTLS Unix endpoint. Keeping the TLS endpoint on the host
// lets libkrun own the guest-facing vsock accept while the proxy still
// authenticates the guest supervisor.
func forwardSupervisorControl(ctx context.Context, workerSocket, proxySocket string) {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	for ctx.Err() == nil {
		worker, err := dialer.DialContext(ctx, "unix", workerSocket)
		if err != nil {
			if !waitSupervisorForwardRetry(ctx) {
				return
			}
			continue
		}
		proxy, err := dialer.DialContext(ctx, "unix", proxySocket)
		if err != nil {
			_ = worker.Close()
			if !waitSupervisorForwardRetry(ctx) {
				return
			}
			continue
		}
		stopClose := context.AfterFunc(ctx, func() {
			_ = worker.Close()
			_ = proxy.Close()
		})
		bridgeSupervisorForward(worker, proxy)
		stopClose()
		_ = worker.Close()
		_ = proxy.Close()
	}
}

func waitSupervisorForwardRetry(ctx context.Context) bool {
	timer := time.NewTimer(supervisorForwardRetry)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func bridgeSupervisorForward(worker, proxy net.Conn) {
	done := make(chan struct{}, 2)
	copyHalf := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		if closer, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyHalf(worker, proxy)
	go copyHalf(proxy, worker)
	<-done
	<-done
}
