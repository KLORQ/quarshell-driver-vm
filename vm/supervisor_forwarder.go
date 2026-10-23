//go:build darwin || linux

package vm

import (
	"context"
	"io"
	"net"
	"time"
)

const supervisorForwardRetry = 100 * time.Millisecond

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
