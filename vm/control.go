package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/KLORQ/quarshell-driver-vm/vmguest"
	"io"
	"net"
)

const (
	guestControlPort   = vmguest.ControlPort
	controlFrameMax    = vmguest.FrameMax
	guestControlSocket = "guest-control.sock"
	workerSocket       = "worker-control.sock"
)

type controlRequest = vmguest.Request
type controlResponse = vmguest.Response

func exchangeControl(ctx context.Context, socket string, request controlRequest) (controlResponse, error) {
	var response controlResponse
	if ctx == nil {
		return response, fmt.Errorf("VM control context is nil")
	}
	if request.Version != 0 && request.Version != vmguest.ProtocolVersion {
		return response, fmt.Errorf("unsupported VM control protocol version %d", request.Version)
	}
	request.Version = vmguest.ProtocolVersion
	encoded, err := json.Marshal(request)
	if err != nil {
		return response, fmt.Errorf("encode VM control request: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > controlFrameMax {
		return response, fmt.Errorf("VM control request exceeds %d bytes", controlFrameMax)
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return response, fmt.Errorf("connect VM guest control socket: %w", err)
	}
	defer connection.Close()
	stopCancel := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stopCancel:
		}
	}()
	defer close(stopCancel)
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := vmguest.WriteFrame(connection, encoded); err != nil {
		return response, fmt.Errorf("write VM control request: %w", err)
	}
	answer, err := vmguest.ReadFrame(connection)
	if err != nil {
		return response, fmt.Errorf("read VM control response: %w", err)
	}
	if err := json.Unmarshal(answer, &response); err != nil {
		return response, fmt.Errorf("decode VM control response: %w", err)
	}
	if response.Version != vmguest.ProtocolVersion {
		return response, fmt.Errorf("unsupported VM control response version %d", response.Version)
	}
	if response.Error != "" {
		return response, fmt.Errorf("guest control %s: %s", request.Operation, response.Error)
	}
	return response, nil
}

func writeFrame(writer io.Writer, payload []byte) error {
	return vmguest.WriteFrame(writer, payload)
}

func readFrame(reader io.Reader) ([]byte, error) {
	return vmguest.ReadFrame(reader)
}
