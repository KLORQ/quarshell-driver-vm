//go:build linux

package vmguest

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// dialLoopback opens a TCP stream from inside the workload network namespace.
// Only literal loopback targets pass request validation.
func (s *controlServer) dialLoopback(control net.Conn, host string, port uint32) {
	target, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_ = writeResponse(control, Response{Error: fmt.Sprintf("dial boundary loopback target: %v", err)})
		return
	}
	defer target.Close()
	if err := writeResponse(control, Response{}); err != nil {
		return
	}
	var writeMu sync.Mutex
	writeFrame := func(frame TerminalFrame) error {
		payload, marshalErr := json.Marshal(frame)
		if marshalErr != nil {
			return marshalErr
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return WriteFrame(control, payload)
	}
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		for {
			payload, readErr := ReadFrame(control)
			if readErr != nil {
				_ = target.Close()
				return
			}
			var frame TerminalFrame
			if json.Unmarshal(payload, &frame) != nil {
				_ = target.Close()
				return
			}
			switch frame.Type {
			case "data":
				if _, writeErr := target.Write(frame.Data); writeErr != nil {
					_ = target.Close()
					return
				}
			case "eof":
				if closer, ok := target.(interface{ CloseWrite() error }); ok {
					_ = closer.CloseWrite()
				}
				return
			default:
				_ = target.Close()
				return
			}
		}
	}()
	buffer := make([]byte, 32<<10)
	for {
		count, readErr := target.Read(buffer)
		if count > 0 {
			if err := writeFrame(TerminalFrame{Type: "data", Data: append([]byte(nil), buffer[:count]...)}); err != nil {
				return
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				_ = writeFrame(TerminalFrame{Type: "error", Data: []byte(readErr.Error())})
			}
			_ = writeFrame(TerminalFrame{Type: "eof"})
			break
		}
	}
	_ = control.Close()
	<-inputDone
}
