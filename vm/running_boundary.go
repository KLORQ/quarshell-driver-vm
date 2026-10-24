package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver-vm/vmguest"
	"github.com/KLORQ/quarshell-driver/driver"
)

var _ driver.RunningBoundaryProvider = (*Driver)(nil)

// OpenRunningBoundary returns one aggregate handle for the canonical process
// and capabilities of a started VM sandbox.
func (d *Driver) OpenRunningBoundary(ctx context.Context, id core.ID) (driver.RunningBoundary, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm driver: OpenRunningBoundary requires a driver and context")
	}
	process, err := d.OpenMainProcessBoundary(ctx, id)
	if err != nil {
		return nil, err
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return nil, err
	}
	state, err := store.load(string(id))
	if err != nil {
		return nil, err
	}
	if state.Status != "running" {
		return nil, fmt.Errorf("vm running boundary: sandbox %q is %s", state.Name, state.Status)
	}
	return &vmRunningBoundary{driver: d, sandboxID: id, agent: process}, nil
}

type vmRunningBoundary struct {
	driver    *Driver
	sandboxID core.ID
	agent     driver.BoundaryProcess
}

func (b *vmRunningBoundary) Agent() driver.BoundaryProcess { return b.agent }
func (b *vmRunningBoundary) Exec() driver.BoundaryExec {
	return vmBoundaryExec{driver: b.driver, sandboxID: b.sandboxID}
}
func (b *vmRunningBoundary) LoopbackConnector() driver.BoundaryLoopbackConnector {
	return vmLoopbackConnector{driver: b.driver, sandboxID: b.sandboxID}
}
func (b *vmRunningBoundary) Terminate(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("vm running boundary: termination context is nil")
	}
	return b.driver.Stop(ctx, b.sandboxID)
}

type vmBoundaryExec struct {
	driver    *Driver
	sandboxID core.ID
}

func (e vmBoundaryExec) Exec(ctx context.Context, spec driver.BoundaryExecSpec) (driver.BoundaryExecSession, error) {
	if len(spec.Argv) == 0 || strings.TrimSpace(spec.Argv[0]) == "" {
		return driver.BoundaryExecSession{}, fmt.Errorf("vm boundary exec: command is empty")
	}
	request := driver.ExecTerminalRequest{
		Argv: append([]string(nil), spec.Argv...), Env: append([]string(nil), spec.Env...),
		WorkDir: spec.WorkDir, NoLoginShell: spec.NoLoginShell,
		Columns: spec.Columns, Rows: spec.Rows,
	}
	if spec.TTY {
		session, err := e.driver.OpenExecTerminal(ctx, e.sandboxID, request)
		if err != nil {
			return driver.BoundaryExecSession{}, err
		}
		owner, ok := session.(driver.BoundaryProcessOwner)
		if !ok || owner.BoundaryProcess() == nil {
			_ = session.Close()
			return driver.BoundaryExecSession{}, fmt.Errorf("vm boundary exec: terminal has no retained process handle")
		}
		return driver.BoundaryExecSession{Process: owner.BoundaryProcess(), Attachment: &vmTerminalBoundaryAttachment{session: session}}, nil
	}
	stream, err := e.driver.OpenExecStream(ctx, e.sandboxID, request)
	if err != nil {
		return driver.BoundaryExecSession{}, err
	}
	owner, ok := stream.(driver.BoundaryProcessOwner)
	if !ok || owner.BoundaryProcess() == nil {
		_ = stream.Close()
		return driver.BoundaryExecSession{}, fmt.Errorf("vm boundary exec: stream has no retained process handle")
	}
	return driver.BoundaryExecSession{Process: owner.BoundaryProcess(), Attachment: vmStreamBoundaryAttachment{stream: stream}}, nil
}

type vmStreamBoundaryAttachment struct{ stream driver.ExecStreamSession }

func (a vmStreamBoundaryAttachment) ReadOutput() (driver.ExecStreamOutput, error) {
	return a.stream.ReadOutput()
}
func (a vmStreamBoundaryAttachment) Write(p []byte) (int, error) { return a.stream.Write(p) }
func (a vmStreamBoundaryAttachment) CloseStdin() error           { return a.stream.CloseStdin() }
func (a vmStreamBoundaryAttachment) Resize(context.Context, uint32, uint32) error {
	return fmt.Errorf("vm boundary exec: PTY resize is unavailable for a non-TTY session")
}
func (a vmStreamBoundaryAttachment) Close() error { return a.stream.Close() }

type vmLoopbackConnector struct {
	driver    *Driver
	sandboxID core.ID
}

func (c vmLoopbackConnector) Connect(ctx context.Context, host string, port uint16) (io.ReadWriteCloser, error) {
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || port == 0 {
		return nil, fmt.Errorf("vm loopback connector: target must be a literal loopback IP and valid port")
	}
	store, err := openStateStore(c.driver.host.StateDir)
	if err != nil {
		return nil, err
	}
	state, err := store.load(string(c.sandboxID))
	if err != nil {
		return nil, err
	}
	if state.Status != "running" {
		return nil, fmt.Errorf("vm loopback connector: sandbox %q is %s", state.Name, state.Status)
	}
	_, socket, _ := workerSocketPaths(store.root, state.ID)
	connection, _, err := c.driver.openControlStream(ctx, state.ID, socket, controlRequest{
		Operation: "dial-loopback", TargetHost: ip.String(), TargetPort: uint32(port),
	})
	if err != nil {
		return nil, err
	}
	return &vmLoopbackConnection{connection: connection}, nil
}

type vmLoopbackConnection struct {
	connection net.Conn
	readMu     sync.Mutex
	writeMu    sync.Mutex
	readBuf    []byte
	closeOnce  sync.Once
	closeErr   error
}

func (c *vmLoopbackConnection) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.readBuf) == 0 {
		payload, err := vmguest.ReadFrame(c.connection)
		if err != nil {
			return 0, err
		}
		var frame vmguest.TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			return 0, fmt.Errorf("decode VM loopback frame: %w", err)
		}
		switch frame.Type {
		case "data":
			c.readBuf = frame.Data
		case "eof":
			return 0, io.EOF
		case "error":
			return 0, fmt.Errorf("VM loopback dial: %s", frame.Data)
		default:
			return 0, fmt.Errorf("unexpected VM loopback frame %q", frame.Type)
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *vmLoopbackConnection) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		count := len(p)
		if count > terminalFrameChunk {
			count = terminalFrameChunk
		}
		payload, err := json.Marshal(vmguest.TerminalFrame{Type: "data", Data: append([]byte(nil), p[:count]...)})
		if err != nil {
			return written, err
		}
		if err := vmguest.WriteFrame(c.connection, payload); err != nil {
			return written, err
		}
		written += count
		p = p[count:]
	}
	return written, nil
}

func (c *vmLoopbackConnection) Close() error {
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		payload, err := json.Marshal(vmguest.TerminalFrame{Type: "eof"})
		if err == nil {
			err = vmguest.WriteFrame(c.connection, payload)
		}
		c.writeMu.Unlock()
		c.closeErr = errors.Join(err, c.connection.Close())
	})
	return c.closeErr
}
