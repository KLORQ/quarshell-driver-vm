package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver-vm/vmguest"
	"github.com/KLORQ/quarshell-driver/driver"
)

var _ driver.InteractiveExecStream = (*Driver)(nil)
var _ driver.ExecStreamAttach = (*Driver)(nil)
var _ driver.ExecStreamCursorAttacher = (*Driver)(nil)
var _ driver.ExecTerminalCursorAttacher = (*Driver)(nil)
var _ driver.BoundaryProcess = (*vmBoundaryProcess)(nil)
var _ driver.BoundaryProcessOwner = (*vmExecStreamSession)(nil)
var _ driver.MainProcessBoundary = (*Driver)(nil)
var _ driver.MainProcessStreamCursorAttacher = (*Driver)(nil)

func (d *Driver) OpenExecStream(ctx context.Context, id core.ID, request driver.ExecTerminalRequest) (driver.ExecStreamSession, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm driver: OpenExecStream requires a driver and context")
	}
	if len(request.Argv) == 0 || strings.TrimSpace(request.Argv[0]) == "" {
		return nil, fmt.Errorf("vm stream exec: argv is empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.SessionID == "" {
		sessionID, err := newTerminalSessionID()
		if err != nil {
			return nil, err
		}
		request.SessionID = sessionID
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
		return nil, fmt.Errorf("vm stream exec: sandbox %q is %s", state.Name, state.Status)
	}
	d.mu.Lock()
	launchSpec, configured := d.launchSpecs[state.ID]
	d.mu.Unlock()
	if !configured {
		return nil, fmt.Errorf("vm stream exec: workload spec is unavailable; restore it before opening a session")
	}
	workdir := strings.TrimSpace(request.WorkDir)
	if workdir == "" {
		workdir = launchSpec.WorkDir
	}
	if workdir == "" {
		workdir = "/sandbox"
	}
	env, err := mergeLaunchEnvironment(launchSpec.Env, request.Env)
	if err != nil {
		return nil, err
	}
	if !hasEnvironmentKey(env, "TERM") {
		env = append(env, "TERM=xterm-256color")
		sort.Strings(env)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	connection, handshake, err := d.openControlStream(ctx, state.ID, guestSocket, controlRequest{
		Operation: "exec-stream", Argv: append([]string(nil), request.Argv...), Env: env,
		WorkDir: workdir, User: launchSpec.User, NoLoginShell: request.NoLoginShell, SessionID: request.SessionID,
	})
	if err != nil {
		return nil, err
	}
	process := &vmBoundaryProcess{driver: d, sandboxID: id, sessionID: request.SessionID}
	session := &vmExecStreamSession{connection: connection, sessionID: request.SessionID, process: process, inputOwner: handshake.InputOwner, closed: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-session.closed:
		}
	}()
	return session, nil
}

// AttachExecStream reconnects to a retained non-TTY process by its stable ID.
func (d *Driver) AttachExecStream(ctx context.Context, id core.ID, sessionID string) (driver.ExecStreamSession, error) {
	return d.attachExecStreamFromCursor(ctx, id, sessionID, 0, false)
}

// AttachExecStreamFromCursor resumes retained output after a durable frame cursor.
func (d *Driver) AttachExecStreamFromCursor(ctx context.Context, id core.ID, sessionID string, cursor uint64) (driver.ExecStreamSession, error) {
	return d.attachExecStreamFromCursor(ctx, id, sessionID, cursor, true)
}

func (d *Driver) attachExecStreamFromCursor(ctx context.Context, id core.ID, sessionID string, cursor uint64, cursorSet bool) (driver.ExecStreamSession, error) {
	if d == nil || ctx == nil || !validTerminalSessionID(sessionID) {
		return nil, fmt.Errorf("vm driver: AttachExecStream requires a driver, context, and valid session ID")
	}
	if err := ctx.Err(); err != nil {
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
		return nil, fmt.Errorf("vm exec stream attach: sandbox %q is %s", state.Name, state.Status)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	var connection net.Conn
	var handshake controlResponse
	for {
		connection, handshake, err = d.openControlStream(ctx, state.ID, guestSocket, controlRequest{Operation: "attach-exec-stream", SessionID: sessionID, OutputCursor: cursor, OutputCursorSet: cursorSet})
		if err != nil {
			return nil, err
		}
		if handshake.InputOwner || handshake.StdinClosed {
			break
		}
		_ = connection.Close()
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	process := &vmBoundaryProcess{driver: d, sandboxID: id, sessionID: sessionID}
	session := &vmExecStreamSession{connection: connection, sessionID: sessionID, process: process, inputOwner: handshake.InputOwner, closed: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-session.closed:
		}
	}()
	return session, nil
}

// OpenMainProcessStream reconnects to the retained canonical workload pipes
// using the stable session ID persisted with the VM state.
func (d *Driver) OpenMainProcessStream(ctx context.Context, id core.ID) (driver.ExecStreamSession, error) {
	return d.openMainProcessStreamFromCursor(ctx, id, 0, false)
}

// OpenMainProcessStreamFromCursor resumes canonical workload output from a durable cursor.
func (d *Driver) OpenMainProcessStreamFromCursor(ctx context.Context, id core.ID, cursor uint64) (driver.ExecStreamSession, error) {
	return d.openMainProcessStreamFromCursor(ctx, id, cursor, true)
}

func (d *Driver) openMainProcessStreamFromCursor(ctx context.Context, id core.ID, cursor uint64, cursorSet bool) (driver.ExecStreamSession, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm driver: OpenMainProcessStream requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
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
		return nil, fmt.Errorf("vm main-process stream: sandbox %q is %s", state.Name, state.Status)
	}
	sessionID := state.MainProcessSessionID
	if sessionID == "" {
		sessionID = state.MainProcessTTYSessionID
	}
	if !validTerminalSessionID(sessionID) {
		return nil, fmt.Errorf("vm main-process stream: sandbox %q has no retained canonical process session", state.Name)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	connection, handshake, err := d.openControlStream(ctx, state.ID, guestSocket, controlRequest{Operation: "attach-main-process", SessionID: sessionID, OutputCursor: cursor, OutputCursorSet: cursorSet})
	if err != nil {
		return nil, err
	}
	session := &vmExecStreamSession{connection: connection, sessionID: sessionID, inputOwner: handshake.InputOwner, closed: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-session.closed:
		}
	}()
	return session, nil
}

// OpenMainProcessBoundary returns a placement-neutral handle to the canonical
// workload process retained by the running VM guest.
func (d *Driver) OpenMainProcessBoundary(ctx context.Context, id core.ID) (driver.BoundaryProcess, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm driver: OpenMainProcessBoundary requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
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
		return nil, fmt.Errorf("vm main-process boundary: sandbox %q is %s", state.Name, state.Status)
	}
	sessionID := state.MainProcessSessionID
	if sessionID == "" {
		sessionID = state.MainProcessTTYSessionID
	}
	if !validTerminalSessionID(sessionID) {
		return nil, fmt.Errorf("vm main-process boundary: sandbox %q has no retained process session", state.Name)
	}
	return &vmBoundaryProcess{driver: d, sandboxID: id, sessionID: sessionID, main: true, tty: state.MainProcessTTY}, nil
}

type vmExecStreamSession struct {
	connection  net.Conn
	sessionID   string
	process     *vmBoundaryProcess
	inputOwner  bool
	writeMu     sync.Mutex
	closeOnce   sync.Once
	closed      chan struct{}
	stdinClosed bool
}

func (s *vmExecStreamSession) SessionID() string { return s.sessionID }

func (s *vmExecStreamSession) BoundaryProcess() driver.BoundaryProcess { return s.process }

func (s *vmExecStreamSession) Resize(context.Context, uint32, uint32) error {
	return fmt.Errorf("VM non-TTY process attachment does not support resize")
}

type vmBoundaryProcess struct {
	driver    *Driver
	sandboxID core.ID
	sessionID string
	main      bool
	tty       bool
}

func (p *vmBoundaryProcess) SessionID() string { return p.sessionID }

func (p *vmBoundaryProcess) Attach(ctx context.Context) (driver.BoundaryProcessAttachment, error) {
	if p == nil || p.driver == nil {
		return nil, fmt.Errorf("vm boundary process: driver is unavailable")
	}
	if p.tty {
		session, err := p.driver.AttachExecTerminal(ctx, p.sandboxID, p.sessionID)
		if err != nil {
			return nil, err
		}
		return &vmTerminalBoundaryAttachment{session: session}, nil
	}
	if p.main {
		stream, err := p.driver.OpenMainProcessStream(ctx, p.sandboxID)
		if err != nil {
			return nil, err
		}
		attachment, ok := stream.(driver.BoundaryProcessAttachment)
		if !ok {
			_ = stream.Close()
			return nil, fmt.Errorf("vm boundary process: main-process stream does not support process attachment")
		}
		return attachment, nil
	}
	stream, err := p.driver.AttachExecStream(ctx, p.sandboxID, p.sessionID)
	if err != nil {
		return nil, err
	}
	attachment, ok := stream.(driver.BoundaryProcessAttachment)
	if !ok {
		_ = stream.Close()
		return nil, fmt.Errorf("vm boundary process: exec stream does not support process attachment")
	}
	return attachment, nil
}

func (p *vmBoundaryProcess) Wait(ctx context.Context) (int, error) {
	if p == nil || p.driver == nil || ctx == nil {
		return 0, fmt.Errorf("vm boundary process: Wait requires a driver and context")
	}
	if p.main {
		return p.driver.WaitMainProcess(ctx, p.sandboxID)
	}
	operation := "wait-exec-stream"
	if p.tty {
		operation = "wait-terminal"
	}
	response, err := p.driver.copyControlRequest(ctx, p.sandboxID, controlRequest{Operation: operation, SessionID: p.sessionID})
	if err != nil {
		return 0, err
	}
	if !response.Finished {
		return 0, fmt.Errorf("vm boundary process: guest did not confirm terminal status")
	}
	return response.ExitCode, nil
}

func (p *vmBoundaryProcess) Signal(ctx context.Context, signal driver.ExecProcessSignal) error {
	if p == nil || p.driver == nil || ctx == nil {
		return fmt.Errorf("vm boundary process: Signal requires a driver and context")
	}
	if p.main {
		return p.driver.SignalMainProcess(ctx, p.sandboxID, signal)
	}
	name, ok := guestSignalName(signal)
	if !ok {
		return fmt.Errorf("vm boundary process: unsupported signal %q", signal)
	}
	operation := "signal-exec-stream"
	if p.tty {
		operation = "signal-terminal"
	}
	return p.driver.copyControl(ctx, p.sandboxID, controlRequest{Operation: operation, SessionID: p.sessionID, Signal: name})
}

func (p *vmBoundaryProcess) Terminate(ctx context.Context) error {
	if p == nil || p.driver == nil || ctx == nil {
		return fmt.Errorf("vm boundary process: Terminate requires a driver and context")
	}
	if p.main {
		if err := p.driver.SignalMainProcess(ctx, p.sandboxID, driver.ExecSignalKill); err != nil {
			return err
		}
		// Terminate requests process-group shutdown. Wait remains separate
		// because the authenticated supervisor owns the durable exit report.
		return nil
	}
	if p.tty {
		if err := p.driver.TerminateExecTerminal(ctx, p.sandboxID, p.sessionID); err != nil {
			return err
		}
		_, err := p.Wait(ctx)
		return err
	}
	response, err := p.driver.copyControlRequest(ctx, p.sandboxID, controlRequest{Operation: "terminate-exec-stream", SessionID: p.sessionID})
	if err != nil {
		return err
	}
	if !response.Finished {
		return fmt.Errorf("vm boundary process: guest did not confirm termination")
	}
	return nil
}

type vmTerminalBoundaryAttachment struct {
	session driver.ExecTerminalSession
}

func (a *vmTerminalBoundaryAttachment) ReadOutput() (driver.ExecStreamOutput, error) {
	buffer := make([]byte, terminalFrameChunk)
	count, err := a.session.Read(buffer)
	if count == 0 {
		return driver.ExecStreamOutput{}, err
	}
	return driver.ExecStreamOutput{Stdout: buffer[:count]}, err
}

func (a *vmTerminalBoundaryAttachment) Write(payload []byte) (int, error) {
	return a.session.Write(payload)
}

func (a *vmTerminalBoundaryAttachment) CloseStdin() error {
	closer, ok := a.session.(interface{ CloseStdin() error })
	if !ok {
		return fmt.Errorf("VM terminal session does not support stdin close")
	}
	return closer.CloseStdin()
}

func (a *vmTerminalBoundaryAttachment) Resize(ctx context.Context, columns, rows uint32) error {
	return a.session.Resize(ctx, columns, rows)
}

func (a *vmTerminalBoundaryAttachment) Close() error { return a.session.Close() }

func guestSignalName(signal driver.ExecProcessSignal) (string, bool) {
	switch signal {
	case driver.ExecSignalTerminate:
		return "terminate", true
	case driver.ExecSignalKill:
		return "kill", true
	case driver.ExecSignalInterrupt:
		return "interrupt", true
	case driver.ExecSignalHangup:
		return "hangup", true
	default:
		return "", false
	}
}

func (s *vmExecStreamSession) Write(payload []byte) (int, error) {
	if !s.inputOwner {
		return 0, fmt.Errorf("VM main-process attachment does not own stdin")
	}
	written := 0
	for len(payload) > 0 {
		n := len(payload)
		if n > terminalFrameChunk {
			n = terminalFrameChunk
		}
		if err := s.writeFrame(vmguest.TerminalFrame{Type: "stdin", Data: append([]byte(nil), payload[:n]...)}); err != nil {
			return written, err
		}
		written += n
		payload = payload[n:]
	}
	return written, nil
}

func (s *vmExecStreamSession) ReadOutput() (driver.ExecStreamOutput, error) {
	var frame vmguest.TerminalFrame
	encoded, err := vmguest.ReadFrame(s.connection)
	if err != nil {
		return driver.ExecStreamOutput{}, fmt.Errorf("read VM exec stream frame: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil || decoder.Decode(new(any)) != io.EOF {
		return driver.ExecStreamOutput{}, fmt.Errorf("decode VM exec stream frame")
	}
	switch frame.Type {
	case "stdout":
		return driver.ExecStreamOutput{Stdout: frame.Data, Cursor: frame.Sequence}, nil
	case "stderr":
		return driver.ExecStreamOutput{Stderr: frame.Data, Cursor: frame.Sequence}, nil
	case "exit":
		return driver.ExecStreamOutput{ExitCode: frame.ExitCode, Exited: true}, nil
	case "lagged":
		return driver.ExecStreamOutput{}, fmt.Errorf("VM main-process output attachment fell behind by %d chunks", frame.LostChunks)
	default:
		return driver.ExecStreamOutput{}, fmt.Errorf("unexpected VM exec stream frame type %q", frame.Type)
	}
}

func (s *vmExecStreamSession) CloseStdin() error {
	if !s.inputOwner {
		return fmt.Errorf("VM main-process attachment does not own stdin")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.stdinClosed {
		return nil
	}
	s.stdinClosed = true
	return s.writeFrameLocked(vmguest.TerminalFrame{Type: "eof"})
}

func (s *vmExecStreamSession) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		close(s.closed)
		closeErr = s.connection.Close()
	})
	return closeErr
}

func (s *vmExecStreamSession) writeFrame(frame vmguest.TerminalFrame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.stdinClosed {
		return fmt.Errorf("VM exec stream stdin is closed")
	}
	return s.writeFrameLocked(frame)
}

func (s *vmExecStreamSession) writeFrameLocked(frame vmguest.TerminalFrame) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	if err := vmguest.WriteFrame(s.connection, encoded); err != nil {
		return fmt.Errorf("write VM exec stream frame: %w", err)
	}
	return nil
}
