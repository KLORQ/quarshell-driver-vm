package vm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver-vm/vmguest"
	"github.com/KLORQ/quarshell-driver/driver"
)

const (
	defaultTerminalColumns = 80
	defaultTerminalRows    = 24
	terminalFrameChunk     = 32 << 10
	terminalOutputLimit    = 8 << 20
)

func (d *Driver) OpenExecTerminal(ctx context.Context, id core.ID, request driver.ExecTerminalRequest) (driver.ExecTerminalSession, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm driver: OpenExecTerminal requires a driver and context")
	}
	if len(request.Argv) == 0 {
		return nil, fmt.Errorf("vm terminal exec: argv is empty")
	}
	if request.Columns > 65535 || request.Rows > 65535 {
		return nil, fmt.Errorf("vm terminal exec: columns and rows must not exceed 65535")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.SessionID == "" {
		sessionID, idErr := newTerminalSessionID()
		if idErr != nil {
			return nil, idErr
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
		return nil, fmt.Errorf("vm terminal exec: sandbox %q is %s", state.Name, state.Status)
	}
	d.mu.Lock()
	launchSpec, configured := d.launchSpecs[state.ID]
	d.mu.Unlock()
	if !configured {
		return nil, fmt.Errorf("vm terminal exec: workload spec is unavailable; restore it before opening a session")
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
	columns, rows := request.Columns, request.Rows
	if columns == 0 {
		columns = defaultTerminalColumns
	}
	if rows == 0 {
		rows = defaultTerminalRows
	}
	connection, err := d.openControlStream(ctx, state.ID, guestSocket, controlRequest{
		Operation: "exec-terminal", Argv: append([]string(nil), request.Argv...), Env: env,
		WorkDir: workdir, User: launchSpec.User, NoLoginShell: request.NoLoginShell,
		Columns: columns, Rows: rows, SessionID: request.SessionID,
	})
	if err != nil {
		return nil, err
	}
	session := newVMExecTerminalSession(connection, request.SessionID)
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-session.done:
		}
	}()
	return session, nil
}

// AttachExecTerminal reconnects to a retained guest PTY process after its
// previous control stream disconnected.
func (d *Driver) AttachExecTerminal(ctx context.Context, id core.ID, sessionID string) (driver.ExecTerminalSession, error) {
	if d == nil || ctx == nil || strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("vm driver: AttachExecTerminal requires a driver, context, and session ID")
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
		return nil, fmt.Errorf("vm terminal attach: sandbox %q is %s", state.Name, state.Status)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	connection, err := d.openControlStream(ctx, state.ID, guestSocket, controlRequest{Operation: "attach-terminal", SessionID: sessionID})
	if err != nil {
		return nil, err
	}
	session := newVMExecTerminalSession(connection, sessionID)
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-session.done:
		}
	}()
	return session, nil
}

// TerminateExecTerminal stops a retained PTY process by session ID even when
// no terminal stream is currently attached.
func (d *Driver) TerminateExecTerminal(ctx context.Context, id core.ID, sessionID string) error {
	if d == nil || ctx == nil || strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("vm driver: TerminateExecTerminal requires a driver, context, and session ID")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	state, err := store.load(string(id))
	if err != nil {
		return err
	}
	if state.Status != "running" {
		return fmt.Errorf("vm terminal terminate: sandbox %q is %s", state.Name, state.Status)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	connection, err := d.openControlStream(ctx, state.ID, guestSocket, controlRequest{Operation: "terminate-terminal", SessionID: sessionID})
	if err != nil {
		return err
	}
	return connection.Close()
}

func newTerminalSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate VM terminal session ID: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func validTerminalSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// OpenMainProcessTTY attaches to the PTY owned by the canonical guest workload
// process. The session ID is durable, so a Gateway transport reconnect can
// reattach without creating a second main process.
func (d *Driver) OpenMainProcessTTY(ctx context.Context, id core.ID, columns, rows uint32) (io.ReadWriteCloser, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm driver: OpenMainProcessTTY requires a driver and context")
	}
	if columns > 65535 || rows > 65535 {
		return nil, fmt.Errorf("vm main-process TTY dimensions must not exceed 65535")
	}
	sessionID, err := d.mainProcessTTYSessionID(id)
	if err != nil {
		return nil, err
	}
	session, err := d.AttachExecTerminal(ctx, id, sessionID)
	if err != nil {
		return nil, fmt.Errorf("attach VM main-process TTY: %w", err)
	}
	if columns > 0 && rows > 0 {
		if err := session.Resize(ctx, columns, rows); err != nil {
			_ = session.Close()
			return nil, fmt.Errorf("resize VM main-process TTY: %w", err)
		}
	}
	return session, nil
}

// ResizeMainProcessTTY attaches briefly to send a resize update to the retained
// PTY. Closing the stream detaches while leaving the canonical process running.
func (d *Driver) ResizeMainProcessTTY(ctx context.Context, id core.ID, columns, rows uint32) error {
	if columns == 0 || rows == 0 {
		return nil
	}
	session, err := d.OpenMainProcessTTY(ctx, id, columns, rows)
	if err != nil {
		return err
	}
	return session.Close()
}

func (d *Driver) mainProcessTTYSessionID(id core.ID) (string, error) {
	if d == nil {
		return "", fmt.Errorf("vm driver: main-process TTY requires a driver")
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return "", err
	}
	state, err := store.load(string(id))
	if err != nil {
		return "", err
	}
	if state.Status != "running" {
		return "", fmt.Errorf("vm main-process TTY: sandbox %q is %s", state.Name, state.Status)
	}
	sessionID := state.MainProcessSessionID
	if sessionID == "" {
		sessionID = state.MainProcessTTYSessionID
	}
	if !validTerminalSessionID(sessionID) {
		return "", fmt.Errorf("vm main-process TTY: sandbox %q was not started with a TTY", state.Name)
	}
	return sessionID, nil
}

var _ driver.MainProcessTTY = (*Driver)(nil)

func (d *Driver) execWithTerminal(ctx context.Context, id core.ID, request driver.ExecRequest) (driver.ExecResult, error) {
	columns, rows := request.Columns, request.Rows
	if columns == 0 {
		columns = defaultTerminalColumns
	}
	if rows == 0 {
		rows = defaultTerminalRows
	}
	session, err := d.OpenExecTerminal(ctx, id, driver.ExecTerminalRequest{
		Argv: request.Argv, Env: request.Env, WorkDir: request.WorkDir,
		NoLoginShell: request.NoLoginShell, Columns: columns, Rows: rows,
	})
	if err != nil {
		return driver.ExecResult{}, err
	}
	defer session.Close()
	input := io.Reader(bytes.NewReader(request.Stdin))
	if request.StdinReader != nil {
		input = request.StdinReader
	}
	inputDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(session, input)
		if copyErr == nil {
			_, copyErr = session.Write([]byte{4})
		}
		inputDone <- copyErr
	}()
	var output ptyOutputBuffer
	buffer := make([]byte, terminalFrameChunk)
	for {
		count, readErr := session.Read(buffer)
		if count > 0 {
			output.Write(buffer[:count])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return driver.ExecResult{}, readErr
		}
	}
	code, err := session.Wait(ctx)
	if err != nil {
		return driver.ExecResult{}, err
	}
	return driver.ExecResult{ExitCode: code, Stdout: output.data, OutputTruncated: output.truncated}, nil
}

type ptyOutputBuffer struct {
	data      []byte
	truncated bool
}

func (buffer *ptyOutputBuffer) Write(payload []byte) {
	remaining := terminalOutputLimit - len(buffer.data)
	if remaining > len(payload) {
		remaining = len(payload)
	}
	if remaining > 0 {
		buffer.data = append(buffer.data, payload[:remaining]...)
	}
	if remaining < len(payload) {
		buffer.truncated = true
	}
}

func hasEnvironmentKey(env []string, want string) bool {
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok && key == want {
			return true
		}
	}
	return false
}

func (d *Driver) openControlStream(ctx context.Context, id, socket string, request controlRequest) (net.Conn, error) {
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return nil, err
	}
	sandboxDir := filepath.Join(store.root, "sandboxes", id)
	for attempt := 0; attempt < 2; attempt++ {
		d.rotationMu.Lock()
		if err := d.completePendingControlTokenRotation(ctx, sandboxDir, socket); err != nil {
			d.rotationMu.Unlock()
			return nil, err
		}
		token, err := readControlToken(sandboxDir)
		d.rotationMu.Unlock()
		if err != nil {
			return nil, err
		}
		request.AuthToken = token
		connection, err := writeControlStreamRequest(ctx, socket, request)
		if err == nil {
			return connection, nil
		}
		if !isGuestControlUnauthorized(err) || attempt != 0 || ctx.Err() != nil {
			return nil, err
		}
		d.rotationMu.Lock()
		err = d.completePendingControlTokenRotation(ctx, sandboxDir, socket)
		d.rotationMu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("VM terminal control authentication retry exhausted")
}

func writeControlStreamRequest(ctx context.Context, socket string, request controlRequest) (net.Conn, error) {
	var response controlResponse
	request.Version = vmguest.ProtocolVersion
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode VM terminal request: %w", err)
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect VM guest terminal socket: %w", err)
	}
	stopCancel := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stopCancel:
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := vmguest.WriteFrame(connection, encoded); err != nil {
		close(stopCancel)
		_ = connection.Close()
		return nil, fmt.Errorf("write VM terminal request: %w", err)
	}
	answer, err := vmguest.ReadFrame(connection)
	if err != nil {
		close(stopCancel)
		_ = connection.Close()
		return nil, fmt.Errorf("read VM terminal handshake: %w", err)
	}
	if err := json.Unmarshal(answer, &response); err != nil {
		close(stopCancel)
		_ = connection.Close()
		return nil, fmt.Errorf("decode VM terminal handshake: %w", err)
	}
	if response.Version != vmguest.ProtocolVersion {
		close(stopCancel)
		_ = connection.Close()
		return nil, fmt.Errorf("unsupported VM terminal protocol response version %d", response.Version)
	}
	if response.Error != "" {
		close(stopCancel)
		_ = connection.Close()
		return nil, fmt.Errorf("guest control exec-terminal: %s", response.Error)
	}
	close(stopCancel)
	return connection, nil
}

type vmExecTerminalSession struct {
	connection net.Conn
	sessionID  string
	output     *io.PipeReader
	outputSink *io.PipeWriter
	done       chan struct{}
	writeMu    sync.Mutex
	stateMu    sync.Mutex
	exitCode   int
	readErr    error
	closeOnce  sync.Once
}

func newVMExecTerminalSession(connection net.Conn, sessionID string) *vmExecTerminalSession {
	reader, writer := io.Pipe()
	session := &vmExecTerminalSession{
		connection: connection, sessionID: sessionID, output: reader, outputSink: writer, done: make(chan struct{}),
	}
	go session.readFrames()
	return session
}

func (session *vmExecTerminalSession) SessionID() string { return session.sessionID }

func (session *vmExecTerminalSession) Read(payload []byte) (int, error) {
	return session.output.Read(payload)
}

func (session *vmExecTerminalSession) Write(payload []byte) (int, error) {
	written := 0
	for len(payload) > 0 {
		count := len(payload)
		if count > terminalFrameChunk {
			count = terminalFrameChunk
		}
		if err := session.writeFrame(vmguest.TerminalFrame{Type: "stdin", Data: append([]byte(nil), payload[:count]...)}); err != nil {
			return written, err
		}
		written += count
		payload = payload[count:]
	}
	return written, nil
}

func (session *vmExecTerminalSession) CloseStdin() error {
	return session.writeFrame(vmguest.TerminalFrame{Type: "eof"})
}

func (session *vmExecTerminalSession) Resize(ctx context.Context, columns, rows uint32) error {
	if ctx == nil {
		return fmt.Errorf("VM terminal resize context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if columns == 0 || rows == 0 || columns > 65535 || rows > 65535 {
		return fmt.Errorf("VM terminal dimensions must be between 1 and 65535")
	}
	return session.writeFrame(vmguest.TerminalFrame{Type: "resize", Columns: columns, Rows: rows})
}

func (session *vmExecTerminalSession) Signal(ctx context.Context, signal driver.ExecProcessSignal) error {
	if ctx == nil {
		return fmt.Errorf("VM terminal signal context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validExecProcessSignal(signal) {
		return fmt.Errorf("unsupported VM terminal process signal %q", signal)
	}
	return session.writeFrame(vmguest.TerminalFrame{Type: "signal", Signal: string(signal)})
}

func validExecProcessSignal(signal driver.ExecProcessSignal) bool {
	switch signal {
	case driver.ExecSignalTerminate, driver.ExecSignalKill, driver.ExecSignalInterrupt, driver.ExecSignalHangup:
		return true
	default:
		return false
	}
}

func (session *vmExecTerminalSession) Wait(ctx context.Context) (int, error) {
	if ctx == nil {
		return 0, fmt.Errorf("VM terminal wait context is nil")
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-session.done:
	}
	session.stateMu.Lock()
	defer session.stateMu.Unlock()
	return session.exitCode, session.readErr
}

func (session *vmExecTerminalSession) Close() error {
	var closeErr error
	session.closeOnce.Do(func() {
		closeErr = session.connection.Close()
		_ = session.output.Close()
	})
	return closeErr
}

func (session *vmExecTerminalSession) writeFrame(frame vmguest.TerminalFrame) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	if err := vmguest.WriteFrame(session.connection, encoded); err != nil {
		return fmt.Errorf("write VM terminal frame: %w", err)
	}
	return nil
}

func (session *vmExecTerminalSession) readFrames() {
	var terminalErr error
	for {
		payload, err := vmguest.ReadFrame(session.connection)
		if err != nil {
			terminalErr = err
			break
		}
		var frame vmguest.TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			terminalErr = fmt.Errorf("decode VM terminal frame: %w", err)
			break
		}
		switch frame.Type {
		case "output":
			if len(frame.Data) == 0 {
				continue
			}
			if _, err := session.outputSink.Write(frame.Data); err != nil {
				terminalErr = err
				_ = session.connection.Close()
			}
		case "exit":
			session.stateMu.Lock()
			session.exitCode = frame.ExitCode
			session.stateMu.Unlock()
			terminalErr = nil
			goto finished
		default:
			terminalErr = fmt.Errorf("unexpected VM terminal frame type %q", frame.Type)
		}
		if terminalErr != nil {
			break
		}
	}

finished:
	session.stateMu.Lock()
	session.readErr = terminalErr
	session.stateMu.Unlock()
	if terminalErr != nil && !errors.Is(terminalErr, io.EOF) {
		_ = session.outputSink.CloseWithError(terminalErr)
	} else {
		_ = session.outputSink.Close()
	}
	close(session.done)
}
