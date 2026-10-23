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

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver-vm/vmguest"
	"github.com/KLORQ/quarshell-driver/driver"
)

var _ driver.InteractiveExecStream = (*Driver)(nil)

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
	connection, err := d.openControlStream(ctx, state.ID, guestSocket, controlRequest{
		Operation: "exec-stream", Argv: append([]string(nil), request.Argv...), Env: env,
		WorkDir: workdir, User: launchSpec.User, NoLoginShell: request.NoLoginShell,
	})
	if err != nil {
		return nil, err
	}
	session := &vmExecStreamSession{connection: connection, closed: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-session.closed:
		}
	}()
	return session, nil
}

type vmExecStreamSession struct {
	connection  net.Conn
	writeMu     sync.Mutex
	closeOnce   sync.Once
	closed      chan struct{}
	stdinClosed bool
}

func (s *vmExecStreamSession) Write(payload []byte) (int, error) {
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
		return driver.ExecStreamOutput{Stdout: frame.Data}, nil
	case "stderr":
		return driver.ExecStreamOutput{Stderr: frame.Data}, nil
	case "exit":
		return driver.ExecStreamOutput{ExitCode: frame.ExitCode, Exited: true}, nil
	default:
		return driver.ExecStreamOutput{}, fmt.Errorf("unexpected VM exec stream frame type %q", frame.Type)
	}
}

func (s *vmExecStreamSession) CloseStdin() error {
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
