//go:build linux

package vmguest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

const (
	retainedTerminalOutputLimit = 1 << 20
	retainedTerminalFinishedTTL = 15 * time.Minute
	retainedTerminalMaxSessions = 256
)

// retainedTerminal owns a guest PTY independently of any one control stream.
// Output produced while detached is retained up to a bounded tail.
type retainedTerminal struct {
	owner             *controlServer
	id                string
	pid               int
	command           *exec.Cmd
	pty               *os.File
	mu                sync.Mutex
	connection        net.Conn
	output            []TerminalFrame
	outputBytes       int
	outputFirstSeq    uint64
	outputNextSeq     uint64
	outputChanged     chan struct{}
	finished          bool
	exitCode          int
	finishedAt        time.Time
	outputDone        chan struct{}
	awaitAttachment   bool
	attachmentSeen    bool
	activeAttachments int
	attachmentChanged chan struct{}
	onExit            func()
}

func (s *controlServer) pruneTerminalsLocked(now time.Time) {
	for id, process := range s.terminals {
		process.mu.Lock()
		attachmentComplete := !process.awaitAttachment || (process.attachmentSeen && process.activeAttachments == 0)
		expired := process.finished && attachmentComplete && now.Sub(process.finishedAt) >= retainedTerminalFinishedTTL
		process.mu.Unlock()
		if expired {
			delete(s.terminals, id)
		}
	}
}

func (s *controlServer) retainTerminalLocked(id string, command *exec.Cmd, terminal *os.File, awaitAttachment bool, onExit func()) (*retainedTerminal, error) {
	if s.terminals == nil {
		s.terminals = make(map[string]*retainedTerminal)
	}
	s.pruneTerminalsLocked(time.Now())
	if len(s.terminals) >= retainedTerminalMaxSessions {
		return nil, fmt.Errorf("guest terminal session limit reached")
	}
	process := &retainedTerminal{
		owner: s, id: id, pid: command.Process.Pid, command: command, pty: terminal,
		outputDone: make(chan struct{}), outputChanged: make(chan struct{}), awaitAttachment: awaitAttachment,
		attachmentChanged: make(chan struct{}), onExit: onExit,
	}
	s.terminals[id] = process
	go process.readOutput()
	go process.wait()
	return process, nil
}

func (s *controlServer) attachTerminal(connection net.Conn, id string) {
	s.attachTerminalFromCursor(connection, id, 0, false)
}

func (s *controlServer) attachTerminalFromCursor(connection net.Conn, id string, cursor uint64, cursorSet bool) {
	if strings.TrimSpace(id) == "" {
		_ = writeResponse(connection, Response{Error: "terminal session ID is required"})
		return
	}
	s.terminalMu.Lock()
	s.pruneTerminalsLocked(time.Now())
	process := s.terminals[id]
	s.terminalMu.Unlock()
	if process == nil {
		_ = writeResponse(connection, Response{Error: "terminal session not found"})
		return
	}
	process.attachFromCursor(connection, cursor, cursorSet)
}

func (s *controlServer) waitForTerminalAttachment(id string) {
	s.terminalMu.Lock()
	process := s.terminals[id]
	s.terminalMu.Unlock()
	if process != nil {
		process.waitForExpectedAttachment()
	}
}

func (process *retainedTerminal) waitForExpectedAttachment() {
	for {
		process.mu.Lock()
		complete := process.attachmentSeen && process.activeAttachments == 0
		changed := process.attachmentChanged
		process.mu.Unlock()
		if complete {
			return
		}
		<-changed
	}
}

func (s *controlServer) retainedTerminalOutputTail(id string, limit int) string {
	if s == nil || id == "" || limit <= 0 {
		return ""
	}
	s.terminalMu.Lock()
	process := s.terminals[id]
	s.terminalMu.Unlock()
	if process == nil {
		return ""
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	var output []byte
	for _, frame := range process.output {
		output = append(output, frame.Data...)
	}
	if len(output) > limit {
		return string(output[len(output)-limit:])
	}
	return string(output)
}

func (process *retainedTerminal) notifyAttachmentChangedLocked() {
	close(process.attachmentChanged)
	process.attachmentChanged = make(chan struct{})
}

func (s *controlServer) terminateTerminal(connection net.Conn, id string) {
	if strings.TrimSpace(id) == "" {
		_ = writeResponse(connection, Response{Error: "terminal session ID is required"})
		return
	}
	s.terminalMu.Lock()
	s.pruneTerminalsLocked(time.Now())
	process := s.terminals[id]
	s.terminalMu.Unlock()
	if process == nil {
		_ = writeResponse(connection, Response{Error: "terminal session not found"})
		return
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if !process.finished {
		if err := syscall.Kill(-process.pid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
			_ = writeResponse(connection, Response{Error: fmt.Sprintf("terminate guest terminal process: %v", err)})
			return
		}
	}
	_ = writeResponse(connection, Response{PID: process.pid, SessionID: process.id})
}

func (process *retainedTerminal) readOutput() {
	defer close(process.outputDone)
	buffer := make([]byte, 32<<10)
	for {
		count, err := process.pty.Read(buffer)
		if count > 0 {
			process.mu.Lock()
			process.retainOutput(buffer[:count])
			process.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (process *retainedTerminal) retainOutput(payload []byte) {
	data := append([]byte(nil), payload...)
	process.output = append(process.output, TerminalFrame{Type: "output", Data: data})
	process.outputNextSeq++
	process.outputBytes += len(data)
	for process.outputBytes > retainedTerminalOutputLimit && len(process.output) > 0 {
		process.outputBytes -= len(process.output[0].Data)
		process.output = process.output[1:]
		process.outputFirstSeq++
	}
	close(process.outputChanged)
	process.outputChanged = make(chan struct{})
}

func (process *retainedTerminal) wait() {
	err := process.command.Wait()
	<-process.outputDone
	process.mu.Lock()
	process.finished = true
	process.exitCode = normalizeGuestExitCode(err)
	process.finishedAt = time.Now()
	close(process.outputChanged)
	process.outputChanged = make(chan struct{})
	process.mu.Unlock()
	_ = process.pty.Close()
	if process.onExit != nil {
		process.onExit()
	}
	time.AfterFunc(retainedTerminalFinishedTTL, func() {
		process.owner.terminalMu.Lock()
		if process.owner.terminals[process.id] == process {
			delete(process.owner.terminals, process.id)
		}
		process.owner.terminalMu.Unlock()
	})
}

func (process *retainedTerminal) waitForExit(ctx context.Context) (int, error) {
	if ctx == nil {
		return 0, fmt.Errorf("terminal wait context is nil")
	}
	for {
		process.mu.Lock()
		if process.finished {
			code := process.exitCode
			process.mu.Unlock()
			return code, nil
		}
		changed := process.outputChanged
		process.mu.Unlock()
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-changed:
		}
	}
}

func (process *retainedTerminal) signal(name string) error {
	signal, ok := guestTerminalSignal(name)
	if !ok {
		return fmt.Errorf("unsupported terminal process signal %q", name)
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.finished {
		return nil
	}
	if err := syscall.Kill(-process.pid, signal); err != nil && err != syscall.ESRCH {
		return fmt.Errorf("signal guest terminal process group: %w", err)
	}
	return nil
}

func (process *retainedTerminal) attach(connection net.Conn) {
	process.attachFromCursor(connection, 0, false)
}

func (process *retainedTerminal) attachFromCursor(connection net.Conn, cursor uint64, cursorSet bool) {
	process.mu.Lock()
	inputOwner := process.connection == nil && !process.finished
	if inputOwner {
		process.connection = connection
	}
	if err := writeResponse(connection, Response{PID: process.pid, SessionID: process.id, InputOwner: inputOwner}); err != nil {
		if inputOwner {
			process.connection = nil
		}
		process.mu.Unlock()
		return
	}
	process.attachmentSeen = true
	process.activeAttachments++
	process.notifyAttachmentChangedLocked()
	defer func() {
		process.mu.Lock()
		if inputOwner && process.connection == connection {
			process.connection = nil
		}
		process.activeAttachments--
		process.notifyAttachmentChangedLocked()
		process.mu.Unlock()
	}()
	if !cursorSet {
		cursor = process.outputFirstSeq
	}
	if cursor > process.outputNextSeq {
		if inputOwner && process.connection == connection {
			process.connection = nil
		}
		process.mu.Unlock()
		_ = writeResponse(connection, Response{Error: "output cursor is ahead of retained terminal output"})
		return
	}
	process.mu.Unlock()
	inputDone := make(chan struct{})
	go process.readAttachmentInput(connection, inputOwner, inputDone)
	defer connection.Close()
	for {
		process.mu.Lock()
		var frame TerminalFrame
		var changed <-chan struct{}
		switch {
		case cursor < process.outputFirstSeq:
			frame = TerminalFrame{Type: "lagged", LostChunks: process.outputFirstSeq - cursor}
			cursor = process.outputFirstSeq
		case cursor < process.outputNextSeq:
			frame = process.output[cursor-process.outputFirstSeq]
			cursor++
			frame.Sequence = cursor
		case process.finished:
			frame = TerminalFrame{Type: "exit", ExitCode: process.exitCode}
			process.mu.Unlock()
			_ = writeTerminalFrame(connection, frame)
			return
		default:
			changed = process.outputChanged
		}
		process.mu.Unlock()
		if frame.Type != "" {
			if err := writeTerminalFrame(connection, frame); err != nil {
				return
			}
			continue
		}
		select {
		case <-changed:
		case <-inputDone:
			return
		}
	}
}

func (process *retainedTerminal) readAttachmentInput(connection net.Conn, inputOwner bool, done chan<- struct{}) {
	defer close(done)
	for {
		payload, err := ReadFrame(connection)
		if err != nil {
			return
		}
		var frame TerminalFrame
		decoder := json.NewDecoder(strings.NewReader(string(payload)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&frame) != nil || decoder.Decode(new(any)) != io.EOF {
			return
		}
		process.mu.Lock()
		finished := process.finished
		ownsInput := inputOwner && process.connection == connection
		process.mu.Unlock()
		if finished {
			return
		}
		switch frame.Type {
		case "stdin":
			if !ownsInput {
				continue
			}
			if len(frame.Data) > 0 {
				if _, err := process.pty.Write(frame.Data); err != nil {
					return
				}
			}
		case "resize":
			if frame.Columns == 0 || frame.Rows == 0 || frame.Columns > 65535 || frame.Rows > 65535 {
				return
			}
			if err := pty.Setsize(process.pty, &pty.Winsize{Cols: uint16(frame.Columns), Rows: uint16(frame.Rows)}); err != nil {
				return
			}
		case "eof":
			if ownsInput {
				_, _ = process.pty.Write([]byte{4})
			}
		case "signal":
			signal, ok := guestTerminalSignal(frame.Signal)
			if !ok || syscall.Kill(-process.pid, signal) != nil {
				return
			}
		default:
			return
		}
	}
}
