//go:build linux

package vmguest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const retainedMainProcessOutputLimit = 1 << 20

func validMainSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// retainedMainProcess owns non-PTY stdio independently of an RPC connection.
// It keeps a bounded event tail so a reconnect can replay output already
// produced by the canonical workload.
type retainedMainProcess struct {
	owner             *controlServer
	id                string
	pid               int
	command           *exec.Cmd
	stdin             *os.File
	outputFiles       []*os.File
	mu                sync.Mutex
	connection        net.Conn
	output            []TerminalFrame
	outputBytes       int
	outputFirstSeq    uint64
	outputNextSeq     uint64
	outputChanged     chan struct{}
	finished          bool
	exitCode          int
	stdinClosed       bool
	outputDone        chan struct{}
	readersLeft       atomic.Int32
	awaitAttachment   bool
	attachmentSeen    bool
	activeAttachments int
	attachmentChanged chan struct{}
	onExit            func()
}

func (s *controlServer) retainMainProcess(id string, command *exec.Cmd, stdin, stdout, stderr *os.File, awaitAttachment bool, onExit func()) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("canonical non-TTY workload requires a retained session ID")
	}
	s.mainProcessMu.Lock()
	if s.mainProcesses == nil {
		s.mainProcesses = make(map[string]*retainedMainProcess)
	}
	if len(s.mainProcesses) >= retainedTerminalMaxSessions {
		s.mainProcessMu.Unlock()
		return fmt.Errorf("guest main-process session limit reached")
	}
	if _, exists := s.mainProcesses[id]; exists {
		s.mainProcessMu.Unlock()
		return fmt.Errorf("main-process session ID already exists")
	}
	process := &retainedMainProcess{
		owner: s, id: id, pid: command.Process.Pid, command: command, stdin: stdin,
		outputFiles: []*os.File{stdout, stderr},
		outputDone:  make(chan struct{}), outputChanged: make(chan struct{}), awaitAttachment: awaitAttachment,
		attachmentChanged: make(chan struct{}), onExit: onExit,
	}
	process.readersLeft.Store(2)
	s.mainProcesses[id] = process
	s.mainProcessMu.Unlock()
	go process.readOutput("stdout", stdout)
	go process.readOutput("stderr", stderr)
	go process.wait()
	return nil
}

func (s *controlServer) attachMainProcess(connection net.Conn, id string) {
	s.attachMainProcessFromCursor(connection, id, 0, false)
}

func (s *controlServer) attachMainProcessFromCursor(connection net.Conn, id string, cursor uint64, cursorSet bool) {
	s.mainProcessMu.Lock()
	process := s.mainProcesses[id]
	s.mainProcessMu.Unlock()
	if strings.TrimSpace(id) == "" {
		_ = writeResponse(connection, Response{Error: "main-process session not found"})
		return
	}
	if process == nil {
		s.terminalMu.Lock()
		terminal := s.terminals[id]
		s.terminalMu.Unlock()
		if terminal == nil {
			_ = writeResponse(connection, Response{Error: "main-process session not found"})
			return
		}
		terminal.attachFromCursor(connection, cursor, cursorSet)
		return
	}
	process.attachFromCursor(connection, cursor, cursorSet)
}

func (s *controlServer) waitForMainProcessAttachment(id string) {
	s.mainProcessMu.Lock()
	process := s.mainProcesses[id]
	s.mainProcessMu.Unlock()
	if process == nil {
		return
	}
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

func (process *retainedMainProcess) readOutput(kind string, reader *os.File) {
	defer reader.Close()
	defer func() {
		if process.readersLeft.Add(-1) == 0 {
			close(process.outputDone)
		}
	}()
	buffer := make([]byte, 32<<10)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			process.publish(TerminalFrame{Type: kind, Data: append([]byte(nil), buffer[:count]...)})
		}
		if err != nil {
			return
		}
	}
}

func (process *retainedMainProcess) publish(frame TerminalFrame) {
	process.mu.Lock()
	defer process.mu.Unlock()
	process.output = append(process.output, frame)
	process.outputNextSeq++
	process.outputBytes += len(frame.Data)
	for process.outputBytes > retainedMainProcessOutputLimit && len(process.output) > 0 {
		process.outputBytes -= len(process.output[0].Data)
		process.output = process.output[1:]
		process.outputFirstSeq++
	}
	process.notifyOutputLocked()
}

func (process *retainedMainProcess) wait() {
	err := process.command.Wait()
	select {
	case <-process.outputDone:
	case <-time.After(2 * time.Second):
		for _, output := range process.outputFiles {
			_ = output.Close()
		}
		<-process.outputDone
	}
	process.mu.Lock()
	process.finished = true
	process.exitCode = normalizeGuestExitCode(err)
	process.notifyOutputLocked()
	if process.stdin != nil {
		_ = process.stdin.Close()
		process.stdin = nil
		process.stdinClosed = true
	}
	process.mu.Unlock()
	if process.onExit != nil {
		process.onExit()
	}
	time.AfterFunc(retainedTerminalFinishedTTL, func() {
		process.owner.mainProcessMu.Lock()
		if process.owner.mainProcesses[process.id] == process {
			delete(process.owner.mainProcesses, process.id)
		}
		process.owner.mainProcessMu.Unlock()
	})
}

func (process *retainedMainProcess) waitForExit(ctx context.Context) (int, error) {
	if ctx == nil {
		return 0, fmt.Errorf("process wait context is nil")
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

func (process *retainedMainProcess) exitCodeValue() int {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.exitCode
}

func (process *retainedMainProcess) signal(name string) error {
	signal, ok := guestTerminalSignal(name)
	if !ok {
		return fmt.Errorf("unsupported process signal %q", name)
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.finished {
		return nil
	}
	if err := syscall.Kill(-process.pid, signal); err != nil && err != syscall.ESRCH {
		return fmt.Errorf("signal guest exec process group: %w", err)
	}
	return nil
}

func (process *retainedMainProcess) terminate(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("process termination context is nil")
	}
	process.mu.Lock()
	finished := process.finished
	pid := process.pid
	process.mu.Unlock()
	if finished {
		return nil
	}
	if err := process.signal("terminate"); err != nil {
		return err
	}
	_, waitErr := process.waitForExit(ctx)
	if waitErr != nil {
		return waitErr
	}
	// The leader may exit while descendants still hold inherited output pipes.
	// The stable process-group ID remains owned until those descriptors drain.
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return fmt.Errorf("kill remaining guest exec descendants: %w", err)
	}
	return nil
}

func (process *retainedMainProcess) attach(connection net.Conn) {
	process.attachFromCursor(connection, 0, false)
}

func (process *retainedMainProcess) attachFromCursor(connection net.Conn, cursor uint64, cursorSet bool) {
	process.mu.Lock()
	inputOwner := process.connection == nil && !process.stdinClosed && process.stdin != nil
	if inputOwner {
		process.connection = connection
	}
	stdinClosed := process.stdinClosed || process.stdin == nil
	if !cursorSet {
		cursor = process.outputFirstSeq
	}
	if cursor > process.outputNextSeq {
		if inputOwner && process.connection == connection {
			process.connection = nil
		}
		process.mu.Unlock()
		_ = writeResponse(connection, Response{Error: "output cursor is ahead of retained process output"})
		return
	}
	if err := writeResponse(connection, Response{PID: process.pid, SessionID: process.id, InputOwner: inputOwner, StdinClosed: stdinClosed}); err != nil {
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
			if err := writeTerminalFrame(connection, frame); err != nil {
				return
			}
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

func (process *retainedMainProcess) notifyOutputLocked() {
	close(process.outputChanged)
	process.outputChanged = make(chan struct{})
}

func (process *retainedMainProcess) readAttachmentInput(connection net.Conn, inputOwner bool, done chan<- struct{}) {
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
		switch frame.Type {
		case "stdin":
			if inputOwner && process.connection == connection && !process.stdinClosed && len(frame.Data) > 0 {
				_, err = process.stdin.Write(frame.Data)
				if err != nil {
					process.stdin = nil
					process.stdinClosed = true
					process.connection = nil
					err = nil
				}
			}
		case "eof":
			if inputOwner && process.connection == connection && !process.stdinClosed {
				err = process.stdin.Close()
				process.stdinClosed = true
				process.stdin = nil
				process.connection = nil
			}
		case "resize":
			// Pipe based canonical processes have no terminal dimensions.
		case "signal":
			if !inputOwner || process.connection != connection {
				break
			}
			if signal, ok := guestTerminalSignal(frame.Signal); ok {
				err = syscall.Kill(-process.pid, signal)
			} else {
				err = fmt.Errorf("unsupported main-process signal %q", frame.Signal)
			}
		default:
			err = fmt.Errorf("unsupported main-process input frame %q", frame.Type)
		}
		process.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (process *retainedMainProcess) notifyAttachmentChangedLocked() {
	close(process.attachmentChanged)
	process.attachmentChanged = make(chan struct{})
}
