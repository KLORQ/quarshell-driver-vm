//go:build linux

package vmguest

import (
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
	finished          bool
	exitCode          int
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
		outputDone:  make(chan struct{}), awaitAttachment: awaitAttachment,
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
		terminal.attach(connection)
		return
	}
	process.attach(connection)
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
	if process.connection != nil {
		if writeTerminalFrame(process.connection, frame) == nil {
			return
		}
		process.connection = nil
	}
	process.output = append(process.output, frame)
	process.outputBytes += len(frame.Data)
	for process.outputBytes > retainedMainProcessOutputLimit && len(process.output) > 0 {
		process.outputBytes -= len(process.output[0].Data)
		process.output = process.output[1:]
	}
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
	if process.connection != nil {
		if writeTerminalFrame(process.connection, TerminalFrame{Type: "exit", ExitCode: process.exitCode}) != nil {
			process.connection = nil
		}
	}
	process.mu.Unlock()
	_ = process.stdin.Close()
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

func (process *retainedMainProcess) attach(connection net.Conn) {
	process.mu.Lock()
	if process.connection != nil || process.activeAttachments != 0 {
		process.mu.Unlock()
		_ = writeResponse(connection, Response{Error: "main process already has an input owner"})
		return
	}
	process.connection = connection
	if err := writeResponse(connection, Response{PID: process.pid, SessionID: process.id}); err != nil {
		process.connection = nil
		process.mu.Unlock()
		return
	}
	process.attachmentSeen = true
	process.activeAttachments++
	process.notifyAttachmentChangedLocked()
	defer func() {
		process.mu.Lock()
		if process.connection == connection {
			process.connection = nil
		}
		process.activeAttachments--
		process.notifyAttachmentChangedLocked()
		process.mu.Unlock()
	}()
	for _, frame := range process.output {
		if err := writeTerminalFrame(connection, frame); err != nil {
			process.connection = nil
			process.mu.Unlock()
			return
		}
	}
	process.output = nil
	process.outputBytes = 0
	if process.finished {
		if err := writeTerminalFrame(connection, TerminalFrame{Type: "exit", ExitCode: process.exitCode}); err != nil {
			process.mu.Unlock()
			return
		}
		process.mu.Unlock()
		for {
			if _, err := ReadFrame(connection); err != nil {
				return
			}
		}
	}
	process.mu.Unlock()
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
			if len(frame.Data) > 0 {
				_, err = process.stdin.Write(frame.Data)
			}
		case "eof":
			err = process.stdin.Close()
		case "resize":
			// Pipe based canonical processes have no terminal dimensions.
		case "signal":
			if signal, ok := guestTerminalSignal(frame.Signal); ok {
				err = syscall.Kill(-process.pid, signal)
			} else {
				err = fmt.Errorf("unsupported main-process signal %q", frame.Signal)
			}
		default:
			err = fmt.Errorf("unsupported main-process input frame %q", frame.Type)
		}
		process.mu.Unlock()
		if err != nil || frame.Type == "eof" {
			return
		}
	}
}

func (process *retainedMainProcess) notifyAttachmentChangedLocked() {
	close(process.attachmentChanged)
	process.attachmentChanged = make(chan struct{})
}
