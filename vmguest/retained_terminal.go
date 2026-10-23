//go:build linux

package vmguest

import (
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
	retainedTerminalOutputLimit = 256 << 10
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
	output            []byte
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
		outputDone: make(chan struct{}), awaitAttachment: awaitAttachment,
		attachmentChanged: make(chan struct{}), onExit: onExit,
	}
	s.terminals[id] = process
	go process.readOutput()
	go process.wait()
	return process, nil
}

func (s *controlServer) attachTerminal(connection net.Conn, id string) {
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
	process.attach(connection)
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
	if len(process.output) > limit {
		return string(process.output[len(process.output)-limit:])
	}
	return string(process.output)
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
			if process.connection != nil {
				if writeTerminalFrame(process.connection, TerminalFrame{Type: "output", Data: append([]byte(nil), buffer[:count]...)}) != nil {
					process.connection = nil
					process.retainOutput(buffer[:count])
				}
			} else {
				process.retainOutput(buffer[:count])
			}
			process.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (process *retainedTerminal) retainOutput(payload []byte) {
	process.output = append(process.output, payload...)
	if len(process.output) > retainedTerminalOutputLimit {
		process.output = append([]byte(nil), process.output[len(process.output)-retainedTerminalOutputLimit:]...)
	}
}

func (process *retainedTerminal) wait() {
	err := process.command.Wait()
	<-process.outputDone
	process.mu.Lock()
	process.finished = true
	process.exitCode = normalizeGuestExitCode(err)
	process.finishedAt = time.Now()
	if process.connection != nil {
		if writeTerminalFrame(process.connection, TerminalFrame{Type: "exit", ExitCode: process.exitCode}) != nil {
			process.connection = nil
		}
	}
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

func (process *retainedTerminal) attach(connection net.Conn) {
	process.mu.Lock()
	if process.connection != nil || process.activeAttachments != 0 {
		process.mu.Unlock()
		_ = writeResponse(connection, Response{Error: "terminal session is already attached"})
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
	if len(process.output) != 0 {
		if err := writeTerminalFrame(connection, TerminalFrame{Type: "output", Data: append([]byte(nil), process.output...)}); err != nil {
			process.connection = nil
			process.mu.Unlock()
			return
		}
		process.output = nil
	}
	if process.finished {
		if err := writeTerminalFrame(connection, TerminalFrame{Type: "exit", ExitCode: process.exitCode}); err != nil {
			process.mu.Unlock()
			return
		}
		process.mu.Unlock()
		// A post-exit attachment is complete only after the client has read the
		// retained exit frame and closed its side of the stream.
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
		switch frame.Type {
		case "stdin":
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
			_, _ = process.pty.Write([]byte{4})
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
