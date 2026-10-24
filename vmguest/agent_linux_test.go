//go:build linux

package vmguest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestGuestControlRequiresPerSandboxToken(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("x", 64)}
	if server.authorized("") || server.authorized(server.token[:62]+"00") || !server.authorized(server.token) {
		t.Fatal("guest control token authorization did not reject invalid credentials")
	}
	guest, host := net.Pipe()
	defer guest.Close()
	go server.serve(guest)
	if err := WriteFrame(host, []byte(`{"version":1,"operation":"shutdown"}`)); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadFrame(host)
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(frame, &response); err != nil {
		t.Fatal(err)
	}
	_ = host.Close()
	if response.Error != "unauthorized guest control request" {
		t.Fatalf("unauthenticated shutdown response=%+v", response)
	}
	if response.Version != ProtocolVersion {
		t.Fatalf("response version=%d; want %d", response.Version, ProtocolVersion)
	}
}

func TestGuestLoopbackDialBridgesTCPInsideBoundary(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		payload, _ := io.ReadAll(connection)
		_, _ = connection.Write(append([]byte("echo:"), payload...))
	}()
	guestControl, hostControl := net.Pipe()
	defer hostControl.Close()
	address := listener.Addr().(*net.TCPAddr)
	server := &controlServer{}
	go server.dialLoopback(guestControl, "127.0.0.1", uint32(address.Port))
	ack, err := ReadFrame(hostControl)
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(ack, &response); err != nil || response.Error != "" {
		t.Fatalf("loopback connect response = %+v, err=%v", response, err)
	}
	writeTerminalFrame(hostControl, TerminalFrame{Type: "data", Data: []byte("request")})
	writeTerminalFrame(hostControl, TerminalFrame{Type: "eof"})
	var got []byte
	for {
		payload, readErr := ReadFrame(hostControl)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			t.Fatal(err)
		}
		if frame.Type == "data" {
			got = append(got, frame.Data...)
		}
		if frame.Type == "eof" {
			break
		}
		if frame.Type == "error" {
			t.Fatalf("loopback bridge error: %s", frame.Data)
		}
	}
	if string(got) != "echo:request" {
		t.Fatalf("loopback bridged output = %q", got)
	}
}

func TestGuestLoopbackDialRejectsNonLoopbackTargets(t *testing.T) {
	server := &controlServer{token: strings.Repeat("a", 64)}
	for _, target := range []struct {
		host string
		port uint32
	}{{host: "0.0.0.0", port: 80}, {host: "example.com", port: 80}, {host: "127.0.0.1", port: 0}, {host: "::1", port: 65536}} {
		err := server.validateRequest(Request{
			Version: ProtocolVersion, AuthToken: server.token, Operation: "dial-loopback",
			TargetHost: target.host, TargetPort: target.port,
		})
		if err == nil {
			t.Errorf("accepted loopback target %s:%d", target.host, target.port)
		}
	}
}

func TestGuestControlRotatesTokenAndAllowsOnlyIdempotentRetry(t *testing.T) {
	oldToken := strings.Repeat("1", 64)
	nextToken := strings.Repeat("2", 64)
	rotationID := strings.Repeat("a", 32)
	server := &controlServer{token: oldToken}
	call := func(request Request) Response {
		t.Helper()
		guest, host := net.Pipe()
		defer guest.Close()
		go server.serve(guest)
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(host, encoded); err != nil {
			t.Fatal(err)
		}
		frame, err := ReadFrame(host)
		if err != nil {
			t.Fatal(err)
		}
		_ = host.Close()
		var response Response
		if err := json.Unmarshal(frame, &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	rotation := Request{
		Version: ProtocolVersion, AuthToken: oldToken, NextAuthToken: nextToken,
		RotationID: rotationID, Operation: "rotate-token",
	}
	if response := call(rotation); response.Error != "" {
		t.Fatalf("rotate token response=%+v", response)
	}
	if !server.authorized(nextToken) || server.authorized(oldToken) {
		t.Fatal("guest did not replace the old control token")
	}
	if response := call(rotation); response.Error != "" {
		t.Fatalf("idempotent rotation retry response=%+v", response)
	}
	rotation.RotationID = strings.Repeat("b", 32)
	if response := call(rotation); response.Error != "unauthorized guest control request" {
		t.Fatalf("altered rotation retry response=%+v", response)
	}
	if response := call(Request{Version: ProtocolVersion, AuthToken: oldToken, Operation: "ping"}); response.Error != "unauthorized guest control request" {
		t.Fatalf("old token ping response=%+v", response)
	}
}

func TestRetainedMainProcessStreamsPipesAndAcceptsInput(t *testing.T) {
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", "IFS= read -r value; printf 'out:%s' \"$value\"; printf 'err:%s' \"$value\" >&2; exit 7")
	command.Stdin, command.Stdout, command.Stderr = stdinReader, stdoutWriter, stderrWriter
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stdinReader.Close()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	server := &controlServer{mainProcesses: make(map[string]*retainedMainProcess)}
	if err := server.retainMainProcess(strings.Repeat("a", 32), command, stdinWriter, stdoutReader, stderrReader, false, nil); err != nil {
		t.Fatal(err)
	}
	guest, host := net.Pipe()
	defer host.Close()
	go server.attachMainProcess(guest, strings.Repeat("a", 32))
	responseData, err := ReadFrame(host)
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(responseData, &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != "" || response.PID == 0 {
		t.Fatalf("attachment response = %+v", response)
	}
	input, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte("value\n")})
	if err := WriteFrame(host, input); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr []byte
	exitCode := -1
	for exitCode == -1 {
		encoded, readErr := ReadFrame(host)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(encoded, &frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "stdout":
			stdout = append(stdout, frame.Data...)
		case "stderr":
			stderr = append(stderr, frame.Data...)
		case "exit":
			exitCode = frame.ExitCode
		default:
			t.Fatalf("unexpected frame type %q", frame.Type)
		}
	}
	if string(stdout) != "out:value" || string(stderr) != "err:value" || exitCode != 7 {
		t.Fatalf("stdout=%q stderr=%q exit=%d", stdout, stderr, exitCode)
	}
}

func TestRetainedMainProcessReplaysOutputFromPriorAttachment(t *testing.T) {
	const sessionID = "cccccccccccccccccccccccccccccccc"
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", "printf 'before\\n'; IFS= read -r value; printf 'after:%s\\n' \"$value\"")
	command.Stdin, command.Stdout, command.Stderr = stdinReader, stdoutWriter, stderrWriter
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stdinReader.Close()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	server := &controlServer{mainProcesses: make(map[string]*retainedMainProcess)}
	if err := server.retainMainProcess(sessionID, command, stdinWriter, stdoutReader, stderrReader, false, nil); err != nil {
		t.Fatal(err)
	}

	firstGuest, firstHost := net.Pipe()
	go server.attachMainProcess(firstGuest, sessionID)
	if _, err := ReadFrame(firstHost); err != nil {
		t.Fatalf("read first attachment handshake: %v", err)
	}
	firstOutput, err := ReadFrame(firstHost)
	if err != nil {
		t.Fatalf("read initial main-process output: %v", err)
	}
	var firstFrame TerminalFrame
	if err := json.Unmarshal(firstOutput, &firstFrame); err != nil || firstFrame.Type != "stdout" || string(firstFrame.Data) != "before\n" || firstFrame.Sequence != 1 {
		t.Fatalf("initial main-process output frame=%+v err=%v", firstFrame, err)
	}
	_ = firstHost.Close()

	deadline := time.Now().Add(time.Second)
	for {
		process := server.mainProcesses[sessionID]
		process.mu.Lock()
		detached := process.connection == nil
		process.mu.Unlock()
		if detached {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("main process did not detach after transport loss")
		}
		time.Sleep(time.Millisecond)
	}

	secondGuest, secondHost := net.Pipe()
	defer secondHost.Close()
	go server.attachMainProcessFromCursor(secondGuest, sessionID, firstFrame.Sequence, true)
	if _, err := ReadFrame(secondHost); err != nil {
		t.Fatalf("read reattached main-process handshake: %v", err)
	}
	input, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte("again\n")})
	if err := WriteFrame(secondHost, input); err != nil {
		t.Fatalf("send reattached main-process input: %v", err)
	}
	var after string
	for {
		payload, err := ReadFrame(secondHost)
		if err != nil {
			t.Fatalf("read main-process output after reconnect: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "stdout":
			after += string(frame.Data)
			if frame.Sequence != 2 {
				t.Fatalf("reattached output sequence = %d, want 2", frame.Sequence)
			}
		case "exit":
			if frame.ExitCode != 0 || after != "after:again\n" {
				t.Fatalf("reattached main process result = exit %d, output %q", frame.ExitCode, after)
			}
			return
		}
	}
}

func TestRetainedMainProcessAllowsOutputReadersWithOneInputOwner(t *testing.T) {
	const sessionID = "dddddddddddddddddddddddddddddddd"
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", "printf 'before\\n'; IFS= read -r value; printf 'after:%s\\n' \"$value\"")
	command.Stdin, command.Stdout, command.Stderr = stdinReader, stdoutWriter, stderrWriter
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stdinReader.Close()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	server := &controlServer{mainProcesses: make(map[string]*retainedMainProcess)}
	if err := server.retainMainProcess(sessionID, command, stdinWriter, stdoutReader, stderrReader, false, nil); err != nil {
		t.Fatal(err)
	}

	firstGuest, firstHost := net.Pipe()
	defer firstHost.Close()
	go server.attachMainProcess(firstGuest, sessionID)
	var firstHandshake Response
	payload, err := ReadFrame(firstHost)
	if err != nil || json.Unmarshal(payload, &firstHandshake) != nil || !firstHandshake.InputOwner {
		t.Fatalf("first attachment did not acquire stdin: response=%+v err=%v", firstHandshake, err)
	}
	if _, err := ReadFrame(firstHost); err != nil {
		t.Fatalf("read initial output for first attachment: %v", err)
	}

	secondGuest, secondHost := net.Pipe()
	defer secondHost.Close()
	go server.attachMainProcess(secondGuest, sessionID)
	var secondHandshake Response
	payload, err = ReadFrame(secondHost)
	if err != nil || json.Unmarshal(payload, &secondHandshake) != nil || secondHandshake.InputOwner {
		t.Fatalf("second attachment did not remain read-only: response=%+v err=%v", secondHandshake, err)
	}
	if _, err := ReadFrame(secondHost); err != nil {
		t.Fatalf("read replay output for second attachment: %v", err)
	}
	ignored, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte("ignored\n")})
	if err := WriteFrame(secondHost, ignored); err != nil {
		t.Fatalf("send read-only attachment input: %v", err)
	}
	actual, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte("owner-input\n")})
	if err := WriteFrame(firstHost, actual); err != nil {
		t.Fatalf("send owner input: %v", err)
	}

	readResult := func(connection net.Conn) string {
		t.Helper()
		var output string
		for {
			payload, readErr := ReadFrame(connection)
			if readErr != nil {
				t.Fatalf("read attached process output: %v", readErr)
			}
			var frame TerminalFrame
			if err := json.Unmarshal(payload, &frame); err != nil {
				t.Fatal(err)
			}
			switch frame.Type {
			case "stdout":
				output += string(frame.Data)
			case "exit":
				if frame.ExitCode != 0 {
					t.Fatalf("attached process exit code=%d", frame.ExitCode)
				}
				return output
			}
		}
	}
	if output := readResult(firstHost); output != "after:owner-input\n" {
		t.Fatalf("input owner output=%q", output)
	}
	if output := readResult(secondHost); output != "after:owner-input\n" {
		t.Fatalf("read-only attachment output=%q", output)
	}
}

func TestRetainedMainProcessReportsLaggedOutputCursor(t *testing.T) {
	process := &retainedMainProcess{
		id: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", pid: 1,
		outputChanged: make(chan struct{}), attachmentChanged: make(chan struct{}),
	}
	guest, host := net.Pipe()
	defer host.Close()
	go process.attach(guest)
	if _, err := ReadFrame(host); err != nil {
		t.Fatalf("read output subscriber handshake: %v", err)
	}
	process.publish(TerminalFrame{Type: "stdout", Data: []byte("first")})
	first, err := ReadFrame(host)
	var firstFrame TerminalFrame
	if err != nil || json.Unmarshal(first, &firstFrame) != nil || string(firstFrame.Data) != "first" {
		t.Fatalf("first output frame=%+v err=%v", firstFrame, err)
	}
	chunk := bytes.Repeat([]byte("x"), 32<<10)
	for i := 0; i < retainedMainProcessOutputLimit/(32<<10)+4; i++ {
		process.publish(TerminalFrame{Type: "stdout", Data: chunk})
	}
	encoded, err := ReadFrame(host)
	var lagged TerminalFrame
	if err != nil || json.Unmarshal(encoded, &lagged) != nil || lagged.Type != "lagged" || lagged.LostChunks == 0 {
		t.Fatalf("slow output subscriber did not receive a lag marker: frame=%+v err=%v", lagged, err)
	}
}

func TestStartWorkloadRetainsNonTTYCanonicalProcessOutput(t *testing.T) {
	workDir := t.TempDir()
	if err := os.Chmod(workDir, 0o777); err != nil {
		t.Fatal(err)
	}
	const sessionID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	poweredOff := make(chan struct{}, 1)
	server := &controlServer{
		uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()),
		powerOffGuest: func() error { poweredOff <- struct{}{}; return nil },
	}
	if err := server.startWorkload(context.Background(), Request{
		Argv:    []string{"/bin/sh", "-c", "printf stdout; printf stderr >&2; exit 9"},
		WorkDir: workDir, SessionID: sessionID, AwaitMainProcessAttachment: true,
	}); err != nil {
		t.Fatalf("startWorkload() error=%v", err)
	}
	guest, host := net.Pipe()
	done := make(chan struct{})
	go func() { server.attachMainProcess(guest, sessionID); close(done) }()
	if _, err := ReadFrame(host); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr []byte
	exitCode := -1
	for exitCode < 0 {
		encoded, err := ReadFrame(host)
		if err != nil {
			t.Fatal(err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(encoded, &frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "stdout":
			stdout = append(stdout, frame.Data...)
		case "stderr":
			stderr = append(stderr, frame.Data...)
		case "exit":
			exitCode = frame.ExitCode
		default:
			t.Fatalf("unexpected frame type %q", frame.Type)
		}
	}
	_ = host.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("main-process attachment did not close")
	}
	select {
	case <-poweredOff:
	case <-time.After(2 * time.Second):
		t.Fatal("guest did not power off after attachment finished")
	}
	if string(stdout) != "stdout" || string(stderr) != "stderr" || exitCode != 9 {
		t.Fatalf("stdout=%q stderr=%q exit=%d", stdout, stderr, exitCode)
	}
}

func TestGuestControlExecStreamSupportsSeparateOutputAndStdinEOF(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("a", 64)}
	guest, host := net.Pipe()
	done := make(chan struct{})
	go func() { server.serve(guest); close(done) }()
	request, err := json.Marshal(Request{
		Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-stream",
		Argv:    []string{"/bin/sh", "-c", "read value; printf 'stdout:%s' \"$value\"; printf 'stderr:%s' \"$value\" >&2; exit 9"},
		WorkDir: t.TempDir(), NoLoginShell: true, SessionID: strings.Repeat("1", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(host, request); err != nil {
		t.Fatal(err)
	}
	encoded, err := ReadFrame(host)
	if err != nil {
		t.Fatal(err)
	}
	var started Response
	if err := json.Unmarshal(encoded, &started); err != nil || started.Error != "" || started.PID <= 1 {
		t.Fatalf("exec stream handshake=%+v error=%v", started, err)
	}
	stdin, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte("value\n")})
	if err := WriteFrame(host, stdin); err != nil {
		t.Fatal(err)
	}
	eof, _ := json.Marshal(TerminalFrame{Type: "eof"})
	if err := WriteFrame(host, eof); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr string
	exitCode := -1
	for exitCode < 0 {
		encoded, err := ReadFrame(host)
		if err != nil {
			t.Fatalf("read exec stream output: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(encoded, &frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "stdout":
			stdout += string(frame.Data)
		case "stderr":
			stderr += string(frame.Data)
		case "exit":
			exitCode = frame.ExitCode
		default:
			t.Fatalf("unexpected exec stream frame: %+v", frame)
		}
	}
	_ = host.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("exec stream control handler did not terminate")
	}
	if stdout != "stdout:value" || stderr != "stderr:value" || exitCode != 9 {
		t.Fatalf("exec stream stdout=%q stderr=%q exit=%d", stdout, stderr, exitCode)
	}
}

func TestGuestControlExecStreamDrainsFastProcessOutput(t *testing.T) {
	for iteration := 0; iteration < 30; iteration++ {
		server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("d", 64)}
		guest, host := net.Pipe()
		done := make(chan struct{})
		go func() { server.serve(guest); close(done) }()
		request, err := json.Marshal(Request{
			Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-stream",
			Argv:    []string{"/bin/sh", "-c", "i=0; while [ $i -lt 1000 ]; do printf x; printf y >&2; i=$((i + 1)); done"},
			WorkDir: t.TempDir(), NoLoginShell: true, SessionID: fmt.Sprintf("%032x", iteration+1),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(host, request); err != nil {
			t.Fatal(err)
		}
		encoded, err := ReadFrame(host)
		if err != nil {
			t.Fatalf("iteration %d read exec stream handshake: %v", iteration, err)
		}
		var started Response
		if err := json.Unmarshal(encoded, &started); err != nil || started.Error != "" || started.PID <= 1 {
			t.Fatalf("iteration %d exec stream handshake=%+v error=%v", iteration, started, err)
		}
		eof, _ := json.Marshal(TerminalFrame{Type: "eof"})
		if err := WriteFrame(host, eof); err != nil {
			t.Fatalf("iteration %d send stdin EOF: %v", iteration, err)
		}
		var stdout, stderr strings.Builder
		exitCode := -1
		for exitCode < 0 {
			encoded, err := ReadFrame(host)
			if err != nil {
				t.Fatalf("iteration %d read exec stream output: %v", iteration, err)
			}
			var frame TerminalFrame
			if err := json.Unmarshal(encoded, &frame); err != nil {
				t.Fatalf("iteration %d decode exec stream frame: %v", iteration, err)
			}
			switch frame.Type {
			case "stdout":
				stdout.Write(frame.Data)
			case "stderr":
				stderr.Write(frame.Data)
			case "exit":
				exitCode = frame.ExitCode
			default:
				t.Fatalf("iteration %d unexpected exec stream frame: %+v", iteration, frame)
			}
		}
		_ = host.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("iteration %d exec stream handler did not terminate", iteration)
		}
		if stdout.Len() != 1000 || stderr.Len() != 1000 || strings.Trim(stdout.String(), "x") != "" || strings.Trim(stderr.String(), "y") != "" || exitCode != 0 {
			t.Fatalf("iteration %d exec stream stdout bytes=%d stderr bytes=%d exit=%d", iteration, stdout.Len(), stderr.Len(), exitCode)
		}
	}
}

func TestGuestControlExecStreamRetainsProcessAfterDisconnectAndReattaches(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("c", 64)}
	guest, host := net.Pipe()
	done := make(chan struct{})
	go func() { server.serve(guest); close(done) }()
	request, err := json.Marshal(Request{
		Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-stream",
		Argv:    []string{"/bin/sh", "-c", "sleep 60 & child=$!; echo $child; read value; kill $child; wait $child 2>/dev/null || true; printf 'done:%s' \"$value\""},
		WorkDir: t.TempDir(), NoLoginShell: true, SessionID: strings.Repeat("2", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(host, request); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(host); err != nil { // process handshake
		t.Fatalf("read exec stream handshake: %v", err)
	}
	var childPID int
	for childPID == 0 {
		encoded, err := ReadFrame(host)
		if err != nil {
			t.Fatalf("read child PID before disconnect: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(encoded, &frame); err != nil {
			t.Fatal(err)
		}
		if frame.Type != "stdout" {
			continue
		}
		childPID, err = strconv.Atoi(strings.TrimSpace(string(frame.Data)))
		if err != nil {
			t.Fatalf("parse child PID from %q: %v", frame.Data, err)
		}
	}
	if childPID <= 1 {
		t.Fatalf("invalid child PID %d", childPID)
	}
	if err := host.Close(); err != nil {
		t.Fatalf("close exec stream transport: %v", err)
	}
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("exec stream handler did not terminate after transport loss")
	}
	deadline := time.Now().Add(time.Second)
	for {
		alive, err := linuxProcessAlive(childPID)
		if err != nil {
			t.Fatalf("inspect disconnected exec child %d: %v", childPID, err)
		}
		if alive {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("exec child %d did not survive transport loss", childPID)
		}
		time.Sleep(10 * time.Millisecond)
	}

	reattachGuest, reattachedHost := net.Pipe()
	defer reattachedHost.Close()
	reattachDone := make(chan struct{})
	go func() { server.serve(reattachGuest); close(reattachDone) }()
	attachRequest, _ := json.Marshal(Request{Version: ProtocolVersion, AuthToken: server.token, Operation: "attach-exec-stream", SessionID: strings.Repeat("2", 32)})
	if err := WriteFrame(reattachedHost, attachRequest); err != nil {
		t.Fatal(err)
	}
	encoded, err := ReadFrame(reattachedHost)
	var attached Response
	if err != nil || json.Unmarshal(encoded, &attached) != nil || attached.Error != "" || !attached.InputOwner {
		t.Fatalf("reattached exec stream response=%+v err=%v", attached, err)
	}
	input, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte("resumed\n")})
	if err := WriteFrame(reattachedHost, input); err != nil {
		t.Fatal(err)
	}
	var resumed string
	for {
		encoded, err = ReadFrame(reattachedHost)
		if err != nil {
			t.Fatalf("read reattached exec output: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(encoded, &frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "stdout":
			resumed += string(frame.Data)
		case "exit":
			if frame.ExitCode != 0 || !strings.Contains(resumed, "done:resumed") {
				t.Fatalf("reattached exec result exit=%d output=%q", frame.ExitCode, resumed)
			}
			select {
			case <-reattachDone:
			case <-time.After(time.Second):
				t.Fatal("reattached exec stream handler did not terminate")
			}
			return
		}
	}
}

func linuxProcessAlive(pid int) (bool, error) {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	closeParen := strings.LastIndexByte(string(stat), ')')
	if closeParen < 0 {
		return false, fmt.Errorf("invalid proc stat for pid %d", pid)
	}
	fields := strings.Fields(string(stat[closeParen+1:]))
	if len(fields) == 0 {
		return false, fmt.Errorf("missing process state for pid %d", pid)
	}
	return fields[0] != "Z", nil
}

func TestGuestControlRejectsUnsupportedProtocolVersions(t *testing.T) {
	server := &controlServer{token: strings.Repeat("x", 64)}
	for _, version := range []uint16{0, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			guest, host := net.Pipe()
			defer guest.Close()
			go server.serve(guest)
			encoded, err := json.Marshal(Request{Version: version, AuthToken: server.token, Operation: "ping"})
			if err != nil {
				t.Fatal(err)
			}
			if err := WriteFrame(host, encoded); err != nil {
				t.Fatal(err)
			}
			frame, err := ReadFrame(host)
			if err != nil {
				t.Fatal(err)
			}
			var response Response
			if err := json.Unmarshal(frame, &response); err != nil {
				t.Fatal(err)
			}
			_ = host.Close()
			if response.Error == "" || response.Version != ProtocolVersion {
				t.Fatalf("unsupported version response=%+v", response)
			}
		})
	}
}

func TestGuestWorkloadEnvironmentDoesNotInheritAgentSecrets(t *testing.T) {
	t.Setenv("QUARSHELL_VM_CONTROL_TOKEN", "must-not-leak")
	for _, entry := range guestEnvironment(nil) {
		if entry == "QUARSHELL_VM_CONTROL_TOKEN=must-not-leak" {
			t.Fatal("guest workload inherited the agent control token")
		}
	}
}

func TestGuestWorkloadEnvironmentForcesPolicyBrokerAndDropsControlValues(t *testing.T) {
	env := guestEnvironmentForWorkload([]string{
		"HTTP_PROXY=http://attacker.invalid:8080",
		"https_proxy=http://attacker.invalid:8080",
		"NO_PROXY=example.com",
		"QUARSHELL_VM_NETWORK_BROKER_PORT=9999",
		"OPENSHELL_OCI_IMAGE_USER=spoofed",
		"OPENSHELL_SANDBOX_UID=0",
		"OPENSHELL_SANDBOX_GID=0",
		"TOKEN=guest-value",
	}, "http://127.0.0.1:3128")
	values := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if values[key] != "http://127.0.0.1:3128" {
			t.Errorf("%s=%q; want forced guest policy proxy", key, values[key])
		}
	}
	if values["NO_PROXY"] != "localhost,127.0.0.1,::1" || values["no_proxy"] != values["NO_PROXY"] {
		t.Errorf("no_proxy values = %q / %q", values["NO_PROXY"], values["no_proxy"])
	}
	for _, key := range []string{
		"QUARSHELL_VM_NETWORK_BROKER_PORT", "OPENSHELL_OCI_IMAGE_USER",
		"OPENSHELL_SANDBOX_UID", "OPENSHELL_SANDBOX_GID",
	} {
		if _, ok := values[key]; ok {
			t.Fatalf("internal identity/control value %s leaked to workload", key)
		}
	}
	if values["TOKEN"] != "guest-value" {
		t.Fatalf("unrelated workload env was dropped: %v", values)
	}
}

func TestGuestWorkloadCredentialAppliesOCIUserFailClosed(t *testing.T) {
	if credential, err := guestWorkloadCredential("", uint32(os.Geteuid()), uint32(os.Getegid())); err != nil || credential != nil {
		t.Fatalf("current guest identity credential = %+v, %v; want no-op", credential, err)
	}
	defaultCredential, err := guestWorkloadCredential("", 1000, 1001)
	if err != nil || defaultCredential.Uid != 1000 || defaultCredential.Gid != 1001 {
		t.Fatalf("default credential = %+v, %v", defaultCredential, err)
	}
	credential, err := guestWorkloadCredential("1234:1235", 1000, 1001)
	if err != nil || credential.Uid != 1234 || credential.Gid != 1235 {
		t.Fatalf("numeric OCI credential = %+v, %v", credential, err)
	}
	for _, declaration := range []string{"0", "0:1000", "1000:0", "1000:1000:1000", "unknown-user-name-for-test"} {
		if _, err := guestWorkloadCredential(declaration, 1000, 1001); err == nil {
			t.Errorf("guestWorkloadCredential(%q) unexpectedly succeeded", declaration)
		}
	}
}

func TestNetworkProxyConfigurationRequiresValidPortPair(t *testing.T) {
	t.Setenv("QUARSHELL_VM_NETWORK_PROXY_PORT", "3128")
	t.Setenv("QUARSHELL_VM_NETWORK_BROKER_PORT", "5501")
	proxyPort, brokerPort, err := networkProxyConfigurationFromEnvironment()
	if err != nil || proxyPort != 3128 || brokerPort != 5501 {
		t.Fatalf("networkProxyConfigurationFromEnvironment() = (%d, %d, %v)", proxyPort, brokerPort, err)
	}
	if os.Getenv("QUARSHELL_VM_NETWORK_PROXY_PORT") != "" || os.Getenv("QUARSHELL_VM_NETWORK_BROKER_PORT") != "" {
		t.Fatal("internal network proxy configuration was not removed from guest agent environment")
	}
	t.Setenv("QUARSHELL_VM_NETWORK_PROXY_PORT", "3128")
	t.Setenv("QUARSHELL_VM_NETWORK_BROKER_PORT", "")
	if _, _, err := networkProxyConfigurationFromEnvironment(); err == nil {
		t.Fatal("partial network proxy configuration was accepted")
	}
}

func TestGuestRelayConfigurationValidatesPortsAndSupervisorPair(t *testing.T) {
	t.Setenv("QUARSHELL_VM_SSH_RELAY_PORT", "5502")
	t.Setenv("QUARSHELL_VM_SUPERVISOR_CONTROL_PORT", "5503")
	t.Setenv("QUARSHELL_VM_SUPERVISOR_ENABLED", "1")
	config, err := relayConfigurationFromEnvironment()
	if err != nil || config.sshPort != 5502 || config.controlPort != 5503 || !config.supervisor {
		t.Fatalf("relayConfigurationFromEnvironment() = %+v, %v", config, err)
	}
	for _, key := range []string{"QUARSHELL_VM_SSH_RELAY_PORT", "QUARSHELL_VM_SUPERVISOR_CONTROL_PORT", "QUARSHELL_VM_SUPERVISOR_ENABLED"} {
		if os.Getenv(key) != "" {
			t.Errorf("internal VM relay setting %s was not removed", key)
		}
	}
	t.Setenv("QUARSHELL_VM_SUPERVISOR_CONTROL_PORT", "5503")
	t.Setenv("QUARSHELL_VM_SUPERVISOR_ENABLED", "")
	if _, err := relayConfigurationFromEnvironment(); err == nil || !strings.Contains(err.Error(), "must be configured together") {
		t.Fatalf("orphaned supervisor control bridge error = %v", err)
	}
}

func TestGuestWorkloadAndExecCommandsUseHardenedSupervisorPattern(t *testing.T) {
	workload := guestWorkloadCommand([]string{"/bin/sh", "-c", "printf a b"}, true)
	wantWorkload := []string{
		guestSupervisorBinary, "--", guestInitBinary, "--policy", guestPolicyFile, "--",
		"/bin/sh", "-c", "printf a b",
	}
	if strings.Join(workload, "\x00") != strings.Join(wantWorkload, "\x00") {
		t.Fatalf("supervised workload argv = %q; want %q", workload, wantWorkload)
	}
	execArgv := guestExecCommand([]string{"/usr/bin/id", "-u"}, true)
	wantExec := []string{guestInitBinary, "--policy", guestPolicyFile, "--", "/usr/bin/id", "-u"}
	if strings.Join(execArgv, "\x00") != strings.Join(wantExec, "\x00") {
		t.Fatalf("hardened exec argv = %q; want %q", execArgv, wantExec)
	}
	if got := guestWorkloadCommand([]string{"true"}, false); len(got) != 1 || got[0] != "true" {
		t.Fatalf("unsupervised argv = %q", got)
	}
}

func TestGuestRestartPolicyValidation(t *testing.T) {
	for input, want := range map[string]string{"": "never", "never": "never", "on-failure": "on-failure", "always": "always", " ALWAYS ": "always"} {
		got, err := normalizeGuestRestartPolicy(input)
		if err != nil || got != want {
			t.Errorf("normalizeGuestRestartPolicy(%q)=(%q,%v), want %q", input, got, err, want)
		}
	}
	if _, err := normalizeGuestRestartPolicy("sometimes"); err == nil {
		t.Fatal("invalid restart policy was accepted")
	}
	server := &controlServer{}
	if err := server.startWorkload(context.Background(), Request{Argv: []string{"true"}, RestartPolicy: "always"}); err == nil || !strings.Contains(err.Error(), "requires the guest supervisor") {
		t.Fatalf("unsupervised restart policy error=%v", err)
	}
}

func TestSupervisorReadinessRequiresPrivateRegularMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	if ready, _, _, err := readSupervisorReadiness(path); err != nil || ready {
		t.Fatalf("missing readiness marker=(%v,%v), want false,nil", ready, err)
	}
	if err := os.WriteFile(path, []byte("quarshell-supervisor-ready-v2 1000 1001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ready, uid, gid, err := readSupervisorReadiness(path); err != nil || !ready || uid != 1000 || gid != 1001 {
		t.Fatalf("valid readiness marker=(%v,%d,%d,%v), want true,1000,1001,nil", ready, uid, gid, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readSupervisorReadiness(path); err == nil {
		t.Fatal("world-readable readiness marker was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readSupervisorReadiness(path); err == nil {
		t.Fatal("symlink readiness marker was accepted")
	}
}

func TestWaitForSupervisorReadinessHonorsContextAndProcessExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := waitForSupervisorReadiness(ctx, path, make(chan struct{})); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled readiness wait error=%v, want context canceled", err)
	}
	done := make(chan struct{})
	close(done)
	if _, _, err := waitForSupervisorReadiness(context.Background(), path, done); err == nil || !strings.Contains(err.Error(), "exited before") {
		t.Fatalf("exited readiness wait error=%v", err)
	}
}

func TestStartWorkloadWaitsForSupervisorReadiness(t *testing.T) {
	if err := (&controlServer{}).confirmWorkloadStart(); err == nil {
		t.Fatal("confirmed a workload before guest supervisor readiness")
	}
	root := t.TempDir()
	readyPath := filepath.Join(root, "run", "supervisor.ready")
	supervisorPath := filepath.Join(root, "fake-supervisor")
	script := "#!/bin/sh\numask 077\nprintf 'quarshell-supervisor-ready-v2 1000 1001\\n' > \"$QUARSHELL_VM_SUPERVISOR_READY_FILE\"\nexec sleep 30\n"
	if err := os.WriteFile(supervisorPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	server := &controlServer{
		supervisorEnabled: true,
		supervisorReady:   readyPath,
		powerOffGuest:     func() error { t.Error("intentional stop powered off the guest"); return nil },
		workloadCommand: func([]string, bool) []string {
			return []string{supervisorPath}
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.startWorkload(ctx, Request{Argv: []string{"ignored"}, WorkDir: root}); err != nil {
		t.Fatalf("startWorkload() error=%v", err)
	}
	if server.workloadUID != 1000 || server.workloadGID != 1001 {
		t.Fatalf("observed workload identity=%d:%d, want 1000:1001", server.workloadUID, server.workloadGID)
	}
	if _, err := os.Lstat(readyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness marker remains after acknowledgement: %v", err)
	}
	if server.workloadConfirmed || server.workloadStartGate == nil {
		t.Fatal("guest start gate state was not held pending host confirmation")
	}
	if err := server.confirmWorkloadStart(); err != nil {
		t.Fatalf("confirmWorkloadStart() error=%v", err)
	}
	if !server.workloadConfirmed {
		t.Fatal("workload confirmation state was not recorded")
	}
	if err := server.confirmWorkloadStart(); err != nil {
		t.Fatalf("idempotent confirmWorkloadStart() error=%v", err)
	}
	if err := server.stopWorkload(); err != nil {
		t.Fatalf("stop ready workload: %v", err)
	}
	if server.workloadStartGate != nil {
		t.Fatal("guest start gate pipe remained open after stop")
	}
}

func TestRetainedExecProcessWaitSignalAndTerminateAreStable(t *testing.T) {
	t.Run("repeated wait", func(t *testing.T) {
		server := &controlServer{}
		process := startRetainedTestProcess(t, server, strings.Repeat("3", 32), "/bin/sh", "-c", "exit 13")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for attempt := 0; attempt < 2; attempt++ {
			code, err := process.waitForExit(ctx)
			if err != nil || code != 13 {
				t.Fatalf("wait attempt %d = (%d, %v), want stable exit 13", attempt, code, err)
			}
		}
	})

	t.Run("detached signal", func(t *testing.T) {
		server := &controlServer{}
		process := startRetainedTestProcess(t, server, strings.Repeat("4", 32), "/bin/sh", "-c", "exec sleep 60")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := process.signal("terminate"); err != nil {
			t.Fatalf("signal detached process: %v", err)
		}
		code, err := process.waitForExit(ctx)
		if err != nil || code != 128+int(syscall.SIGTERM) {
			t.Fatalf("signal exit = (%d, %v), want %d", code, err, 128+int(syscall.SIGTERM))
		}
	})

	t.Run("detached terminate", func(t *testing.T) {
		server := &controlServer{}
		process := startRetainedTestProcess(t, server, strings.Repeat("5", 32), "/bin/sh", "-c", "sleep 60 & wait")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := process.terminate(ctx); err != nil {
			t.Fatalf("terminate detached process group: %v", err)
		}
		code, err := process.waitForExit(ctx)
		if err != nil || code < 128 {
			t.Fatalf("terminated process wait = (%d, %v), want a signal exit status", code, err)
		}
	})
}

func startRetainedTestProcess(t *testing.T, server *controlServer, id string, argv ...string) *retainedMainProcess {
	t.Helper()
	command := exec.Command(argv[0], argv[1:]...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	childStdin, stdin, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, childStdout, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, childStderr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stdin, command.Stdout, command.Stderr = childStdin, childStdout, childStderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = childStdin.Close()
	_ = childStdout.Close()
	_ = childStderr.Close()
	t.Cleanup(func() { _ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL) })
	if err := server.retainMainProcess(id, command, stdin, stdout, stderr, false, nil); err != nil {
		t.Fatal(err)
	}
	server.mainProcessMu.Lock()
	process := server.mainProcesses[id]
	server.mainProcessMu.Unlock()
	if process == nil {
		t.Fatal("retained process was not registered")
	}
	return process
}

func TestStartWorkloadReturnsWhenSupervisorExitsBeforeReadiness(t *testing.T) {
	root := t.TempDir()
	supervisorPath := filepath.Join(root, "fake-supervisor")
	if err := os.WriteFile(supervisorPath, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	server := &controlServer{
		supervisorEnabled: true,
		supervisorReady:   filepath.Join(root, "run", "supervisor.ready"),
		workloadCommand: func([]string, bool) []string {
			return []string{supervisorPath}
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.startWorkload(ctx, Request{Argv: []string{"ignored"}, WorkDir: root}); err == nil || !strings.Contains(err.Error(), "exited before") {
		t.Fatalf("startWorkload() error=%v, want supervisor exit before readiness", err)
	}
}

func TestRetainedTerminalOutputTailIsBounded(t *testing.T) {
	server := &controlServer{terminals: map[string]*retainedTerminal{
		"startup": {id: "startup", output: []TerminalFrame{{Type: "output", Data: []byte("supervisor-startup-error")}}},
	}}
	if got := server.retainedTerminalOutputTail("startup", 7); got != "p-error" {
		t.Fatalf("output tail=%q, want bounded suffix", got)
	}
	if got := server.retainedTerminalOutputTail("missing", 7); got != "" {
		t.Fatalf("missing terminal output=%q, want empty", got)
	}
}

func TestNaturalWorkloadExitPowersOffGuest(t *testing.T) {
	poweredOff := make(chan struct{}, 1)
	workDir := t.TempDir()
	if err := os.Chmod(workDir, 0o777); err != nil {
		t.Fatal(err)
	}
	server := &controlServer{
		uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()),
		workloadCommand: func([]string, bool) []string { return []string{"/bin/sh", "-c", "exit 7"} },
		powerOffGuest:   func() error { poweredOff <- struct{}{}; return nil },
	}
	if err := server.startWorkload(context.Background(), Request{Argv: []string{"ignored"}, WorkDir: workDir}); err != nil {
		t.Fatalf("startWorkload() error=%v", err)
	}
	if server.workloadUID != uint32(os.Geteuid()) || server.workloadGID != uint32(os.Getegid()) {
		t.Fatalf("observed workload identity=%d:%d, want %d:%d", server.workloadUID, server.workloadGID, os.Geteuid(), os.Getegid())
	}
	select {
	case <-poweredOff:
	case <-time.After(2 * time.Second):
		t.Fatal("guest was not powered off after the canonical workload exited")
	}
}

func TestAwaitMainProcessAttachmentKeepsGuestAliveAndDeliversExit(t *testing.T) {
	poweredOff := make(chan struct{}, 1)
	workDir := t.TempDir()
	if err := os.Chmod(workDir, 0o777); err != nil {
		t.Fatal(err)
	}
	server := &controlServer{
		uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()), token: strings.Repeat("b", 64),
		workloadCommand: func([]string, bool) []string {
			return []string{"/bin/sh", "-c", "printf 'fast-main-output\\n'; exit 7"}
		},
		powerOffGuest: func() error { poweredOff <- struct{}{}; return nil },
	}
	if err := server.startWorkload(context.Background(), Request{
		Argv: []string{"ignored"}, WorkDir: workDir, TTY: true,
		SessionID: strings.Repeat("a", 32), AwaitMainProcessAttachment: true,
	}); err != nil {
		t.Fatalf("startWorkload() error=%v", err)
	}
	var process *retainedTerminal
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		server.terminalMu.Lock()
		process = server.terminals[strings.Repeat("a", 32)]
		server.terminalMu.Unlock()
		if process != nil {
			process.mu.Lock()
			finished := process.finished
			process.mu.Unlock()
			if finished {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if process == nil {
		t.Fatal("main process terminal was not retained")
	}
	process.mu.Lock()
	finished := process.finished
	process.mu.Unlock()
	if !finished {
		t.Fatal("main process did not exit before the attachment test")
	}
	select {
	case <-poweredOff:
		t.Fatal("guest powered off before the declared main-process attachment")
	case <-time.After(100 * time.Millisecond):
	}

	guest, host := net.Pipe()
	t.Cleanup(func() { _ = host.Close() })
	attachmentDone := make(chan struct{})
	go func() {
		server.serve(guest)
		close(attachmentDone)
	}()
	request, err := json.Marshal(Request{
		Version: ProtocolVersion, AuthToken: server.token, Operation: "attach-terminal",
		SessionID: strings.Repeat("a", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(host, request); err != nil {
		t.Fatal(err)
	}
	responseFrame, err := ReadFrame(host)
	if err != nil {
		t.Fatalf("read terminal attachment response: %v", err)
	}
	var response Response
	if err := json.Unmarshal(responseFrame, &response); err != nil || response.Error != "" {
		t.Fatalf("terminal attachment response=%+v err=%v", response, err)
	}
	var outputSeen, exitSeen bool
	for !exitSeen {
		frameBytes, err := ReadFrame(host)
		if err != nil {
			t.Fatalf("read retained terminal frame: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(frameBytes, &frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "output":
			outputSeen = outputSeen || strings.Contains(string(frame.Data), "fast-main-output")
		case "exit":
			exitSeen = true
			if frame.ExitCode != 7 {
				t.Fatalf("retained main process exit code=%d want=7", frame.ExitCode)
			}
		default:
			t.Fatalf("unexpected terminal frame: %+v", frame)
		}
	}
	if !outputSeen {
		t.Fatal("retained terminal did not deliver the fast main process output")
	}
	if err := host.Close(); err != nil {
		t.Fatalf("close terminal attachment: %v", err)
	}
	select {
	case <-attachmentDone:
	case <-time.After(time.Second):
		t.Fatal("finished terminal attachment did not close")
	}
	select {
	case <-poweredOff:
	case <-time.After(2 * time.Second):
		t.Fatal("guest was not powered off after terminal exit delivery")
	}
}

func TestGuestCopyRoundTripAndRejectSymlink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "file.txt")
	if err := guestCopyTo(path, []byte("payload"), 0o640, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	data, err := guestCopyFrom(path)
	if err != nil || string(data) != "payload" {
		t.Fatalf("copy roundtrip = (%q, %v)", data, err)
	}
	if err := os.Symlink(path, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := guestCopyFrom(filepath.Join(root, "link")); err == nil {
		t.Fatal("copy-from followed a symlink")
	}
}

func TestGuestCopyRejectsSymlinkParentsWithoutTouchingTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	protected := filepath.Join(outside, "protected.txt")
	if err := os.WriteFile(protected, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "redirect")); err != nil {
		t.Fatal(err)
	}
	redirected := filepath.Join(root, "redirect", "protected.txt")
	if err := guestCopyTo(redirected, []byte("overwrite"), 0o600, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("copy-to followed a symlink parent")
	}
	if data, err := guestCopyFrom(redirected); err == nil {
		t.Fatalf("copy-from followed a symlink parent: %q", data)
	}
	if data, err := os.ReadFile(protected); err != nil || string(data) != "keep" {
		t.Fatalf("outside file changed: data=%q err=%v", data, err)
	}
}

func TestGuestCopyToRejectsFinalSymlinkWithoutTruncatingTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := guestCopyTo(link, []byte("overwrite"), 0o600, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("copy-to followed a final symlink")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
		t.Fatalf("symlink target changed: data=%q err=%v", data, err)
	}
}

func TestGuestExecReturnsStreamsAndExitCode(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	response := server.exec(context.Background(), Request{
		Argv:    []string{"/bin/sh", "-c", "printf out; printf err >&2; exit 7"},
		WorkDir: t.TempDir(),
	})
	if response.Error != "" || response.ExitCode != 7 || string(response.Stdout) != "out" || string(response.Stderr) != "err" {
		t.Fatalf("exec response = %+v", response)
	}
}

func TestGuestShellCommandQuotesArgvAndSelectsLoginMode(t *testing.T) {
	argv := []string{"printf", "%s", "a b'c; $(touch /tmp/should-not-exist)"}
	login := guestShellCommandWithPath("/bin/bash", argv, false)
	if len(login) != 3 || login[0] != "/bin/bash" || login[1] != "-lc" || login[2] != `'printf' '%s' 'a b'"'"'c; $(touch /tmp/should-not-exist)'` {
		t.Fatalf("login shell argv = %q", login)
	}
	plain := guestShellCommandWithPath("/bin/bash", argv, true)
	if len(plain) != 3 || plain[0] != "/bin/bash" || plain[1] != "-c" || plain[2] != login[2] {
		t.Fatalf("non-login shell argv = %q", plain)
	}
}

func TestGuestExecLoginShellReadsProfile(t *testing.T) {
	shellArgv, err := guestShellCommand([]string{"/bin/sh", "-c", `printf '%s' "$QUARSHELL_LOGIN_PROFILE"`}, false)
	if err != nil {
		t.Fatalf("resolve guest login shell: %v", err)
	}
	if shellArgv[0] != "/bin/bash" && shellArgv[0] != "/usr/bin/bash" {
		t.Skipf("profile fixture expects bash, found %s", shellArgv[0])
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".bash_profile"), []byte("export QUARSHELL_LOGIN_PROFILE=loaded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	response := server.exec(context.Background(), Request{
		Argv: []string{"/bin/sh", "-c", `printf '%s' "$QUARSHELL_LOGIN_PROFILE"`}, WorkDir: t.TempDir(), Env: []string{"HOME=" + home},
	})
	if response.Error != "" || response.ExitCode != 0 || string(response.Stdout) != "loaded" {
		t.Fatalf("login profile exec response = %+v", response)
	}
	response = server.exec(context.Background(), Request{
		Argv: []string{"/bin/sh", "-c", `printf '%s' "${QUARSHELL_LOGIN_PROFILE-unset}"`}, WorkDir: t.TempDir(), Env: []string{"HOME=" + home}, NoLoginShell: true,
	})
	if response.Error != "" || response.ExitCode != 0 || string(response.Stdout) != "unset" {
		t.Fatalf("non-login profile exec response = %+v", response)
	}
}

func TestGuestExecTreatsShellMetacharactersAsArguments(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "should-not-exist")
	argument := "$(touch " + marker + "); a'b"
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	response := server.exec(context.Background(), Request{
		Argv: []string{"printf", "%s", argument}, WorkDir: t.TempDir(), NoLoginShell: true,
	})
	if response.Error != "" || response.ExitCode != 0 || string(response.Stdout) != argument {
		t.Fatalf("exec response = %+v", response)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("shell metacharacter created marker: stat error=%v", err)
	}
}

func TestGuestExecFeedsNonInteractiveStdin(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	response := server.exec(context.Background(), Request{
		Argv:    []string{"/bin/sh", "-c", "read value; printf '%s' \"$value\""},
		WorkDir: t.TempDir(), Stdin: []byte("from-client\n"),
	})
	if response.Error != "" || response.ExitCode != 0 || string(response.Stdout) != "from-client" {
		t.Fatalf("stdin exec response = %+v", response)
	}
}

func TestGuestInteractiveExecCreatesAndResizesPTY(t *testing.T) {
	server := &controlServer{
		uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("a", 64),
	}
	guest, host := net.Pipe()
	defer host.Close()
	if err := host.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go server.serve(guest)
	request, err := json.Marshal(Request{
		Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-terminal",
		Argv:    []string{"/bin/sh", "-c", "stty size; IFS= read -r line; stty size"},
		WorkDir: t.TempDir(), NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(host, request); err != nil {
		t.Fatal(err)
	}
	handshakePayload, err := ReadFrame(host)
	if err != nil {
		t.Fatalf("read terminal handshake: %v", err)
	}
	var handshake Response
	if err := json.Unmarshal(handshakePayload, &handshake); err != nil || handshake.Error != "" || handshake.PID <= 0 {
		t.Fatalf("terminal handshake = %+v; decode error=%v", handshake, err)
	}

	readTerminalFrame := func() TerminalFrame {
		t.Helper()
		payload, err := ReadFrame(host)
		if err != nil {
			t.Fatalf("read terminal frame: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			t.Fatalf("decode terminal frame: %v", err)
		}
		return frame
	}
	first := readTerminalFrame()
	if first.Type != "output" || !strings.Contains(string(first.Data), "24 80") {
		t.Fatalf("initial terminal output = %+v; want 24 rows and 80 columns", first)
	}
	for _, frame := range []TerminalFrame{
		{Type: "resize", Columns: 101, Rows: 41},
		{Type: "stdin", Data: []byte("resize-check\n")},
	} {
		payload, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(host, payload); err != nil {
			t.Fatalf("send terminal %s frame: %v", frame.Type, err)
		}
	}
	var output strings.Builder
	for {
		frame := readTerminalFrame()
		if frame.Type == "exit" {
			if frame.ExitCode != 0 {
				t.Fatalf("interactive command exit code = %d", frame.ExitCode)
			}
			break
		}
		if frame.Type != "output" {
			t.Fatalf("unexpected terminal frame: %+v", frame)
		}
		output.Write(frame.Data)
	}
	if !strings.Contains(output.String(), "41 101") {
		t.Fatalf("resized terminal output = %q; want 41 rows and 101 columns", output.String())
	}
}

func TestGuestInteractiveExecDrainsOutputBeforeExitFrame(t *testing.T) {
	server := &controlServer{
		uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("c", 64),
	}
	for index := 0; index < 25; index++ {
		t.Run(fmt.Sprintf("run-%02d", index), func(t *testing.T) {
			guest, host := net.Pipe()
			defer host.Close()
			if err := host.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			go server.serve(guest)
			marker := fmt.Sprintf("terminal-output-%02d", index)
			request, err := json.Marshal(Request{
				Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-terminal",
				Argv: []string{"/bin/sh", "-c", "printf " + marker}, WorkDir: t.TempDir(),
				NoLoginShell: true, Columns: 80, Rows: 24,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := WriteFrame(host, request); err != nil {
				t.Fatalf("write terminal request: %v", err)
			}
			if payload, err := ReadFrame(host); err != nil {
				t.Fatalf("read terminal handshake: %v", err)
			} else {
				var response Response
				if err := json.Unmarshal(payload, &response); err != nil || response.Error != "" || response.PID <= 0 {
					t.Fatalf("terminal handshake = %+v; decode error=%v", response, err)
				}
			}
			var output strings.Builder
			for {
				payload, err := ReadFrame(host)
				if err != nil {
					t.Fatalf("read terminal output after %q: %v", output.String(), err)
				}
				var frame TerminalFrame
				if err := json.Unmarshal(payload, &frame); err != nil {
					t.Fatalf("decode terminal frame: %v", err)
				}
				switch frame.Type {
				case "output":
					output.Write(frame.Data)
				case "exit":
					if frame.ExitCode != 0 || !strings.Contains(output.String(), marker) {
						t.Fatalf("terminal exit = %d, output = %q; want marker %q before exit", frame.ExitCode, output.String(), marker)
					}
					return
				default:
					t.Fatalf("unexpected terminal frame: %+v", frame)
				}
			}
		})
	}
}

func TestGuestInteractiveExecForwardsTerminalInterrupt(t *testing.T) {
	server := &controlServer{
		uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("b", 64),
	}
	guest, host := net.Pipe()
	defer host.Close()
	if err := host.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go server.serve(guest)
	request, err := json.Marshal(Request{
		Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-terminal",
		Argv:    []string{"/bin/sh", "-c", "trap 'printf interrupted; exit 42' INT; printf 'ready\\n'; while :; do sleep 1; done"},
		WorkDir: t.TempDir(), NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(host, request); err != nil {
		t.Fatal(err)
	}
	handshakePayload, err := ReadFrame(host)
	if err != nil {
		t.Fatalf("read terminal handshake: %v", err)
	}
	var handshake Response
	if err := json.Unmarshal(handshakePayload, &handshake); err != nil || handshake.Error != "" || handshake.PID <= 0 {
		t.Fatalf("terminal handshake = %+v; decode error=%v", handshake, err)
	}
	var output strings.Builder
	for !strings.Contains(output.String(), "ready") {
		payload, err := ReadFrame(host)
		if err != nil {
			t.Fatalf("read interactive command readiness from %q: %v", output.String(), err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil || frame.Type != "output" {
			t.Fatalf("readiness terminal frame = %+v; decode error=%v", frame, err)
		}
		output.Write(frame.Data)
	}
	interrupt, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte{3}})
	if err := WriteFrame(host, interrupt); err != nil {
		t.Fatalf("send terminal interrupt: %v", err)
	}
	for {
		payload, err := ReadFrame(host)
		if err != nil {
			t.Fatalf("read terminal output after interrupt: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "output":
			output.Write(frame.Data)
		case "exit":
			if frame.ExitCode != 42 || !strings.Contains(output.String(), "interrupted") {
				t.Fatalf("interrupt result = exit %d, output %q; want trap exit 42", frame.ExitCode, output.String())
			}
			return
		default:
			t.Fatalf("unexpected terminal frame after interrupt: %+v", frame)
		}
	}
}

func TestGuestRetainedTerminalCanReattachAfterTransportLoss(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("e", 64)}
	const sessionID = "retained-terminal-test"
	firstGuest, firstHost := net.Pipe()
	go server.serve(firstGuest)
	request, _ := json.Marshal(Request{
		Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-terminal", SessionID: sessionID,
		Argv:    []string{"/bin/sh", "-c", "printf ready; IFS= read -r line; printf 'received:%s' \"$line\""},
		WorkDir: t.TempDir(), NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err := WriteFrame(firstHost, request); err != nil {
		t.Fatal(err)
	}
	var handshake Response
	payload, err := ReadFrame(firstHost)
	if err != nil || json.Unmarshal(payload, &handshake) != nil || handshake.Error != "" || handshake.SessionID != sessionID {
		t.Fatalf("initial terminal handshake = %+v, err=%v", handshake, err)
	}
	var ready strings.Builder
	var cursor uint64
	for !strings.Contains(ready.String(), "ready") {
		payload, err = ReadFrame(firstHost)
		if err != nil {
			t.Fatalf("read initial output: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			t.Fatal(err)
		}
		if frame.Type == "output" {
			ready.Write(frame.Data)
			cursor = frame.Sequence
		}
	}
	_ = firstHost.Close()
	deadline := time.Now().Add(time.Second)
	for {
		server.terminalMu.Lock()
		process := server.terminals[sessionID]
		server.terminalMu.Unlock()
		if process == nil {
			t.Fatal("retained terminal was not registered")
		}
		process.mu.Lock()
		detached := process.connection == nil
		process.mu.Unlock()
		if detached {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal did not detach after transport loss")
		}
		time.Sleep(time.Millisecond)
	}
	secondGuest, secondHost := net.Pipe()
	defer secondHost.Close()
	go server.serve(secondGuest)
	attach, _ := json.Marshal(Request{Version: ProtocolVersion, AuthToken: server.token, Operation: "attach-terminal", SessionID: sessionID, OutputCursor: cursor, OutputCursorSet: true})
	if err := WriteFrame(secondHost, attach); err != nil {
		t.Fatal(err)
	}
	payload, err = ReadFrame(secondHost)
	if err != nil || json.Unmarshal(payload, &handshake) != nil || handshake.Error != "" || handshake.SessionID != sessionID {
		t.Fatalf("reattach handshake = %+v, err=%v", handshake, err)
	}
	input, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte("reattached\n")})
	if err := WriteFrame(secondHost, input); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	for {
		payload, err = ReadFrame(secondHost)
		if err != nil {
			t.Fatalf("read reattached output: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "output":
			if frame.Sequence <= cursor {
				t.Fatalf("reattached PTY output cursor = %d, want > %d", frame.Sequence, cursor)
			}
			output.Write(frame.Data)
		case "exit":
			if frame.ExitCode != 0 || !strings.Contains(output.String(), "received:reattached") {
				t.Fatalf("reattached terminal result = exit %d, output %q", frame.ExitCode, output.String())
			}
			return
		}
	}
}

func TestGuestRetainedTerminalAllowsMultipleOutputReadersWithOneInputOwner(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("c", 64)}
	const sessionID = "retained-terminal-readers"
	attach := func() (net.Conn, Response) {
		guest, host := net.Pipe()
		go server.serve(guest)
		request, _ := json.Marshal(Request{Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-terminal", SessionID: sessionID,
			Argv:    []string{"/bin/sh", "-c", "printf ready; IFS= read -r line; printf 'received:%s' \"$line\""},
			WorkDir: t.TempDir(), NoLoginShell: true, Columns: 80, Rows: 24})
		if err := WriteFrame(host, request); err != nil {
			t.Fatal(err)
		}
		payload, err := ReadFrame(host)
		var response Response
		if err != nil || json.Unmarshal(payload, &response) != nil || response.Error != "" {
			t.Fatalf("terminal attach response=%+v err=%v", response, err)
		}
		return host, response
	}
	owner, ownerHandshake := attach()
	defer owner.Close()
	if !ownerHandshake.InputOwner {
		t.Fatal("first terminal attachment did not receive stdin ownership")
	}
	reader, readerHandshake := func() (net.Conn, Response) {
		guest, host := net.Pipe()
		go server.serve(guest)
		request, _ := json.Marshal(Request{Version: ProtocolVersion, AuthToken: server.token, Operation: "attach-terminal", SessionID: sessionID})
		if err := WriteFrame(host, request); err != nil {
			t.Fatal(err)
		}
		payload, err := ReadFrame(host)
		var response Response
		if err != nil || json.Unmarshal(payload, &response) != nil || response.Error != "" {
			t.Fatalf("second terminal attachment response=%+v err=%v", response, err)
		}
		return host, response
	}()
	defer reader.Close()
	if readerHandshake.InputOwner {
		t.Fatal("second terminal attachment unexpectedly received stdin ownership")
	}
	readOutput := func(connection net.Conn, want string) {
		t.Helper()
		for {
			payload, err := ReadFrame(connection)
			if err != nil {
				t.Fatalf("read terminal output: %v", err)
			}
			var frame TerminalFrame
			if err := json.Unmarshal(payload, &frame); err != nil {
				t.Fatal(err)
			}
			if frame.Type == "output" && strings.Contains(string(frame.Data), want) {
				return
			}
		}
	}
	readOutput(owner, "ready")
	readOutput(reader, "ready")
	ignored, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte("wrong\n")})
	if err := WriteFrame(reader, ignored); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte("right\n")})
	if err := WriteFrame(owner, input); err != nil {
		t.Fatal(err)
	}
	readOutput(owner, "received:right")
	readOutput(reader, "received:right")
}

func TestGuestRetainedTerminalCanBeTerminatedWhileDetached(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("f", 64)}
	const sessionID = "f1111111111111111111111111111111"
	guest, host := net.Pipe()
	go server.serve(guest)
	request, _ := json.Marshal(Request{
		Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-terminal", SessionID: sessionID,
		Argv: []string{"/bin/sleep", "30"}, WorkDir: t.TempDir(), NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err := WriteFrame(host, request); err != nil {
		t.Fatal(err)
	}
	payload, err := ReadFrame(host)
	var handshake Response
	if err != nil || json.Unmarshal(payload, &handshake) != nil || handshake.Error != "" {
		t.Fatalf("terminal handshake = %+v, err=%v", handshake, err)
	}
	_ = host.Close()
	deadline := time.Now().Add(time.Second)
	var process *retainedTerminal
	for {
		server.terminalMu.Lock()
		process = server.terminals[sessionID]
		server.terminalMu.Unlock()
		if process == nil {
			t.Fatal("retained terminal was not registered")
		}
		process.mu.Lock()
		detached := process.connection == nil
		process.mu.Unlock()
		if detached {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal did not detach after transport loss")
		}
		time.Sleep(time.Millisecond)
	}

	terminateGuest, terminateHost := net.Pipe()
	defer terminateHost.Close()
	go server.serve(terminateGuest)
	terminate, _ := json.Marshal(Request{Version: ProtocolVersion, AuthToken: server.token, Operation: "terminate-terminal", SessionID: sessionID})
	if err := WriteFrame(terminateHost, terminate); err != nil {
		t.Fatal(err)
	}
	payload, err = ReadFrame(terminateHost)
	var result Response
	if err != nil || json.Unmarshal(payload, &result) != nil || result.Error != "" || result.SessionID != sessionID {
		t.Fatalf("detached process terminate result = %+v, err=%v", result, err)
	}
	deadline = time.Now().Add(time.Second)
	for {
		process.mu.Lock()
		finished, code := process.finished, process.exitCode
		process.mu.Unlock()
		if finished {
			if code != 128+int(syscall.SIGTERM) {
				t.Fatalf("terminated process exit code = %d, want %d", code, 128+int(syscall.SIGTERM))
			}
			for attempt := 0; attempt < 2; attempt++ {
				waited, waitErr := process.waitForExit(context.Background())
				if waitErr != nil || waited != code {
					t.Fatalf("retained terminal Wait attempt %d = (%d, %v), want stable %d", attempt, waited, waitErr, code)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("detached process did not exit after terminate request")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestGuestTerminalSignalAllowlist(t *testing.T) {
	for name, want := range map[string]syscall.Signal{
		"terminate": syscall.SIGTERM,
		"kill":      syscall.SIGKILL,
		"interrupt": syscall.SIGINT,
		"hangup":    syscall.SIGHUP,
	} {
		got, ok := guestTerminalSignal(name)
		if !ok || got != want {
			t.Errorf("guestTerminalSignal(%q) = (%v, %v), want (%v, true)", name, got, ok, want)
		}
	}
	if _, ok := guestTerminalSignal("SIGSTOP"); ok {
		t.Fatal("guestTerminalSignal accepted a signal outside the protocol allowlist")
	}
}

func TestSignalMainProcessSignalsCanonicalProcessGroup(t *testing.T) {
	workDir := t.TempDir()
	if err := os.Chmod(workDir, 0o777); err != nil {
		t.Fatal(err)
	}
	poweredOff := make(chan struct{}, 1)
	server := &controlServer{
		uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()),
		workloadCommand: func([]string, bool) []string { return []string{"/bin/sh", "-c", "exec sleep 30"} },
		powerOffGuest:   func() error { poweredOff <- struct{}{}; return nil },
	}
	if err := server.startWorkload(context.Background(), Request{Argv: []string{"ignored"}, WorkDir: workDir}); err != nil {
		t.Fatalf("startWorkload() error=%v", err)
	}
	if err := server.signalMainProcess("terminate"); err != nil {
		t.Fatalf("signalMainProcess() error=%v", err)
	}
	done := server.jobDone
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canonical main process did not exit after TERM")
	}
	select {
	case <-poweredOff:
	case <-time.After(2 * time.Second):
		t.Fatal("guest did not power off after canonical process termination")
	}
}

func TestGuestExecOutputBufferIsBounded(t *testing.T) {
	buffer := boundedBuffer{limit: 4}
	if written, err := buffer.Write([]byte("abcdefgh")); written != 8 || err != nil {
		t.Fatalf("Write() = (%d, %v)", written, err)
	}
	if string(buffer.data) != "abcd" || !buffer.truncated {
		t.Fatalf("bounded output = (%q, truncated=%t)", buffer.data, buffer.truncated)
	}
}

func TestSignalMainProcessTargetsSupervisorManagedWorkloadGroup(t *testing.T) {
	workDir := t.TempDir()
	pidFile := filepath.Join(workDir, "workload.pid")
	command := exec.Command("/bin/sh", "-c", "setsid sleep 30 & child=$!; echo $child > \"$1\"; wait $child", "signal-main", pidFile)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		data, _ := os.ReadFile(pidFile)
		if childPID, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			_ = syscall.Kill(-childPID, syscall.SIGKILL)
		}
	})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := os.Stat(pidFile); err != nil {
		t.Fatalf("workload PID was not published: %v", err)
	}
	server := &controlServer{supervisorEnabled: true, job: command, jobDone: done}
	if err := server.signalMainProcess("kill"); err != nil {
		t.Fatalf("signalMainProcess() error=%v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor-managed workload process group remained alive after KILL")
	}
}

func TestGuestExecCancellationKillsProcessGroup(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	workDir := t.TempDir()
	startedPath := filepath.Join(workDir, "descendant-started")
	markerPath := filepath.Join(workDir, "descendant-survived-cancel")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan Response, 1)
	go func() {
		command := fmt.Sprintf("(/bin/sh -c 'touch \"$1\"; sleep 1; touch \"$2\"' sh %q %q) & wait", startedPath, markerPath)
		finished <- server.exec(ctx, Request{Argv: []string{"/bin/sh", "-c", command}, WorkDir: workDir})
	}()
	startedDeadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(startedPath); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatalf("inspect descendant start marker: %v", err)
		}
		if time.Now().After(startedDeadline) {
			t.Fatal("exec descendant did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case response := <-finished:
		if response.Error != "" || response.ExitCode == 0 {
			t.Fatalf("unexpected cancellation response: %+v", response)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("guest exec did not stop after client cancellation")
	}
	time.Sleep(1200 * time.Millisecond)
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("exec descendant survived cancellation; marker stat error = %v", err)
	}
}
