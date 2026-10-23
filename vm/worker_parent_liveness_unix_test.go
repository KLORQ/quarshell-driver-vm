//go:build darwin || linux

package vm

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestParentLivenessWatchKillsWorkerWhenParentExits(t *testing.T) {
	if os.Getenv("CAUTEM_VM_LIVENESS_TEST_CHILD") == "1" {
		stop, err := startParentLivenessWatch(3)
		if err != nil {
			fmt.Fprintln(os.Stdout, "watch error:", err)
			os.Exit(2)
		}
		defer stop()
		fmt.Fprintln(os.Stdout, "armed")
		select {}
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestParentLivenessWatchKillsWorkerWhenParentExits$")
	command.Env = append(os.Environ(), "CAUTEM_VM_LIVENESS_TEST_CHILD=1")
	command.ExtraFiles = []*os.File{reader}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		t.Fatal(err)
	}
	_ = reader.Close()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	completed := false
	defer func() {
		_ = writer.Close()
		if !completed {
			_ = killWorkerProcessGroup(command)
			<-waited
		}
	}()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if !strings.Contains(line, "armed") {
			t.Fatalf("worker liveness setup output = %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not arm its parent-liveness watch")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waited:
		completed = true
		if err == nil {
			t.Fatal("worker exited successfully after its parent-liveness pipe closed")
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-waited
		t.Fatal("worker remained alive after its parent process exited")
	}
}

func TestParentLivenessStopReturnsWhileParentAlive(t *testing.T) {
	if os.Getenv("CAUTEM_VM_LIVENESS_STOP_TEST_CHILD") == "1" {
		stop, err := startParentLivenessWatch(3)
		if err != nil {
			fmt.Fprintln(os.Stdout, "watch error:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stdout, "armed")
		var callers sync.WaitGroup
		for range 8 {
			callers.Add(1)
			go func() {
				defer callers.Done()
				stop()
			}()
		}
		callers.Wait()
		stop() // Stopping the watcher remains safe after concurrent calls.
		fmt.Fprintln(os.Stdout, "stopped")
		return
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestParentLivenessStopReturnsWhileParentAlive$")
	command.Env = append(os.Environ(), "CAUTEM_VM_LIVENESS_STOP_TEST_CHILD=1")
	command.ExtraFiles = []*os.File{reader}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		t.Fatal(err)
	}
	_ = reader.Close()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	commandDone := false
	defer func() {
		_ = writer.Close()
		if !commandDone {
			_ = killWorkerProcessGroup(command)
			<-waited
		}
	}()

	lines := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	for _, expected := range []string{"armed", "stopped"} {
		select {
		case line := <-lines:
			if strings.Contains(line, "watch error:") || line != expected {
				t.Fatalf("parent-liveness child output = %q; want %q", line, expected)
			}
		case err := <-waited:
			commandDone = true
			t.Fatalf("child exited before output %q: %v", expected, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("child did not print %q while parent kept the liveness pipe open", expected)
		}
	}
	select {
	case err := <-waited:
		commandDone = true
		if err != nil {
			t.Fatalf("parent-liveness child exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child remained alive after stopping the parent-liveness watcher")
	}
}

func TestParentLivenessStopRacingWithEOFIsBounded(t *testing.T) {
	if os.Getenv("CAUTEM_VM_LIVENESS_EOF_RACE_CHILD") == "1" {
		stop, err := startParentLivenessWatch(3)
		if err != nil {
			fmt.Fprintln(os.Stdout, "watch error:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stdout, "armed")
		var signal [1]byte
		_, _ = os.Stdin.Read(signal[:])
		stop()
		fmt.Fprintln(os.Stdout, "stopped")
		return
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, childInput, err := os.Pipe()
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestParentLivenessStopRacingWithEOFIsBounded$")
	command.Env = append(os.Environ(), "CAUTEM_VM_LIVENESS_EOF_RACE_CHILD=1")
	command.ExtraFiles = []*os.File{reader}
	command.Stdin = stdin
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		_ = stdin.Close()
		_ = childInput.Close()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		_ = stdin.Close()
		_ = childInput.Close()
		t.Fatal(err)
	}
	_ = reader.Close()
	_ = stdin.Close()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	completed := false
	defer func() {
		_ = writer.Close()
		_ = childInput.Close()
		if !completed {
			_ = killWorkerProcessGroup(command)
			<-waited
		}
	}()

	lines := make(chan string, 2)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	select {
	case line := <-lines:
		if line != "armed" {
			t.Fatalf("EOF-race child setup output = %q; want armed", line)
		}
	case err := <-waited:
		completed = true
		t.Fatalf("EOF-race child exited before arming watcher: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("EOF-race child did not arm watcher")
	}

	// EOF and an orderly stop arrive together. Either outcome is valid: the
	// watcher may kill this isolated child group, or stop may win the race.
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, _ = childInput.Write([]byte{1}) // EPIPE is valid when EOF already killed the child.
	_ = childInput.Close()
	select {
	case err := <-waited:
		completed = true
		if err == nil {
			select {
			case line := <-lines:
				if line != "stopped" {
					t.Fatalf("orderly EOF-race child output = %q; want stopped", line)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("orderly EOF-race child exited without stop confirmation")
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EOF and watcher stop race left the isolated worker alive")
	}
}

func TestParentLivenessWorkerCanReturnNormally(t *testing.T) {
	if os.Getenv("CAUTEM_VM_LIVENESS_NORMAL_RETURN_CHILD") == "1" {
		if _, err := startParentLivenessWatch(3); err != nil {
			fmt.Fprintln(os.Stdout, "watch error:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stdout, "armed")
		var signal [1]byte
		_, _ = os.Stdin.Read(signal[:])
		return // Model a worker/prep process whose main operation completed.
	}

	stdin, childInput, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestParentLivenessWorkerCanReturnNormally$")
	command.Env = append(os.Environ(), "CAUTEM_VM_LIVENESS_NORMAL_RETURN_CHILD=1")
	command.Stdin = stdin
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		_ = childInput.Close()
		t.Fatal(err)
	}
	parentLiveness, err := startWorkerWithParentLiveness(command)
	if err != nil {
		_ = stdin.Close()
		_ = childInput.Close()
		t.Fatalf("start worker with parent-liveness pipe: %v", err)
	}
	_ = stdin.Close()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	completed := false
	defer func() {
		_ = parentLiveness.Close()
		_ = childInput.Close()
		if !completed {
			_ = killWorkerProcessGroup(command)
			<-waited
		}
	}()

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "armed" {
		t.Fatalf("normal-return worker readiness = %q, %v", line, err)
	}
	if _, err := childInput.Write([]byte{1}); err != nil {
		t.Fatalf("release normal-return worker: %v", err)
	}
	_ = childInput.Close()
	select {
	case err := <-waited:
		completed = true
		if err != nil {
			t.Fatalf("normally completed worker required kill fallback: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("normally completed worker did not return from command.Wait")
	}
}
