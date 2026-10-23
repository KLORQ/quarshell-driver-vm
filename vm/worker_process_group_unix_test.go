//go:build darwin || linux

package vm

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestKillWorkerProcessGroupStopsWorker(t *testing.T) {
	command := exec.Command("sh", "-c", "sleep 60 & wait")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	completed := false
	defer func() {
		if !completed {
			_ = killWorkerProcessGroup(command)
			<-done
		}
	}()
	if err := killWorkerProcessGroup(command); err != nil {
		t.Fatalf("killWorkerProcessGroup() error = %v", err)
	}
	select {
	case err := <-done:
		completed = true
		if err == nil {
			t.Fatal("worker exited successfully after SIGKILL")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker process group did not stop")
	}
}
