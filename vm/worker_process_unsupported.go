//go:build !darwin && !linux

package vm

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func workerProcessAttributes() *syscall.SysProcAttr { return nil }

func killWorkerProcessGroup(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return nil
	}
	return command.Process.Kill()
}

func killProcessGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}

func workerIsolationForChild() (workerIsolationConfig, error) {
	return workerIsolationConfig{}, fmt.Errorf("VM worker isolation is unsupported on this platform")
}

func prepareWorkerIsolation(workerIsolationConfig) error {
	return fmt.Errorf("VM worker isolation is unsupported on this platform")
}

func verifyWorkerCodeSignature(string, string) error {
	return fmt.Errorf("Apple code signature verification is unsupported on this platform")
}

func verifyWorkerAdHocSignature(string) error {
	return fmt.Errorf("Apple ad-hoc code signature verification is unsupported on this platform")
}
