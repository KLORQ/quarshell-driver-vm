//go:build darwin

package vm

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

func workerProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func killWorkerProcessGroup(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return nil
	}
	return killProcessGroup(command.Process.Pid)
}

func killProcessGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return err
	}
	return nil
}

func workerIsolationForChild() (workerIsolationConfig, error) {
	return workerIsolationConfig{NoHostMounts: true}, nil
}

func prepareWorkerIsolation(config workerIsolationConfig) error {
	if !config.NoHostMounts || config.HostMountNamespace != "" || config.HostUserNamespace != "" {
		return fmt.Errorf("macOS VM workers require an explicit no-host-mounts isolation mode")
	}
	return nil
}

func verifyWorkerCodeSignature(path, expectedTeamID string) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(expectedTeamID) == "" {
		return fmt.Errorf("worker path and trusted Team ID are required")
	}
	if output, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", "--verbose=2", path).CombinedOutput(); err != nil {
		return fmt.Errorf("codesign verification failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	output, err := exec.Command("/usr/bin/codesign", "-dv", "--verbose=4", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("read worker code-signing identity: %w: %s", err, strings.TrimSpace(string(output)))
	}
	teamID := ""
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "TeamIdentifier=") {
			teamID = strings.TrimSpace(strings.TrimPrefix(line, "TeamIdentifier="))
			break
		}
	}
	if teamID == "" || teamID == "not set" {
		return fmt.Errorf("worker has no signed Apple Developer Team ID")
	}
	if teamID != expectedTeamID {
		return fmt.Errorf("worker Team ID %q does not match configured trusted Team ID", teamID)
	}
	return nil
}

func verifyWorkerAdHocSignature(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("worker path is required")
	}
	if output, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", "--verbose=2", path).CombinedOutput(); err != nil {
		return fmt.Errorf("codesign verification failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	output, err := exec.Command("/usr/bin/codesign", "-dv", "--verbose=4", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("read worker code-signing metadata: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "Signature=adhoc" {
			return nil
		}
	}
	return fmt.Errorf("worker does not carry an ad-hoc code signature")
}
