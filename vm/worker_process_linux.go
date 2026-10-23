//go:build linux

package vm

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func workerProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid:     true,
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getuid(),
			Size:        1,
		}},
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getgid(),
			Size:        1,
		}},
		GidMappingsEnableSetgroups: false,
	}
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
	if os.Getuid() == 0 || os.Getgid() == 0 {
		return workerIsolationConfig{}, fmt.Errorf("VM worker requires a non-root host identity; mapping namespace root to host root would not isolate host access")
	}
	mountNamespace, err := namespaceIdentity("/proc/self/ns/mnt")
	if err != nil {
		return workerIsolationConfig{}, fmt.Errorf("inspect host mount namespace: %w", err)
	}
	userNamespace, err := namespaceIdentity("/proc/self/ns/user")
	if err != nil {
		return workerIsolationConfig{}, fmt.Errorf("inspect host user namespace: %w", err)
	}
	return workerIsolationConfig{HostMountNamespace: mountNamespace, HostUserNamespace: userNamespace}, nil
}

func prepareWorkerIsolation(config workerIsolationConfig) error {
	// Linux capabilities are per-thread. Keep namespace setup on the initial
	// worker thread before any background goroutine is started.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if config.HostMountNamespace == "" || config.HostUserNamespace == "" {
		return fmt.Errorf("VM worker requires host mount and user namespace identities")
	}
	mountNamespace, err := namespaceIdentity("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("inspect VM worker mount namespace: %w", err)
	}
	if mountNamespace == config.HostMountNamespace {
		return fmt.Errorf("VM worker did not enter a private mount namespace")
	}
	userNamespace, err := namespaceIdentity("/proc/self/ns/user")
	if err != nil {
		return fmt.Errorf("inspect VM worker user namespace: %w", err)
	}
	if userNamespace == config.HostUserNamespace {
		return fmt.Errorf("VM worker did not enter a private user namespace")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("VM worker must run as namespace root with a mapped host identity")
	}
	private, err := mountNamespaceIsPrivate()
	if err != nil {
		return fmt.Errorf("inspect VM worker mount propagation: %w", err)
	}
	if !private {
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			return fmt.Errorf("make VM worker mount propagation private: %w", err)
		}
		private, err = mountNamespaceIsPrivate()
		if err != nil {
			return fmt.Errorf("verify VM worker mount propagation: %w", err)
		}
		if !private {
			return fmt.Errorf("VM worker mount namespace still has shared or slave mounts")
		}
	}
	return nil
}

func mountNamespaceIsPrivate() (bool, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	defer file.Close()
	return mountInfoIsPrivate(file)
}

func mountInfoIsPrivate(info *os.File) (bool, error) {
	scanner := bufio.NewScanner(info)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 0 || separator < 6 {
			return false, fmt.Errorf("invalid /proc/self/mountinfo entry")
		}
		for _, optional := range fields[6:separator] {
			if strings.HasPrefix(optional, "shared:") || strings.HasPrefix(optional, "master:") || strings.HasPrefix(optional, "propagate_from:") {
				return false, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return true, nil
}

func verifyWorkerCodeSignature(string, string) error {
	return fmt.Errorf("Apple code signature verification is unavailable on Linux")
}

func verifyWorkerAdHocSignature(string) error {
	return fmt.Errorf("Apple ad-hoc code signature verification is unavailable on Linux")
}

func namespaceIdentity(path string) (string, error) {
	identity, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(identity, "mnt:[") && !strings.HasPrefix(identity, "user:[") {
		return "", fmt.Errorf("unexpected namespace identity %q", identity)
	}
	return identity, nil
}
