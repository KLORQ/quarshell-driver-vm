//go:build darwin || linux

package vm

import "syscall"

func killVMWorkerProcessGroupForAcceptance(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}
