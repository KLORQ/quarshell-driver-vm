//go:build !darwin && !linux

package vm

import "os"

func killVMWorkerProcessGroupForAcceptance(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}
