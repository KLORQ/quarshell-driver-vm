//go:build !darwin && !linux

package vm

import (
	"fmt"
	"os"
	"os/exec"
)

func startParentLivenessWatch(uintptr) (func(), error) {
	return nil, fmt.Errorf("VM worker parent-liveness is unsupported on this host")
}

func startWorkerWithParentLiveness(*exec.Cmd) (*os.File, error) {
	return nil, fmt.Errorf("VM worker parent-liveness is unsupported on this host")
}
