//go:build darwin || linux

package vm

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// runFormatterCommand gives the formatter a private process group so canceling
// rootfs preparation also terminates helper processes it started.
func runFormatterCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// Some formatters invoke helpers that inherit the captured output pipe.
	// Bound Wait after cancellation even if a grandchild ignores the process
	// group signal, while the process-group kill below still stops normal trees.
	command.WaitDelay = 2 * time.Second
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	return command.CombinedOutput()
}
