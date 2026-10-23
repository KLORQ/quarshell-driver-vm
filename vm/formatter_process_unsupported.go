//go:build !darwin && !linux

package vm

import (
	"context"
	"os/exec"
)

func runFormatterCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, path, args...).CombinedOutput()
}
