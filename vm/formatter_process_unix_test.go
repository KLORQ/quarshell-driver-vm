//go:build darwin || linux

package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunFormatterCommandCancellationStopsChildProcesses(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "child-survived")
	formatter := filepath.Join(dir, "formatter")
	script := "#!/bin/sh\n(sleep 0.4; echo leaked > '" + marker + "') &\nwait\n"
	if err := os.WriteFile(formatter, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := runFormatterCommand(ctx, formatter)
	if err == nil {
		t.Fatal("runFormatterCommand() unexpectedly succeeded")
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("context error = %v, want deadline exceeded", ctx.Err())
	}

	time.Sleep(600 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("formatter child survived cancellation; marker stat error = %v", err)
	}
}
