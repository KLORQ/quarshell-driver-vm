//go:build !darwin && !linux

package vm

import "context"

// Windows cannot launch the Unix socket policy broker or libkrun worker.
// Keep the lifecycle's optional forwarder hook available for cross-builds;
// startup fails earlier in the platform-specific broker preflight.
func forwardSupervisorControl(context.Context, string, string) {}

func forwardNetworkProxy(context.Context, string, string) {}
