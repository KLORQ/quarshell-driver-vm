//go:build !darwin && !linux

package vm

import (
	"context"
	"fmt"
	"os/exec"
)

type networkBrokerProcess struct{}

func networkBrokerIsolationPID(*networkBrokerProcess) (int, error) {
	return 0, fmt.Errorf("VM policy network broker is unsupported on this platform")
}

func startNetworkBroker(*networkBrokerConfig) (*networkBrokerProcess, error) {
	return nil, fmt.Errorf("VM policy network broker is unsupported on this platform")
}

func stopNetworkBroker(*networkBrokerProcess) {}

func watchHostNetworkBroker(*networkBrokerProcess, *exec.Cmd) {}

func checkNetworkBrokerHealth(context.Context, string) error {
	return fmt.Errorf("VM policy network broker is unsupported on this platform")
}
