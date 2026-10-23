//go:build !darwin && !linux

package vm

import "fmt"

func runWorker(workerConfig) error {
	return fmt.Errorf("libkrun workers are unsupported on this platform")
}
