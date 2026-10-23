//go:build !darwin && !linux

package vm

import "os"

func workerEnvironment(_ string) []string { return os.Environ() }
