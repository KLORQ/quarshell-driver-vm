//go:build darwin || linux

package vm

import (
	"runtime"
)

// workerEnvironment gives libkrun only the runtime bundle path. In particular,
// the worker must not inherit Gateway credentials, proxy variables, or loader
// overrides from the host process.
func workerEnvironment(runtimeDir string) []string {
	libraryPath := "LD_LIBRARY_PATH"
	if runtime.GOOS == "darwin" {
		libraryPath = "DYLD_LIBRARY_PATH"
	}
	return []string{libraryPath + "=" + runtimeDir}
}
