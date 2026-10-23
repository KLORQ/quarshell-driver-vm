//go:build darwin || linux

package vm

import (
	"strings"
	"testing"
)

func TestWorkerEnvironmentContainsOnlyTrustedRuntimePath(t *testing.T) {
	t.Setenv("DYLD_LIBRARY_PATH", "/attacker/dylibs")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/attacker/inject.dylib")
	t.Setenv("LD_PRELOAD", "/attacker/preload.so")
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("HOME", "/private/home")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "host-secret")
	env := workerEnvironment("/trusted/runtime")
	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{"/attacker/", "AWS_SECRET_ACCESS_KEY", "host-secret"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("worker environment contains inherited value %q: %q", forbidden, joined)
		}
	}
	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") || strings.HasPrefix(entry, "HOME=") {
			t.Fatalf("worker environment contains inherited process setting %q", entry)
		}
	}
	loaderPath := "LD_LIBRARY_PATH=/trusted/runtime"
	if testingName := "DYLD_LIBRARY_PATH=/trusted/runtime"; strings.Contains(joined, testingName) {
		loaderPath = testingName
	}
	if !strings.Contains(joined, loaderPath) {
		t.Fatalf("worker environment lacks trusted runtime path %q: %q", loaderPath, joined)
	}
}
