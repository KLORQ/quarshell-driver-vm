//go:build darwin || linux

package vm

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkerSocketPathsFitPortableUnixSocketLimit(t *testing.T) {
	workerSocketPath, guestSocketPath, consolePath := workerSocketPaths(filepath.Join(string(filepath.Separator), strings.Repeat("long-state-directory-", 8)), "12345678-1234-4234-8234-123456789abc")
	for name, path := range map[string]string{"worker": workerSocketPath, "guest": guestSocketPath} {
		if !filepath.IsAbs(path) || len(path) > 100 {
			t.Errorf("%s socket path length = %d, path %q; want absolute path <= 100 bytes", name, len(path), path)
		}
	}
	if !strings.Contains(consolePath, "long-state-directory-") {
		t.Fatalf("console path moved outside persistent state: %q", consolePath)
	}
}
