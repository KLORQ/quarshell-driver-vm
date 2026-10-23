package vm

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestValidateVMPolicyWorkloadIdentity(t *testing.T) {
	for _, test := range []struct {
		name    string
		user    string
		group   string
		wantErr string
	}{
		{name: "omitted selectors"},
		{name: "driver account", user: "sandbox", group: "sandbox"},
		{name: "matching numeric identity", user: "1000", group: "1001"},
		{name: "mismatched uid", user: "10000", group: "1001", wantErr: "run_as_user"},
		{name: "mismatched gid", user: "1000", group: "10000", wantErr: "run_as_group"},
		{name: "unresolved account name", user: "nobody", group: "1001", wantErr: "run_as_user"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			contents := "version: 1\n"
			if test.user != "" || test.group != "" {
				contents += "process:\n"
				if test.user != "" {
					contents += "  run_as_user: " + strconv.Quote(test.user) + "\n"
				}
				if test.group != "" {
					contents += "  run_as_group: " + strconv.Quote(test.group) + "\n"
				}
			}
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			err := validateVMPolicyWorkloadIdentity(path, 1000, 1001)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("identity validation error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("identity validation error = %v, want %q", err, test.wantErr)
			}
		})
	}
}
