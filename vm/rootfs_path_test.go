//go:build darwin || linux

package vm

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-driver/driver"
)

func TestValidateRootfsTarPathAcceptsStagedArchive(t *testing.T) {
	staging := t.TempDir()
	requestDir := filepath.Join(staging, "request-123")
	if err := os.Mkdir(requestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(requestDir, "rootfs.tar")
	if err := os.WriteFile(archive, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := validateRootfsTarPath(archive, staging, 1024)
	if err != nil {
		t.Fatalf("validateRootfsTarPath() error = %v", err)
	}
	want, err := filepath.EvalSymlinks(archive)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("validated path = %q, want %q", got, want)
	}
}

func TestValidateRootfsTarPathRejectsOutsideAndWrongDepth(t *testing.T) {
	staging := t.TempDir()
	requestDir := filepath.Join(staging, "request")
	if err := os.Mkdir(requestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	valid := filepath.Join(requestDir, "rootfs.tar")
	if err := os.WriteFile(valid, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	nestedDir := filepath.Join(requestDir, "nested")
	if err := os.Mkdir(nestedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(nestedDir, "rootfs.tar")
	if err := os.WriteFile(nested, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(outside, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{outside, nested, staging} {
		if _, err := validateRootfsTarPath(path, staging, 1024); err == nil {
			t.Errorf("validateRootfsTarPath(%q) succeeded", path)
		}
	}
}

func TestValidateRootfsTarPathRejectsSymlinkEscape(t *testing.T) {
	staging := t.TempDir()
	requestDir := filepath.Join(staging, "request")
	if err := os.Mkdir(requestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(outside, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(requestDir, "rootfs.tar")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := validateRootfsTarPath(link, staging, 1024); err == nil || !strings.Contains(err.Error(), "without following staging symlinks") {
		t.Fatalf("validateRootfsTarPath() error = %v, want symlink rejection", err)
	}
}

func TestOpenRootfsTarRejectsSymlinkedRequestDirectory(t *testing.T) {
	staging := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "rootfs.tar"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(staging, "request")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openRootfsTar(filepath.Join(staging, "request", "rootfs.tar"), staging, 1024); err == nil {
		t.Fatal("openRootfsTar() followed a symlinked request directory")
	}
}

func TestOpenRootfsTarPinsValidatedFileAcrossReplacement(t *testing.T) {
	staging := t.TempDir()
	requestDir := filepath.Join(staging, "request")
	if err := os.Mkdir(requestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(requestDir, "rootfs.tar")
	if err := os.WriteFile(archive, []byte("validated archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(outside, []byte("outside replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	file, _, err := openRootfsTar(archive, staging, 1024)
	if err != nil {
		t.Fatalf("openRootfsTar() error = %v", err)
	}
	defer file.Close()
	if err := os.Rename(archive, archive+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, archive); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read pinned archive descriptor: %v", err)
	}
	if string(got) != "validated archive" {
		t.Fatalf("opened archive contents = %q, want original validated bytes", got)
	}
}

func TestValidateRootfsTarPathRejectsNonRegularAndOversized(t *testing.T) {
	staging := t.TempDir()
	requestDir := filepath.Join(staging, "request")
	if err := os.Mkdir(requestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(requestDir, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := validateRootfsTarPath(directory, staging, 1024); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory validation error = %v", err)
	}
	large := filepath.Join(requestDir, "large.tar")
	if err := os.WriteFile(large, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateRootfsTarPath(large, staging, 4); err == nil || !strings.Contains(err.Error(), "exceeding") {
		t.Fatalf("oversize validation error = %v", err)
	}
	if _, err := validateRootfsTarPath(large, staging, 0); err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Fatalf("zero limit error = %v", err)
	}
}

func TestVMDriverRootfsTarStagingCapability(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rootfs-tars")
	d := NewWithHostConfig(HostConfig{RootfsTarDir: root, RootfsTarMaxBytes: 128})
	gotPath, gotMax, err := d.RootfsTarStaging(context.Background())
	if err != nil {
		t.Fatalf("RootfsTarStaging() error = %v", err)
	}
	if gotPath != root || gotMax != 128 {
		t.Fatalf("RootfsTarStaging() = (%q, %d), want (%q, 128)", gotPath, gotMax, root)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("staging root mode = %#o, want 0700", info.Mode().Perm())
	}
	if _, ok := any(d).(driver.RuntimeRootfsTarStager); !ok {
		t.Fatal("VM driver does not implement RuntimeRootfsTarStager")
	}
}

func TestVMCreateRejectsRootfsTarOutsideStagingRoot(t *testing.T) {
	staging := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(outside, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := NewWithHostConfig(HostConfig{RootfsTarDir: staging})
	_, err := d.createSandbox(context.Background(), vmCreateSpec{
		Name:             "sandbox",
		DriverConfigJSON: `{"rootfs_tar_path":"` + outside + `"}`,
	})
	if err == nil || !strings.Contains(err.Error(), "outside staging directory") {
		t.Fatalf("Create() error = %v, want rootfs staging boundary rejection", err)
	}
}
