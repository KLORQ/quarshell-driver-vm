//go:build linux

package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyOCILayerPreservesUnixSpecialPermissionBits(t *testing.T) {
	layer := testOCILayer(t, []rootfsTarEntry{
		{name: "bin", kind: '5', mode: 0o755},
		{name: "bin/setuid-tool", kind: '0', mode: 0o4755, body: "#!/bin/sh\nexit 0\n"},
		{name: "tmp", kind: '5', mode: 0o1777},
	})
	base := t.TempDir()
	blobPath := filepath.Join(base, "layer.tar.gz")
	if err := os.WriteFile(blobPath, layer.compressed, 0o600); err != nil {
		t.Fatal(err)
	}
	layerDir := filepath.Join(base, "layer")
	_, diffID, explicitDirectories, err := extractOCICompressedLayer(context.Background(), blobPath, string(layer.descriptor.MediaType), layerDir, 1<<20)
	if err != nil || diffID != layer.diffID {
		t.Fatalf("extract layer diffID=%v err=%v; want %v", diffID, err, layer.diffID)
	}
	rootfs := filepath.Join(base, "rootfs")
	if err := os.Mkdir(rootfs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := applyOCILayer(layerDir, rootfs, explicitDirectories); err != nil {
		t.Fatal(err)
	}
	setuidInfo, err := os.Stat(filepath.Join(rootfs, "bin/setuid-tool"))
	if err != nil {
		t.Fatal(err)
	}
	if setuidInfo.Mode().Perm() != 0o755 || setuidInfo.Mode()&os.ModeSetuid == 0 {
		t.Fatalf("setuid executable mode = %v; want 04755", setuidInfo.Mode())
	}
	stickyInfo, err := os.Stat(filepath.Join(rootfs, "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if stickyInfo.Mode().Perm() != 0o777 || stickyInfo.Mode()&os.ModeSticky == 0 {
		t.Fatalf("sticky directory mode = %v; want 01777", stickyInfo.Mode())
	}
}

func TestExtractOCILayerDefersReadOnlyDirectoryModesUntilApply(t *testing.T) {
	layer := testOCILayer(t, []rootfsTarEntry{
		{name: "etc", kind: '5', mode: 0o555},
		{name: "etc/ca-bundle.pem", kind: '0', mode: 0o444, body: "certificate\n"},
		{name: "etc/ca-bundle-link.pem", kind: '2', mode: 0o777, link: "ca-bundle.pem"},
		{name: "etc/gshadow", kind: '0', mode: 0o001, body: "root:!::\n"},
	})
	base := t.TempDir()
	blobPath := filepath.Join(base, "layer.tar.gz")
	if err := os.WriteFile(blobPath, layer.compressed, 0o600); err != nil {
		t.Fatal(err)
	}
	layerDir := filepath.Join(base, "layer")
	_, diffID, directoryModes, err := extractOCICompressedLayer(context.Background(), blobPath, string(layer.descriptor.MediaType), layerDir, 1<<20)
	if err != nil || diffID != layer.diffID {
		t.Fatalf("extract read-only-directory layer diffID=%v err=%v; want %v", diffID, err, layer.diffID)
	}
	info, err := os.Stat(filepath.Join(layerDir, "etc"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got&0o300 != 0o300 {
		t.Fatalf("staging directory mode = %#o, want writable owner bits", got)
	}
	if target, err := os.Readlink(filepath.Join(layerDir, "etc/ca-bundle-link.pem")); err != nil || target != "ca-bundle.pem" {
		t.Fatalf("read-only directory symlink target = %q, err=%v", target, err)
	}
	stagedFileInfo, err := os.Stat(filepath.Join(layerDir, "etc/gshadow"))
	if err != nil {
		t.Fatal(err)
	}
	if stagedFileInfo.Mode().Perm()&0o400 == 0 {
		t.Fatalf("staged restrictive file mode = %#o, want owner-readable", stagedFileInfo.Mode().Perm())
	}
	rootfs := filepath.Join(base, "rootfs")
	if err := os.Mkdir(rootfs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := applyOCILayer(layerDir, rootfs, directoryModes); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filepath.Join(rootfs, "etc"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o555 {
		t.Fatalf("applied directory mode = %#o, want %#o", got, 0o555)
	}
	info, err = os.Stat(filepath.Join(rootfs, "etc/gshadow"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o001 {
		t.Fatalf("applied restrictive file mode = %#o, want %#o", got, 0o001)
	}
	defer func() { _ = os.Chmod(filepath.Join(rootfs, "etc/gshadow"), 0o600) }()
	defer func() { _ = os.Chmod(filepath.Join(rootfs, "etc"), 0o700) }()
}

func TestApplyOCILayerCanWriteBeneathReadOnlyDirectoryFromEarlierLayer(t *testing.T) {
	base := t.TempDir()
	rootfs := filepath.Join(base, "rootfs")
	if err := os.Mkdir(rootfs, 0o700); err != nil {
		t.Fatal(err)
	}
	apply := func(name string, layer testOCILayerBlob) {
		t.Helper()
		blobPath := filepath.Join(base, name+".tar.gz")
		if err := os.WriteFile(blobPath, layer.compressed, 0o600); err != nil {
			t.Fatal(err)
		}
		layerDir := filepath.Join(base, name)
		_, diffID, explicitDirectories, err := extractOCICompressedLayer(context.Background(), blobPath, string(layer.descriptor.MediaType), layerDir, 1<<20)
		if err != nil || diffID != layer.diffID {
			t.Fatalf("extract layer %s diffID=%v err=%v; want %v", name, diffID, err, layer.diffID)
		}
		if err := applyOCILayer(layerDir, rootfs, explicitDirectories); err != nil {
			t.Fatalf("apply layer %s: %v", name, err)
		}
	}
	apply("base", testOCILayer(t, []rootfsTarEntry{{name: "etc", kind: '5', mode: 0o555}}))
	apply("update", testOCILayer(t, []rootfsTarEntry{{name: "etc/gshadow", kind: '0', mode: 0o400, body: "root:!::\n"}}))
	data, err := os.ReadFile(filepath.Join(rootfs, "etc/gshadow"))
	if err != nil || string(data) != "root:!::\n" {
		t.Fatalf("layered gshadow = %q err=%v", data, err)
	}
	info, err := os.Stat(filepath.Join(rootfs, "etc"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o555 {
		t.Fatalf("merged directory mode = %#o, want %#o", got, 0o555)
	}
	defer func() { _ = os.Chmod(filepath.Join(rootfs, "etc"), 0o700) }()
}
