//go:build darwin || linux

package vm

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type fakeLocalImageEngine struct {
	metadata localImageMetadata
	archive  []byte
	err      error
}

func (engine *fakeLocalImageEngine) InspectImage(context.Context, string) (localImageMetadata, error) {
	if engine.err != nil {
		return localImageMetadata{}, engine.err
	}
	return engine.metadata, nil
}

func (engine *fakeLocalImageEngine) SaveImage(_ context.Context, _ string, _ v1.Platform, writer io.Writer) error {
	_, err := io.Copy(writer, bytes.NewReader(engine.archive))
	return err
}

func TestExtractLocalOCILayoutArchiveRejectsUnsafeEntries(t *testing.T) {
	for _, entry := range []struct {
		name     string
		typeflag byte
	}{
		{name: "../escape", typeflag: tar.TypeReg},
		{name: "blobs/link", typeflag: tar.TypeSymlink},
	} {
		t.Run(entry.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "layout.tar")
			file, err := os.Create(archivePath)
			if err != nil {
				t.Fatal(err)
			}
			writer := tar.NewWriter(file)
			if err := writer.WriteHeader(&tar.Header{Name: entry.name, Typeflag: entry.typeflag, Linkname: "../../outside", Mode: 0o600, Size: 1}); err != nil {
				t.Fatal(err)
			}
			if entry.typeflag == tar.TypeReg {
				if _, err := writer.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := extractLocalOCILayoutArchive(archivePath); err == nil {
				t.Fatalf("accepted unsafe OCI archive entry %q", entry.name)
			}
		})
	}
}

func TestPrepareLocalOCIImageImportsPinnedDockerArchiveAndRestoresConfig(t *testing.T) {
	root := t.TempDir()
	layerBlob := testOCILayer(t, []rootfsTarEntry{
		{name: "etc", kind: tar.TypeDir, mode: 0o755},
		{name: "etc/os-release", kind: tar.TypeReg, mode: 0o644, body: "ID=local-image\n"},
	})
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerBlob.compressed)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	image, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	config := v1.ConfigFile{
		Architecture: runtime.GOARCH,
		OS:           "linux",
		RootFS:       v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{layerBlob.diffID}},
		Config: v1.Config{
			Entrypoint: []string{"/opt/local-entry"}, Cmd: []string{"run"},
			Env: []string{"LOCAL_IMAGE_VALUE=expected"}, User: "1000:1000", WorkingDir: "/workspace/local",
		},
	}
	image, err = mutate.ConfigFile(image, &config)
	if err != nil {
		t.Fatal(err)
	}
	wrongDiffConfig := config
	wrongDiffConfig.RootFS = v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{sha256Hash([]byte("different layer"))}}
	wrongDiffImage, err := mutate.ConfigFile(image, &wrongDiffConfig)
	if err != nil {
		t.Fatal(err)
	}
	wrongRootfs := filepath.Join(root, "wrong-diff-rootfs")
	if err := os.Mkdir(wrongRootfs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := populateRootfsFromOCI(context.Background(), wrongDiffImage, "local-mismatch", v1.Platform{OS: "linux", Architecture: runtime.GOARCH}, wrongRootfs); err == nil || !strings.Contains(err.Error(), "diff ID") {
		t.Fatalf("OCI layer with mismatched DiffID error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(wrongRootfs, "etc", "os-release")); !os.IsNotExist(err) {
		t.Fatalf("layer was applied before DiffID verification: %v", err)
	}
	archiveConfigID, err := image.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	engineID := "sha256:" + strings.Repeat("c", 64)
	if archiveConfigID.String() == engineID {
		t.Fatal("fixture should distinguish Docker Engine ID from docker-save config digest")
	}
	archivePath := filepath.Join(root, "docker-save.tar")
	if err := tarball.WriteToFile(archivePath, nil, image); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	formatter := filepath.Join(root, "mke2fs")
	if err := os.WriteFile(formatter, []byte("#!/bin/sh\nfor last do :; done\nprintf ext4 >> \"$last\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	engine := &fakeLocalImageEngine{
		metadata: localImageMetadata{ID: engineID, OS: "linux", Architecture: runtime.GOARCH, Config: config.Config},
		archive:  archive,
	}
	prepared, resolved, found, err := prepareLocalOCIImage(context.Background(), "openshell/sandbox-from:unit", filepath.Join(root, "cache"), formatter, "", 1<<30, []localImageEngine{engine})
	if err != nil || !found {
		t.Fatalf("prepare local image = (found=%t, err=%v)", found, err)
	}
	defer prepared.Lease.Release()
	defer os.Remove(resolved.LocalArchivePath)
	if info, err := os.Stat(resolved.LocalArchivePath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("local OCI export was not retained for guest prep: info=%v err=%v", info, err)
	}
	if resolved.LocalEngineImageID != engineID || resolved.Platform.String() != "linux/"+runtime.GOARCH {
		t.Fatalf("local image provenance = %+v", resolved)
	}
	if resolved.ImageConfig.User != "1000:1000" || resolved.ImageConfig.WorkingDir != "/workspace/local" || len(resolved.ImageConfig.Env) != 1 {
		t.Fatalf("local image config = %+v", resolved.ImageConfig)
	}
	guestAgent := filepath.Join(root, "guest-agent")
	umoci := filepath.Join(root, "umoci")
	for _, path := range []string{guestAgent, umoci} {
		if err := os.WriteFile(path, testGuestELF(), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bootstrap := filepath.Join(root, "bootstrap.ext4")
	if err := os.WriteFile(bootstrap, []byte("bootstrap"), 0o400); err != nil {
		t.Fatal(err)
	}
	prepFormatter := filepath.Join(root, "prep-mke2fs")
	if err := os.WriteFile(prepFormatter, []byte("#!/bin/sh\nfor last do :; done\nprintf ext4 | dd of=\"$last\" conv=notrunc 2>/dev/null\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	stagedLayout := false
	prepHost := HostConfig{
		VCPUs: 1, MemoryMiB: 128,
		imagePrepRunner: func(_ context.Context, _ HostConfig, _ string, _ string, runDir string) error {
			_, err := os.Stat(filepath.Join(runDir, "overlay", "config", guestImagePayloadDir, "oci", "index.json"))
			stagedLayout = err == nil
			return err
		},
		imagePrepVerifier: func(string, string) error { return nil },
	}
	guestPrepared, err := prepareOCIWorkloadDiskInGuest(context.Background(), resolved, filepath.Join(root, "guest-cache"), prepFormatter, guestAgent, umoci, bootstrap, prepHost, defaultRootfsImageCacheMaxBytes)
	if err != nil {
		t.Fatalf("prepare local OCI image in guest: %v", err)
	}
	defer guestPrepared.Lease.Release()
	if !stagedLayout {
		t.Fatal("local Docker export was unavailable while staging its guest OCI layout")
	}
	rootfs, err := os.Open(prepared.Path)
	if err != nil {
		t.Fatal(err)
	}
	rootfsInfo, err := rootfs.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rootfs.Seek(rootfsInfo.Size()-4, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	tail := make([]byte, 4)
	if _, err := io.ReadFull(rootfs, tail); err != nil || string(tail) != "ext4" {
		t.Fatalf("prepared local rootfs tail = %q, err=%v", tail, err)
	}
	_ = rootfs.Close()

	engine.metadata.Config = config.Config
	restoredConfig, err := resolveLocalOCIImageConfig(context.Background(), "openshell/sandbox-from:unit", engineID, v1.Platform{OS: "linux", Architecture: runtime.GOARCH}, []localImageEngine{engine})
	if err != nil || restoredConfig.WorkingDir != "/workspace/local" || restoredConfig.User != "1000:1000" {
		t.Fatalf("restore local image config = %+v, %v", restoredConfig, err)
	}
	engine.metadata.ID = "sha256:" + strings.Repeat("0", 64)
	if _, err := resolveLocalOCIImageConfig(context.Background(), "openshell/sandbox-from:unit", engineID, v1.Platform{OS: "linux", Architecture: runtime.GOARCH}, []localImageEngine{engine}); err == nil {
		t.Fatal("recovery accepted a moved local image tag")
	}
	engine.metadata.ID = engineID
	guestAgentPath := filepath.Join(root, "guest-agent")
	if err := os.WriteFile(guestAgentPath, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	driverHost := NewWithHostConfig(HostConfig{
		StateDir: filepath.Join(root, "driver-state"), FormatterPath: formatter,
		OverlaySizeBytes: 64 << 20, GuestAgentPath: guestAgentPath,
	})
	driverHost.localImageEngines = []localImageEngine{engine}
	handle, err := driverHost.createSandbox(context.Background(), vmCreateSpec{Name: "local-image", Image: "openshell/sandbox-from:unit"})
	if err != nil {
		t.Fatalf("Create() from local OCI image: %v", err)
	}
	stateStore, err := openStateStore(filepath.Join(root, "driver-state"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := stateStore.load(string(handle.ID))
	if err != nil {
		t.Fatal(err)
	}
	if state.RootfsSourceType != "local-oci" || state.RootfsSourceDigest != engineID || state.RootfsSourceManifestDigest != engineID {
		t.Fatalf("Create() local image provenance = %+v", state)
	}
	if err := driverHost.restoreLaunchSpec(context.Background(), handle.ID, vmCreateSpec{Name: handle.Name, Image: handle.Image}); err != nil {
		t.Fatalf("restore local OCI launch config: %v", err)
	}
	if err := driverHost.Delete(context.Background(), handle.ID); err != nil {
		t.Fatalf("delete local OCI sandbox: %v", err)
	}
}

func TestLocalOCIImageFallbackAndRequiredLocalReference(t *testing.T) {
	missing := &fakeLocalImageEngine{err: errdefs.ErrNotFound}
	_, _, found, err := prepareLocalOCIImage(context.Background(), "alpine:3.22", t.TempDir(), "", "", 1<<30, []localImageEngine{missing})
	if err != nil || found {
		t.Fatalf("missing ordinary local image = (found=%t, err=%v); want registry fallback", found, err)
	}
	_, _, found, err = prepareLocalOCIImage(context.Background(), "openshell/sandbox-from:missing", t.TempDir(), "", "", 1<<30, []localImageEngine{missing})
	if err == nil || found || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("missing required local image = (found=%t, err=%v)", found, err)
	}
}

var _ localImageEngine = (*fakeLocalImageEngine)(nil)
