//go:build darwin || linux

package vm

import (
	"archive/tar"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestCreateBuildsAndPersistsSandboxArtifacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test formatter requires a POSIX shell")
	}
	root := t.TempDir()
	staging := filepath.Join(root, "uploads")
	requestDir := filepath.Join(staging, "request-1")
	if err := os.MkdirAll(requestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(requestDir, "rootfs.tar")
	archive, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(archive)
	if err := tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0o644, Size: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("test\n")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	formatter := filepath.Join(root, "formatter")
	if err := os.WriteFile(formatter, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	guestAgent := filepath.Join(root, "guest-agent")
	if err := os.WriteFile(guestAgent, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "state")
	d := NewWithHostConfig(HostConfig{
		StateDir: stateDir, RootfsTarDir: staging, RootfsTarMaxBytes: 1 << 20,
		FormatterPath: formatter, OverlaySizeBytes: 64 << 20, GuestAgentPath: guestAgent,
		DefaultImage: "registry.example/team/default-sandbox:stable",
	})
	handle, err := d.createSandbox(context.Background(), vmCreateSpec{
		Name:             "sandbox-one",
		Image:            "registry.example/team/requested-sandbox:stable",
		DriverConfigJSON: `{"rootfs_tar_path":"` + archivePath + `"}`,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !validSandboxID(string(handle.ID)) || handle.Name != "sandbox-one" || handle.Image != "registry.example/team/requested-sandbox:stable" {
		t.Fatalf("Create() handle = %+v", handle)
	}
	state, err := openStateStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := state.load(string(handle.ID))
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Rootfs == "" {
		t.Fatal("persisted state has no rootfs image")
	}
	if persisted.Image != "registry.example/team/requested-sandbox:stable" {
		t.Fatalf("persisted image = %q, want requested image identity", persisted.Image)
	}
	if persisted.RootfsSourceType != "tar" || !strings.HasPrefix(persisted.RootfsSourceDigest, "sha256:") || persisted.Platform != "linux/"+runtime.GOARCH {
		t.Fatalf("persisted rootfs provenance = type %q digest %q platform %q", persisted.RootfsSourceType, persisted.RootfsSourceDigest, persisted.Platform)
	}
	for _, path := range []string{persisted.Rootfs, filepath.Join(stateDir, "sandboxes", persisted.ID, "overlay.ext4")} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Fatalf("expected regular non-empty artifact at %q, stat=%v err=%v", path, info, err)
		}
	}
	rows, err := d.List(context.Background())
	if err != nil || len(rows) != 1 || rows[0].ID != handle.ID || rows[0].Status != "created" {
		t.Fatalf("List() = (%+v, %v), want one created sandbox", rows, err)
	}
	byName, err := d.Inspect(context.Background(), handle.Name)
	if err != nil || byName.ID != handle.ID {
		t.Fatalf("Inspect(name) = (%+v, %v)", byName, err)
	}
	byID, err := d.Inspect(context.Background(), string(handle.ID))
	if err != nil || byID.Name != handle.Name {
		t.Fatalf("Inspect(id) = (%+v, %v)", byID, err)
	}
	if err := d.Delete(context.Background(), handle.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "sandboxes", string(handle.ID))); !os.IsNotExist(err) {
		t.Fatalf("sandbox assets remain after delete, stat error = %v", err)
	}
	if err := d.Delete(context.Background(), handle.ID); err != nil {
		t.Fatalf("idempotent Delete() error = %v", err)
	}
}

func testGuestELF() []byte {
	header := make([]byte, 64)
	copy(header[:4], []byte{0x7f, 'E', 'L', 'F'})
	header[4], header[5], header[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(header[16:18], 3)
	machine := uint16(62)
	if runtime.GOARCH == "arm64" {
		machine = 183
	}
	binary.LittleEndian.PutUint16(header[18:20], machine)
	binary.LittleEndian.PutUint32(header[20:24], 1)
	return header
}

func TestCreateUsesDefaultImageAndRejectsInvalidSpec(t *testing.T) {
	d := NewWithHostConfig(HostConfig{StateDir: filepath.Join(t.TempDir(), "state")})
	if _, err := d.createSandbox(context.Background(), vmCreateSpec{Name: "default-image"}); err == nil || !strings.Contains(err.Error(), "CAUTEM_VM_GUEST_AGENT") {
		t.Fatalf("Create() did not resolve default image before host runtime validation: %v", err)
	}
	if _, err := d.createSandbox(context.Background(), vmCreateSpec{Name: "../escape"}); err == nil {
		t.Fatal("Create() accepted path-like sandbox name")
	}
}

func TestCreateWithBootstrapImagePersistsSeparatePinnedDisks(t *testing.T) {
	registry := newTestOCIRegistry(t)
	platform := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	registry.publishImageIndexWithConfig(t, []testOCILayerBlob{testOCILayer(t, []rootfsTarEntry{
		{name: "etc", kind: tar.TypeDir, mode: 0o755},
		{name: "etc/os-release", kind: tar.TypeReg, body: "NAME=fixture\n"},
	})}, platform, v1.Config{WorkingDir: "/"})
	imageRef := strings.TrimPrefix(registry.server.URL, "http://") + "/agent:latest"
	root := t.TempDir()
	guestAgent := filepath.Join(root, "guest-agent")
	if err := os.WriteFile(guestAgent, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	umoci := filepath.Join(root, "umoci")
	if err := os.WriteFile(umoci, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	formatter := filepath.Join(root, "mke2fs")
	if err := os.WriteFile(formatter, []byte("#!/bin/sh\nfor last do :; done\nprintf ext4 | dd of=\"$last\" conv=notrunc 2>/dev/null\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "state")
	var extensionCalls []string
	extension := &recordingLifecycleExtension{name: "recording", calls: &extensionCalls, configure: func(plan *ExtensionLaunchPlan) error {
		plan.Environment = append(plan.Environment, "EXTENSION_RUNTIME_VALUE=ephemeral")
		return nil
	}}
	d := NewWithHostConfig(HostConfig{
		StateDir: stateDir, BootstrapImage: imageRef, DefaultImage: imageRef,
		GuestAgentPath: guestAgent, UMOCIPath: umoci, FormatterPath: formatter,
		LifecycleExtensions:      []LifecycleExtension{extension},
		RootfsImageCacheMaxBytes: defaultRootfsImageCacheMaxBytes, OverlaySizeBytes: 64 << 20,
		imagePrepRunner:   func(context.Context, HostConfig, string, string, string) error { return nil },
		imagePrepVerifier: func(string, string) error { return nil },
	})
	d.ociNameOptions = []name.Option{name.Insecure}
	const workloadSecret = "vm-state-must-not-contain-this-workload-token"
	handle, err := d.createSandbox(context.Background(), vmCreateSpec{
		Name: "two-disk", Image: imageRef,
		Env: []string{"WORKLOAD_TOKEN=" + workloadSecret, "HTTPS_PROXY=https://proxy-user:" + workloadSecret + "@proxy.example"},
	})
	if err != nil {
		t.Fatalf("Create() with bootstrap image error = %v", err)
	}
	store, err := openStateStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.load(string(handle.ID))
	if err != nil {
		t.Fatal(err)
	}
	if state.Rootfs == "" || state.WorkloadDisk == "" || state.Rootfs == state.WorkloadDisk {
		t.Fatalf("two-disk image paths = root %q workload %q", state.Rootfs, state.WorkloadDisk)
	}
	if state.RootfsSourceType != "oci" || state.WorkloadSourceType != "oci" || state.RootfsSourceDigest == "" || state.WorkloadSourceDigest == "" {
		t.Fatalf("two-disk image provenance incomplete: %+v", state)
	}
	if !reflect.DeepEqual(state.LifecycleExtensions, []string{"recording"}) {
		t.Fatalf("durable lifecycle extensions = %v", state.LifecycleExtensions)
	}
	if !containsString(d.launchSpecs[string(handle.ID)].Env, "EXTENSION_RUNTIME_VALUE=ephemeral") {
		t.Fatalf("extension environment was not passed to the in-memory launch spec: %v", d.launchSpecs[string(handle.ID)].Env)
	}
	if !reflect.DeepEqual(extensionCalls, []string{"recording:configure"}) {
		t.Fatalf("extension configure calls = %v", extensionCalls)
	}
	stateJSON, err := os.ReadFile(filepath.Join(stateDir, string(handle.ID)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateJSON), workloadSecret) || strings.Contains(string(stateJSON), "WORKLOAD_TOKEN") || strings.Contains(string(stateJSON), "HTTPS_PROXY") || strings.Contains(string(stateJSON), "EXTENSION_RUNTIME_VALUE") {
		t.Fatalf("durable VM state contains workload or proxy environment: %s", stateJSON)
	}
	var durableFields map[string]json.RawMessage
	if err := json.Unmarshal(stateJSON, &durableFields); err != nil {
		t.Fatalf("decode durable VM state: %v", err)
	}
	for _, forbidden := range []string{"environment", "env", "proxy_env", "credentials", "token"} {
		if _, ok := durableFields[forbidden]; ok {
			t.Errorf("durable VM state unexpectedly stores %q", forbidden)
		}
	}
}

func TestCreateUsesTrustedDefaultImageAsBootstrapWhenUnset(t *testing.T) {
	registry := newTestOCIRegistry(t)
	platform := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	registry.publishImageIndexWithConfig(t, []testOCILayerBlob{testOCILayer(t, []rootfsTarEntry{
		{name: "etc", kind: tar.TypeDir, mode: 0o755},
		{name: "etc/os-release", kind: tar.TypeReg, body: "NAME=trusted-default\n"},
	})}, platform, v1.Config{WorkingDir: "/"})
	imageRef := strings.TrimPrefix(registry.server.URL, "http://") + "/agent:latest"
	t.Setenv("OPENSHELL_SANDBOX_IMAGE", imageRef)
	t.Setenv("OPENSHELL_VM_BOOTSTRAP_IMAGE", "")

	root := t.TempDir()
	guestAgent := filepath.Join(root, "guest-agent")
	if err := os.WriteFile(guestAgent, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	umoci := filepath.Join(root, "umoci")
	if err := os.WriteFile(umoci, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	formatter := filepath.Join(root, "mke2fs")
	if err := os.WriteFile(formatter, []byte("#!/bin/sh\nfor last do :; done\nprintf '\\123\\357' | dd of=\"$last\" bs=1 seek=1080 conv=notrunc 2>/dev/null\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	host := DefaultHostConfig()
	host.StateDir = filepath.Join(root, "state")
	host.GuestAgentPath = guestAgent
	host.UMOCIPath = umoci
	host.FormatterPath = formatter
	host.OverlaySizeBytes = 64 << 20
	host.ServiceDataDiskSizeBytes = 64 << 20
	host.imagePrepRunner = func(context.Context, HostConfig, string, string, string) error { return nil }
	host.imagePrepVerifier = func(string, string) error { return nil }
	d := NewWithHostConfig(host)
	d.ociNameOptions = []name.Option{name.Insecure}
	handle, err := d.createSandbox(context.Background(), vmCreateSpec{Name: "trusted-default-bootstrap", Image: imageRef})
	if err != nil {
		t.Fatalf("Create() with trusted default bootstrap image error = %v", err)
	}
	store, err := openStateStore(host.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.load(string(handle.ID))
	if err != nil {
		t.Fatal(err)
	}
	if state.Rootfs == "" || state.WorkloadDisk == "" || state.Rootfs == state.WorkloadDisk {
		t.Fatalf("default bootstrap did not persist two separate disks: root=%q workload=%q", state.Rootfs, state.WorkloadDisk)
	}
	if state.RootfsSourceDigest == "" || state.WorkloadSourceDigest == "" {
		t.Fatalf("default bootstrap and workload digests were not persisted: %+v", state)
	}
	serviceDisk := filepath.Join(host.StateDir, "sandboxes", string(handle.ID), "service-data.ext4")
	serviceInfo, err := os.Lstat(serviceDisk)
	if err != nil || state.ServiceDataDisk != serviceDisk || !serviceInfo.Mode().IsRegular() || serviceInfo.Mode().Perm() != 0o600 || serviceInfo.Size() != 64<<20 {
		t.Fatalf("service data disk state=%q info=%v err=%v", state.ServiceDataDisk, serviceInfo, err)
	}
	if err := validateSandboxArtifacts(host.StateDir, state, filepath.Join(host.StateDir, "sandboxes", string(handle.ID), "overlay.ext4")); err != nil {
		t.Fatalf("validate sandbox service data disk: %v", err)
	}
}

func TestCreateAdmissionWaitHonorsContextCancellation(t *testing.T) {
	d := NewWithHostConfig(HostConfig{StateDir: filepath.Join(t.TempDir(), "state")})
	gate := d.createAdmissionGate()
	gate <- struct{}{}
	defer func() { <-gate }()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := d.createSandbox(ctx, vmCreateSpec{Name: "cancelled-while-queued"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Create() error = %v; want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Create() remained queued for %s after context deadline", elapsed)
	}
}

func TestCreateDoesNotHoldLifecycleLockDuringImagePreparation(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "uploads")
	requestDir := filepath.Join(staging, "request")
	if err := os.MkdirAll(requestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(requestDir, "rootfs.tar")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{{name: "etc/os-release", kind: tar.TypeReg, body: "test\n"}}); err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(root, "formatter-started")
	formatter := filepath.Join(root, "formatter")
	script := "#!/bin/sh\nfor last do :; done\nprintf started > '" + started + "'\nsleep 10\nprintf ext4 > \"$last\"\n"
	if err := os.WriteFile(formatter, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	guestAgent := filepath.Join(root, "guest-agent")
	if err := os.WriteFile(guestAgent, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	d := NewWithHostConfig(HostConfig{
		StateDir: filepath.Join(root, "state"), RootfsTarDir: staging, RootfsTarMaxBytes: 1 << 20,
		FormatterPath: formatter, OverlaySizeBytes: 64 << 20, GuestAgentPath: guestAgent,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	created := make(chan error, 1)
	go func() {
		_, err := d.createSandbox(ctx, vmCreateSpec{Name: "preparing", DriverConfigJSON: `{"rootfs_tar_path":"` + archivePath + `"}`})
		created <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatalf("inspect formatter marker: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("formatter did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	listed := make(chan error, 1)
	go func() {
		_, err := d.List(context.Background())
		listed <- err
	}()
	select {
	case err := <-listed:
		if err != nil {
			t.Fatalf("List() during preparation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("List() blocked behind rootfs preparation")
	}
	cancel()
	select {
	case err := <-created:
		if err == nil {
			t.Fatal("Create() unexpectedly succeeded after cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Create() did not stop after cancellation")
	}
}

func TestDeleteReconcilesDeadWorkerAndExecReportsMissingGuest(t *testing.T) {
	root := t.TempDir()
	store, err := openStateStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.create("running-vm", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	assets := filepath.Join(store.root, "sandboxes", state.ID)
	if err := os.MkdirAll(assets, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := createControlToken(assets); err != nil {
		t.Fatal(err)
	}
	state.Status = "running"
	if err := store.save(state); err != nil {
		t.Fatal(err)
	}
	d := NewWithHostConfig(HostConfig{StateDir: store.root})
	if _, err := d.Exec(context.Background(), core.ID(state.ID), driver.ExecRequest{Argv: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "connect VM guest control socket") {
		t.Fatalf("Exec() missing worker error = %v", err)
	}
	if err := d.Delete(context.Background(), core.ID(state.ID)); err != nil {
		t.Fatalf("Delete() did not reconcile dead worker: %v", err)
	}
}
