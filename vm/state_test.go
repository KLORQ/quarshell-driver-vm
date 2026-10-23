//go:build darwin || linux

package vm

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStateStorePersistsListsAndDeletesSandboxes(t *testing.T) {
	store, err := openStateStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	want, err := store.create("sandbox-one", "image:latest", now)
	if err != nil {
		t.Fatal(err)
	}
	if !validSandboxID(want.ID) || want.Status != "created" || !want.CreatedAt.Equal(now) {
		t.Fatalf("created state=%+v", want)
	}
	want.WorkloadDisk = filepath.Join(t.TempDir(), "workload.ext4")
	want.WorkloadSourceType = "tar"
	want.WorkloadSourceRef = "uploaded-tar"
	want.WorkloadSourceDigest = "sha256:" + strings.Repeat("c", 64)
	want.WorkloadPlatform = "linux/" + runtime.GOARCH
	if err := store.save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.load(want.ID)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("load state=(%+v, %v), want %+v", got, err, want)
	}
	states, err := store.list()
	if err != nil || len(states) != 1 || !reflect.DeepEqual(states[0], want) {
		t.Fatalf("list states=(%+v, %v), want one state %+v", states, err, want)
	}
	if _, err := store.create("sandbox-one", "image:other", now.Add(time.Second)); err == nil {
		t.Fatal("create duplicate name succeeded")
	}
	if err := store.delete(want.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.delete(want.ID); err != nil {
		t.Fatalf("delete should be idempotent: %v", err)
	}
	states, err = store.list()
	if err != nil || len(states) != 0 {
		t.Fatalf("list after delete=(%+v, %v), want empty", states, err)
	}
}

func TestStoredWorkloadDiskRequiresCompletePinnedProvenance(t *testing.T) {
	now := time.Now().UTC()
	state := sandboxState{
		Version: sandboxStateVersion, ID: "3a967f5c-4ad7-4e36-8cd5-8b9b1b2db00c", Name: "sandbox", Status: "created",
		CreatedAt: now, UpdatedAt: now, WorkloadDisk: "/state/images/workload.ext4",
	}
	if err := validateStoredState(state); err == nil || !strings.Contains(err.Error(), "workload image provenance is required") {
		t.Fatalf("missing workload source provenance error = %v", err)
	}
	state.WorkloadSourceType = "oci"
	state.WorkloadSourceRef = "registry.example/team/workload:stable"
	state.WorkloadSourceDigest = "sha256:" + strings.Repeat("a", 64)
	state.WorkloadManifestDigest = "sha256:" + strings.Repeat("b", 64)
	state.WorkloadPlatform = "linux/" + runtime.GOARCH
	if err := validateStoredState(state); err != nil {
		t.Fatalf("complete workload disk provenance rejected: %v", err)
	}
	state.WorkloadManifestDigest = "sha256:mutable-tag"
	if err := validateStoredState(state); err == nil || !strings.Contains(err.Error(), "manifest digest") {
		t.Fatalf("mutable workload manifest identity error = %v", err)
	}
}

func TestStoredMainProcessTTYSessionIDIsValidated(t *testing.T) {
	now := time.Now().UTC()
	state := sandboxState{
		Version: sandboxStateVersion, ID: "3a967f5c-4ad7-4e36-8cd5-8b9b1b2db00c", Name: "sandbox", Status: "running",
		CreatedAt: now, UpdatedAt: now,
	}
	state.MainProcessTTYSessionID = "not-a-session"
	if err := validateStoredState(state); err == nil || !strings.Contains(err.Error(), "main-process TTY session ID") {
		t.Fatalf("invalid main-process TTY session ID error = %v", err)
	}
	state.MainProcessTTYSessionID = strings.Repeat("a", 32)
	if err := validateStoredState(state); err != nil {
		t.Fatalf("valid main-process TTY session ID rejected: %v", err)
	}
}

func TestWorkloadImageSourceSelectsIndependentDiskAndLegacyRootfs(t *testing.T) {
	state := sandboxState{
		RootfsSourceType: "oci", RootfsSourceRef: "registry.example/bootstrap:v1",
		RootfsSourceDigest:         "sha256:" + strings.Repeat("a", 64),
		RootfsSourceManifestDigest: "sha256:" + strings.Repeat("b", 64), Platform: "linux/amd64",
	}
	if got := state.workloadImageSource(); got.Reference != state.RootfsSourceRef {
		t.Fatalf("legacy workload source = %+v", got)
	}
	state.WorkloadDisk = "/state/images/workload.ext4"
	state.WorkloadSourceType = "oci"
	state.WorkloadSourceRef = "registry.example/workload:stable"
	state.WorkloadSourceDigest = "sha256:" + strings.Repeat("c", 64)
	state.WorkloadManifestDigest = "sha256:" + strings.Repeat("d", 64)
	state.WorkloadPlatform = "linux/arm64"
	if got := state.workloadImageSource(); got.Reference != state.WorkloadSourceRef || got.Digest != state.WorkloadSourceDigest || got.Platform != state.WorkloadPlatform {
		t.Fatalf("dual-disk workload source = %+v", got)
	}
}

func TestStateStoreUsesPrivateDirectoryAndFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := openStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.create("sandbox-one", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if directory.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode=%#o, want 0700", directory.Mode().Perm())
	}
	file, err := os.Stat(filepath.Join(root, state.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if file.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode=%#o, want 0600", file.Mode().Perm())
	}
}

func TestStoredRootfsProvenanceMustBeComplete(t *testing.T) {
	state := sandboxState{
		Version: sandboxStateVersion, ID: "3a967f5c-4ad7-4e36-8cd5-8b9b1b2db00c", Name: "sandbox", Status: "created",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := validateStoredState(state); err != nil {
		t.Fatalf("legacy state without provenance rejected: %v", err)
	}
	state.WorkloadUID = 1000
	if err := validateStoredState(state); err == nil || !strings.Contains(err.Error(), "both UID and GID") {
		t.Fatalf("incomplete workload identity validation error=%v", err)
	}
	state.WorkloadGID = 1001
	if err := validateStoredState(state); err != nil {
		t.Fatalf("complete observed workload identity rejected: %v", err)
	}
	state.WorkloadUID, state.WorkloadGID = 0, 0
	state.RootfsSourceType = "oci"
	state.RootfsSourceRef = "registry.example/team/image:stable"
	state.RootfsSourceDigest = "sha256:" + strings.Repeat("a", 64)
	state.RootfsSourceManifestDigest = "sha256:" + strings.Repeat("b", 64)
	state.Platform = "linux/amd64"
	if err := validateStoredState(state); err != nil {
		t.Fatalf("complete OCI provenance rejected: %v", err)
	}
	state.RootfsSourceManifestDigest = "sha256:short"
	if err := validateStoredState(state); err == nil || !strings.Contains(err.Error(), "invalid rootfs manifest digest") {
		t.Fatalf("invalid manifest digest error = %v", err)
	}
	store, err := openStateStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	state.RootfsSourceManifestDigest = "sha256:" + strings.Repeat("b", 64)
	state.RuntimeGeneration = strings.Repeat("c", 32)
	state.RuntimeSessionID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	state.RuntimeDigest = "sha256:" + strings.Repeat("e", 64)
	if err := store.save(state); err != nil {
		t.Fatalf("persist OCI provenance and VM generation: %v", err)
	}
	loaded, err := store.load(state.ID)
	if err != nil || !reflect.DeepEqual(loaded, state) {
		t.Fatalf("load OCI provenance and VM generation = (%+v, %v), want %+v", loaded, err, state)
	}
	state.RuntimeGeneration = "bad/generation"
	if err := validateStoredState(state); err == nil || !strings.Contains(err.Error(), "runtime generation") {
		t.Fatalf("invalid VM runtime generation error = %v", err)
	}
	state.RuntimeGeneration = strings.Repeat("c", 32)
	state.RuntimeGeneration = "g0000000000000001"
	if err := validateStoredState(state); err != nil {
		t.Fatalf("valid OpenShell runtime generation rejected: %v", err)
	}
	state.RuntimeGeneration = strings.Repeat("c", 32)
	state.RuntimeSessionID = "not-hex"
	if err := validateStoredState(state); err == nil || !strings.Contains(err.Error(), "runtime session ID") {
		t.Fatalf("invalid VM runtime session ID error = %v", err)
	}
	state.RuntimeSessionID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	state.RuntimeDigest = "sha256:invalid"
	if err := validateStoredState(state); err == nil || !strings.Contains(err.Error(), "runtime digest") {
		t.Fatalf("invalid VM runtime digest error = %v", err)
	}
}

func TestStoredLocalOCIProvenancePinsEngineImageIdentity(t *testing.T) {
	now := time.Now().UTC()
	imageID := "sha256:" + strings.Repeat("a", 64)
	state := sandboxState{
		Version: sandboxStateVersion, ID: "3a967f5c-4ad7-4e36-8cd5-8b9b1b2db00c", Name: "local-image", Status: "created",
		CreatedAt: now, UpdatedAt: now, RootfsSourceType: "local-oci", RootfsSourceRef: "openshell/sandbox-from:local",
		RootfsSourceDigest: imageID, RootfsSourceManifestDigest: imageID, Platform: "linux/" + runtime.GOARCH,
	}
	if err := validateStoredState(state); err != nil {
		t.Fatalf("valid local OCI provenance rejected: %v", err)
	}
	state.RootfsSourceDigest = "sha256:" + strings.Repeat("b", 64)
	if err := validateStoredState(state); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched local OCI identity error = %v", err)
	}
}

func TestVMGuestControlTokenIsPrivateAndValidated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sandbox")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	token, err := createControlToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Fatalf("control token length=%d, want 64 hex characters", len(token))
	}
	got, err := readControlToken(dir)
	if err != nil || got != token {
		t.Fatalf("read control token=(%q, %v), want generated token", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, "control.token"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("control token file mode=(%v, %v), want 0600", info, err)
	}
	if err := os.Chmod(filepath.Join(dir, "control.token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readControlToken(dir); err == nil {
		t.Fatal("readControlToken accepted a world-readable token")
	}
}

func TestPendingControlTokenRotationIsPrivateAndCanCommitAtomically(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldToken, err := createControlToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := newControlTokenRotation()
	if err != nil {
		t.Fatal(err)
	}
	if rotation.NextToken == oldToken {
		t.Fatal("rotation generated the current token")
	}
	if err := writePendingControlTokenRotation(dir, rotation); err != nil {
		t.Fatal(err)
	}
	got, pending, err := readPendingControlTokenRotation(dir)
	if err != nil || !pending || got != rotation {
		t.Fatalf("pending rotation=(%+v,%t,%v), want %+v,true,nil", got, pending, err, rotation)
	}
	info, err := os.Stat(filepath.Join(dir, pendingControlTokenRotationName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("pending rotation mode=(%v,%v), want 0600", info, err)
	}
	if err := replaceControlToken(dir, rotation.NextToken); err != nil {
		t.Fatal(err)
	}
	if got, err := readControlToken(dir); err != nil || got != rotation.NextToken {
		t.Fatalf("committed token=(%q,%v), want new token", got, err)
	}
	if err := removePendingControlTokenRotation(dir); err != nil {
		t.Fatal(err)
	}
	if _, pending, err := readPendingControlTokenRotation(dir); err != nil || pending {
		t.Fatalf("pending rotation after commit=(%t,%v), want false,nil", pending, err)
	}
}

func TestStateStoreRejectsSymlinkRootAndRecord(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(base, "root-link")
	if err := os.Symlink(target, rootLink); err != nil {
		t.Fatal(err)
	}
	if _, err := openStateStore(rootLink); err == nil {
		t.Fatal("openStateStore accepted symlink root")
	}

	store, err := openStateStore(filepath.Join(base, "store"))
	if err != nil {
		t.Fatal(err)
	}
	id := "01234567-89ab-4def-8123-0123456789ab"
	if err := os.Symlink(filepath.Join(target, "victim"), filepath.Join(store.root, id+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(id); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("load symlink record error=%v", err)
	}
}

func TestStateStoreRejectsMalformedRecordAndIDs(t *testing.T) {
	store, err := openStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "../escape", "0123456789abcdef", "01234567-89AB-4def-8123-0123456789ab"} {
		if _, err := store.load(id); err == nil {
			t.Errorf("load invalid ID %q succeeded", id)
		}
	}
	id := "01234567-89ab-4def-8123-0123456789ab"
	if err := os.WriteFile(filepath.Join(store.root, id+".json"), []byte(`{"version":1,"id":"`+id+`","name":"broken","status":"unknown","created_at":"2026-10-15T12:00:00Z","updated_at":"2026-10-15T12:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(id); err == nil || !strings.Contains(err.Error(), "invalid sandbox status") {
		t.Fatalf("load malformed record error=%v", err)
	}
}
