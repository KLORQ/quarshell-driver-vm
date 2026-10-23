package vm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/isolation"
)

func TestBuildVMIsolationDescriptorBindsDurableBootClaimsWithoutSecrets(t *testing.T) {
	now := time.Now().UTC()
	state := sandboxState{
		Version: sandboxStateVersion, ID: "3a967f5c-4ad7-4e36-8cd5-8b9b1b2db00c", Name: "sandbox", Status: "running",
		RootfsSourceType: "oci", RootfsSourceRef: "registry.example/bootstrap:v1",
		RootfsSourceDigest: "sha256:" + strings.Repeat("a", 64), RootfsSourceManifestDigest: "sha256:" + strings.Repeat("b", 64),
		Platform: "linux/amd64", RuntimeGeneration: strings.Repeat("c", 32), RuntimeSessionID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		RuntimeDigest: "sha256:" + strings.Repeat("e", 64), CreatedAt: now, UpdatedAt: now,
	}
	identityDir := filepath.Join(t.TempDir(), "sandboxes", state.ID, "supervisor-control")
	identity, err := createVMControlIdentity(identityDir, state.ID, state.RootfsSourceDigest, state.RuntimeDigest, "")
	if err != nil {
		t.Fatalf("create VM control identity: %v", err)
	}
	state.RuntimeGeneration = identity.Generation
	state.RuntimeSessionID = identity.SessionID
	encoded, err := buildVMIsolationDescriptor(state, identity)
	if err != nil {
		t.Fatalf("buildVMIsolationDescriptor() error = %v", err)
	}
	var descriptor isolation.Descriptor
	if err := json.Unmarshal(encoded, &descriptor); err != nil {
		t.Fatal(err)
	}
	if descriptor.BackendName != "quarshell/vm" || descriptor.SandboxID != state.ID || descriptor.SessionID != state.RuntimeSessionID || descriptor.Generation != state.RuntimeGeneration || descriptor.RootfsDigest != state.RootfsSourceDigest || descriptor.RuntimeDigest != state.RuntimeDigest {
		t.Fatalf("descriptor claims = %+v, do not match durable state %+v", descriptor, state)
	}
	for _, private := range [][]byte{identity.ClientKey, identity.ClientCert, identity.ClientCA} {
		if len(private) > 0 && strings.Contains(string(encoded), string(private)) {
			t.Fatal("descriptor contains credential bytes")
		}
	}
	var payload vmIsolationPayload
	if err := json.Unmarshal(descriptor.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.WorkerID != state.ID || filepath.IsAbs(payload.ServerPrivateKeyFile) || payload.ServerPrivateKeyFile != "supervisor-control/server.key" {
		t.Fatalf("descriptor payload contains unexpected host path or identity: %+v", payload)
	}

	sandboxDir := filepath.Dir(identityDir)
	if err := writeVMIsolationDescriptor(sandboxDir, encoded); err != nil {
		t.Fatalf("write descriptor for reader round trip: %v", err)
	}
	got, err := readVMIsolationDescriptor(sandboxDir, state)
	if err != nil {
		t.Fatalf("readVMIsolationDescriptor() error = %v", err)
	}
	if string(got) != string(encoded) {
		t.Fatal("descriptor reader changed the canonical descriptor bytes")
	}
	for _, mutate := range []func(*sandboxState){
		func(stale *sandboxState) { stale.RuntimeSessionID = "ffffffff-ffff-4fff-8fff-ffffffffffff" },
		func(stale *sandboxState) { stale.RuntimeGeneration = strings.Repeat("f", 32) },
		func(stale *sandboxState) { stale.RootfsSourceDigest = "sha256:" + strings.Repeat("f", 64) },
		func(stale *sandboxState) { stale.RuntimeDigest = "sha256:" + strings.Repeat("f", 64) },
	} {
		stale := state
		mutate(&stale)
		if _, err := readVMIsolationDescriptor(sandboxDir, stale); err == nil {
			t.Fatal("descriptor reader accepted claims from a stale durable session")
		}
	}

	var nonCanonical isolation.Descriptor
	if err := json.Unmarshal(encoded, &nonCanonical); err != nil {
		t.Fatal(err)
	}
	nonCanonical.Payload = json.RawMessage(`{"worker_id":"` + state.ID + `","extra":"../host"}`)
	tampered, err := isolation.EncodeDescriptor(nonCanonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeVMIsolationDescriptor(sandboxDir, tampered); err != nil {
		t.Fatalf("publish schema-valid tampered payload for reader test: %v", err)
	}
	if _, err := readVMIsolationDescriptor(sandboxDir, state); err == nil || !strings.Contains(err.Error(), "non-canonical") {
		t.Fatalf("non-canonical payload error = %v", err)
	}
	if err := writeVMIsolationDescriptor(sandboxDir, encoded); err != nil {
		t.Fatalf("restore canonical descriptor: %v", err)
	}
	if err := os.Chmod(filepath.Join(sandboxDir, vmIsolationDescriptorFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readVMIsolationDescriptor(sandboxDir, state); err == nil || !strings.Contains(err.Error(), "mode-0600") {
		t.Fatalf("unprotected descriptor error = %v", err)
	}
	if err := os.Chmod(filepath.Join(sandboxDir, vmIsolationDescriptorFile), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptorPath := filepath.Join(sandboxDir, vmIsolationDescriptorFile)
	if err := os.Remove(descriptorPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(identity.CAPath, descriptorPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readVMIsolationDescriptor(sandboxDir, state); err == nil || !strings.Contains(err.Error(), "regular mode-0600") {
		t.Fatalf("descriptor symlink error = %v", err)
	}
	if err := os.Remove(descriptorPath); err != nil {
		t.Fatal(err)
	}
	if err := writeVMIsolationDescriptor(sandboxDir, encoded); err != nil {
		t.Fatalf("restore descriptor after symlink check: %v", err)
	}

	state.RuntimeSessionID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	if _, err := buildVMIsolationDescriptor(state, identity); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched session error = %v", err)
	}
	state.RuntimeSessionID = identity.SessionID
	if err := os.Chmod(identity.ClientKeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildVMIsolationDescriptor(state, identity); err == nil || !strings.Contains(err.Error(), "mode-0600") {
		t.Fatalf("unprotected credential error = %v", err)
	}
	if err := os.Chmod(identity.ClientKeyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(identity.ClientKeyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(identity.ServerKeyPath, identity.ClientKeyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := buildVMIsolationDescriptor(state, identity); err == nil || !strings.Contains(err.Error(), "mode-0600") {
		t.Fatalf("symlink credential error = %v", err)
	}
}

func TestWriteVMIsolationDescriptorIsAtomicPrivateAndRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	data, err := isolation.EncodeDescriptor(isolation.Descriptor{
		Version: isolation.DescriptorVersion, BackendName: "quarshell/vm", SandboxID: "sandbox-1",
		SessionID: "session-1", Generation: "generation-1",
		RootfsDigest: "sha256:" + strings.Repeat("a", 64), RuntimeDigest: "sha256:" + strings.Repeat("b", 64),
		Payload: json.RawMessage(`{"worker_id":"sandbox-1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeVMIsolationDescriptor(dir, data); err != nil {
		t.Fatalf("writeVMIsolationDescriptor() error = %v", err)
	}
	path := filepath.Join(dir, vmIsolationDescriptorFile)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("descriptor file=(%v, %v), want regular mode 0600", info, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(data) {
		t.Fatalf("descriptor content=(%q, %v), want %q", got, err, data)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "target"), path); err != nil {
		t.Fatal(err)
	}
	if err := writeVMIsolationDescriptor(dir, data); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("symlink destination error = %v", err)
	}
	if err := writeVMIsolationDescriptor(filepath.Join(dir, "missing"), data); err == nil {
		t.Fatal("descriptor write through missing directory unexpectedly succeeded")
	}
	if err := writeVMIsolationDescriptor(dir, []byte(`{"not":"a descriptor"}`)); err == nil {
		t.Fatal("invalid descriptor unexpectedly published")
	}
}
