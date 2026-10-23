package vm

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCreateVMControlIdentityIsPrivateAndBootScoped(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "control")
	first, err := createVMControlIdentity(dir, "sandbox-a", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := createVMControlIdentity(dir, "sandbox-a", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "")
	if err != nil {
		t.Fatal(err)
	}
	if first.ExpectedClientIdentity == second.ExpectedClientIdentity {
		t.Fatal("VM control identity did not rotate across boots")
	}
	if first.Generation == "" || second.Generation == "" || first.Generation == second.Generation {
		t.Fatalf("boot generations did not rotate: first=%q second=%q", first.Generation, second.Generation)
	}
	if first.SessionID == "" || second.SessionID == "" || first.SessionID == second.SessionID {
		t.Fatalf("supervisor sessions did not rotate: first=%q second=%q", first.SessionID, second.SessionID)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(second.SessionID) {
		t.Fatalf("session ID %q is not an OpenShell canonical UUID", second.SessionID)
	}
	if !strings.Contains(second.ExpectedClientIdentity, "/session/"+second.SessionID+"/") || !strings.Contains(second.ExpectedClientIdentity, "/generation/"+second.Generation) {
		t.Fatalf("identity URI does not bind returned session and generation: %s", second.ExpectedClientIdentity)
	}
	caPEM, err := os.ReadFile(second.CAPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("CA PEM is missing")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	client, err := os.ReadFile(second.ClientCertPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(client)
	if block == nil {
		t.Fatal("client certificate PEM is missing")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != second.ExpectedClientIdentity {
		t.Fatalf("client URI SAN=%v, expected %q", cert.URIs, second.ExpectedClientIdentity)
	}
	if !strings.Contains(second.ExpectedClientIdentity, "/runtime/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/") {
		t.Fatalf("identity URI does not bind runtime digest: %s", second.ExpectedClientIdentity)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("client identity is not signed by the VM CA: %v", err)
	}
	for _, path := range []string{second.CAPath, second.ServerCertPath, second.ServerKeyPath, second.ClientCertPath, second.ClientKeyPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode=%o, want 600", path, info.Mode().Perm())
		}
	}
}

func TestCreateVMControlIdentityUsesRequestedRuntimeGeneration(t *testing.T) {
	want := "g0000000000000001"
	wantSession := "11111111-1111-4111-8111-111111111111"
	identity, err := createVMControlIdentity(filepath.Join(t.TempDir(), "control"), "sandbox-a", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", want, wantSession)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Generation != want || identity.SessionID != wantSession || !strings.Contains(identity.ExpectedClientIdentity, "/session/"+wantSession+"/") || !strings.HasSuffix(identity.ExpectedClientIdentity, "/generation/"+want) {
		t.Fatalf("identity generation/session = %q/%q, URI %q; want %q/%q", identity.Generation, identity.SessionID, identity.ExpectedClientIdentity, want, wantSession)
	}
}

func TestVMRuntimeDigestChangesWithArtifacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.bin")
	if err := os.WriteFile(path, []byte("runtime-a"), 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := vmRuntimeDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("runtime-b"), 0o700); err != nil {
		t.Fatal(err)
	}
	second, err := vmRuntimeDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("runtime digest did not change when artifact bytes changed")
	}
}

func pool(cert *x509.Certificate) *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return roots
}
