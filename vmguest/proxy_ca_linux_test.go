//go:build linux

package vmguest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testProxyCABundle(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Corporate CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestInstallProxyCABundleWritesRootOwnedTrustMaterialAndUpdatesStore(t *testing.T) {
	root := t.TempDir()
	bundle := testProxyCABundle(t)
	updated := false
	if err := installProxyCABundleAt(root, bundle, func(string) error { updated = true; return nil }); err != nil {
		t.Fatalf("installProxyCABundleAt() error = %v", err)
	}
	path := filepath.Join(root, filepath.FromSlash(guestProxyCADir), "ca-0001.crt")
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(bundle) {
		t.Fatalf("installed CA = (%d bytes, %v)", len(got), err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("installed CA mode = (%v, %v)", info, err)
	}
	if !updated {
		t.Fatal("system trust updater was not called")
	}
}

func TestInstallProxyCABundleRejectsInvalidAndUnsafeDestination(t *testing.T) {
	root := t.TempDir()
	if err := installProxyCABundleAt(root, []byte("not PEM"), func(string) error { return nil }); err == nil {
		t.Fatal("invalid certificate bundle was accepted")
	}
	path := filepath.Join(root, filepath.FromSlash(guestProxyCADir), "ca-0001.crt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "outside")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := installProxyCABundleAt(root, testProxyCABundle(t), func(string) error { return nil }); err == nil {
		t.Fatal("symlink destination was accepted")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "keep" {
		t.Fatalf("symlink target changed: %q, %v", got, err)
	}
}

func TestGuestTrustStoreFallbackAppendsCAIdempotently(t *testing.T) {
	root := t.TempDir()
	caBundle := testProxyCABundle(t)
	if err := os.MkdirAll(filepath.Join(root, "etc/ssl/certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	systemBundle := filepath.Join(root, "etc/ssl/certs/ca-certificates.crt")
	if err := os.WriteFile(systemBundle, []byte("system roots\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installProxyCABundleAt(root, caBundle, updateGuestTrustStore); err != nil {
		t.Fatal(err)
	}
	if err := installProxyCABundleAt(root, caBundle, updateGuestTrustStore); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(systemBundle)
	if err != nil {
		t.Fatal(err)
	}
	if count := bytes.Count(contents, caBundle); count != 1 {
		t.Fatalf("CA appears %d times in fallback trust bundle", count)
	}
}
