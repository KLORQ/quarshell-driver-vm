//go:build darwin || linux

package vm

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
	"strings"
	"testing"
	"time"
)

func TestGuestProxyCABundleValidatesAndLoadsOperatorCertificate(t *testing.T) {
	contents := newTestProxyCABundle(t)
	path := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := guestProxyCABundle([]string{"QUARSHELL_PROXY_CA_BUNDLE=" + path})
	if err != nil || got != string(contents) {
		t.Fatalf("guestProxyCABundle() error=%v, contents match=%t", err, got == string(contents))
	}
	if got, err := guestProxyCABundle(nil); err != nil || got != "" {
		t.Fatalf("unset bundle = (%q, %v)", got, err)
	}
	largeBundle := bytes.Repeat(contents, 200)
	if err := os.WriteFile(path, largeBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = guestProxyCABundle([]string{"QUARSHELL_PROXY_CA_BUNDLE=" + path})
	if err != nil || got != string(largeBundle) {
		t.Fatalf("bundle over 64 KiB = (%d bytes, %v)", len(got), err)
	}
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := guestProxyCABundle([]string{"QUARSHELL_PROXY_CA_BUNDLE=" + path}); err == nil || !strings.Contains(err.Error(), "valid certificates") {
		t.Fatalf("malformed bundle error = %v", err)
	}
}

func newTestProxyCABundle(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Proxy CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Proxy CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestGuestInitDoesNotReceiveProxyCABundleInEnvironment(t *testing.T) {
	for _, want := range []string{
		"exec /opt/quarshell/bin/guest-agent",
	} {
		if !strings.Contains(guestInitScript, want) {
			t.Errorf("guest init script missing %q", want)
		}
	}
	if strings.Contains(guestInitScript, "QUARSHELL_VM_PROXY_CA_BUNDLE_PEM") {
		t.Fatal("proxy CA bundle must be delivered over authenticated control after boot, not environment")
	}
}
