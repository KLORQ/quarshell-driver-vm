package vm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const guestControlCredentialDir = "/run/quarshell/supervisor-control-private"

type vmControlIdentity struct {
	CAPath, ServerCertPath, ServerKeyPath, ClientCertPath, ClientKeyPath string
	ExpectedClientIdentity                                               string
	Generation, SessionID                                                string
	ClientCA, ClientCert, ClientKey                                      []byte
}

func createVMControlIdentity(dir, sandboxID, rootfsDigest, runtimeDigest, runtimeGeneration string, sessionIDs ...string) (vmControlIdentity, error) {
	var result vmControlIdentity
	if !validVMArtifactDigest(rootfsDigest) || !validVMArtifactDigest(runtimeDigest) {
		return result, fmt.Errorf("VM rootfs and runtime digests must be canonical sha256 digests")
	}
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return result, fmt.Errorf("VM control identity path must be a real directory")
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return result, fmt.Errorf("secure existing VM control identity directory: %w", err)
		}
		for _, name := range []string{"ca.pem", "server.crt", "server.key", "client.crt", "client.key"} {
			path := filepath.Join(dir, name)
			if fileInfo, statErr := os.Lstat(path); statErr == nil {
				if !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 {
					return result, fmt.Errorf("refusing to replace unsafe VM control credential %q", path)
				}
				if removeErr := os.Remove(path); removeErr != nil {
					return result, fmt.Errorf("replace old VM control credential: %w", removeErr)
				}
			} else if !os.IsNotExist(statErr) {
				return result, statErr
			}
		}
	} else if !os.IsNotExist(err) {
		return result, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return result, fmt.Errorf("create VM control identity directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return result, fmt.Errorf("secure VM control identity directory: %w", err)
	}
	generation := runtimeGeneration
	if generation == "" {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return result, fmt.Errorf("generate VM identity generation: %w", err)
		}
		generation = hex.EncodeToString(nonce[:])
	} else if !validOpenShellRuntimeGeneration(generation) {
		return result, fmt.Errorf("invalid requested VM runtime generation")
	}
	if len(sessionIDs) > 1 {
		return result, fmt.Errorf("VM supervisor session identity was provided more than once")
	}
	sessionID := ""
	if len(sessionIDs) == 1 && sessionIDs[0] != "" {
		sessionID = sessionIDs[0]
		if !canonicalNonNilUUID(sessionID) {
			return result, fmt.Errorf("invalid requested VM supervisor session identity")
		}
	} else {
		var sessionNonce [16]byte
		if _, err := rand.Read(sessionNonce[:]); err != nil {
			return result, fmt.Errorf("generate VM supervisor session: %w", err)
		}
		sessionNonce[6] = sessionNonce[6]&0x0f | 0x40
		sessionNonce[8] = sessionNonce[8]&0x3f | 0x80
		encodedSession := hex.EncodeToString(sessionNonce[:])
		sessionID = encodedSession[:8] + "-" + encodedSession[8:12] + "-" + encodedSession[12:16] + "-" + encodedSession[16:20] + "-" + encodedSession[20:]
	}
	identity, err := url.Parse("spiffe://quarshell.vm/sandbox/" + sandboxID + "/session/" + sessionID + "/rootfs/" + rootfsDigest + "/runtime/" + runtimeDigest + "/generation/" + generation)
	if err != nil {
		return result, fmt.Errorf("build VM control identity: %w", err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return result, err
	}
	now := time.Now().UTC()
	caSerial, err := randomSerial()
	if err != nil {
		return result, fmt.Errorf("generate VM control CA serial: %w", err)
	}
	caTemplate := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "quarshell-vm-control-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(370 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return result, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return result, err
	}
	serverCert, err := issueVMControlCert(caCert, caKey, now, true, nil)
	if err != nil {
		return result, err
	}
	clientCert, err := issueVMControlCert(caCert, caKey, now, false, identity)
	if err != nil {
		return result, err
	}
	serverKeyPEM, err := privateKeyPEM(serverCert.PrivateKey)
	if err != nil {
		return result, err
	}
	clientKeyPEM, err := privateKeyPEM(clientCert.PrivateKey)
	if err != nil {
		return result, err
	}
	base := filepath.Clean(dir)
	result = vmControlIdentity{CAPath: filepath.Join(base, "ca.pem"), ServerCertPath: filepath.Join(base, "server.crt"), ServerKeyPath: filepath.Join(base, "server.key"), ClientCertPath: filepath.Join(base, "client.crt"), ClientKeyPath: filepath.Join(base, "client.key"), ExpectedClientIdentity: identity.String(), Generation: generation, SessionID: sessionID, ClientCA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), ClientCert: certPEM(clientCert), ClientKey: clientKeyPEM}
	files := map[string][]byte{result.CAPath: result.ClientCA, result.ServerCertPath: certPEM(serverCert), result.ServerKeyPath: serverKeyPEM, result.ClientCertPath: result.ClientCert, result.ClientKeyPath: result.ClientKey}
	for path, data := range files {
		if err := writePrivateIdentityFile(path, data); err != nil {
			return vmControlIdentity{}, err
		}
	}
	return result, nil
}

func canonicalNonNilUUID(raw string) bool {
	if len(raw) != 36 || strings.ToLower(raw) != raw || raw[8] != '-' || raw[13] != '-' || raw[18] != '-' || raw[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(raw, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return true
		}
	}
	return false
}

func vmRuntimeDigest(paths ...string) (string, error) {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "quarshell-vm-runtime-v1\x00")
	for _, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			return "", fmt.Errorf("VM runtime digest input path is empty")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("VM runtime digest input %q must be a regular file", path)
		}
		file, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("open VM runtime digest input %q: %w", path, err)
		}
		if _, err := fmt.Fprintf(hash, "%s\x00%d\x00", filepath.Base(path), info.Size()); err != nil {
			_ = file.Close()
			return "", err
		}
		if _, err := io.Copy(hash, file); err != nil {
			_ = file.Close()
			return "", fmt.Errorf("hash VM runtime input %q: %w", path, err)
		}
		if err := file.Close(); err != nil {
			return "", err
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func validVMArtifactDigest(raw string) bool {
	if !strings.HasPrefix(raw, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(raw, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func issueVMControlCert(ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time, server bool, identity *url.URL) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	usage := x509.ExtKeyUsageClientAuth
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "quarshell-vm-control-peer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if server {
		template.DNSNames = []string{"quarshell-supervisor-control"}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if identity != nil {
		template.URIs = []*url.URL{identity}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func certPEM(cert tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}
func privateKeyPEM(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode VM control private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
func writePrivateIdentityFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private VM control credential: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
