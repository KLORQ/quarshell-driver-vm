//go:build linux

package vmguest

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const guestProxyCADir = "/usr/local/share/ca-certificates/quarshell-proxy-ca"

func installProxyCABundle(bundle []byte) error {
	return installProxyCABundleAt("/", bundle, updateGuestTrustStore)
}

func installProxyCABundleAt(root string, bundle []byte, update func(string) error) error {
	if len(bundle) == 0 || len(bundle) > 1<<20 {
		return fmt.Errorf("corporate proxy CA bundle has an invalid size")
	}
	certificates, err := parseProxyCACertificates(bundle)
	if err != nil {
		return err
	}
	directory := filepath.Join(root, filepath.FromSlash(guestProxyCADir))
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create corporate proxy CA directory: %w", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("inspect corporate proxy CA directory: %w", err)
	}
	for _, entry := range entries {
		info, statErr := os.Lstat(filepath.Join(directory, entry.Name()))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("corporate proxy CA directory contains an unsafe entry")
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return fmt.Errorf("remove previous corporate proxy CA: %w", err)
		}
	}
	for i, certificate := range certificates {
		path := filepath.Join(directory, fmt.Sprintf("ca-%04d.crt", i+1))
		if err := os.WriteFile(path, certificate, 0o644); err != nil {
			return fmt.Errorf("write corporate proxy CA certificate: %w", err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			return fmt.Errorf("set corporate proxy CA permissions: %w", err)
		}
	}
	if err := update(root); err != nil {
		return fmt.Errorf("update guest trust store: %w", err)
	}
	return nil
}

func parseProxyCACertificates(bundle []byte) ([][]byte, error) {
	remaining := bytes.TrimSpace(bundle)
	var certificates [][]byte
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("corporate proxy CA bundle contains invalid PEM data")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("corporate proxy CA bundle contains an invalid certificate")
		}
		certificates = append(certificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}))
		remaining = bytes.TrimSpace(rest)
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("corporate proxy CA bundle contains no valid certificates")
	}
	return certificates, nil
}

func updateGuestTrustStore(root string) error {
	updater := filepath.Join(root, "usr/sbin/update-ca-certificates")
	if info, err := os.Stat(updater); err == nil && info.Mode().IsRegular() {
		if root == "/" {
			output, runErr := exec.Command(updater).CombinedOutput()
			if runErr != nil {
				return fmt.Errorf("update-ca-certificates failed: %w: %s", runErr, string(output))
			}
			return nil
		}
		return fmt.Errorf("trust updater is unavailable outside the guest root")
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect trust updater: %w", err)
	}
	const certDir = "/usr/local/share/ca-certificates/quarshell-proxy-ca"
	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(certDir)))
	if err != nil {
		return err
	}
	var certificates [][]byte
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return fmt.Errorf("corporate proxy CA directory contains an unsafe entry")
		}
		certificate, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(certDir), entry.Name()))
		if readErr != nil {
			return readErr
		}
		certificates = append(certificates, certificate)
	}
	for _, relative := range []string{
		"etc/ssl/certs/ca-certificates.crt",
		"etc/pki/tls/certs/ca-bundle.crt",
		"etc/ssl/ca-bundle.pem",
		"etc/ssl/cert.pem",
	} {
		path := filepath.Join(root, relative)
		if info, statErr := os.Stat(path); statErr == nil && info.Mode().IsRegular() {
			contents, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			changed := false
			var additions []byte
			for _, certificate := range certificates {
				if !bytes.Contains(contents, certificate) {
					addition := append([]byte("\n"), certificate...)
					contents = append(contents, addition...)
					additions = append(additions, addition...)
					changed = true
				}
			}
			if !changed {
				return nil
			}
			file, openErr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if openErr != nil {
				return openErr
			}
			if _, writeErr := file.Write(additions); writeErr != nil {
				_ = file.Close()
				return writeErr
			}
			return file.Close()
		} else if statErr != nil && !os.IsNotExist(statErr) {
			return statErr
		}
	}
	return fmt.Errorf("guest image has no supported system CA bundle or update-ca-certificates")
}
