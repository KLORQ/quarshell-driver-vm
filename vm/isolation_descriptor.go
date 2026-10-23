package vm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/KLORQ/quarshell-core/isolation"
)

const vmIsolationDescriptorFile = "isolation-descriptor.json"

// vmIsolationPayload contains stable backend references only. Socket IDs are
// resolved by the VM backend from trusted driver configuration; file paths
// are sandbox-relative and never contain credential bytes.
type vmIsolationPayload struct {
	WorkerID                  string `json:"worker_id"`
	SupervisorControlSocketID string `json:"supervisor_control_socket_id"`
	NetworkBrokerSocketID     string `json:"network_broker_socket_id"`
	ControlIdentityDirectory  string `json:"control_identity_directory"`
	ServerCAFile              string `json:"server_ca_file"`
	ServerCertificateFile     string `json:"server_certificate_file"`
	ServerPrivateKeyFile      string `json:"server_private_key_file"`
	ClientCertificateFile     string `json:"client_certificate_file"`
	ClientPrivateKeyFile      string `json:"client_private_key_file"`
}

func buildVMIsolationDescriptor(state sandboxState, identity vmControlIdentity) ([]byte, error) {
	if !validSandboxID(state.ID) || identity.Generation != state.RuntimeGeneration || identity.SessionID != state.RuntimeSessionID || state.RuntimeDigest == "" {
		return nil, fmt.Errorf("VM isolation descriptor identity does not match durable sandbox state")
	}
	if err := validateStoredState(state); err != nil {
		return nil, fmt.Errorf("validate durable VM isolation identity: %w", err)
	}
	if err := validateVMControlIdentityFiles(state, identity); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(vmIsolationPayload{
		WorkerID: state.ID, SupervisorControlSocketID: state.ID,
		NetworkBrokerSocketID: state.ID, ControlIdentityDirectory: "supervisor-control",
		ServerCAFile: "supervisor-control/ca.pem", ServerCertificateFile: "supervisor-control/server.crt",
		ServerPrivateKeyFile: "supervisor-control/server.key", ClientCertificateFile: "supervisor-control/client.crt",
		ClientPrivateKeyFile: "supervisor-control/client.key",
	})
	if err != nil {
		return nil, fmt.Errorf("encode VM isolation backend payload: %w", err)
	}
	return isolation.EncodeDescriptor(isolation.Descriptor{
		Version: isolation.DescriptorVersion, BackendName: "quarshell/vm", SandboxID: state.ID,
		SessionID: state.RuntimeSessionID, Generation: state.RuntimeGeneration,
		RootfsDigest: state.RootfsSourceDigest, RuntimeDigest: state.RuntimeDigest, Payload: payload,
	})
}

func validateVMControlIdentityFiles(state sandboxState, identity vmControlIdentity) error {
	identityDir := filepath.Dir(identity.CAPath)
	// Identity credentials must live directly beneath this sandbox's private
	// control directory. Reject path aliases and symlinks before publishing refs.
	if !filepath.IsAbs(identityDir) || filepath.Base(identityDir) != "supervisor-control" || filepath.Base(filepath.Dir(identityDir)) != state.ID {
		return fmt.Errorf("VM control identity directory is not sandbox-scoped")
	}
	dirInfo, err := os.Lstat(identityDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm() != 0o700 {
		return fmt.Errorf("VM control identity directory must be a private real directory")
	}
	credentialData := make(map[string][]byte, 5)
	for _, credential := range []struct {
		path string
		name string
	}{
		{identity.CAPath, "ca.pem"}, {identity.ServerCertPath, "server.crt"}, {identity.ServerKeyPath, "server.key"},
		{identity.ClientCertPath, "client.crt"}, {identity.ClientKeyPath, "client.key"},
	} {
		expected := filepath.Join(identityDir, credential.name)
		if filepath.Clean(credential.path) != expected {
			return fmt.Errorf("VM control credential %q is not a canonical sandbox child", credential.name)
		}
		data, err := readPrivateVMControlFile(expected)
		if err != nil {
			return fmt.Errorf("VM control credential %q: %w", credential.name, err)
		}
		credentialData[credential.name] = data
	}
	ca, err := parseVMControlCertificate(credentialData["ca.pem"])
	if err != nil || !ca.IsCA {
		return fmt.Errorf("VM control CA certificate is invalid")
	}
	serverCert, err := parseVMControlCertificate(credentialData["server.crt"])
	if err != nil {
		return fmt.Errorf("VM control server certificate is invalid: %w", err)
	}
	clientCert, err := parseVMControlCertificate(credentialData["client.crt"])
	if err != nil {
		return fmt.Errorf("VM control client certificate is invalid: %w", err)
	}
	serverKeyPair, err := tls.X509KeyPair(credentialData["server.crt"], credentialData["server.key"])
	if err != nil || len(serverKeyPair.Certificate) == 0 {
		return fmt.Errorf("VM control server certificate and key do not match")
	}
	clientKeyPair, err := tls.X509KeyPair(credentialData["client.crt"], credentialData["client.key"])
	if err != nil || len(clientKeyPair.Certificate) == 0 {
		return fmt.Errorf("VM control client certificate and key do not match")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := serverCert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("VM control server certificate is not currently trusted: %w", err)
	}
	if _, err := clientCert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("VM control client certificate is not currently trusted: %w", err)
	}
	expectedURI, err := url.Parse("spiffe://quarshell.vm/sandbox/" + state.ID + "/session/" + state.RuntimeSessionID + "/rootfs/" + state.RootfsSourceDigest + "/runtime/" + state.RuntimeDigest + "/generation/" + state.RuntimeGeneration)
	if err != nil || identity.ExpectedClientIdentity != expectedURI.String() || len(clientCert.URIs) != 1 || clientCert.URIs[0].String() != expectedURI.String() {
		return fmt.Errorf("VM control certificate identity does not match sandbox session and generation")
	}
	return nil
}

// readVMIsolationDescriptor accepts a descriptor only when its on-disk claims,
// backend payload, and credential files still match the current durable boot.
func readVMIsolationDescriptor(sandboxDir string, state sandboxState) ([]byte, error) {
	if err := validateStoredState(state); err != nil {
		return nil, fmt.Errorf("validate durable VM descriptor state: %w", err)
	}
	absolute, err := filepath.Abs(sandboxDir)
	if err != nil {
		return nil, fmt.Errorf("resolve VM sandbox descriptor directory: %w", err)
	}
	dirInfo, err := os.Lstat(absolute)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("VM descriptor directory must be a private real directory")
	}
	path := filepath.Join(absolute, vmIsolationDescriptorFile)
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("VM isolation descriptor must be a regular mode-0600 file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open VM isolation descriptor: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("VM isolation descriptor changed while being validated")
	}
	raw, err := io.ReadAll(io.LimitReader(file, isolation.MaxDescriptorBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read VM isolation descriptor: %w", err)
	}
	if len(raw) > isolation.MaxDescriptorBytes {
		return nil, fmt.Errorf("VM isolation descriptor exceeds %d bytes", isolation.MaxDescriptorBytes)
	}
	descriptor, err := isolation.DecodeDescriptor(raw)
	if err != nil {
		return nil, fmt.Errorf("decode VM isolation descriptor: %w", err)
	}
	if descriptor.BackendName != "quarshell/vm" || descriptor.SandboxID != state.ID || descriptor.SessionID != state.RuntimeSessionID || descriptor.Generation != state.RuntimeGeneration || descriptor.RootfsDigest != state.RootfsSourceDigest || descriptor.RuntimeDigest != state.RuntimeDigest {
		return nil, fmt.Errorf("VM isolation descriptor does not match current durable sandbox session")
	}
	expectedPayload, err := json.Marshal(vmIsolationPayload{
		WorkerID: state.ID, SupervisorControlSocketID: state.ID,
		NetworkBrokerSocketID: state.ID, ControlIdentityDirectory: "supervisor-control",
		ServerCAFile: "supervisor-control/ca.pem", ServerCertificateFile: "supervisor-control/server.crt",
		ServerPrivateKeyFile: "supervisor-control/server.key", ClientCertificateFile: "supervisor-control/client.crt",
		ClientPrivateKeyFile: "supervisor-control/client.key",
	})
	if err != nil || !bytes.Equal(descriptor.Payload, expectedPayload) {
		return nil, fmt.Errorf("VM isolation descriptor payload contains unexpected or non-canonical references")
	}
	identityDir := filepath.Join(absolute, "supervisor-control")
	identity := vmControlIdentity{
		CAPath: filepath.Join(identityDir, "ca.pem"), ServerCertPath: filepath.Join(identityDir, "server.crt"),
		ServerKeyPath: filepath.Join(identityDir, "server.key"), ClientCertPath: filepath.Join(identityDir, "client.crt"),
		ClientKeyPath: filepath.Join(identityDir, "client.key"), Generation: state.RuntimeGeneration,
		SessionID:              state.RuntimeSessionID,
		ExpectedClientIdentity: "spiffe://quarshell.vm/sandbox/" + state.ID + "/session/" + state.RuntimeSessionID + "/rootfs/" + state.RootfsSourceDigest + "/runtime/" + state.RuntimeDigest + "/generation/" + state.RuntimeGeneration,
	}
	if err := validateVMControlIdentityFiles(state, identity); err != nil {
		return nil, fmt.Errorf("validate VM descriptor credentials: %w", err)
	}
	return raw, nil
}

func parseVMControlCertificate(data []byte) (*x509.Certificate, error) {
	block, remainder := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(remainder)) != "" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readPrivateVMControlFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("must be a regular mode-0600 file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("changed while being validated")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// writeVMIsolationDescriptor atomically publishes an already validated
// descriptor inside the private sandbox state directory. It refuses symlink
// destinations and leaves no partial file visible after write failures.
func writeVMIsolationDescriptor(sandboxDir string, descriptor []byte) error {
	if _, err := isolation.DecodeDescriptor(descriptor); err != nil {
		return fmt.Errorf("validate VM isolation descriptor before publication: %w", err)
	}
	absolute, err := filepath.Abs(sandboxDir)
	if err != nil {
		return fmt.Errorf("resolve VM sandbox directory: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("VM sandbox descriptor directory must be a real directory")
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return fmt.Errorf("secure VM sandbox descriptor directory: %w", err)
	}
	path := filepath.Join(absolute, vmIsolationDescriptorFile)
	if existing, err := os.Lstat(path); err == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace unsafe VM isolation descriptor")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect VM isolation descriptor: %w", err)
	}
	temporary, err := os.CreateTemp(absolute, ".isolation-descriptor-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary VM isolation descriptor: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary VM isolation descriptor: %w", err)
	}
	if _, err := temporary.Write(descriptor); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary VM isolation descriptor: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary VM isolation descriptor: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary VM isolation descriptor: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish VM isolation descriptor: %w", err)
	}
	directory, err := os.Open(absolute)
	if err != nil {
		return fmt.Errorf("open VM descriptor directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && err != fs.ErrInvalid {
		return fmt.Errorf("sync VM descriptor directory: %w", err)
	}
	return nil
}
