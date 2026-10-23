package vm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// SandboxDriverConfig is the VM driver's strict subset of the OpenShell
// sandbox driver_config schema.
type SandboxDriverConfig struct {
	GPUDeviceIDs  *[]string `json:"gpu_device_ids,omitempty"`
	RootfsTarPath string    `json:"rootfs_tar_path,omitempty"`
	GRPCEndpoint  string    `json:"grpc_endpoint,omitempty"`
	GuestTLSCA    string    `json:"guest_tls_ca,omitempty"`
	GuestTLSCert  string    `json:"guest_tls_cert,omitempty"`
	GuestTLSKey   string    `json:"guest_tls_key,omitempty"`
}

// ParseSandboxDriverConfig strictly decodes VM-specific sandbox options.
func ParseSandboxDriverConfig(raw string) (SandboxDriverConfig, error) {
	var config SandboxDriverConfig
	if strings.TrimSpace(raw) == "" {
		return config, nil
	}
	trimmed := bytes.TrimSpace([]byte(raw))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: must be an object")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: unexpected value after JSON object")
	} else if !errors.Is(err, io.EOF) {
		return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: %w", err)
	}
	if config.GPUDeviceIDs != nil && len(*config.GPUDeviceIDs) == 0 {
		return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: gpu_device_ids must be a non-empty list when provided")
	}
	if config.GPUDeviceIDs != nil {
		for _, id := range *config.GPUDeviceIDs {
			if strings.TrimSpace(id) == "" {
				return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: gpu_device_ids entries must not be empty")
			}
		}
	}
	if err := validateVMRelayTLSConfig(config); err != nil {
		return SandboxDriverConfig{}, err
	}
	return config, nil
}

func validateVMRelayTLSConfig(config SandboxDriverConfig) error {
	endpoint := strings.TrimSpace(config.GRPCEndpoint)
	if endpoint != "" {
		if !strings.Contains(endpoint, "://") {
			endpoint = "http://" + endpoint
		}
		parsed, err := url.Parse(endpoint)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("invalid vm driver_config: grpc_endpoint must be host:port, http://host:port, or https://host:port")
		}
	}
	paths := []string{config.GuestTLSCA, config.GuestTLSCert, config.GuestTLSKey}
	configured := 0
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		configured++
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("invalid vm driver_config: guest TLS paths must be absolute and clean")
		}
	}
	if configured != 0 && configured != len(paths) {
		return fmt.Errorf("invalid vm driver_config: guest_tls_ca, guest_tls_cert and guest_tls_key must be configured together")
	}
	if endpoint != "" {
		parsed, _ := url.Parse(endpoint)
		if parsed.Scheme == "https" && configured != len(paths) {
			return fmt.Errorf("invalid vm driver_config: HTTPS grpc_endpoint requires guest TLS CA, certificate and key")
		}
		if parsed.Scheme == "http" && configured != 0 {
			return fmt.Errorf("invalid vm driver_config: guest TLS materials require an HTTPS grpc_endpoint")
		}
	}
	if configured == 0 {
		return nil
	}
	contents := make([][]byte, len(paths))
	for i, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 1<<20 {
			return fmt.Errorf("invalid vm driver_config: guest TLS files must be regular files no larger than 1 MiB")
		}
		if i == 2 && info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("invalid vm driver_config: guest_tls_key must not be accessible by group or others")
		}
		contents[i], err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("invalid vm driver_config: guest TLS files must be readable")
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents[0]) {
		return fmt.Errorf("invalid vm driver_config: guest_tls_ca contains no certificates")
	}
	if _, err := tls.X509KeyPair(contents[1], contents[2]); err != nil {
		return fmt.Errorf("invalid vm driver_config: guest TLS client certificate/key pair is invalid")
	}
	return nil
}

func validateSandboxName(name string) error {
	if len(name) == 0 || len(name) > 128 || name == "." || name == ".." {
		return fmt.Errorf("vm driver: invalid sandbox name; expected [A-Za-z0-9._-]{1,128}")
	}
	for _, b := range []byte(name) {
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '.', b == '_', b == '-':
		default:
			return fmt.Errorf("vm driver: invalid sandbox name; expected [A-Za-z0-9._-]{1,128}")
		}
	}
	return nil
}

func validateGPURequest(enabled bool, config SandboxDriverConfig) error {
	if config.GPUDeviceIDs == nil {
		return nil
	}
	if !enabled {
		return fmt.Errorf("invalid vm driver_config: gpu_device_ids requires a GPU request")
	}
	if len(*config.GPUDeviceIDs) > 1 {
		return fmt.Errorf("invalid vm driver_config: VM driver supports at most one gpu_device_ids entry")
	}
	return nil
}
