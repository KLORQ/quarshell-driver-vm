package vm

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestHostConfigFromMapPreservesGRPCEndpoint(t *testing.T) {
	t.Setenv("OPENSHELL_GRPC_ENDPOINT", "https://env.gateway:7443")
	// Use a real CA file because HTTPS endpoints require guest trust material.
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("test ca"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSHELL_VM_TLS_CA", ca)

	config, err := hostConfigFromMap(map[string]any{"grpc_endpoint": "http://gateway.internal:7443"})
	if err != nil {
		t.Fatal(err)
	}
	if config.GRPCEndpoint != "http://gateway.internal:7443" {
		t.Fatalf("grpc endpoint = %q", config.GRPCEndpoint)
	}
}

func TestHostConfigFromMapReadsGRPCEndpointEnvironment(t *testing.T) {
	t.Setenv("OPENSHELL_GRPC_ENDPOINT", "http://gateway.internal:7443")
	config, err := hostConfigFromMap(nil)
	if err != nil {
		t.Fatal(err)
	}
	if config.GRPCEndpoint != "http://gateway.internal:7443" {
		t.Fatalf("grpc endpoint = %q", config.GRPCEndpoint)
	}
}

func TestHostConfigFromMapRejectsGRPCEndpointPath(t *testing.T) {
	_, err := hostConfigFromMap(map[string]any{"grpc_endpoint": "http://gateway.internal:7443/api"})
	if err == nil {
		t.Fatal("grpc_endpoint path was accepted")
	}
}

func TestHostConfigFromMapReadsCorporateProxySettings(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(ca, []byte("ca"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := filepath.Join(t.TempDir(), "proxy-auth")
	if err := os.WriteFile(auth, []byte("user:password"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := hostConfigFromMap(map[string]any{
		"https_proxy": "https://proxy.example:8443", "no_proxy": "localhost,.internal",
		"proxy_auth_file": auth, "proxy_ca_bundle": ca, "proxy_connect_by_hostname": true,
		"provider_spiffe_workload_api_tcp_endpoint": "tcp:192.0.2.10:8081", "provider_spiffe_allow_guest_tcp": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.CorporateProxyURL != "https://proxy.example:8443" || config.CorporateProxyNoProxy != "localhost,.internal" || config.CorporateProxyAuthFile != auth || config.CorporateProxyCABundle != ca || config.CorporateProxyConnectByHostname == nil || !*config.CorporateProxyConnectByHostname {
		t.Fatalf("corporate proxy config = %#v", config)
	}
	if config.ProviderSPIFFEWorkloadAPIEndpoint != "tcp:192.0.2.10:8081" || !config.ProviderSPIFFEAllowGuestTCP {
		t.Fatalf("SPIFFE config = %#v", config)
	}
}

func TestHostConfigFromMapRequiresSPIFFEGuestAccessAcknowledgement(t *testing.T) {
	_, err := hostConfigFromMap(map[string]any{"provider_spiffe_workload_api_tcp_endpoint": "tcp:192.0.2.10:8081"})
	if err == nil || !strings.Contains(err.Error(), "provider_spiffe_allow_guest_tcp") {
		t.Fatalf("SPIFFE endpoint error = %v", err)
	}
}

func TestApplyCorporateProxyKeepsGatewaySettingsAuthoritative(t *testing.T) {
	driver := NewWithHostConfig(HostConfig{CorporateProxyURL: "https://proxy.example:8443", CorporateProxyNoProxy: "localhost"})
	driver.host.ProviderSPIFFEWorkloadAPIEndpoint = "tcp:192.0.2.10:8081"
	driver.host.ProviderSPIFFEAllowGuestTCP = true
	spec := vmCreateSpec{ProxyBin: "/proxy", PolicyPath: "/policy", ProxyEnv: []string{
		"HTTPS_PROXY=http://attacker.invalid", "CAUTEM_PROXY_AUTH_FILE=/attacker", "CAUTEM_EGRESS_CA_BUNDLE=/egress-ca",
		"OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET=tcp:192.0.2.99:9999",
	}}
	if err := driver.applyCorporateProxy(&spec); err != nil {
		t.Fatal(err)
	}
	want := []string{"CAUTEM_EGRESS_CA_BUNDLE=/egress-ca", "HTTP_PROXY=https://proxy.example:8443", "HTTPS_PROXY=https://proxy.example:8443", "NO_PROXY=localhost", "OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET=tcp:192.0.2.10:8081"}
	if !slices.Equal(spec.ProxyEnv, want) {
		t.Fatalf("proxy env = %#v, want %#v", spec.ProxyEnv, want)
	}
}

func TestApplyCorporateProxyRequiresPolicyBroker(t *testing.T) {
	driver := NewWithHostConfig(HostConfig{CorporateProxyURL: "https://proxy.example:8443"})
	spec := vmCreateSpec{}
	if err := driver.applyCorporateProxy(&spec); err == nil {
		t.Fatal("corporate proxy without policy broker was accepted")
	}
}
