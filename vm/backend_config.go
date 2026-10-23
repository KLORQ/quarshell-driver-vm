package vm

import (
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// hostConfigFromMap applies the VM deployment settings that the in-process Go
// backend implements. Settings owned by the external OpenShell VM subprocess
// are rejected rather than silently accepted.
func hostConfigFromMap(values map[string]any) (HostConfig, error) {
	config := DefaultHostConfig()
	// OpenShell's Gateway always passes these settings as driver arguments,
	// including when the operator omitted them from TOML. Arg values override
	// Clap's environment defaults, so the modular backend must preserve those
	// Gateway defaults instead of consuming the driver's env fallback.
	config.DefaultImage = defaultVMSandboxImage
	config.StateDir = defaultStateDir()
	config.KrunLogLevel = uint32Pointer(1)
	config.VCPUs = 2
	config.MemoryMiB = 2048
	config.OverlaySizeBytes = defaultOverlaySize
	endpointScheme := ""
	if config.GRPCEndpoint != "" {
		parsed, err := parseHostGRPCEndpoint(config.GRPCEndpoint)
		if err != nil {
			return HostConfig{}, fmt.Errorf("OPENSHELL_GRPC_ENDPOINT: %w", err)
		}
		endpointScheme = parsed.Scheme
	}
	for key, value := range values {
		var err error
		switch key {
		case "default_image":
			config.DefaultImage, err = vmConfigMaybeEmptyString(value, key)
		case "bootstrap_image":
			config.BootstrapImage, err = vmConfigMaybeEmptyString(value, key)
		case "state_dir":
			config.StateDir, err = vmConfigString(value, key)
		case "allow_driver_config":
			var allowed bool
			allowed, err = vmConfigBool(value, key)
			if err == nil {
				config.AllowDriverConfig = allowed
			}
		case "sandbox_uid", "sandbox_gid":
			var number uint64
			number, err = vmConfigUint(value, key)
			if err == nil && (number == 0 || number >= math.MaxUint32) {
				err = fmt.Errorf("%s must be in the non-root u32 range", key)
			}
			if err == nil {
				resolved := uint32(number)
				if key == "sandbox_uid" {
					config.SandboxUID = &resolved
				} else {
					config.SandboxGID = &resolved
				}
			}
		case "rootfs_tar_staging_dir":
			config.RootfsTarDir, err = vmConfigString(value, key)
		case "rootfs_tar_max_bytes":
			var number uint64
			number, err = vmConfigUint(value, key)
			if err == nil && (number == 0 || number > math.MaxInt64) {
				err = fmt.Errorf("rootfs_tar_max_bytes must be a positive signed 64-bit size")
			}
			if err == nil {
				config.RootfsTarMaxBytes = int64(number)
			}
		case "vcpus":
			var number uint64
			number, err = vmConfigUint(value, key)
			if err == nil && (number == 0 || number > math.MaxUint8) {
				err = fmt.Errorf("vcpus must be between 1 and %d", math.MaxUint8)
			}
			if err == nil {
				config.VCPUs = uint8(number)
			}
		case "mem_mib":
			var number uint64
			number, err = vmConfigUint(value, key)
			if err == nil && (number == 0 || number > math.MaxUint32) {
				err = fmt.Errorf("mem_mib must be between 1 and %d", math.MaxUint32)
			}
			if err == nil {
				config.MemoryMiB = uint32(number)
			}
		case "krun_log_level":
			var number uint64
			number, err = vmConfigUint(value, key)
			if err == nil && number > math.MaxUint32 {
				err = fmt.Errorf("krun_log_level must fit in an unsigned 32-bit integer")
			}
			if err == nil {
				config.KrunLogLevel = uint32Pointer(uint32(number))
			}
		case "overlay_disk_mib":
			var number uint64
			number, err = vmConfigUint(value, key)
			if err == nil && (number == 0 || number > math.MaxUint64/(1<<20)) {
				err = fmt.Errorf("overlay_disk_mib must be a positive size")
			}
			if err == nil {
				config.OverlaySizeBytes = number << 20
			}
		case "grpc_endpoint":
			var endpoint string
			endpoint, err = vmConfigString(value, key)
			if err == nil {
				var parsed *url.URL
				parsed, err = parseHostGRPCEndpoint(endpoint)
				if err == nil {
					config.GRPCEndpoint = endpoint
					endpointScheme = parsed.Scheme
				}
			}
		case "guest_tls_ca":
			var guestTLSCA string
			guestTLSCA, err = vmConfigString(value, key)
			if err == nil {
				config.GuestTLSCA = guestTLSCA
				info, statErr := os.Stat(guestTLSCA)
				if statErr != nil || !info.Mode().IsRegular() {
					err = fmt.Errorf("guest_tls_ca must reference an existing regular file")
				}
			}
		case "guest_tls_cert", "guest_tls_key":
			err = fmt.Errorf("sandbox client certificates are no longer supported; remove guest_tls_cert and guest_tls_key")
		case "https_proxy":
			config.CorporateProxyURL, err = vmConfigString(value, key)
		case "no_proxy":
			config.CorporateProxyNoProxy, err = vmConfigString(value, key)
		case "proxy_auth_file":
			config.CorporateProxyAuthFile, err = vmConfigString(value, key)
		case "proxy_auth_allow_insecure":
			var allowed bool
			allowed, err = vmConfigBool(value, key)
			if err == nil {
				config.CorporateProxyAuthAllowInsecure = &allowed
			}
		case "proxy_connect_by_hostname":
			var enabled bool
			enabled, err = vmConfigBool(value, key)
			if err == nil {
				config.CorporateProxyConnectByHostname = &enabled
			}
		case "proxy_ca_bundle":
			config.CorporateProxyCABundle, err = vmConfigString(value, key)
		case "provider_spiffe_workload_api_tcp_endpoint":
			config.ProviderSPIFFEWorkloadAPIEndpoint, err = vmConfigString(value, key)
		case "provider_spiffe_allow_guest_tcp":
			config.ProviderSPIFFEAllowGuestTCP, err = vmConfigBool(value, key)
		default:
			err = fmt.Errorf("unsupported VM deployment setting %q", key)
		}
		if err != nil {
			return HostConfig{}, fmt.Errorf("vm config %s: %w", key, err)
		}
	}
	environmentFallbacks := make(map[string]any, len(values)+6)
	for key, value := range values {
		environmentFallbacks[key] = value
	}
	for _, key := range []string{"default_image", "state_dir", "krun_log_level", "vcpus", "mem_mib", "overlay_disk_mib"} {
		if _, explicit := values[key]; !explicit {
			environmentFallbacks[key] = nil
		}
	}
	endpointScheme, err := applyVMEnvironmentOverrides(&config, endpointScheme, environmentFallbacks)
	if err != nil {
		return HostConfig{}, err
	}
	if err := validateCorporateProxySettings(config); err != nil {
		return HostConfig{}, err
	}
	_, explicitlySetDefaultImage := values["default_image"]
	explicitlyEmptyDefaultImage := explicitlySetDefaultImage && configStringIsEmpty(values["default_image"])
	if strings.TrimSpace(config.DefaultImage) == "" && strings.TrimSpace(config.BootstrapImage) == "" {
		return HostConfig{}, fmt.Errorf("bootstrap_image or default_image is required when using the vm compute driver; sandbox images cannot be used as VM bootstrap images")
	}
	if endpointScheme == "https" && config.GuestTLSCA == "" {
		return HostConfig{}, fmt.Errorf("VM HTTPS grpc_endpoint requires guest_tls_ca")
	}
	if config.GuestTLSCA != "" {
		info, statErr := os.Stat(config.GuestTLSCA)
		if statErr != nil || !info.Mode().IsRegular() {
			return HostConfig{}, fmt.Errorf("guest_tls_ca must reference an existing regular file")
		}
	}
	config = normalizeHostConfig(config)
	if explicitlyEmptyDefaultImage {
		config.DefaultImage = ""
	}
	absoluteStateDir, err := filepath.Abs(config.StateDir)
	if err != nil {
		return HostConfig{}, fmt.Errorf("vm config state_dir: resolve path: %w", err)
	}
	config.StateDir = absoluteStateDir
	if _, configuredInDeployment := values["rootfs_tar_staging_dir"]; !configuredInDeployment {
		if _, configuredInEnvironment := os.LookupEnv("OPENSHELL_VM_ROOTFS_TAR_STAGING_DIR"); !configuredInEnvironment {
			config.RootfsTarDir = filepath.Join(config.StateDir, "rootfs-tar-staging")
		}
	}
	if strings.TrimSpace(config.BootstrapImage) == "" {
		config.BootstrapImage = config.DefaultImage
	}
	return config, nil
}

func parseHostGRPCEndpoint(endpoint string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, fmt.Errorf("grpc_endpoint must be an http(s) URL without credentials, path, query, or fragment")
	}
	return parsed, nil
}

func validateCorporateProxySettings(config HostConfig) error {
	proxyURL := strings.TrimSpace(config.CorporateProxyURL)
	proxyScheme := ""
	if proxyURL != "" {
		parsed, err := url.Parse(proxyURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return fmt.Errorf("vm config https_proxy must be an http(s) proxy URL without credentials, path, query or fragment")
		}
		proxyScheme = parsed.Scheme
	}
	if config.CorporateProxyNoProxy != "" && proxyURL == "" {
		return fmt.Errorf("vm config no_proxy is set but no https_proxy is configured")
	}
	if config.CorporateProxyAuthFile != "" {
		if proxyURL == "" {
			return fmt.Errorf("vm config proxy_auth_file is set but no https_proxy is configured")
		}
		if err := validateVMConfigFile("proxy_auth_file", config.CorporateProxyAuthFile); err != nil {
			return err
		}
		if proxyScheme == "http" && (config.CorporateProxyAuthAllowInsecure == nil || !*config.CorporateProxyAuthAllowInsecure) {
			return fmt.Errorf("vm config proxy_auth_allow_insecure must be true for Basic auth over an http proxy")
		}
	} else if config.CorporateProxyAuthAllowInsecure != nil {
		return fmt.Errorf("vm config proxy_auth_allow_insecure is set but no proxy_auth_file is configured")
	}
	if config.CorporateProxyConnectByHostname != nil && proxyURL == "" {
		return fmt.Errorf("vm config proxy_connect_by_hostname is set but no https_proxy is configured")
	}
	if config.CorporateProxyCABundle != "" {
		if proxyURL == "" {
			return fmt.Errorf("vm config proxy_ca_bundle is set but no https_proxy is configured")
		}
		if err := validateVMConfigFile("proxy_ca_bundle", config.CorporateProxyCABundle); err != nil {
			return err
		}
	}
	if endpoint := config.ProviderSPIFFEWorkloadAPIEndpoint; endpoint != "" {
		if !strings.HasPrefix(endpoint, "tcp:") || strings.TrimSpace(endpoint) != endpoint {
			return fmt.Errorf("vm config provider_spiffe_workload_api_tcp_endpoint must use tcp:IP:port")
		}
		address, err := netip.ParseAddrPort(strings.TrimPrefix(endpoint, "tcp:"))
		if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() {
			return fmt.Errorf("vm config provider_spiffe_workload_api_tcp_endpoint must use a concrete IP address and non-zero port")
		}
		if !config.ProviderSPIFFEAllowGuestTCP {
			return fmt.Errorf("vm config provider_spiffe_workload_api_tcp_endpoint exposes the Workload API; set provider_spiffe_allow_guest_tcp=true to acknowledge guest access")
		}
	} else if config.ProviderSPIFFEAllowGuestTCP {
		return fmt.Errorf("vm config provider_spiffe_allow_guest_tcp is set but no provider_spiffe_workload_api_tcp_endpoint is configured")
	}
	return nil
}

func validateVMConfigFile(key, path string) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("vm config %s must be a non-empty absolute clean path", key)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("vm config %s must reference an existing regular file", key)
	}
	return nil
}

func applyVMEnvironmentOverrides(config *HostConfig, endpointScheme string, explicit map[string]any) (string, error) {
	for _, unsupported := range []struct {
		env, label string
		boolFlag   bool
	}{
		{"OPENSHELL_VM_UPSTREAM_PROXY", "upstream proxy", false},
		{"OPENSHELL_VM_UPSTREAM_NO_PROXY", "upstream no_proxy", false},
		{"OPENSHELL_VM_UPSTREAM_PROXY_AUTH_FILE", "upstream proxy auth", false},
		{"OPENSHELL_VM_UPSTREAM_PROXY_AUTH_ALLOW_INSECURE", "upstream proxy auth", true},
		{"OPENSHELL_VM_UPSTREAM_PROXY_CONNECT_BY_HOSTNAME", "upstream proxy", true},
		{"OPENSHELL_VM_UPSTREAM_PROXY_CA_BUNDLE", "upstream proxy CA", false},
		{"OPENSHELL_VM_GPU", "GPU passthrough", true},
		{"OPENSHELL_VM_SUPERVISOR_BIN", "host supervisor binary override", false},
	} {
		env, label := unsupported.env, unsupported.label
		if raw, configured := os.LookupEnv(env); configured {
			if unsupported.boolFlag && disabledBoolEnvironmentValue(raw) {
				continue
			}
			return "", fmt.Errorf("%s is not implemented by the in-process Go VM backend; remove %s", label, env)
		}
	}
	for _, setting := range []struct{ env, key string }{
		{"OPENSHELL_VM_HTTPS_PROXY", "https_proxy"},
		{"OPENSHELL_VM_NO_PROXY", "no_proxy"},
		{"OPENSHELL_VM_PROXY_AUTH_FILE", "proxy_auth_file"},
		{"OPENSHELL_VM_PROXY_CA_BUNDLE", "proxy_ca_bundle"},
	} {
		if _, explicit := explicit[setting.key]; explicit {
			continue
		}
		if value, configured := os.LookupEnv(setting.env); configured {
			switch setting.key {
			case "https_proxy":
				config.CorporateProxyURL = value
			case "no_proxy":
				config.CorporateProxyNoProxy = value
			case "proxy_auth_file":
				config.CorporateProxyAuthFile = value
			case "proxy_ca_bundle":
				config.CorporateProxyCABundle = value
			}
		}
	}
	if _, explicit := explicit["proxy_auth_allow_insecure"]; !explicit {
		if value, configured := os.LookupEnv("OPENSHELL_VM_PROXY_AUTH_ALLOW_INSECURE"); configured {
			allowed, err := strconv.ParseBool(value)
			if err != nil {
				return "", fmt.Errorf("OPENSHELL_VM_PROXY_AUTH_ALLOW_INSECURE must be a boolean")
			}
			config.CorporateProxyAuthAllowInsecure = &allowed
		}
	}
	if _, explicit := explicit["proxy_connect_by_hostname"]; !explicit {
		if value, configured := os.LookupEnv("OPENSHELL_VM_PROXY_CONNECT_BY_HOSTNAME"); configured {
			enabled, err := strconv.ParseBool(value)
			if err != nil {
				return "", fmt.Errorf("OPENSHELL_VM_PROXY_CONNECT_BY_HOSTNAME must be a boolean")
			}
			config.CorporateProxyConnectByHostname = &enabled
		}
	}
	if _, explicit := explicit["provider_spiffe_workload_api_tcp_endpoint"]; !explicit {
		if value, configured := os.LookupEnv("OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_TCP_ENDPOINT"); configured {
			config.ProviderSPIFFEWorkloadAPIEndpoint = value
		}
	}
	if _, explicit := explicit["provider_spiffe_allow_guest_tcp"]; !explicit {
		if value, configured := os.LookupEnv("OPENSHELL_PROVIDER_SPIFFE_ALLOW_GUEST_TCP"); configured {
			allowed, err := strconv.ParseBool(value)
			if err != nil {
				return "", fmt.Errorf("OPENSHELL_PROVIDER_SPIFFE_ALLOW_GUEST_TCP must be a boolean")
			}
			config.ProviderSPIFFEAllowGuestTCP = allowed
		}
	}
	for _, numericEnv := range []struct {
		name    string
		bitSize int
	}{
		{name: "OPENSHELL_VM_GPU_MEM_MIB", bitSize: 32},
		{name: "OPENSHELL_VM_GPU_VCPUS", bitSize: 8},
	} {
		if raw, configured := os.LookupEnv(numericEnv.name); configured {
			if _, err := strconv.ParseUint(raw, 10, numericEnv.bitSize); err != nil {
				return "", fmt.Errorf("%s must be a non-negative integer fitting in %d bits", numericEnv.name, numericEnv.bitSize)
			}
		}
	}
	stringOverrides := []struct {
		env    string
		name   string
		target *string
	}{
		{env: "OPENSHELL_VM_RUNTIME_DIR", name: "runtime_dir", target: &config.RuntimeDir},
		{env: "OPENSHELL_VM_BOOTSTRAP_IMAGE", name: "bootstrap_image", target: &config.BootstrapImage},
		{env: "OPENSHELL_VM_ROOTFS_TAR_STAGING_DIR", name: "rootfs_tar_staging_dir", target: &config.RootfsTarDir},
		{env: "OPENSHELL_VM_TLS_CA", name: "guest_tls_ca", target: &config.GuestTLSCA},
	}
	for _, override := range stringOverrides {
		if _, hasExplicitValue := explicit[override.name]; hasExplicitValue {
			continue
		}
		if raw, configured := os.LookupEnv(override.env); configured {
			var value string
			var err error
			if override.name == "bootstrap_image" {
				value, err = vmConfigMaybeEmptyString(raw, override.env)
			} else {
				value, err = vmConfigString(raw, override.env)
			}
			if err != nil {
				return "", err
			}
			*override.target = value
		}
	}
	if _, configured := os.LookupEnv("OPENSHELL_VM_TLS_CERT"); configured {
		return "", fmt.Errorf("sandbox client certificates are no longer supported; remove OPENSHELL_VM_TLS_CERT and OPENSHELL_VM_TLS_KEY")
	}
	if _, configured := os.LookupEnv("OPENSHELL_VM_TLS_KEY"); configured {
		return "", fmt.Errorf("sandbox client certificates are no longer supported; remove OPENSHELL_VM_TLS_CERT and OPENSHELL_VM_TLS_KEY")
	}
	uintOverrides := []struct {
		env   string
		name  string
		apply func(uint64) error
	}{
		{env: "OPENSHELL_VM_ROOTFS_TAR_MAX_BYTES", name: "rootfs_tar_max_bytes", apply: func(value uint64) error {
			if value == 0 || value > math.MaxInt64 {
				return fmt.Errorf("rootfs_tar_max_bytes must be a positive signed 64-bit size")
			}
			config.RootfsTarMaxBytes = int64(value)
			return nil
		}},
	}
	for _, override := range uintOverrides {
		if _, hasExplicitValue := explicit[override.name]; hasExplicitValue {
			continue
		}
		raw, configured := os.LookupEnv(override.env)
		if !configured {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return "", fmt.Errorf("%s must be a non-negative integer", override.env)
		}
		if err := override.apply(value); err != nil {
			return "", fmt.Errorf("%s: %w", override.env, err)
		}
	}
	for _, override := range []struct {
		env, name string
		target    **uint32
	}{
		{env: "OPENSHELL_VM_SANDBOX_UID", name: "sandbox_uid", target: &config.SandboxUID},
		{env: "OPENSHELL_VM_SANDBOX_GID", name: "sandbox_gid", target: &config.SandboxGID},
	} {
		if _, hasExplicitValue := explicit[override.name]; hasExplicitValue {
			continue
		}
		raw, configured := os.LookupEnv(override.env)
		if !configured {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32)
		if err != nil || value == 0 || value >= math.MaxUint32 {
			return "", fmt.Errorf("%s must be in the non-root u32 range", override.env)
		}
		*override.target = uint32Pointer(uint32(value))
	}
	return endpointScheme, nil
}

func disabledBoolEnvironmentValue(value string) bool {
	return value == "false"
}

func vmConfigString(value any, key string) (string, error) {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("%s must be a non-empty string", key)
	}
	return strings.TrimSpace(text), nil
}

func vmConfigMaybeEmptyString(value any, key string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return strings.TrimSpace(text), nil
}

func configStringIsEmpty(value any) bool {
	text, ok := value.(string)
	return ok && strings.TrimSpace(text) == ""
}

func vmConfigUint(value any, key string) (uint64, error) {
	switch number := value.(type) {
	case int64:
		if number >= 0 {
			return uint64(number), nil
		}
	case int:
		if number >= 0 {
			return uint64(number), nil
		}
	case uint64:
		return number, nil
	case uint32:
		return uint64(number), nil
	}
	return 0, fmt.Errorf("%s must be a non-negative integer", key)
}

func vmConfigBool(value any, key string) (bool, error) {
	if enabled, ok := value.(bool); ok {
		return enabled, nil
	}
	return false, fmt.Errorf("%s must be a boolean", key)
}
