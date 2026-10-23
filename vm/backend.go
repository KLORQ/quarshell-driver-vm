package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver/driver"
)

var _ driver.Backend = (*Driver)(nil)
var _ driver.RuntimeLaunchSpecRestorer = (*Driver)(nil)
var _ driver.RuntimeContractValidator = (*Driver)(nil)
var _ driver.RuntimeRootfsTarStager = (*Driver)(nil)
var _ driver.RuntimeTokenStarter = (*Driver)(nil)
var _ driver.RuntimeCredentialStarter = (*Driver)(nil)

func (d *Driver) ValidateRuntimeContract(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("vm backend: ValidateRuntimeContract context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return d.validateGatewayRuntime(ctx)
}

func (d *Driver) ID() driver.BackendID { return "vm" }

func (d *Driver) Capabilities(ctx context.Context) (driver.BackendInfo, error) {
	if ctx == nil {
		return driver.BackendInfo{}, fmt.Errorf("vm backend: Capabilities context is nil")
	}
	if err := ctx.Err(); err != nil {
		return driver.BackendInfo{}, err
	}
	return d.backendInfo(), nil
}

func (d *Driver) ValidateCreate(ctx context.Context, request driver.BackendCreateRequest) error {
	if ctx == nil {
		return fmt.Errorf("vm backend: ValidateCreate context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.validateBackendDriverConfig(request.Config); err != nil {
		return err
	}
	spec, err := vmSpecFromBackendRequest(ctx, request)
	if err != nil {
		return fmt.Errorf("vm backend request: %w", err)
	}
	if err := d.applyCorporateProxy(&spec); err != nil {
		return err
	}
	return d.validateCreateSpec(spec)
}

func (d *Driver) Create(ctx context.Context, request driver.BackendCreateRequest) (driver.Handle, error) {
	if ctx == nil {
		return driver.Handle{}, fmt.Errorf("vm backend: Create context is nil")
	}
	if err := d.validateBackendDriverConfig(request.Config); err != nil {
		return driver.Handle{}, err
	}
	spec, err := vmSpecFromBackendRequest(ctx, request)
	if err != nil {
		return driver.Handle{}, fmt.Errorf("vm backend request: %w", err)
	}
	if err := d.applyCorporateProxy(&spec); err != nil {
		return driver.Handle{}, err
	}
	return d.createSandbox(ctx, spec)
}

func (d *Driver) RestoreLaunchSpec(ctx context.Context, id core.ID, request driver.BackendCreateRequest) error {
	if ctx == nil {
		return fmt.Errorf("vm backend: RestoreLaunchSpec context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.validateBackendDriverConfig(request.Config); err != nil {
		return err
	}
	spec, err := vmSpecFromBackendRequest(ctx, request)
	if err != nil {
		return fmt.Errorf("vm backend restore request: %w", err)
	}
	if err := d.applyCorporateProxy(&spec); err != nil {
		return err
	}
	return d.restoreLaunchSpec(ctx, id, spec)
}

// applyCorporateProxy makes Gateway operator configuration authoritative over
// sandbox supplied broker environment. Proxy credentials remain a file path;
// the credential contents are read by the proxy process itself.
func (d *Driver) applyCorporateProxy(spec *vmCreateSpec) error {
	if d == nil || spec == nil {
		return fmt.Errorf("vm backend: corporate proxy configuration requires a driver and launch spec")
	}
	host := d.host
	if err := validateCorporateProxySettings(host); err != nil {
		return err
	}
	if host.CorporateProxyURL == "" && host.ProviderSPIFFEWorkloadAPIEndpoint == "" {
		return nil
	}
	if spec.ProxyBin == "" || spec.PolicyPath == "" {
		return fmt.Errorf("vm backend: https_proxy requires the policy network proxy binary and policy path")
	}
	managed := make(map[string]string)
	if host.CorporateProxyURL != "" {
		managed["HTTP_PROXY"] = host.CorporateProxyURL
		managed["HTTPS_PROXY"] = host.CorporateProxyURL
	}
	if host.CorporateProxyNoProxy != "" {
		managed["NO_PROXY"] = host.CorporateProxyNoProxy
	}
	if host.CorporateProxyAuthFile != "" {
		managed["QUARSHELL_PROXY_AUTH_FILE"] = host.CorporateProxyAuthFile
	}
	if host.CorporateProxyCABundle != "" {
		managed["QUARSHELL_PROXY_CA_BUNDLE"] = host.CorporateProxyCABundle
	}
	if host.CorporateProxyConnectByHostname != nil && *host.CorporateProxyConnectByHostname {
		managed["QUARSHELL_PROXY_CONNECT_BY_HOSTNAME"] = "true"
	}
	if host.ProviderSPIFFEWorkloadAPIEndpoint != "" {
		managed["OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET"] = host.ProviderSPIFFEWorkloadAPIEndpoint
	}
	filtered := make([]string, 0, len(spec.ProxyEnv)+len(managed))
	operatorKeys := map[string]struct{}{"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "NO_PROXY": {}, "QUARSHELL_PROXY_AUTH_FILE": {}, "QUARSHELL_PROXY_CA_BUNDLE": {}, "QUARSHELL_PROXY_CONNECT_BY_HOSTNAME": {}, "OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET": {}}
	for _, entry := range spec.ProxyEnv {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		if _, operatorManaged := operatorKeys[key]; !operatorManaged {
			filtered = append(filtered, entry)
		}
	}
	keys := []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "QUARSHELL_PROXY_AUTH_FILE", "QUARSHELL_PROXY_CA_BUNDLE", "QUARSHELL_PROXY_CONNECT_BY_HOSTNAME", "OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET"}
	for _, key := range keys {
		if value, ok := managed[key]; ok {
			filtered = append(filtered, key+"="+value)
		}
	}
	spec.ProxyEnv = filtered
	return nil
}

func (d *Driver) validateBackendDriverConfig(config any) error {
	if d == nil {
		return fmt.Errorf("vm backend: driver is nil")
	}
	if config == nil || d.host.AllowDriverConfig {
		return nil
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode VM driver config: %w", err)
	}
	trimmed := bytes.TrimSpace(encoded)
	if bytes.Equal(trimmed, []byte("{}")) || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if !d.host.AllowDriverConfig {
		return fmt.Errorf("caller driver_config is disabled; a gateway administrator must enable allow_driver_config")
	}
	return nil
}

// vmSpecFromBackendRequest maps the modular domain request into the current
// VM launch model. It lives here so VM behavior validates every modular
// backend field and rejects values it cannot honor.
func vmSpecFromBackendRequest(ctx context.Context, request driver.BackendCreateRequest) (vmCreateSpec, error) {
	if request.Name == "" {
		return vmCreateSpec{}, fmt.Errorf("sandbox name is required")
	}
	if request.SandboxID != "" && request.SandboxID != core.ID(request.Name) {
		return vmCreateSpec{}, fmt.Errorf("VM backend cannot honor a distinct sandbox id")
	}
	if request.Workspace.Kind != driver.WorkspaceGuestOverlay {
		return vmCreateSpec{}, fmt.Errorf("VM backend requires workspace kind %q", driver.WorkspaceGuestOverlay)
	}
	if request.Workspace.HostPath != "" {
		return vmCreateSpec{}, fmt.Errorf("VM guest-overlay workspace must not include a host path")
	}
	if !request.Workspace.Persist {
		return vmCreateSpec{}, fmt.Errorf("VM backend requires a persistent guest-overlay workspace")
	}
	// The VM state store owns one persistent overlay per sandbox. Workspace.ID
	// stays a control-plane association and does not select a host directory.
	if len(request.Mounts) != 0 {
		return vmCreateSpec{}, fmt.Errorf("VM backend does not support host mount requests")
	}
	configJSON := ""
	if request.Config != nil {
		encoded, err := json.Marshal(request.Config)
		if err != nil {
			return vmCreateSpec{}, fmt.Errorf("encode VM driver config: %w", err)
		}
		configJSON = string(encoded)
	}
	env := driver.SupervisorTelemetryEnvironment(ctx, request.Runtime.TelemetryEndpoint, request.Workload.Environment)
	spec := vmCreateSpec{
		Name: request.Name, Image: request.Workload.Image,
		Command: slices.Clone(request.Workload.Command), TTY: request.Workload.TTY,
		AwaitMainProcessAttachment: request.Workload.AwaitMainProcessAttachment,
		MainProcessRestartPolicy:   request.Workload.RestartPolicy,
		Env:                        env,
		GatewayURL:                 request.Network.GatewayURL,
		// Gateway identity remains control-plane-owned. The URL is used by the
		// guest relay when the driver config has no explicit endpoint.
		PersistVolume: request.Workspace.Persist,
		GPU:           request.Resources.GPU, GPUCount: request.Resources.GPUCount,
		CDIDevices: slices.Clone(request.Resources.CDIDevices),
		CPU:        request.Resources.CPUCores, MemoryBytes: request.Resources.MemoryBytes,
		PidsLimit: request.Resources.PIDs,
		InitBin:   request.Runtime.InitBinary, SupervisorBin: request.Runtime.SupervisorBinary,
		NoHarden: request.Runtime.NoHarden, EnableSSH: request.Runtime.EnableSSH,
		SSHBin:      request.Runtime.SSHBinary,
		DisplayMode: request.Runtime.DisplayMode, DisplayPort: request.Runtime.DisplayPort,
		DisplayPassword: request.Runtime.DisplayPassword,
		Labels:          extensionActivationLabels(request.Labels), IKnow: request.AllowUnsafeMount,
		ExtraHosts:       slices.Clone(request.Network.ExtraHosts),
		PublishPorts:     slices.Clone(request.Network.PortPublish),
		DriverConfigJSON: configJSON,
	}
	if request.Network.Proxy != nil {
		spec.ProxyBin = request.Network.Proxy.Binary
		spec.ProxyImage = request.Network.Proxy.Image
		spec.PolicyPath = request.Network.Proxy.PolicyPath
		spec.ProxyPort = request.Network.Proxy.Port
		spec.ProxyEnv = slices.Clone(request.Network.Proxy.Environment)
	}
	return spec, nil
}
