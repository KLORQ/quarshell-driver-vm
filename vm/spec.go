package vm

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-driver/driver"
)

func (d *Driver) validateCreateSpec(spec vmCreateSpec) error {
	if d == nil {
		return fmt.Errorf("vm driver: driver is nil")
	}
	if d.lifecycleExtensionsErr != nil {
		return fmt.Errorf("vm driver lifecycle extensions: %w", d.lifecycleExtensionsErr)
	}
	config, err := ParseSandboxDriverConfig(spec.DriverConfigJSON)
	if err != nil {
		return err
	}
	spec = d.applyDefaultImage(spec)
	if err := validateMainProcessRestartPolicy(spec); err != nil {
		return err
	}
	if spec.AwaitMainProcessAttachment && !spec.TTY {
		return fmt.Errorf("vm driver: awaiting a main-process attachment requires a TTY workload")
	}
	if err := validateGPURequest(spec.GPU, config); err != nil {
		return err
	}
	if err := validateResourceLimits(spec.CPU, spec.MemoryBytes); err != nil {
		return err
	}
	if err := validateNetworkBrokerSpec(spec); err != nil {
		return err
	}
	if err := validateGuestRuntimeAssets(spec); err != nil {
		return err
	}
	if err := validateSupportedSpec(spec); err != nil {
		return err
	}
	if err := d.lifecycleExtensions.ValidateActivationLabels(spec); err != nil {
		return err
	}
	if config.RootfsTarPath == "" && strings.TrimSpace(spec.Image) == "" {
		return fmt.Errorf("vm driver: image or rootfs_tar_path is required")
	}
	if config.RootfsTarPath == "" {
		if _, err := parseOCIImageReference(spec.Image); err != nil {
			return fmt.Errorf("vm driver: %w", err)
		}
	}
	return nil
}

// applyDefaultImage mirrors OpenShell's operator-configured default_image
// fallback when the sandbox does not request an image explicitly.
func (d *Driver) applyDefaultImage(spec vmCreateSpec) vmCreateSpec {
	if strings.TrimSpace(spec.Image) == "" && d != nil {
		spec.Image = strings.TrimSpace(d.host.DefaultImage)
	}
	return spec
}

func validateMainProcessRestartPolicy(spec vmCreateSpec) error {
	policy, err := driver.NormalizeMainProcessRestartPolicy(spec.MainProcessRestartPolicy)
	if err != nil {
		return fmt.Errorf("vm driver: %w", err)
	}
	if policy != "never" && spec.SupervisorBin == "" {
		return fmt.Errorf("vm driver: main process restart policy requires supervisor_bin")
	}
	return nil
}

// validateResourceLimits ensures requested resources can be represented by
// libkrun's public VM configuration without silently changing the request.
func validateResourceLimits(cpu float64, memoryBytes int64) error {
	if math.IsNaN(cpu) || math.IsInf(cpu, 0) || cpu < 0 {
		return fmt.Errorf("vm driver: CPU limit must be finite and non-negative")
	}
	if cpu > 0 && math.Ceil(cpu) > float64(^uint8(0)) {
		return fmt.Errorf("vm driver: CPU limit %.3g exceeds libkrun maximum of %d vCPUs", cpu, ^uint8(0))
	}
	if memoryBytes < 0 {
		return fmt.Errorf("vm driver: memory limit must be non-negative")
	}
	if memoryBytes > 0 {
		const mebibyte = uint64(1 << 20)
		maxBytes := uint64(^uint32(0)) * mebibyte
		if uint64(memoryBytes) > maxBytes {
			return fmt.Errorf("vm driver: memory limit exceeds libkrun maximum of %d MiB", ^uint32(0))
		}
	}
	return nil
}

// validateGatewayRuntime checks the selected host profile before Gateway
// lifecycle state or one-shot rootfs uploads are consumed. Gateway starts
// then attach and confirm the VM backend through isolation.Registry before
// releasing the guest's one-shot workload start gate.
func (d *Driver) validateGatewayRuntime(ctx context.Context) error {
	if d == nil {
		return fmt.Errorf("vm driver: driver is nil")
	}
	if d.lifecycleExtensionsErr != nil {
		return fmt.Errorf("vm driver: invalid lifecycle extension registry: %w", d.lifecycleExtensionsErr)
	}
	if _, err := probeHost(runtime.GOOS, runtime.GOARCH, d.host); err != nil {
		return fmt.Errorf("vm driver: Gateway host preflight failed: %w", err)
	}
	worker, err := workerPath(d.host.WorkerPath)
	if err != nil {
		return fmt.Errorf("vm driver: Gateway host preflight failed: %w", err)
	}
	if runtime.GOOS == "darwin" {
		if err := validateGatewayWorkerTrust(worker, d.host); err != nil {
			return fmt.Errorf("vm driver: Gateway host preflight failed: %w", err)
		}
	}
	if strings.TrimSpace(d.host.GuestAgentPath) == "" {
		return fmt.Errorf("vm driver: Gateway host preflight failed: guest agent path is unset")
	}
	if _, err := validateExecutablePath(d.host.GuestAgentPath); err != nil {
		return fmt.Errorf("vm driver: Gateway host preflight failed: guest agent: %w", err)
	}
	isolationCheck := d.host.workerIsolation
	if isolationCheck == nil {
		isolationCheck = workerIsolationForChild
	}
	isolation, err := isolationCheck()
	if err != nil {
		return fmt.Errorf("vm driver: Gateway host preflight failed: worker isolation prerequisites: %w", err)
	}
	probeConfig := workerConfig{Isolation: isolation, ProbeIsolation: true}
	probeInput, err := workerConfigJSON(probeConfig)
	if err != nil {
		return fmt.Errorf("vm driver: encode worker isolation probe: %w", err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	probe := exec.CommandContext(probeCtx, worker)
	probe.Env = workerEnvironment(d.host.RuntimeDir)
	probe.Stdin = strings.NewReader(string(probeInput))
	attributes := d.host.workerProcessAttributes
	if attributes == nil {
		attributes = workerProcessAttributes
	}
	probe.SysProcAttr = attributes()
	if output, err := probe.CombinedOutput(); err != nil {
		return fmt.Errorf("vm driver: Gateway host preflight failed: isolated worker probe: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func validateGatewayWorkerTrust(worker string, host HostConfig) error {
	teamID := strings.TrimSpace(host.WorkerTeamID)
	workerHash := strings.TrimSpace(host.WorkerSHA256)
	if teamID == "" && workerHash == "" {
		return fmt.Errorf("configure CAUTEM_VM_WORKER_TEAM_ID or CAUTEM_VM_WORKER_SHA256 to trust the macOS VM worker")
	}
	if teamID != "" {
		verify := host.workerSignatureVerifier
		if verify == nil {
			verify = verifyWorkerCodeSignature
		}
		if err := verify(worker, teamID); err != nil {
			return fmt.Errorf("VM worker signature is not trusted: %w", err)
		}
	} else {
		verifyAdHoc := host.workerAdHocSignatureVerifier
		if verifyAdHoc == nil {
			verifyAdHoc = verifyWorkerAdHocSignature
		}
		if err := verifyAdHoc(worker); err != nil {
			return fmt.Errorf("VM worker ad-hoc signature is invalid: %w", err)
		}
	}
	if workerHash != "" {
		if err := verifyWorkerSHA256(worker, workerHash); err != nil {
			return fmt.Errorf("VM worker digest is not trusted: %w", err)
		}
	}
	return nil
}

func validateNetworkBrokerSpec(spec vmCreateSpec) error {
	configured := spec.ProxyBin != "" || spec.PolicyPath != "" || spec.ProxyPort != 0 || len(spec.ProxyEnv) != 0
	if !configured {
		return nil
	}
	if spec.ProxyBin == "" || spec.PolicyPath == "" {
		return fmt.Errorf("vm driver: policy network broker requires both proxy_bin and policy_path")
	}
	if spec.ProxyPort < 0 || spec.ProxyPort > 65535 {
		return fmt.Errorf("vm driver: policy proxy port must be between 1 and 65535")
	}
	if !filepath.IsAbs(spec.ProxyBin) || filepath.Clean(spec.ProxyBin) != spec.ProxyBin {
		return fmt.Errorf("vm driver: policy proxy binary path must be a clean absolute path")
	}
	if _, err := validateExecutablePath(spec.ProxyBin); err != nil {
		return fmt.Errorf("vm driver: policy proxy binary: %w", err)
	}
	if !filepath.IsAbs(spec.PolicyPath) || filepath.Clean(spec.PolicyPath) != spec.PolicyPath {
		return fmt.Errorf("vm driver: policy path must be a clean absolute path")
	}
	policyInfo, err := os.Lstat(spec.PolicyPath)
	if err != nil {
		return fmt.Errorf("vm driver: inspect policy file: %w", err)
	}
	if !policyInfo.Mode().IsRegular() || policyInfo.Mode()&os.ModeSymlink != 0 || policyInfo.Size() == 0 || policyInfo.Size() > 4<<20 || policyInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("vm driver: policy file must be a non-empty regular file no larger than 4 MiB and not writable by group or others")
	}
	if err := validateNetworkBrokerEnvironment(spec.ProxyEnv); err != nil {
		return err
	}
	return nil
}

func validateNetworkBrokerEnvironment(entries []string) error {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !validBrokerEnvKey(key) || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("vm driver: policy proxy environment contains an invalid entry")
		}
		if strings.HasPrefix(key, "LD_") || strings.HasPrefix(key, "DYLD_") || key == "PATH" || key == "HOME" {
			return fmt.Errorf("vm driver: policy proxy environment may not override %s or dynamic loader settings", key)
		}
		if key == "CAUTEM_HOST_PARENT_LIVENESS" {
			return fmt.Errorf("vm driver: policy proxy environment may not override host lifecycle controls")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("vm driver: policy proxy environment contains duplicate key %s", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateGuestRuntimeAssets(spec vmCreateSpec) error {
	supervisorConfigured := spec.SupervisorBin != ""
	sshConfigured := spec.EnableSSH || spec.SSHBin != ""
	if !supervisorConfigured && !sshConfigured {
		if spec.InitBin != "" {
			return fmt.Errorf("vm driver: init_bin requires supervisor_bin or SSH relay")
		}
		return nil
	}
	if spec.InitBin == "" {
		return fmt.Errorf("vm driver: hardened init binary is required for supervisor and SSH relay")
	}
	if sshConfigured && !supervisorConfigured {
		return fmt.Errorf("vm driver: SSH relay requires the workload supervisor")
	}
	if spec.ProxyBin == "" || spec.PolicyPath == "" {
		return fmt.Errorf("vm driver: supervisor and SSH relay require the per-VM policy proxy")
	}
	for label, path := range map[string]string{"hardened init": spec.InitBin} {
		if _, err := validateExecutablePath(path); err != nil {
			return fmt.Errorf("vm driver: %s binary: %w", label, err)
		}
	}
	if supervisorConfigured {
		if _, err := validateExecutablePath(spec.SupervisorBin); err != nil {
			return fmt.Errorf("vm driver: supervisor binary: %w", err)
		}
	}
	if sshConfigured {
		if !spec.EnableSSH || spec.SSHBin == "" {
			return fmt.Errorf("vm driver: SSH relay requires both ssh=true and ssh_bin")
		}
		if _, err := validateExecutablePath(spec.SSHBin); err != nil {
			return fmt.Errorf("vm driver: SSH daemon binary: %w", err)
		}
	}
	return nil
}

func validBrokerEnvKey(key string) bool {
	if key == "" || key[0] == '=' {
		return false
	}
	for i, char := range key {
		isLetter := char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z'
		isDigit := i > 0 && char >= '0' && char <= '9'
		if char != '_' && !isLetter && !isDigit {
			return false
		}
	}
	return true
}

// validateSupportedSpec prevents the VM backend from silently accepting
// compute guarantees that it does not implement. Keep this list explicit so
// adding fields to vmCreateSpec requires an intentional VM capability decision.
func validateSupportedSpec(spec vmCreateSpec) error {
	unsupported := make([]string, 0, 24)
	add := func(enabled bool, field string) {
		if enabled {
			unsupported = append(unsupported, field)
		}
	}
	add(spec.Workspace != "", "workspace")
	add(spec.GatewayID != "", "gateway_id")
	add(spec.IKnow, "i_know")
	add(spec.NoHarden, "no_harden")
	// Supervisor and SSH binaries are copied into the per-sandbox overlay and
	// run through the guest control agent when their complete contracts validate.
	add(spec.DisplayMode != "", "display_mode")
	add(spec.DisplayPort != 0, "display_port")
	add(spec.DisplayPassword != "", "display_password")
	if err := validateExtensionActivationLabels(spec.Labels); err != nil {
		if strings.Contains(err.Error(), "unsupported spec fields: labels") {
			add(true, "labels")
		} else {
			return err
		}
	}
	add(len(spec.ExtraHosts) != 0, "extra_hosts")
	// VM sandboxes always retain their writable ext4 overlay across Stop/Start,
	// which provides the persistent workspace contract without host volumes.
	add(spec.GPU || spec.GPUCount != 0 || len(spec.CDIDevices) != 0, "gpu")
	add(spec.PidsLimit != 0, "pids_limit")
	add(spec.ProxyImage != "", "proxy_image")
	add(len(spec.PublishPorts) != 0, "publish_ports")
	if len(unsupported) != 0 {
		return fmt.Errorf("vm driver: unsupported spec fields: %s", strings.Join(unsupported, ", "))
	}
	return nil
}
