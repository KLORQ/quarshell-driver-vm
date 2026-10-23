package vm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	corepaths "github.com/KLORQ/quarshell-core/paths"
)

const defaultRootfsTarMaxBytes int64 = 10 * 1024 * 1024 * 1024
const defaultRootfsImageCacheMaxBytes int64 = 64 * 1024 * 1024 * 1024

// defaultVMSandboxImage matches OpenShell v0.1.4's default_sandbox_image().
const defaultVMSandboxImage = "nvcr.io/nvidia/base/ubuntu:24.04"

// HostConfig selects the libkrun runtime bundle and host virtualization device.
// RuntimeDir follows OpenShell's OPENSHELL_VM_RUNTIME_DIR override.
type HostConfig struct {
	RuntimeDir string
	// GRPCEndpoint is the Gateway supervisor gRPC endpoint supplied to the
	// guest. OpenShell keeps this host deployment setting out of sandbox config.
	GRPCEndpoint                      string
	DefaultImage                      string
	AllowDriverConfig                 bool
	SandboxUID                        *uint32
	SandboxGID                        *uint32
	GuestTLSCA                        string
	CorporateProxyURL                 string
	CorporateProxyNoProxy             string
	CorporateProxyAuthFile            string
	CorporateProxyAuthAllowInsecure   *bool
	CorporateProxyConnectByHostname   *bool
	CorporateProxyCABundle            string
	ProviderSPIFFEWorkloadAPIEndpoint string
	ProviderSPIFFEAllowGuestTCP       bool
	// BootstrapImage overrides the trusted DefaultImage fallback for the
	// OpenShell-style two-disk boot layout.
	BootstrapImage               string
	BootstrapDisk                string
	KVMDevice                    string
	StateDir                     string
	RootfsTarDir                 string
	RootfsTarMaxBytes            int64
	RootfsImageCacheMaxBytes     int64
	FormatterPath                string
	OverlaySizeBytes             uint64
	ServiceDataDiskSizeBytes     uint64
	GuestAgentPath               string
	UMOCIPath                    string
	WorkerPath                   string
	WorkerTeamID                 string
	WorkerSHA256                 string
	VCPUs                        uint8
	MemoryMiB                    uint32
	KrunLogLevel                 *uint32
	kvmDeviceCheck               func(string) error
	workerIsolation              func() (workerIsolationConfig, error)
	workerProcessAttributes      func() *syscall.SysProcAttr
	workerSignatureVerifier      func(string, string) error
	workerAdHocSignatureVerifier func(string) error
	LifecycleExtensions          []LifecycleExtension
	imagePrepRunner              func(context.Context, HostConfig, string, string, string) error
	imagePrepVerifier            func(string, string) error
}

// HostCapabilities describes the runtime path accepted by the OpenShell-style
// libkrun backend. Linux uses KVM; macOS ARM64 uses Hypervisor.framework.
type HostCapabilities struct {
	OS           string
	Architecture string
	Hypervisor   string
	RuntimeDir   string
}

// DefaultHostConfig reads the VM runtime override and supplies the KVM device.
func DefaultHostConfig() HostConfig {
	runtimeDir := strings.TrimSpace(os.Getenv("OPENSHELL_VM_RUNTIME_DIR"))
	if runtimeDir == "" {
		runtimeDir = defaultRuntimeBundleDir()
	}
	defaultImage := strings.TrimSpace(os.Getenv("OPENSHELL_SANDBOX_IMAGE"))
	bootstrapImage := strings.TrimSpace(os.Getenv("OPENSHELL_VM_BOOTSTRAP_IMAGE"))
	bootstrapDisk := strings.TrimSpace(os.Getenv("CAUTEM_VM_BOOTSTRAP_DISK"))
	kvmDevice := strings.TrimSpace(os.Getenv("CAUTEM_KVM_DEVICE"))
	if kvmDevice == "" {
		kvmDevice = "/dev/kvm"
	}
	stateDir := defaultStateDir()
	rootfsTarDir := strings.TrimSpace(os.Getenv("OPENSHELL_VM_ROOTFS_TAR_STAGING_DIR"))
	rootfsImageCacheMaxBytes := defaultRootfsImageCacheMaxBytes
	if raw := strings.TrimSpace(os.Getenv("CAUTEM_VM_IMAGE_CACHE_MAX_BYTES")); raw != "" {
		if parsed, parseErr := strconv.ParseInt(raw, 10, 64); parseErr == nil && parsed > 0 {
			rootfsImageCacheMaxBytes = parsed
		}
	}
	guestAgentPath := strings.TrimSpace(os.Getenv("CAUTEM_VM_GUEST_AGENT"))
	if guestAgentPath == "" {
		guestAgentPath = defaultGuestAgentPath()
	}
	umociPath := strings.TrimSpace(os.Getenv("CAUTEM_VM_UMOCI"))
	if umociPath == "" {
		umociPath = defaultGuestUMOCIPath(guestAgentPath)
	}
	workerPath := strings.TrimSpace(os.Getenv("CAUTEM_VM_WORKER"))
	workerTeamID := strings.TrimSpace(os.Getenv("CAUTEM_VM_WORKER_TEAM_ID"))
	workerSHA256 := strings.TrimSpace(os.Getenv("CAUTEM_VM_WORKER_SHA256"))
	grpcEndpoint := strings.TrimSpace(os.Getenv("OPENSHELL_GRPC_ENDPOINT"))
	config := normalizeHostConfig(HostConfig{
		RuntimeDir: runtimeDir, GRPCEndpoint: grpcEndpoint, DefaultImage: defaultImage, BootstrapImage: bootstrapImage, BootstrapDisk: bootstrapDisk, KVMDevice: kvmDevice, StateDir: stateDir,
		RootfsTarDir: rootfsTarDir, RootfsTarMaxBytes: defaultRootfsTarMaxBytes,
		RootfsImageCacheMaxBytes: rootfsImageCacheMaxBytes,
		GuestAgentPath:           guestAgentPath, UMOCIPath: umociPath, WorkerPath: workerPath, WorkerTeamID: workerTeamID, WorkerSHA256: workerSHA256,
		KrunLogLevel: uint32Pointer(1),
	})
	if strings.TrimSpace(config.BootstrapImage) == "" {
		// Match OpenShell's trusted configured fallback. The sandbox-selected
		// image is never promoted to a bootstrap image implicitly.
		config.BootstrapImage = config.DefaultImage
	}
	return config
}

// defaultRuntimeBundleDir follows OpenShell's XDG data location for VM runtime
// assets. Unlike upstream's embedded build resources, this Go module currently
// requires an operator-provided compatible bundle at this path or via env.
func defaultRuntimeBundleDir() string {
	root, err := corepaths.OpenShellDataDir()
	if err != nil {
		return ""
	}
	return filepath.Join(root, "vm-runtime")
}

func defaultGuestAgentPath() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	path := filepath.Join(filepath.Dir(executable), "cautem-vm-guest-agent-linux-"+runtime.GOARCH)
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
		return path
	}
	return ""
}

func defaultGuestUMOCIPath(guestAgentPath string) string {
	if guestAgentPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(guestAgentPath), "cautem-vm-umoci-linux-"+runtime.GOARCH)
}

func normalizeHostConfig(config HostConfig) HostConfig {
	if config.KrunLogLevel == nil {
		config.KrunLogLevel = uint32Pointer(1)
	}
	if strings.TrimSpace(config.StateDir) == "" {
		config.StateDir = defaultStateDir()
	}
	if strings.TrimSpace(config.DefaultImage) == "" {
		config.DefaultImage = defaultVMSandboxImage
	}
	if strings.TrimSpace(config.RootfsTarDir) == "" && strings.TrimSpace(config.StateDir) != "" {
		config.RootfsTarDir = filepath.Join(config.StateDir, "rootfs-tar-staging")
	}
	if config.RootfsTarMaxBytes <= 0 {
		config.RootfsTarMaxBytes = defaultRootfsTarMaxBytes
	}
	if config.RootfsImageCacheMaxBytes <= 0 {
		config.RootfsImageCacheMaxBytes = defaultRootfsImageCacheMaxBytes
	}
	if strings.TrimSpace(config.UMOCIPath) == "" {
		config.UMOCIPath = defaultGuestUMOCIPath(config.GuestAgentPath)
	}
	if config.VCPUs == 0 {
		config.VCPUs = 2
	}
	if config.MemoryMiB == 0 {
		config.MemoryMiB = 2048
	}
	if strings.TrimSpace(config.KVMDevice) == "" {
		config.KVMDevice = "/dev/kvm"
	}
	return config
}

func uint32Pointer(value uint32) *uint32 { return &value }

func configuredKrunLogLevel(config HostConfig) uint32 {
	if config.KrunLogLevel == nil {
		return 1
	}
	return *config.KrunLogLevel
}

// ProbeHost verifies the current host and installed libkrun runtime bundle. It
// does not create directories, alter device permissions, or modify networking.
func ProbeHost(config HostConfig) (HostCapabilities, error) {
	return probeHost(runtime.GOOS, runtime.GOARCH, config)
}

func probeHost(goos, goarch string, config HostConfig) (HostCapabilities, error) {
	caps := HostCapabilities{OS: goos, Architecture: goarch, RuntimeDir: config.RuntimeDir}
	libName, fwName, platformErr := libKrunLibraryNames(goos, goarch)
	if platformErr != nil {
		return HostCapabilities{}, platformErr
	}
	switch goos {
	case "linux":
		caps.Hypervisor = "KVM"
		checkKVM := config.kvmDeviceCheck
		if checkKVM == nil {
			checkKVM = checkKVMDevice
		}
		if err := checkKVM(config.KVMDevice); err != nil {
			return HostCapabilities{}, err
		}
	case "darwin":
		caps.Hypervisor = "Hypervisor.framework"
	}
	if strings.TrimSpace(config.RuntimeDir) == "" {
		return HostCapabilities{}, fmt.Errorf("VM runtime directory is unset; set OPENSHELL_VM_RUNTIME_DIR")
	}
	info, err := os.Stat(config.RuntimeDir)
	if err != nil {
		return HostCapabilities{}, fmt.Errorf("VM runtime directory %q is unavailable: %w", config.RuntimeDir, err)
	}
	if !info.IsDir() {
		return HostCapabilities{}, fmt.Errorf("VM runtime path %q is not a directory", config.RuntimeDir)
	}
	for _, name := range []string{libName, fwName} {
		if err := checkRuntimeLibrary(filepath.Join(config.RuntimeDir, name)); err != nil {
			return HostCapabilities{}, err
		}
	}
	return caps, nil
}

func libKrunLibraryNames(goos, goarch string) (lib, fw string, err error) {
	switch {
	case goos == "linux" && (goarch == "amd64" || goarch == "arm64"):
		return "libkrun.so", "libkrunfw.so.5", nil
	case goos == "darwin" && goarch == "arm64":
		return "libkrun.dylib", "libkrunfw.5.dylib", nil
	default:
		return "", "", fmt.Errorf("unsupported MicroVM host %s/%s; supported: Linux amd64/arm64, macOS arm64", goos, goarch)
	}
}

func checkRuntimeLibrary(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("libkrun runtime file %q is unavailable: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect libkrun runtime file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("libkrun runtime file %q must be a non-empty regular file", path)
	}
	return nil
}
