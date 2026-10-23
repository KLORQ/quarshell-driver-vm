//go:build darwin || linux

package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
)

// libKrunAPI mirrors the C ABI used by OpenShell's libkrun runtime. Function
// pointers are loaded at runtime so the driver can build without libkrun
// installed and select the matching Linux or macOS bundle on the host.
type libKrunAPI struct {
	handle               uintptr
	supportHandle        uintptr
	initLog              func(int32, uint32, uint32, uint32) int32
	createCtx            func() int32
	freeCtx              func(uint32) int32
	setVMConfig          func(uint32, uint8, uint32) int32
	addDisk              func(uint32, string, string, bool) int32
	setRootDiskRemount   func(uint32, string, string, string) int32
	setWorkdir           func(uint32, string) int32
	setExec              func(uint32, string, unsafe.Pointer, unsafe.Pointer) int32
	setConsoleOutput     func(uint32, string) int32
	startEnter           func(uint32) int32
	disableImplicitVsock func(uint32) int32
	addVsock             func(uint32, uint32) int32
	addVsockPort         func(uint32, uint32, string, bool) int32
}

type krunContext struct {
	api    *libKrunAPI
	id     uint32
	closed bool
}

const (
	krunLogTargetDefault int32  = -1
	krunLogLevelTrace    uint32 = 5
	krunLogStyleAuto     uint32 = 0
	krunLogOptionNoEnv   uint32 = 1
)

var (
	loadedLibKrunMu sync.Mutex
	loadedLibKrun   = map[string]*libKrunAPI{}
)

func loadLibKrun(runtimeDir string) (*libKrunAPI, error) {
	loadedLibKrunMu.Lock()
	defer loadedLibKrunMu.Unlock()
	if api := loadedLibKrun[runtimeDir]; api != nil {
		return api, nil
	}

	libName, fwName, err := libKrunLibraryNames(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	libPath := filepath.Join(runtimeDir, libName)
	fwPath := filepath.Join(runtimeDir, fwName)
	if err := checkRuntimeLibrary(libPath); err != nil {
		return nil, err
	}
	if err := checkRuntimeLibrary(fwPath); err != nil {
		return nil, err
	}

	// libkrun may resolve libkrunfw symbols when it is loaded. Load fw with
	// RTLD_GLOBAL first, matching the upstream OpenShell loader.
	fwHandle, err := purego.Dlopen(fwPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("load libkrun support library %q: %w", fwPath, err)
	}
	handle, err := purego.Dlopen(libPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		_ = purego.Dlclose(fwHandle)
		return nil, fmt.Errorf("load libkrun library %q: %w", libPath, err)
	}

	api := &libKrunAPI{handle: handle, supportHandle: fwHandle}
	for _, symbol := range []struct {
		name   string
		target any
	}{
		{"krun_init_log", &api.initLog},
		{"krun_create_ctx", &api.createCtx},
		{"krun_free_ctx", &api.freeCtx},
		{"krun_set_vm_config", &api.setVMConfig},
		{"krun_add_disk", &api.addDisk},
		{"krun_set_root_disk_remount", &api.setRootDiskRemount},
		{"krun_set_workdir", &api.setWorkdir},
		{"krun_set_exec", &api.setExec},
		{"krun_set_console_output", &api.setConsoleOutput},
		{"krun_start_enter", &api.startEnter},
		{"krun_disable_implicit_vsock", &api.disableImplicitVsock},
		{"krun_add_vsock", &api.addVsock},
		{"krun_add_vsock_port2", &api.addVsockPort},
	} {
		address, err := purego.Dlsym(handle, symbol.name)
		if err != nil {
			_ = purego.Dlclose(handle)
			_ = purego.Dlclose(fwHandle)
			return nil, fmt.Errorf("load libkrun symbol %s from %q: %w", symbol.name, libPath, err)
		}
		purego.RegisterFunc(symbol.target, address)
	}
	// Keep both handles loaded until process exit: function pointers and
	// libkrun's references to libkrunfw remain valid for the lifetime of VMs.
	loadedLibKrun[runtimeDir] = api
	return api, nil
}

func newKrunContext(api *libKrunAPI, config KrunLaunchConfig) (*krunContext, error) {
	if api == nil {
		return nil, fmt.Errorf("libkrun API is not loaded")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if ret := api.initLog(krunLogTargetDefault, clampKrunLogLevel(config.KrunLogLevel), krunLogStyleAuto, krunLogOptionNoEnv); ret < 0 {
		return nil, fmt.Errorf("krun_init_log failed with status %d", ret)
	}
	id := api.createCtx()
	if id < 0 {
		return nil, fmt.Errorf("krun_create_ctx failed with status %d", id)
	}
	ctx := &krunContext{api: api, id: uint32(id)}
	if err := ctx.configure(config); err != nil {
		if freeErr := ctx.Close(); freeErr != nil {
			return nil, fmt.Errorf("%w (also failed to free context: %v)", err, freeErr)
		}
		return nil, err
	}
	return ctx, nil
}

func clampKrunLogLevel(level uint32) uint32 {
	if level > krunLogLevelTrace {
		return krunLogLevelTrace
	}
	return level
}

func (c KrunLaunchConfig) validate() error {
	if c.RootDisk == "" || c.OverlayDisk == "" || c.ExecPath == "" || c.WorkDir == "" || c.ConsolePath == "" {
		return fmt.Errorf("libkrun launch config requires root disk, overlay disk, executable, workdir and console path")
	}
	for label, value := range map[string]string{
		"root disk": c.RootDisk, "overlay disk": c.OverlayDisk, "console path": c.ConsolePath,
	} {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("libkrun %s path must be absolute", label)
		}
	}
	if c.ImageDisk != "" && !filepath.IsAbs(c.ImageDisk) {
		return fmt.Errorf("libkrun image disk path must be absolute")
	}
	if c.ServiceDataDisk != "" && !filepath.IsAbs(c.ServiceDataDisk) {
		return fmt.Errorf("libkrun service data disk path must be absolute")
	}
	if (c.VsockPort == 0) != (c.VsockSocket == "") {
		return fmt.Errorf("libkrun vsock port and host socket must be configured together")
	}
	seenPorts := make(map[uint32]struct{}, len(c.VsockPorts)+1)
	if c.VsockPort != 0 {
		seenPorts[c.VsockPort] = struct{}{}
		if err := validateVsockSocketPath(c.VsockSocket); err != nil {
			return err
		}
	}
	for _, mapping := range c.VsockPorts {
		if mapping.Port == 0 {
			return fmt.Errorf("libkrun vsock mapping port must be positive")
		}
		if _, duplicate := seenPorts[mapping.Port]; duplicate {
			return fmt.Errorf("libkrun vsock port %d is configured more than once", mapping.Port)
		}
		seenPorts[mapping.Port] = struct{}{}
		if err := validateVsockSocketPath(mapping.Socket); err != nil {
			return err
		}
	}
	if !strings.HasPrefix(c.ExecPath, "/") || !strings.HasPrefix(c.WorkDir, "/") {
		return fmt.Errorf("libkrun guest executable and workdir must be absolute paths")
	}
	for _, value := range []string{c.RootDisk, c.OverlayDisk, c.ImageDisk, c.ServiceDataDisk, c.ConsolePath, c.ExecPath, c.WorkDir} {
		if strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("libkrun launch paths must not contain NUL bytes")
		}
	}
	if c.VCPUs == 0 || c.MemoryMiB == 0 {
		return fmt.Errorf("libkrun launch config requires positive vCPU and memory values")
	}
	return nil
}

func validateVsockSocketPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("libkrun vsock host socket path must be absolute and contain no NUL bytes")
	}
	if len(path) > 96 {
		return fmt.Errorf("libkrun vsock host socket path exceeds the portable Unix socket limit")
	}
	return nil
}

func (c *krunContext) configure(config KrunLaunchConfig) error {
	if config.KrunLogLevel >= 4 {
		logKrunVsockSocketPermissions(config.VsockPorts)
	}
	if err := checkKrun("krun_set_vm_config", c.api.setVMConfig(c.id, config.VCPUs, config.MemoryMiB)); err != nil {
		return err
	}
	for _, disk := range []struct {
		id       string
		path     string
		readOnly bool
	}{
		{"root", config.RootDisk, true},
		{"overlay", config.OverlayDisk, false},
	} {
		if err := checkKrun("krun_add_disk", c.api.addDisk(c.id, disk.id, disk.path, disk.readOnly)); err != nil {
			return err
		}
	}
	if config.ImageDisk != "" {
		if err := checkKrun("krun_add_disk", c.api.addDisk(c.id, "image", config.ImageDisk, true)); err != nil {
			return err
		}
	}
	if config.ServiceDataDisk != "" {
		if err := checkKrun("krun_add_disk", c.api.addDisk(c.id, "service-data", config.ServiceDataDisk, false)); err != nil {
			return err
		}
	}
	if err := checkKrun("krun_set_root_disk_remount", c.api.setRootDiskRemount(c.id, "/dev/vda", "ext4", "ro")); err != nil {
		return err
	}
	if err := checkKrun("krun_set_workdir", c.api.setWorkdir(c.id, config.WorkDir)); err != nil {
		return err
	}
	if err := checkKrun("krun_disable_implicit_vsock", c.api.disableImplicitVsock(c.id)); err != nil {
		return err
	}
	// TSI feature mask 0 deliberately disables libkrun's transparent IP/Unix
	// socket interception. The policy broker is the only guest egress path.
	if err := checkKrun("krun_add_vsock", c.api.addVsock(c.id, 0)); err != nil {
		return err
	}
	ports := make([]KrunVsockPort, 0, len(config.VsockPorts)+1)
	if config.VsockSocket != "" {
		ports = append(ports, KrunVsockPort{Port: config.VsockPort, Socket: config.VsockSocket, Listen: true})
	}
	ports = append(ports, config.VsockPorts...)
	for _, mapping := range ports {
		// A guest-initiated mapping connects libkrun to a host listener owned by
		// the broker (or relay control server). Removing that socket here would
		// unlink the live listener after its readiness check.
		if mapping.Listen {
			if err := removeStaleUnixSocket(mapping.Socket); err != nil {
				return fmt.Errorf("prepare libkrun vsock host socket: %w", err)
			}
		}
		if err := checkKrun("krun_add_vsock_port2", c.api.addVsockPort(c.id, mapping.Port, mapping.Socket, mapping.Listen)); err != nil {
			return err
		}
	}
	if err := checkKrun("krun_set_console_output", c.api.setConsoleOutput(c.id, config.ConsolePath)); err != nil {
		return err
	}
	argvOwners, argv, err := cStringVector(config.Args)
	if err != nil {
		return fmt.Errorf("encode libkrun argv: %w", err)
	}
	envValues := libkrunGuestEnvironment(config.Env)
	envOwners, env, err := cStringVector(envValues)
	if err != nil {
		return fmt.Errorf("encode libkrun environment: %w", err)
	}
	if err := checkKrun("krun_set_exec", c.api.setExec(c.id, config.ExecPath, argv, env)); err != nil {
		return err
	}
	runtime.KeepAlive(argvOwners)
	runtime.KeepAlive(argv)
	runtime.KeepAlive(envOwners)
	runtime.KeepAlive(env)
	return nil
}

func logKrunVsockSocketPermissions(mappings []KrunVsockPort) {
	fmt.Fprintf(os.Stderr, "libkrun vsock socket diagnostics: uid=%d euid=%d gid=%d egid=%d\n", os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid())
	for _, mapping := range mappings {
		for current := mapping.Socket; current != "/"; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil {
				fmt.Fprintf(os.Stderr, "libkrun vsock socket path component %q: %v\n", current, err)
				continue
			}
			owner := "unknown"
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				owner = fmt.Sprintf("uid=%d gid=%d", stat.Uid, stat.Gid)
			}
			fmt.Fprintf(os.Stderr, "libkrun vsock socket path component %q: mode=%#o %s\n", current, info.Mode().Perm(), owner)
		}
	}
}

func libkrunGuestEnvironment(environment []string) []string {
	values := make([]string, 0, len(environment)+1)
	for _, value := range environment {
		if !strings.HasPrefix(value, "KRUN_INIT_PID1=") {
			values = append(values, value)
		}
	}
	return append(values, "KRUN_INIT_PID1=1")
}

// StartEnter blocks until the guest workload exits. The VM driver must call it
// from an isolated worker process so the host driver can manage lifecycle.
func (c *krunContext) StartEnter() int32 {
	return c.api.startEnter(c.id)
}

func (c *krunContext) Close() error {
	if c == nil || c.closed {
		return nil
	}
	c.closed = true
	if ret := c.api.freeCtx(c.id); ret < 0 {
		return fmt.Errorf("krun_free_ctx failed with status %d", ret)
	}
	return nil
}

func checkKrun(operation string, status int32) error {
	if status < 0 {
		return fmt.Errorf("%s failed with status %d", operation, status)
	}
	return nil
}

func cStringVector(values []string) ([][]byte, unsafe.Pointer, error) {
	owners := make([][]byte, len(values))
	pointers := make([]unsafe.Pointer, len(values)+1)
	for index, value := range values {
		if strings.IndexByte(value, 0) >= 0 {
			return nil, nil, fmt.Errorf("value %d contains NUL byte", index)
		}
		owners[index] = append([]byte(value), 0)
		pointers[index] = unsafe.Pointer(&owners[index][0])
	}
	return owners, unsafe.Pointer(unsafe.SliceData(pointers)), nil
}
