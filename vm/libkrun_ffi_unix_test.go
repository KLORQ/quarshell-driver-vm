//go:build darwin || linux

package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestNewKrunContextConfiguresCompatDiskAndVsockPattern(t *testing.T) {
	var calls []string
	api := fakeLibKrunAPI(&calls)
	config := KrunLaunchConfig{
		RootDisk:        "/vm/base.ext4",
		OverlayDisk:     "/vm/overlay.ext4",
		ImageDisk:       "/vm/image.ext4",
		ServiceDataDisk: "/vm/service-data.ext4",
		VCPUs:           2,
		MemoryMiB:       2048,
		WorkDir:         "/sandbox",
		ExecPath:        "/usr/bin/cautem-supervisor",
		Args:            []string{"--sandbox", "test"},
		Env:             []string{"HOME=/root", "PATH=/usr/bin"},
		ConsolePath:     "/vm/console.log",
	}
	ctx, err := newKrunContext(api, config)
	if err != nil {
		t.Fatalf("newKrunContext() error = %v", err)
	}
	want := []string{
		"init_log", "create_ctx", "set_vm_config", "add_disk:root:true",
		"add_disk:overlay:false", "add_disk:image:true", "add_disk:service-data:false", "set_root_disk_remount",
		"set_workdir", "disable_implicit_vsock", "add_vsock:tsi=0", "set_console_output", "set_exec",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("libkrun call sequence = %#v; want %#v", calls, want)
	}
	if ctx.StartEnter() != 0 {
		t.Fatal("StartEnter() should forward guest exit status")
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if calls[len(calls)-1] != "free_ctx" {
		t.Fatalf("last call = %q; want free_ctx", calls[len(calls)-1])
	}
}

func TestNewKrunContextFreesContextWhenConfigurationFails(t *testing.T) {
	var calls []string
	api := fakeLibKrunAPI(&calls)
	api.setWorkdir = func(uint32, string) int32 { calls = append(calls, "set_workdir"); return -5 }
	_, err := newKrunContext(api, validKrunConfig())
	if err == nil || !strings.Contains(err.Error(), "krun_set_workdir failed with status -5") {
		t.Fatalf("newKrunContext() error = %v; want workdir error", err)
	}
	if calls[len(calls)-1] != "free_ctx" {
		t.Fatalf("context wasn't freed after setup error: calls=%v", calls)
	}
}

func TestKrunConfigAndCStringVectorRejectUnsafeValues(t *testing.T) {
	config := validKrunConfig()
	config.VCPUs = 0
	var calls []string
	if _, err := newKrunContext(fakeLibKrunAPI(&calls), config); err == nil || !strings.Contains(err.Error(), "positive vCPU") {
		t.Fatalf("invalid resource config error = %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("invalid config invoked libkrun: %v", calls)
	}
	config = validKrunConfig()
	config.WorkDir = "relative"
	if _, err := newKrunContext(fakeLibKrunAPI(&calls), config); err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("relative guest workdir error = %v", err)
	}
	if _, _, err := cStringVector([]string{"ok", "bad\x00value"}); err == nil {
		t.Fatal("cStringVector accepted embedded NUL")
	}
}

func TestKrunGuestEnvironmentForcesPIDOneAndVsockMapping(t *testing.T) {
	got := libkrunGuestEnvironment([]string{"KRUN_INIT_PID1=0", "HOME=/root", "KRUN_INIT_PID1=unexpected"})
	count := 0
	for _, entry := range got {
		if strings.HasPrefix(entry, "KRUN_INIT_PID1=") {
			count++
			if entry != "KRUN_INIT_PID1=1" {
				t.Fatalf("PID1 override = %q", entry)
			}
		}
	}
	if count != 1 {
		t.Fatalf("PID1 entries = %v", got)
	}
	var calls []string
	api := fakeLibKrunAPI(&calls)
	config := validKrunConfig()
	config.VsockPort = guestControlPort
	root, err := os.MkdirTemp("/tmp", "vm-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	config.VsockSocket = filepath.Join(root, "guest.sock")
	guest, err := newKrunContext(api, config)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	if !containsCall(calls, "add_vsock_port") {
		t.Fatalf("vsock mapping wasn't configured: %v", calls)
	}
}

func TestKrunConfigMapsHostListeningPolicyBrokerVsock(t *testing.T) {
	var calls []string
	api := fakeLibKrunAPI(&calls)
	api.addVsockPort = func(_ uint32, port uint32, socket string, listen bool) int32 {
		calls = append(calls, fmt.Sprintf("add_vsock_port:%d:%s:%t", port, socket, listen))
		return 0
	}
	config := validKrunConfig()
	config.VsockPorts = []KrunVsockPort{{Port: networkBrokerVsockPort, Socket: "/tmp/cautem-vm-proxy.sock", Listen: true}}
	guest, err := newKrunContext(api, config)
	if err != nil {
		t.Fatalf("newKrunContext() error = %v", err)
	}
	defer guest.Close()
	want := "add_vsock_port:5501:/tmp/cautem-vm-proxy.sock:true"
	if !containsCall(calls, want) {
		t.Fatalf("host-listening policy broker mapping was not configured: calls=%v", calls)
	}
	config.VsockPorts = append(config.VsockPorts, KrunVsockPort{Port: networkBrokerVsockPort, Socket: "/tmp/other.sock", Listen: true})
	if _, err := newKrunContext(api, config); err == nil || !strings.Contains(err.Error(), "configured more than once") {
		t.Fatalf("duplicate vsock mapping error = %v", err)
	}
}

func TestKrunConfigurePreparesHostListeningVsockSocket(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "vm-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socket := filepath.Join(root, "broker.sock")
	config := validKrunConfig()
	config.VsockPorts = []KrunVsockPort{{Port: networkBrokerVsockPort, Socket: socket, Listen: true}}
	var calls []string
	api := fakeLibKrunAPI(&calls)
	api.addVsockPort = func(_ uint32, port uint32, path string, listen bool) int32 {
		calls = append(calls, fmt.Sprintf("add_vsock_port:%d:%s:%t", port, path, listen))
		return 0
	}
	guest, err := newKrunContext(api, config)
	if err != nil {
		t.Fatalf("newKrunContext() error = %v", err)
	}
	defer guest.Close()
	if containsCall(calls, "add_vsock_port:5501:"+socket+":false") || !containsCall(calls, "add_vsock_port:5501:"+socket+":true") {
		t.Fatalf("host-listening vsock endpoint was not configured: calls=%v", calls)
	}
}

func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

func validKrunConfig() KrunLaunchConfig {
	return KrunLaunchConfig{
		RootDisk: "/vm/base.ext4", OverlayDisk: "/vm/overlay.ext4",
		VCPUs: 1, MemoryMiB: 1024, WorkDir: "/sandbox",
		ExecPath: "/bin/sh", ConsolePath: "/vm/console.log",
	}
}

func fakeLibKrunAPI(calls *[]string) *libKrunAPI {
	return &libKrunAPI{
		initLog:     func(int32, uint32, uint32, uint32) int32 { *calls = append(*calls, "init_log"); return 0 },
		createCtx:   func() int32 { *calls = append(*calls, "create_ctx"); return 42 },
		freeCtx:     func(uint32) int32 { *calls = append(*calls, "free_ctx"); return 0 },
		setVMConfig: func(uint32, uint8, uint32) int32 { *calls = append(*calls, "set_vm_config"); return 0 },
		addDisk: func(_ uint32, id, _ string, readOnly bool) int32 {
			*calls = append(*calls, "add_disk:"+id+":"+map[bool]string{true: "true", false: "false"}[readOnly])
			return 0
		},
		setRootDiskRemount: func(uint32, string, string, string) int32 { *calls = append(*calls, "set_root_disk_remount"); return 0 },
		setWorkdir:         func(uint32, string) int32 { *calls = append(*calls, "set_workdir"); return 0 },
		setExec: func(_ uint32, _ string, argv, env unsafe.Pointer) int32 {
			if argv == nil || env == nil {
				return -1
			}
			*calls = append(*calls, "set_exec")
			return 0
		},
		setConsoleOutput:     func(uint32, string) int32 { *calls = append(*calls, "set_console_output"); return 0 },
		startEnter:           func(uint32) int32 { *calls = append(*calls, "start_enter"); return 0 },
		disableImplicitVsock: func(uint32) int32 { *calls = append(*calls, "disable_implicit_vsock"); return 0 },
		addVsock: func(_ uint32, features uint32) int32 {
			*calls = append(*calls, fmt.Sprintf("add_vsock:tsi=%d", features))
			return 0
		},
		addVsockPort: func(uint32, uint32, string, bool) int32 { *calls = append(*calls, "add_vsock_port"); return 0 },
	}
}
