package vm

import (
	"fmt"
	"os"
)

// KrunLaunchConfig is the guest boot configuration passed to libkrun. Disk
// preparation and sandbox state ownership are handled by the VM driver before
// this structure is built.
type KrunLaunchConfig struct {
	RootDisk        string
	OverlayDisk     string
	ImageDisk       string
	ServiceDataDisk string
	VCPUs           uint8
	MemoryMiB       uint32
	KrunLogLevel    uint32
	WorkDir         string
	ExecPath        string
	Args            []string
	Env             []string
	ConsolePath     string
	VsockPort       uint32
	VsockSocket     string
	VsockPorts      []KrunVsockPort
}

// KrunVsockPort maps a guest-initiated AF_VSOCK connection to a host Unix
// socket. Listen=false means libkrun dials Socket when the guest connects.
type KrunVsockPort struct {
	Port   uint32
	Socket string
	Listen bool
}

func removeStaleUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket path %q", path)
	}
	return os.Remove(path)
}
