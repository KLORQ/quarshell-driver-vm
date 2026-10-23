package vm

import "github.com/KLORQ/quarshell-driver/driver"

// vmCreateSpec is the VM-owned launch input consumed by image preparation,
// guest runtime setup, and lifecycle extensions.
type vmCreateSpec struct {
	Name                       string
	Image                      string
	Workspace                  string
	GatewayID                  string
	Command                    []string
	TTY                        bool
	AwaitMainProcessAttachment bool
	MainProcessRestartPolicy   string
	Env                        []string
	IKnow                      bool
	ProxyBin                   string
	PolicyPath                 string
	ProxyPort                  int
	ProxyEnv                   []string
	InitBin                    string
	NoHarden                   bool
	SupervisorBin              string
	DisplayMode                string
	DisplayPort                int
	DisplayPassword            string
	Labels                     map[string]string
	ExtraHosts                 []string
	GatewayURL                 string
	PersistVolume              bool
	EnableSSH                  bool
	SSHBin                     string
	GPU                        bool
	GPUCount                   int
	CDIDevices                 []string
	CPU                        float64
	MemoryBytes                int64
	PidsLimit                  int64
	ProxyImage                 string
	PublishPorts               []driver.PortPublish
	DriverConfigJSON           string
}
