package vm

import "github.com/KLORQ/quarshell-driver/driver"

func (*Driver) backendInfo() driver.BackendInfo {
	return driver.BackendInfo{
		ID:                  "vm",
		Version:             driver.BackendVersion,
		ConfigSchemaVersion: driver.ConfigSchemaVersionV1,
		Resources: &driver.ResourceCapabilities{
			CPU:    &driver.CPUResourceCapabilities{LimitSupported: false},
			Memory: &driver.MemoryResourceCapabilities{LimitSupported: false},
			GPU:    &driver.GPUResourceCapabilities{DefaultSelectionSupported: false, CountSelectionSupported: false},
		},
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityTokenAwareStart:          {},
			driver.CapabilityPlatformEvents:           {},
			driver.CapabilitySandboxWatch:             {},
			driver.CapabilityInteractiveExec:          {},
			driver.CapabilityPTY:                      {},
			driver.CapabilityExecTerminal:             {},
			driver.CapabilityLogAccess:                {},
			driver.CapabilityFileTransfer:             {},
			driver.CapabilityLaunchSpecRestore:        {},
			driver.CapabilityGatewayRuntimeValidation: {},
			driver.CapabilityProxyReadiness:           {},
			driver.CapabilityRootfsTarStaging:         {},
		},
	}
}
