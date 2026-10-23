//go:build darwin || linux

package vm

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-driver/driver"
)

func TestBackendCapabilitiesAdvertiseRuntimeExtensions(t *testing.T) {
	info, err := (*Driver)(nil).Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Resources == nil || info.Resources.CPU == nil || info.Resources.Memory == nil || info.Resources.GPU == nil {
		t.Fatalf("VM backend omitted OpenShell VM resource capability fields: %+v", info.Resources)
	}
	if info.Resources.CPU.LimitSupported || info.Resources.Memory.LimitSupported {
		t.Fatalf("VM backend must report that CPU/memory limit overrides are unsupported: %+v", info.Resources)
	}
	if info.Resources.GPU.DefaultSelectionSupported || info.Resources.GPU.CountSelectionSupported {
		t.Fatalf("VM backend without GPU enablement must not advertise GPU selection: %+v", info.Resources.GPU)
	}
	for _, capability := range []driver.Capability{
		driver.CapabilityPlatformEvents,
		driver.CapabilitySandboxWatch,
		driver.CapabilityInteractiveExec,
		driver.CapabilityPTY,
		driver.CapabilityExecTerminal,
		driver.CapabilityLogAccess,
		driver.CapabilityFileTransfer,
		driver.CapabilityLaunchSpecRestore,
		driver.CapabilityTokenAwareStart,
		driver.CapabilityGatewayRuntimeValidation,
		driver.CapabilityProxyReadiness,
		driver.CapabilityRootfsTarStaging,
	} {
		if !info.Has(capability) {
			t.Errorf("VM backend omitted capability %q", capability)
		}
	}
}
