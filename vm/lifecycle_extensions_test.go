//go:build darwin || linux

package vm

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type recordingLifecycleExtension struct {
	name            string
	activation      ExtensionActivation
	descriptor      ExtensionDescriptor
	calls           *[]string
	configure       func(*ExtensionLaunchPlan) error
	before          func(*ExtensionLaunchPlan) error
	restoreErr      error
	afterRestoreErr error
}

func (extension *recordingLifecycleExtension) Name() string { return extension.name }
func (extension *recordingLifecycleExtension) Activation() ExtensionActivation {
	return extension.activation
}
func (extension *recordingLifecycleExtension) Descriptor() ExtensionDescriptor {
	return extension.descriptor
}
func (extension *recordingLifecycleExtension) ConfigureLaunch(_ context.Context, _ vmCreateSpec, _ string, plan *ExtensionLaunchPlan) error {
	*extension.calls = append(*extension.calls, extension.name+":configure")
	if extension.configure != nil {
		return extension.configure(plan)
	}
	return nil
}
func (extension *recordingLifecycleExtension) BeforeLaunch(_ context.Context, _ vmCreateSpec, _ string, plan *ExtensionLaunchPlan) error {
	*extension.calls = append(*extension.calls, extension.name+":before")
	if extension.before != nil {
		return extension.before(plan)
	}
	return nil
}
func (extension *recordingLifecycleExtension) AfterLaunchFailed(_ context.Context, _ string, reason LaunchAbortReason) error {
	*extension.calls = append(*extension.calls, extension.name+":failed:"+string(reason))
	return nil
}
func (extension *recordingLifecycleExtension) AfterDelete(_ context.Context, _ string) error {
	*extension.calls = append(*extension.calls, extension.name+":delete")
	return nil
}
func (extension *recordingLifecycleExtension) BeforeRestore(_ context.Context, restore ExtensionRestoreContext) error {
	if extension.restoreErr != nil {
		*extension.calls = append(*extension.calls, extension.name+":before-restore-failed")
		return extension.restoreErr
	}
	if restore.ExtensionStateDir == "" {
		return fmt.Errorf("extension restore state dir is unset")
	}
	*extension.calls = append(*extension.calls, extension.name+":before-restore")
	return nil
}
func (extension *recordingLifecycleExtension) AfterRestore(_ context.Context, restore ExtensionRestoreContext) error {
	if restore.ExtensionStateDir == "" || restore.Status != "running" {
		return fmt.Errorf("extension restore context is incomplete")
	}
	*extension.calls = append(*extension.calls, extension.name+":after-restore")
	return extension.afterRestoreErr
}

func TestAfterRestoreFailureCleansExtensionResources(t *testing.T) {
	var calls []string
	extension := &recordingLifecycleExtension{name: "resource", calls: &calls, afterRestoreErr: fmt.Errorf("resource setup failed")}
	registry, err := NewLifecycleExtensionRegistry(extension)
	if err != nil {
		t.Fatal(err)
	}
	registry.AfterRestore(context.Background(), ExtensionRestoreContext{SandboxID: "sandbox-1", StateDir: t.TempDir(), Status: "running"}, []string{"resource"})
	want := []string{"resource:after-restore", "resource:failed:restore-failed"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("AfterRestore failure calls = %v, want %v", calls, want)
	}
}

func TestLifecycleExtensionRegistryActivationOrderingAndCleanup(t *testing.T) {
	var calls []string
	global := &recordingLifecycleExtension{name: "alpha", calls: &calls}
	requested := &recordingLifecycleExtension{name: "relay", activation: ExtensionActivation{RequestKey: "ssh-relay"}, calls: &calls}
	registry, err := NewLifecycleExtensionRegistry(global, requested)
	if err != nil {
		t.Fatal(err)
	}
	spec := vmCreateSpec{Labels: map[string]string{SandboxExtensionLabelPrefix + "ssh-relay": "enabled"}}
	plan := &ExtensionLaunchPlan{}
	stateDir := t.TempDir()
	if err := registry.ConfigureLaunch(context.Background(), spec, stateDir, plan); err != nil {
		t.Fatalf("ConfigureLaunch() error = %v", err)
	}
	if err := registry.BeforeLaunch(context.Background(), spec, stateDir, registry.ActiveNames(spec), plan); err != nil {
		t.Fatalf("BeforeLaunch() error = %v", err)
	}
	wantCalls := []string{"alpha:configure", "relay:configure", "alpha:before", "relay:before"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("extension calls = %v; want %v", calls, wantCalls)
	}
	registry.AfterLaunchFailed(context.Background(), stateDir, registry.ActiveNames(spec), LaunchAbortProcessExited)
	restore := ExtensionRestoreContext{SandboxID: "sandbox-1", StateDir: stateDir, Status: "stopped"}
	if err := registry.BeforeRestore(context.Background(), restore, registry.ActiveNames(spec)); err != nil {
		t.Fatalf("BeforeRestore() error = %v", err)
	}
	registry.AfterRestore(context.Background(), ExtensionRestoreContext{SandboxID: "sandbox-1", StateDir: stateDir, Status: "running"}, registry.ActiveNames(spec))
	registry.AfterDelete(context.Background(), stateDir, registry.ActiveNames(spec))
	wantCalls = append(wantCalls, "relay:failed:process-exited", "alpha:failed:process-exited", "alpha:before-restore", "relay:before-restore", "alpha:after-restore", "relay:after-restore", "relay:delete", "alpha:delete")
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("extension cleanup calls = %v; want %v", calls, wantCalls)
	}
	if names := registry.ActiveNames(vmCreateSpec{}); !reflect.DeepEqual(names, []string{"alpha"}) {
		t.Fatalf("active extensions without request label = %v", names)
	}
}

func TestLifecycleExtensionRegistryRejectsBadRegistrationAndLaunchPlan(t *testing.T) {
	for _, extension := range []*recordingLifecycleExtension{
		{name: "../escape"},
		{name: "mismatch", descriptor: ExtensionDescriptor{Name: "other"}},
		{name: "bad-key", activation: ExtensionActivation{RequestKey: "../key"}},
		{name: "bad-capability", descriptor: ExtensionDescriptor{Name: "bad-capability", Provides: ExtensionCapabilities{LaunchFeatures: []string{"bad/key"}}}},
	} {
		if _, err := NewLifecycleExtensionRegistry(extension); err == nil {
			t.Errorf("invalid extension %q was accepted", extension.name)
		}
	}
	if _, err := NewLifecycleExtensionRegistry(&recordingLifecycleExtension{name: "same"}, &recordingLifecycleExtension{name: "same"}); err == nil {
		t.Fatal("duplicate extension names were accepted")
	}

	calls := []string{}
	extension := &recordingLifecycleExtension{name: "dropins", calls: &calls, configure: func(plan *ExtensionLaunchPlan) error {
		plan.GuestInitDropins = append(plan.GuestInitDropins,
			GuestInitDropin{Name: "50-first.sh", Contents: []byte("#!/bin/sh\n")},
			GuestInitDropin{Name: "50-first.sh", Contents: []byte("#!/bin/sh\n")},
		)
		return nil
	}}
	registry, err := NewLifecycleExtensionRegistry(extension)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ConfigureLaunch(context.Background(), vmCreateSpec{}, t.TempDir(), &ExtensionLaunchPlan{}); err == nil {
		t.Fatal("duplicate guest init drop-ins were accepted")
	}
	supported, err := NewLifecycleExtensionRegistry(&recordingLifecycleExtension{
		name: "dropin-feature", calls: &calls,
		configure: func(plan *ExtensionLaunchPlan) error {
			plan.GuestInitDropins = append(plan.GuestInitDropins, GuestInitDropin{Name: "10-ready", Contents: []byte("#!/bin/sh\n")})
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := &ExtensionLaunchPlan{}
	if err := supported.ConfigureLaunch(context.Background(), vmCreateSpec{}, t.TempDir(), plan); err != nil {
		t.Fatalf("ConfigureLaunch() rejected supported guest-init feature: %v", err)
	}
	if !reflect.DeepEqual(plan.RequiredBackendFeatures, []string{BackendFeatureGuestInitDropins}) {
		t.Fatalf("required backend features = %v, want guest-init-dropins", plan.RequiredBackendFeatures)
	}
	unsupported, err := NewLifecycleExtensionRegistry(&recordingLifecycleExtension{
		name: "vfio", calls: &calls,
		descriptor: ExtensionDescriptor{Name: "vfio", RequiredBackendFeatures: []string{BackendFeaturePCIPassthrough}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := unsupported.ConfigureLaunch(context.Background(), vmCreateSpec{}, t.TempDir(), &ExtensionLaunchPlan{}); err == nil || !strings.Contains(err.Error(), "does not support required feature") {
		t.Fatalf("ConfigureLaunch() error for unsupported backend feature = %v", err)
	}
	if err := validateExtensionLaunchPlan(&ExtensionLaunchPlan{Environment: []string{"INVALID"}}); err == nil {
		t.Fatal("malformed extension environment was accepted")
	}
	if err := validateExtensionLaunchPlan(&ExtensionLaunchPlan{GuestInitDropins: []GuestInitDropin{{Name: "../escape", Contents: []byte("x")}}}); err == nil {
		t.Fatal("path-unsafe guest init drop-in was accepted")
	}
	if err := validateExtensionLaunchPlan(&ExtensionLaunchPlan{Environment: []string{"TOKEN=secret\x00value"}}); err == nil {
		t.Fatal("NUL in extension environment was accepted")
	}
}

func TestLifecycleExtensionActivationLabelsRequireRegisteredPolicyLabel(t *testing.T) {
	var calls []string
	registered, err := NewLifecycleExtensionRegistry(&recordingLifecycleExtension{
		name: "ssh", activation: ExtensionActivation{RequestKey: "ssh-relay"}, calls: &calls,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"enabled", "true", "1", "yes", "on", "disabled", "false", "0", "no", "off"} {
		spec := vmCreateSpec{Labels: map[string]string{SandboxExtensionLabelPrefix + "ssh-relay": value}}
		if err := registered.ValidateActivationLabels(spec); err != nil {
			t.Errorf("ValidateActivationLabels(%q) error = %v", value, err)
		}
	}
	if err := registered.ValidateActivationLabels(vmCreateSpec{Labels: map[string]string{SandboxExtensionLabelPrefix + "unknown": "enabled"}}); err == nil || !strings.Contains(err.Error(), "unregistered") {
		t.Fatalf("unknown extension label error = %v", err)
	}
	if err := registered.ValidateActivationLabels(vmCreateSpec{Labels: map[string]string{SandboxExtensionLabelPrefix + "ssh-relay": "maybe"}}); err == nil || !strings.Contains(err.Error(), "invalid value") {
		t.Fatalf("invalid extension label value error = %v", err)
	}
	if _, err := NewLifecycleExtensionRegistry(
		&recordingLifecycleExtension{name: "one", activation: ExtensionActivation{RequestKey: "same"}},
		&recordingLifecycleExtension{name: "two", activation: ExtensionActivation{RequestKey: "same"}},
	); err == nil || !strings.Contains(err.Error(), "share activation key") {
		t.Fatalf("duplicate activation key error = %v", err)
	}
}
