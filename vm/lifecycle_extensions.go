package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
)

const SandboxExtensionLabelPrefix = "openshell.ai/extension."

const (
	BackendFeatureGuestInitDropins = "guest-init-dropins"
	BackendFeatureExternalKernel   = "external-kernel-image"
	BackendFeaturePCIPassthrough   = "pci-passthrough"
)

const (
	maxGuestInitDropins      = 64
	maxGuestInitDropinsBytes = 1 << 20
)

type ExtensionActivation struct {
	// Empty RequestKey activates the extension globally. Otherwise the
	// policy-controlled label openshell.ai/extension.<RequestKey> must be on.
	RequestKey string
}

type ExtensionCapabilities struct {
	KernelProfiles   []string
	GuestInitDropins []string
	LaunchFeatures   []string
	HostResources    []string
}

type ExtensionDescriptor struct {
	Name                    string
	Provides                ExtensionCapabilities
	RequiredBackendFeatures []string
}

type GuestInitDropin struct {
	Name     string
	Contents []byte
}

type ExtensionLaunchPlan struct {
	Environment             []string
	GuestInitDropins        []GuestInitDropin
	RequiredBackendFeatures []string
}

// ExtensionRestoreContext identifies a persisted sandbox being reconciled
// after the driver process restarts. StateDir is private to the sandbox.
type ExtensionRestoreContext struct {
	SandboxID         string
	SandboxName       string
	Status            string
	StateDir          string
	ExtensionStateDir string
}

type LaunchAbortReason string

const (
	LaunchAbortLauncherSpawnFailed LaunchAbortReason = "launcher-spawn-failed"
	LaunchAbortBeforeLaunchFailed  LaunchAbortReason = "before-launch-hook-failed"
	LaunchAbortGuestPrepareFailed  LaunchAbortReason = "guest-prepare-failed"
	LaunchAbortRestoreFailed       LaunchAbortReason = "restore-failed"
	LaunchAbortProcessExited       LaunchAbortReason = "process-exited"
	LaunchAbortStopped             LaunchAbortReason = "stopped"
)

// LifecycleExtension is the registration identity. Optional interfaces below
// add lifecycle hooks, allowing extensions to implement only the phases they
// need while the registry retains deterministic ordering and cleanup rules.
type LifecycleExtension interface {
	Name() string
}

type lifecycleExtensionActivator interface {
	Activation() ExtensionActivation
}

type lifecycleExtensionDescriptor interface {
	Descriptor() ExtensionDescriptor
}

type lifecycleExtensionConfigurer interface {
	ConfigureLaunch(context.Context, vmCreateSpec, string, *ExtensionLaunchPlan) error
}

type lifecycleExtensionBeforeLauncher interface {
	BeforeLaunch(context.Context, vmCreateSpec, string, *ExtensionLaunchPlan) error
}

type lifecycleExtensionFailureHandler interface {
	AfterLaunchFailed(context.Context, string, LaunchAbortReason) error
}

type lifecycleExtensionDeleteHandler interface {
	AfterDelete(context.Context, string) error
}

type lifecycleExtensionBeforeRestorer interface {
	BeforeRestore(context.Context, ExtensionRestoreContext) error
}

type lifecycleExtensionAfterRestorer interface {
	AfterRestore(context.Context, ExtensionRestoreContext) error
}

type LifecycleExtensionRegistry struct {
	extensions []LifecycleExtension
	byName     map[string]LifecycleExtension
}

func NewLifecycleExtensionRegistry(extensions ...LifecycleExtension) (*LifecycleExtensionRegistry, error) {
	registry := &LifecycleExtensionRegistry{extensions: append([]LifecycleExtension(nil), extensions...), byName: make(map[string]LifecycleExtension, len(extensions))}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	return registry, nil
}

func (registry *LifecycleExtensionRegistry) Validate() error {
	if registry == nil {
		return nil
	}
	registry.byName = make(map[string]LifecycleExtension, len(registry.extensions))
	for _, extension := range registry.extensions {
		if extension == nil {
			return fmt.Errorf("VM lifecycle extension is nil")
		}
		name := extension.Name()
		if err := validateExtensionName(name); err != nil {
			return fmt.Errorf("VM lifecycle extension name: %w", err)
		}
		if _, exists := registry.byName[name]; exists {
			return fmt.Errorf("duplicate VM lifecycle extension name %q", name)
		}
		if activator, ok := extension.(lifecycleExtensionActivator); ok && activator.Activation().RequestKey != "" {
			if err := validateExtensionIdentifier(activator.Activation().RequestKey); err != nil {
				return fmt.Errorf("VM lifecycle extension %q has invalid activation key: %w", name, err)
			}
		}
		if provider, ok := extension.(lifecycleExtensionDescriptor); ok {
			descriptor := provider.Descriptor()
			if descriptor.Name == "" {
				descriptor.Name = name
			}
			if descriptor.Name != name {
				return fmt.Errorf("VM lifecycle extension %q descriptor name does not match", name)
			}
			for _, value := range extensionDescriptorIdentifiers(descriptor) {
				if err := validateExtensionIdentifier(value); err != nil {
					return fmt.Errorf("VM lifecycle extension %q has invalid capability %q: %w", name, value, err)
				}
			}
		}
		registry.byName[name] = extension
	}
	requestKeys := make(map[string]string)
	for _, extension := range registry.extensions {
		activator, ok := extension.(lifecycleExtensionActivator)
		if !ok || activator.Activation().RequestKey == "" {
			continue
		}
		key := activator.Activation().RequestKey
		if previous, exists := requestKeys[key]; exists {
			return fmt.Errorf("VM lifecycle extensions %q and %q share activation key %q", previous, extension.Name(), key)
		}
		requestKeys[key] = extension.Name()
	}
	return nil
}

func (registry *LifecycleExtensionRegistry) ValidateActivationLabels(spec vmCreateSpec) error {
	if err := validateExtensionActivationLabels(spec.Labels); err != nil {
		return err
	}
	known := make(map[string]struct{})
	if registry != nil {
		for _, extension := range registry.extensions {
			if activator, ok := extension.(lifecycleExtensionActivator); ok && activator.Activation().RequestKey != "" {
				known[activator.Activation().RequestKey] = struct{}{}
			}
		}
	}
	for label := range spec.Labels {
		if !strings.HasPrefix(label, SandboxExtensionLabelPrefix) {
			continue
		}
		key := strings.TrimPrefix(label, SandboxExtensionLabelPrefix)
		if _, ok := known[key]; !ok {
			return fmt.Errorf("VM sandbox requests unregistered lifecycle extension %q", key)
		}
	}
	return nil
}

func (registry *LifecycleExtensionRegistry) Names() []string {
	if registry == nil {
		return nil
	}
	names := make([]string, 0, len(registry.extensions))
	for _, extension := range registry.extensions {
		names = append(names, extension.Name())
	}
	return names
}

func (registry *LifecycleExtensionRegistry) ActiveNames(spec vmCreateSpec) []string {
	if registry == nil {
		return nil
	}
	var names []string
	for _, extension := range registry.extensions {
		activation := ExtensionActivation{}
		if activator, ok := extension.(lifecycleExtensionActivator); ok {
			activation = activator.Activation()
		}
		if activation.RequestKey == "" || extensionRequested(spec.Labels, activation.RequestKey) {
			names = append(names, extension.Name())
		}
	}
	return names
}

func (registry *LifecycleExtensionRegistry) ActiveByNames(names []string) ([]LifecycleExtension, error) {
	if registry == nil && len(names) == 0 {
		return nil, nil
	}
	if registry == nil {
		return nil, fmt.Errorf("VM sandbox requires lifecycle extensions but no registry is configured")
	}
	active := make([]LifecycleExtension, 0, len(names))
	for _, name := range names {
		extension, ok := registry.byName[name]
		if !ok {
			return nil, fmt.Errorf("VM sandbox requires unregistered lifecycle extension %q", name)
		}
		active = append(active, extension)
	}
	return active, nil
}

func (registry *LifecycleExtensionRegistry) ConfigureLaunch(ctx context.Context, spec vmCreateSpec, sandboxStateDir string, plan *ExtensionLaunchPlan) error {
	if plan == nil {
		return fmt.Errorf("VM lifecycle launch plan is nil")
	}
	active, err := registry.ActiveByNames(registry.ActiveNames(spec))
	if err != nil {
		return err
	}
	for _, extension := range active {
		if provider, ok := extension.(lifecycleExtensionDescriptor); ok {
			for _, feature := range provider.Descriptor().RequiredBackendFeatures {
				plan.RequiredBackendFeatures = appendUniqueString(plan.RequiredBackendFeatures, feature)
			}
		}
		stateDir, err := extensionStateDir(sandboxStateDir, extension.Name())
		if err != nil {
			return err
		}
		if err := ensurePrivateDirectory(stateDir); err != nil {
			return fmt.Errorf("create state for VM lifecycle extension %q: %w", extension.Name(), err)
		}
		if hook, ok := extension.(lifecycleExtensionConfigurer); ok {
			if err := hook.ConfigureLaunch(ctx, spec, stateDir, plan); err != nil {
				return fmt.Errorf("VM lifecycle extension %q configure launch: %w", extension.Name(), err)
			}
		}
	}
	if len(plan.GuestInitDropins) != 0 {
		plan.RequiredBackendFeatures = appendUniqueString(plan.RequiredBackendFeatures, BackendFeatureGuestInitDropins)
	}
	return validateExtensionLaunchPlan(plan)
}

func (registry *LifecycleExtensionRegistry) BeforeLaunch(ctx context.Context, spec vmCreateSpec, sandboxStateDir string, names []string, plan *ExtensionLaunchPlan) error {
	if plan == nil {
		return fmt.Errorf("VM lifecycle launch plan is nil")
	}
	active, err := registry.ActiveByNames(names)
	if err != nil {
		return err
	}
	for _, extension := range active {
		stateDir, err := extensionStateDir(sandboxStateDir, extension.Name())
		if err != nil {
			return err
		}
		if hook, ok := extension.(lifecycleExtensionBeforeLauncher); ok {
			requiredFeatures := append([]string(nil), plan.RequiredBackendFeatures...)
			if err := hook.BeforeLaunch(ctx, spec, stateDir, plan); err != nil {
				return fmt.Errorf("VM lifecycle extension %q before launch: %w", extension.Name(), err)
			}
			if !sameStrings(requiredFeatures, plan.RequiredBackendFeatures) {
				return fmt.Errorf("VM lifecycle extension %q cannot add backend requirements after launch configuration", extension.Name())
			}
		}
	}
	return validateExtensionLaunchPlan(plan)
}

func (registry *LifecycleExtensionRegistry) BeforeRestore(ctx context.Context, restore ExtensionRestoreContext, names []string) error {
	active, err := registry.ActiveByNames(names)
	if err != nil {
		return err
	}
	for _, extension := range active {
		stateDir, err := extensionStateDir(restore.StateDir, extension.Name())
		if err != nil {
			return err
		}
		extensionRestore := restore
		extensionRestore.ExtensionStateDir = stateDir
		if hook, ok := extension.(lifecycleExtensionBeforeRestorer); ok {
			if err := hook.BeforeRestore(ctx, extensionRestore); err != nil {
				return fmt.Errorf("VM lifecycle extension %q before restore: %w", extension.Name(), err)
			}
		}
	}
	return nil
}

func (registry *LifecycleExtensionRegistry) AfterRestore(ctx context.Context, restore ExtensionRestoreContext, names []string) {
	active, err := registry.ActiveByNames(names)
	if err != nil {
		return
	}
	failed := false
	for _, extension := range active {
		stateDir, err := extensionStateDir(restore.StateDir, extension.Name())
		if err != nil {
			continue
		}
		extensionRestore := restore
		extensionRestore.ExtensionStateDir = stateDir
		if hook, ok := extension.(lifecycleExtensionAfterRestorer); ok {
			if err := hook.AfterRestore(ctx, extensionRestore); err != nil {
				slog.Warn("VM lifecycle extension after restore failed", "extension", extension.Name(), "sandbox_id", restore.SandboxID, "error", err)
				failed = true
			}
		}
	}
	if failed {
		registry.AfterLaunchFailed(context.Background(), restore.StateDir, names, LaunchAbortRestoreFailed)
	}
}

func (registry *LifecycleExtensionRegistry) AfterLaunchFailed(ctx context.Context, sandboxStateDir string, names []string, reason LaunchAbortReason) {
	active, err := registry.ActiveByNames(names)
	if err != nil {
		return
	}
	for index := len(active) - 1; index >= 0; index-- {
		extension := active[index]
		stateDir, err := extensionStateDir(sandboxStateDir, extension.Name())
		if err != nil {
			continue
		}
		if hook, ok := extension.(lifecycleExtensionFailureHandler); ok {
			if err := hook.AfterLaunchFailed(ctx, stateDir, reason); err != nil {
				slog.Warn("VM lifecycle extension cleanup after launch failure failed", "extension", extension.Name(), "error", err)
			}
		}
	}
}

func (registry *LifecycleExtensionRegistry) AfterDelete(ctx context.Context, sandboxStateDir string, names []string) {
	active, err := registry.ActiveByNames(names)
	if err != nil {
		return
	}
	for index := len(active) - 1; index >= 0; index-- {
		extension := active[index]
		stateDir, err := extensionStateDir(sandboxStateDir, extension.Name())
		if err != nil {
			continue
		}
		if hook, ok := extension.(lifecycleExtensionDeleteHandler); ok {
			if err := hook.AfterDelete(ctx, stateDir); err != nil {
				slog.Warn("VM lifecycle extension cleanup after delete failed", "extension", extension.Name(), "error", err)
			}
		}
	}
}

func extensionRequested(labels map[string]string, key string) bool {
	value := strings.ToLower(strings.TrimSpace(labels[SandboxExtensionLabelPrefix+key]))
	switch value {
	case "enabled", "enable", "requested", "request", "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

func extensionActivationLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		if strings.HasPrefix(key, SandboxExtensionLabelPrefix) {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validateExtensionActivationLabels(labels map[string]string) error {
	for key, value := range labels {
		if !strings.HasPrefix(key, SandboxExtensionLabelPrefix) {
			return fmt.Errorf("vm driver: unsupported spec fields: labels")
		}
		if err := validateExtensionIdentifier(strings.TrimPrefix(key, SandboxExtensionLabelPrefix)); err != nil {
			return fmt.Errorf("vm driver: invalid lifecycle extension label %q: %w", key, err)
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "", "enabled", "enable", "requested", "request", "true", "1", "yes", "on", "disabled", "disable", "false", "0", "no", "off":
		default:
			return fmt.Errorf("vm driver: lifecycle extension label %q has invalid value %q", key, value)
		}
	}
	return nil
}

func extensionStateDir(sandboxStateDir, name string) (string, error) {
	if err := validateExtensionName(name); err != nil {
		return "", err
	}
	if strings.TrimSpace(sandboxStateDir) == "" {
		return "", fmt.Errorf("VM lifecycle extension sandbox state directory is unset")
	}
	return filepath.Join(sandboxStateDir, "extensions", name), nil
}

func validateExtensionLaunchPlan(plan *ExtensionLaunchPlan) error {
	if plan == nil {
		return fmt.Errorf("VM lifecycle launch plan is nil")
	}
	seen := make(map[string]struct{}, len(plan.GuestInitDropins))
	if len(plan.GuestInitDropins) > maxGuestInitDropins {
		return fmt.Errorf("guest init drop-in count exceeds limit %d", maxGuestInitDropins)
	}
	seenFeatures := make(map[string]struct{}, len(plan.RequiredBackendFeatures))
	for _, feature := range plan.RequiredBackendFeatures {
		if err := validateExtensionIdentifier(feature); err != nil {
			return fmt.Errorf("invalid required backend feature %q: %w", feature, err)
		}
		if _, exists := seenFeatures[feature]; exists {
			return fmt.Errorf("duplicate required backend feature %q", feature)
		}
		seenFeatures[feature] = struct{}{}
		if feature != BackendFeatureGuestInitDropins {
			return fmt.Errorf("VM backend does not support required feature %q", feature)
		}
	}
	var dropinBytes int
	for _, dropin := range plan.GuestInitDropins {
		if err := validateExtensionIdentifier(dropin.Name); err != nil {
			return fmt.Errorf("invalid guest init drop-in name %q: %w", dropin.Name, err)
		}
		if strings.ContainsAny(dropin.Name, `/\\`) {
			return fmt.Errorf("guest init drop-in name %q must not contain path separators", dropin.Name)
		}
		if _, exists := seen[dropin.Name]; exists {
			return fmt.Errorf("duplicate guest init drop-in name %q", dropin.Name)
		}
		seen[dropin.Name] = struct{}{}
		if strings.IndexByte(string(dropin.Contents), 0) >= 0 {
			return fmt.Errorf("guest init drop-in %q contains NUL", dropin.Name)
		}
		dropinBytes += len(dropin.Contents)
		if dropinBytes > maxGuestInitDropinsBytes {
			return fmt.Errorf("guest init drop-in contents exceed %d bytes", maxGuestInitDropinsBytes)
		}
	}
	if _, err := mergeLaunchEnvironment(nil, plan.Environment); err != nil {
		return fmt.Errorf("VM lifecycle extension environment: %w", err)
	}
	return nil
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func guestInitDropinsDigest(dropins []GuestInitDropin) (string, error) {
	if err := validateExtensionLaunchPlan(&ExtensionLaunchPlan{GuestInitDropins: dropins}); err != nil {
		return "", err
	}
	if len(dropins) == 0 {
		return "", nil
	}
	ordered := append([]GuestInitDropin(nil), dropins...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	hash := sha256.New()
	for _, dropin := range ordered {
		_, _ = hash.Write([]byte(dropin.Name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(dropin.Contents)
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func validateExtensionName(name string) error {
	if err := validateExtensionIdentifier(name); err != nil {
		return err
	}
	return nil
}

func validateExtensionIdentifier(value string) error {
	if value == "" || value == "." || value == ".." {
		return fmt.Errorf("identifier is empty or reserved")
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9', char == '.', char == '-', char == '_':
		default:
			return fmt.Errorf("identifier must contain only ASCII letters, digits, '.', '-', or '_'")
		}
	}
	return nil
}

func extensionDescriptorIdentifiers(descriptor ExtensionDescriptor) []string {
	values := make([]string, 0, len(descriptor.Provides.KernelProfiles)+len(descriptor.Provides.GuestInitDropins)+len(descriptor.Provides.LaunchFeatures)+len(descriptor.Provides.HostResources)+len(descriptor.RequiredBackendFeatures))
	values = append(values, descriptor.Provides.KernelProfiles...)
	values = append(values, descriptor.Provides.GuestInitDropins...)
	values = append(values, descriptor.Provides.LaunchFeatures...)
	values = append(values, descriptor.Provides.HostResources...)
	values = append(values, descriptor.RequiredBackendFeatures...)
	return values
}
