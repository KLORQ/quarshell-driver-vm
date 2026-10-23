// Package vm contains the OpenShell-style libkrun MicroVM driver.
package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Driver configures and preflights libkrun-backed microVM sandboxes.
type Driver struct {
	host                   HostConfig
	mu                     sync.Mutex
	createGate             chan struct{}
	rotationMu             sync.Mutex
	launchSpecs            map[string]vmLaunchSpec
	launchSpecInputs       map[string]vmLaunchSpec
	pendingRestores        map[string]ExtensionRestoreContext
	workers                map[string]*exec.Cmd
	workerDone             map[string]<-chan error
	brokers                map[string]*networkBrokerProcess
	supervisorForwarders   map[string]context.CancelFunc
	workerLiveness         map[string]*os.File
	localImageEngines      []localImageEngine
	lifecycleExtensions    *LifecycleExtensionRegistry
	lifecycleExtensionsErr error
	// ociNameOptions permits in-package acceptance tests to use a local HTTP
	// registry. Production drivers leave it empty and retain secure defaults.
	ociNameOptions []name.Option
}

// New returns the MicroVM driver using the process host configuration.
func New() *Driver { return NewWithHostConfig(DefaultHostConfig()) }

// NewWithHostConfig returns a MicroVM driver with explicit runtime paths.
func NewWithHostConfig(config HostConfig) *Driver {
	registry, registryErr := NewLifecycleExtensionRegistry(config.LifecycleExtensions...)
	return &Driver{
		host: normalizeHostConfig(config), launchSpecs: make(map[string]vmLaunchSpec),
		launchSpecInputs: make(map[string]vmLaunchSpec), pendingRestores: make(map[string]ExtensionRestoreContext),
		workers: make(map[string]*exec.Cmd), workerDone: make(map[string]<-chan error), brokers: make(map[string]*networkBrokerProcess), supervisorForwarders: make(map[string]context.CancelFunc), workerLiveness: make(map[string]*os.File), createGate: make(chan struct{}, 1),
		lifecycleExtensions: registry, lifecycleExtensionsErr: registryErr,
	}
}

func (d *Driver) createSandbox(ctx context.Context, spec vmCreateSpec) (driver.Handle, error) {
	if ctx == nil {
		return driver.Handle{}, fmt.Errorf("vm driver: Create context is nil")
	}
	if d == nil {
		return driver.Handle{}, fmt.Errorf("vm driver: driver is nil")
	}
	if d.lifecycleExtensionsErr != nil {
		return driver.Handle{}, fmt.Errorf("vm driver lifecycle extensions: %w", d.lifecycleExtensionsErr)
	}
	gate := d.createAdmissionGate()
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-ctx.Done():
		return driver.Handle{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return driver.Handle{}, err
	}
	if err := validateSandboxName(spec.Name); err != nil {
		return driver.Handle{}, err
	}
	if err := d.validateCreateSpec(spec); err != nil {
		return driver.Handle{}, err
	}
	spec = d.applyDefaultImage(spec)
	config, err := ParseSandboxDriverConfig(spec.DriverConfigJSON)
	if err != nil {
		return driver.Handle{}, err
	}
	var archiveFile *os.File
	archivePath := ""
	if config.RootfsTarPath != "" {
		archiveFile, archivePath, err = openRootfsTar(config.RootfsTarPath, d.host.RootfsTarDir, d.host.RootfsTarMaxBytes)
		if err != nil {
			return driver.Handle{}, fmt.Errorf("vm driver rootfs: %w", err)
		}
		defer archiveFile.Close()
	}
	if d.host.GuestAgentPath == "" {
		return driver.Handle{}, fmt.Errorf("vm driver: set QUARSHELL_VM_GUEST_AGENT to the matching static Linux guest agent binary")
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return driver.Handle{}, err
	}
	cacheDir := filepath.Join(store.root, "images")
	assetsDir := filepath.Join(store.root, "sandboxes")
	if err := ensurePrivateDirectory(assetsDir); err != nil {
		return driver.Handle{}, err
	}

	if err := func() error {
		d.mu.Lock()
		defer d.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		states, err := store.list()
		if err != nil {
			return err
		}
		for _, state := range states {
			if state.Name == spec.Name {
				return fmt.Errorf("vm driver: sandbox %q already exists", spec.Name)
			}
		}
		return nil
	}(); err != nil {
		return driver.Handle{}, err
	}
	activeExtensionNames := d.lifecycleExtensions.ActiveNames(spec)
	var rootfsImage string
	var rootfsSourceType, rootfsSourceRef, rootfsSourceDigest, rootfsSourceManifestDigest, imagePlatform string
	var workloadDisk, workloadSourceType, workloadSourceRef, workloadSourceDigest, workloadManifestDigest, workloadPlatform string
	var imageConfig *v1.Config
	if strings.TrimSpace(d.host.BootstrapDisk) != "" {
		info, statErr := os.Stat(d.host.BootstrapDisk)
		if statErr != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return driver.Handle{}, fmt.Errorf("vm driver bootstrap disk is missing or invalid: %s", d.host.BootstrapDisk)
		}
		rootfsSourceType = "tar"
		rootfsSourceRef = "uploaded-tar"
		imagePlatform = "linux/" + runtime.GOARCH
		digestFile, openErr := os.Open(d.host.BootstrapDisk)
		if openErr != nil {
			return driver.Handle{}, fmt.Errorf("open bootstrap disk: %w", openErr)
		}
		rootfsSourceDigest, openErr = digestOpenFile(digestFile)
		_ = digestFile.Close()
		if openErr != nil {
			return driver.Handle{}, fmt.Errorf("digest bootstrap disk: %w", openErr)
		}
		rootfsSourceManifestDigest = ""
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			return driver.Handle{}, fmt.Errorf("create VM image cache: %w", err)
		}
		cachedBootstrap := filepath.Join(cacheDir, "bootstrap-"+rootfsSourceDigest[:16]+".ext4")
		if info, statErr := os.Stat(cachedBootstrap); statErr != nil || !info.Mode().IsRegular() {
			if err := copyRegularFile(d.host.BootstrapDisk, cachedBootstrap, 0o444); err != nil {
				return driver.Handle{}, fmt.Errorf("cache bootstrap disk: %w", err)
			}
			if err := os.Chmod(cachedBootstrap, 0o400); err != nil {
				return driver.Handle{}, fmt.Errorf("make cached bootstrap disk immutable: %w", err)
			}
		}
		rootfsImage = cachedBootstrap

		var workload preparedRootfsImage
		var workloadSource resolvedOCIImage
		if archiveFile != nil {
			workload, workloadSourceDigest, err = prepareRootfsTarWorkloadDiskInGuest(ctx, archiveFile, archivePath, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.UMOCIPath, rootfsImage, d.host, d.host.RootfsTarMaxBytes, d.host.RootfsImageCacheMaxBytes)
			if err != nil {
				return driver.Handle{}, fmt.Errorf("vm driver prepare workload tar disk: %w", err)
			}
			workloadSourceType = "tar"
			workloadSourceRef = "uploaded-tar"
			workloadPlatform = "linux/" + runtime.GOARCH
		} else {
			localImage, localSource, localFound, localErr := prepareLocalOCIImage(ctx, spec.Image, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.RootfsImageCacheMaxBytes, d.localImageEngines)
			if localErr != nil {
				return driver.Handle{}, fmt.Errorf("vm driver import local workload image: %w", localErr)
			}
			if localFound {
				if localSource.LocalArchivePath != "" {
					defer os.Remove(localSource.LocalArchivePath)
				}
				if releaseErr := localImage.Lease.Release(); releaseErr != nil {
					return driver.Handle{}, fmt.Errorf("vm driver release temporary local image lease: %w", releaseErr)
				}
				workloadSource = localSource
				workload, err = prepareOCIWorkloadDiskInGuest(ctx, workloadSource, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.UMOCIPath, rootfsImage, d.host, d.host.RootfsImageCacheMaxBytes)
			} else {
				workloadSource, err = resolveWorkloadOCI(ctx, spec.Image, d.ociNameOptions)
				if err == nil {
					workload, err = prepareOCIWorkloadDiskInGuest(ctx, workloadSource, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.UMOCIPath, rootfsImage, d.host, d.host.RootfsImageCacheMaxBytes)
				}
			}
			if err != nil {
				return driver.Handle{}, fmt.Errorf("vm driver prepare workload OCI disk: %w", err)
			}
			imageConfig = &workloadSource.ImageConfig
			workloadSourceType = "oci"
			if workloadSource.LocalEngineImageID != "" {
				workloadSourceType = "local-oci"
			}
			workloadSourceRef = workloadSource.RequestedReference
			workloadSourceDigest = workloadSource.PlatformManifestDigest
			workloadManifestDigest = workloadSource.SourceManifestDigest
			workloadPlatform = workloadSource.Platform.String()
		}
		workloadDisk = workload.Path
	} else if strings.TrimSpace(d.host.BootstrapImage) != "" {
		bootstrap, source, prepareErr := prepareOCIImageRootfsWithNameOptions(ctx, d.host.BootstrapImage, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.RootfsImageCacheMaxBytes, d.ociNameOptions, d.host.UMOCIPath)
		if prepareErr != nil {
			return driver.Handle{}, fmt.Errorf("vm driver prepare bootstrap root disk: %w", prepareErr)
		}
		rootfsImage = bootstrap.Path
		defer bootstrap.Lease.Release()
		rootfsSourceType = "oci"
		if source.LocalEngineImageID != "" {
			rootfsSourceType = "local-oci"
		}
		rootfsSourceRef = source.RequestedReference
		rootfsSourceDigest = source.PlatformManifestDigest
		rootfsSourceManifestDigest = source.SourceManifestDigest
		imagePlatform = source.Platform.String()

		var workload preparedRootfsImage
		var workloadSource resolvedOCIImage
		if archiveFile != nil {
			workload, workloadSourceDigest, err = prepareRootfsTarWorkloadDiskInGuest(ctx, archiveFile, archivePath, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.UMOCIPath, rootfsImage, d.host, d.host.RootfsTarMaxBytes, d.host.RootfsImageCacheMaxBytes)
			if err != nil {
				return driver.Handle{}, fmt.Errorf("vm driver prepare workload tar disk: %w", err)
			}
			workloadSourceType = "tar"
			workloadSourceRef = "uploaded-tar"
			workloadPlatform = "linux/" + runtime.GOARCH
		} else {
			localImage, localSource, localFound, localErr := prepareLocalOCIImage(ctx, spec.Image, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.RootfsImageCacheMaxBytes, d.localImageEngines)
			if localErr != nil {
				return driver.Handle{}, fmt.Errorf("vm driver import local workload image: %w", localErr)
			}
			if localFound {
				if localSource.LocalArchivePath != "" {
					defer os.Remove(localSource.LocalArchivePath)
				}
				if releaseErr := localImage.Lease.Release(); releaseErr != nil {
					return driver.Handle{}, fmt.Errorf("vm driver release temporary local image lease: %w", releaseErr)
				}
				workloadSource = localSource
				workload, err = prepareOCIWorkloadDiskInGuest(ctx, workloadSource, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.UMOCIPath, rootfsImage, d.host, d.host.RootfsImageCacheMaxBytes)
			} else {
				workloadSource, err = resolveWorkloadOCI(ctx, spec.Image, d.ociNameOptions)
				if err == nil {
					workload, err = prepareOCIWorkloadDiskInGuest(ctx, workloadSource, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.UMOCIPath, rootfsImage, d.host, d.host.RootfsImageCacheMaxBytes)
				}
			}
			if err != nil {
				return driver.Handle{}, fmt.Errorf("vm driver prepare workload OCI disk: %w", err)
			}
			imageConfig = &workloadSource.ImageConfig
			workloadSourceType = "oci"
			if workloadSource.LocalEngineImageID != "" {
				workloadSourceType = "local-oci"
			}
			workloadSourceRef = workloadSource.RequestedReference
			workloadSourceDigest = workloadSource.PlatformManifestDigest
			workloadManifestDigest = workloadSource.SourceManifestDigest
			workloadPlatform = workloadSource.Platform.String()
		}
		workloadDisk = workload.Path
		defer workload.Lease.Release()
	} else if archiveFile != nil {
		prepared, prepareErr := prepareRootfsImageFileWithGuestLease(ctx, archiveFile, archivePath, cacheDir, d.host.FormatterPath, d.host.RootfsTarMaxBytes, d.host.GuestAgentPath, d.host.RootfsImageCacheMaxBytes)
		err = prepareErr
		if err != nil {
			return driver.Handle{}, fmt.Errorf("vm driver prepare rootfs: %w", err)
		}
		rootfsImage = prepared.Path
		defer prepared.Lease.Release()
		rootfsSourceType = "tar"
		rootfsSourceRef = "uploaded-tar"
		rootfsSourceDigest, err = digestOpenFile(archiveFile)
		if err != nil {
			return driver.Handle{}, fmt.Errorf("vm driver identify uploaded rootfs: %w", err)
		}
		imagePlatform = "linux/" + runtime.GOARCH
	} else {
		prepared, source, localFound, localErr := prepareLocalOCIImage(ctx, spec.Image, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.RootfsImageCacheMaxBytes, d.localImageEngines)
		if localErr != nil {
			return driver.Handle{}, fmt.Errorf("vm driver import local OCI image: %w", localErr)
		}
		if !localFound {
			prepared, source, err = prepareOCIImageRootfsWithNameOptions(ctx, spec.Image, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.RootfsImageCacheMaxBytes, d.ociNameOptions)
			if err != nil {
				return driver.Handle{}, fmt.Errorf("vm driver pull and prepare OCI rootfs: %w", err)
			}
		}
		if source.LocalArchivePath != "" {
			defer os.Remove(source.LocalArchivePath)
		}
		rootfsImage = prepared.Path
		imageConfig = &source.ImageConfig
		defer prepared.Lease.Release()
		rootfsSourceType = "oci"
		if source.LocalEngineImageID != "" {
			rootfsSourceType = "local-oci"
		}
		rootfsSourceRef = source.RequestedReference
		rootfsSourceDigest = source.PlatformManifestDigest
		rootfsSourceManifestDigest = source.SourceManifestDigest
		imagePlatform = source.Platform.String()
	}
	launchSpec := cloneVMLaunchSpec(spec)
	if imageConfig != nil {
		launchSpec, err = applyOCIImageConfig(launchSpec, *imageConfig)
		if err != nil {
			return driver.Handle{}, fmt.Errorf("vm driver apply OCI image config: %w", err)
		}
	} else if len(launchSpec.Command) == 0 {
		launchSpec.Command = defaultVMCommand()
	}
	id, err := newSandboxID()
	if err != nil {
		return driver.Handle{}, fmt.Errorf("vm driver: allocate sandbox ID: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	sandboxDir := filepath.Join(assetsDir, id)
	if err := os.Mkdir(sandboxDir, 0o700); err != nil {
		return driver.Handle{}, fmt.Errorf("create VM sandbox asset directory: %w", err)
	}
	creationComplete := false
	defer func() {
		if !creationComplete {
			d.lifecycleExtensions.AfterLaunchFailed(context.Background(), sandboxDir, activeExtensionNames, LaunchAbortBeforeLaunchFailed)
			_ = removePrivateTree(sandboxDir)
		}
	}()
	extensionPlan := &ExtensionLaunchPlan{}
	if err := d.lifecycleExtensions.ConfigureLaunch(ctx, spec, sandboxDir, extensionPlan); err != nil {
		return driver.Handle{}, err
	}
	launchSpec.Env = append(launchSpec.Env, extensionPlan.Environment...)
	if _, err := createControlToken(sandboxDir); err != nil {
		return driver.Handle{}, err
	}
	overlayPath := filepath.Join(sandboxDir, "overlay.ext4")
	dropinsDigest, err := guestInitDropinsDigest(extensionPlan.GuestInitDropins)
	if err != nil {
		return driver.Handle{}, err
	}
	var overlayErr error
	if len(extensionPlan.GuestInitDropins) != 0 {
		sizeBytes := d.host.OverlaySizeBytes
		if sizeBytes == 0 {
			sizeBytes = defaultOverlaySize
		}
		overlayErr = createSandboxOverlayWithDropins(ctx, d.host.FormatterPath, sizeBytes, overlayPath, extensionPlan.GuestInitDropins)
	} else {
		var template string
		template, overlayErr = prepareOverlayTemplate(ctx, filepath.Join(store.root, "templates"), d.host.FormatterPath, d.host.OverlaySizeBytes)
		if overlayErr == nil {
			overlayErr = createSandboxOverlay(template, overlayPath)
		}
	}
	if overlayErr != nil {
		return driver.Handle{}, fmt.Errorf("create VM sandbox overlay: %w", overlayErr)
	}
	serviceDataDisk := ""
	if d.host.ServiceDataDiskSizeBytes != 0 {
		template, templateErr := prepareOverlayTemplate(ctx, filepath.Join(store.root, "templates"), d.host.FormatterPath, d.host.ServiceDataDiskSizeBytes)
		if templateErr != nil {
			return driver.Handle{}, fmt.Errorf("prepare VM service data disk template: %w", templateErr)
		}
		serviceDataDisk = filepath.Join(sandboxDir, "service-data.ext4")
		if err := createSandboxOverlay(template, serviceDataDisk); err != nil {
			return driver.Handle{}, fmt.Errorf("create VM service data disk: %w", err)
		}
	}
	now := time.Now().UTC()
	state := sandboxState{
		Version: sandboxStateVersion, ID: id, Name: spec.Name, Image: spec.Image,
		Rootfs: rootfsImage, RootfsSourceType: rootfsSourceType, RootfsSourceRef: rootfsSourceRef,
		RootfsSourceDigest: rootfsSourceDigest, RootfsSourceManifestDigest: rootfsSourceManifestDigest, Platform: imagePlatform,
		WorkloadDisk: workloadDisk, WorkloadSourceType: workloadSourceType, WorkloadSourceRef: workloadSourceRef,
		WorkloadSourceDigest: workloadSourceDigest, WorkloadManifestDigest: workloadManifestDigest, WorkloadPlatform: workloadPlatform,
		ServiceDataDisk:        serviceDataDisk,
		LifecycleExtensions:    activeExtensionNames,
		LifecycleDropinsDigest: dropinsDigest,
		VCPUs:                  specVCPUs(spec.CPU, d.host.VCPUs),
		MemoryMiB:              specMemoryMiB(spec.MemoryBytes, d.host.MemoryMiB),
		Status:                 "created", CreatedAt: now, UpdatedAt: now,
	}
	if err := store.save(state); err != nil {
		return driver.Handle{}, fmt.Errorf("persist VM sandbox state: %w", err)
	}
	d.launchSpecs[id] = launchSpec
	d.launchSpecInputs[id] = cloneVMLaunchSpec(spec)
	creationComplete = true
	return driver.Handle{ID: core.ID(state.ID), Name: state.Name, Image: state.Image}, nil
}

func (d *Driver) createAdmissionGate() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.createGate == nil {
		d.createGate = make(chan struct{}, 1)
	}
	return d.createGate
}

func digestOpenFile(file *os.File) (string, error) {
	if file == nil {
		return "", fmt.Errorf("rootfs source file is nil")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func cloneVMLaunchSpec(spec vmCreateSpec) vmLaunchSpec {
	cloned := spec
	cloned.Labels = maps.Clone(spec.Labels)
	cloned.Command = append([]string(nil), spec.Command...)
	cloned.Env = append([]string(nil), spec.Env...)
	cloned.ProxyEnv = append([]string(nil), spec.ProxyEnv...)
	cloned.ExtraHosts = append([]string(nil), spec.ExtraHosts...)
	cloned.CDIDevices = append([]string(nil), spec.CDIDevices...)
	cloned.PublishPorts = append([]driver.PortPublish(nil), spec.PublishPorts...)
	return vmLaunchSpec{vmCreateSpec: cloned, WorkDir: "/sandbox"}
}

// RootfsTarStaging exposes the private staging root consumed by the Gateway's
// single-use rootfs archive upload flow.
func (d *Driver) RootfsTarStaging(ctx context.Context) (string, uint64, error) {
	if d == nil {
		return "", 0, fmt.Errorf("vm driver: driver is nil")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
	}
	root := strings.TrimSpace(d.host.RootfsTarDir)
	if root == "" {
		return "", 0, fmt.Errorf("vm driver rootfs staging directory is unset")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", 0, fmt.Errorf("resolve vm rootfs staging directory: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", 0, fmt.Errorf("create vm rootfs staging directory %q: %w", root, err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", 0, fmt.Errorf("inspect vm rootfs staging directory %q: %w", root, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("vm rootfs staging path %q must be a real directory", root)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", 0, fmt.Errorf("secure vm rootfs staging directory %q: %w", root, err)
	}
	return root, uint64(d.host.RootfsTarMaxBytes), nil
}

func (d *Driver) Delete(ctx context.Context, id core.ID) error {
	if d == nil {
		return fmt.Errorf("vm driver: driver is nil")
	}
	if d.lifecycleExtensionsErr != nil {
		return fmt.Errorf("vm driver lifecycle extensions: %w", d.lifecycleExtensionsErr)
	}
	if ctx == nil {
		return fmt.Errorf("vm driver: Delete context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	state, err := store.load(string(id))
	if err != nil {
		if os.IsNotExist(err) && validSandboxID(string(id)) {
			return nil
		}
		return err
	}
	if _, err := d.lifecycleExtensions.ActiveByNames(state.LifecycleExtensions); err != nil {
		return err
	}
	state = d.refreshState(store, state)
	if state.Status == "running" {
		if err := d.stopLocked(ctx, store, state); err != nil {
			return fmt.Errorf("stop VM sandbox before delete: %w", err)
		}
	}
	d.stopNetworkBroker(state.ID)
	d.lifecycleExtensions.AfterDelete(ctx, filepath.Join(store.root, "sandboxes", state.ID), state.LifecycleExtensions)
	workerSocketPath, guestSocketPath, _ := workerSocketPaths(store.root, state.ID)
	for _, socketPath := range []string{
		workerSocketPath, guestSocketPath, networkBrokerSocketPath(workerSocketPath, state.ID),
		sshRelaySocketPath(workerSocketPath, state.ID), supervisorControlSocketPath(workerSocketPath, state.ID),
	} {
		if err := removeStaleUnixSocket(socketPath); err != nil {
			return fmt.Errorf("remove stale VM socket: %w", err)
		}
	}
	assets := filepath.Join(store.root, "sandboxes", state.ID)
	if err := removePrivateTree(assets); err != nil {
		return fmt.Errorf("remove VM sandbox assets: %w", err)
	}
	if err := store.delete(state.ID); err != nil {
		return err
	}
	delete(d.launchSpecs, state.ID)
	delete(d.launchSpecInputs, state.ID)
	delete(d.pendingRestores, state.ID)
	return nil
}
func (d *Driver) List(ctx context.Context) ([]driver.Info, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm driver: List requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return nil, err
	}
	states, err := store.list()
	if err != nil {
		return nil, err
	}
	infos := make([]driver.Info, 0, len(states))
	for _, state := range states {
		state = d.refreshState(store, state)
		infos = append(infos, stateInfo(state))
	}
	return infos, nil
}
func (d *Driver) Inspect(ctx context.Context, nameOrID string) (driver.Info, error) {
	if d == nil || ctx == nil {
		return driver.Info{}, fmt.Errorf("vm driver: Inspect requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
		return driver.Info{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return driver.Info{}, err
	}
	state, err := store.find(strings.TrimSpace(nameOrID))
	if err != nil {
		return driver.Info{}, err
	}
	state = d.refreshState(store, state)
	return stateInfo(state), nil
}
func stateInfo(state sandboxState) driver.Info {
	return driver.Info{ID: core.ID(state.ID), Name: state.Name, Image: state.Image, Status: state.Status, WorkloadUID: state.WorkloadUID, WorkloadGID: state.WorkloadGID}
}

func removePrivateTree(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("VM sandbox asset path must be absolute")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("VM sandbox assets %q must be a real directory", path)
	}
	return os.RemoveAll(path)
}
