//go:build linux

package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver/driver"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// TestLiveMicroVMNestedDocker boots a trusted Docker daemon inside a disposable
// Linux MicroVM. It is deliberately separate from the regular workload profile:
// the guest init starts dockerd before the unprivileged test workload runs.
func TestLiveMicroVMNestedDocker(t *testing.T) {
	if os.Getenv("QUARSHELL_VM_DOCKER_ACCEPTANCE") != "1" {
		t.Skip("set QUARSHELL_VM_DOCKER_ACCEPTANCE=1 to run the Docker-in-MicroVM acceptance profile")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("Docker-in-MicroVM acceptance requires a native Linux KVM host")
	}
	rootfsTar := requireLiveRegularFile(t, "QUARSHELL_VM_TEST_ROOTFS_TAR")
	guestAgent := requireLiveAsset(t, "QUARSHELL_VM_TEST_GUEST_AGENT")
	worker := requireLiveAsset(t, "QUARSHELL_VM_WORKER")
	runtimeDir := strings.TrimSpace(os.Getenv("OPENSHELL_VM_RUNTIME_DIR"))
	if runtimeDir == "" {
		t.Fatal("OPENSHELL_VM_RUNTIME_DIR is required")
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, "libkrun.so")); err != nil {
		t.Fatalf("Linux libkrun runtime is unavailable: %v", err)
	}
	formatter := strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_E2FS_FORMATTER"))
	if formatter == "" {
		var err error
		formatter, err = resolveExt4Formatter()
		if err != nil {
			t.Fatal(err)
		}
	}

	stateDir := filepath.Join(t.TempDir(), "state")
	registry := newTestOCIRegistry(t)
	registry.publishImageIndex(t, []testOCILayerBlob{testOCILayerFromArchive(t, rootfsTar)}, v1.Platform{OS: "linux", Architecture: runtime.GOARCH})
	host := normalizeHostConfig(HostConfig{
		RuntimeDir: runtimeDir,
		StateDir:   stateDir, RootfsTarDir: filepath.Dir(filepath.Dir(rootfsTar)),
		BootstrapImage: strings.TrimPrefix(registry.server.URL, "http://") + "/agent:latest",
		KVMDevice:      strings.TrimSpace(os.Getenv("QUARSHELL_KVM_DEVICE")),
		FormatterPath:  formatter, OverlaySizeBytes: defaultOverlaySize, ServiceDataDiskSizeBytes: 20 << 30,
		GuestAgentPath: guestAgent, WorkerPath: worker,
		VCPUs: 2, MemoryMiB: 3072,
		LifecycleExtensions: []LifecycleExtension{nestedDockerInitExtension{}},
	})
	if _, err := ProbeHost(host); err != nil {
		t.Fatalf("probe Linux MicroVM host: %v", err)
	}
	driverConfig, err := json.Marshal(SandboxDriverConfig{RootfsTarPath: rootfsTar})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	proxyBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(t.TempDir(), "policy")
	if err := os.Mkdir(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(policyDir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nlandlock:\n  compatibility: best_effort\nprocess:\n  run_as_user: '1000'\n  run_as_group: '1000'\nnetwork_policies: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := newLiveAcceptanceDriver(host)
	handle, err := d.createSandbox(ctx, vmCreateSpec{
		Name: "live-microvm-nested-docker", Image: "quarshell-docker-test:28.0.0",
		Labels:           map[string]string{SandboxExtensionLabelPrefix + "live-nested-docker": "enabled"},
		DriverConfigJSON: string(driverConfig),
		Command:          []string{"/bin/sh", "-c", "while :; do sleep 1; done"},
		ProxyBin:         proxyBinary, PolicyPath: policyPath, ProxyEnv: []string{"QUARSHELL_VM_TEST_POLICY_PROXY_HELPER=1"},
	})
	if err != nil {
		t.Fatalf("create Docker-in-MicroVM guest: %v", err)
	}
	registerLiveSandboxCleanup(t, host, handle.ID)
	if err := d.Start(ctx, handle.ID); err != nil {
		var logs strings.Builder
		_ = d.Logs(context.Background(), handle.ID, false, &logs)
		store, _ := openStateStore(host.StateDir)
		_, _, consolePath := workerSocketPaths(store.root, string(handle.ID))
		workerLog, _ := os.ReadFile(consolePath + ".worker")
		t.Fatalf("start Docker-in-MicroVM guest: %v; guest logs: %s; worker log: %s", err, logs.String(), workerLog)
	}
	t.Log("Docker test workload started; waiting for guest daemon API")
	assertNestedDockerReady(t, ctx, d, handle.ID)
	logNestedEngineMetrics(t, ctx, d, handle.ID, "/run/docker-test/resource-metrics")
	t.Log("Docker 28 guest daemon started on ext4-backed VM overlay (2 vCPU, 3072 MiB RAM)")
}

type nestedDockerInitExtension struct{}

func TestNestedDockerInitExtensionScriptSyntax(t *testing.T) {
	var plan ExtensionLaunchPlan
	if err := (nestedDockerInitExtension{}).ConfigureLaunch(context.Background(), vmCreateSpec{}, t.TempDir(), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.GuestInitDropins) != 1 {
		t.Fatalf("Docker init drop-ins = %d, want 1", len(plan.GuestInitDropins))
	}
	script := filepath.Join(t.TempDir(), "docker-init.sh")
	if err := os.WriteFile(script, plan.GuestInitDropins[0].Contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", "-n", script).CombinedOutput(); err != nil {
		t.Fatalf("Docker guest init script has invalid shell syntax: %v\n%s", err, output)
	}
	for _, want := range []string{
		`timeout 2 /usr/local/bin/ctr --address "$containerd_socket" version`,
		`containerd exited while dockerd was starting`,
		`dockerd exited before its API socket became ready`,
	} {
		if !strings.Contains(string(plan.GuestInitDropins[0].Contents), want) {
			t.Errorf("Docker guest init script missing daemon readiness guard %q", want)
		}
	}
}

func (nestedDockerInitExtension) Name() string { return "live-nested-docker" }
func (nestedDockerInitExtension) Activation() ExtensionActivation {
	return ExtensionActivation{RequestKey: "live-nested-docker"}
}
func (nestedDockerInitExtension) Descriptor() ExtensionDescriptor {
	return ExtensionDescriptor{Name: "live-nested-docker", RequiredBackendFeatures: []string{BackendFeatureGuestInitDropins}}
}
func (nestedDockerInitExtension) ConfigureLaunch(_ context.Context, _ vmCreateSpec, _ string, plan *ExtensionLaunchPlan) error {
	plan.GuestInitDropins = append(plan.GuestInitDropins, GuestInitDropin{
		Name: "10-live-nested-docker.sh",
		Contents: append([]byte(`#!/bin/sh
set -eu
mkdir -p /run/docker-test /var/lib/docker-test /var/log
# Docker CLI probes plugin metadata on every info request. Keep this daemon
# smoke focused on the engine API instead of booting Compose/Buildx in KVM.
for plugin_dir in /usr/local/libexec/docker/cli-plugins /usr/local/lib/docker/cli-plugins /usr/libexec/docker/cli-plugins /usr/lib/docker/cli-plugins; do
  [ ! -d "$plugin_dir" ] || mv "$plugin_dir" "$plugin_dir.quarshell-disabled"
done
store_fstype=$(awk '$2 == "/var/lib/docker-test" { print $3; exit }' /proc/mounts)
[ "$store_fstype" = ext4 ] || { echo "Docker data root must use ext4, found $store_fstype" >&2; exit 1; }
printf '%s\n' "$store_fstype" >/run/docker-test/store-fstype
chmod 0644 /run/docker-test/store-fstype
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /sys/fs/cgroup
if ! grep -q ' /sys/fs/cgroup cgroup2 ' /proc/mounts; then
  mount -t cgroup2 -o nsdelegate cgroup2 /sys/fs/cgroup
fi
(
set -eu
echo "waiting for containerd socket" >&2
containerd_socket=/run/docker-test/containerd/containerd.sock
mkdir -p /run/docker-test/containerd /run/docker-test/containerd-state /var/lib/docker-test/containerd
/usr/local/bin/containerd \
  --address "$containerd_socket" \
  --root=/var/lib/docker-test/containerd \
  --state=/run/docker-test/containerd-state \
  >/var/log/quarshell-containerd.log 2>&1 &
containerd_pid=$!
attempt=0
while ! timeout 2 /usr/local/bin/ctr --address "$containerd_socket" version >/dev/null 2>&1; do
  if ! kill -0 "$containerd_pid" 2>/dev/null; then echo "containerd exited before its API became ready" >&2; cat /var/log/quarshell-containerd.log >&2; exit 1; fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 120 ]; then echo "containerd API did not become ready" >&2; cat /var/log/quarshell-containerd.log >&2; exit 1; fi
  sleep 0.1
done
echo "containerd ready; starting dockerd" >&2
/usr/local/bin/dockerd \
  --host=unix:///run/docker-test/docker.sock \
  --data-root=/var/lib/docker-test \
  --exec-root=/run/docker-test/exec \
  --pidfile=/run/docker-test/dockerd.pid \
  --containerd="$containerd_socket" \
  --exec-opt native.cgroupdriver=cgroupfs \
  --iptables=false \
  --bridge=none \
  --ip-forward=false \
  --userland-proxy=false \
  --storage-driver=overlay2 \
  >/var/log/quarshell-dockerd.log 2>&1 </dev/null &
dockerd_pid=$!
(
set -eu
attempt=0
while [ ! -S /run/docker-test/docker.sock ]; do
  if ! kill -0 "$containerd_pid" 2>/dev/null; then echo "containerd exited while dockerd was starting" >&2; cat /var/log/quarshell-containerd.log >&2; exit 1; fi
  if ! kill -0 "$dockerd_pid" 2>/dev/null; then echo "dockerd exited before its API socket became ready" >&2; cat /var/log/quarshell-dockerd.log >&2; exit 1; fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 600 ]; then cat /var/log/quarshell-dockerd.log >&2; exit 1; fi
  sleep 0.1
done
chmod 0660 /run/docker-test/docker.sock
chown 0:1000 /run/docker-test/docker.sock
) >/dev/null 2>&1 </dev/null &
) >/var/log/quarshell-docker-bootstrap.log 2>&1 </dev/null &

`), []byte(nestedEngineMetricsCollectorScript("/run/docker-test/resource-metrics"))...),
	})
	return nil
}

func assertNestedDockerReady(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	store, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/cat", "/run/docker-test/store-fstype"}, NoLoginShell: true})
	if err != nil || store.ExitCode != 0 || strings.TrimSpace(string(store.Stdout)) != "ext4" {
		t.Fatalf("Docker data-root filesystem = %q exit=%d err=%v, want ext4", store.Stdout, store.ExitCode, err)
	}
	t.Log("Docker data-root is ext4; probing dockerd")
	deadline, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	attempts := 0
	for {
		attempts++
		attemptCtx, cancelAttempt := context.WithTimeout(deadline, 20*time.Second)
		result, err := d.Exec(attemptCtx, id, driver.ExecRequest{Argv: []string{
			"/usr/local/bin/docker", "--host=unix:///run/docker-test/docker.sock", "info", "--format", "{{.Driver}}",
		}, NoLoginShell: true})
		cancelAttempt()
		if err == nil && result.ExitCode == 0 {
			driverName := strings.TrimSpace(string(result.Stdout))
			if driverName == "" {
				select {
				case <-deadline.Done():
					t.Fatalf("nested Docker info returned an empty storage driver until timeout; stderr=%q; guest engine logs:\n%s", result.Stderr, nestedDockerGuestLogs(d, id))
				case <-time.After(500 * time.Millisecond):
					continue
				}
			}
			if driverName != "overlay2" {
				t.Fatalf("guest Docker storage driver = %q, want overlay2", driverName)
			}
			t.Logf("Docker daemon API ready after %d probe(s), storage driver=%s", attempts, driverName)
			break
		}
		select {
		case <-deadline.Done():
			t.Fatalf("nested Docker daemon did not become ready after %d probe(s): exit=%d stderr=%q err=%v; guest engine logs:\n%s", attempts, result.ExitCode, result.Stderr, err, nestedDockerGuestLogs(d, id))
		case <-time.After(250 * time.Millisecond):
		}
	}
	loaded, err := d.Exec(deadline, id, driver.ExecRequest{Argv: []string{
		"/usr/local/bin/docker", "--host=unix:///run/docker-test/docker.sock", "load", "-i", "/opt/quarshell-test/alpine-image.tar",
	}, NoLoginShell: true})
	if err != nil || loaded.ExitCode != 0 {
		t.Fatalf("load nested Docker test image: exit=%d stdout=%q stderr=%q err=%v", loaded.ExitCode, loaded.Stdout, loaded.Stderr, err)
	}
	t.Log("loaded nested Docker test image")
	result, err := d.Exec(deadline, id, driver.ExecRequest{Argv: []string{
		"/usr/local/bin/docker", "--host=unix:///run/docker-test/docker.sock", "run", "--rm", "--network=none",
		"alpine:3.22", "/bin/sh", "-c", "printf nested-docker-ok",
	}, NoLoginShell: true})
	if err != nil || result.ExitCode != 0 || strings.TrimSpace(string(result.Stdout)) != "nested-docker-ok" {
		t.Fatalf("container run inside MicroVM: exit=%d stdout=%q stderr=%q err=%v", result.ExitCode, result.Stdout, result.Stderr, err)
	}
	t.Log("nested Docker run completed")
	limits, err := d.Exec(deadline, id, driver.ExecRequest{Argv: []string{
		"/usr/local/bin/docker", "--host=unix:///run/docker-test/docker.sock", "run", "--rm",
		"--memory=128m", "--cpus=1", "--pids-limit=32", "alpine:3.22",
		"/bin/sh", "-c", "printf '%s %s %s' \"$(cat /sys/fs/cgroup/memory.max)\" \"$(cat /sys/fs/cgroup/cpu.max)\" \"$(cat /sys/fs/cgroup/pids.max)\"",
	}, NoLoginShell: true})
	if err != nil || limits.ExitCode != 0 {
		t.Fatalf("nested container resource-limit probe: exit=%d stdout=%q stderr=%q err=%v", limits.ExitCode, limits.Stdout, limits.Stderr, err)
	}
	fields := strings.Fields(string(limits.Stdout))
	if len(fields) != 4 || fields[0] != "134217728" || fields[1] != "100000" || fields[2] != "100000" || fields[3] != "32" {
		t.Fatalf("nested cgroup limits = %q, want memory=134217728 cpu=100000/100000 pids=32", strings.TrimSpace(string(limits.Stdout)))
	}
	t.Logf("nested Docker cgroup limits enforced: memory=%s cpu=%s/%s pids=%s", fields[0], fields[1], fields[2], fields[3])
}

func nestedDockerGuestLogs(d *Driver, id core.ID) string {
	if d == nil {
		return "driver unavailable"
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return fmt.Sprintf("open VM state: %v", err)
	}
	overlay := filepath.Join(store.root, "sandboxes", string(id), "overlay.ext4")
	debugfs, err := exec.LookPath("debugfs")
	if err != nil {
		return fmt.Sprintf("debugfs unavailable: %v", err)
	}
	var logs strings.Builder
	for _, path := range []string{
		"/upper/var/log/quarshell-docker-bootstrap.log",
		"/upper/var/log/quarshell-containerd.log",
		"/upper/var/log/quarshell-dockerd.log",
	} {
		output, err := exec.Command(debugfs, "-R", "cat "+path, overlay).CombinedOutput()
		if err != nil || len(output) == 0 {
			continue
		}
		text := string(output)
		if len(text) > 8<<10 {
			text = text[len(text)-(8<<10):]
		}
		fmt.Fprintf(&logs, "--- %s ---\n%s\n", path, text)
	}
	if logs.Len() == 0 {
		return "guest init logs unavailable or empty"
	}
	return logs.String()
}

func requireLiveRegularFile(t *testing.T, variable string) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(variable))
	if path == "" {
		t.Fatalf("%s is required", variable)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("%s must name a non-empty regular file: %q", variable, path)
	}
	return path
}
