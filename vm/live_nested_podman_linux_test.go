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

// TestLiveMicroVMNestedPodman boots a trusted rootful Podman 6 API service in
// a disposable MicroVM and verifies ext4 storage and cgroup enforcement.
func TestLiveMicroVMNestedPodman(t *testing.T) {
	if os.Getenv("QUARSHELL_VM_PODMAN_ACCEPTANCE") != "1" {
		t.Skip("set QUARSHELL_VM_PODMAN_ACCEPTANCE=1 to run the Podman-in-MicroVM acceptance profile")
	}
	runLiveMicroVMNestedPodman(t, false)
}

func TestLiveMicroVMNestedPodmanRootless(t *testing.T) {
	if os.Getenv("QUARSHELL_VM_PODMAN_ROOTLESS_ACCEPTANCE") != "1" {
		t.Skip("set QUARSHELL_VM_PODMAN_ROOTLESS_ACCEPTANCE=1 to run rootless Podman-in-MicroVM acceptance")
	}
	runLiveMicroVMNestedPodman(t, true)
}

func runLiveMicroVMNestedPodman(t *testing.T, rootless bool) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatal("Podman-in-MicroVM acceptance requires a native Linux KVM host")
	}
	rootfsTar := requireLiveRegularFile(t, "QUARSHELL_VM_TEST_ROOTFS_TAR")
	bootstrapRootfsTar := strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_BOOTSTRAP_ROOTFS_TAR"))
	if bootstrapRootfsTar == "" {
		bootstrapRootfsTar = rootfsTar
	}
	bootstrapInfo, err := os.Stat(bootstrapRootfsTar)
	if err != nil || !bootstrapInfo.Mode().IsRegular() || bootstrapInfo.Size() == 0 {
		t.Fatalf("Podman bootstrap rootfs must be a non-empty regular file: %q", bootstrapRootfsTar)
	}
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
	registry.publishImageIndex(t, []testOCILayerBlob{testOCILayerFromArchive(t, bootstrapRootfsTar)}, v1.Platform{OS: "linux", Architecture: runtime.GOARCH})
	host := normalizeHostConfig(HostConfig{
		RuntimeDir: runtimeDir,
		StateDir:   stateDir, RootfsTarDir: filepath.Dir(filepath.Dir(rootfsTar)),
		BootstrapImage: strings.TrimPrefix(registry.server.URL, "http://") + "/agent:latest",
		KVMDevice:      strings.TrimSpace(os.Getenv("QUARSHELL_KVM_DEVICE")),
		FormatterPath:  formatter, OverlaySizeBytes: defaultOverlaySize, ServiceDataDiskSizeBytes: 20 << 30,
		GuestAgentPath: guestAgent, WorkerPath: worker,
		VCPUs: 2, MemoryMiB: 2048,
		LifecycleExtensions: []LifecycleExtension{nestedPodmanInitExtension{rootless: rootless}},
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
		Name: "live-microvm-nested-podman", Image: "quarshell-podman-test:6.1.4",
		Labels:           map[string]string{SandboxExtensionLabelPrefix + podmanExtensionKey(rootless): "enabled"},
		DriverConfigJSON: string(driverConfig),
		Command:          []string{"/bin/sh", "-c", "while :; do sleep 1; done"},
		ProxyBin:         proxyBinary, PolicyPath: policyPath, ProxyEnv: []string{"QUARSHELL_VM_TEST_POLICY_PROXY_HELPER=1"},
	})
	if err != nil {
		t.Fatalf("create Podman-in-MicroVM guest: %v", err)
	}
	registerLiveSandboxCleanup(t, host, handle.ID)
	if err := d.Start(ctx, handle.ID); err != nil {
		var logs strings.Builder
		_ = d.Logs(context.Background(), handle.ID, false, &logs)
		t.Fatalf("start Podman-in-MicroVM guest: %v; workload logs: %s; guest engine logs:\n%s", err, logs.String(), nestedPodmanGuestLogs(d, handle.ID))
	}
	assertNestedPodmanReady(t, ctx, d, handle.ID, rootless)
	logNestedEngineMetrics(t, ctx, d, handle.ID, "/run/podman-test/resource-metrics")
	mode := "rootful"
	if rootless {
		mode = "rootless"
	}
	t.Logf("Podman 6.1.4 %s API started on ext4-backed VM storage (2 vCPU, 2048 MiB RAM)", mode)
}

func podmanExtensionKey(rootless bool) string {
	if rootless {
		return "live-nested-podman-rootless"
	}
	return "live-nested-podman"
}

type nestedPodmanInitExtension struct{ rootless bool }

func TestNestedPodmanInitExtensionScriptSyntax(t *testing.T) {
	for _, rootless := range []bool{false, true} {
		mode := "rootful"
		if rootless {
			mode = "rootless"
		}
		t.Run(mode, func(t *testing.T) {
			var plan ExtensionLaunchPlan
			if err := (nestedPodmanInitExtension{rootless: rootless}).ConfigureLaunch(context.Background(), vmCreateSpec{}, t.TempDir(), &plan); err != nil {
				t.Fatal(err)
			}
			if len(plan.GuestInitDropins) != 1 {
				t.Fatalf("Podman init drop-ins = %d, want 1", len(plan.GuestInitDropins))
			}
			script := filepath.Join(t.TempDir(), "podman-init.sh")
			if err := os.WriteFile(script, plan.GuestInitDropins[0].Contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command("sh", "-n", script).CombinedOutput(); err != nil {
				t.Fatalf("Podman guest init script has invalid shell syntax: %v\n%s", err, output)
			}
			if rootless {
				init := string(plan.GuestInitDropins[0].Contents)
				if !strings.Contains(init, "runuser -u sandbox") {
					t.Fatal("rootless init script does not drop privileges to sandbox user")
				}
				if !strings.Contains(init, "cgroup.subtree_control") || !strings.Contains(init, "quarshell-podman-rootless/api/cgroup.procs") {
					t.Fatal("rootless init script does not prepare a delegated cgroup v2 subtree")
				}
				if !strings.Contains(init, "echo starting rootless Podman service; exec runuser") {
					t.Fatal("rootless Podman service command is not launched from the delegated API cgroup")
				}
			}
		})
	}
}

func (extension nestedPodmanInitExtension) Name() string {
	return podmanExtensionKey(extension.rootless)
}
func (extension nestedPodmanInitExtension) Activation() ExtensionActivation {
	return ExtensionActivation{RequestKey: podmanExtensionKey(extension.rootless)}
}
func (extension nestedPodmanInitExtension) Descriptor() ExtensionDescriptor {
	return ExtensionDescriptor{Name: podmanExtensionKey(extension.rootless), RequiredBackendFeatures: []string{BackendFeatureGuestInitDropins}}
}
func (extension nestedPodmanInitExtension) ConfigureLaunch(_ context.Context, _ vmCreateSpec, _ string, plan *ExtensionLaunchPlan) error {
	script := string(append([]byte(`#!/bin/sh
set -eu
mkdir -p /run/podman-test /var/log /var/lib/docker-test/containers
exec >>/var/log/quarshell-podman-bootstrap.log 2>&1
trap 'status=$?; echo "podman bootstrap exited: $status"; exit "$status"' EXIT
echo "starting Podman MicroVM bootstrap"
test "$(/usr/bin/podman --version)" = "podman version 6.1.4" || { echo "expected Podman 6.1.4" >&2; exit 1; }
store_fstype=$(awk '$2 == "/var/lib/docker-test" { print $3; exit }' /proc/mounts)
[ "$store_fstype" = ext4 ] || { echo "Podman graphroot backing filesystem must be ext4, found $store_fstype" >&2; exit 1; }
echo "Podman backing filesystem: $store_fstype"
printf '%s\n' "$store_fstype" >/run/podman-test/store-fstype
chmod 0644 /run/podman-test/store-fstype
mkdir -p /sys/fs/cgroup
if ! grep -q ' /sys/fs/cgroup cgroup2 ' /proc/mounts; then
  mount -t cgroup2 -o nsdelegate cgroup2 /sys/fs/cgroup
fi
cat >/run/podman-test/storage.conf <<'EOF'
[storage]
driver = "overlay"
runroot = "/run/podman-test/runroot"
graphroot = "/var/lib/docker-test/containers"
EOF
chmod 0644 /run/podman-test/storage.conf
CONTAINERS_STORAGE_CONF=/run/podman-test/storage.conf /usr/bin/podman system service --time=0 unix:///run/podman-test/podman.sock >/var/log/quarshell-podman.log 2>&1 &
(
set -eu
attempt=0
while [ ! -S /run/podman-test/podman.sock ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 300 ]; then cat /var/log/quarshell-podman.log >&2; exit 1; fi
  sleep 0.1
done
chmod 0660 /run/podman-test/podman.sock
chown 0:1000 /run/podman-test/podman.sock
) >/dev/null 2>&1 </dev/null &

`), []byte(nestedEngineMetricsCollectorScript("/run/podman-test/resource-metrics"))...))
	if extension.rootless {
		rootlessSetup := `
echo "preparing rootless Podman user and subordinate IDs"
command -v runuser
test -x /usr/bin/newuidmap -a -x /usr/bin/newgidmap
echo "preparing delegated rootless cgroup v2 subtree"
for controller in cpu memory pids; do
  grep -qw "$controller" /sys/fs/cgroup/cgroup.controllers || { echo "guest cgroup v2 controller unavailable: $controller" >&2; exit 1; }
done
printf '%s\n' '+cpu +memory +pids' >/sys/fs/cgroup/cgroup.subtree_control
mkdir -p /sys/fs/cgroup/quarshell-podman-rootless/api
printf '%s\n' '+cpu +memory +pids' >/sys/fs/cgroup/quarshell-podman-rootless/cgroup.subtree_control
chown 1000:1000 /sys/fs/cgroup/quarshell-podman-rootless
chown 1000:1000 /sys/fs/cgroup/quarshell-podman-rootless/cgroup.procs /sys/fs/cgroup/quarshell-podman-rootless/cgroup.subtree_control
mkdir -p /home/sandbox /run/user/1000 /var/lib/docker-test/rootless/containers
chmod 0711 /var/lib/docker-test
chown -R 1000:1000 /home/sandbox /run/user/1000 /var/lib/docker-test/rootless
chmod 0700 /run/user/1000
touch /etc/subuid /etc/subgid
grep -q '^sandbox:' /etc/subuid || echo 'sandbox:100000:65536' >>/etc/subuid
grep -q '^sandbox:' /etc/subgid || echo 'sandbox:100000:65536' >>/etc/subgid
cat >/run/user/1000/storage.conf <<'EOF'
[storage]
driver = "overlay"
runroot = "/run/user/1000/containers"
graphroot = "/var/lib/docker-test/rootless/containers"
EOF
chown 1000:1000 /run/user/1000/storage.conf
mkdir -p /home/sandbox/.config/containers
cat >/home/sandbox/.config/containers/containers.conf <<'EOF'
[engine]
cgroup_manager = "cgroupfs"
cgroup_parent = "/quarshell-podman-rootless"
events_logger = "file"
EOF
chown -R 1000:1000 /home/sandbox/.config
echo "rootless Podman graphroot prepared on ext4"
`
		script = strings.Replace(script, "mkdir -p /run/podman-test /var/log /var/lib/docker-test/containers", "mkdir -p /run/podman-test /var/log", 1)
		script = strings.Replace(script, "cat >/run/podman-test/storage.conf <<'EOF'", rootlessSetup+"\ncat >/run/podman-test/storage.conf <<'EOF'", 1)
		script = strings.Replace(script,
			"CONTAINERS_STORAGE_CONF=/run/podman-test/storage.conf /usr/bin/podman system service --time=0 unix:///run/podman-test/podman.sock",
			"runuser -u sandbox -- /usr/bin/env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/home/sandbox XDG_RUNTIME_DIR=/run/user/1000 CONTAINERS_STORAGE_CONF=/run/user/1000/storage.conf /usr/bin/podman system service --time=0 unix:///run/user/1000/podman.sock", 1)
		script = strings.Replace(script,
			"runuser -u sandbox -- /usr/bin/env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/home/sandbox XDG_RUNTIME_DIR=/run/user/1000 CONTAINERS_STORAGE_CONF=/run/user/1000/storage.conf /usr/bin/podman system service --time=0 unix:///run/user/1000/podman.sock",
			"/bin/sh -c 'echo \"$$\" >/sys/fs/cgroup/quarshell-podman-rootless/api/cgroup.procs; echo starting rootless Podman service; exec runuser -u sandbox -- /usr/bin/env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/home/sandbox XDG_RUNTIME_DIR=/run/user/1000 CONTAINERS_STORAGE_CONF=/run/user/1000/storage.conf /usr/bin/podman system service --time=0 unix:///run/user/1000/podman.sock'", 1)
		script = strings.Replace(script, "/run/podman-test/podman.sock", "/run/user/1000/podman.sock", 2)
		script = strings.Replace(script, `chown 0:1000 "$socket"`, `:`, 1)
	}
	plan.GuestInitDropins = append(plan.GuestInitDropins, GuestInitDropin{
		Name:     "10-live-nested-podman.sh",
		Contents: []byte(script),
	})
	return nil
}

func assertNestedPodmanReady(t *testing.T, ctx context.Context, d *Driver, id core.ID, rootless bool) {
	t.Helper()
	store, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/cat", "/run/podman-test/store-fstype"}, NoLoginShell: true})
	if err != nil || store.ExitCode != 0 || strings.TrimSpace(string(store.Stdout)) != "ext4" {
		t.Fatalf("Podman graphroot filesystem = %q exit=%d err=%v, want ext4", store.Stdout, store.ExitCode, err)
	}
	readyTimeout := 5 * time.Minute
	deadline, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	attempts := 0
	socket := "unix:///run/podman-test/podman.sock"
	if rootless {
		socket = "unix:///run/user/1000/podman.sock"
	}
	for {
		attempts++
		attemptCtx, cancelAttempt := context.WithTimeout(deadline, 20*time.Second)
		info, infoErr := d.Exec(attemptCtx, id, driver.ExecRequest{Argv: []string{
			"/usr/bin/env", "CONTAINER_HOST=" + socket, "/usr/bin/podman", "info", "--format", "{{.Host.Security.Rootless}} {{.Store.GraphDriverName}}",
		}, NoLoginShell: true})
		cancelAttempt()
		if infoErr == nil && info.ExitCode == 0 {
			if details := strings.Fields(string(info.Stdout)); len(details) == 2 {
				wantRootless := "false"
				if rootless {
					wantRootless = "true"
				}
				if details[0] != wantRootless || details[1] != "overlay" {
					t.Fatalf("Podman info = %q, want rootless=%s storage=overlay", strings.TrimSpace(string(info.Stdout)), wantRootless)
				}
				break
			}
		}
		select {
		case <-deadline.Done():
			t.Fatalf("Podman API did not become ready after %d probe(s): exit=%d stdout=%q stderr=%q err=%v; guest engine logs:\n%s", attempts, info.ExitCode, info.Stdout, info.Stderr, infoErr, nestedPodmanGuestLogs(d, id))
		case <-time.After(500 * time.Millisecond):
		}
	}
	loaded, err := d.Exec(deadline, id, driver.ExecRequest{Argv: []string{
		"/usr/bin/env", "CONTAINER_HOST=" + socket, "/usr/bin/podman", "load", "-i", "/opt/quarshell-test/alpine-image.tar",
	}, NoLoginShell: true})
	if err != nil || loaded.ExitCode != 0 {
		t.Fatalf("load nested Podman test image: exit=%d stdout=%q stderr=%q err=%v", loaded.ExitCode, loaded.Stdout, loaded.Stderr, err)
	}
	run, err := d.Exec(deadline, id, driver.ExecRequest{Argv: []string{
		"/usr/bin/env", "CONTAINER_HOST=" + socket, "/usr/bin/podman", "run", "--rm", "--network=none",
		"docker.io/library/alpine:3.22", "/bin/sh", "-c", "printf nested-podman-ok",
	}, NoLoginShell: true})
	if err != nil || run.ExitCode != 0 || strings.TrimSpace(string(run.Stdout)) != "nested-podman-ok" {
		t.Fatalf("container run inside MicroVM: exit=%d stdout=%q stderr=%q err=%v", run.ExitCode, run.Stdout, run.Stderr, err)
	}
	if rootless {
		keepID, err := d.Exec(deadline, id, driver.ExecRequest{Argv: []string{
			"/usr/bin/env", "CONTAINER_HOST=" + socket, "/usr/bin/podman", "run", "--rm", "--network=none", "--userns=keep-id", "--user=1000",
			"docker.io/library/alpine:3.22", "/bin/sh", "-c", "id -u",
		}, NoLoginShell: true})
		if err != nil || keepID.ExitCode != 0 || strings.TrimSpace(string(keepID.Stdout)) != "1000" {
			t.Fatalf("rootless Podman keep-id returned uid=%q exit=%d stderr=%q err=%v; want uid 1000", keepID.Stdout, keepID.ExitCode, keepID.Stderr, err)
		}
		t.Log("rootless Podman API, offline run, and keep-id mapping passed; checking delegated cgroup resource limits")
	}
	resourceProbe := `printf '%s %s %s' "$(cat /sys/fs/cgroup/memory.max)" "$(cat /sys/fs/cgroup/cpu.max)" "$(cat /sys/fs/cgroup/pids.max)"`
	resourceRunArgs := []string{"--memory=128m", "--cpus=1", "--pids-limit=32"}
	if rootless {
		resourceRunArgs = append([]string{"--cgroup-parent=/quarshell-podman-rootless"}, resourceRunArgs...)
		resourceProbe = `set -eu
probe() { if [ -r "$1" ]; then cat "$1"; else printf unavailable; fi; }
cpu_limit=$(probe /sys/fs/cgroup/cpu.max)
cpu_limit=$(printf '%s' "$cpu_limit" | tr ' ' '/')
printf 'memory=%s cpu=%s pids=%s' "$(probe /sys/fs/cgroup/memory.max)" "$cpu_limit" "$(probe /sys/fs/cgroup/pids.max)"`
	}
	resourceArgv := []string{
		"/usr/bin/env", "CONTAINER_HOST=" + socket, "/usr/bin/podman", "run", "--rm", "--network=none",
	}
	resourceArgv = append(resourceArgv, resourceRunArgs...)
	resourceArgv = append(resourceArgv, "docker.io/library/alpine:3.22", "/bin/sh", "-c", resourceProbe)
	limits, err := d.Exec(deadline, id, driver.ExecRequest{Argv: resourceArgv, NoLoginShell: true})
	fields := strings.Fields(string(limits.Stdout))
	limitsEnforced := err == nil && limits.ExitCode == 0
	if rootless {
		limitsEnforced = limitsEnforced && len(fields) == 3 && fields[0] == "memory=134217728" && fields[1] == "cpu=100000/100000" && fields[2] == "pids=32"
	} else {
		limitsEnforced = limitsEnforced && len(fields) == 4 && fields[0] == "134217728" && fields[1] == "100000" && fields[2] == "100000" && fields[3] == "32"
	}
	if !limitsEnforced {
		detail := fmt.Sprintf("exit=%d stdout=%q stderr=%q err=%v", limits.ExitCode, strings.TrimSpace(string(limits.Stdout)), strings.TrimSpace(string(limits.Stderr)), err)
		if rootless && os.Getenv("QUARSHELL_VM_REQUIRE_ROOTLESS_CGROUP") != "1" {
			t.Logf("rootless Podman API and keep-id smoke passed; resource limits are unavailable without guest cgroup delegation (%s)", detail)
			return
		}
		t.Fatalf("nested Podman cgroup limits not enforced: %s; want memory=134217728 cpu=100000/100000 pids=32", detail)
	}
	mode := "rootful"
	if rootless {
		mode = "rootless"
	}
	t.Logf("nested Podman %s cgroup limits enforced: %s", mode, strings.Join(fields, " "))
}

func nestedPodmanGuestLogs(d *Driver, id core.ID) string {
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
		"/upper/var/log/quarshell-podman-bootstrap.log",
		"/upper/var/log/quarshell-podman.log",
	} {
		output, err := exec.Command(debugfs, "-R", "cat "+path, overlay).CombinedOutput()
		if err != nil || len(output) == 0 {
			continue
		}
		content := string(output)
		if len(content) > 8<<10 {
			content = content[len(content)-(8<<10):]
		}
		fmt.Fprintf(&logs, "--- %s ---\n%s\n", path, content)
	}
	if logs.Len() == 0 {
		return "guest init logs unavailable or empty"
	}
	return logs.String()
}
