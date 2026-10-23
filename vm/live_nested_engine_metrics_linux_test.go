//go:build linux

package vm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver/driver"
)

// logNestedEngineMetrics records comparable host worker and guest snapshots.
// Metrics are diagnostic only: a missing kernel counter never makes an
// otherwise passing acceptance run fail.
func logNestedEngineMetrics(t *testing.T, ctx context.Context, d *Driver, id core.ID, metricsPath string) {
	t.Helper()
	control, _, _ := workerSocketPaths(d.host.StateDir, string(id))
	worker, err := workerControl(ctx, control, "status")
	if err != nil {
		t.Logf("resource metrics: host worker status unavailable: %v", err)
	} else {
		t.Logf("resource metrics: host worker pid=%d %s", worker.PID, hostProcessMemoryMetrics(worker.PID))
	}

	result, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/cat", metricsPath}, NoLoginShell: true})
	if err != nil || result.ExitCode != 0 {
		t.Logf("resource metrics: guest snapshot unavailable: exit=%d err=%v stderr=%q", result.ExitCode, err, result.Stderr)
		return
	}
	t.Logf("resource metrics: guest snapshot:\n%s", strings.TrimSpace(string(result.Stdout)))
}

func hostProcessMemoryMetrics(pid int) string {
	if pid <= 0 {
		return "rss_kib=unavailable pss_kib=unavailable cgroup=unavailable"
	}
	base := filepath.Join("/proc", strconv.Itoa(pid))
	values := map[string]string{"Rss": "unavailable", "Pss": "unavailable"}
	if data, err := os.ReadFile(filepath.Join(base, "smaps_rollup")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && (fields[0] == "Rss:" || fields[0] == "Pss:") {
				values[strings.TrimSuffix(fields[0], ":")] = fields[1]
			}
		}
	}
	cgroup := "unavailable"
	if data, err := os.ReadFile(filepath.Join(base, "cgroup")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "0::") {
				cgroup = strings.TrimPrefix(line, "0::")
				break
			}
		}
	}
	current, events := "unavailable", "unavailable"
	if cgroup != "unavailable" {
		root := filepath.Join("/sys/fs/cgroup", filepath.Clean("/"+cgroup))
		current = readMetric(filepath.Join(root, "memory.current"))
		events = strings.ReplaceAll(strings.TrimSpace(readMetric(filepath.Join(root, "memory.events"))), "\n", ",")
	}
	return fmt.Sprintf("rss_kib=%s pss_kib=%s cgroup_memory_current_bytes=%s cgroup_memory_events=%s", values["Rss"], values["Pss"], current, events)
}

func readMetric(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(string(data))
}

func nestedEngineMetricsCollectorScript(metricsPath string) string {
	return fmt.Sprintf(`(
  while :; do
    tmp=%q.tmp
    {
      printf 'timestamp_utc='; date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ
      awk '/^(MemTotal|MemAvailable):/ { printf "guest_%%s_kib=%%s\\n", $1, $2 }' /proc/meminfo
      for metric in memory.current memory.max memory.events pids.current; do
        if [ -r "/sys/fs/cgroup/$metric" ]; then
          sed "s/^/guest_cgroup_${metric}_/" "/sys/fs/cgroup/$metric"
        fi
      done
      df -Pk /var/lib/docker-test | awk 'NR == 2 { printf "data_disk_size_kib=%%s data_disk_used_kib=%%s data_disk_available_kib=%%s data_disk_use_percent=%%s\\n", $2, $3, $4, $5 }'
    } >"$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" %q
    sleep 1
  done
) </dev/null >/dev/null 2>&1 &
`, metricsPath, metricsPath)
}

func TestHostProcessMemoryMetricsHandlesMissingProcess(t *testing.T) {
	if got := hostProcessMemoryMetrics(-1); !strings.Contains(got, "unavailable") {
		t.Fatalf("missing-process metrics = %q, want unavailable markers", got)
	}
	if got := readMetric(filepath.Join(t.TempDir(), "missing")); got != "unavailable" {
		t.Fatalf("missing metric = %q, want unavailable", got)
	}
}
