package vm

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const vmHostToolProbeTimeout = 5 * time.Second
const vmHostToolOutputLimit = 8 << 10

type boundedOutput struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (w *boundedOutput) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := w.limit - w.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			w.truncated = true
			data = data[:remaining]
		}
		_, _ = w.buffer.Write(data)
	} else if originalLength != 0 {
		w.truncated = true
	}
	return originalLength, nil
}

func preflightVMHostTools(ctx context.Context, values map[string]any) ([]string, error) {
	host, err := hostConfigFromMap(values)
	if err != nil {
		return nil, err
	}
	formatter := strings.TrimSpace(host.FormatterPath)
	if formatter == "" {
		formatter, err = resolveExt4Formatter()
		if err != nil {
			return nil, err
		}
	}
	formatter, err = filepath.Abs(formatter)
	if err != nil {
		return nil, fmt.Errorf("resolve ext4 formatter path: %w", err)
	}
	checks := []struct {
		name     string
		identity string
		path     string
	}{
		{name: "mke2fs", identity: "mke2fs", path: formatter},
		{name: "debugfs", identity: "debugfs", path: siblingOrPath(formatter, "debugfs")},
		{name: "e2fsck", identity: "e2fsck", path: siblingOrPath(formatter, "e2fsck")},
	}
	reports := make([]string, 0, len(checks))
	for _, check := range checks {
		if err := ctx.Err(); err != nil {
			return reports, fmt.Errorf("VM host tool preflight canceled: %w", err)
		}
		if check.path == "" {
			return reports, fmt.Errorf("VM host tool %s not found; install e2fsprogs 1.43 or newer and ensure its directory is on the Gateway service PATH", check.name)
		}
		version, err := probeE2FSTool(ctx, check.path, check.identity)
		if err != nil {
			return reports, err
		}
		reports = append(reports, fmt.Sprintf("VM host tool %s: %s (%s)", check.identity, check.path, version))
	}
	return reports, nil
}

func siblingOrPath(formatter, name string) string {
	candidate := filepath.Join(filepath.Dir(formatter), name)
	if info, err := exec.LookPath(candidate); err == nil {
		return info
	}
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	for _, root := range []string{"/opt/homebrew/opt/e2fsprogs", "/usr/local/opt/e2fsprogs"} {
		for _, directory := range []string{"sbin", "bin"} {
			if path, err := exec.LookPath(filepath.Join(root, directory, name)); err == nil {
				return path
			}
		}
	}
	return ""
}

func probeE2FSTool(parent context.Context, path, identity string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, vmHostToolProbeTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, "-V")
	command.WaitDelay = time.Second
	command.Stdin = strings.NewReader("")
	output := &boundedOutput{limit: vmHostToolOutputLimit}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("run %s -V: %w", path, ctx.Err())
	}
	if err != nil {
		return "", fmt.Errorf("run %s -V: %w: %s", path, err, strings.TrimSpace(output.buffer.String()))
	}
	if output.truncated {
		return "", fmt.Errorf("%s -V output exceeded %d bytes", path, vmHostToolOutputLimit)
	}
	version, ok := e2fsToolVersion(identity, output.buffer.String())
	if !ok {
		return "", fmt.Errorf("%s -V did not report a recognizable %s version: %s", path, identity, strings.TrimSpace(output.buffer.String()))
	}
	if !e2fsVersionAtLeast143(version) {
		return "", fmt.Errorf("%s version %s is too old; install e2fsprogs 1.43 or newer", identity, version)
	}
	return version, nil
}

func e2fsToolVersion(identity, output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != identity {
			continue
		}
		parts := strings.Split(fields[1], ".")
		if len(parts) < 2 || len(parts) > 3 {
			return "", false
		}
		for _, part := range parts {
			if _, err := strconv.ParseUint(part, 10, 32); err != nil {
				return "", false
			}
		}
		return fields[1], true
	}
	return "", false
}

func e2fsVersionAtLeast143(value string) bool {
	parts := strings.Split(value, ".")
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := 0, error(nil)
	if len(parts) > 1 {
		minor, errMinor = strconv.Atoi(parts[1])
	}
	if errMajor != nil || errMinor != nil {
		return false
	}
	return major > 1 || (major == 1 && minor >= 43)
}
