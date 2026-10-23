package vm

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/KLORQ/quarshell-driver/driver"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// vmLaunchSpec keeps OCI execution defaults with the in-memory workload spec.
// Env and User can contain credentials and are deliberately excluded from the
// durable sandbox state.
type vmLaunchSpec struct {
	vmCreateSpec
	WorkDir          string
	User             string
	GatewaySandboxID string
	GatewayID        string
	VerificationKeys []driver.RuntimeVerificationKey
}

func defaultVMCommand() []string { return []string{"/bin/sh", "-c", "sleep infinity"} }

func applyOCIImageConfig(spec vmLaunchSpec, config v1.Config) (vmLaunchSpec, error) {
	if spec.WorkDir == "" {
		spec.WorkDir = "/sandbox"
	}
	if config.WorkingDir != "" {
		if !path.IsAbs(config.WorkingDir) || path.Clean(config.WorkingDir) != config.WorkingDir || strings.IndexByte(config.WorkingDir, 0) >= 0 {
			return vmLaunchSpec{}, fmt.Errorf("OCI image working directory %q must be a clean absolute path", config.WorkingDir)
		}
		// OpenShell VM workloads default to the private /sandbox workspace.
		// Treat OCI's common implicit root workdir as unset so it does not
		// overlap supervisor-only credentials under /run during hardening.
		if config.WorkingDir != "/" {
			spec.WorkDir = config.WorkingDir
		}
	}

	imageUser, err := validateOCIUser(config.User)
	if err != nil {
		return vmLaunchSpec{}, err
	}
	spec.User = imageUser

	command := append([]string(nil), spec.Command...)
	if len(command) == 0 {
		command = append(command, config.Cmd...)
	}
	if len(command) == 0 && len(config.Entrypoint) == 0 {
		command = defaultVMCommand()
	}
	spec.Command = append(append([]string(nil), config.Entrypoint...), command...)
	for index, arg := range spec.Command {
		if strings.IndexByte(arg, 0) >= 0 {
			return vmLaunchSpec{}, fmt.Errorf("OCI image command argument %d contains NUL", index)
		}
	}

	imageEnv, err := parseOCIEnvironment(config.Env)
	if err != nil {
		return vmLaunchSpec{}, fmt.Errorf("OCI image environment: %w", err)
	}
	userEnv, err := parseOCIEnvironment(spec.Env)
	if err != nil {
		return vmLaunchSpec{}, fmt.Errorf("workload environment: %w", err)
	}
	for key, value := range userEnv {
		imageEnv[key] = value
	}
	for _, key := range []string{"OPENSHELL_OCI_IMAGE_USER", "OPENSHELL_SANDBOX_UID", "OPENSHELL_SANDBOX_GID"} {
		delete(imageEnv, key)
	}
	spec.Env = make([]string, 0, len(imageEnv))
	keys := make([]string, 0, len(imageEnv))
	for key := range imageEnv {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		spec.Env = append(spec.Env, key+"="+imageEnv[key])
	}
	return spec, nil
}

func validateOCIUser(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if strings.TrimSpace(raw) != raw || strings.IndexByte(raw, 0) >= 0 || strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("OCI image user %q is malformed", raw)
	}
	parts := strings.Split(raw, ":")
	if len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
		return "", fmt.Errorf("OCI image user %q is malformed", raw)
	}
	for _, part := range parts {
		for _, char := range part {
			if char < 0x21 || char == 0x7f || char == ':' {
				return "", fmt.Errorf("OCI image user %q is malformed", raw)
			}
		}
	}
	return raw, nil
}

func parseOCIEnvironment(entries []string) (map[string]string, error) {
	values := make(map[string]string, len(entries))
	for index, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !validOCIEnvironmentKey(key) || strings.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("entry %d is malformed", index)
		}
		values[key] = value
	}
	return values, nil
}

func mergeLaunchEnvironment(base, overrides []string) ([]string, error) {
	values, err := parseOCIEnvironment(base)
	if err != nil {
		return nil, fmt.Errorf("image environment: %w", err)
	}
	requestValues, err := parseOCIEnvironment(overrides)
	if err != nil {
		return nil, fmt.Errorf("exec environment: %w", err)
	}
	for key, value := range requestValues {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	merged := make([]string, 0, len(keys))
	for _, key := range keys {
		merged = append(merged, key+"="+values[key])
	}
	return merged, nil
}

func validOCIEnvironmentKey(key string) bool {
	if key == "" || strings.IndexByte(key, 0) >= 0 {
		return false
	}
	for index, char := range key {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_' || (index > 0 && char >= '0' && char <= '9') {
			continue
		}
		return false
	}
	return true
}
