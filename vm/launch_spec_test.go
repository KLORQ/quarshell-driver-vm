//go:build darwin || linux

package vm

import (
	"reflect"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestApplyOCIImageConfigBuildsEffectiveWorkload(t *testing.T) {
	spec := cloneVMLaunchSpec(vmCreateSpec{
		Command: []string{"custom", "arg"},
		Env: []string{
			"BASE=override", "USER_VALUE=kept", "OPENSHELL_OCI_IMAGE_USER=spoofed",
			"OPENSHELL_SANDBOX_UID=0", "OPENSHELL_SANDBOX_GID=0",
		},
	})
	got, err := applyOCIImageConfig(spec, v1.Config{
		Entrypoint: []string{"/usr/local/bin/entry", "--fixed"},
		Cmd:        []string{"image-default"},
		Env:        []string{"BASE=image", "IMAGE_VALUE=kept", "OPENSHELL_SANDBOX_UID=123"},
		WorkingDir: "/opt/app",
		User:       "1000:1001",
	})
	if err != nil {
		t.Fatalf("applyOCIImageConfig() error = %v", err)
	}
	if want := []string{"/usr/local/bin/entry", "--fixed", "custom", "arg"}; !reflect.DeepEqual(got.Command, want) {
		t.Fatalf("effective command = %q, want %q", got.Command, want)
	}
	if got.WorkDir != "/opt/app" || got.User != "1000:1001" {
		t.Fatalf("effective directory/user = %q / %q", got.WorkDir, got.User)
	}
	wantEnv := []string{"BASE=override", "IMAGE_VALUE=kept", "USER_VALUE=kept"}
	if !reflect.DeepEqual(got.Env, wantEnv) {
		t.Fatalf("effective environment = %q, want %q", got.Env, wantEnv)
	}
}

func TestApplyOCIImageConfigUsesImageDefaultsAndSafeFallback(t *testing.T) {
	got, err := applyOCIImageConfig(cloneVMLaunchSpec(vmCreateSpec{}), v1.Config{
		Entrypoint: []string{"entry"}, Cmd: []string{"image-cmd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"entry", "image-cmd"}; !reflect.DeepEqual(got.Command, want) {
		t.Fatalf("image command = %q, want %q", got.Command, want)
	}
	if got.WorkDir != "/sandbox" || got.User != "" {
		t.Fatalf("default OCI config = %+v", got)
	}
	got, err = applyOCIImageConfig(cloneVMLaunchSpec(vmCreateSpec{}), v1.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if want := defaultVMCommand(); !reflect.DeepEqual(got.Command, want) {
		t.Fatalf("empty image command = %q, want %q", got.Command, want)
	}
}

func TestApplyOCIImageConfigKeepsSandboxWorkdirForRootImageWorkdir(t *testing.T) {
	got, err := applyOCIImageConfig(cloneVMLaunchSpec(vmCreateSpec{}), v1.Config{WorkingDir: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if got.WorkDir != "/sandbox" {
		t.Fatalf("root image workdir resolved to %q, want private sandbox workspace", got.WorkDir)
	}
}

func TestApplyOCIImageConfigRejectsMalformedRuntimeFields(t *testing.T) {
	tests := []struct {
		name   string
		config v1.Config
		spec   vmCreateSpec
		want   string
	}{
		{name: "relative workdir", config: v1.Config{WorkingDir: "opt/app"}, want: "clean absolute path"},
		{name: "unclean workdir", config: v1.Config{WorkingDir: "/opt/../etc"}, want: "clean absolute path"},
		{name: "malformed user", config: v1.Config{User: "app:group:extra"}, want: "malformed"},
		{name: "malformed image env", config: v1.Config{Env: []string{"BROKEN"}}, want: "environment"},
		{name: "malformed override env", spec: vmCreateSpec{Env: []string{"1BAD=value"}}, want: "environment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := applyOCIImageConfig(cloneVMLaunchSpec(test.spec), test.config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("applyOCIImageConfig() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestMergeLaunchEnvironmentAppliesSortedExecOverrides(t *testing.T) {
	got, err := mergeLaunchEnvironment(
		[]string{"Z_LAST=image", "A_FIRST=image", "UNCHANGED=kept"},
		[]string{"Z_LAST=exec", "B_MIDDLE=exec"},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"A_FIRST=image", "B_MIDDLE=exec", "UNCHANGED=kept", "Z_LAST=exec"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged exec environment = %q, want %q", got, want)
	}
}
