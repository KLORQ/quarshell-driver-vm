//go:build darwin || linux

package vm

import (
	"context"
	"os"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestLiveLocalOCIEngineImport(t *testing.T) {
	if os.Getenv("CAUTEM_VM_LOCAL_IMAGE_ACCEPTANCE") != "1" {
		t.Skip("set CAUTEM_VM_LOCAL_IMAGE_ACCEPTANCE=1 to test local Docker/Podman image import")
	}
	reference := strings.TrimSpace(os.Getenv("CAUTEM_VM_TEST_LOCAL_IMAGE"))
	if reference == "" {
		t.Fatal("CAUTEM_VM_TEST_LOCAL_IMAGE must name an image already present in Docker or Podman")
	}
	formatter := strings.TrimSpace(os.Getenv("CAUTEM_VM_TEST_E2FS_FORMATTER"))
	if formatter == "" {
		var err error
		formatter, err = resolveExt4Formatter()
		if err != nil {
			t.Fatal(err)
		}
	}
	guestAgent := strings.TrimSpace(os.Getenv("CAUTEM_VM_TEST_GUEST_AGENT"))
	prepared, resolved, found, err := prepareLocalOCIImage(context.Background(), reference, t.TempDir(), formatter, guestAgent, defaultRootfsImageCacheMaxBytes, nil)
	if err != nil {
		t.Fatalf("import local image %q from Docker/Podman: %v", reference, err)
	}
	if !found {
		t.Fatalf("local Engine did not return configured image %q", reference)
	}
	defer os.Remove(resolved.LocalArchivePath)
	defer func() {
		if err := prepared.Lease.Release(); err != nil {
			t.Errorf("release local image cache lease: %v", err)
		}
	}()
	if resolved.LocalEngineImageID == "" || resolved.Platform.OS != "linux" {
		t.Fatalf("local Engine image identity/platform = %q/%s", resolved.LocalEngineImageID, resolved.Platform.String())
	}
	config, err := resolveLocalOCIImageConfig(context.Background(), reference, resolved.LocalEngineImageID, resolved.Platform, nil)
	if err != nil {
		t.Fatalf("recover local image config by immutable Engine ID: %v", err)
	}
	if config.User != resolved.ImageConfig.User || config.WorkingDir != resolved.ImageConfig.WorkingDir || len(config.Env) != len(resolved.ImageConfig.Env) {
		t.Fatalf("local image config changed during recovery: created=%+v recovered=%+v", resolved.ImageConfig, config)
	}
	if _, err := v1.NewHash(resolved.LocalEngineImageID); err != nil {
		t.Fatalf("local Engine image ID is not a content digest: %v", err)
	}
	t.Logf("local %s image imported and recovered by immutable ID %s for %s", reference, resolved.LocalEngineImageID, resolved.Platform.String())
}
