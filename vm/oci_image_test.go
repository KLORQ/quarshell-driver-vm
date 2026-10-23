//go:build darwin || linux

package vm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/klauspost/compress/zstd"
)

func TestRegistryLayerDownloadConcurrencyMatchesUpstreamBounds(t *testing.T) {
	for _, test := range []struct {
		value string
		want  int
	}{
		{"", defaultRegistryLayerConcurrency},
		{"0", defaultRegistryLayerConcurrency},
		{"invalid", defaultRegistryLayerConcurrency},
		{"7", 7},
		{"999", maxRegistryLayerConcurrency},
	} {
		if got := registryLayerDownloadConcurrencyValue(test.value); got != test.want {
			t.Errorf("registryLayerDownloadConcurrencyValue(%q) = %d; want %d", test.value, got, test.want)
		}
	}
	if err := downloadOCIImageLayers(context.Background(), maxRegistryLayerConcurrency+3, maxRegistryLayerConcurrency+10, func(context.Context, int) error { return nil }); err != nil {
		t.Fatalf("hard-capped layer download pool: %v", err)
	}
}

func TestDownloadOCIImageLayersRunsBoundedParallelWorkers(t *testing.T) {
	var active, maximum atomic.Int32
	err := downloadOCIImageLayers(context.Background(), 24, 3, func(context.Context, int) error {
		current := active.Add(1)
		for observed := maximum.Load(); current > observed && !maximum.CompareAndSwap(observed, current); observed = maximum.Load() {
		}
		time.Sleep(15 * time.Millisecond)
		active.Add(-1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := maximum.Load(); got <= 1 || got > 3 {
		t.Fatalf("maximum concurrent downloads = %d; want 2..3", got)
	}
}

func TestDownloadOCIImageLayersWaitsForCancellationCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 3)
	finished := make(chan error, 1)
	go func() {
		finished <- downloadOCIImageLayers(ctx, 100, 3, func(workCtx context.Context, _ int) error {
			started <- struct{}{}
			<-workCtx.Done()
			return workCtx.Err()
		})
	}()
	for index := 0; index < cap(started); index++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("download workers did not start")
		}
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("layer downloads returned %v; want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("download pool returned before waiting for canceled workers")
	}
}

func TestOCIImagePullResolvesPlatformAndAppliesWhiteouts(t *testing.T) {
	registry := newTestOCIRegistry(t)
	lower := testOCILayer(t, []rootfsTarEntry{
		{name: "etc", kind: tar.TypeDir, mode: 0o755},
		{name: "etc/remove-me", kind: tar.TypeReg, body: "lower"},
		{name: "etc/keep-me", kind: tar.TypeReg, body: "kept"},
		{name: "var", kind: tar.TypeDir, mode: 0o755},
		{name: "var/lib", kind: tar.TypeDir, mode: 0o755},
		{name: "var/lib/cache", kind: tar.TypeDir, mode: 0o755},
		{name: "var/lib/cache/old", kind: tar.TypeReg, body: "old"},
	})
	upper := testOCILayer(t, []rootfsTarEntry{
		{name: "etc", kind: tar.TypeDir, mode: 0o755},
		{name: "etc/.wh.remove-me", kind: tar.TypeReg, body: ""},
		{name: "etc/new-file", kind: tar.TypeReg, body: "new"},
		{name: "var/lib/cache", kind: tar.TypeDir, mode: 0o755},
		{name: "var/lib/cache/.wh..wh..opq", kind: tar.TypeReg, body: ""},
		{name: "var/lib/cache/fresh", kind: tar.TypeReg, body: "fresh"},
	})
	registry.publishImageIndexWithConfig(t, []testOCILayerBlob{lower, upper}, v1.Platform{OS: "linux", Architecture: "amd64"}, v1.Config{
		Entrypoint: []string{"/usr/local/bin/entry"}, Cmd: []string{"--serve"},
		Env: []string{"IMAGE_KEY=image-value"}, WorkingDir: "/opt/app", User: "1000:1001",
	})
	ref := strings.TrimPrefix(registry.server.URL, "http://") + "/agent:latest"
	platform := v1.Platform{OS: "linux", Architecture: "amd64"}
	resolved, err := resolveOCIImageWithOptions(context.Background(), ref, platform, []name.Option{name.Insecure}, []remote.Option{
		remote.WithContext(context.Background()), remote.WithAuth(authn.Anonymous), remote.WithPlatform(platform),
	})
	if err != nil {
		t.Fatalf("resolveOCIImageWithOptions() error = %v", err)
	}
	if !strings.HasPrefix(resolved.SourceManifestDigest, "sha256:") || !strings.HasPrefix(resolved.PlatformManifestDigest, "sha256:") || resolved.Platform.String() != "linux/amd64" {
		t.Fatalf("resolved identity = %+v", resolved)
	}
	if resolved.ImageConfig.User != "1000:1001" || resolved.ImageConfig.WorkingDir != "/opt/app" || !reflect.DeepEqual(resolved.ImageConfig.Env, []string{"IMAGE_KEY=image-value"}) {
		t.Fatalf("resolved image config = %+v", resolved.ImageConfig)
	}
	pinnedChild, err := resolveOCIImageAtDigestWithOptions(context.Background(), ref, resolved.PlatformManifestDigest, platform, []name.Option{name.Insecure}, []remote.Option{
		remote.WithContext(context.Background()), remote.WithAuth(authn.Anonymous), remote.WithPlatform(platform),
	})
	if err != nil {
		t.Fatalf("resolve OCI image by selected platform digest: %v", err)
	}
	if pinnedChild.PlatformManifestDigest != resolved.PlatformManifestDigest || pinnedChild.ImageConfig.User != resolved.ImageConfig.User {
		t.Fatalf("pinned image recovery differs: initial=%+v pinned=%+v", resolved, pinnedChild)
	}
	pinnedRef := strings.TrimPrefix(registry.server.URL, "http://") + "/agent@" + registry.rootDigest
	pinned, err := resolveOCIImageWithOptions(context.Background(), pinnedRef, platform, []name.Option{name.Insecure}, []remote.Option{
		remote.WithContext(context.Background()), remote.WithAuth(authn.Anonymous), remote.WithPlatform(platform),
	})
	if err != nil {
		t.Fatalf("resolve pinned OCI image: %v", err)
	}
	if pinned.cacheIdentity() != resolved.cacheIdentity() {
		t.Fatalf("tag and digest cache identities differ: tag=%q pinned=%q", resolved.cacheIdentity(), pinned.cacheIdentity())
	}
	if got := countString(registry.recordedRequests(), "HEAD /v2/agent/manifests/latest"); got != 1 {
		t.Fatalf("registry HEAD count = %d; want one HEAD for the mutable tag and none for digest-pinned recovery", got)
	}
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(rootfs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := populateRootfsFromOCI(context.Background(), resolved.Image, ref, platform, rootfs); err != nil {
		t.Fatalf("populateRootfsFromOCI() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(rootfs, "etc", "remove-me")); !os.IsNotExist(err) {
		t.Fatalf("lower-layer whiteout target still exists: err=%v", err)
	}
	if got, err := os.ReadFile(filepath.Join(rootfs, "etc", "keep-me")); err != nil || string(got) != "kept" {
		t.Fatalf("retained lower-layer file = %q, err=%v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(rootfs, "etc", "new-file")); err != nil || string(got) != "new" {
		t.Fatalf("upper-layer file = %q, err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(rootfs, "var", "lib", "cache", "old")); !os.IsNotExist(err) {
		t.Fatalf("opaque whiteout retained old child: err=%v", err)
	}
	if got, err := os.ReadFile(filepath.Join(rootfs, "var", "lib", "cache", "fresh")); err != nil || string(got) != "fresh" {
		t.Fatalf("opaque directory's new file = %q, err=%v", got, err)
	}
}

func TestOCIImageTagIsPinnedBetweenHeadAndManifestGet(t *testing.T) {
	registry := newTestOCIRegistry(t)
	registry.publishImageIndex(t, []testOCILayerBlob{
		testOCILayer(t, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "trusted"}}),
	}, v1.Platform{OS: "linux", Architecture: runtime.GOARCH})
	trustedDigest := registry.rootDigest
	registry.headDigestOverrides = map[string]string{"latest": trustedDigest}
	registry.getDigestOverrides = map[string]string{trustedDigest: trustedDigest}
	// Simulate the registry replacing the content after HEAD returned the
	// trusted digest but before the pinned GET is served.
	registry.manifests[trustedDigest] = []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","forged":true}`)
	ref := strings.TrimPrefix(registry.server.URL, "http://") + "/agent:latest"
	root := t.TempDir()
	guestAgent := filepath.Join(root, "guest-agent")
	if err := os.WriteFile(guestAgent, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	prepared, _, err := prepareOCIImageRootfsWithNameOptions(context.Background(), ref, filepath.Join(root, "cache"), "", guestAgent, defaultRootfsImageCacheMaxBytes, []name.Option{name.Insecure})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "digest") {
		if prepared.Lease != nil {
			_ = prepared.Lease.Release()
		}
		t.Fatalf("tag race did not fail digest verification: prepared=%+v err=%v", prepared, err)
	}
	requests := registry.recordedRequests()
	if !containsString(requests, "HEAD /v2/agent/manifests/latest") || !containsString(requests, "GET /v2/agent/manifests/"+trustedDigest) {
		t.Fatalf("tag resolution requests = %v; want HEAD tag then GET pinned digest", requests)
	}
	for _, request := range requests {
		if strings.Contains(request, "/blobs/") {
			t.Fatalf("registry requested a blob before pinned manifest verification: %v", requests)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "cache")); !os.IsNotExist(err) {
		t.Fatalf("failed tag race created an image cache: stat error=%v", err)
	}
}

func TestOCIImageDigestPinSupportsSHA512WithoutHead(t *testing.T) {
	registry := newTestOCIRegistry(t)
	registry.publishImageIndex(t, []testOCILayerBlob{
		testOCILayer(t, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "sha512"}}),
	}, v1.Platform{OS: "linux", Architecture: runtime.GOARCH})
	indexBytes := registry.manifests[registry.rootDigest]
	sha512Digest := digestWithAlgorithm(t, indexBytes, "sha512").String()
	registry.manifests[sha512Digest] = indexBytes
	ref := strings.TrimPrefix(registry.server.URL, "http://") + "/agent@" + sha512Digest
	platform := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	resolved, err := resolveOCIImageWithOptions(context.Background(), ref, platform, []name.Option{name.Insecure}, nil)
	if err != nil {
		t.Fatalf("resolve SHA-512 pinned image: %v", err)
	}
	if resolved.SourceManifestDigest != sha512Digest {
		t.Fatalf("source digest = %q; want caller's SHA-512 pin %q", resolved.SourceManifestDigest, sha512Digest)
	}
	if containsString(registry.recordedRequests(), "HEAD /v2/agent/manifests/"+sha512Digest) {
		t.Fatal("digest-pinned image unexpectedly issued HEAD")
	}
}

func TestOCIImageRegistryRetriesTransientHeadAndManifestFailures(t *testing.T) {
	registry := newTestOCIRegistry(t)
	registry.publishImageIndex(t, []testOCILayerBlob{
		testOCILayer(t, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "retry"}}),
	}, v1.Platform{OS: "linux", Architecture: runtime.GOARCH})
	registry.failManifestRequests = map[string]int{
		"HEAD latest":                1,
		"GET " + registry.rootDigest: 1,
	}
	platform := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	resolved, err := resolveOCIImageWithOptions(context.Background(), strings.TrimPrefix(registry.server.URL, "http://")+"/agent:latest", platform, []name.Option{name.Insecure}, []remote.Option{
		remote.WithContext(context.Background()), remote.WithAuth(authn.Anonymous), remote.WithPlatform(platform),
		remote.WithRetryBackoff(remote.Backoff{Duration: time.Millisecond, Steps: 2}),
	})
	if err != nil {
		t.Fatalf("resolve after transient registry failures: %v", err)
	}
	requests := registry.recordedRequests()
	if got := countString(requests, "HEAD /v2/agent/manifests/latest"); got < 2 {
		t.Fatalf("HEAD retry count = %d; requests=%v", got, requests)
	}
	if got := countString(requests, "GET /v2/agent/manifests/"+registry.rootDigest); got < 2 {
		t.Fatalf("manifest retry count = %d; requests=%v", got, requests)
	}
	if resolved.SourceManifestDigest != registry.rootDigest {
		t.Fatalf("resolved source digest = %q; want %q", resolved.SourceManifestDigest, registry.rootDigest)
	}
}

func TestOCIImageIndexRejectsChangedPlatformChildBeforeBlobDownload(t *testing.T) {
	registry := newTestOCIRegistry(t)
	registry.publishImageIndex(t, []testOCILayerBlob{
		testOCILayer(t, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "trusted child"}}),
	}, v1.Platform{OS: "linux", Architecture: runtime.GOARCH})
	var index v1.IndexManifest
	if err := json.Unmarshal(registry.manifests[registry.rootDigest], &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 1 {
		t.Fatalf("fixture image index descriptors = %d; want one", len(index.Manifests))
	}
	childDigest := index.Manifests[0].Digest.String()
	registry.manifests[childDigest] = []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","forged":true}`)
	platform := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	_, err := resolveOCIImageWithOptions(context.Background(), strings.TrimPrefix(registry.server.URL, "http://")+"/agent:latest", platform, []name.Option{name.Insecure}, nil)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "digest") {
		t.Fatalf("changed index child was accepted: %v", err)
	}
	for _, request := range registry.recordedRequests() {
		if strings.Contains(request, "/blobs/") {
			t.Fatalf("OCI blobs were requested before platform child verification: %v", registry.recordedRequests())
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func countString(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}

func TestPrepareOCIWorkloadDiskPlacesGuestRootAtImageRootfs(t *testing.T) {
	registry := newTestOCIRegistry(t)
	platform := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	registry.publishImageIndexWithConfig(t, []testOCILayerBlob{testOCILayer(t, []rootfsTarEntry{
		{name: "etc", kind: tar.TypeDir, mode: 0o755},
		{name: "etc/workload-marker", kind: tar.TypeReg, body: "workload"},
	})}, platform, v1.Config{WorkingDir: "/app", Env: []string{"FROM_IMAGE=yes"}})
	ref := strings.TrimPrefix(registry.server.URL, "http://") + "/agent:latest"
	root := t.TempDir()
	guestAgent := filepath.Join(root, "guest-agent")
	if err := os.WriteFile(guestAgent, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	formatter := filepath.Join(root, "mke2fs")
	if err := os.WriteFile(formatter, []byte("#!/bin/sh\nfor last do :; done\nprintf ext4 > \"$last\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	prepared, resolved, err := prepareOCIWorkloadDisk(context.Background(), ref, filepath.Join(root, "cache"), formatter, guestAgent, defaultRootfsImageCacheMaxBytes, []name.Option{name.Insecure})
	if err != nil {
		t.Fatalf("prepareOCIWorkloadDisk() error = %v", err)
	}
	defer prepared.Lease.Release()
	if resolved.Platform.String() != platform.String() || resolved.ImageConfig.WorkingDir != "/app" {
		t.Fatalf("resolved workload metadata = %+v", resolved)
	}
	if _, err := os.Stat(prepared.Path); err != nil {
		t.Fatalf("prepared workload disk missing: %v", err)
	}
	if prepared.Path == "" || filepath.Ext(prepared.Path) != ".ext4" || filepath.Dir(prepared.Path) != filepath.Join(root, "cache") {
		t.Fatalf("workload disk cache path = %q", prepared.Path)
	}

	staging := filepath.Join(root, "verify")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := populateOCIWorkloadRootfs(context.Background(), resolved.Image, ref, platform, guestAgent, staging); err != nil {
		t.Fatalf("populateOCIWorkloadRootfs() error = %v", err)
	}
	workloadRoot := filepath.Join(staging, "image-rootfs")
	if got, err := os.ReadFile(filepath.Join(workloadRoot, "etc", "workload-marker")); err != nil || string(got) != "workload" {
		t.Fatalf("workload root marker = %q, err=%v", got, err)
	}
	for _, asset := range []string{"opt/cautem/bin/guest-agent", "opt/cautem/vm-init"} {
		if _, err := os.Stat(filepath.Join(workloadRoot, asset)); err != nil {
			t.Errorf("workload disk missing runtime asset %s: %v", asset, err)
		}
	}
}

func TestOCIImagePullUsesDockerCredentialHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test credential helper fixture uses a Unix executable")
	}
	registry := newTestOCIRegistry(t)
	const username = "credential-helper-user"
	const password = "credential-helper-secret"
	registry.requireBasicAuth(username, password)
	registryHost := strings.TrimPrefix(registry.server.URL, "http://")
	marker := configureTestDockerCredentialHelper(t, registryHost, username, password)
	dockerConfigDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dockerConfigDir, "config.json"), []byte(fmt.Sprintf(`{"credHelpers":{"%s":"test"}}`, registryHost)), 0o600); err != nil {
		t.Fatalf("write Docker credential-helper config: %v", err)
	}
	t.Setenv("DOCKER_CONFIG", dockerConfigDir)
	platform := v1.Platform{OS: "linux", Architecture: "amd64"}
	registry.publishImageIndex(t, []testOCILayerBlob{testOCILayer(t, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "authenticated"}})}, platform)
	ref := registryHost + "/agent:latest"
	resolved, err := resolveOCIImageWithOptions(context.Background(), ref, platform, []name.Option{name.Insecure}, nil)
	if err != nil {
		t.Fatalf("resolve private OCI image through Docker credential helper: %v", err)
	}
	if resolved.PlatformManifestDigest == "" {
		t.Fatal("credential-helper image resolved without a platform manifest digest")
	}
	calls, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(calls), registryHost) {
		t.Fatalf("credential helper calls = %q, err=%v; want registry %q", calls, err, registryHost)
	}
}

func configureTestDockerCredentialHelper(t *testing.T, registryHost, username, password string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Fatal("Unix credential-helper fixture requested on Windows")
	}
	binDir := t.TempDir()
	marker := filepath.Join(binDir, "credential-helper.calls")
	helper := filepath.Join(binDir, "docker-credential-test")
	contents := []byte(`#!/bin/sh
set -eu
[ "$#" -eq 1 ] && [ "$1" = "get" ]
IFS= read -r server || true
[ "$server" = "$CAUTEM_TEST_CREDENTIAL_SERVER" ]
printf '%s\n' "$server" >> "$CAUTEM_TEST_CREDENTIAL_MARKER"
printf '{"Username":"%s","Secret":"%s"}\n' "$CAUTEM_TEST_CREDENTIAL_USERNAME" "$CAUTEM_TEST_CREDENTIAL_SECRET"
`)
	if err := os.WriteFile(helper, contents, 0o700); err != nil {
		t.Fatalf("write Docker credential-helper executable: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CAUTEM_TEST_CREDENTIAL_SERVER", registryHost)
	t.Setenv("CAUTEM_TEST_CREDENTIAL_MARKER", marker)
	t.Setenv("CAUTEM_TEST_CREDENTIAL_USERNAME", username)
	t.Setenv("CAUTEM_TEST_CREDENTIAL_SECRET", password)
	return marker
}

func TestOCIImagePullRejectsMissingPlatform(t *testing.T) {
	registry := newTestOCIRegistry(t)
	registry.publishImageIndex(t, []testOCILayerBlob{testOCILayer(t, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "x"}})}, v1.Platform{OS: "linux", Architecture: "amd64"})
	ref := strings.TrimPrefix(registry.server.URL, "http://") + "/agent:latest"
	platform := v1.Platform{OS: "linux", Architecture: "arm64"}
	_, err := resolveOCIImageWithOptions(context.Background(), ref, platform, []name.Option{name.Insecure}, []remote.Option{
		remote.WithContext(context.Background()), remote.WithAuth(authn.Anonymous), remote.WithPlatform(platform),
	})
	if err == nil || !strings.Contains(err.Error(), "select OCI image platform") {
		t.Fatalf("missing image platform error = %v", err)
	}
}

func TestOCIImagePullPreservesPlatformManifestDigestAlgorithm(t *testing.T) {
	registry := newTestOCIRegistry(t)
	registry.publishImageIndexWithManifestAlgorithm(t, []testOCILayerBlob{testOCILayer(t, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "x"}})}, v1.Platform{OS: "linux", Architecture: "amd64"}, "sha512")
	platform := v1.Platform{OS: "linux", Architecture: "amd64"}
	ref := strings.TrimPrefix(registry.server.URL, "http://") + "/agent:latest"
	resolved, err := resolveOCIImageWithOptions(context.Background(), ref, platform, []name.Option{name.Insecure}, []remote.Option{
		remote.WithContext(context.Background()), remote.WithAuth(authn.Anonymous), remote.WithPlatform(platform),
	})
	if err != nil {
		t.Fatalf("resolve OCI image with SHA-512 child manifest: %v", err)
	}
	if !strings.HasPrefix(resolved.PlatformManifestDigest, "sha512:") {
		t.Fatalf("platform manifest digest = %q, want SHA-512 descriptor digest", resolved.PlatformManifestDigest)
	}
}

func TestOCIImagePullRejectsLayerDigestMismatch(t *testing.T) {
	registry := newTestOCIRegistry(t)
	layer := testOCILayer(t, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "trusted"}})
	registry.publishImageIndex(t, []testOCILayerBlob{layer}, v1.Platform{OS: "linux", Architecture: "amd64"})
	mutated := append([]byte(nil), layer.compressed...)
	mutated[len(mutated)/2] ^= 0xff
	registry.blobs[layer.descriptor.Digest.String()] = mutated
	platform := v1.Platform{OS: "linux", Architecture: "amd64"}
	ref := strings.TrimPrefix(registry.server.URL, "http://") + "/agent:latest"
	resolved, err := resolveOCIImageWithOptions(context.Background(), ref, platform, []name.Option{name.Insecure}, []remote.Option{
		remote.WithContext(context.Background()), remote.WithAuth(authn.Anonymous), remote.WithPlatform(platform),
	})
	if err != nil {
		t.Fatalf("resolve OCI manifest before blob pull: %v", err)
	}
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(rootfs, 0o700); err != nil {
		t.Fatal(err)
	}
	err = populateRootfsFromOCI(context.Background(), resolved.Image, ref, platform, rootfs)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "error verifying") {
		t.Fatalf("populateRootfsFromOCI() digest error = %v", err)
	}
}

func TestExtractOCICompressedLayerSupportsRawAndZstd(t *testing.T) {
	var tarBytes bytes.Buffer
	tarWriter := tar.NewWriter(&tarBytes)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "etc/os-release", Typeflag: tar.TypeReg, Mode: 0o644, Size: 8}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write([]byte("ID=test\n")); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		mediaType string
		content   []byte
	}{
		{name: "raw", mediaType: "application/vnd.oci.image.layer.v1.tar", content: tarBytes.Bytes()},
		{name: "zstd", mediaType: "application/vnd.oci.image.layer.v1.tar+zstd", content: zstdCompress(t, tarBytes.Bytes())},
	} {
		t.Run(test.name, func(t *testing.T) {
			blob := filepath.Join(t.TempDir(), "layer.blob")
			if err := os.WriteFile(blob, test.content, 0o600); err != nil {
				t.Fatal(err)
			}
			rootfs := filepath.Join(t.TempDir(), "rootfs")
			if _, _, _, err := extractOCICompressedLayer(context.Background(), blob, test.mediaType, rootfs, 1<<20); err != nil {
				t.Fatalf("extractOCICompressedLayer() error = %v", err)
			}
			if got, err := os.ReadFile(filepath.Join(rootfs, "etc", "os-release")); err != nil || string(got) != "ID=test\n" {
				t.Fatalf("extracted file = %q, err=%v", got, err)
			}
		})
	}
}

func zstdCompress(t *testing.T, input []byte) []byte {
	t.Helper()
	writer, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	return writer.EncodeAll(input, nil)
}

func TestApplyOCILayerDoesNotWhiteoutThroughExistingSymlink(t *testing.T) {
	root := t.TempDir()
	rootfs := filepath.Join(root, "rootfs")
	layer := filepath.Join(root, "layer")
	outside := filepath.Join(root, "outside")
	for _, path := range []string{rootfs, layer, outside} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "payload"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkTarget, err := filepath.Rel(rootfs, outside)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linkTarget, filepath.Join(rootfs, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(layer, "escape"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layer, "escape", ".wh.payload"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applyOCILayer(layer, rootfs, nil); err == nil || !strings.Contains(err.Error(), "path escapes") {
		t.Fatalf("applyOCILayer() escape error = %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(outside, "payload")); err != nil || string(got) != "keep" {
		t.Fatalf("layer whiteouted outside rootfs: payload=%q err=%v", got, err)
	}
	if info, err := os.Lstat(filepath.Join(rootfs, "escape")); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("failed import modified escaping symlink: info=%v err=%v", info, err)
	}
}

type testOCILayerBlob struct {
	compressed []byte
	diffID     v1.Hash
	descriptor v1.Descriptor
}

func testOCILayer(t *testing.T, entries []rootfsTarEntry) testOCILayerBlob {
	t.Helper()
	var tarBytes bytes.Buffer
	writer := tar.NewWriter(&tarBytes)
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		header := &tar.Header{Name: entry.name, Typeflag: entry.kind, Mode: mode, Linkname: entry.link, Size: int64(len(entry.body))}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write(tarBytes.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	diffID := sha256Hash(tarBytes.Bytes())
	compressedBytes := compressed.Bytes()
	return testOCILayerBlob{
		compressed: compressedBytes,
		diffID:     diffID,
		descriptor: v1.Descriptor{MediaType: types.OCILayer, Digest: sha256Hash(compressedBytes), Size: int64(len(compressedBytes))},
	}
}

func testOCILayerFromArchive(t *testing.T, archivePath string) testOCILayerBlob {
	t.Helper()
	tarBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("read rootfs archive for live OCI registry: %v", err)
	}
	reader := tar.NewReader(bytes.NewReader(tarBytes))
	if _, err := reader.Next(); err != nil {
		t.Fatalf("validate rootfs archive for live OCI registry: %v", err)
	}
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write(tarBytes); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	compressedBytes := compressed.Bytes()
	return testOCILayerBlob{
		compressed: compressedBytes,
		diffID:     sha256Hash(tarBytes),
		descriptor: v1.Descriptor{MediaType: types.OCILayer, Digest: sha256Hash(compressedBytes), Size: int64(len(compressedBytes))},
	}
}

func sha256Hash(data []byte) v1.Hash {
	digest := sha256.Sum256(data)
	return v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(digest[:])}
}

type testOCIRegistry struct {
	server               *httptest.Server
	manifests            map[string][]byte
	blobs                map[string][]byte
	rootDigest           string
	username             string
	password             string
	headDigestOverrides  map[string]string
	getDigestOverrides   map[string]string
	failManifestRequests map[string]int
	requestMu            sync.Mutex
	requests             []string
}

func newTestOCIRegistry(t *testing.T) *testOCIRegistry {
	t.Helper()
	registry := &testOCIRegistry{manifests: make(map[string][]byte), blobs: make(map[string][]byte)}
	registry.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		registry.requestMu.Lock()
		registry.requests = append(registry.requests, request.Method+" "+request.URL.Path)
		registry.requestMu.Unlock()
		if registry.username != "" {
			username, password, ok := request.BasicAuth()
			if !ok || username != registry.username || password != registry.password {
				response.Header().Set("WWW-Authenticate", `Basic realm="test OCI registry"`)
				http.Error(response, "registry authentication required", http.StatusUnauthorized)
				return
			}
		}
		if request.URL.Path == "/v2/" {
			response.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
			response.WriteHeader(http.StatusOK)
			return
		}
		const manifestsPrefix = "/v2/agent/manifests/"
		const blobsPrefix = "/v2/agent/blobs/"
		if strings.HasPrefix(request.URL.Path, manifestsPrefix) {
			identifier := strings.TrimPrefix(request.URL.Path, manifestsPrefix)
			body, ok := registry.manifests[identifier]
			if !ok {
				http.NotFound(response, request)
				return
			}
			failureKey := request.Method + " " + identifier
			registry.requestMu.Lock()
			if registry.failManifestRequests[failureKey] > 0 {
				registry.failManifestRequests[failureKey]--
				registry.requestMu.Unlock()
				http.Error(response, "temporary registry failure", http.StatusServiceUnavailable)
				return
			}
			registry.requestMu.Unlock()
			response.Header().Set("Content-Type", manifestMediaType(body))
			digest := "sha256:" + digestSHA256(body)
			if request.Method == http.MethodHead {
				if override := registry.headDigestOverrides[identifier]; override != "" {
					digest = override
				}
			} else if override := registry.getDigestOverrides[identifier]; override != "" {
				digest = override
			}
			response.Header().Set("Docker-Content-Digest", digest)
			response.Header().Set("Content-Length", fmt.Sprint(len(body)))
			if request.Method == http.MethodHead {
				response.WriteHeader(http.StatusOK)
				return
			}
			_, _ = response.Write(body)
			return
		}
		if strings.HasPrefix(request.URL.Path, blobsPrefix) {
			digest := strings.TrimPrefix(request.URL.Path, blobsPrefix)
			body, ok := registry.blobs[digest]
			if !ok {
				http.NotFound(response, request)
				return
			}
			response.Header().Set("Content-Length", fmt.Sprint(len(body)))
			_, _ = response.Write(body)
			return
		}
		http.NotFound(response, request)
	}))
	t.Cleanup(registry.server.Close)
	return registry
}

func (registry *testOCIRegistry) recordedRequests() []string {
	registry.requestMu.Lock()
	defer registry.requestMu.Unlock()
	return append([]string(nil), registry.requests...)
}

func (registry *testOCIRegistry) requireBasicAuth(username, password string) {
	registry.username = username
	registry.password = password
}

func (registry *testOCIRegistry) publishImageIndex(t *testing.T, layers []testOCILayerBlob, platform v1.Platform) {
	registry.publishImageIndexWithManifestAlgorithm(t, layers, platform, "sha256")
}

func (registry *testOCIRegistry) publishImageIndexWithManifestAlgorithm(t *testing.T, layers []testOCILayerBlob, platform v1.Platform, algorithm string) {
	registry.publishImageIndexWithConfigAndAlgorithm(t, layers, platform, v1.Config{}, algorithm)
}

func (registry *testOCIRegistry) publishImageIndexWithConfig(t *testing.T, layers []testOCILayerBlob, platform v1.Platform, imageConfig v1.Config) {
	registry.publishImageIndexWithConfigAndAlgorithm(t, layers, platform, imageConfig, "sha256")
}

func (registry *testOCIRegistry) publishImageIndexWithConfigAndAlgorithm(t *testing.T, layers []testOCILayerBlob, platform v1.Platform, imageConfig v1.Config, algorithm string) {
	t.Helper()
	var diffIDs []v1.Hash
	for _, layer := range layers {
		diffIDs = append(diffIDs, layer.diffID)
		registry.blobs[layer.descriptor.Digest.String()] = layer.compressed
	}
	configBytes, err := json.Marshal(v1.ConfigFile{
		Architecture: platform.Architecture,
		OS:           platform.OS,
		RootFS:       v1.RootFS{Type: "layers", DiffIDs: diffIDs},
		Config:       imageConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	configDescriptor := v1.Descriptor{MediaType: types.OCIConfigJSON, Digest: sha256Hash(configBytes), Size: int64(len(configBytes))}
	registry.blobs[configDescriptor.Digest.String()] = configBytes
	manifest := v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: configDescriptor}
	for _, layer := range layers {
		manifest.Layers = append(manifest.Layers, layer.descriptor)
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digestWithAlgorithm(t, manifestBytes, algorithm)
	registry.manifests[manifestDigest.String()] = manifestBytes
	index := v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests: []v1.Descriptor{{
			MediaType: types.OCIManifestSchema1,
			Digest:    manifestDigest,
			Size:      int64(len(manifestBytes)),
			Platform:  &platform,
		}},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	registry.manifests["latest"] = indexBytes
	registry.rootDigest = sha256Hash(indexBytes).String()
	registry.manifests[registry.rootDigest] = indexBytes
}

func digestWithAlgorithm(t *testing.T, content []byte, algorithm string) v1.Hash {
	t.Helper()
	switch algorithm {
	case "sha256":
		return sha256Hash(content)
	case "sha512":
		digest := sha512.Sum512(content)
		return v1.Hash{Algorithm: "sha512", Hex: hex.EncodeToString(digest[:])}
	default:
		t.Fatalf("unsupported test digest algorithm %q", algorithm)
		return v1.Hash{}
	}
}

func manifestMediaType(body []byte) string {
	var header struct {
		MediaType string `json:"mediaType"`
	}
	_ = json.Unmarshal(body, &header)
	return header.MediaType
}
