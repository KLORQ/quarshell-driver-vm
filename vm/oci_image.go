package vm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/klauspost/compress/zstd"
	"github.com/moby/go-archive"
)

const (
	rootfsRegistryMaxCompressedBytes = int64(16 << 30)
	rootfsRegistryMaxLayers          = 256
	defaultRegistryLayerConcurrency  = 4
	maxRegistryLayerConcurrency      = 16
)

var errOCIManifestNotFound = errors.New("selected OCI manifest not found in index")

type resolvedOCIImage struct {
	Image                  v1.Image
	ImageConfig            v1.Config
	RequestedReference     string
	SourceManifestDigest   string
	PlatformManifestDigest string
	LocalEngineImageID     string
	LocalArchivePath       string
	Platform               v1.Platform
}

func vmOCIPlatform() (v1.Platform, error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return v1.Platform{}, fmt.Errorf("VM OCI images are unsupported on host architecture %q", runtime.GOARCH)
	}
	return v1.Platform{OS: "linux", Architecture: runtime.GOARCH}, nil
}

func parseOCIImageReference(imageRef string) (name.Reference, error) {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return nil, fmt.Errorf("OCI image reference is required")
	}
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid OCI image reference %q: %w", imageRef, err)
	}
	return ref, nil
}

func resolveOCIImageWithOptions(ctx context.Context, imageRef string, platform v1.Platform, nameOptions []name.Option, remoteOptions []remote.Option) (resolvedOCIImage, error) {
	if ctx == nil {
		return resolvedOCIImage{}, fmt.Errorf("OCI image resolution context is nil")
	}
	if err := ctx.Err(); err != nil {
		return resolvedOCIImage{}, err
	}
	if platform.OS != "linux" || platform.Architecture == "" {
		return resolvedOCIImage{}, fmt.Errorf("VM OCI platform must specify linux and an architecture")
	}
	var ref name.Reference
	var err error
	if len(nameOptions) == 0 {
		ref, err = parseOCIImageReference(imageRef)
	} else {
		ref, err = name.ParseReference(strings.TrimSpace(imageRef), nameOptions...)
	}
	if err != nil {
		return resolvedOCIImage{}, fmt.Errorf("parse OCI image reference %q: %w", imageRef, err)
	}
	if len(remoteOptions) == 0 {
		remoteOptions = []remote.Option{
			remote.WithContext(ctx),
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
			remote.WithPlatform(platform),
		}
	}
	// Snapshot mutable tags by their registry-advertised digest, then fetch
	// that immutable reference. The remote client verifies the GET body against
	// the requested digest, so a tag that moves between the two requests cannot
	// silently change the image selected for this preparation.
	if _, isTag := ref.(name.Tag); isTag {
		head, headErr := remote.Head(ref, remoteOptions...)
		if headErr != nil {
			return resolvedOCIImage{}, fmt.Errorf("pin OCI image tag %q: %w", imageRef, headErr)
		}
		if head.Digest.Algorithm == "" || head.Digest.Hex == "" {
			return resolvedOCIImage{}, fmt.Errorf("pin OCI image tag %q: registry returned an empty manifest digest", imageRef)
		}
		ref = ref.Context().Digest(head.Digest.String())
	}
	descriptor, err := remote.Get(ref, remoteOptions...)
	if err != nil {
		return resolvedOCIImage{}, fmt.Errorf("resolve OCI image %q: %w", imageRef, err)
	}
	image, err := descriptor.Image()
	if err != nil {
		return resolvedOCIImage{}, fmt.Errorf("select OCI image platform %s for %q: %w", platform.String(), imageRef, err)
	}
	config, err := image.ConfigFile()
	if err != nil {
		return resolvedOCIImage{}, fmt.Errorf("read OCI image config %q: %w", imageRef, err)
	}
	if config.OS != platform.OS || config.Architecture != platform.Architecture {
		return resolvedOCIImage{}, fmt.Errorf("OCI image %q config platform is %s/%s; requested %s", imageRef, config.OS, config.Architecture, platform.String())
	}
	manifestDigest, err := selectedOCIManifestDigest(descriptor, image, platform)
	if err != nil {
		return resolvedOCIImage{}, fmt.Errorf("identify selected OCI manifest %q: %w", imageRef, err)
	}
	return resolvedOCIImage{
		Image:                  image,
		ImageConfig:            config.Config,
		RequestedReference:     imageRef,
		SourceManifestDigest:   descriptor.Digest.String(),
		PlatformManifestDigest: manifestDigest,
		Platform:               platform,
	}, nil
}

// resolveOCIImageAtDigestWithOptions retrieves the selected platform image by
// its immutable manifest digest. Recovery does not follow a moved tag.
func resolveOCIImageAtDigestWithOptions(ctx context.Context, imageRef, manifestDigest string, platform v1.Platform, nameOptions []name.Option, remoteOptions []remote.Option) (resolvedOCIImage, error) {
	var ref name.Reference
	var err error
	if len(nameOptions) == 0 {
		ref, err = parseOCIImageReference(imageRef)
	} else {
		ref, err = name.ParseReference(strings.TrimSpace(imageRef), nameOptions...)
	}
	if err != nil {
		return resolvedOCIImage{}, err
	}
	pinned := ref.Context().Digest(manifestDigest)
	resolved, err := resolveOCIImageWithOptions(ctx, pinned.String(), platform, nameOptions, remoteOptions)
	if err != nil {
		return resolvedOCIImage{}, err
	}
	if resolved.PlatformManifestDigest != manifestDigest {
		return resolvedOCIImage{}, fmt.Errorf("OCI image %q resolved to platform manifest %s; durable state requires %s", imageRef, resolved.PlatformManifestDigest, manifestDigest)
	}
	resolved.RequestedReference = imageRef
	return resolved, nil
}

func selectedOCIManifestDigest(descriptor *remote.Descriptor, image v1.Image, platform v1.Platform) (string, error) {
	if descriptor == nil || image == nil {
		return "", fmt.Errorf("OCI manifest descriptor and image are required")
	}
	switch descriptor.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		selectedManifest, err := image.RawManifest()
		if err != nil {
			return "", err
		}
		index, err := descriptor.ImageIndex()
		if err != nil {
			return "", err
		}
		return findOCIManifestDigest(index, selectedManifest, platform)
	default:
		return descriptor.Digest.String(), nil
	}
}

func findOCIManifestDigest(index v1.ImageIndex, selectedManifest []byte, platform v1.Platform) (string, error) {
	manifest, err := index.IndexManifest()
	if err != nil {
		return "", err
	}
	for _, child := range manifest.Manifests {
		if child.Platform != nil && !child.Platform.Satisfies(platform) {
			continue
		}
		switch child.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			nested, err := index.ImageIndex(child.Digest)
			if err != nil {
				return "", err
			}
			digest, err := findOCIManifestDigest(nested, selectedManifest, platform)
			if err == nil {
				return digest, nil
			}
			if !errors.Is(err, errOCIManifestNotFound) {
				return "", err
			}
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			if child.Platform == nil {
				continue
			}
			candidate, err := index.Image(child.Digest)
			if err != nil {
				return "", err
			}
			candidateManifest, err := candidate.RawManifest()
			if err != nil {
				return "", err
			}
			if bytes.Equal(candidateManifest, selectedManifest) {
				return child.Digest.String(), nil
			}
		}
	}
	return "", fmt.Errorf("selected manifest for %s is not present in the registry index: %w", platform.String(), errOCIManifestNotFound)
}

func (resolved resolvedOCIImage) cacheIdentity() string {
	return "oci:" + resolved.SourceManifestDigest + ":" + resolved.PlatformManifestDigest + ":" + resolved.Platform.String()
}

func prepareOCIImageRootfsWithNameOptions(ctx context.Context, imageRef, cacheDir, formatterPath, guestAgentPath string, cacheMaxBytes int64, nameOptions []name.Option, guestUMOCIPath ...string) (preparedRootfsImage, resolvedOCIImage, error) {
	platform, err := vmOCIPlatform()
	if err != nil {
		return preparedRootfsImage{}, resolvedOCIImage{}, err
	}
	resolved, err := resolveOCIImageWithOptions(ctx, imageRef, platform, nameOptions, nil)
	if err != nil {
		return preparedRootfsImage{}, resolvedOCIImage{}, err
	}
	guestDigest, err := validateGuestAgent(guestAgentPath)
	if err != nil {
		return preparedRootfsImage{}, resolvedOCIImage{}, err
	}
	prepared, err := prepareRootfsImageFromSource(ctx, cacheDir, formatterPath, guestAgentPath, resolved.cacheIdentity(), guestDigest, cacheMaxBytes, func(rootfsDir string) error {
		return populateRootfsFromOCI(ctx, resolved.Image, resolved.RequestedReference, resolved.Platform, rootfsDir)
	}, guestUMOCIPath...)
	if err != nil {
		return preparedRootfsImage{}, resolvedOCIImage{}, err
	}
	return prepared, resolved, nil
}

// prepareOCIWorkloadDisk builds a second immutable disk whose filesystem root
// contains the OCI workload tree under /image-rootfs. The guest boot root stays
// independent and can provide the VM control plane and init implementation.
func prepareOCIWorkloadDisk(ctx context.Context, imageRef, cacheDir, formatterPath, guestAgentPath string, cacheMaxBytes int64, nameOptions []name.Option) (preparedRootfsImage, resolvedOCIImage, error) {
	resolved, err := resolveWorkloadOCI(ctx, imageRef, nameOptions)
	if err != nil {
		return preparedRootfsImage{}, resolvedOCIImage{}, err
	}
	prepared, err := prepareOCIWorkloadDiskFromResolved(ctx, resolved, cacheDir, formatterPath, guestAgentPath, cacheMaxBytes)
	if err != nil {
		return preparedRootfsImage{}, resolvedOCIImage{}, err
	}
	return prepared, resolved, nil
}

func resolveWorkloadOCI(ctx context.Context, imageRef string, nameOptions []name.Option) (resolvedOCIImage, error) {
	platform, err := vmOCIPlatform()
	if err != nil {
		return resolvedOCIImage{}, err
	}
	return resolveOCIImageWithOptions(ctx, imageRef, platform, nameOptions, nil)
}

func prepareOCIWorkloadDiskFromResolved(ctx context.Context, resolved resolvedOCIImage, cacheDir, formatterPath, guestAgentPath string, cacheMaxBytes int64) (preparedRootfsImage, error) {
	guestDigest, err := validateGuestAgent(guestAgentPath)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	identity := "oci-workload-disk-v1:" + resolved.cacheIdentity()
	prepared, err := prepareRootfsImageFromSource(ctx, cacheDir, formatterPath, guestAgentPath, identity, guestDigest, cacheMaxBytes, func(rootfsDir string) error {
		return populateOCIWorkloadRootfs(ctx, resolved.Image, resolved.RequestedReference, resolved.Platform, guestAgentPath, rootfsDir)
	})
	if err != nil {
		return preparedRootfsImage{}, err
	}
	return prepared, nil
}

func populateOCIWorkloadRootfs(ctx context.Context, image v1.Image, imageRef string, platform v1.Platform, guestAgentPath, diskRoot string) error {
	workloadRoot := filepath.Join(diskRoot, "image-rootfs")
	if err := os.MkdirAll(workloadRoot, 0o700); err != nil {
		return fmt.Errorf("create workload rootfs mount directory: %w", err)
	}
	if err := populateRootfsFromOCI(ctx, image, imageRef, platform, workloadRoot); err != nil {
		return err
	}
	if err := installGuestRuntime(workloadRoot, guestAgentPath); err != nil {
		return fmt.Errorf("install guest runtime in workload image: %w", err)
	}
	return nil
}

func populateRootfsFromOCI(ctx context.Context, image v1.Image, imageRef string, platform v1.Platform, rootfsDir string) error {
	manifest, err := image.Manifest()
	if err != nil {
		return fmt.Errorf("read OCI manifest for %q: %w", imageRef, err)
	}
	if len(manifest.Layers) > rootfsRegistryMaxLayers {
		return fmt.Errorf("OCI image %q has %d layers, exceeding the %d layer limit", imageRef, len(manifest.Layers), rootfsRegistryMaxLayers)
	}
	layers, err := image.Layers()
	if err != nil {
		return fmt.Errorf("read OCI layers for %q: %w", imageRef, err)
	}
	if len(layers) != len(manifest.Layers) {
		return fmt.Errorf("OCI image %q has inconsistent manifest and layer counts", imageRef)
	}
	config, err := image.ConfigFile()
	if err != nil {
		return fmt.Errorf("read OCI config for %q: %w", imageRef, err)
	}
	if len(config.RootFS.DiffIDs) != len(layers) {
		return fmt.Errorf("OCI image %q has %d rootfs diff IDs for %d layers", imageRef, len(config.RootFS.DiffIDs), len(layers))
	}
	var compressedTotal int64
	for _, descriptor := range manifest.Layers {
		if descriptor.Size < 0 || descriptor.Size > rootfsRegistryMaxCompressedBytes-compressedTotal {
			return fmt.Errorf("OCI image %q compressed layers exceed the %d byte limit", imageRef, rootfsRegistryMaxCompressedBytes)
		}
		compressedTotal += descriptor.Size
		if err := validateOCILayerMediaType(string(descriptor.MediaType)); err != nil {
			return fmt.Errorf("OCI image %q: %w", imageRef, err)
		}
	}

	stagingDir, err := os.MkdirTemp(filepath.Dir(rootfsDir), ".oci-layer-staging-*")
	if err != nil {
		return fmt.Errorf("create OCI layer staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDir)
	if err := os.Chmod(stagingDir, 0o700); err != nil {
		return fmt.Errorf("secure OCI layer staging directory: %w", err)
	}
	if err := downloadOCIImageLayers(ctx, len(layers), registryLayerDownloadConcurrency(), func(downloadCtx context.Context, index int) error {
		descriptor := manifest.Layers[index]
		blobPath := filepath.Join(stagingDir, fmt.Sprintf("layer-%03d.blob", index))
		if err := downloadOCICompressedLayer(downloadCtx, layers[index], descriptor, blobPath); err != nil {
			return fmt.Errorf("download OCI layer %d (%s) for %q: %w", index, descriptor.Digest, imageRef, err)
		}
		return nil
	}); err != nil {
		return err
	}
	var expandedTotal int64
	for index, descriptor := range manifest.Layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		blobPath := filepath.Join(stagingDir, fmt.Sprintf("layer-%03d.blob", index))
		layerDir := filepath.Join(stagingDir, fmt.Sprintf("layer-%03d", index))
		layerExpanded, diffID, entryModes, err := extractOCICompressedLayer(ctx, blobPath, string(descriptor.MediaType), layerDir, rootfsExpandedMaxBytes-expandedTotal)
		if err != nil {
			return fmt.Errorf("extract OCI layer %d (%s) for %q: %w", index, descriptor.Digest, imageRef, err)
		}
		if diffID != config.RootFS.DiffIDs[index] {
			return fmt.Errorf("OCI image %q layer %d diff ID %s does not match config %s", imageRef, index, diffID, config.RootFS.DiffIDs[index])
		}
		expandedTotal += layerExpanded
		if err := applyOCILayer(layerDir, rootfsDir, entryModes); err != nil {
			return fmt.Errorf("apply OCI layer %d for %q on %s: %w", index, imageRef, platform.String(), err)
		}
		if err := os.Remove(blobPath); err != nil {
			return fmt.Errorf("remove downloaded OCI layer blob: %w", err)
		}
		if err := os.RemoveAll(layerDir); err != nil {
			return fmt.Errorf("remove extracted OCI layer: %w", err)
		}
	}
	return nil
}

func registryLayerDownloadConcurrency() int {
	return registryLayerDownloadConcurrencyValue(os.Getenv("OPENSHELL_VM_IMAGE_PULL_CONCURRENCY"))
}

func registryLayerDownloadConcurrencyValue(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return defaultRegistryLayerConcurrency
	}
	if value > maxRegistryLayerConcurrency {
		return maxRegistryLayerConcurrency
	}
	return value
}

func downloadOCIImageLayers(ctx context.Context, count, concurrency int, download func(context.Context, int) error) error {
	if ctx == nil || download == nil {
		return fmt.Errorf("OCI layer download requires a context and callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if count <= 0 {
		return nil
	}
	if concurrency <= 0 {
		concurrency = defaultRegistryLayerConcurrency
	}
	if concurrency > maxRegistryLayerConcurrency {
		concurrency = maxRegistryLayerConcurrency
	}
	if concurrency > count {
		concurrency = count
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var next atomic.Int64
	var workers sync.WaitGroup
	firstErr := make(chan error, 1)
	workers.Add(concurrency)
	for worker := 0; worker < concurrency; worker++ {
		go func() {
			defer workers.Done()
			for {
				if err := workCtx.Err(); err != nil {
					return
				}
				index := int(next.Add(1) - 1)
				if index >= count {
					return
				}
				if err := download(workCtx, index); err != nil {
					select {
					case firstErr <- err:
					default:
					}
					cancel()
					return
				}
			}
		}()
	}
	workers.Wait()
	select {
	case err := <-firstErr:
		return err
	default:
	}
	return ctx.Err()
}

func downloadOCICompressedLayer(ctx context.Context, layer v1.Layer, descriptor v1.Descriptor, destination string) error {
	if descriptor.Size < 0 || descriptor.Size > rootfsRegistryMaxCompressedBytes {
		return fmt.Errorf("invalid compressed layer size %d", descriptor.Size)
	}
	reader, err := layer.Compressed()
	if err != nil {
		return err
	}
	defer reader.Close()
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	hasher, err := v1.Hasher(descriptor.Digest.Algorithm)
	if err != nil {
		return fmt.Errorf("unsupported layer digest algorithm %q: %w", descriptor.Digest.Algorithm, err)
	}
	bounded := &contextReader{ctx: ctx, reader: io.LimitReader(reader, descriptor.Size+1)}
	written, err := io.Copy(io.MultiWriter(file, hasher), bounded)
	if err != nil {
		return fmt.Errorf("read compressed layer: %w", err)
	}
	if written != descriptor.Size {
		return fmt.Errorf("compressed layer size is %d bytes; manifest declares %d", written, descriptor.Size)
	}
	digest := v1.Hash{Algorithm: descriptor.Digest.Algorithm, Hex: hex.EncodeToString(hasher.Sum(nil))}
	if digest != descriptor.Digest {
		return fmt.Errorf("compressed layer digest %s does not match manifest digest %s", digest, descriptor.Digest)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync compressed layer: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close compressed layer: %w", err)
	}
	closed = true
	return nil
}

func validateOCILayerMediaType(mediaType string) error {
	switch {
	case mediaType == "application/vnd.oci.image.layer.v1.tar",
		mediaType == "application/vnd.oci.image.layer.nondistributable.v1.tar",
		mediaType == "application/vnd.docker.image.rootfs.diff.tar":
		return nil
	case strings.HasSuffix(mediaType, "+gzip"), strings.HasSuffix(mediaType, ".gzip"):
		return nil
	case strings.HasSuffix(mediaType, "+zstd"):
		return nil
	default:
		return fmt.Errorf("unsupported OCI layer media type %q", mediaType)
	}
}

func extractOCICompressedLayer(ctx context.Context, blobPath, mediaType, layerDir string, maxExpanded int64) (int64, v1.Hash, map[string]os.FileMode, error) {
	if maxExpanded <= 0 {
		return 0, v1.Hash{}, nil, fmt.Errorf("expanded OCI rootfs exceeds %d byte limit", rootfsExpandedMaxBytes)
	}
	file, err := os.Open(blobPath)
	if err != nil {
		return 0, v1.Hash{}, nil, err
	}
	defer file.Close()
	if err := os.Mkdir(layerDir, 0o700); err != nil {
		return 0, v1.Hash{}, nil, err
	}
	var input io.Reader = &contextReader{ctx: ctx, reader: file}
	var closer io.Closer
	switch {
	case strings.HasSuffix(mediaType, "+gzip"), strings.HasSuffix(mediaType, ".gzip"):
		gzipReader, err := gzip.NewReader(input)
		if err != nil {
			return 0, v1.Hash{}, nil, fmt.Errorf("open gzip layer: %w", err)
		}
		input, closer = gzipReader, gzipReader
	case strings.HasSuffix(mediaType, "+zstd"):
		zstdReader, err := zstd.NewReader(input)
		if err != nil {
			return 0, v1.Hash{}, nil, fmt.Errorf("open zstd layer: %w", err)
		}
		input, closer = zstdReader, zstdReader.IOReadCloser()
	}
	if closer != nil {
		defer closer.Close()
	}
	hasher := sha256.New()
	bounded := &boundedReader{reader: io.TeeReader(input, hasher), limit: maxExpanded}
	relaxedTar, transformDone := relaxOCILayerDirectoryModes(bounded)
	unpackErr := archive.UntarUncompressed(relaxedTar, layerDir, &archive.TarOptions{
		NoLchown:             true,
		NoOverwriteDirNonDir: true,
	})
	if unpackErr != nil {
		_ = relaxedTar.CloseWithError(unpackErr)
	}
	transformResult := <-transformDone
	if unpackErr != nil {
		return 0, v1.Hash{}, nil, unpackErr
	}
	if transformResult.err != nil {
		return 0, v1.Hash{}, nil, transformResult.err
	}
	if _, err := io.Copy(io.Discard, bounded); err != nil {
		return 0, v1.Hash{}, nil, fmt.Errorf("finish decompressed OCI layer: %w", err)
	}
	if bounded.exceeded {
		return 0, v1.Hash{}, nil, fmt.Errorf("expanded OCI layer exceeds remaining %d byte limit", maxExpanded)
	}
	if err := restoreOCILayerSpecialModes(ctx, blobPath, mediaType, layerDir); err != nil {
		return 0, v1.Hash{}, nil, fmt.Errorf("restore OCI layer special permission bits: %w", err)
	}
	entryModes := make(map[string]os.FileMode, len(transformResult.entryModes))
	for name, mode := range transformResult.entryModes {
		entryModes[name] = mode
	}
	return bounded.read, v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(hasher.Sum(nil))}, entryModes, nil
}

type relaxedOCILayerTarResult struct {
	entryModes map[string]os.FileMode
	err        error
}

// relaxOCILayerDirectoryModes keeps read-only layer directories writable while
// archive entries are extracted. Their original modes are restored from the
// unmodified layer stream afterward. Without this, a 0555 directory appearing
// before its children prevents non-root OCI importers from creating symlinks
// or files beneath it.
func relaxOCILayerDirectoryModes(input io.Reader) (*io.PipeReader, <-chan relaxedOCILayerTarResult) {
	reader, writer := io.Pipe()
	done := make(chan relaxedOCILayerTarResult, 1)
	go func() {
		archiveReader := tar.NewReader(input)
		archiveWriter := tar.NewWriter(writer)
		var result error
		entryModes := make(map[string]os.FileMode)
		for {
			header, err := archiveReader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				result = err
				break
			}
			switch header.Typeflag {
			case tar.TypeDir:
				name := path.Clean(strings.TrimPrefix(header.Name, "./"))
				if name != "." {
					entryModes[name] = os.FileMode(header.Mode).Perm() | ociSpecialModeFromTar(header.Mode)
				}
				copy := *header
				copy.Mode |= 0o700
				header = &copy
			case tar.TypeReg, 0:
				name := path.Clean(strings.TrimPrefix(header.Name, "./"))
				if name != "." {
					entryModes[name] = os.FileMode(header.Mode).Perm() | ociSpecialModeFromTar(header.Mode)
				}
				copy := *header
				copy.Mode |= 0o600
				header = &copy
			}
			if err := archiveWriter.WriteHeader(header); err != nil {
				result = err
				break
			}
			if header.Size > 0 {
				if _, err := io.CopyN(archiveWriter, archiveReader, header.Size); err != nil {
					result = err
					break
				}
			}
		}
		if result == nil {
			result = archiveWriter.Close()
		}
		done <- relaxedOCILayerTarResult{entryModes: entryModes, err: result}
		_ = writer.CloseWithError(result)
	}()
	return reader, done
}

func restoreOCILayerSpecialModes(ctx context.Context, blobPath, mediaType, layerDir string) error {
	file, err := os.Open(blobPath)
	if err != nil {
		return err
	}
	defer file.Close()
	var input io.Reader = &contextReader{ctx: ctx, reader: file}
	var closer io.Closer
	switch {
	case strings.HasSuffix(mediaType, "+gzip"), strings.HasSuffix(mediaType, ".gzip"):
		reader, err := gzip.NewReader(input)
		if err != nil {
			return err
		}
		input, closer = reader, reader
	case strings.HasSuffix(mediaType, "+zstd"):
		reader, err := zstd.NewReader(input)
		if err != nil {
			return err
		}
		input, closer = reader, reader.IOReadCloser()
	}
	if closer != nil {
		defer closer.Close()
	}
	root, err := os.OpenRoot(layerDir)
	if err != nil {
		return err
	}
	defer root.Close()
	reader := tar.NewReader(input)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		special := ociSpecialModeFromTar(header.Mode)
		isDirectory := header.Typeflag == tar.TypeDir
		if special == 0 && !isDirectory {
			continue
		}
		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if name == "." || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("layer path %q escapes extraction root", header.Name)
		}
		// Typeflag 0 is the legacy NUL encoding of a regular tar file.
		if header.Typeflag != tar.TypeReg && header.Typeflag != 0 && header.Typeflag != tar.TypeDir {
			continue
		}
		components := strings.Split(name, "/")
		for index := 1; index < len(components); index++ {
			parent := path.Join(components[:index]...)
			info, err := root.Lstat(filepath.FromSlash(parent))
			if err != nil {
				return fmt.Errorf("inspect parent %q: %w", parent, err)
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("layer parent %q is not a real directory", parent)
			}
		}
		info, err := root.Lstat(filepath.FromSlash(name))
		if err != nil {
			return fmt.Errorf("inspect entry %q: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || (header.Typeflag == tar.TypeDir) != info.IsDir() {
			return fmt.Errorf("entry %q changed type while restoring permission bits", name)
		}
		if isDirectory {
			// Keep staging directories writable until their entries have been
			// copied and the temporary layer can be removed. The original mode
			// is carried separately and applied to the merged rootfs.
			continue
		}
		if err := root.Chmod(filepath.FromSlash(name), info.Mode()|special); err != nil {
			return fmt.Errorf("chmod %q: %w", name, err)
		}
	}
	return nil
}

func ociSpecialModeFromTar(mode int64) os.FileMode {
	var special os.FileMode
	if mode&0o4000 != 0 {
		special |= os.ModeSetuid
	}
	if mode&0o2000 != 0 {
		special |= os.ModeSetgid
	}
	if mode&0o1000 != 0 {
		special |= os.ModeSticky
	}
	return special
}

func applyOCILayer(layerDir, rootfsDir string, entryModes map[string]os.FileMode) error {
	source, err := os.OpenRoot(layerDir)
	if err != nil {
		return fmt.Errorf("open extracted layer root: %w", err)
	}
	defer source.Close()
	destination, err := os.OpenRoot(rootfsDir)
	if err != nil {
		return fmt.Errorf("open merged rootfs: %w", err)
	}
	defer destination.Close()
	var entries []string
	err = filepath.WalkDir(layerDir, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == layerDir {
			return nil
		}
		relative, err := filepath.Rel(layerDir, filePath)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." || path.IsAbs(relative) || strings.HasPrefix(relative, "../") || strings.Contains(relative, "/../") {
			return fmt.Errorf("layer path %q escapes extraction root", relative)
		}
		entries = append(entries, relative)
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk extracted OCI layer: %w", err)
	}
	sort.Strings(entries)
	writableDirectories := make(map[string]os.FileMode)
	for _, entry := range entries {
		if err := relaxOCIParentDirectories(destination, entry, writableDirectories); err != nil {
			return fmt.Errorf("make rootfs parents writable for %q: %w", entry, err)
		}
	}
	for _, entry := range entries {
		base := path.Base(entry)
		if base == ".wh..wh..opq" {
			if err := clearOCIPath(destination, path.Dir(entry)); err != nil {
				return fmt.Errorf("apply opaque whiteout %q: %w", entry, err)
			}
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			name := strings.TrimPrefix(base, ".wh.")
			if name == "" || name == "." || name == ".." {
				return fmt.Errorf("invalid OCI whiteout entry %q", entry)
			}
			target := path.Join(path.Dir(entry), name)
			if err := removeOCIPath(destination, target); err != nil {
				return fmt.Errorf("apply whiteout %q: %w", entry, err)
			}
		}
	}
	for _, entry := range entries {
		base := path.Base(entry)
		if strings.HasPrefix(base, ".wh.") {
			continue
		}
		info, err := source.Lstat(filepath.FromSlash(entry))
		if err != nil {
			return fmt.Errorf("inspect layer entry %q: %w", entry, err)
		}
		if info.IsDir() {
			if err := ensureOCIDirectory(destination, entry); err != nil {
				return fmt.Errorf("create layer directory %q: %w", entry, err)
			}
			if err := copyOCIDirectoryXattrs(source, destination, entry); err != nil {
				return fmt.Errorf("copy layer directory attributes %q: %w", entry, err)
			}
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if err := ensureOCIParent(destination, entry); err != nil {
				return err
			}
			if err := removeOCIPath(destination, entry); err != nil {
				return err
			}
			target, err := source.Readlink(filepath.FromSlash(entry))
			if err != nil {
				return fmt.Errorf("read layer symlink %q: %w", entry, err)
			}
			if err := destination.Symlink(target, filepath.FromSlash(entry)); err != nil {
				return fmt.Errorf("create layer symlink %q: %w", entry, err)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			if strings.HasPrefix(entry, "dev/") {
				continue
			}
			return fmt.Errorf("unsupported special file %q with mode %s", entry, info.Mode())
		}
		mode, hasLayerMode := entryModes[entry]
		if !hasLayerMode {
			mode = info.Mode()
		}
		if err := copyOCIRegularFile(source, destination, entry, mode, info.ModTime()); err != nil {
			return fmt.Errorf("copy layer file %q: %w", entry, err)
		}
	}
	layerDirectories := make(map[string]struct{})
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		info, err := source.Lstat(filepath.FromSlash(entry))
		if err != nil || !info.IsDir() {
			continue
		}
		mode, explicit := entryModes[entry]
		if !explicit {
			continue
		}
		layerDirectories[entry] = struct{}{}
		if err := destination.Chmod(filepath.FromSlash(entry), mode); err != nil {
			return fmt.Errorf("set layer directory mode %q: %w", entry, err)
		}
		if err := destination.Chtimes(filepath.FromSlash(entry), info.ModTime(), info.ModTime()); err != nil {
			return fmt.Errorf("set layer directory time %q: %w", entry, err)
		}
	}
	if err := restoreOCIParentDirectoryModes(destination, writableDirectories, layerDirectories); err != nil {
		return fmt.Errorf("restore rootfs directory modes: %w", err)
	}
	return nil
}

func relaxOCIParentDirectories(root *os.Root, name string, modes map[string]os.FileMode) error {
	parent := path.Dir(name)
	if parent == "." || parent == "" {
		return nil
	}
	current := ""
	for _, component := range strings.Split(parent, "/") {
		if component == "" || component == "." {
			continue
		}
		current = path.Join(current, component)
		if _, alreadyRelaxed := modes[current]; alreadyRelaxed {
			continue
		}
		info, err := root.Lstat(filepath.FromSlash(current))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			info, err = root.Stat(filepath.FromSlash(current))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			mode = info.Mode()
		}
		if !mode.IsDir() || mode.Perm()&0o300 == 0o300 {
			continue
		}
		if err := root.Chmod(filepath.FromSlash(current), mode|0o700); err != nil {
			return err
		}
		modes[current] = mode
	}
	return nil
}

func restoreOCIParentDirectoryModes(root *os.Root, modes map[string]os.FileMode, layerDirectories map[string]struct{}) error {
	paths := make([]string, 0, len(modes))
	for name := range modes {
		if _, replacedByLayer := layerDirectories[name]; !replacedByLayer {
			paths = append(paths, name)
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		depthI := strings.Count(paths[i], "/")
		depthJ := strings.Count(paths[j], "/")
		if depthI == depthJ {
			return paths[i] > paths[j]
		}
		return depthI > depthJ
	})
	for _, name := range paths {
		if err := root.Chmod(filepath.FromSlash(name), modes[name]); err != nil {
			return fmt.Errorf("chmod %q: %w", name, err)
		}
	}
	return nil
}

func ensureOCIDirectory(root *os.Root, name string) error {
	if err := ensureOCIParent(root, name); err != nil {
		return err
	}
	name = filepath.FromSlash(name)
	info, err := root.Lstat(name)
	if err == nil && info.IsDir() {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := root.RemoveAll(name); err != nil {
		return err
	}
	return root.MkdirAll(name, 0o755)
}

func ensureOCIParent(root *os.Root, name string) error {
	parent := filepath.ToSlash(path.Dir(name))
	if parent == "." || parent == "" {
		return nil
	}
	current := ""
	for _, component := range strings.Split(parent, "/") {
		if component == "" || component == "." {
			continue
		}
		current = path.Join(current, component)
		info, err := root.Lstat(filepath.FromSlash(current))
		if errors.Is(err, os.ErrNotExist) {
			if err := root.Mkdir(filepath.FromSlash(current), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			opened, err := root.OpenRoot(filepath.FromSlash(current))
			if err == nil {
				_ = opened.Close()
				continue
			}
			targetInfo, targetErr := root.Stat(filepath.FromSlash(current))
			if targetErr != nil {
				return fmt.Errorf("resolve layer parent symlink %q within rootfs: %w", current, targetErr)
			}
			if targetInfo.IsDir() {
				return fmt.Errorf("open layer parent symlink %q within rootfs: %w", current, err)
			}
		}
		if err := root.RemoveAll(filepath.FromSlash(current)); err != nil {
			return err
		}
		if err := root.Mkdir(filepath.FromSlash(current), 0o755); err != nil {
			return err
		}
	}
	return nil
}

func removeOCIPath(root *os.Root, name string) error {
	if name == "." || name == "" || path.IsAbs(name) || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return fmt.Errorf("invalid rootfs path %q", name)
	}
	err := root.RemoveAll(filepath.FromSlash(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func clearOCIPath(root *os.Root, name string) error {
	directoryPath := filepath.FromSlash(name)
	if name == "." {
		directoryPath = "."
	}
	info, err := root.Lstat(directoryPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("opaque whiteout parent %q is not a directory", name)
	}
	directory, err := root.OpenRoot(directoryPath)
	if err != nil {
		return err
	}
	defer directory.Close()
	file, err := directory.Open(".")
	if err != nil {
		return err
	}
	children, err := file.ReadDir(-1)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, child := range children {
		if err := directory.RemoveAll(child.Name()); err != nil {
			return err
		}
	}
	return nil
}

func copyOCIRegularFile(source, destination *os.Root, name string, mode os.FileMode, modified time.Time) error {
	if err := ensureOCIParent(destination, name); err != nil {
		return fmt.Errorf("ensure destination parent: %w", err)
	}
	if err := removeOCIPath(destination, name); err != nil {
		return fmt.Errorf("remove previous destination: %w", err)
	}
	input, err := source.Open(filepath.FromSlash(name))
	if err != nil {
		return fmt.Errorf("open layer source: %w", err)
	}
	defer input.Close()
	output, err := destination.OpenFile(filepath.FromSlash(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
	if err != nil {
		parent := filepath.ToSlash(path.Dir(name))
		parentInfo, statErr := destination.Stat(filepath.FromSlash(parent))
		parentMode := os.FileMode(0)
		if parentInfo != nil {
			parentMode = parentInfo.Mode()
		}
		return fmt.Errorf("open destination (parent=%q mode=%s stat_error=%v): %w", parent, parentMode, statErr, err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := copyOCIXattrs(input, output); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := destination.Chmod(filepath.FromSlash(name), ociUnixMode(mode)); err != nil {
		return err
	}
	return destination.Chtimes(filepath.FromSlash(name), modified, modified)
}

func ociUnixMode(mode os.FileMode) os.FileMode {
	permissions := mode.Perm()
	if mode&os.ModeSetuid != 0 {
		permissions |= os.ModeSetuid
	}
	if mode&os.ModeSetgid != 0 {
		permissions |= os.ModeSetgid
	}
	if mode&os.ModeSticky != 0 {
		permissions |= os.ModeSticky
	}
	return permissions
}

func copyOCIDirectoryXattrs(source, destination *os.Root, name string) error {
	input, err := source.Open(filepath.FromSlash(name))
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := destination.Open(filepath.FromSlash(name))
	if err != nil {
		return err
	}
	defer output.Close()
	return copyOCIXattrs(input, output)
}

func digestSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
