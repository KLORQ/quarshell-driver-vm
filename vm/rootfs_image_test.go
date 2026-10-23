//go:build darwin || linux

package vm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPrepareRootfsImageBuildsAndReusesContentAddressedImage(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "rootfs.tar.gz")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{
		{name: "etc/hostname", kind: tar.TypeReg, body: "sandbox"},
		{name: "bin", kind: tar.TypeDir, mode: 0o755},
	}); err != nil {
		t.Fatal(err)
	}
	countPath := filepath.Join(root, "formatter-count")
	formatter := filepath.Join(root, "mke2fs")
	script := "#!/bin/sh\nprintf x >> '" + countPath + "'\nfor last do :; done\nprintf ext4 >> \"$last\"\n"
	if err := os.WriteFile(formatter, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(root, "cache")
	first, err := prepareRootfsImage(context.Background(), archivePath, cacheDir, formatter, 4096)
	if err != nil {
		t.Fatalf("prepareRootfsImage() error = %v", err)
	}
	second, err := prepareRootfsImage(context.Background(), archivePath, cacheDir, formatter, 4096)
	if err != nil {
		t.Fatalf("prepareRootfsImage() second call error = %v", err)
	}
	if first != second || !strings.HasSuffix(first, ".ext4") {
		t.Fatalf("image paths = %q and %q", first, second)
	}
	imageInfo, err := os.Stat(first)
	if err != nil || imageInfo.Mode().Perm() != 0o400 {
		t.Fatalf("cached image mode = %v, err=%v; want 0400", imageInfo, err)
	}
	count, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(count) != "x" {
		t.Fatalf("formatter invocation count = %q, want one invocation", count)
	}
	if image, err := os.ReadFile(first); err != nil || !strings.HasSuffix(string(image), "ext4") {
		t.Fatalf("cached image tail = %q, err=%v", image, err)
	}
}

func TestGuestInitMountsOptionalWorkloadDiskReadOnly(t *testing.T) {
	for _, want := range []string{
		`if [ "${QUARSHELL_VM_IMAGE_DISK:-}" = "1" ]; then`,
		"mount -t ext4 -o ro,noload /dev/vdc /image",
		"mount --bind /image/image-rootfs /lower",
		"mount --bind / /lower",
		`if [ -n "${QUARSHELL_VM_SERVICE_DATA_DISK:-}" ]; then`,
		"mkdir -p /newroot/var/lib/docker-test",
		`mount -t ext4 -o rw "$QUARSHELL_VM_SERVICE_DATA_DISK" /newroot/var/lib/docker-test`,
		"mkdir -p /newroot/.oldroot",
		"mount --make-rprivate /",
		"pivot_root . .oldroot",
		"umount -l /.oldroot",
		"export LC_ALL=C",
		"for dropin in /opt/quarshell/init.d/*; do",
		`"/opt/quarshell/init.d/$dropin_name"`,
		"exec /opt/quarshell/bin/guest-agent",
	} {
		if !strings.Contains(guestInitScript, want) {
			t.Errorf("guest init script missing workload disk behavior %q", want)
		}
	}
	if strings.Contains(guestInitScript, "chroot /newroot") {
		t.Fatal("guest init must pivot into the guest root instead of retaining the initramfs chroot")
	}
}

func TestGuestInitImagePrepRequiresVersionedPayloadAndPublishesAtomically(t *testing.T) {
	for _, want := range []string{
		`if [ "${QUARSHELL_VM_INIT_MODE:-sandbox}" = "image-prep" ] || [ -f /overlay/config/quarshell-image/source ]; then`,
		"payload_dir=/overlay/config/quarshell-image",
		"prep_log=\"$payload_dir/prep.log\"",
		"image-prep extracting rootfs.tar",
		"image-prep rootfs.tar extraction complete",
		"image-prep exit status=",
		`source="$(cat "$payload_dir/source" 2>/dev/null || true)"`,
		"tar -xpf \"$payload_dir/rootfs.tar\" -C /overlay/image-rootfs.partial",
		"tar -xzpf \"$payload_dir/rootfs.tar.gz\" -C /overlay/image-rootfs.partial",
		"/opt/quarshell/bin/umoci raw unpack",
		"--image \"$payload_dir/oci:quarshell\"",
		"du --apparent-size -s -B1 /overlay/image-rootfs.partial",
		"du -sk /overlay/image-rootfs.partial",
		`QUARSHELL_VM_IMAGE_PREP_MAX_BYTES:-34493956096`,
		"cp /opt/quarshell/bin/guest-agent /overlay/image-rootfs.partial/opt/quarshell/bin/guest-agent",
		"mv /overlay/image-rootfs.partial /overlay/image-rootfs",
		"rm -rf \"$payload_dir\"",
		"umount /overlay",
		"mount -t ext4 -o ro /dev/vdb /image-prep-check",
		"/image-prep-check/image-rootfs/opt/quarshell/bin/guest-agent",
	} {
		if !strings.Contains(guestInitScript, want) {
			t.Errorf("guest init script missing image-prep behavior %q", want)
		}
	}
	if strings.Index(guestInitScript, `tar -xpf "$payload_dir/rootfs.tar"`) > strings.Index(guestInitScript, "mv /overlay/image-rootfs.partial /overlay/image-rootfs") {
		t.Fatal("guest init publishes image-rootfs before extraction")
	}
}

func TestInstallGuestRuntimeIncludesPinnedUMOCIForBootstrapPrep(t *testing.T) {
	root := t.TempDir()
	guestAgent := filepath.Join(root, "guest-agent")
	umoci := filepath.Join(root, "umoci")
	if err := os.WriteFile(guestAgent, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(umoci, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	guestRoot := filepath.Join(root, "bootstrap")
	if err := os.Mkdir(guestRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installGuestRuntime(guestRoot, guestAgent, umoci); err != nil {
		t.Fatalf("installGuestRuntime() error = %v", err)
	}
	installed, err := os.ReadFile(filepath.Join(guestRoot, "opt", "quarshell", "bin", "umoci"))
	if err != nil || string(installed) != string(testGuestELF()) {
		t.Fatalf("installed umoci differs from pinned runtime: err=%v", err)
	}
}

func TestPrepareRootfsTarWorkloadDiskPlacesArchiveUnderImageRootfs(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "workload.tar")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{
		{name: "etc/workload-marker", kind: tar.TypeReg, body: "workload"},
	}); err != nil {
		t.Fatal(err)
	}
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archiveFile.Close()
	guestAgent := filepath.Join(root, "guest-agent")
	if err := os.WriteFile(guestAgent, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	formatter := filepath.Join(root, "mke2fs")
	script := `#!/bin/sh
source=
previous=
for argument do
  if [ "$previous" = "-d" ]; then source=$argument; fi
  previous=$argument
done
test -f "$source/image-rootfs/etc/workload-marker"
test -f "$source/image-rootfs/opt/quarshell/bin/guest-agent"
for last do :; done
printf ext4 > "$last"
`
	if err := os.WriteFile(formatter, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	prepared, digest, err := prepareRootfsTarWorkloadDisk(context.Background(), archiveFile, archivePath, filepath.Join(root, "cache"), formatter, guestAgent, 1<<20, defaultRootfsImageCacheMaxBytes)
	if err != nil {
		t.Fatalf("prepareRootfsTarWorkloadDisk() error = %v", err)
	}
	defer prepared.Lease.Release()
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("workload archive digest = %q", digest)
	}
	if _, err := os.Stat(prepared.Path); err != nil {
		t.Fatalf("prepared workload disk missing: %v", err)
	}
}

func TestPrepareRootfsImageSerializesConcurrentBuildsForSameIdentity(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "rootfs.tar")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "content"}}); err != nil {
		t.Fatal(err)
	}
	countPath := filepath.Join(root, "formatter-count")
	formatter := filepath.Join(root, "mke2fs")
	script := "#!/bin/sh\nprintf x >> '" + countPath + "'\nsleep 0.3\nfor last do :; done\nprintf ext4 >> \"$last\"\n"
	if err := os.WriteFile(formatter, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(root, "cache")
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(2)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			_, err := prepareRootfsImage(context.Background(), archivePath, cacheDir, formatter, 4096)
			errs <- err
		}()
	}
	ready.Wait()
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent preparation failed: %v", err)
		}
	}
	count, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(count) != "x" {
		t.Fatalf("concurrent builds invoked formatter %d times; want once", len(count))
	}
}

func TestRootfsPreparationLockWaitHonorsCancellation(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	if err := ensureRootfsImageCacheDirectories(cacheDir); err != nil {
		t.Fatal(err)
	}
	release, err := lockRootfsImagePreparation(context.Background(), cacheDir, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := lockRootfsImagePreparation(ctx, cacheDir, strings.Repeat("a", 64)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting for preparation lock error = %v; want context deadline", err)
	}
}

func TestPrepareRootfsImageRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "rootfs.tar")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{
		{name: "escape", kind: tar.TypeSymlink, link: "../../outside"},
		{name: "escape/payload", kind: tar.TypeReg, body: "owned"},
	}); err != nil {
		t.Fatal(err)
	}
	formatter := filepath.Join(root, "unused-formatter")
	if _, err := prepareRootfsImage(context.Background(), archivePath, filepath.Join(root, "cache"), formatter, 4096); err == nil {
		t.Fatal("prepareRootfsImage accepted symlink escape archive")
	}
	if _, err := os.Stat(filepath.Join(root, "outside", "payload")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("archive wrote outside extraction root: stat error=%v", err)
	}
}

func TestPrepareRootfsImageHonorsCancellationAndFormatterFailure(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "rootfs.tar")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "content"}}); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prepareRootfsImage(canceled, archivePath, filepath.Join(root, "canceled-cache"), "", 4096); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled build error = %v", err)
	}
	formatter := filepath.Join(root, "failing-mke2fs")
	if err := os.WriteFile(formatter, []byte("#!/bin/sh\necho formatter-failed >&2\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRootfsImage(context.Background(), archivePath, filepath.Join(root, "failed-cache"), formatter, 4096); err == nil || !strings.Contains(err.Error(), "formatter-failed") {
		t.Fatalf("formatter failure = %v", err)
	}
}

func TestPrepareRootfsImageCancellationDoesNotPublishPartialImage(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "rootfs.tar")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "content"}}); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(root, "cache")
	startedPath := filepath.Join(root, "formatter-started")
	formatter := filepath.Join(root, "blocking-mke2fs")
	script := "#!/bin/sh\nfor last do :; done\nprintf started > '" + startedPath + "'\nsleep 10\nprintf partial > \"$last\"\n"
	if err := os.WriteFile(formatter, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := prepareRootfsImage(ctx, archivePath, cacheDir, formatter, 4096)
		result <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(startedPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect formatter start marker: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("formatter did not start before timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled rootfs preparation unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rootfs preparation did not return after cancellation")
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".ext4") {
			t.Fatalf("canceled preparation published partial image %q", entry.Name())
		}
		if strings.HasPrefix(entry.Name(), ".rootfs-build-") {
			t.Fatalf("canceled preparation left staging directory %q", entry.Name())
		}
	}
}

func TestPrepareRootfsImageLiveE2FS(t *testing.T) {
	if os.Getenv("QUARSHELL_VM_ACCEPTANCE") != "1" {
		t.Skip("set QUARSHELL_VM_ACCEPTANCE=1 to run live ext4 acceptance")
	}
	formatter := os.Getenv("QUARSHELL_VM_TEST_E2FS_FORMATTER")
	if formatter == "" {
		var err error
		formatter, err = resolveExt4Formatter()
		if err != nil {
			t.Skip(err.Error())
		}
	}
	if _, err := exec.LookPath(formatter); err != nil {
		if _, statErr := os.Stat(formatter); statErr != nil {
			t.Fatalf("live formatter %q is unavailable: %v", formatter, err)
		}
	}
	root := t.TempDir()
	archivePath := filepath.Join(root, "rootfs.tar.gz")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{
		{name: "etc", kind: tar.TypeDir, mode: 0o755},
		{name: "etc/os-release", kind: tar.TypeReg, body: "ID=quarshell-test\n"},
		{name: "bin", kind: tar.TypeDir, mode: 0o755},
	}); err != nil {
		t.Fatal(err)
	}
	guestAgent := os.Getenv("QUARSHELL_VM_TEST_GUEST_AGENT")
	imagePath, err := prepareRootfsImageWithGuest(context.Background(), archivePath, filepath.Join(root, "cache"), formatter, 4096, guestAgent)
	if err != nil {
		t.Fatalf("live ext4 image build: %v", err)
	}
	info, err := os.Stat(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < int64(rootfsImageMinBytes) || info.Mode().Perm() != 0o400 {
		t.Fatalf("ext4 image metadata = size %d mode %#o", info.Size(), info.Mode().Perm())
	}
	if guestAgent != "" {
		verifier := os.Getenv("QUARSHELL_VM_TEST_E2FS_VERIFY")
		if verifier != "" {
			output, err := exec.Command(verifier, imagePath).CombinedOutput()
			if err != nil {
				t.Fatalf("verify injected guest runtime: %v: %s", err, output)
			}
		}
	}
	overlayTemplate, err := prepareOverlayTemplate(context.Background(), filepath.Join(root, "cache"), formatter, 64<<20)
	if err != nil {
		t.Fatalf("live overlay template build: %v", err)
	}
	overlay := filepath.Join(root, "sandbox", "overlay.ext4")
	if err := createSandboxOverlay(overlayTemplate, overlay); err != nil {
		t.Fatalf("live sandbox overlay clone: %v", err)
	}
	overlayInfo, err := os.Stat(overlay)
	if err != nil || overlayInfo.Size() != 64<<20 || overlayInfo.Mode().Perm() != 0o600 {
		t.Fatalf("sandbox overlay metadata = %v, err=%v", overlayInfo, err)
	}
}

func TestBoundedReaderRejectsExpandedArchiveOverLimit(t *testing.T) {
	reader := &boundedReader{reader: strings.NewReader("123456"), limit: 5}
	data, err := io.ReadAll(reader)
	if err == nil || !reader.exceeded || string(data) != "12345" {
		t.Fatalf("read=(%q, %v), exceeded=%t", data, err, reader.exceeded)
	}
}

type rootfsTarEntry struct {
	name string
	kind byte
	mode int64
	link string
	body string
}

func writeRootfsArchive(path string, entries []rootfsTarEntry) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	var writer io.WriteCloser = file
	if strings.HasSuffix(path, ".gz") {
		compressed := gzip.NewWriter(file)
		writer = compressed
	}
	tarWriter := tar.NewWriter(writer)
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		header := &tar.Header{Name: entry.name, Typeflag: entry.kind, Mode: mode, Linkname: entry.link, Size: int64(len(entry.body))}
		if err := tarWriter.WriteHeader(header); err != nil {
			_ = writer.Close()
			return err
		}
		if _, err := io.WriteString(tarWriter, entry.body); err != nil {
			_ = writer.Close()
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}
