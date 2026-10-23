//go:build darwin || linux

package vm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFormatExt4ImagePreservesUnreadableSourceModes(t *testing.T) {
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("debugfs is unavailable")
	}
	formatter, err := resolveExt4Formatter()
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(source, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(source, "etc", "gshadow")
	if err := os.WriteFile(file, []byte("root:!::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o001); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(root, "rootfs.ext4")
	if err := os.WriteFile(image, make([]byte, 32<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := formatExt4Image(t.Context(), formatter, source, image); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o001 {
		if info == nil {
			t.Fatalf("stat source file: %v", err)
		}
		t.Fatalf("source mode after formatting = %#o, err=%v; want 0001", info.Mode().Perm(), err)
	}
	output, err := exec.Command("debugfs", "-R", "stat /etc/gshadow", image).CombinedOutput()
	if err != nil {
		t.Fatalf("debugfs inspect image: %v: %s", err, output)
	}
	if !strings.Contains(string(output), "Mode:  0001") {
		t.Fatalf("formatted ext4 mode output = %q; want mode 0001", output)
	}
}

func TestPrepareOverlayTemplateFormatsPrivateExt4Cache(t *testing.T) {
	root := t.TempDir()
	count := filepath.Join(root, "count")
	formatter := filepath.Join(root, "mke2fs")
	statMode := `stat -c %a`
	if runtime.GOOS == "darwin" {
		statMode = `stat -f %Lp`
	}
	script := "#!/bin/sh\n" +
		"printf x >> '" + count + "'\n" +
		"expect=0\nfor arg do if [ \"$expect\" = 1 ]; then root=$arg; expect=0; elif [ \"$arg\" = -d ]; then expect=1; fi; done\n" +
		"test -d \"$root/upper\" && test -d \"$root/work\" && test -d \"$root/config\"\n" +
		"test \"$(" + statMode + " \"$root\")\" = 755\n" +
		"test \"$(" + statMode + " \"$root/upper\")\" = 755\n" +
		"test \"$(" + statMode + " \"$root/work\")\" = 700\n"
	if err := os.WriteFile(formatter, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "cache")
	first, err := prepareOverlayTemplate(t.Context(), cache, formatter, 64<<20)
	if err != nil {
		t.Fatalf("prepareOverlayTemplate() error = %v", err)
	}
	second, err := prepareOverlayTemplate(t.Context(), cache, formatter, 64<<20)
	if err != nil {
		t.Fatalf("prepareOverlayTemplate() second error = %v", err)
	}
	if first != second {
		t.Fatalf("template paths differ: %q and %q", first, second)
	}
	info, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 64<<20 || info.Mode().Perm() != 0o400 {
		t.Fatalf("overlay template size=%d mode=%#o", info.Size(), info.Mode().Perm())
	}
	calls, err := os.ReadFile(count)
	if err != nil || string(calls) != "x" {
		t.Fatalf("formatter calls=%q err=%v, want once", calls, err)
	}
	if _, err := prepareOverlayTemplate(t.Context(), cache, formatter, 32<<20); err == nil || !strings.Contains(err.Error(), "64 MiB minimum") {
		t.Fatalf("undersized overlay error=%v", err)
	}
}

func TestCreateSandboxOverlayMakesPrivateIndependentWritableCopy(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "template.ext4")
	if err := os.WriteFile(template, []byte("base-image"), 0o400); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "sandbox", "overlay.ext4")
	if err := createSandboxOverlay(template, destination); err != nil {
		t.Fatalf("createSandboxOverlay() error = %v", err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("overlay mode=%#o, want 0600", info.Mode().Perm())
	}
	if err := os.WriteFile(destination, []byte("sandbox-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(template)
	if err != nil || string(base) != "base-image" {
		t.Fatalf("template changed to %q, err=%v", base, err)
	}
	if err := createSandboxOverlay(template, destination); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate overlay creation error=%v", err)
	}
}

func TestCreateSandboxOverlayWithDropinsFormatsPrivateExecutableHooks(t *testing.T) {
	root := t.TempDir()
	formatter := filepath.Join(root, "mke2fs")
	output := filepath.Join(root, "formatter-args")
	script := "#!/bin/sh\n" +
		"src=; image=; previous=; for arg do if [ \"$previous\" = -d ]; then src=$arg; fi; previous=$arg; image=$arg; done\n" +
		"printf '%s\\n' \"$src\" \"$image\" > '" + output + "'\n" +
		"test -f \"$src/upper/opt/cautem/init.d/10-test\"\n" +
		"test -x \"$src/upper/opt/cautem/init.d/10-test\"\n" +
		"test \"$(cat \"$src/upper/opt/cautem/init.d/10-test\")\" = '#!/bin/sh\\nprintf ready\\n'\n" +
		"cp \"$image\" '" + filepath.Join(root, "formatted-image") + "'\n"
	if err := os.WriteFile(formatter, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "sandbox", "overlay.ext4")
	err := createSandboxOverlayWithDropins(t.Context(), formatter, 64<<20, destination, []GuestInitDropin{{Name: "10-test", Contents: []byte("#!/bin/sh\nprintf ready\n")}})
	if err != nil {
		t.Fatalf("createSandboxOverlayWithDropins() error = %v", err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 64<<20 || info.Mode().Perm() != 0o600 {
		t.Fatalf("overlay size=%d mode=%#o, want 64 MiB and 0600", info.Size(), info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(root, "sandbox", ".overlay-dropins-*")); !os.IsNotExist(err) {
		t.Fatalf("staging directory was not removed: %v", err)
	}
}

func TestSandboxOverlaysAreIsolatedAndDeleteOwnershipIsPerSandbox(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "template.ext4")
	if err := os.WriteFile(template, []byte("immutable-rootfs"), 0o400); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "sandboxes", "sandbox-a", "overlay.ext4")
	second := filepath.Join(root, "sandboxes", "sandbox-b", "overlay.ext4")
	for _, overlay := range []string{first, second} {
		if err := createSandboxOverlay(template, overlay); err != nil {
			t.Fatalf("createSandboxOverlay(%q): %v", overlay, err)
		}
	}
	firstInfo, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	secondInfo, err := os.Stat(second)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(firstInfo, secondInfo) {
		t.Fatal("sandbox overlays share the same backing file")
	}

	firstFile, err := os.OpenFile(first, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := firstFile.WriteAt([]byte("A"), 0); err != nil {
		_ = firstFile.Close()
		t.Fatal(err)
	}
	if err := firstFile.Close(); err != nil {
		t.Fatal(err)
	}
	secondFile, err := os.OpenFile(second, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondFile.WriteAt([]byte("B"), 0); err != nil {
		_ = secondFile.Close()
		t.Fatal(err)
	}
	if err := secondFile.Close(); err != nil {
		t.Fatal(err)
	}

	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	baseBytes, err := os.ReadFile(template)
	if err != nil {
		t.Fatal(err)
	}
	if firstBytes[0] != 'A' || secondBytes[0] != 'B' || string(baseBytes) != "immutable-rootfs" {
		t.Fatalf("overlay writes crossed sandbox boundary: first=%q second=%q base=%q", firstBytes[:1], secondBytes[:1], baseBytes)
	}

	if err := os.RemoveAll(filepath.Dir(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatalf("deleting sandbox A removed or damaged sandbox B overlay: %v", err)
	}
	secondBytes, err = os.ReadFile(second)
	if err != nil || secondBytes[0] != 'B' {
		t.Fatalf("sandbox B overlay after deleting sandbox A begins with %q, err=%v", secondBytes, err)
	}
}

func TestCreateSandboxOverlayRejectsSymlinkAndInvalidTemplate(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "regular.ext4")
	if err := os.WriteFile(regular, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "template.ext4")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	if err := createSandboxOverlay(symlink, filepath.Join(root, "overlay.ext4")); err == nil {
		t.Fatal("createSandboxOverlay accepted symlink template")
	}
}

func TestCopySparseFilePreservesContentsAndLength(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "copy")
	content := make([]byte, 2<<20)
	content[17] = 0x4a
	content[len(content)-1] = 0x6b
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copySparseFile(source, destination); err != nil {
		t.Fatalf("copySparseFile() error = %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("sparse copy contents differ")
	}
}
