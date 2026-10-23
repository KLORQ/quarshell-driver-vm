// Command quarshell-vm-bootstrap builds the ext4 bootstrap disk used by VM guests.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/KLORQ/quarshell-driver-vm/vm"
)

func main() {
	out := flag.String("out", "", "output ext4 image")
	agent := flag.String("guest-agent", "", "linux guest agent binary")
	umoci := flag.String("umoci", "", "linux umoci binary")
	baseRootfs := flag.String("base-rootfs", "", "optional base rootfs tar")
	size := flag.String("size", "512M", "filesystem size")
	flag.Parse()
	if *out == "" || *agent == "" || *umoci == "" {
		fmt.Fprintln(os.Stderr, "usage: quarshell-vm-bootstrap --out FILE --guest-agent FILE --umoci FILE")
		os.Exit(2)
	}
	root, err := os.MkdirTemp("", "quarshell-vm-bootstrap-*")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(root)
	if *baseRootfs != "" {
		command := exec.Command("tar", "-xpf", *baseRootfs, "-C", root)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			fatal(fmt.Errorf("extract base rootfs: %w", err))
		}
	}
	for _, dir := range []string{"proc", "sys", "dev", "run", "tmp", "overlay", "lower", "newroot", "image"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			fatal(err)
		}
	}
	if err := vm.WriteGuestInit(root); err != nil {
		fatal(err)
	}
	bin := filepath.Join(root, "opt", "quarshell", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		fatal(err)
	}
	for _, item := range []struct{ source, name string }{{*agent, "guest-agent"}, {*umoci, "umoci"}} {
		if err := copyExecutable(item.source, filepath.Join(bin, item.name)); err != nil {
			fatal(err)
		}
	}
	formatter := "mke2fs"
	if _, err := exec.LookPath(formatter); err != nil {
		if path, lookupErr := exec.LookPath("mkfs.ext4"); lookupErr == nil {
			formatter = path
		} else {
			fatal(fmt.Errorf("mke2fs or mkfs.ext4 is required"))
		}
	}
	_ = os.Remove(*out)
	command := exec.Command(formatter, "-q", "-F", "-t", "ext4", "-d", root, "-L", "quarshell-bootstrap", *out, *size)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fatal(fmt.Errorf("mke2fs: %w", err))
	}
	fmt.Println("bootstrap disk:", *out)
}

func copyExecutable(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "quarshell-vm-bootstrap:", err)
	os.Exit(1)
}
