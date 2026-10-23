package vm

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"regexp"
)

var workerSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func verifyWorkerSHA256(path, expected string) error {
	if !workerSHA256Pattern.MatchString(expected) {
		return fmt.Errorf("expected worker SHA-256 must be 64 lowercase hexadecimal digits")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect worker: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o111 == 0 || before.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("worker must be a non-writable executable regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open worker: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return fmt.Errorf("worker changed while being opened")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash worker: %w", err)
	}
	after, err := file.Stat()
	if err != nil || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return fmt.Errorf("worker changed while being hashed")
	}
	actual := fmt.Sprintf("%x", hash.Sum(nil))
	if actual != expected {
		return fmt.Errorf("worker SHA-256 %s does not match configured pin", actual)
	}
	return nil
}
