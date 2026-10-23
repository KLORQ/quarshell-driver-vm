//go:build !unix

package vm

import (
	"os"
	"path/filepath"
	"sync"
)

type imageCacheLock struct{}

var imageCacheFileLocks sync.Map

func lockImageCache(string) (*imageCacheLock, error) { return &imageCacheLock{}, nil }
func (*imageCacheLock) Close() error                 { return nil }
func tryLockImageCacheLease(file *os.File) (bool, error) {
	_, loaded := imageCacheFileLocks.LoadOrStore(filepath.Clean(file.Name()), struct{}{})
	return !loaded, nil
}
func unlockImageCacheLease(file *os.File) error {
	imageCacheFileLocks.Delete(filepath.Clean(file.Name()))
	return nil
}
