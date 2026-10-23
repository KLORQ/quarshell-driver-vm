//go:build !darwin && !linux

package vm

import (
	"os"
	"path/filepath"
)

func openRootfsArchive(root, requestDir, fileName string) (*os.File, error) {
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer rootDir.Close()
	return rootDir.Open(filepath.Join(requestDir, fileName))
}
