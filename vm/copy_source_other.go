//go:build !darwin && !linux

package vm

import (
	"fmt"
	"io"
	"io/fs"
	"os"
)

func readCopySource(path string, maxBytes int64) ([]byte, fs.FileMode, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, 0, fmt.Errorf("vm copy-to source must be a regular file no larger than %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(data)) > maxBytes {
		return nil, 0, fmt.Errorf("vm copy-to source must be a regular file no larger than %d bytes", maxBytes)
	}
	return data, info.Mode().Perm(), nil
}
