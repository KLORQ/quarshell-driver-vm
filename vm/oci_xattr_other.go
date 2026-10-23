//go:build !unix

package vm

import "os"

func copyOCIXattrs(source, destination *os.File) error { return nil }
