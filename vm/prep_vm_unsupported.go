//go:build !darwin && !linux

package vm

import (
	"context"
	"errors"
	"os"
)

func prepareRootfsTarWorkloadDiskInGuest(
	_ context.Context,
	_ *os.File,
	_, _, _, _, _, _ string,
	_ HostConfig,
	_, _ int64,
) (preparedRootfsImage, string, error) {
	return preparedRootfsImage{}, "", errors.New("guest rootfs preparation is unsupported on this platform")
}

func prepareOCIWorkloadDiskInGuest(
	_ context.Context,
	_ resolvedOCIImage,
	_, _, _, _, _ string,
	_ HostConfig,
	_ int64,
) (preparedRootfsImage, error) {
	return preparedRootfsImage{}, errors.New("guest OCI preparation is unsupported on this platform")
}
