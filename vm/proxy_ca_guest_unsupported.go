//go:build !darwin && !linux

package vm

import "errors"

func guestProxyCABundle(_ []string) (string, error) {
	return "", errors.New("guest proxy CA delivery is unsupported on this platform")
}
