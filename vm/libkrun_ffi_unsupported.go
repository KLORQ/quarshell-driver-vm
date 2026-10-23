//go:build !darwin && !linux

package vm

import "fmt"

type libKrunAPI struct{}

func loadLibKrun(_ string) (*libKrunAPI, error) {
	return nil, fmt.Errorf("libkrun dynamic loading is unsupported on this platform")
}
