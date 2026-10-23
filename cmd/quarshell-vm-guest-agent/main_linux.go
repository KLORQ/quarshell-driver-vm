//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/KLORQ/quarshell-driver-vm/vmguest"
)

func main() {
	if err := vmguest.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
