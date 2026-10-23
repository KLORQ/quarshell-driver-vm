//go:build darwin || linux

package main

import (
	"fmt"
	"os"

	"github.com/KLORQ/quarshell-driver-vm/vm"
)

func main() {
	if err := vm.RunWorkerFromStdin(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
