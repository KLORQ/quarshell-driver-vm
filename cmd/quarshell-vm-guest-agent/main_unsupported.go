//go:build !linux

package main

import "fmt"

func main() { fmt.Println("quarshell-vm-guest-agent is built for Linux guests") }
