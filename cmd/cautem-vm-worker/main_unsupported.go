//go:build !darwin && !linux

package main

import "fmt"

func main() { fmt.Println("cautem-vm-worker is supported on Linux and macOS") }
