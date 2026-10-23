//go:build linux

// Command guest-security-probe is copied into the live acceptance guest. It
// exercises network paths that the guest shell tools cannot probe directly.
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("expected raw or vsock probe")
	}
	switch os.Args[1] {
	case "raw":
		probeRawEgress()
	case "vsock":
		if len(os.Args) != 3 {
			fatalf("vsock probe requires a port")
		}
		port, err := strconv.ParseUint(os.Args[2], 10, 32)
		if err != nil || port == 0 {
			fatalf("invalid vsock port %q", os.Args[2])
		}
		probeUnmappedVsock(uint32(port))
	default:
		fatalf("unknown probe %q", os.Args[1])
	}
}

func probeRawEgress() {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			fmt.Printf("raw-egress-denied: raw socket creation: %v\n", err)
			return
		}
		fatalf("create raw ICMP socket: %v", err)
	}
	defer unix.Close(fd)

	packet := []byte{8, 0, 0, 0, 0x51, 0x52, 0, 1}
	checksum := icmpChecksum(packet)
	packet[2], packet[3] = byte(checksum>>8), byte(checksum)
	destination := &unix.SockaddrInet4{Addr: [4]byte{198, 51, 100, 1}}
	if err := unix.Sendto(fd, packet, 0, destination); err != nil {
		fmt.Printf("raw-egress-denied: raw ICMP send: %v\n", err)
		return
	}
	fatalf("raw ICMP packet was accepted for external delivery")
}

func probeUnmappedVsock(port uint32) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fatalf("create guest vsock socket: %v", err)
	}
	defer unix.Close(fd)
	err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port})
	if err == nil {
		fatalf("guest connected to unmapped host vsock port %d", port)
	}
	fmt.Printf("unmapped-vsock-denied: port=%d error=%v\n", port, err)
}

func icmpChecksum(packet []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(packet); index += 2 {
		sum += uint32(packet[index])<<8 | uint32(packet[index+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
