package vm

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-driver-vm/vmguest"
)

func TestVMExecStreamReportsLostMainProcessOutput(t *testing.T) {
	guest, host := net.Pipe()
	defer guest.Close()
	defer host.Close()
	session := &vmExecStreamSession{connection: guest, inputOwner: true, closed: make(chan struct{})}
	writeDone := make(chan error, 1)
	go func() {
		frame, err := json.Marshal(vmguest.TerminalFrame{Type: "lagged", LostChunks: 7})
		if err == nil {
			err = vmguest.WriteFrame(host, frame)
		}
		writeDone <- err
	}()
	if _, err := session.ReadOutput(); err == nil || !strings.Contains(err.Error(), "7 chunks") {
		t.Fatalf("ReadOutput() error = %v, want a lost-output cursor error", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write lagged output frame: %v", err)
	}
}

func TestVMExecStreamsRejectInputWithoutOwnership(t *testing.T) {
	session := &vmExecStreamSession{inputOwner: false}
	if written, err := session.Write([]byte("input")); written != 0 || err == nil {
		t.Fatalf("read-only stream Write() = (%d, %v), want ownership error", written, err)
	}
	if err := session.CloseStdin(); err == nil {
		t.Fatal("read-only stream CloseStdin() succeeded")
	}
	terminal := &vmExecTerminalSession{inputOwner: false}
	if written, err := terminal.Write([]byte("input")); written != 0 || err == nil {
		t.Fatalf("read-only terminal Write() = (%d, %v), want ownership error", written, err)
	}
	if err := terminal.CloseStdin(); err == nil {
		t.Fatal("read-only terminal CloseStdin() succeeded")
	}
}
