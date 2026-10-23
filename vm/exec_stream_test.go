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
	session := &vmExecStreamSession{connection: guest, closed: make(chan struct{})}
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
