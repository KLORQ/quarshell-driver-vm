package vm

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/KLORQ/quarshell-driver-vm/vmguest"
)

func TestTerminalSessionReadsOutputWithReplayCursor(t *testing.T) {
	guest, host := net.Pipe()
	defer host.Close()
	session := newVMExecTerminalSession(guest, "session", true, nil)
	writes := make(chan error, 1)
	write := func(frame vmguest.TerminalFrame) {
		payload, err := json.Marshal(frame)
		if err != nil {
			writes <- err
			return
		}
		writes <- vmguest.WriteFrame(host, payload)
	}
	go write(vmguest.TerminalFrame{Type: "output", Data: []byte("resumed"), Sequence: 17})
	data, cursor, err := session.ReadOutput()
	if err != nil || string(data) != "resumed" || cursor != 17 {
		t.Fatalf("ReadOutput() = %q, %d, %v; want resumed, 17, nil", data, cursor, err)
	}
	if err := <-writes; err != nil {
		t.Fatal(err)
	}
	go write(vmguest.TerminalFrame{Type: "exit", ExitCode: 0})
	if code, err := session.Wait(context.Background()); err != nil || code != 0 {
		t.Fatalf("Wait() = %d, %v; want 0, nil", code, err)
	}
	if err := <-writes; err != nil {
		t.Fatal(err)
	}
	if _, _, err := session.ReadOutput(); err == nil {
		t.Fatal("ReadOutput after exit unexpectedly succeeded")
	}
}
