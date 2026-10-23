//go:build darwin || linux

package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestControlFramingAndExchange(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "guest.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer connection.Close()
		frame, err := readFrame(connection)
		if err != nil {
			serverErr <- err
			return
		}
		var request controlRequest
		if err := json.Unmarshal(frame, &request); err != nil {
			serverErr <- err
			return
		}
		if request.Version != 1 || request.Operation != "exec" || len(request.Argv) != 2 || request.Argv[1] != "hello" {
			serverErr <- errors.New("unexpected control request")
			return
		}
		response, _ := json.Marshal(controlResponse{Version: 1, ExitCode: 7, Stdout: []byte("output")})
		serverErr <- writeFrame(connection, response)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := exchangeControl(ctx, socket, controlRequest{Operation: "exec", Argv: []string{"printf", "hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if response.ExitCode != 7 || string(response.Stdout) != "output" {
		t.Fatalf("control response = %+v", response)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestReadCopySourceRejectsSymlinkAndEnforcesLimit(t *testing.T) {
	root := t.TempDir()
	dataPath := filepath.Join(root, "payload")
	if err := os.WriteFile(dataPath, []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(root, "link")
	if err := os.Symlink(dataPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCopySource(linkPath, 32); err == nil {
		t.Fatal("copy-to source followed a final symlink")
	}
	if _, _, err := readCopySource(dataPath, 3); err == nil {
		t.Fatal("copy-to source exceeded the encoded control-frame bound")
	}
	data, mode, err := readCopySource(dataPath, 32)
	if err != nil || string(data) != "payload" || mode.Perm() != 0o640 {
		t.Fatalf("readCopySource()=(%q,%#o,%v)", data, mode.Perm(), err)
	}
}

func TestGuestControlTokenRotationRetriesAfterLostReply(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	store, err := openStateStore(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	id, err := newSandboxID()
	if err != nil {
		t.Fatal(err)
	}
	sandboxDir := filepath.Join(store.root, "sandboxes", id)
	if err := os.MkdirAll(sandboxDir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldToken, err := createControlToken(sandboxDir)
	if err != nil {
		t.Fatal(err)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, id)
	if err := os.MkdirAll(filepath.Dir(guestSocket), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", guestSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	driver := NewWithHostConfig(HostConfig{StateDir: stateRoot})
	serverDone := make(chan error, 1)
	go func() {
		var first controlRequest
		for index := 0; index < 3; index++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverDone <- acceptErr
				return
			}
			frame, readErr := readFrame(connection)
			if readErr != nil {
				_ = connection.Close()
				serverDone <- readErr
				return
			}
			var request controlRequest
			if decodeErr := json.Unmarshal(frame, &request); decodeErr != nil {
				_ = connection.Close()
				serverDone <- decodeErr
				return
			}
			switch index {
			case 0:
				if request.Operation != "rotate-token" || request.AuthToken != oldToken || request.NextAuthToken == "" || request.RotationID == "" {
					_ = connection.Close()
					serverDone <- errors.New("first token rotation request is malformed")
					return
				}
				first = request
				// Model a guest that applied the rotation but lost the response.
				_ = connection.Close()
				continue
			case 1:
				if request.Operation != "rotate-token" || request.AuthToken != first.AuthToken || request.NextAuthToken != first.NextAuthToken || request.RotationID != first.RotationID {
					_ = connection.Close()
					serverDone <- errors.New("rotation retry changed its durable candidate")
					return
				}
			case 2:
				if request.Operation != "ping" || request.AuthToken != first.NextAuthToken {
					_ = connection.Close()
					serverDone <- errors.New("host did not persist the rotated guest token")
					return
				}
			}
			response, _ := json.Marshal(controlResponse{Version: 1})
			writeErr := writeFrame(connection, response)
			_ = connection.Close()
			if writeErr != nil {
				serverDone <- writeErr
				return
			}
		}
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := driver.rotateGuestControlToken(ctx, id, guestSocket); err == nil {
		t.Fatal("rotation succeeded even though the guest response was lost")
	}
	if _, pending, err := readPendingControlTokenRotation(sandboxDir); err != nil || !pending {
		t.Fatalf("lost-reply pending rotation=(%t,%v), want true,nil", pending, err)
	}
	if _, err := driver.exchangeControl(ctx, id, guestSocket, controlRequest{Operation: "ping"}); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if _, pending, err := readPendingControlTokenRotation(sandboxDir); err != nil || pending {
		t.Fatalf("pending rotation after retry=(%t,%v), want false,nil", pending, err)
	}
	if token, err := readControlToken(sandboxDir); err != nil || token == oldToken {
		t.Fatalf("control token after retry=(%q,%v), want rotated token", token, err)
	}
}

func TestControlRejectsOversizedAndEmptyFrames(t *testing.T) {
	for _, size := range []int{0, controlFrameMax + 1} {
		if err := writeFrame(discardWriter{}, make([]byte, size)); err == nil {
			t.Errorf("writeFrame accepted payload size %d", size)
		}
	}
	frame := []byte{0, 0, 0, 0}
	if _, err := readFrame(bytes.NewReader(frame)); err == nil {
		t.Fatal("readFrame accepted empty payload")
	}
}

func TestControlRejectsUnsupportedProtocolVersions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, version := range []uint16{2, 65535} {
		if _, err := exchangeControl(ctx, filepath.Join(t.TempDir(), "missing.sock"), controlRequest{Version: version, Operation: "ping"}); err == nil {
			t.Errorf("accepted unsupported protocol version %d", version)
		}
	}
}

func TestControlRejectsUnsupportedResponseVersion(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "vm-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socket := filepath.Join(root, "guest.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer connection.Close()
		if _, err := readFrame(connection); err != nil {
			serverErr <- err
			return
		}
		response, _ := json.Marshal(controlResponse{Version: 2})
		serverErr <- writeFrame(connection, response)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := exchangeControl(ctx, socket, controlRequest{Operation: "ping"}); err == nil {
		t.Fatal("accepted response from unsupported protocol version")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

type discardWriter struct{}

func (discardWriter) Write(value []byte) (int, error) { return len(value), nil }

func TestWorkerControlSocketLifecycle(t *testing.T) {
	shortRoot, err := os.MkdirTemp("/tmp", "vm-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(shortRoot)
	path := filepath.Join(shortRoot, workerSocket)
	listener, ready, stop, err := startWorkerControl(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	close(ready)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := workerControl(ctx, path, "status")
	if err != nil || !response.Ready {
		t.Fatalf("worker status = (%+v, %v)", response, err)
	}
	if _, err := workerControl(ctx, path, "stop"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stop:
	case <-ctx.Done():
		t.Fatal("stop command was not delivered")
	}
}
