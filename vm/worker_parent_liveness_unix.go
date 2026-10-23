//go:build darwin || linux

package vm

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

func startWorkerWithParentLiveness(command *exec.Cmd) (*os.File, error) {
	if command == nil {
		return nil, fmt.Errorf("VM worker command is nil")
	}
	if len(command.ExtraFiles) != 0 {
		return nil, fmt.Errorf("VM worker command already has inherited files")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create VM worker parent-liveness pipe: %w", err)
	}
	command.ExtraFiles = []*os.File{reader} // fd 3 in the worker.
	if err := command.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	_ = reader.Close()
	return writer, nil
}

// startParentLivenessWatch consumes the extra fd passed by the driver. The
// parent keeps the write end open for the worker lifetime; EOF means the
// Gateway/supervisor process exited and this VM worker must not outlive it.
func startParentLivenessWatch(fd uintptr) (func(), error) {
	// Inherited ExtraFiles start as blocking descriptors. Make the read end
	// nonblocking before os.NewFile so the runtime poller can wake the reader
	// goroutine when stop closes the descriptor during a normal worker exit.
	if err := syscall.SetNonblock(int(fd), true); err != nil {
		return nil, fmt.Errorf("make VM worker parent-liveness descriptor nonblocking: %w", err)
	}
	file := os.NewFile(fd, "vm-parent-liveness")
	if file == nil {
		return nil, fmt.Errorf("VM worker parent-liveness descriptor is unavailable")
	}
	// Do not let the policy broker or other descendants keep the pipe alive
	// after this worker exits or execs a child.
	syscall.CloseOnExec(int(fd))
	done := make(chan struct{})
	stopping := make(chan struct{})
	go func() {
		defer close(done)
		var signal [1]byte
		for {
			n, err := file.Read(signal[:])
			if n != 0 || err != nil {
				select {
				case <-stopping:
					return
				default:
				}
				_ = killProcessGroup(os.Getpid())
				return
			}
		}
	}()
	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() {
			close(stopping)
			_ = file.Close()
			<-done
		})
	}, nil
}
