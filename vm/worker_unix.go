//go:build darwin || linux

package vm

import (
	"fmt"
	"os"
	"syscall"
)

func runWorker(config workerConfig) error {
	if err := prepareWorkerIsolation(config.Isolation); err != nil {
		return fmt.Errorf("prepare VM worker isolation: %w", err)
	}
	if config.WatchParentLiveness {
		stopWatch, err := startParentLivenessWatch(3)
		if err != nil {
			return err
		}
		defer stopWatch()
	}
	listener, ready, stop, err := startWorkerControl(config.ControlSocket)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(config.ControlSocket)
	}()
	go func() {
		<-stop
		_ = syscall.Kill(-os.Getpid(), syscall.SIGTERM)
	}()
	api, err := loadLibKrun(config.RuntimeDir)
	if err != nil {
		return err
	}
	guest, err := newKrunContext(api, config.Launch)
	if err != nil {
		return err
	}
	defer func() {
		if err := guest.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	close(ready)
	status := guest.StartEnter()
	if status < 0 {
		return fmt.Errorf("krun_start_enter failed with status %d", status)
	}
	return nil
}
