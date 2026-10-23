//go:build darwin || linux

package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuestImagePrepFailureDoesNotPublishCacheEntry(t *testing.T) {
	for _, test := range []struct {
		name      string
		runnerErr error
		verifyErr error
	}{
		{name: "worker failure", runnerErr: errors.New("injected prep worker failure")},
		{name: "output verification failure", verifyErr: errors.New("missing image-rootfs")},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			guestAgent := filepath.Join(root, "guest-agent")
			umoci := filepath.Join(root, "umoci")
			for _, path := range []string{guestAgent, umoci} {
				if err := os.WriteFile(path, testGuestELF(), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			bootstrap := filepath.Join(root, "bootstrap.ext4")
			if err := os.WriteFile(bootstrap, []byte("bootstrap"), 0o400); err != nil {
				t.Fatal(err)
			}
			formatter := filepath.Join(root, "mke2fs")
			if err := os.WriteFile(formatter, []byte("#!/bin/sh\nfor last do :; done\nprintf ext4 >> \"$last\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			cacheDir := filepath.Join(root, "cache")
			host := HostConfig{
				VCPUs: 1, MemoryMiB: 128,
				imagePrepRunner:   func(context.Context, HostConfig, string, string, string) error { return test.runnerErr },
				imagePrepVerifier: func(string, string) error { return test.verifyErr },
			}
			prepared, err := prepareWorkloadDiskInGuest(context.Background(), cacheDir, formatter, guestAgent, umoci, bootstrap, host, "test-source-digest", 0, defaultRootfsImageCacheMaxBytes, func(payloadDir string) (int64, error) {
				if err := writePrivateFile(filepath.Join(payloadDir, "source"), []byte("tar-rootfs-v1")); err != nil {
					return 0, err
				}
				if err := writePrivateFile(filepath.Join(payloadDir, "rootfs.tar"), []byte("payload")); err != nil {
					return 0, err
				}
				return int64(len("payload")), nil
			})
			if err == nil {
				if prepared.Lease != nil {
					_ = prepared.Lease.Release()
				}
				t.Fatal("guest prep failure unexpectedly published a workload disk")
			}
			if test.runnerErr != nil && !strings.Contains(err.Error(), test.runnerErr.Error()) {
				t.Fatalf("prep worker error = %v; want %q", err, test.runnerErr)
			}
			if test.verifyErr != nil && !strings.Contains(err.Error(), test.verifyErr.Error()) {
				t.Fatalf("verification error = %v; want %q", err, test.verifyErr)
			}
			entries, readErr := os.ReadDir(cacheDir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".ext4") {
					t.Fatalf("failed prep published cache disk %q", entry.Name())
				}
			}
		})
	}
}

func TestGuestImagePrepCanceledBeforeBuildDoesNotStagePayload(t *testing.T) {
	root := t.TempDir()
	guestAgent := filepath.Join(root, "guest-agent")
	umoci := filepath.Join(root, "umoci")
	for _, path := range []string{guestAgent, umoci} {
		if err := os.WriteFile(path, testGuestELF(), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bootstrap := filepath.Join(root, "bootstrap.ext4")
	if err := os.WriteFile(bootstrap, []byte("bootstrap"), 0o400); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	staged := false
	_, err := prepareWorkloadDiskInGuest(ctx, filepath.Join(root, "cache"), "", guestAgent, umoci, bootstrap, HostConfig{}, "cancelled", 0, defaultRootfsImageCacheMaxBytes, func(string) (int64, error) {
		staged = true
		return 0, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled image-prep error = %v; want context.Canceled", err)
	}
	if staged {
		t.Fatal("image-prep staged payload after its context was canceled")
	}
}
