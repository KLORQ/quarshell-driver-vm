package vm

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver/driver"
)

var _ driver.PlatformEventStream = (*Driver)(nil)
var _ driver.SandboxWatchStream = (*Driver)(nil)

const vmPlatformWatchBuffer = 128
const vmPlatformWatchPollInterval = 250 * time.Millisecond
const vmSandboxWatchPollInterval = time.Second

type vmPlatformWatchKey struct {
	stateRoot string
	sandboxID string
}

var vmPlatformWatchers = struct {
	sync.Mutex
	next     uint64
	watchers map[vmPlatformWatchKey]map[uint64]chan driver.PlatformEventResult
}{watchers: make(map[vmPlatformWatchKey]map[uint64]chan driver.PlatformEventResult)}

type vmSandboxWatchKey struct{ stateRoot string }

var vmSandboxWatchers = struct {
	sync.Mutex
	next     uint64
	watchers map[vmSandboxWatchKey]map[uint64]chan driver.SandboxWatchResult
}{watchers: make(map[vmSandboxWatchKey]map[uint64]chan driver.SandboxWatchResult)}

// WatchSandboxes emits current VM snapshots followed by state changes and
// deletions. Local updates are delivered immediately; polling the shared state
// directory also observes changes made by other processes. Intermediate states
// may be coalesced between polls.
func (d *Driver) WatchSandboxes(ctx context.Context) (<-chan driver.SandboxWatchResult, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm sandbox watch: driver and context are required")
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return nil, err
	}
	updates, unsubscribe := subscribeVMSandboxes(vmSandboxWatchKey{stateRoot: filepath.Clean(store.root)})
	snapshots, err := d.List(ctx)
	if err != nil {
		unsubscribe()
		return nil, err
	}
	results := make(chan driver.SandboxWatchResult)
	go func() {
		defer close(results)
		defer unsubscribe()
		known := make(map[core.ID]driver.Info, len(snapshots))
		for index := range snapshots {
			info := snapshots[index]
			known[info.ID] = info
			if !sendVMSandboxWatchEvent(ctx, results, driver.SandboxWatchResult{Event: driver.SandboxWatchEvent{Sandbox: &info}}) {
				return
			}
		}
		ticker := time.NewTicker(vmSandboxWatchPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case update := <-updates:
				if update.Event.Sandbox != nil {
					info := *update.Event.Sandbox
					if previous, ok := known[info.ID]; ok && previous == info {
						continue
					}
					known[info.ID] = info
				} else if update.Event.DeletedID != "" {
					if _, ok := known[update.Event.DeletedID]; !ok {
						continue
					}
					delete(known, update.Event.DeletedID)
				}
				if !sendVMSandboxWatchEvent(ctx, results, update) {
					return
				}
			case <-ticker.C:
				states, err := store.list()
				if err != nil {
					if !sendVMSandboxWatchEvent(ctx, results, driver.SandboxWatchResult{Err: err}) {
						return
					}
					return
				}
				seen := make(map[core.ID]struct{}, len(states))
				for _, state := range states {
					info := stateInfo(state)
					seen[info.ID] = struct{}{}
					if previous, ok := known[info.ID]; ok && previous == info {
						continue
					}
					known[info.ID] = info
					if !sendVMSandboxWatchEvent(ctx, results, driver.SandboxWatchResult{Event: driver.SandboxWatchEvent{Sandbox: &info}}) {
						return
					}
				}
				for id := range known {
					if _, ok := seen[id]; ok {
						continue
					}
					delete(known, id)
					if !sendVMSandboxWatchEvent(ctx, results, driver.SandboxWatchResult{Event: driver.SandboxWatchEvent{DeletedID: id}}) {
						return
					}
				}
			}
		}
	}()
	return results, nil
}

func subscribeVMSandboxes(key vmSandboxWatchKey) (<-chan driver.SandboxWatchResult, func()) {
	vmSandboxWatchers.Lock()
	vmSandboxWatchers.next++
	id := vmSandboxWatchers.next
	updates := make(chan driver.SandboxWatchResult, vmPlatformWatchBuffer)
	if vmSandboxWatchers.watchers[key] == nil {
		vmSandboxWatchers.watchers[key] = make(map[uint64]chan driver.SandboxWatchResult)
	}
	vmSandboxWatchers.watchers[key][id] = updates
	vmSandboxWatchers.Unlock()
	return updates, func() {
		vmSandboxWatchers.Lock()
		defer vmSandboxWatchers.Unlock()
		delete(vmSandboxWatchers.watchers[key], id)
		if len(vmSandboxWatchers.watchers[key]) == 0 {
			delete(vmSandboxWatchers.watchers, key)
		}
	}
}

func publishVMSandboxSnapshot(stateRoot string, state sandboxState) {
	info := stateInfo(state)
	publishVMSandboxUpdate(vmSandboxWatchKey{stateRoot: filepath.Clean(stateRoot)}, driver.SandboxWatchResult{
		Event: driver.SandboxWatchEvent{Sandbox: &info},
	})
}

func publishVMSandboxDeleted(stateRoot, sandboxID string) {
	publishVMSandboxUpdate(vmSandboxWatchKey{stateRoot: filepath.Clean(stateRoot)}, driver.SandboxWatchResult{
		Event: driver.SandboxWatchEvent{DeletedID: core.ID(sandboxID)},
	})
}

func publishVMSandboxUpdate(key vmSandboxWatchKey, event driver.SandboxWatchResult) {
	vmSandboxWatchers.Lock()
	defer vmSandboxWatchers.Unlock()
	for _, updates := range vmSandboxWatchers.watchers[key] {
		select {
		case updates <- event:
		default:
			select {
			case <-updates:
			default:
			}
			select {
			case updates <- event:
			default:
			}
		}
	}
}

func sendVMSandboxWatchEvent(ctx context.Context, results chan<- driver.SandboxWatchResult, event driver.SandboxWatchResult) bool {
	select {
	case results <- event:
		return true
	case <-ctx.Done():
		return false
	}
}

// WatchPlatformEvents sends a persisted-state snapshot, then lifecycle changes
// published by the state store. Polling the shared state directory observes
// changes made by other processes, but does not provide durable replay and may
// coalesce intermediate states.
func (d *Driver) WatchPlatformEvents(ctx context.Context, request driver.PlatformEventWatchRequest) (<-chan driver.PlatformEventResult, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm platform watch: driver and context are required")
	}
	if request.SandboxID == "" {
		return nil, fmt.Errorf("vm platform watch: sandbox ID is required")
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return nil, err
	}
	key := vmPlatformWatchKey{stateRoot: filepath.Clean(store.root), sandboxID: string(request.SandboxID)}
	updates, unsubscribe := subscribeVMPlatformEvents(key)
	state, err := store.load(string(request.SandboxID))
	if err != nil {
		unsubscribe()
		return nil, err
	}
	results := make(chan driver.PlatformEventResult)
	go func() {
		defer close(results)
		defer unsubscribe()
		ticker := time.NewTicker(vmPlatformWatchPollInterval)
		defer ticker.Stop()
		lastUpdate := state.UpdatedAt
		lastStatus := state.Status
		if !sendVMPlatformEvent(ctx, results, vmStateEvent(state, false)) {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				current, err := store.load(string(request.SandboxID))
				if errors.Is(err, fs.ErrNotExist) {
					_ = sendVMPlatformEvent(ctx, results, driver.PlatformEventResult{Event: driver.PlatformEvent{
						SandboxID: request.SandboxID, Time: time.Now().UTC(), Source: "vm", Type: "deleted", Reason: "sandbox_deleted", Terminal: true,
					}})
					return
				}
				if err != nil {
					_ = sendVMPlatformEvent(ctx, results, driver.PlatformEventResult{Err: err})
					return
				}
				if current.Status == lastStatus && !current.UpdatedAt.After(lastUpdate) {
					continue
				}
				if !sendVMPlatformEvent(ctx, results, vmStateEvent(current, vmStateTerminal(current.Status))) {
					return
				}
				if current.UpdatedAt.After(lastUpdate) {
					lastUpdate = current.UpdatedAt
				}
				lastStatus = current.Status
			case update := <-updates:
				if update.Event.Type == "sandbox_state" && update.Event.Reason == lastStatus && !update.Event.Time.After(lastUpdate) {
					continue
				}
				if !sendVMPlatformEvent(ctx, results, update) {
					return
				}
				if update.Event.Type == "sandbox_state" {
					if update.Event.Time.After(lastUpdate) {
						lastUpdate = update.Event.Time
					}
					lastStatus = update.Event.Reason
				}
				if update.Event.Type == "deleted" {
					return
				}
			}
		}
	}()
	return results, nil
}

func subscribeVMPlatformEvents(key vmPlatformWatchKey) (<-chan driver.PlatformEventResult, func()) {
	vmPlatformWatchers.Lock()
	vmPlatformWatchers.next++
	id := vmPlatformWatchers.next
	updates := make(chan driver.PlatformEventResult, vmPlatformWatchBuffer)
	if vmPlatformWatchers.watchers[key] == nil {
		vmPlatformWatchers.watchers[key] = make(map[uint64]chan driver.PlatformEventResult)
	}
	vmPlatformWatchers.watchers[key][id] = updates
	vmPlatformWatchers.Unlock()
	return updates, func() {
		vmPlatformWatchers.Lock()
		defer vmPlatformWatchers.Unlock()
		delete(vmPlatformWatchers.watchers[key], id)
		if len(vmPlatformWatchers.watchers[key]) == 0 {
			delete(vmPlatformWatchers.watchers, key)
		}
	}
}

func publishVMPlatformState(stateRoot string, state sandboxState) {
	publishVMSandboxSnapshot(stateRoot, state)
	publishVMPlatformEvent(vmPlatformWatchKey{stateRoot: filepath.Clean(stateRoot), sandboxID: state.ID}, vmStateEvent(state, vmStateTerminal(state.Status)))
}

func publishVMPlatformDeleted(stateRoot, sandboxID string) {
	publishVMSandboxDeleted(stateRoot, sandboxID)
	publishVMPlatformEvent(vmPlatformWatchKey{stateRoot: filepath.Clean(stateRoot), sandboxID: sandboxID}, driver.PlatformEventResult{Event: driver.PlatformEvent{
		SandboxID: core.ID(sandboxID), Time: time.Now().UTC(), Source: "vm", Type: "deleted", Reason: "sandbox_deleted", Terminal: true,
	}})
}

func publishVMPlatformEvent(key vmPlatformWatchKey, event driver.PlatformEventResult) {
	vmPlatformWatchers.Lock()
	defer vmPlatformWatchers.Unlock()
	for _, updates := range vmPlatformWatchers.watchers[key] {
		select {
		case updates <- event:
		default:
			// Keep the newest state after a slow consumer falls behind, matching
			// the upstream broadcast feed's lagged-receiver behavior.
			select {
			case <-updates:
			default:
			}
			select {
			case updates <- event:
			default:
			}
		}
	}
}

func vmStateEvent(state sandboxState, terminal bool) driver.PlatformEventResult {
	return driver.PlatformEventResult{Event: driver.PlatformEvent{
		SandboxID: core.ID(state.ID), Time: state.UpdatedAt.UTC(), Source: "vm", Type: "sandbox_state",
		Reason: state.Status, Message: "VM sandbox state changed", Metadata: map[string]string{"status": state.Status}, Terminal: terminal,
	}}
}

func vmStateTerminal(status string) bool {
	return status == "stopped" || status == "completed" || status == "error"
}

func sendVMPlatformEvent(ctx context.Context, results chan<- driver.PlatformEventResult, event driver.PlatformEventResult) bool {
	select {
	case results <- event:
		return true
	case <-ctx.Done():
		return false
	}
}
