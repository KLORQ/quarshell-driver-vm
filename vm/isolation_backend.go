package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/KLORQ/quarshell-core/isolation"
)

const (
	vmIsolationBackendName = "quarshell/vm"
	vmIdentitySource       = "guest-supervisor-readiness-v1"
)

type vmIsolationBackend struct {
	driver       *Driver
	state        sandboxState
	sandboxDir   string
	guestSocket  string
	descriptor   []byte
	worker       *exec.Cmd
	broker       *networkBrokerProcess
	brokerSocket string
	workloadUID  uint32
	workloadGID  uint32
	controlID    *vmControlIdentity
	proxyEnabled bool
}

type vmIsolationEvidenceRecord struct {
	DescriptorSHA256 string `json:"descriptor_sha256"`
	SandboxID        string `json:"sandbox_id"`
	Generation       string `json:"generation"`
	WorkerPID        int    `json:"worker_pid"`
	BrokerPID        int    `json:"broker_pid"`
	WorkloadUID      uint32 `json:"workload_uid"`
	WorkloadGID      uint32 `json:"workload_gid"`
	NetworkMode      string `json:"network_mode"`
	RevocationPath   string `json:"revocation_path"`
	FilesystemPath   string `json:"filesystem_confinement"`
	SupervisorReady  bool   `json:"supervisor_ready"`
	BrokerHealthy    bool   `json:"broker_healthy"`
}

func (b *vmIsolationBackend) Name() string { return vmIsolationBackendName }

func (b *vmIsolationBackend) Attach(ctx context.Context, descriptor isolation.VerifiedDescriptor, sandbox isolation.SandboxContext) (isolation.Boundary, error) {
	if ctx == nil || b == nil || b.driver == nil || b.worker == nil || b.worker.Process == nil || b.controlID == nil || !b.proxyEnabled || b.broker == nil {
		return nil, fmt.Errorf("VM isolation attach requires a live worker, broker, and authenticated supervisor")
	}
	if descriptor.BackendName() != vmIsolationBackendName || descriptor.SandboxID() != b.state.ID || descriptor.SessionID() != b.state.RuntimeSessionID || descriptor.Generation() != b.state.RuntimeGeneration {
		return nil, fmt.Errorf("VM isolation descriptor changed during attach")
	}
	if sandbox.WorkloadUID != b.workloadUID || sandbox.WorkloadGID != b.workloadGID || sandbox.IdentitySource != vmIdentitySource || sandbox.IdentityDigest != vmWorkloadIdentityDigest(b.workloadUID, b.workloadGID) {
		return nil, fmt.Errorf("VM isolation attach received an unverified workload identity")
	}
	var payload vmIsolationPayload
	decoder := json.NewDecoder(bytes.NewReader(descriptor.Payload()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode VM isolation backend payload: %w", err)
	}
	if payload.WorkerID != b.state.ID || payload.SupervisorControlSocketID != b.state.ID || payload.NetworkBrokerSocketID != b.state.ID || payload.ControlIdentityDirectory != "supervisor-control" {
		return nil, fmt.Errorf("VM isolation payload does not identify the current worker and control identity")
	}
	current, err := readVMIsolationDescriptor(b.sandboxDir, b.state)
	if err != nil || !bytes.Equal(current, b.descriptor) {
		return nil, fmt.Errorf("VM isolation descriptor changed before backend attach")
	}
	return b, nil
}

func (b *vmIsolationBackend) Confirm(ctx context.Context) (isolation.EnforcementEvidence, error) {
	var evidence isolation.EnforcementEvidence
	if ctx == nil || b == nil || b.driver == nil || b.worker == nil || b.worker.Process == nil || b.broker == nil {
		return evidence, fmt.Errorf("VM isolation confirmation requires live worker and policy broker processes")
	}
	if b.workloadUID == 0 || b.workloadGID == 0 || b.controlID == nil || !b.proxyEnabled {
		return evidence, fmt.Errorf("VM isolation confirmation requires non-root readiness and authenticated policy controls")
	}
	if err := processIsAlive(b.worker.Process); err != nil {
		return evidence, fmt.Errorf("VM worker exited before isolation confirmation: %w", err)
	}
	brokerPID, err := networkBrokerIsolationPID(b.broker)
	if err != nil {
		return evidence, fmt.Errorf("VM policy broker is not safely supervised: %w", err)
	}
	if _, err := readVMIsolationDescriptor(b.sandboxDir, b.state); err != nil {
		return evidence, fmt.Errorf("revalidate VM isolation descriptor during confirmation: %w", err)
	}
	healthCtx, cancel := context.WithTimeout(ctx, time.Second)
	err = checkNetworkBrokerHealth(healthCtx, b.brokerSocket)
	cancel()
	if err != nil {
		return evidence, fmt.Errorf("VM policy broker failed its live health check: %w", err)
	}
	if _, err := b.driver.exchangeControl(ctx, b.state.ID, b.guestSocket, controlRequest{Operation: "ping"}); err != nil {
		return evidence, fmt.Errorf("VM guest control failed during isolation confirmation: %w", err)
	}
	if err := validateVMControlIdentityFiles(b.state, *b.controlID); err != nil {
		return evidence, fmt.Errorf("VM mTLS identity failed isolation confirmation: %w", err)
	}

	record := vmIsolationEvidenceRecord{
		DescriptorSHA256: fmt.Sprintf("%x", sha256.Sum256(b.descriptor)),
		SandboxID:        b.state.ID,
		Generation:       b.state.RuntimeGeneration,
		WorkerPID:        b.worker.Process.Pid,
		BrokerPID:        brokerPID,
		WorkloadUID:      b.workloadUID,
		WorkloadGID:      b.workloadGID,
		NetworkMode:      "vsock-only; TSI-mask=0; no virtual NIC",
		RevocationPath:   "broker loss closes host-parent liveness pipe; worker group and guest stop",
		FilesystemPath:   "guest-only root and workload disks; host filesystem is not mounted",
		SupervisorReady:  true,
		BrokerHealthy:    true,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return evidence, fmt.Errorf("encode VM isolation evidence: %w", err)
	}
	identityDigest := vmWorkloadIdentityDigest(b.workloadUID, b.workloadGID)
	evidence = isolation.EnforcementEvidence{
		Generation:                b.state.RuntimeGeneration,
		DefaultDenyEgress:         true,
		NoUnmanagedEgressPath:     true,
		RevocationVerified:        true,
		ControllerLossFailsClosed: true,
		FilesystemConfinement:     true,
		RequestAttribution:        true,
		PrivilegeFloor:            true,
		AuthenticatedSupervisor:   true,
		RuntimeExitStopsWorkload:  true,
		WorkloadUID:               b.workloadUID,
		WorkloadGID:               b.workloadGID,
		IdentitySource:            vmIdentitySource,
		IdentityDigest:            identityDigest,
		EvidenceDigest:            isolation.EvidenceDigest(b.state.RuntimeGeneration, encoded),
	}
	return evidence, nil
}

func (b *vmIsolationBackend) StartWorkload(ctx context.Context) error {
	if _, err := b.Confirm(ctx); err != nil {
		return fmt.Errorf("VM isolation changed before workload release: %w", err)
	}
	if _, err := b.driver.exchangeControl(ctx, b.state.ID, b.guestSocket, controlRequest{Operation: "confirm-workload"}); err != nil {
		return fmt.Errorf("release guest workload start gate: %w", err)
	}
	return nil
}

func (b *vmIsolationBackend) Close(context.Context) error { return nil }

func processIsAlive(process *os.Process) error {
	if process == nil {
		return fmt.Errorf("process handle is missing")
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return err
	}
	return nil
}

func vmWorkloadIdentityDigest(uid, gid uint32) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(fmt.Sprintf("guest-supervisor-readiness-v1\x00%d:%d", uid, gid))))
}
