//go:build linux

package vmguest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	userdb "os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KLORQ/quarshell-core/defaults"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// RunGuestAgent serves the VM control protocol on virtio-vsock. It is built as
// a static Linux binary and injected into each prepared rootfs by the host.
func Run() error {
	proxyPort, brokerPort, err := networkProxyConfigurationFromEnvironment()
	if err != nil {
		return err
	}
	relayConfig, err := relayConfigurationFromEnvironment()
	if err != nil {
		return err
	}
	proxyURL := ""
	if brokerPort != 0 {
		listener, err := startNetworkProxyBridge(proxyPort)
		if err != nil {
			return fmt.Errorf("start guest policy proxy: %w", err)
		}
		brokerListener, err := startNetworkBrokerVsock(brokerPort)
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("listen for host policy broker on vsock port %d: %w", brokerPort, err)
		}
		proxyURL = "http://127.0.0.1:" + strconv.Itoa(int(proxyPort))
		go serveNetworkProxyBridge(listener, brokerListener)
	}
	if relayConfig.sshPort != 0 {
		if err := startSSHRelayBridge(relayConfig.sshPort); err != nil {
			return fmt.Errorf("start guest SSH relay: %w", err)
		}
	}
	supervisorSocket := ""
	if relayConfig.controlPort != 0 {
		supervisorSocket, err = startSupervisorControlBridge(relayConfig.controlPort)
		if err != nil {
			return fmt.Errorf("start guest supervisor control relay: %w", err)
		}
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create guest vsock: %w", err)
	}
	defer unix.Close(fd)
	address := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: ControlPort}
	if err := unix.Bind(fd, address); err != nil {
		return fmt.Errorf("bind guest vsock port %d: %w", ControlPort, err)
	}
	if err := unix.Listen(fd, 64); err != nil {
		return fmt.Errorf("listen on guest vsock: %w", err)
	}
	uid, gid := guestIdentity()
	token := os.Getenv("QUARSHELL_VM_CONTROL_TOKEN")
	_ = os.Unsetenv("QUARSHELL_VM_CONTROL_TOKEN")
	decodedToken, err := hex.DecodeString(token)
	if err != nil || len(decodedToken) != 32 {
		return fmt.Errorf("guest control token is missing or invalid")
	}
	server := &controlServer{
		uid: uid, gid: gid, token: token, proxyURL: proxyURL,
		supervisorSocket: supervisorSocket, supervisorEnabled: relayConfig.supervisor,
		sshEnabled: relayConfig.sshPort != 0, terminals: make(map[string]*retainedTerminal),
		mainProcesses: make(map[string]*retainedMainProcess),
	}
	localListener, err := listenGuestAgentSocket(server, token)
	if err != nil {
		return fmt.Errorf("listen on guest agent local socket: %w", err)
	}
	defer localListener.Close()
	go func() {
		for {
			connection, acceptErr := localListener.Accept()
			if acceptErr != nil {
				return
			}
			go server.serve(connection)
		}
	}()
	for {
		connectionFD, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return nil
			}
			return fmt.Errorf("accept guest control connection: %w", err)
		}
		go server.serve(&guestVsockConn{File: os.NewFile(uintptr(connectionFD), "guest-vsock-client")})
	}
}

type guestVsockConn struct{ *os.File }

func (*guestVsockConn) LocalAddr() net.Addr              { return guestVsockAddr("local") }
func (*guestVsockConn) RemoteAddr() net.Addr             { return guestVsockAddr("remote") }
func (*guestVsockConn) SetDeadline(time.Time) error      { return nil }
func (*guestVsockConn) SetReadDeadline(time.Time) error  { return nil }
func (*guestVsockConn) SetWriteDeadline(time.Time) error { return nil }

type guestVsockAddr string

func (addr guestVsockAddr) Network() string { return "vsock" }
func (addr guestVsockAddr) String() string  { return string(addr) }

func guestIdentity() (uint32, uint32) {
	uid, _ := strconv.ParseUint(os.Getenv("QUARSHELL_VM_UID"), 10, 32)
	gid, _ := strconv.ParseUint(os.Getenv("QUARSHELL_VM_GID"), 10, 32)
	if uid == 0 {
		uid = 1000
	}
	if gid == 0 {
		gid = uid
	}
	return uint32(uid), uint32(gid)
}

type controlServer struct {
	uid                  uint32
	gid                  uint32
	token                string
	proxyURL             string
	supervisorSocket     string
	supervisorEnabled    bool
	sshEnabled           bool
	supervisorReady      string
	workloadCommand      func([]string, bool) []string
	authMu               sync.RWMutex
	mu                   sync.Mutex
	job                  *exec.Cmd
	mainProcessSessionID string
	jobDone              chan struct{}
	jobStopRequested     bool
	workloadConfirmed    bool
	workloadStartGate    *os.File
	workloadUID          uint32
	workloadGID          uint32
	powerOffGuest        func() error
	previousToken        string
	rotationID           string
	tokenFile            string
	sshMu                sync.Mutex
	sshDaemon            *exec.Cmd
	terminalMu           sync.Mutex
	terminals            map[string]*retainedTerminal
	mainProcessMu        sync.Mutex
	mainProcesses        map[string]*retainedMainProcess
}

const execOutputLimit = 8 << 20

const (
	guestSupervisorReadyFile            = "/run/quarshell/supervisor.ready"
	guestSupervisorControlCredentialDir = SupervisorControlCredentialDir
	guestSupervisorReadyEnv             = "QUARSHELL_VM_SUPERVISOR_READY_FILE"
	supervisorReadyContents             = "quarshell-supervisor-ready-v1\n"
	// Keep this above the guest supervisor's 30-second host-control begin
	// retry window so the supervisor can report its terminal startup error.
	supervisorReadyTimeout = 45 * time.Second
)

type boundedBuffer struct {
	data      []byte
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(payload []byte) (int, error) {
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		if remaining > len(payload) {
			remaining = len(payload)
		}
		b.data = append(b.data, payload[:remaining]...)
	}
	if remaining < len(payload) {
		b.truncated = true
	}
	return len(payload), nil
}

func (s *controlServer) serve(connection net.Conn) {
	defer connection.Close()
	encoded, err := ReadFrame(connection)
	if err != nil {
		return
	}
	var request Request
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		_ = writeResponse(connection, Response{Error: "invalid request"})
		return
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		_ = writeResponse(connection, Response{Error: "invalid request framing"})
		return
	}
	if request.Operation == "exec-terminal" || request.Operation == "attach-terminal" || request.Operation == "terminate-terminal" || request.Operation == "exec-stream" {
		if err := s.validateRequest(request); err != nil {
			_ = writeResponse(connection, Response{Error: err.Error()})
			return
		}
		if request.Operation == "exec-terminal" {
			s.execTerminal(connection, request)
		} else if request.Operation == "attach-terminal" {
			s.attachTerminal(connection, request.SessionID)
		} else if request.Operation == "terminate-terminal" {
			s.terminateTerminal(connection, request.SessionID)
		} else {
			s.execStream(connection, request)
		}
		return
	}
	if request.Operation == "attach-main-process" {
		if err := s.validateRequest(request); err != nil {
			_ = writeResponse(connection, Response{Error: err.Error()})
			return
		}
		if request.SessionID == "" {
			s.mu.Lock()
			request.SessionID = s.mainProcessSessionID
			s.mu.Unlock()
		}
		s.attachMainProcess(connection, request.SessionID)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		var byteBuffer [1]byte
		_, readErr := connection.Read(byteBuffer[:])
		if readErr != nil {
			cancel()
		}
	}()
	response := Response{}
	if err := s.validateRequest(request); err != nil {
		response.Error = err.Error()
	} else {
		response = s.dispatch(ctx, request)
	}
	cancel()
	_ = writeResponse(connection, response)
	_ = connection.Close()
	<-watchDone
	if request.Operation == "shutdown" && response.Error == "" {
		go func() {
			syscall.Sync()
			time.Sleep(100 * time.Millisecond)
			_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
		}()
	}
}

func (s *controlServer) validateRequest(request Request) error {
	if request.Version != ProtocolVersion {
		return fmt.Errorf("unsupported control protocol version %d", request.Version)
	}
	if request.Operation != "rotate-token" && (request.NextAuthToken != "" || request.RotationID != "") {
		return fmt.Errorf("token rotation fields are only valid for rotate-token")
	}
	if request.User != "" && request.Operation != "start-workload" && request.Operation != "exec" && request.Operation != "exec-terminal" && request.Operation != "exec-stream" {
		return fmt.Errorf("workload identity is only valid for workload operations")
	}
	if request.Signal != "" && request.Operation != "signal-main-process" {
		return fmt.Errorf("signal is only valid for signal-main-process")
	}
	if request.Operation == "signal-main-process" {
		if _, ok := guestTerminalSignal(request.Signal); !ok {
			return fmt.Errorf("main-process signal is not supported")
		}
	}
	if !s.authorizedRequest(request) {
		return fmt.Errorf("unauthorized guest control request")
	}
	return nil
}

func (s *controlServer) authorized(token string) bool {
	if s == nil {
		return false
	}
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	if len(s.token) != 64 || len(token) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.token), []byte(token)) == 1
}

func (s *controlServer) authorizedRequest(request Request) bool {
	if s.authorized(request.AuthToken) {
		return true
	}
	if s == nil || request.Operation != "rotate-token" || !validControlToken(request.NextAuthToken) || !validRotationID(request.RotationID) {
		return false
	}
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	return subtle.ConstantTimeCompare([]byte(s.previousToken), []byte(request.AuthToken)) == 1 &&
		subtle.ConstantTimeCompare([]byte(s.token), []byte(request.NextAuthToken)) == 1 &&
		subtle.ConstantTimeCompare([]byte(s.rotationID), []byte(request.RotationID)) == 1
}

func (s *controlServer) dispatch(ctx context.Context, request Request) Response {
	switch request.Operation {
	case "ping":
		return Response{}
	case "rotate-token":
		if err := s.rotateToken(request); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "start-workload":
		if request.SessionID == "" {
			var err error
			request.SessionID, err = newGuestMainSessionID()
			if err != nil {
				return Response{Error: fmt.Sprintf("generate canonical workload session ID: %v", err)}
			}
		}
		if err := s.startWorkload(ctx, request); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{WorkloadUID: s.workloadUID, WorkloadGID: s.workloadGID, SessionID: request.SessionID}
	case "confirm-workload":
		if err := s.confirmWorkloadStart(); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "stop-workload":
		if err := s.stopWorkload(); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "signal-main-process":
		if err := s.signalMainProcess(request.Signal); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "start-ssh":
		if err := s.startSSHDaemon(); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "shutdown":
		return Response{}
	case "exec":
		return s.exec(ctx, request)
	case "copy-to":
		if err := guestCopyTo(request.Path, request.Data, request.Mode, s.uid, s.gid); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "copy-control-credential":
		if err := guestCopyControlCredential(request.Path, request.Data); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "install-proxy-ca":
		if err := installProxyCABundle(request.Data); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "copy-from":
		data, err := guestCopyFrom(request.Path)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Data: data}
	default:
		return Response{Error: "unsupported operation"}
	}
}

func (s *controlServer) rotateToken(request Request) error {
	if !validControlToken(request.NextAuthToken) || !validRotationID(request.RotationID) {
		return fmt.Errorf("guest control token rotation request is malformed")
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if subtle.ConstantTimeCompare([]byte(s.previousToken), []byte(request.AuthToken)) == 1 &&
		subtle.ConstantTimeCompare([]byte(s.token), []byte(request.NextAuthToken)) == 1 &&
		subtle.ConstantTimeCompare([]byte(s.rotationID), []byte(request.RotationID)) == 1 {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(s.token), []byte(request.AuthToken)) != 1 {
		return fmt.Errorf("guest control token rotation is unauthorized")
	}
	if subtle.ConstantTimeCompare([]byte(s.token), []byte(request.NextAuthToken)) == 1 {
		return fmt.Errorf("guest control token rotation must change the token")
	}
	s.previousToken = s.token
	s.token = request.NextAuthToken
	s.rotationID = request.RotationID
	if s.tokenFile != "" {
		return writeGuestAgentToken(s.tokenFile, s.token)
	}
	return nil
}

func validControlToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(token)
	return err == nil && len(decoded) == 32
}

func listenGuestAgentSocket(server *controlServer, token string) (net.Listener, error) {
	if server == nil || !validControlToken(token) {
		return nil, fmt.Errorf("guest agent local socket requires a valid control token")
	}
	if err := os.MkdirAll(filepath.Dir(defaults.GuestAgentSocket), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(filepath.Dir(defaults.GuestAgentSocket), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(defaults.GuestAgentSocket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("guest agent socket path exists and is not a socket")
		}
		if err := os.Remove(defaults.GuestAgentSocket); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	server.tokenFile = defaults.GuestAgentTokenFile
	if err := writeGuestAgentToken(server.tokenFile, token); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", defaults.GuestAgentSocket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(defaults.GuestAgentSocket, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(defaults.GuestAgentSocket)
		return nil, err
	}
	return listener, nil
}

func writeGuestAgentToken(path, token string) error {
	if !validControlToken(token) {
		return fmt.Errorf("guest agent control token is invalid")
	}
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(token); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return os.Rename(temporary, path)
}

func newGuestMainSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func validRotationID(id string) bool {
	if len(id) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16
}

func (s *controlServer) startWorkload(ctx context.Context, request Request) error {
	if ctx == nil {
		return fmt.Errorf("guest workload start context is nil")
	}
	if len(request.Argv) == 0 {
		return fmt.Errorf("workload argv is empty")
	}
	if request.TTY && strings.TrimSpace(request.SessionID) == "" {
		return fmt.Errorf("TTY workload requires a retained session ID")
	}
	if request.SessionID == "" {
		var err error
		request.SessionID, err = newGuestMainSessionID()
		if err != nil {
			return fmt.Errorf("generate canonical workload session ID: %w", err)
		}
	}
	if !validMainSessionID(request.SessionID) {
		return fmt.Errorf("canonical workload requires a retained session ID")
	}
	restartPolicy, err := normalizeGuestRestartPolicy(request.RestartPolicy)
	if err != nil {
		return err
	}
	if restartPolicy != "never" && !s.supervisorEnabled {
		return fmt.Errorf("main process restart policy requires the guest supervisor")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job != nil && s.job.Process != nil {
		return fmt.Errorf("sandbox workload is already running")
	}
	s.jobStopRequested = false
	s.workloadConfirmed = false
	readyPath := ""
	if s.supervisorEnabled {
		readyPath = s.supervisorReady
		if readyPath == "" {
			readyPath = guestSupervisorReadyFile
		}
		if err := prepareSupervisorReadiness(readyPath); err != nil {
			return fmt.Errorf("prepare guest supervisor readiness: %w", err)
		}
	}
	buildCommand := guestWorkloadCommand
	if s.workloadCommand != nil {
		buildCommand = s.workloadCommand
	}
	argv := buildCommand(request.Argv, s.supervisorEnabled)
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = guestEnvironmentForWorkload(request.Env, s.proxyURL)
	var startGateReader, startGateWriter *os.File
	if s.supervisorEnabled {
		var err error
		startGateReader, startGateWriter, err = os.Pipe()
		if err != nil {
			return fmt.Errorf("create guest workload start gate: %w", err)
		}
		command.ExtraFiles = []*os.File{startGateReader}
		command.Env = mergeGuestEnvironment(command.Env,
			"QUARSHELL_POLICY="+guestPolicyFile,
			"QUARSHELL_SUPERVISOR_WAIT_FOR_WORKLOAD_READY=1",
			"QUARSHELL_SUPERVISOR_CONTROL_SOCKET="+s.supervisorSocket,
			"QUARSHELL_SUPERVISOR_CONTROL_CLIENT_CA="+guestSupervisorControlCredentialDir+"/ca.pem",
			"QUARSHELL_SUPERVISOR_CONTROL_CLIENT_CERT="+guestSupervisorControlCredentialDir+"/client.crt",
			"QUARSHELL_SUPERVISOR_CONTROL_CLIENT_KEY="+guestSupervisorControlCredentialDir+"/client.key",
			"QUARSHELL_MAIN_PROCESS_RESTART_POLICY="+restartPolicy,
			guestSupervisorReadyEnv+"="+readyPath,
		)
		if request.User != "" {
			command.Env = mergeGuestEnvironment(command.Env, "OPENSHELL_OCI_IMAGE_USER="+request.User)
		}
		command.Env = mergeGuestEnvironment(command.Env, "QUARSHELL_SUPERVISOR_START_GATE_FD=3")
	}
	command.Dir = guestWorkdir(request.WorkDir)
	var mainStdin, childStdin, mainStdout, childStdout, mainStderr, childStderr *os.File
	if !request.TTY {
		childStdin, mainStdin, err = os.Pipe()
		if err != nil {
			return fmt.Errorf("create canonical workload stdin: %w", err)
		}
		mainStdout, childStdout, err = os.Pipe()
		if err != nil {
			_ = mainStdin.Close()
			_ = childStdin.Close()
			return fmt.Errorf("create canonical workload stdout: %w", err)
		}
		mainStderr, childStderr, err = os.Pipe()
		if err != nil {
			_ = mainStdin.Close()
			_ = childStdin.Close()
			_ = mainStdout.Close()
			_ = childStdout.Close()
			return fmt.Errorf("create canonical workload stderr: %w", err)
		}
		command.Stdin, command.Stdout, command.Stderr = childStdin, childStdout, childStderr
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	var workloadUID, workloadGID uint32
	if !s.supervisorEnabled {
		credential, err := guestWorkloadCredential(request.User, s.uid, s.gid)
		if err != nil {
			return fmt.Errorf("resolve guest workload identity: %w", err)
		}
		if command.SysProcAttr == nil {
			command.SysProcAttr = &syscall.SysProcAttr{}
		}
		command.SysProcAttr.Credential = credential
		if credential == nil {
			workloadUID, workloadGID = uint32(os.Geteuid()), uint32(os.Getegid())
		} else {
			workloadUID, workloadGID = credential.Uid, credential.Gid
		}
	}
	var terminal *os.File
	if request.TTY {
		columns, rows := request.Columns, request.Rows
		if columns == 0 {
			columns = 80
		}
		if rows == 0 {
			rows = 24
		}
		if columns > 65535 || rows > 65535 {
			if startGateReader != nil {
				_ = startGateReader.Close()
			}
			if startGateWriter != nil {
				_ = startGateWriter.Close()
			}
			return fmt.Errorf("TTY workload dimensions must not exceed 65535")
		}
		terminal, err = pty.StartWithSize(command, &pty.Winsize{Cols: uint16(columns), Rows: uint16(rows)})
	} else {
		err = command.Start()
	}
	if err != nil {
		for _, file := range []*os.File{mainStdin, childStdin, mainStdout, childStdout, mainStderr, childStderr} {
			if file != nil {
				_ = file.Close()
			}
		}
		if startGateReader != nil {
			_ = startGateReader.Close()
		}
		if startGateWriter != nil {
			_ = startGateWriter.Close()
		}
		return fmt.Errorf("start sandbox workload: %w", err)
	}
	if startGateReader != nil {
		_ = startGateReader.Close()
	}
	if !request.TTY {
		_ = childStdin.Close()
		_ = childStdout.Close()
		_ = childStderr.Close()
	}
	s.job = command
	s.mainProcessSessionID = request.SessionID
	s.workloadStartGate = startGateWriter
	done := make(chan struct{})
	s.jobDone = done
	onExit := func() {
		// Signal process completion before taking s.mu. startWorkload holds the
		// mutex while waiting for supervisor readiness and, on failure, waits
		// for done after killing the child. Closing done after locking here
		// would deadlock that cleanup path against this callback.
		close(done)
		s.mu.Lock()
		naturalExit := false
		if s.job == command {
			naturalExit = !s.jobStopRequested
			s.job = nil
			s.jobDone = nil
			s.workloadConfirmed = false
			closeWorkloadStartGate(s.workloadStartGate)
			s.workloadStartGate = nil
		}
		s.mu.Unlock()
		if naturalExit {
			if request.AwaitMainProcessAttachment {
				if request.TTY {
					s.waitForTerminalAttachment(request.SessionID)
				} else {
					s.waitForMainProcessAttachment(request.SessionID)
				}
			}
			if err := s.powerOffAfterWorkloadExit(); err != nil {
				fmt.Fprintf(os.Stderr, "quarshell-vm-guest-agent: power off after workload exit: %v\n", err)
			}
		}
	}
	if request.TTY {
		s.terminalMu.Lock()
		_, exists := s.terminals[request.SessionID]
		if exists {
			s.terminalMu.Unlock()
			_ = terminal.Close()
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			_ = command.Wait()
			s.job = nil
			s.jobDone = nil
			return fmt.Errorf("terminal session ID already exists")
		}
		_, retainErr := s.retainTerminalLocked(request.SessionID, command, terminal, request.AwaitMainProcessAttachment, onExit)
		s.terminalMu.Unlock()
		if retainErr != nil {
			_ = terminal.Close()
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			_ = command.Wait()
			s.job = nil
			s.jobDone = nil
			return retainErr
		}
	} else {
		if err := s.retainMainProcess(request.SessionID, command, mainStdin, mainStdout, mainStderr, request.AwaitMainProcessAttachment, onExit); err != nil {
			_ = mainStdin.Close()
			_ = mainStdout.Close()
			_ = mainStderr.Close()
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			_ = command.Wait()
			s.job = nil
			s.jobDone = nil
			return err
		}
	}
	if s.supervisorEnabled {
		var err error
		workloadUID, workloadGID, err = waitForSupervisorReadiness(ctx, readyPath, done)
		if err != nil {
			s.jobStopRequested = true
			closeWorkloadStartGate(s.workloadStartGate)
			s.workloadStartGate = nil
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = command.Process.Kill()
				<-done
			}
			s.job = nil
			s.jobDone = nil
			_ = os.Remove(readyPath)
			if output := s.retainedTerminalOutputTail(request.SessionID, 4096); output != "" {
				return fmt.Errorf("guest supervisor did not become ready: %w (pre-readiness output: %q)", err, output)
			}
			return fmt.Errorf("guest supervisor did not become ready: %w", err)
		}
	}
	s.workloadUID, s.workloadGID = workloadUID, workloadGID
	return nil
}

func (s *controlServer) confirmWorkloadStart() error {
	if s == nil || !s.supervisorEnabled {
		return fmt.Errorf("guest supervisor is not enabled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job == nil || s.job.Process == nil || s.workloadUID == 0 || s.workloadGID == 0 {
		return fmt.Errorf("guest workload has not completed the isolation readiness handshake")
	}
	if s.workloadConfirmed {
		return nil
	}
	if s.workloadStartGate == nil {
		return fmt.Errorf("guest workload start gate is unavailable")
	}
	if _, err := io.WriteString(s.workloadStartGate, "confirmed\n"); err != nil {
		closeWorkloadStartGate(s.workloadStartGate)
		s.workloadStartGate = nil
		return fmt.Errorf("signal guest workload start gate: %w", err)
	}
	closeWorkloadStartGate(s.workloadStartGate)
	s.workloadStartGate = nil
	s.workloadConfirmed = true
	return nil
}

func closeWorkloadStartGate(file *os.File) {
	if file != nil {
		_ = file.Close()
	}
}

func prepareSupervisorReadiness(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("supervisor readiness path is invalid")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("supervisor readiness directory must be a real directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace a non-regular supervisor readiness marker")
	}
	return os.Remove(path)
}

func waitForSupervisorReadiness(ctx context.Context, path string, done <-chan struct{}) (uint32, uint32, error) {
	timer := time.NewTimer(supervisorReadyTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready, uid, gid, err := readSupervisorReadiness(path)
		if err != nil {
			return 0, 0, err
		}
		if ready {
			if err := os.Remove(path); err != nil {
				return 0, 0, err
			}
			return uid, gid, nil
		}
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		case <-done:
			return 0, 0, fmt.Errorf("supervisor exited before publishing readiness")
		case <-timer.C:
			return 0, 0, fmt.Errorf("supervisor readiness timed out after %s", supervisorReadyTimeout)
		case <-ticker.C:
		}
	}
}

func readSupervisorReadiness(path string) (bool, uint32, uint32, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, 0, 0, nil
	}
	if err != nil {
		return false, 0, 0, err
	}
	file := os.NewFile(uintptr(fd), "supervisor-readiness")
	defer file.Close()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return false, 0, 0, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Size > 128 || info.Mode&0o077 != 0 {
		return false, 0, 0, fmt.Errorf("supervisor readiness marker has unsafe type, size or permissions")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil {
		return false, 0, 0, err
	}
	fields := strings.Fields(string(contents))
	if !strings.HasSuffix(string(contents), "\n") && strings.HasPrefix(string(contents), "quarshell-supervisor-ready-v2 ") {
		return false, 0, 0, nil
	}
	if len(fields) == 1 && fields[0] == strings.TrimSpace(supervisorReadyContents) {
		return false, 0, 0, fmt.Errorf("supervisor readiness marker does not contain a verified workload identity")
	}
	if len(fields) != 3 || fields[0] != "quarshell-supervisor-ready-v2" {
		return false, 0, 0, fmt.Errorf("supervisor readiness marker has invalid contents")
	}
	uid, uidErr := strconv.ParseUint(fields[1], 10, 32)
	gid, gidErr := strconv.ParseUint(fields[2], 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return false, 0, 0, fmt.Errorf("supervisor readiness marker has invalid workload identity")
	}
	return true, uint32(uid), uint32(gid), nil
}

func normalizeGuestRestartPolicy(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "never":
		return "never", nil
	case "on-failure", "always":
		return strings.ToLower(strings.TrimSpace(raw)), nil
	default:
		return "", fmt.Errorf("invalid main process restart policy")
	}
}

func (s *controlServer) startSSHDaemon() error {
	if !s.sshEnabled {
		return fmt.Errorf("sandbox has no SSH relay")
	}
	s.sshMu.Lock()
	if s.sshDaemon != nil && s.sshDaemon.Process != nil {
		if connection, err := net.DialTimeout("unix", guestSSHSocket, 150*time.Millisecond); err == nil {
			_ = connection.Close()
			s.sshMu.Unlock()
			return nil
		}
	}
	command := exec.Command(guestSSHBinary,
		"--socket", guestSSHSocket,
		"--init", guestInitBinary,
		"--workdir", "/sandbox",
	)
	command.Env = mergeGuestEnvironment(guestEnvironmentForWorkload(nil, s.proxyURL), "QUARSHELL_POLICY="+guestPolicyFile)
	command.Dir = "/"
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		s.sshMu.Unlock()
		return fmt.Errorf("start guest SSH daemon: %w", err)
	}
	s.sshDaemon = command
	go func() {
		_ = command.Wait()
		s.sshMu.Lock()
		if s.sshDaemon == command {
			s.sshDaemon = nil
		}
		s.sshMu.Unlock()
	}()
	s.sshMu.Unlock()

	// A guest init drop-in may start a container engine before the workload.
	// On nested KVM that can keep the guest CPU busy long enough that sshd
	// needs more than the usual few seconds to initialize its host key/socket.
	deadline := time.Now().Add(30 * time.Second)
	var lastSocketErr error
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("unix", guestSSHSocket, 150*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		lastSocketErr = err
		s.sshMu.Lock()
		stillRunning := s.sshDaemon == command
		s.sshMu.Unlock()
		if !stillRunning {
			return fmt.Errorf("guest SSH daemon exited before readiness")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if info, err := os.Lstat(guestSSHSocket); err == nil {
		return fmt.Errorf("guest SSH socket did not become ready: dial: %v; socket mode=%s uid=%d gid=%d", lastSocketErr, info.Mode(), info.Sys().(*syscall.Stat_t).Uid, info.Sys().(*syscall.Stat_t).Gid)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("guest SSH socket did not become ready after 30s: dial: %v; process: %s; inspect socket: %w", lastSocketErr, guestProcessDiagnostic(command.Process.Pid), err)
	}
	return fmt.Errorf("guest SSH socket did not become ready after 30s: dial: %v; process: %s; socket does not exist", lastSocketErr, guestProcessDiagnostic(command.Process.Pid))
}

func guestProcessDiagnostic(pid int) string {
	if pid <= 0 {
		return "pid unavailable"
	}
	base := filepath.Join("/proc", strconv.Itoa(pid))
	stat, statErr := os.ReadFile(filepath.Join(base, "stat"))
	wchan, wchanErr := os.ReadFile(filepath.Join(base, "wchan"))
	if statErr != nil {
		return "process exited or stat unavailable: " + statErr.Error()
	}
	state := "unknown"
	if closeParen := strings.LastIndexByte(string(stat), ')'); closeParen >= 0 {
		fields := strings.Fields(string(stat[closeParen+1:]))
		if len(fields) > 0 {
			state = fields[0]
		}
	}
	if wchanErr != nil {
		return fmt.Sprintf("pid=%d state=%s wchan unavailable: %v", pid, state, wchanErr)
	}
	return fmt.Sprintf("pid=%d state=%s wchan=%s", pid, state, strings.TrimSpace(string(wchan)))
}

func (s *controlServer) signalMainProcess(name string) error {
	signal, ok := guestTerminalSignal(name)
	if !ok {
		return fmt.Errorf("main-process signal is not supported")
	}
	s.mu.Lock()
	command, done := s.job, s.jobDone
	if command == nil || command.Process == nil {
		s.mu.Unlock()
		return fmt.Errorf("main process is not running")
	}
	processPID := command.Process.Pid
	supervisorEnabled := s.supervisorEnabled
	s.mu.Unlock()
	processGroups := []int{processPID}
	if supervisorEnabled {
		var err error
		processGroups, err = guestMainProcessGroups(processPID)
		if err != nil {
			if done != nil {
				select {
				case <-done:
					return nil
				default:
				}
			}
			return fmt.Errorf("find canonical workload process groups: %w", err)
		}
	}
	for _, processGroup := range processGroups {
		if err := syscall.Kill(-processGroup, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("signal main-process group %d: %w", processGroup, err)
		}
	}
	return nil
}

type guestProcessInfo struct {
	pid  int
	ppid int
	pgid int
}

func guestMainProcessGroups(supervisorPID int) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	processes := make(map[int]guestProcessInfo, len(entries))
	children := make(map[int][]guestProcessInfo, len(entries))
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if readErr != nil {
			continue
		}
		process, parseErr := parseGuestProcessInfo(pid, data)
		if parseErr == nil {
			processes[pid] = process
			children[process.ppid] = append(children[process.ppid], process)
		}
	}
	root, ok := processes[supervisorPID]
	if !ok {
		return nil, fmt.Errorf("supervisor process %d is no longer present", supervisorPID)
	}
	descendants := map[int]struct{}{supervisorPID: {}}
	queue := []int{supervisorPID}
	groups := make(map[int]struct{})
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range children[parent] {
			if _, seen := descendants[child.pid]; seen {
				continue
			}
			descendants[child.pid] = struct{}{}
			groups[child.pgid] = struct{}{}
			queue = append(queue, child.pid)
		}
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("supervisor process %d has no live workload descendants", supervisorPID)
	}
	// The canonical supervisor has a separate process group. If any workload
	// descendant has its own group, signal workload groups only; otherwise the
	// wrapper and workload intentionally share the same process group.
	if _, separate := groups[root.pgid]; separate && len(groups) > 1 {
		delete(groups, root.pgid)
	} else if _, separate := groups[root.pgid]; separate {
		workloadPIDs := 0
		for pid := range descendants {
			if pid != supervisorPID && processes[pid].pgid != root.pgid {
				workloadPIDs++
			}
		}
		if workloadPIDs > 0 {
			delete(groups, root.pgid)
		}
	}
	result := make([]int, 0, len(groups))
	for group := range groups {
		if group > 0 {
			result = append(result, group)
		}
	}
	sort.Ints(result)
	if len(result) == 0 {
		return nil, fmt.Errorf("supervisor process %d has no signalable workload groups", supervisorPID)
	}
	return result, nil
}

func parseGuestProcessInfo(pid int, data []byte) (guestProcessInfo, error) {
	closeParen := strings.LastIndexByte(string(data), ')')
	if closeParen < 0 || closeParen+2 >= len(data) {
		return guestProcessInfo{}, fmt.Errorf("malformed process stat")
	}
	fields := strings.Fields(string(data[closeParen+1:]))
	if len(fields) < 3 {
		return guestProcessInfo{}, fmt.Errorf("malformed process stat")
	}
	ppid, ppidErr := strconv.Atoi(fields[1])
	pgid, pgidErr := strconv.Atoi(fields[2])
	if ppidErr != nil || pgidErr != nil || ppid < 0 || pgid <= 0 {
		return guestProcessInfo{}, fmt.Errorf("malformed process stat")
	}
	return guestProcessInfo{pid: pid, ppid: ppid, pgid: pgid}, nil
}

func (s *controlServer) stopWorkload() error {
	s.mu.Lock()
	command := s.job
	done := s.jobDone
	if command != nil {
		s.jobStopRequested = true
	}
	s.mu.Unlock()
	if command == nil || command.Process == nil {
		s.closeWorkloadStartGate()
		return nil
	}
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("stop sandbox workload: %w", err)
	}
	if done != nil {
		select {
		case <-done:
			s.closeWorkloadStartGate()
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("force stop sandbox workload: %w", err)
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			return fmt.Errorf("sandbox workload did not exit after SIGKILL")
		}
	}
	s.closeWorkloadStartGate()
	return nil
}

func (s *controlServer) closeWorkloadStartGate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	gate := s.workloadStartGate
	s.workloadStartGate = nil
	s.mu.Unlock()
	closeWorkloadStartGate(gate)
}

func (s *controlServer) powerOffAfterWorkloadExit() error {
	if s.powerOffGuest != nil {
		return s.powerOffGuest()
	}
	syscall.Sync()
	time.Sleep(100 * time.Millisecond)
	return unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}

func (s *controlServer) exec(ctx context.Context, request Request) Response {
	if len(request.Argv) == 0 {
		return Response{Error: "exec argv is empty"}
	}
	shellArgv, err := guestShellCommand(request.Argv, request.NoLoginShell)
	if err != nil {
		return Response{Error: err.Error()}
	}
	argv := guestExecCommand(shellArgv, s.supervisorEnabled)
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = guestEnvironmentForWorkload(request.Env, s.proxyURL)
	if s.supervisorEnabled {
		command.Env = mergeGuestEnvironment(command.Env, "QUARSHELL_POLICY="+guestPolicyFile)
		if request.User != "" {
			command.Env = mergeGuestEnvironment(command.Env, "OPENSHELL_OCI_IMAGE_USER="+request.User)
		}
	}
	command.Dir = guestWorkdir(request.WorkDir)
	command.Stdin = bytes.NewReader(request.Stdin)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if !s.supervisorEnabled {
		credential, err := guestWorkloadCredential(request.User, s.uid, s.gid)
		if err != nil {
			return Response{Error: fmt.Sprintf("resolve guest workload identity: %v", err)}
		}
		command.SysProcAttr.Credential = credential
	}
	stdout := boundedBuffer{limit: execOutputLimit}
	stderr := boundedBuffer{limit: execOutputLimit}
	command.Stdout = &stdout
	command.Stderr = &stderr
	if startErr := command.Start(); startErr != nil {
		return Response{Error: startErr.Error()}
	}
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		case <-watchDone:
		}
	}()
	waitErr := command.Wait()
	close(watchDone)
	response := Response{Stdout: stdout.data, Stderr: stderr.data, OutputTruncated: stdout.truncated || stderr.truncated}
	if waitErr == nil {
		return response
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		response.ExitCode = exitError.ExitCode()
		return response
	}
	response.Error = waitErr.Error()
	return response
}

func (s *controlServer) execTerminal(connection net.Conn, request Request) {
	if len(request.Argv) == 0 {
		_ = writeResponse(connection, Response{Error: "exec argv is empty"})
		return
	}
	if request.Columns == 0 || request.Rows == 0 || request.Columns > 65535 || request.Rows > 65535 {
		_ = writeResponse(connection, Response{Error: "terminal dimensions must be between 1 and 65535"})
		return
	}
	if request.SessionID != "" {
		if len(request.SessionID) > 128 || strings.TrimSpace(request.SessionID) != request.SessionID {
			_ = writeResponse(connection, Response{Error: "terminal session ID is invalid"})
			return
		}
		s.terminalMu.Lock()
		_, exists := s.terminals[request.SessionID]
		s.terminalMu.Unlock()
		if exists {
			_ = writeResponse(connection, Response{Error: "terminal session ID already exists"})
			return
		}
	}
	shellArgv, err := guestShellCommand(request.Argv, request.NoLoginShell)
	if err != nil {
		_ = writeResponse(connection, Response{Error: err.Error()})
		return
	}
	argv := guestExecCommand(shellArgv, s.supervisorEnabled)
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = guestEnvironmentForWorkload(request.Env, s.proxyURL)
	if s.supervisorEnabled {
		command.Env = mergeGuestEnvironment(command.Env, "QUARSHELL_POLICY="+guestPolicyFile)
		if request.User != "" {
			command.Env = mergeGuestEnvironment(command.Env, "OPENSHELL_OCI_IMAGE_USER="+request.User)
		}
	}
	command.Dir = guestWorkdir(request.WorkDir)
	if !s.supervisorEnabled {
		credential, err := guestWorkloadCredential(request.User, s.uid, s.gid)
		if err != nil {
			_ = writeResponse(connection, Response{Error: fmt.Sprintf("resolve guest workload identity: %v", err)})
			return
		}
		command.SysProcAttr = credentialPTYAttributes(credential)
	}
	terminal, err := pty.StartWithSize(command, &pty.Winsize{Cols: uint16(request.Columns), Rows: uint16(request.Rows)})
	if err != nil {
		_ = writeResponse(connection, Response{Error: fmt.Sprintf("start guest PTY command: %v", err)})
		return
	}
	if request.SessionID != "" {
		s.terminalMu.Lock()
		if _, exists := s.terminals[request.SessionID]; exists {
			s.terminalMu.Unlock()
			_ = terminal.Close()
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			_ = command.Wait()
			_ = writeResponse(connection, Response{Error: "terminal session ID already exists"})
			return
		}
		process, retainErr := s.retainTerminalLocked(request.SessionID, command, terminal, false, nil)
		s.terminalMu.Unlock()
		if retainErr != nil {
			_ = terminal.Close()
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			_ = command.Wait()
			_ = writeResponse(connection, Response{Error: retainErr.Error()})
			return
		}
		process.attach(connection)
		return
	}
	if err := writeResponse(connection, Response{PID: command.Process.Pid}); err != nil {
		_ = terminal.Close()
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return
	}

	processDone := make(chan struct{})
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		buffer := make([]byte, 32<<10)
		for {
			count, readErr := terminal.Read(buffer)
			if count > 0 {
				if err := writeTerminalFrame(connection, TerminalFrame{Type: "output", Data: append([]byte(nil), buffer[:count]...)}); err != nil {
					terminatePTYProcess(command.Process.Pid, processDone)
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		for {
			payload, readErr := ReadFrame(connection)
			if readErr != nil {
				terminatePTYProcess(command.Process.Pid, processDone)
				return
			}
			var frame TerminalFrame
			decoder := json.NewDecoder(strings.NewReader(string(payload)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&frame); err != nil || decoder.Decode(new(any)) != io.EOF {
				terminatePTYProcess(command.Process.Pid, processDone)
				return
			}
			switch frame.Type {
			case "stdin":
				if len(frame.Data) > 0 {
					if _, err := terminal.Write(frame.Data); err != nil {
						terminatePTYProcess(command.Process.Pid, processDone)
						return
					}
				}
			case "resize":
				if frame.Columns == 0 || frame.Rows == 0 || frame.Columns > 65535 || frame.Rows > 65535 {
					terminatePTYProcess(command.Process.Pid, processDone)
					return
				}
				if err := pty.Setsize(terminal, &pty.Winsize{Cols: uint16(frame.Columns), Rows: uint16(frame.Rows)}); err != nil {
					terminatePTYProcess(command.Process.Pid, processDone)
					return
				}
			case "eof":
				_, _ = terminal.Write([]byte{4})
			case "signal":
				signal, ok := guestTerminalSignal(frame.Signal)
				if !ok || syscall.Kill(-command.Process.Pid, signal) != nil {
					terminatePTYProcess(command.Process.Pid, processDone)
					return
				}
			default:
				terminatePTYProcess(command.Process.Pid, processDone)
				return
			}
		}
	}()
	waitErr := command.Wait()
	close(processDone)
	// The process may exit before the PTY reader drains its last buffered
	// bytes; emit the exit frame only after that reader reaches EOF/EIO.
	<-outputDone
	_ = terminal.Close()
	_ = writeTerminalFrame(connection, TerminalFrame{Type: "exit", ExitCode: normalizeGuestExitCode(waitErr)})
	_ = connection.Close()
	<-inputDone
}

func guestTerminalSignal(name string) (syscall.Signal, bool) {
	switch name {
	case "terminate":
		return syscall.SIGTERM, true
	case "kill":
		return syscall.SIGKILL, true
	case "interrupt":
		return syscall.SIGINT, true
	case "hangup":
		return syscall.SIGHUP, true
	default:
		return 0, false
	}
}

func (s *controlServer) execStream(connection net.Conn, request Request) {
	if len(request.Argv) == 0 {
		_ = writeResponse(connection, Response{Error: "exec argv is empty"})
		return
	}
	shellArgv, err := guestShellCommand(request.Argv, request.NoLoginShell)
	if err != nil {
		_ = writeResponse(connection, Response{Error: err.Error()})
		return
	}
	argv := guestExecCommand(shellArgv, s.supervisorEnabled)
	command := exec.Command(argv[0], argv[1:]...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Env = guestEnvironmentForWorkload(request.Env, s.proxyURL)
	if s.supervisorEnabled {
		command.Env = mergeGuestEnvironment(command.Env, "QUARSHELL_POLICY="+guestPolicyFile)
		if request.User != "" {
			command.Env = mergeGuestEnvironment(command.Env, "OPENSHELL_OCI_IMAGE_USER="+request.User)
		}
	} else {
		credential, err := guestWorkloadCredential(request.User, s.uid, s.gid)
		if err != nil {
			_ = writeResponse(connection, Response{Error: fmt.Sprintf("resolve guest workload identity: %v", err)})
			return
		}
		command.SysProcAttr.Credential = credential
	}
	command.Dir = guestWorkdir(request.WorkDir)
	stdin, err := command.StdinPipe()
	if err != nil {
		_ = writeResponse(connection, Response{Error: fmt.Sprintf("open exec stdin: %v", err)})
		return
	}
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		_ = stdin.Close()
		_ = writeResponse(connection, Response{Error: fmt.Sprintf("open exec stdout: %v", err)})
		return
	}
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stdoutWriter.Close()
		_ = writeResponse(connection, Response{Error: fmt.Sprintf("open exec stderr: %v", err)})
		return
	}
	defer stdout.Close()
	defer stderr.Close()
	command.Stdout = stdoutWriter
	command.Stderr = stderrWriter
	if err := command.Start(); err != nil {
		_ = writeResponse(connection, Response{Error: fmt.Sprintf("start guest command: %v", err)})
		_ = stdin.Close()
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return
	}
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	if err := writeResponse(connection, Response{PID: command.Process.Pid}); err != nil {
		_ = stdin.Close()
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return
	}
	processDone := make(chan struct{})
	var frameMu sync.Mutex
	writeOutput := func(kind string, data []byte) error {
		frameMu.Lock()
		defer frameMu.Unlock()
		return writeTerminalFrame(connection, TerminalFrame{Type: kind, Data: append([]byte(nil), data...)})
	}
	var outputWG sync.WaitGroup
	copyOutput := func(reader io.Reader, kind string) {
		defer outputWG.Done()
		buffer := make([]byte, 32<<10)
		for {
			count, readErr := reader.Read(buffer)
			if count > 0 {
				if err := writeOutput(kind, buffer[:count]); err != nil {
					terminatePTYProcess(command.Process.Pid, processDone)
					return
				}
			}
			if readErr != nil {
				if readErr != io.EOF {
					terminatePTYProcess(command.Process.Pid, processDone)
				}
				return
			}
		}
	}
	outputWG.Add(2)
	go copyOutput(stdout, "stdout")
	go copyOutput(stderr, "stderr")
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		stdinClosed := false
		for {
			payload, readErr := ReadFrame(connection)
			if readErr != nil {
				terminatePTYProcess(command.Process.Pid, processDone)
				return
			}
			var frame TerminalFrame
			decoder := json.NewDecoder(strings.NewReader(string(payload)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&frame); err != nil || decoder.Decode(new(any)) != io.EOF {
				terminatePTYProcess(command.Process.Pid, processDone)
				return
			}
			switch frame.Type {
			case "stdin":
				if stdinClosed {
					terminatePTYProcess(command.Process.Pid, processDone)
					return
				}
				if len(frame.Data) > 0 {
					if _, err := stdin.Write(frame.Data); err != nil {
						terminatePTYProcess(command.Process.Pid, processDone)
						return
					}
				}
			case "eof":
				if !stdinClosed {
					stdinClosed = true
					_ = stdin.Close()
				}
			default:
				terminatePTYProcess(command.Process.Pid, processDone)
				return
			}
		}
	}()
	waitErr := command.Wait()
	close(processDone)
	_ = stdin.Close()
	outputWG.Wait()
	frameMu.Lock()
	_ = writeTerminalFrame(connection, TerminalFrame{Type: "exit", ExitCode: normalizeGuestExitCode(waitErr)})
	frameMu.Unlock()
	_ = connection.Close()
	<-inputDone
}

func writeTerminalFrame(writer io.Writer, frame TerminalFrame) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return WriteFrame(writer, encoded)
}

func terminatePTYProcess(pid int, done <-chan struct{}) {
	if pid <= 1 {
		return
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		return
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}

func normalizeGuestExitCode(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exitError.ExitCode()
	}
	return 255
}

func credentialPTYAttributes(credential *syscall.Credential) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Credential: credential}
}

func guestCopyTo(path string, data []byte, mode, uid, gid uint32) error {
	clean, err := cleanGuestPath(path)
	if err != nil {
		return err
	}
	if len(data) > FrameMax/2 {
		return fmt.Errorf("copy-to payload exceeds %d bytes", FrameMax/2)
	}
	parentFD, name, err := openGuestParent(clean, true)
	if err != nil {
		return fmt.Errorf("open guest destination directory: %w", err)
	}
	defer unix.Close(parentFD)
	mode &= 0o777
	if mode == 0 {
		mode = 0o644
	}
	fd, err := openGuestFileForWrite(parentFD, name, mode)
	if err != nil {
		return fmt.Errorf("open guest destination: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return fmt.Errorf("inspect guest destination: %w", err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("guest destination must be a regular file")
	}
	if err := unix.Ftruncate(fd, 0); err != nil {
		return fmt.Errorf("truncate guest destination: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write guest destination: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync guest destination: %w", err)
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return fmt.Errorf("set guest destination owner: %w", err)
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return fmt.Errorf("set guest destination mode: %w", err)
	}
	return nil
}

func guestCopyControlCredential(path string, data []byte) error {
	clean, err := cleanGuestPath(path)
	if err != nil {
		return err
	}
	switch clean {
	case guestSupervisorControlCredentialDir + "/ca.pem", guestSupervisorControlCredentialDir + "/client.crt", guestSupervisorControlCredentialDir + "/client.key", guestSupervisorControlCredentialDir + "/gateway-verification-keys.json":
	default:
		return fmt.Errorf("control credential destination is not allowed")
	}
	if len(data) == 0 || len(data) > FrameMax/2 {
		return fmt.Errorf("control credential payload has invalid size")
	}
	if err := guestCopyTo(clean, data, 0o600, 0, 0); err != nil {
		return err
	}
	parentFD, _, err := openGuestParent(clean, false)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := unix.Fchmod(parentFD, 0o700); err != nil {
		return fmt.Errorf("secure control credential directory: %w", err)
	}
	if err := unix.Fchown(parentFD, 0, 0); err != nil {
		return fmt.Errorf("set control credential directory owner: %w", err)
	}
	return nil
}

func openGuestFileForWrite(parentFD int, name string, mode uint32) (int, error) {
	pathFD, err := unix.Openat(parentFD, name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		// O_EXCL ensures a file created between the O_PATH lookup and this call
		// cannot redirect the write through a symlink or device node.
		return unix.Openat(parentFD, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, mode)
	}
	if err != nil {
		return -1, err
	}
	defer unix.Close(pathFD)
	var info unix.Stat_t
	if err := unix.Fstat(pathFD, &info); err != nil {
		return -1, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1, fmt.Errorf("guest destination must be a regular file")
	}
	// Reopen the already-verified inode through procfs so a concurrent rename
	// cannot substitute a different path between validation and writing.
	return unix.Open(fmt.Sprintf("/proc/self/fd/%d", pathFD), unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
}

func guestCopyFrom(path string) ([]byte, error) {
	clean, err := cleanGuestPath(path)
	if err != nil {
		return nil, err
	}
	parentFD, name, err := openGuestParent(clean, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return nil, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Size > FrameMax/2 {
		return nil, fmt.Errorf("guest source must be a regular file no larger than %d bytes", FrameMax/2)
	}
	data, err := io.ReadAll(io.LimitReader(file, FrameMax/2+1))
	if err != nil {
		return nil, err
	}
	if len(data) > FrameMax/2 {
		return nil, fmt.Errorf("guest source grew beyond %d bytes", FrameMax/2)
	}
	return data, nil
}

// openGuestParent walks from the guest root one directory at a time. O_NOFOLLOW
// prevents a workload-created symlink from redirecting a privileged copy
// operation outside the requested path hierarchy.
func openGuestParent(path string, create bool) (int, string, error) {
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 || components[len(components)-1] == "" {
		return -1, "", fmt.Errorf("guest path has no file name")
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open guest root: %w", err)
	}
	parentFD := rootFD
	for _, component := range components[:len(components)-1] {
		childFD, openErr := unix.Openat(parentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(parentFD, component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(parentFD)
				return -1, "", fmt.Errorf("create guest destination directory: %w", mkdirErr)
			}
			childFD, openErr = unix.Openat(parentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = unix.Close(parentFD)
			return -1, "", fmt.Errorf("resolve guest path component %q: %w", component, openErr)
		}
		_ = unix.Close(parentFD)
		parentFD = childFD
	}
	return parentFD, components[len(components)-1], nil
}

func cleanGuestPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return "", fmt.Errorf("guest path must be a clean absolute file path")
	}
	return path, nil
}

func guestEnvironment(overrides []string) []string {
	values := map[string]string{"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/sandbox", "USER": "sandbox"}
	for _, entry := range overrides {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key != "" {
			values[key] = value
		}
	}
	out := make([]string, 0, len(values))
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

func guestEnvironmentForWorkload(overrides []string, proxyURL string) []string {
	values := map[string]string{
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME": "/sandbox",
		"USER": "sandbox",
	}
	for _, entry := range overrides {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" || strings.HasPrefix(key, "QUARSHELL_VM_") || isGuestIdentityEnvironment(key) {
			continue
		}
		values[key] = value
	}
	if proxyURL != "" {
		for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
			values[key] = proxyURL
		}
		values["NO_PROXY"] = "localhost,127.0.0.1,::1"
		values["no_proxy"] = values["NO_PROXY"]
	}
	out := make([]string, 0, len(values))
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

func isGuestIdentityEnvironment(key string) bool {
	switch key {
	case "OPENSHELL_OCI_IMAGE_USER", "OPENSHELL_SANDBOX_UID", "OPENSHELL_SANDBOX_GID":
		return true
	default:
		return false
	}
}

func guestWorkloadCredential(declaration string, defaultUID, defaultGID uint32) (*syscall.Credential, error) {
	if declaration == "" {
		if defaultUID == uint32(os.Geteuid()) && defaultGID == uint32(os.Getegid()) {
			return nil, nil
		}
		return &syscall.Credential{Uid: defaultUID, Gid: defaultGID}, nil
	}
	parts := strings.Split(declaration, ":")
	if len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
		return nil, fmt.Errorf("OCI user declaration is malformed")
	}
	for _, part := range parts {
		if strings.TrimSpace(part) != part || strings.IndexByte(part, 0) >= 0 || strings.ContainsAny(part, "\r\n") {
			return nil, fmt.Errorf("OCI user declaration is malformed")
		}
		for _, char := range part {
			if char < 0x21 || char == 0x7f || char == ':' {
				return nil, fmt.Errorf("OCI user declaration is malformed")
			}
		}
	}
	uid, resolvedUser, err := resolveGuestUID(parts[0])
	if err != nil {
		return nil, err
	}
	if uid == 0 {
		return nil, fmt.Errorf("OCI user resolves to prohibited root identity")
	}
	gid := uid
	if resolvedUser != nil {
		gid, err = parseGuestID(resolvedUser.Gid)
		if err != nil {
			return nil, fmt.Errorf("OCI user primary group: %w", err)
		}
	}
	if len(parts) == 2 {
		gid, err = resolveGuestGID(parts[1])
		if err != nil {
			return nil, err
		}
	}
	if gid == 0 {
		return nil, fmt.Errorf("OCI group resolves to prohibited root identity")
	}
	groups := make([]uint32, 0)
	if resolvedUser != nil {
		groupIDs, lookupErr := resolvedUser.GroupIds()
		if lookupErr != nil {
			return nil, fmt.Errorf("OCI user supplementary groups: %w", lookupErr)
		}
		for _, raw := range groupIDs {
			groupID, parseErr := parseGuestID(raw)
			if parseErr != nil || groupID == 0 {
				return nil, fmt.Errorf("OCI user has an invalid or prohibited supplementary group")
			}
			groups = append(groups, groupID)
		}
	}
	// Avoid a privileged setuid/setgid transition when the guest agent already
	// runs as the requested identity. This is the same effective workload
	// identity and supports unprivileged environments where re-applying the
	// current IDs is denied by the host.
	if uid == uint32(os.Geteuid()) && gid == uint32(os.Getegid()) && len(groups) == 0 {
		return nil, nil
	}
	return &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}, nil
}

func resolveGuestUID(value string) (uint32, *userdb.User, error) {
	if numeric, err := strconv.ParseUint(value, 10, 32); err == nil {
		if numeric >= uint64(^uint32(0)) {
			return 0, nil, fmt.Errorf("OCI user UID is outside the supported range")
		}
		if numeric == 0 {
			return 0, nil, nil
		}
		resolved, lookupErr := userdb.LookupId(strconv.FormatUint(numeric, 10))
		if lookupErr != nil {
			return uint32(numeric), nil, nil
		}
		return uint32(numeric), resolved, nil
	}
	resolved, err := userdb.Lookup(value)
	if err != nil {
		return 0, nil, fmt.Errorf("OCI user %q cannot be resolved: %w", value, err)
	}
	uid, err := parseGuestID(resolved.Uid)
	if err != nil {
		return 0, nil, fmt.Errorf("OCI user %q has an invalid UID", value)
	}
	return uid, resolved, nil
}

func resolveGuestGID(value string) (uint32, error) {
	if numeric, err := parseGuestID(value); err == nil {
		return numeric, nil
	}
	resolved, err := userdb.LookupGroup(value)
	if err != nil {
		return 0, fmt.Errorf("OCI group %q cannot be resolved: %w", value, err)
	}
	gid, err := parseGuestID(resolved.Gid)
	if err != nil {
		return 0, fmt.Errorf("OCI group %q has an invalid GID", value)
	}
	return gid, nil
}

func parseGuestID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 || parsed >= uint64(^uint32(0)) {
		return 0, fmt.Errorf("identity %q is outside the supported non-root range", value)
	}
	return uint32(parsed), nil
}

func mergeGuestEnvironment(environment []string, overrides ...string) []string {
	values := make(map[string]string, len(environment)+len(overrides))
	for _, entry := range append(append([]string(nil), environment...), overrides...) {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key != "" {
			values[key] = value
		}
	}
	out := make([]string, 0, len(values))
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

func guestWorkloadCommand(argv []string, supervised bool) []string {
	result := append([]string(nil), argv...)
	if !supervised {
		return result
	}
	return append([]string{guestSupervisorBinary, "--", guestInitBinary, "--policy", guestPolicyFile, "--"}, result...)
}

func guestExecCommand(argv []string, supervised bool) []string {
	result := append([]string(nil), argv...)
	if !supervised {
		return result
	}
	return append([]string{guestInitBinary, "--policy", guestPolicyFile, "--"}, result...)
}

func guestShellCommand(argv []string, noLoginShell bool) ([]string, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("exec argv is empty")
	}
	shell := ""
	for _, candidate := range []string{"/bin/bash", "/usr/bin/bash", "/bin/sh"} {
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			shell = candidate
			break
		}
	}
	if shell == "" {
		return nil, fmt.Errorf("sandbox image does not provide an executable shell at /bin/bash, /usr/bin/bash, or /bin/sh")
	}
	return guestShellCommandWithPath(shell, argv, noLoginShell), nil
}

func guestShellCommandWithPath(shell string, argv []string, noLoginShell bool) []string {
	mode := "-lc"
	if noLoginShell {
		mode = "-c"
	}
	quoted := make([]string, len(argv))
	for index, arg := range argv {
		quoted[index] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
	}
	return []string{shell, mode, strings.Join(quoted, " ")}
}

func guestWorkdir(path string) string {
	if path == "" {
		return "/sandbox"
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "/sandbox"
	}
	return path
}

func writeResponse(writer io.Writer, response Response) error {
	if response.Version == 0 {
		response.Version = ProtocolVersion
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	return WriteFrame(writer, encoded)
}
