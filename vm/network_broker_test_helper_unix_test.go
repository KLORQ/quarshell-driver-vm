//go:build darwin || linux

package vm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/engine"
	"github.com/KLORQ/quarshell-core/policy"
	"github.com/KLORQ/quarshell-proxy/proxy"
)

// supervisorControlTestProtocol must track quarshell-runtime/supervisorcontrol.VMControlProtocol.
// Keep the fixture independent of the runtime module dependency graph.
const supervisorControlTestProtocol uint32 = 2

func TestMain(m *testing.M) {
	if os.Getenv("CAUTEM_VM_TEST_BROKER_LOSS_HELPER") == "1" {
		os.Exit(runNetworkBrokerLossTestHelper())
	}
	if os.Getenv("CAUTEM_VM_TEST_POLICY_PROXY_HELPER") == "1" {
		os.Exit(runPolicyProxyTestHelper(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runNetworkBrokerLossTestHelper() int {
	pidFile := os.Getenv("CAUTEM_VM_TEST_BROKER_PID_FILE")
	if pidFile == "" {
		return 2
	}
	command := exec.Command("sleep", "60")
	if err := command.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	process := &networkBrokerProcess{command: command, done: make(chan struct{})}
	go func() {
		process.mu.Lock()
		process.err = command.Wait()
		process.mu.Unlock()
		close(process.done)
	}()
	defer func() {
		select {
		case <-process.done:
		default:
			_ = command.Process.Kill()
			<-process.done
		}
	}()
	identity := fmt.Sprintf("%d %d %d", command.Process.Pid, os.Getpid(), syscall.Getpgrp())
	if err := os.WriteFile(pidFile, []byte(identity), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// The go test binary installs signal handlers; restore the worker's default
	// SIGTERM behavior before exercising the worker process group.
	signal.Reset(syscall.SIGTERM)
	worker, err := os.FindProcess(os.Getpid())
	if err != nil {
		return 1
	}
	watchHostNetworkBroker(process, &exec.Cmd{Process: worker})
	select {}
}

func TestWatchNetworkBrokerStopsWorkerProcessGroupOnBrokerLoss(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "broker.pid")
	helper := exec.Command(os.Args[0], "-test.run=^$")
	helper.Env = append(os.Environ(),
		"CAUTEM_VM_TEST_BROKER_LOSS_HELPER=1",
		"CAUTEM_VM_TEST_BROKER_PID_FILE="+pidFile,
	)
	helper.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var stderr bytes.Buffer
	helper.Stderr = &stderr
	if err := helper.Start(); err != nil {
		t.Fatalf("start isolated VM worker helper: %v", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- helper.Wait() }()
	helperExited := false
	defer func() {
		if !helperExited {
			_ = syscall.Kill(-helper.Process.Pid, syscall.SIGKILL)
			<-waited
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	var brokerPID int
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) != 3 {
				t.Fatalf("invalid worker/broker process identity %q", data)
			}
			brokerPID, err = strconv.Atoi(fields[0])
			helperPID, helperPIDErr := strconv.Atoi(fields[1])
			groupID, groupErr := strconv.Atoi(fields[2])
			if err != nil || helperPIDErr != nil || groupErr != nil || brokerPID <= 0 {
				t.Fatalf("invalid broker helper PID %q: %v", data, err)
			}
			if helperPID != helper.Process.Pid || groupID != helper.Process.Pid {
				t.Fatalf("worker process identity = pid %d, process group %d; helper pid %d", helperPID, groupID, helper.Process.Pid)
			}
			break
		}
		select {
		case err := <-waited:
			helperExited = true
			t.Fatalf("worker helper exited before starting broker: %v stderr=%q", err, stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if brokerPID == 0 {
		t.Fatalf("worker helper did not publish broker PID: stderr=%q", stderr.String())
	}
	broker, err := os.FindProcess(brokerPID)
	if err != nil {
		t.Fatalf("find broker helper process: %v", err)
	}
	if err := broker.Kill(); err != nil {
		t.Fatalf("kill policy broker helper: %v", err)
	}
	select {
	case err := <-waited:
		helperExited = true
		if err == nil {
			t.Fatal("worker helper exited successfully after broker loss")
		}
		status, ok := helper.ProcessState.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
			t.Fatalf("worker helper exit after broker loss = %v (status=%v), want SIGTERM; stderr=%q", err, helper.ProcessState, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker process group did not stop after policy broker loss")
	}
}

func runPolicyProxyTestHelper(args []string) int {
	var socket, policyPath string
	for index := 0; index+1 < len(args); index++ {
		switch args[index] {
		case "--listen":
			if strings.HasPrefix(args[index+1], "unix://") {
				socket = strings.TrimPrefix(args[index+1], "unix://")
			}
		case "--policy":
			policyPath = args[index+1]
		}
	}
	if socket == "" || policyPath == "" {
		fmt.Fprintln(os.Stderr, "VM policy proxy test helper requires a Unix socket listener and policy file")
		return 2
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socket)
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.Remove(socket) }()
	document, err := policy.Load(policyPath)
	if err != nil {
		_ = listener.Close()
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := document.Validate(); err != nil {
		_ = listener.Close()
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var allowlist engine.Allowlist
	if err := allowlist.Apply(document); err != nil {
		_ = listener.Close()
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	server := proxy.NewServer(&allowlist, os.Stderr)
	if pidFile := os.Getenv("CAUTEM_VM_TEST_BROKER_PID_FILE"); pidFile != "" {
		if !filepath.IsAbs(pidFile) || filepath.Clean(pidFile) != pidFile {
			_ = listener.Close()
			fmt.Fprintln(os.Stderr, "VM policy proxy test broker PID path must be a clean absolute path")
			return 1
		}
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			_ = listener.Close()
			fmt.Fprintf(os.Stderr, "publish VM policy proxy test broker PID: %v\n", err)
			return 1
		}
	}
	var controlServer net.Listener
	controlPath := os.Getenv("CAUTEM_SUPERVISOR_CONTROL_SOCKET")
	if controlPath != "" {
		controlTLS, err := testSupervisorControlTLSConfig()
		if err != nil {
			_ = listener.Close()
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		controlServer, err = net.Listen("unix", controlPath)
		if err != nil {
			_ = listener.Close()
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer func() { _ = os.Remove(controlPath) }()
		if err := os.Chmod(controlPath, 0o600); err != nil {
			_ = controlServer.Close()
			_ = listener.Close()
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		go serveSupervisorControlTestHelper(controlServer, os.Getenv("CAUTEM_VM_TEST_CONTROL_EVENTS"), os.Getenv("CAUTEM_SUPERVISOR_CONTROL_EXPECTED_CLIENT_IDENTITY"), controlTLS)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	if ackPath := os.Getenv("CAUTEM_VM_TEST_POLICY_ACK_FILE"); ackPath != "" {
		if !filepath.IsAbs(ackPath) || filepath.Clean(ackPath) != ackPath {
			_ = listener.Close()
			fmt.Fprintln(os.Stderr, "VM policy proxy test acknowledgement path must be a clean absolute path")
			return 1
		}
		server.ReportPolicyStatus = func(_ context.Context, revision uint32, loadError string) error {
			status := "loaded"
			if loadError != "" {
				status = "failed"
			}
			return os.WriteFile(ackPath, []byte(fmt.Sprintf("%d %s\n", revision, status)), 0o600)
		}
		go server.WatchPolicy(ctx, policyPath, 25*time.Millisecond)
	}
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- server.Serve(ctx, listener) }()
	go func() {
		<-ctx.Done()
		if controlServer != nil {
			_ = controlServer.Close()
		}
	}()
	err = <-proxyDone
	if err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func TestNetworkBrokerTestHelperEnforcesDefaultDeny(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "vmp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nnetwork_policies: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "proxy.sock")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^$")
	command.Args = append(command.Args, "proxy", "--listen", "unix://"+socket, "--policy", policyPath)
	command.Env = append(os.Environ(), "CAUTEM_VM_TEST_POLICY_PROXY_HELPER=1")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start actual policy proxy helper: %v", err)
	}
	defer func() {
		if command.Process == nil {
			return
		}
		_ = command.Process.Signal(syscall.SIGTERM)
		waited := make(chan struct{})
		go func() { _ = command.Wait(); close(waited) }()
		select {
		case <-waited:
		case <-time.After(2 * time.Second):
			_ = command.Process.Kill()
			<-waited
		}
	}()
	if err := waitForProxySocket(ctx, socket); err != nil {
		t.Fatalf("%v; helper stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		t.Fatalf("connect to actual policy proxy: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(connection, "GET http://policy-probe.invalid/ HTTP/1.1\r\nHost: policy-probe.invalid\r\nConnection: close\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read default-deny response from actual policy proxy: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "quarshell-proxy: denied") {
		t.Fatalf("actual proxy default-deny response = status %d body=%q readErr=%v", response.StatusCode, body, readErr)
	}
}

func waitForProxySocket(ctx context.Context, socket string) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := checkNetworkBrokerHealth(ctx, socket); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("policy proxy helper did not become ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

type supervisorControlTestRequest struct {
	Operation  string `json:"operation"`
	InstanceID string `json:"instance_id,omitempty"`
	ExitCode   int32  `json:"exit_code,omitempty"`
	Peer       *struct {
		Identity string `json:"identity"`
		Protocol uint32 `json:"protocol"`
		Nonce    string `json:"nonce"`
		IssuedAt int64  `json:"issued_at_ms"`
	} `json:"peer,omitempty"`
}

type supervisorControlTestResponse struct {
	InstanceID string `json:"instance_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

func TestSupervisorControlTestHelperAcceptsCurrentProtocol(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	eventsPath := filepath.Join(t.TempDir(), "events.log")
	go serveSupervisorControlTestHelper(listener, eventsPath, "test-vm-identity")

	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	request := map[string]any{
		"operation": "begin",
		"peer": map[string]any{
			"identity": "test-vm-identity", "protocol": supervisorControlTestProtocol,
			"nonce": strings.Repeat("a", 32), "issued_at_ms": time.Now().UnixMilli(),
		},
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response supervisorControlTestResponse
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error != "" || response.InstanceID != "live-vm-instance" {
		t.Fatalf("current control protocol response = %+v", response)
	}
	if events, err := os.ReadFile(eventsPath); err != nil || string(events) != "begin\n" {
		t.Fatalf("control events = %q, err=%v", events, err)
	}
}

func testSupervisorControlTLSConfig() (*tls.Config, error) {
	caPEM, err := os.ReadFile(os.Getenv("CAUTEM_SUPERVISOR_CONTROL_SERVER_CA"))
	if err != nil {
		return nil, fmt.Errorf("read test VM control CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("test VM control CA contains no certificates")
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv("CAUTEM_SUPERVISOR_CONTROL_SERVER_CERT"), os.Getenv("CAUTEM_SUPERVISOR_CONTROL_SERVER_KEY"))
	if err != nil {
		return nil, fmt.Errorf("load test VM control server identity: %w", err)
	}
	expected := os.Getenv("CAUTEM_SUPERVISOR_CONTROL_EXPECTED_CLIENT_IDENTITY")
	if expected == "" {
		return nil, fmt.Errorf("test VM control expected identity is missing")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("VM client certificate is missing")
		}
		for _, uri := range state.PeerCertificates[0].URIs {
			if uri.String() == expected {
				return nil
			}
		}
		return fmt.Errorf("VM client identity does not match")
	}}, nil
}

func serveSupervisorControlTestHelper(listener net.Listener, eventPath, expectedIdentity string, tlsConfigs ...*tls.Config) {
	var seen sync.Map
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		writeSupervisorControlDiagnostic("accepted")
		go func() {
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
			var transport net.Conn = connection
			if len(tlsConfigs) > 0 && tlsConfigs[0] != nil {
				counted := &supervisorControlCountingConn{Conn: connection}
				tlsConnection := tls.Server(counted, tlsConfigs[0])
				transport = tlsConnection
				writeSupervisorControlDiagnostic("tls-handshake-started")
				if handshakeErr := tlsConnection.Handshake(); handshakeErr != nil {
					writeSupervisorControlDiagnostic(fmt.Sprintf("tls-handshake-failed: %v (server-read=%d server-written=%d)", handshakeErr, counted.readBytes, counted.writtenBytes))
					if handshakeErr != io.EOF {
						fmt.Fprintf(os.Stderr, "supervisor control test TLS handshake failed: %v\n", handshakeErr)
					}
					return
				}
				writeSupervisorControlDiagnostic(fmt.Sprintf("tls-handshake-completed (server-read=%d server-written=%d)", counted.readBytes, counted.writtenBytes))
			}
			line, err := bufio.NewReader(io.LimitReader(transport, 8<<10)).ReadBytes('\n')
			if err != nil {
				_ = json.NewEncoder(transport).Encode(supervisorControlTestResponse{Error: "invalid supervisor control request"})
				return
			}
			var request supervisorControlTestRequest
			if err := json.Unmarshal(line, &request); err != nil || request.Operation == "" || request.Peer == nil || request.Peer.Identity != expectedIdentity || request.Peer.Protocol != supervisorControlTestProtocol || request.Peer.IssuedAt < time.Now().Add(-time.Minute).UnixMilli() || request.Peer.IssuedAt > time.Now().Add(time.Minute).UnixMilli() {
				_ = json.NewEncoder(transport).Encode(supervisorControlTestResponse{Error: "invalid supervisor control request"})
				return
			}
			nonce, nonceErr := hex.DecodeString(request.Peer.Nonce)
			if nonceErr != nil || len(nonce) != 16 || strings.ToLower(request.Peer.Nonce) != request.Peer.Nonce {
				_ = json.NewEncoder(transport).Encode(supervisorControlTestResponse{Error: "invalid supervisor control nonce"})
				return
			}
			if _, loaded := seen.LoadOrStore(request.Peer.Nonce, struct{}{}); loaded {
				_ = json.NewEncoder(transport).Encode(supervisorControlTestResponse{Error: "replayed supervisor control request"})
				return
			}
			if eventPath != "" {
				file, openErr := os.OpenFile(eventPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
				if openErr == nil {
					_, _ = fmt.Fprintln(file, request.Operation)
					_ = file.Close()
				}
			}
			if detailsPath := os.Getenv("CAUTEM_VM_TEST_CONTROL_DETAILS"); detailsPath != "" {
				if data, marshalErr := json.Marshal(request); marshalErr == nil {
					if file, openErr := os.OpenFile(detailsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); openErr == nil {
						_, _ = file.Write(append(data, '\n'))
						_ = file.Close()
					}
				}
			}
			response := supervisorControlTestResponse{}
			if request.Operation == "begin" {
				response.InstanceID = "live-vm-instance"
			}
			_ = json.NewEncoder(transport).Encode(response)
		}()
	}
}

type supervisorControlCountingConn struct {
	net.Conn
	readBytes    int64
	writtenBytes int64
}

func (connection *supervisorControlCountingConn) Read(payload []byte) (int, error) {
	n, err := connection.Conn.Read(payload)
	connection.readBytes += int64(n)
	return n, err
}

func (connection *supervisorControlCountingConn) Write(payload []byte) (int, error) {
	n, err := connection.Conn.Write(payload)
	connection.writtenBytes += int64(n)
	return n, err
}

func writeSupervisorControlDiagnostic(message string) {
	path := os.Getenv("CAUTEM_VM_TEST_CONTROL_DIAGNOSTICS")
	if path == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(file, message)
	_ = file.Close()
}
