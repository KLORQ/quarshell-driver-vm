//go:build darwin || linux

package vm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-driver/driver"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	liveGatewayID     = "openshell"
	liveSessionKeyID  = "vm-live-acceptance"
	liveGatewayJWTTyp = "openshell-gateway-session+jwt"
	liveSandboxJWTTyp = "openshell-sandbox-session+jwt"
)

type liveSessionJWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type liveSessionJWTClaims struct {
	Issuer            string `json:"iss"`
	Subject           string `json:"sub"`
	Audience          string `json:"aud"`
	IssuedAt          int64  `json:"iat"`
	ExpiresAt         int64  `json:"exp"`
	TokenID           string `json:"jti"`
	SandboxID         string `json:"sandbox_id"`
	RuntimeGeneration string `json:"runtime_generation"`
	AuthEpoch         uint64 `json:"auth_epoch"`
	Component         string `json:"component"`
}

type liveGatewayRPC struct {
	gatewayv1.UnimplementedOpenShellServer
	wantGatewayToken string
	wantSandboxToken string
	hello            chan *gatewayv1.SupervisorHello
	policy           chan uint32
	logs             chan *gatewayv1.SandboxLogLine
	mu               sync.Mutex
	streamErr        error
}

func newLiveGatewayRPC(gatewayToken, sandboxToken string) *liveGatewayRPC {
	return &liveGatewayRPC{
		wantGatewayToken: gatewayToken,
		wantSandboxToken: sandboxToken,
		hello:            make(chan *gatewayv1.SupervisorHello, 8),
		policy:           make(chan uint32, 8),
		logs:             make(chan *gatewayv1.SandboxLogLine, 32),
	}
}

func (s *liveGatewayRPC) ConnectSupervisor(stream gatewayv1.OpenShell_ConnectSupervisorServer) error {
	if got := bearerFromGRPC(stream.Context()); got != s.wantSandboxToken {
		s.setStreamErr(fmt.Errorf("ConnectSupervisor used Sandbox bearer %q, want paired Sandbox bearer", redactForTest(got)))
		return fmt.Errorf("ConnectSupervisor used the wrong bearer")
	}
	first, err := stream.Recv()
	if err != nil {
		s.setStreamErr(fmt.Errorf("receive supervisor hello: %w", err))
		return err
	}
	hello := first.GetHello()
	if hello == nil || hello.GetSandboxId() == "" || hello.GetInstanceId() == "" || hello.GetConnectionEpoch() == 0 {
		s.setStreamErr(fmt.Errorf("supervisor sent an invalid hello"))
		return fmt.Errorf("invalid supervisor hello")
	}
	s.hello <- hello
	if err := stream.Send(&gatewayv1.GatewayMessage{Payload: &gatewayv1.GatewayMessage_SessionAccepted{
		SessionAccepted: &gatewayv1.SessionAccepted{HeartbeatInterval: durationpb.New(time.Minute)},
	}}); err != nil {
		s.setStreamErr(fmt.Errorf("accept supervisor session: %w", err))
		return err
	}
	for {
		if _, err := stream.Recv(); err != nil {
			if err != io.EOF && stream.Context().Err() == nil {
				s.setStreamErr(err)
			}
			return err
		}
	}
}

func (s *liveGatewayRPC) ReportPolicyStatus(ctx context.Context, request *gatewayv1.ReportPolicyStatusRequest) (*gatewayv1.ReportPolicyStatusResponse, error) {
	if got := bearerFromGRPC(ctx); got != s.wantSandboxToken {
		return nil, fmt.Errorf("ReportPolicyStatus used the wrong paired Sandbox bearer")
	}
	select {
	case s.policy <- request.GetVersion():
	default:
	}
	return &gatewayv1.ReportPolicyStatusResponse{}, nil
}

func (s *liveGatewayRPC) GetSandbox(_ context.Context, request *gatewayv1.GetSandboxRequest) (*gatewayv1.SandboxResponse, error) {
	return &gatewayv1.SandboxResponse{Sandbox: &gatewayv1.Sandbox{Metadata: &datamodelv1.ObjectMeta{Id: request.GetName(), Name: request.GetName()}}}, nil
}

func (s *liveGatewayRPC) GetSandboxProviderEnvironment(_ context.Context, _ *gatewayv1.GetSandboxProviderEnvironmentRequest) (*gatewayv1.GetSandboxProviderEnvironmentResponse, error) {
	return &gatewayv1.GetSandboxProviderEnvironmentResponse{Environment: map[string]string{}}, nil
}

func (s *liveGatewayRPC) PushSandboxLogs(stream gatewayv1.OpenShell_PushSandboxLogsServer) error {
	if got := bearerFromGRPC(stream.Context()); got != s.wantSandboxToken {
		return fmt.Errorf("PushSandboxLogs used the wrong paired Sandbox bearer")
	}
	for {
		request, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&gatewayv1.PushSandboxLogsResponse{})
		}
		if err != nil {
			return err
		}
		if request.GetSandboxId() == "" {
			return fmt.Errorf("PushSandboxLogs omitted sandbox identity")
		}
		for _, line := range request.GetLogs() {
			select {
			case s.logs <- line:
			default:
			}
		}
	}
}

func (s *liveGatewayRPC) setStreamErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streamErr == nil {
		s.streamErr = err
	}
}

func (s *liveGatewayRPC) firstStreamErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streamErr
}

func bearerFromGRPC(ctx context.Context) string {
	values, _ := metadata.FromIncomingContext(ctx)
	for _, value := range values.Get("authorization") {
		if bearer, ok := strings.CutPrefix(value, "Bearer "); ok {
			return bearer
		}
	}
	return ""
}

func redactForTest(token string) string {
	if token == "" {
		return ""
	}
	return "<redacted>"
}

func newLiveSessionID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

func issueLiveSessionJWT(t *testing.T, privateKey ed25519.PrivateKey, typ, audience, sandboxID, generation, tokenID string, issuedAt, expiresAt time.Time) string {
	t.Helper()
	header, err := json.Marshal(liveSessionJWTHeader{Algorithm: "EdDSA", Type: typ, KeyID: liveSessionKeyID})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(liveSessionJWTClaims{
		Issuer: "openshell-gateway:" + liveGatewayID, Subject: "spiffe://openshell/sandbox/" + sandboxID,
		Audience: audience, IssuedAt: issuedAt.Unix(), ExpiresAt: expiresAt.Unix(), TokenID: tokenID,
		SandboxID: sandboxID, RuntimeGeneration: generation, AuthEpoch: 1, Component: "openshell-supervisor",
	})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(unsigned)))
}

func liveGatewayCredentials(t *testing.T, sandboxID string) (driver.RuntimeLaunchCredentials, string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	verificationKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(10 * time.Minute)
	generation := "g0000000000000001"
	gatewayToken := issueLiveSessionJWT(t, privateKey, liveGatewayJWTTyp, "openshell-gateway:"+liveGatewayID, sandboxID, generation, newLiveSessionID(t), now, expires)
	sandboxToken := issueLiveSessionJWT(t, privateKey, liveSandboxJWTTyp, "openshell-sandbox", sandboxID, generation, newLiveSessionID(t), now, expires)
	credentials := driver.RuntimeLaunchCredentials{
		SandboxID: sandboxID, RuntimeGeneration: generation, SessionID: newLiveSessionID(t), GatewayID: liveGatewayID,
		VerificationKeys: []driver.RuntimeVerificationKey{{KeyID: liveSessionKeyID, PublicKeyPEM: verificationKey}},
		GatewayToken:     gatewayToken, GatewayExpiresAt: expires, SandboxToken: sandboxToken,
		SandboxExpiresAt: expires, CredentialEpoch: 1, SessionRotation: 1,
	}
	return credentials, gatewayToken, sandboxToken
}

func assertLiveGatewayCredentialLaunch(t *testing.T, ctx context.Context, host HostConfig, rootfsTar, initBin, supervisorBin, sshBin, proxyBinary, policyPath string) {
	t.Helper()
	initialPolicy := []byte("# quarshell-policy-revision: 1\nversion: 1\nlandlock:\n  compatibility: best_effort\nprocess:\n  run_as_user: '1000'\n  run_as_group: '1000'\nnetwork_policies: {}\n")
	if err := os.WriteFile(policyPath, initialPolicy, 0o600); err != nil {
		t.Fatalf("write initial paired-credential policy: %v", err)
	}
	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer grpcListener.Close()
	// Use a small independent HTTP endpoint for the proxy's optional secret
	// lookup. The supervisor control session uses the gRPC listener below.
	httpGateway := httptest.NewServer(http.NotFoundHandler())
	defer httpGateway.Close()
	grpcServer := grpc.NewServer()
	defer grpcServer.Stop()
	server := newLiveGatewayRPC("", "")
	gatewayv1.RegisterOpenShellServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(grpcListener) }()

	stateDir := filepath.Join(host.StateDir, "gateway-credential-acceptance")
	host.StateDir = stateDir
	driverConfig, err := json.Marshal(SandboxDriverConfig{RootfsTarPath: rootfsTar, GRPCEndpoint: grpcListener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	proxyEnv := []string{}
	d := NewWithHostConfig(host)
	sandbox, err := d.createSandbox(ctx, vmCreateSpec{
		Name: "live-vm-paired-credentials", Image: "alpine:3.22", DriverConfigJSON: string(driverConfig),
		GatewayURL: httpGateway.URL, Labels: liveGuestInitExtensionLabels(), Command: []string{"/bin/sh", "-c", "printf '%s:%s\\n' \"$(id -u)\" \"$(id -g)\" > /sandbox/gateway-auth-started; while :; do sleep 1; done"},
		ProxyBin: proxyBinary, PolicyPath: policyPath, ProxyEnv: proxyEnv,
		InitBin: initBin, SupervisorBin: supervisorBin, EnableSSH: true, SSHBin: sshBin,
	})
	if err != nil {
		t.Fatalf("create VM for paired Gateway credentials: %v", err)
	}
	registerLiveSandboxCleanup(t, host, sandbox.ID)
	credentials, gatewayToken, sandboxToken := liveGatewayCredentials(t, string(sandbox.ID))
	server.wantGatewayToken, server.wantSandboxToken = gatewayToken, sandboxToken
	launchCtx, launchCancel := context.WithTimeout(ctx, 60*time.Second)
	defer launchCancel()
	if err := d.StartWithCredentials(launchCtx, sandbox.ID, credentials); err != nil {
		var logs strings.Builder
		_ = d.Logs(context.Background(), sandbox.ID, false, &logs)
		t.Fatalf("start VM with signed paired Gateway credentials: %v; logs: %s", err, logs.String())
	}
	helloDeadline := time.NewTimer(20 * time.Second)
	defer helloDeadline.Stop()
	select {
	case hello := <-server.hello:
		if hello.GetSandboxId() != string(sandbox.ID) {
			t.Fatalf("Gateway supervisor hello sandbox=%q, want %q", hello.GetSandboxId(), sandbox.ID)
		}
	case <-helloDeadline.C:
		t.Fatalf("waiting for signed Sandbox bearer to establish Gateway supervisor relay: %v", server.firstStreamErr())
	case <-ctx.Done():
		t.Fatalf("waiting for signed Sandbox bearer to establish Gateway supervisor relay: %v", ctx.Err())
	}
	// Check the initial report, then force a distinct revision so this
	// acceptance proves both credential routing and the live policy path.
	select {
	case revision := <-server.policy:
		if revision != 1 {
			t.Fatalf("initial policy revision=%d, want 1", revision)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("production proxy did not report the initial policy with the Sandbox bearer")
	}
	if err := os.WriteFile(policyPath, []byte("# quarshell-policy-revision: 2\nversion: 1\nlandlock:\n  compatibility: best_effort\nprocess:\n  run_as_user: '1000'\n  run_as_group: '1000'\nnetwork_policies:\n  credential-acceptance:\n    endpoints:\n      - host: acceptance.invalid\n        port: 80\n"), 0o600); err != nil {
		t.Fatalf("write paired-credential policy update: %v", err)
	}
	t.Log("live Gateway accepted supervisor session with the Sandbox bearer")
	policyDeadline := time.NewTimer(20 * time.Second)
	defer policyDeadline.Stop()
	for {
		select {
		case revision := <-server.policy:
			if revision == 2 {
				goto policyAcknowledged
			}
		case <-policyDeadline.C:
			t.Fatal("production proxy did not report policy revision 2 using the Sandbox bearer")
		case <-ctx.Done():
			t.Fatalf("waiting for policy revision acknowledgement: %v", ctx.Err())
		}
	}

policyAcknowledged:
	t.Log("live Gateway acknowledged policy revision 2 with the Sandbox bearer")
	execCtx, execCancel := context.WithTimeout(ctx, 20*time.Second)
	defer execCancel()
	result, err := d.Exec(execCtx, sandbox.ID, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", "test -s /sandbox/gateway-auth-started"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("paired-credential VM workload did not start behind the guest gate: result=%+v err=%v", result, err)
	}
	logDeadline := time.NewTimer(10 * time.Second)
	defer logDeadline.Stop()
	for {
		select {
		case line := <-server.logs:
			if strings.Contains(line.GetMessage(), "PROC:LAUNCH") {
				t.Log("live Gateway accepted the Sandbox bearer and received a supervisor process event")
				goto processEventReceived
			}
		case <-logDeadline.C:
			t.Fatal("production supervisor did not deliver its process event through PushSandboxLogs")
		case <-ctx.Done():
			t.Fatalf("waiting for supervisor process event: %v", ctx.Err())
		}
	}

processEventReceived:
	if streamErr := server.firstStreamErr(); streamErr != nil {
		t.Fatalf("signed Gateway supervisor relay: %v", streamErr)
	}
	if err := d.Stop(ctx, sandbox.ID); err != nil {
		t.Fatalf("stop paired-credential VM: %v", err)
	}
}

var _ gatewayv1.OpenShellServer = (*liveGatewayRPC)(nil)
