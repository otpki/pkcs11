//go:build !windows

package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

const (
	mockDiagLoginCalls      = raw.CKM_VENDOR_DEFINED + 0x7f01
	mockDiagLogoutCalls     = raw.CKM_VENDOR_DEFINED + 0x7f02
	mockDiagMaxSessions     = raw.CKM_VENDOR_DEFINED + 0x7f03
	mockDiagOpenSessions    = raw.CKM_VENDOR_DEFINED + 0x7f04
	mockDiagSlowObjectReads = raw.CKM_VENDOR_DEFINED + 0x7f05
	mockSlowRandomLength    = 4093
)

type proxyTestVendor struct{ pkcs11.VendorBase }

func (proxyTestVendor) Definition() pkcs11.VendorDefinition {
	return pkcs11.VendorDefinition{
		ID:       pkcs11.AdapterFamily("internal-proxy-test"),
		Name:     "OTPKI proxy test module",
		Priority: 10_000,
		Source:   "internal native proxy fixture",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers: []string{"otpki test"},
		},
		Behavior: pkcs11.VendorBehavior{
			LoginScope:            pkcs11.VendorLoginToken,
			LockSessionToOSThread: true,
			RejectNullOutputProbe: true,
		},
	}
}

var testProxyVendor pkcs11.VendorModule = proxyTestVendor{}

type proxySessionLoginVendor struct{ pkcs11.VendorBase }

func (proxySessionLoginVendor) Definition() pkcs11.VendorDefinition {
	definition := proxyTestVendor{}.Definition()
	definition.ID = pkcs11.AdapterFamily("internal-proxy-session-login-test")
	definition.Name = "OTPKI proxy session-login test module"
	definition.Behavior.LoginScope = pkcs11.VendorLoginSession
	return definition
}

var testProxySessionVendor pkcs11.VendorModule = proxySessionLoginVendor{}

type proxyTestCodec struct{}

func (proxyTestCodec) ID() string      { return "test:proxy-codec" }
func (proxyTestCodec) Version() uint32 { return 1 }
func (proxyTestCodec) Encode(value any) ([]byte, bool, error) {
	text, ok := value.(proxyTestParameter)
	if !ok {
		return nil, false, nil
	}
	return []byte(text), true, nil
}

func (proxyTestCodec) Decode(payload []byte) (any, error) {
	return proxyTestParameter(string(payload)), nil
}

type proxyTestParameter string

type proxyCodecVendor struct{ pkcs11.VendorBase }

func (proxyCodecVendor) Definition() pkcs11.VendorDefinition {
	definition := proxyTestVendor{}.Definition()
	definition.ID = pkcs11.AdapterFamily("internal-proxy-codec-test")
	definition.Name = "OTPKI proxy codec test module"
	return definition
}

func (proxyCodecVendor) ProxyParameterCodecs() []ParameterCodec {
	return []ParameterCodec{proxyTestCodec{}}
}

func buildProxyMockModule(t *testing.T) string {
	t.Helper()
	return buildProxyMockModuleWithFlags(t)
}

func buildProxyMockModuleWithFlags(t *testing.T, extraFlags ...string) string {
	t.Helper()
	compiler := os.Getenv("CC")
	if compiler == "" {
		compiler = "cc"
	}
	if _, err := exec.LookPath(compiler); err != nil {
		t.Skipf("C compiler is unavailable: %v", err)
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve proxy test source path")
	}
	root := filepath.Dir(filepath.Dir(file))
	output := filepath.Join(t.TempDir(), "libotpki-pkcs11-proxy-mock.so")
	args := []string{
		"-std=c11", "-fPIC", "-shared", "-pthread",
		"-I", filepath.Join(root, "raw", "internal", "cryptoki"),
		filepath.Join(root, "internal", "testmodule", "mock.c"),
		"-o", output,
	}
	if runtime.GOOS == "darwin" {
		output = filepath.Join(t.TempDir(), "libotpki-pkcs11-proxy-mock.dylib")
		args = []string{
			"-std=c11", "-fPIC", "-dynamiclib", "-pthread",
			"-I", filepath.Join(root, "raw", "internal", "cryptoki"),
			filepath.Join(root, "internal", "testmodule", "mock.c"),
			"-o", output,
		}
	}
	args = append(extraFlags, args...)
	command := exec.Command(compiler, args...)
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile proxy mock module: %v\n%s", err, combined)
	}
	return output
}

type instrumentedListener struct {
	net.Listener
	accepted atomic.Int64
	dropNext atomic.Bool
}

func (listener *instrumentedListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	listener.accepted.Add(1)
	return &instrumentedConnection{
		Conn:       connection,
		dropWrites: listener.dropNext.CompareAndSwap(true, false),
	}, nil
}

type instrumentedConnection struct {
	net.Conn
	dropWrites bool
	dropped    atomic.Bool
}

func (connection *instrumentedConnection) Write(value []byte) (int, error) {
	if connection.dropWrites && connection.dropped.CompareAndSwap(false, true) {
		_ = connection.Close()
		return 0, io.ErrClosedPipe
	}
	return connection.Conn.Write(value)
}

func proxyTestTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "proxy-test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	issue := func(serial int64, commonName string, usages []x509.ExtKeyUsage) tls.Certificate {
		_, key, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		}
		if commonName == "proxy-server" {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, issueErr := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}

	serverCertificate := issue(2, "proxy-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCertificate := issue(3, "proxy-client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}, &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost",
		Certificates: []tls.Certificate{clientCertificate},
	}
}

type proxyHarness struct {
	server   *Server
	listener *instrumentedListener
	target   Target
	module   string
}

func newProxyHarness(t *testing.T, budget SessionBudget, mutate func(*TargetConfig)) *proxyHarness {
	t.Helper()
	module := buildProxyMockModule(t)
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &instrumentedListener{Listener: base}
	config := TargetConfig{
		ID:       "mock-hsm",
		Revision: "revision-1",
		Client: pkcs11.Config{
			Module:  pkcs11.LocalModule(module),
			Vendors: []pkcs11.VendorModule{testProxyVendor},
		},
		Sessions: budget,
		Login: LoginPolicy{
			PhysicalPIN: pkcs11.StaticPIN("1234"),
			Authenticate: func(_ context.Context, attempt LoginAttempt) error {
				if string(attempt.PIN) != "1234" {
					return raw.Error(raw.CKR_PIN_INCORRECT)
				}
				return nil
			},
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
	}
	if mutate != nil {
		mutate(&config)
	}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener:       listener,
		AllowInsecure:  true,
		MaxConnections: 512,
	}, config)
	if err != nil {
		_ = base.Close()
		t.Fatal(err)
	}
	serveContext, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveContext) }()
	t.Cleanup(func() {
		cancel()
		if err := server.Close(context.Background()); err != nil {
			t.Errorf("close proxy server: %v", err)
		}
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("serve proxy: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("proxy Serve did not stop")
		}
	})
	return &proxyHarness{
		server:   server,
		listener: listener,
		module:   module,
		target: Target{
			ConfigID: "db-config-1", Revision: config.Revision,
			Endpoints: []string{base.Addr().String()}, Route: config.ID,
			AllowInsecure: true, RequestTimeout: 5 * time.Second,
			MaxAttempts: 2, Vendors: slices.Clone(config.Client.Vendors),
		},
	}
}

func openRemoteRaw(t *testing.T, target Target) *Client {
	t.Helper()
	client, err := Open(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Initialize(); err != nil {
		client.Destroy()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Finalize()
		client.Destroy()
	})
	return client
}

func remoteSlot(t *testing.T, client *Client) raw.SlotID {
	t.Helper()
	slots, err := client.GetSlotList(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 1 {
		t.Fatalf("slot count = %d, want 1", len(slots))
	}
	return slots[0]
}

func openVirtualSession(t *testing.T, client *Client, slot raw.SlotID, readWrite bool) raw.SessionHandle {
	t.Helper()
	flags := raw.CKF_SERIAL_SESSION
	if readWrite {
		flags |= raw.CKF_RW_SESSION
	}
	session, err := client.OpenSession(slot, flags)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func diagnostic(t *testing.T, client *Client, slot raw.SlotID, mechanism uint) uint {
	t.Helper()
	info, err := client.GetMechanismInfo(slot, raw.MechanismType(mechanism))
	if err != nil {
		t.Fatalf("diagnostic mechanism 0x%x: %v", mechanism, err)
	}
	return info.MinKeySize
}

func TestServerMayStartWithoutTargetsAndPublishOneLater(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{Listener: listener, AllowInsecure: true})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	if got := server.TargetIDs(); len(got) != 0 {
		t.Fatalf("initial target IDs = %v, want none", got)
	}

	module := buildProxyMockModule(t)
	err = server.AddTarget(context.Background(), TargetConfig{
		ID: "late-target", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 3},
		Login: LoginPolicy{
			PhysicalPIN:      pkcs11.StaticPIN("1234"),
			Authenticate:     func(context.Context, LoginAttempt) error { return nil },
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := server.TargetIDs(); len(got) != 1 || got[0] != "late-target" {
		t.Fatalf("published target IDs = %v, want [late-target]", got)
	}
}

func TestListRoutesReturnsCatalog(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	// Publish a second route bound to another token selector on the same module.
	if err := harness.server.AddTarget(context.Background(), TargetConfig{
		ID: "mock-hsm-second", Revision: "revision-2",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(harness.module), Token: pkcs11.TokenSelector{Label: "OTPKI-MOCK"}, Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 3},
		Login: LoginPolicy{
			PhysicalPIN:      pkcs11.StaticPIN("1234"),
			Authenticate:     func(context.Context, LoginAttempt) error { return nil },
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
	}); err != nil {
		t.Fatal(err)
	}
	// A third route on a token without CKF_LOGIN_REQUIRED reports the flag as
	// false while the login-requiring tokens report it as true.
	noLoginModule := buildProxyMockModuleWithFlags(t, "-DMOCK_NO_LOGIN_REQUIRED=1")
	if err := harness.server.AddTarget(context.Background(), TargetConfig{
		ID: "mock-hsm-nologin", Revision: "revision-2",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(noLoginModule), Token: pkcs11.TokenSelector{Label: "OTPKI-MOCK"}, Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 3},
		Login: LoginPolicy{
			PhysicalPIN:      pkcs11.StaticPIN("1234"),
			Authenticate:     func(context.Context, LoginAttempt) error { return nil },
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Discovery is server-scoped: only transport fields are required — no
	// Route, Revision, or ConfigID.
	routes, err := ListRoutes(context.Background(), Target{
		Endpoints: harness.target.Endpoints, AllowInsecure: true, RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 || routes[0].ID != "mock-hsm" || routes[1].ID != "mock-hsm-nologin" || routes[2].ID != "mock-hsm-second" {
		t.Fatalf("catalog IDs = %+v", routes)
	}
	if routes[0].Revision != "revision-1" || routes[1].Revision != "revision-2" || routes[2].Revision != "revision-2" {
		t.Fatalf("catalog revisions = %+v", routes)
	}
	for _, route := range routes {
		if route.TokenLabel != "OTPKI-MOCK" || route.TokenSerial != "0000000000000001" || route.SlotID != 1 {
			t.Fatalf("route %q token metadata = %+v", route.ID, route)
		}
	}
	if !routes[0].LoginRequired || !routes[2].LoginRequired {
		t.Fatalf("login-required routes report LoginRequired=false: %+v", routes)
	}
	if routes[1].LoginRequired {
		t.Fatalf("token without CKF_LOGIN_REQUIRED reports LoginRequired=true: %+v", routes[1])
	}

	// A selected route still answers its own methods after catalog discovery.
	client := openRemoteRaw(t, harness.target)
	if slots, err := client.GetSlotList(true); err != nil || len(slots) != 1 {
		t.Fatalf("remote slot list = %v, %v", slots, err)
	}
}

func TestListRoutesHidesUnauthorizedRoutes(t *testing.T) {
	module := buildProxyMockModule(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var listingMu sync.Mutex
	var listingRequests []AuthorizationRequest
	server, err := NewServer(context.Background(), ServerConfig{
		Listener:      listener,
		AllowInsecure: true,
		Authorizer: func(_ context.Context, identity RequestIdentity) (string, error) {
			if len(identity.Auth) == 0 {
				return "", errors.New("missing workload identity")
			}
			return string(identity.Auth), nil
		},
	}, TargetConfig{
		ID: "restricted-hsm", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 3},
		Login: LoginPolicy{
			PhysicalPIN:      pkcs11.StaticPIN("1234"),
			Authenticate:     func(context.Context, LoginAttempt) error { return nil },
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
		Authorize: func(_ context.Context, request AuthorizationRequest) error {
			if request.Operation != AuthorizationOperationListRoutes {
				return nil
			}
			listingMu.Lock()
			listingRequests = append(listingRequests, request)
			listingMu.Unlock()
			return errors.New("route listing is not authorized for this workload")
		},
	}, TargetConfig{
		// A route without an Authorize callback lists for every authenticated
		// caller, even while a sibling route is hidden from them.
		ID: "open-hsm", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 3},
		Login: LoginPolicy{
			PhysicalPIN:      pkcs11.StaticPIN("1234"),
			Authenticate:     func(context.Context, LoginAttempt) error { return nil },
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveContext, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveContext) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close(context.Background())
		<-serveDone
	})

	listTarget := func(principal string) Target {
		return Target{
			Endpoints:     []string{listener.Addr().String()},
			AllowInsecure: true, SecurityContextID: principal,
			Auth:           func(context.Context) ([]byte, error) { return []byte(principal), nil },
			RequestTimeout: 5 * time.Second,
		}
	}
	for _, principal := range []string{"workload-a", "workload-b"} {
		routes, err := ListRoutes(context.Background(), listTarget(principal))
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 || routes[0].ID != "open-hsm" {
			t.Fatalf("ListRoutes for %q = %+v, want only open-hsm", principal, routes)
		}
	}

	// The operator's in-process view is unfiltered: both configured routes are
	// present even though neither caller could list restricted-hsm.
	catalog := server.RouteCatalog()
	if len(catalog) != 2 || catalog[0].ID != "open-hsm" || catalog[1].ID != "restricted-hsm" {
		t.Fatalf("RouteCatalog = %+v", catalog)
	}

	listingMu.Lock()
	captured := slices.Clone(listingRequests)
	listingMu.Unlock()
	if len(captured) != 2 {
		t.Fatalf("list-routes authorization calls = %+v, want 2", captured)
	}
	for i, request := range captured {
		principal := []string{"workload-a", "workload-b"}[i]
		switch {
		case request.Identity.Principal != principal:
			t.Errorf("listing request %d principal = %q, want %q", i, request.Identity.Principal, principal)
		case request.Target != "restricted-hsm" || request.Revision != "revision-1":
			t.Errorf("listing request %d target = %q revision %q", i, request.Target, request.Revision)
		case request.Operation != AuthorizationOperationListRoutes:
			t.Errorf("listing request %d operation = %q", i, request.Operation)
		case request.PhysicalActivation:
			t.Errorf("listing request %d physical activation = true", i)
		case request.ClientID == ([16]byte{}):
			t.Errorf("listing request %d client ID = zero", i)
		case len(request.Identity.Auth) != 0:
			t.Errorf("listing request %d exposed raw auth material", i)
		}
	}
}

func TestListRoutesRequiresTransportSecurity(t *testing.T) {
	if _, err := ListRoutes(context.Background(), Target{Endpoints: []string{"127.0.0.1:1"}}); err == nil {
		t.Fatal("ListRoutes without TLS or AllowInsecure succeeded")
	}
}

// A target without an Auth provider still sends a stable workload credential:
// SecurityContextID when set, ConfigID otherwise, and the per-client ID as a
// last resort so credential-expecting brokers never see an empty identity.
func TestRequestDefaultWorkloadCredential(t *testing.T) {
	module := buildProxyMockModule(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var credentials []string
	server, err := NewServer(context.Background(), ServerConfig{
		Listener:      listener,
		AllowInsecure: true,
		Authorizer: func(_ context.Context, identity RequestIdentity) (string, error) {
			if len(identity.Auth) == 0 {
				return "", errors.New("missing workload identity")
			}
			mu.Lock()
			credentials = append(credentials, string(identity.Auth))
			mu.Unlock()
			return string(identity.Auth), nil
		},
	}, TargetConfig{
		ID: "test-route", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 3},
		Login: LoginPolicy{
			PhysicalPIN:      pkcs11.StaticPIN("1234"),
			Authenticate:     func(context.Context, LoginAttempt) error { return nil },
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveContext, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveContext) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close(context.Background())
		<-serveDone
	})

	for _, tc := range []struct {
		name           string
		target         Target
		wantCredential string
	}{
		{
			name: "security context id",
			target: Target{
				Endpoints: []string{listener.Addr().String()}, AllowInsecure: true,
				SecurityContextID: "ctx-identity", ConfigID: "cfg-identity",
			},
			wantCredential: "ctx-identity",
		},
		{
			name: "config id",
			target: Target{
				Endpoints: []string{listener.Addr().String()}, AllowInsecure: true,
				ConfigID: "cfg-identity",
			},
			wantCredential: "cfg-identity",
		},
		{
			name: "client id fallback",
			target: Target{
				Endpoints: []string{listener.Addr().String()}, AllowInsecure: true,
			},
			wantCredential: "nonempty", // validated below as 16 raw client-id bytes
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ListRoutes(context.Background(), tc.target); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			got := credentials[len(credentials)-1]
			mu.Unlock()
			if tc.name == "client id fallback" {
				if len(got) != 16 {
					t.Fatalf("default credential length = %d, want 16 client-id bytes", len(got))
				}
				return
			}
			if got != tc.wantCredential {
				t.Fatalf("credential = %q, want %q", got, tc.wantCredential)
			}
		})
	}

	// An explicit Auth provider still wins over every default.
	mu.Lock()
	credentials = nil
	mu.Unlock()
	target := Target{
		Endpoints: []string{listener.Addr().String()}, AllowInsecure: true,
		SecurityContextID: "ctx-identity", ConfigID: "cfg-identity",
		Auth: func(context.Context) ([]byte, error) { return []byte("explicit"), nil },
	}
	if _, err := ListRoutes(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(credentials) != 1 || credentials[0] != "explicit" {
		t.Fatalf("credentials = %v, want [explicit]", credentials)
	}
}

func TestProtectedAuthenticationPathAllowsNoPhysicalPIN(t *testing.T) {
	module := buildProxyMockModuleWithFlags(t, "-DMOCK_PROTECTED_AUTH_PATH=1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{Listener: listener, AllowInsecure: true}, TargetConfig{
		ID: "protected", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 3},
		Login: LoginPolicy{
			Authenticate:     func(context.Context, LoginAttempt) error { return nil },
			AllowedUserTypes: []uint{raw.CKU_USER}, EagerPhysicalLogin: true,
		},
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	if stats, ok := server.TargetStats("protected"); !ok || stats.PhysicalOpened != 1 {
		t.Fatalf("protected-path target stats = %+v, ok=%v", stats, ok)
	}
}

func TestRemoteWaitForSlotEventHonorsContextCancellation(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := client.WithContext(ctx, func(module raw.Module) error {
		_, waitErr := module.WaitForSlotEvent(0)
		return waitErr
	})
	// WaitForSlotEvent consumes a provider event, so a connection ending at the
	// deadline is conservatively reported as outcome-unknown. The important
	// property here is that the broker's nonblocking poll loop exits promptly
	// instead of leaving an uninterruptible native wait behind.
	if !errors.Is(err, ErrOutcomeUnknown) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitForSlotEvent error = %v, want deadline or ErrOutcomeUnknown", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("WaitForSlotEvent cancellation took %s", elapsed)
	}
}

func TestMutualTLSIdentityAuthorizesLogicalLogin(t *testing.T) {
	serverTLS, clientTLS := proxyTestTLS(t)
	module := buildProxyMockModule(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{Listener: listener, TLS: serverTLS}, TargetConfig{
		ID: "mtls", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 3},
		Login: LoginPolicy{
			PhysicalPIN: pkcs11.StaticPIN("1234"), TrustTransportIdentity: true,
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveContext, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(serveContext) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close(context.Background())
		<-done
	})

	client := openRemoteRaw(t, Target{
		ConfigID: "mtls-config", Revision: "revision-1", Endpoints: []string{listener.Addr().String()}, Route: "mtls",
		TLS: clientTLS, SecurityContextID: "proxy-test-mtls", RequestTimeout: 5 * time.Second,
		Vendors: []pkcs11.VendorModule{testProxyVendor},
	})
	session := openVirtualSession(t, client, remoteSlot(t, client), true)
	if err := client.Login(session, raw.CKU_USER, nil); err != nil {
		t.Fatalf("logical login through verified mTLS: %v", err)
	}
	if got := diagnostic(t, client, remoteSlot(t, client), mockDiagLoginCalls); got != 1 {
		t.Fatalf("physical login calls = %d, want 1", got)
	}
}

func TestRemoteModuleUsesFreshConnectionsAndVirtualSessions(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{
		MaxPhysicalTotal: 3, MaxPhysicalReadWrite: 2,
		MaxVirtualSessionsPerClient: 64,
	}, nil)
	client := openRemoteRaw(t, harness.target)

	// Calls reuse pooled connections: GetInfo must not dial again.
	before := harness.listener.accepted.Load()
	if _, err := client.GetInfo(); err != nil {
		t.Fatal(err)
	}
	if got := harness.listener.accepted.Load(); got != before {
		t.Fatalf("GetInfo accepted connections = %d, want %d (pooled reuse)", got, before)
	}

	slot := remoteSlot(t, client)
	var sessions []raw.SessionHandle
	for range 32 {
		sessions = append(sessions, openVirtualSession(t, client, slot, true))
	}
	stats, ok := harness.server.TargetStats("mock-hsm")
	if !ok {
		t.Fatal("target stats unavailable")
	}
	if stats.VirtualSessions != len(sessions) {
		t.Fatalf("virtual sessions = %d, want %d", stats.VirtualSessions, len(sessions))
	}
	if stats.PhysicalOpened != 1 || stats.PhysicalActive != 1 {
		t.Fatalf("physical sessions after virtual opens = opened:%d active:%d, want control session only", stats.PhysicalOpened, stats.PhysicalActive)
	}

	info, err := client.GetTokenInfo(slot)
	if err != nil {
		t.Fatal(err)
	}
	if info.SessionCount != uint(len(sessions)) {
		t.Fatalf("logical token session count = %d, want %d", info.SessionCount, len(sessions))
	}
	for _, session := range sessions {
		if err := client.CloseSession(session); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLogicalLoginIsolationAndNoPhysicalLogout(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, nil)
	clientA := openRemoteRaw(t, harness.target)
	clientB := openRemoteRaw(t, harness.target)
	slotA := remoteSlot(t, clientA)
	slotB := remoteSlot(t, clientB)
	sessionA := openVirtualSession(t, clientA, slotA, true)
	sessionB := openVirtualSession(t, clientB, slotB, true)

	if err := clientA.Login(sessionA, raw.CKU_USER, []byte("bad")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("wrong logical PIN error = %v", err)
	}
	if got := diagnostic(t, clientA, slotA, mockDiagLoginCalls); got != 0 {
		t.Fatalf("physical login calls after rejected logical PIN = %d", got)
	}
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	if got := diagnostic(t, clientA, slotA, mockDiagLoginCalls); got != 1 {
		t.Fatalf("physical login calls = %d, want 1", got)
	}

	infoA, err := clientA.GetSessionInfo(sessionA)
	if err != nil {
		t.Fatal(err)
	}
	infoB, err := clientB.GetSessionInfo(sessionB)
	if err != nil {
		t.Fatal(err)
	}
	if infoA.State != raw.State(raw.CKS_RW_USER_FUNCTIONS) || infoB.State != raw.State(raw.CKS_RW_PUBLIC_SESSION) {
		t.Fatalf("logical states A=%d B=%d", infoA.State, infoB.State)
	}

	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	if got := diagnostic(t, clientB, slotB, mockDiagLoginCalls); got != 1 {
		t.Fatalf("second logical client caused %d physical logins, want 1", got)
	}
	if err := clientA.Logout(sessionA); err != nil {
		t.Fatal(err)
	}
	if got := diagnostic(t, clientA, slotA, mockDiagLogoutCalls); got != 0 {
		t.Fatalf("logical logout caused %d physical logout calls", got)
	}
	infoA, _ = clientA.GetSessionInfo(sessionA)
	infoB, _ = clientB.GetSessionInfo(sessionB)
	if infoA.State != raw.State(raw.CKS_RW_PUBLIC_SESSION) || infoB.State != raw.State(raw.CKS_RW_USER_FUNCTIONS) {
		t.Fatalf("post-logout logical states A=%d B=%d", infoA.State, infoB.State)
	}
}

func TestLastLogicalSessionCloseRevokesLoginAndPrivateHandles(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)
	if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}

	privateObject, err := client.CreateObject(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, true),
		raw.NewAttribute(raw.CKA_LABEL, "private-token-object"),
		raw.NewAttribute(raw.CKA_ID, []byte{9, 8, 7}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetObjectSize(session, privateObject); err != nil {
		t.Fatalf("read private object before close: %v", err)
	}

	if err := client.CloseSession(session); err != nil {
		t.Fatal(err)
	}
	if got := diagnostic(t, client, slot, mockDiagLogoutCalls); got != 0 {
		t.Fatalf("closing the final logical session caused %d physical logout calls", got)
	}

	newSession := openVirtualSession(t, client, slot, true)
	info, err := client.GetSessionInfo(newSession)
	if err != nil {
		t.Fatal(err)
	}
	if info.State != raw.State(raw.CKS_RW_PUBLIC_SESSION) {
		t.Fatalf("new session state = %d, want public", info.State)
	}
	if _, err := client.GetObjectSize(newSession, privateObject); !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
		t.Fatalf("private virtual handle survived the last-session boundary: %v", err)
	}
}

// Closing a managed client's last logical session ends its broker login.
func TestManagedClientLogsInAgainAfterItsLastLogicalSessionCloses(t *testing.T) {
	rejected := pkcs11.KeyPairOptions{
		Algorithm:        pkcs11.AlgorithmRSA,
		PublicAttributes: []*raw.Attribute{raw.NewAttribute(raw.CKA_MODULUS_BITS, uint(1024))},
	}
	for _, test := range []struct {
		name             string
		sessions         pkcs11.SessionConfig
		closeLastSession func(context.Context, *testing.T, *pkcs11.Client)
	}{
		{
			name: "failed key generation",
			closeLastSession: func(ctx context.Context, t *testing.T, client *pkcs11.Client) {
				t.Helper()
				if _, err := client.GenerateKeyPair(ctx, rejected); !raw.IsError(err, raw.CKR_KEY_SIZE_RANGE) {
					t.Fatalf("GenerateKeyPair(RSA-1024) = %v, want CKR_KEY_SIZE_RANGE", err)
				}
			},
		},
		{
			name:             "idle timeout",
			sessions:         pkcs11.SessionConfig{IdleTimeout: time.Millisecond},
			closeLastSession: func(context.Context, *testing.T, *pkcs11.Client) { time.Sleep(10 * time.Millisecond) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			config := testmockBrokerConfig(testmock.SharedSource{Name: t.Name(), Module: testmock.New(t.Name(), 1)})
			config.Login = LoginPolicy{
				Mode:             PhysicalLoginClientActivated,
				Authenticate:     func(context.Context, LoginAttempt) error { return nil },
				AllowedUserTypes: []uint{raw.CKU_USER},
			}
			_, address := newTestmockBroker(t, config)
			client, err := pkcs11.Open(ctx, pkcs11.Config{
				Module:   RemoteModule(haTarget(address)),
				PIN:      pkcs11.StaticPIN(testmock.DefaultPIN),
				Login:    pkcs11.LoginConfig{Mode: pkcs11.LoginLazy},
				Sessions: test.sessions,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close(ctx) })
			if err := createPrivateObject(ctx, client); err != nil {
				t.Fatalf("first session: %v", err)
			}
			test.closeLastSession(ctx, t, client)
			if err := createPrivateObject(ctx, client); err != nil {
				t.Fatalf("session after the last one closed: %v", err)
			}
		})
	}
}

// createPrivateObject needs a logged-in read/write session. It fails on a
// session in the public state.
func createPrivateObject(ctx context.Context, client *pkcs11.Client) error {
	return client.WithRawSession(ctx, pkcs11.RawSessionOptions{ReadWrite: true}, func(module raw.Module, session raw.SessionHandle) error {
		info, err := module.GetSessionInfo(session)
		if err != nil {
			return err
		}
		var stateErr error
		if info.State != raw.State(raw.CKS_RW_USER_FUNCTIONS) {
			stateErr = fmt.Errorf("session state = %d, want CKS_RW_USER_FUNCTIONS", info.State)
		}
		_, createErr := module.CreateObject(session, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
			raw.NewAttribute(raw.CKA_PRIVATE, true),
		})
		return errors.Join(stateErr, createErr)
	})
}

func TestDroppedNonIdempotentResponseUsesDedupLedger(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)

	harness.listener.dropNext.Store(true)
	if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatalf("login after dropped first response: %v", err)
	}
	if got := diagnostic(t, client, slot, mockDiagLoginCalls); got != 1 {
		t.Fatalf("deduplicated login executed %d physical calls, want 1", got)
	}
}

func TestMultipartAndSessionObjectAffinity(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4, MaxPinned: 2}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	owner := openVirtualSession(t, client, slot, true)
	peer := openVirtualSession(t, client, slot, true)
	if err := client.Login(owner, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}

	tokenKey, err := client.CreateObject(owner, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
		raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
		raw.NewAttribute(raw.CKA_LABEL, "proxy-token-key"),
		raw.NewAttribute(raw.CKA_ID, []byte{1, 2, 3}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.EncryptInit(owner, []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_CBC, nil)}, tokenKey); err != nil {
		t.Fatal(err)
	}
	stats, _ := harness.server.TargetStats("mock-hsm")
	if stats.PinnedSessions != 1 {
		t.Fatalf("pinned sessions after EncryptInit = %d, want 1", stats.PinnedSessions)
	}
	plaintext := []byte("multipart operation stays on one physical session")
	ciphertext, err := client.Encrypt(owner, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) != string(plaintext) {
		t.Fatalf("ciphertext = %q", ciphertext)
	}
	stats, _ = harness.server.TargetStats("mock-hsm")
	if stats.PinnedSessions != 0 {
		t.Fatalf("pinned sessions after Encrypt = %d, want 0", stats.PinnedSessions)
	}

	sessionObject, err := client.CreateObject(owner, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, false),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
		raw.NewAttribute(raw.CKA_LABEL, "session-object"),
	})
	if err != nil {
		t.Fatal(err)
	}
	stats, _ = harness.server.TargetStats("mock-hsm")
	if stats.PinnedSessions != 1 {
		t.Fatalf("session object did not retain one physical lease: %+v", stats)
	}
	if _, err := client.GetObjectSize(peer, sessionObject); err != nil {
		t.Fatalf("session object should be visible across logical sessions: %v", err)
	}
	if err := client.CloseSession(owner); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetObjectSize(peer, sessionObject); !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
		t.Fatalf("session object survived creator close: %v", err)
	}
	stats, _ = harness.server.TargetStats("mock-hsm")
	if stats.PinnedSessions != 0 {
		t.Fatalf("creator close left pinned session: %+v", stats)
	}
}

func TestCrossSessionAffineObjectLifetimeIsBorrowed(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 5, MaxPinned: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	owner := openVirtualSession(t, client, slot, true)
	peer := openVirtualSession(t, client, slot, true)

	object, err := client.CreateObject(owner, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, false),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
		raw.NewAttribute(raw.CKA_LABEL, "slow-session-object"),
	})
	if err != nil {
		t.Fatal(err)
	}

	readDone := make(chan error, 1)
	go func() {
		_, readErr := client.GetObjectSize(peer, object)
		readDone <- readErr
	}()

	deadline := time.Now().Add(3 * time.Second)
	for diagnostic(t, client, slot, mockDiagSlowObjectReads) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("slow cross-session object read did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.CloseSession(owner) }()
	select {
	case closeErr := <-closeDone:
		t.Fatalf("owner session closed while a foreign session was using its object: %v", closeErr)
	case <-time.After(40 * time.Millisecond):
		// Expected: close is waiting for the foreign object's lifetime borrow.
	}

	if err := <-readDone; err != nil {
		t.Fatalf("cross-session object read failed while owner was closing: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("close owner session: %v", err)
	}
	if _, err := client.GetObjectSize(peer, object); !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
		t.Fatalf("session object remained usable after owner close: %v", err)
	}
}

func TestCrossSessionAffineObjectUseHasNoLockInversion(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 5, MaxPinned: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	first := openVirtualSession(t, client, slot, true)
	second := openVirtualSession(t, client, slot, true)

	create := func(session raw.SessionHandle) raw.ObjectHandle {
		object, err := client.CreateObject(session, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_PRIVATE, false),
			raw.NewAttribute(raw.CKA_LABEL, "slow-session-object"),
		})
		if err != nil {
			t.Fatal(err)
		}
		return object
	}
	firstObject := create(first)
	secondObject := create(second)

	start := make(chan struct{})
	done := make(chan error, 2)
	go func() {
		<-start
		_, err := client.GetObjectSize(first, secondObject)
		done <- err
	}()
	go func() {
		<-start
		_, err := client.GetObjectSize(second, firstObject)
		done <- err
	}()
	close(start)

	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("cross-session affine operations deadlocked")
		}
	}
}

// The native module exposes session objects application-wide (matching real
// Cryptoki token behavior on pooled physical sessions). One logical client
// must never adopt a session object another logical client created.
func TestForeignSessionObjectIsInvisibleAcrossClients(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 5, MaxPinned: 3}, nil)
	alice := openRemoteRaw(t, harness.target)
	bob := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, alice)
	aliceSession := openVirtualSession(t, alice, slot, true)
	bobSession := openVirtualSession(t, bob, remoteSlot(t, bob), true)

	aliceObject, err := alice.CreateObject(aliceSession, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, false),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
		raw.NewAttribute(raw.CKA_LABEL, "alice-session-object"),
	})
	if err != nil {
		t.Fatal(err)
	}
	tokenObject, err := alice.CreateObject(aliceSession, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
		raw.NewAttribute(raw.CKA_LABEL, "alice-token-object"),
	})
	if err != nil {
		t.Fatal(err)
	}

	findAll := func(client *Client, session raw.SessionHandle) []raw.ObjectHandle {
		t.Helper()
		if err := client.FindObjectsInit(session, []*raw.Attribute{raw.NewAttribute(raw.CKA_PRIVATE, false)}); err != nil {
			t.Fatal(err)
		}
		var found []raw.ObjectHandle
		for {
			batch, more, err := client.FindObjects(session, 4)
			if err != nil {
				t.Fatal(err)
			}
			found = append(found, batch...)
			if !more {
				break
			}
		}
		if err := client.FindObjectsFinal(session); err != nil {
			t.Fatal(err)
		}
		return found
	}

	// Bob cannot address Alice's session object by guessing her virtual handle —
	// virtual handles are per-client, but with no objects of his own yet this
	// value is provably unassigned in his namespace.
	if _, err := bob.GetObjectSize(bobSession, aliceObject); !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
		t.Fatalf("foreign session object by handle = %v, want CKR_OBJECT_HANDLE_INVALID", err)
	}
	if err := bob.DestroyObject(bobSession, aliceObject); !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
		t.Fatalf("foreign session destroy = %v, want CKR_OBJECT_HANDLE_INVALID", err)
	}

	// The creating client sees both objects; the token object is shared while
	// the session object stays scoped to its logical client.
	aliceFound := findAll(alice, aliceSession)
	if len(aliceFound) != 2 {
		t.Fatalf("creator search returned %d objects, want 2", len(aliceFound))
	}
	bobFound := findAll(bob, bobSession)
	if len(bobFound) != 1 {
		t.Fatalf("foreign client search returned %v; only the shared token object is allowed", bobFound)
	}
	// The handle Bob received is a valid virtual alias for the shared token
	// object, proving the foreign session object was filtered rather than the
	// search itself being rejected.
	labels, err := bob.GetAttributeValue(bobSession, bobFound[0], []*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, nil)})
	if err != nil {
		t.Fatalf("shared token object unusable by second client: %v", err)
	}
	if len(labels) != 1 || string(labels[0].Value) != "alice-token-object" {
		t.Fatalf("foreign-visible object label = %+v, want alice-token-object", labels)
	}
	_ = tokenObject

	// A second virtual session of the SAME client adopts the alias recorded
	// against the owning session — cross-session visibility stays intact.
	sibling := openVirtualSession(t, alice, slot, true)
	siblingFound := findAll(alice, sibling)
	if len(siblingFound) != 2 {
		t.Fatalf("same-client sibling lost session object: %v", siblingFound)
	}
	var adopted raw.ObjectHandle
	for _, handle := range siblingFound {
		siblingLabels, labelErr := alice.GetAttributeValue(sibling, handle, []*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, nil)})
		if labelErr == nil && len(siblingLabels) == 1 && string(siblingLabels[0].Value) == "alice-session-object" {
			adopted = handle
		}
	}
	if adopted == 0 {
		t.Fatalf("same-client sibling session lost the session object: %v", siblingFound)
	}
	if _, err := alice.GetObjectSize(sibling, adopted); err != nil {
		t.Fatalf("same-client cross-session use failed: %v", err)
	}
}

// A foreign-owned session object destroyed through a sibling session must
// decrement the owner's accounting and return its pinned lease once idle.
func TestCrossSessionDestroyReleasesForeignOwner(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 5, MaxPinned: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	owner := openVirtualSession(t, client, slot, true)
	peer := openVirtualSession(t, client, slot, true)

	object, err := client.CreateObject(owner, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, false),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
		raw.NewAttribute(raw.CKA_LABEL, "peer-session-object"),
	})
	if err != nil {
		t.Fatal(err)
	}
	stats, _ := harness.server.TargetStats("mock-hsm")
	if stats.PinnedSessions != 1 {
		t.Fatalf("pinned sessions after create = %d, want 1", stats.PinnedSessions)
	}
	if err := client.DestroyObject(peer, object); err != nil {
		t.Fatalf("cross-session destroy: %v", err)
	}
	stats, _ = harness.server.TargetStats("mock-hsm")
	if stats.PinnedSessions != 0 {
		t.Fatalf("owner lease still pinned after foreign destroy: %+v", stats)
	}
	if _, err := client.GetObjectSize(peer, object); !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
		t.Fatalf("destroyed object remained usable: %v", err)
	}
}

// Two sessions starting operations keyed on each other's session objects used
// to deadlock: each held the foreign owner's lifetime read lock while waiting
// on its own write lock (pin). Borrow locks now drop before pinning.
func TestMutualForeignKeyOperationStartsDoNotDeadlock(t *testing.T) {
	source := testmock.Source{Name: "cross-session-ops"}
	config := testmockBrokerConfig(source)
	_, addr := newTestmockBroker(t, config)

	client, err := Open(context.Background(), haTarget(addr))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	slot, err := client.GetSlotList(true)
	if err != nil || len(slot) == 0 {
		t.Fatalf("slot list = %v, %v", slot, err)
	}
	openRW := func() raw.SessionHandle {
		t.Helper()
		session, err := client.OpenSession(slot[0], raw.CKF_SERIAL_SESSION|raw.CKF_RW_SESSION)
		if err != nil {
			t.Fatal(err)
		}
		return session
	}
	first := openRW()
	second := openRW()

	keygen := []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_KEY_GEN, nil)}
	keyAttrs := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_TOKEN, false),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
		raw.NewAttribute(raw.CKA_VALUE_LEN, uint(16)),
	}
	firstKey, err := client.GenerateKey(first, keygen, keyAttrs)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := client.GenerateKey(second, keygen, keyAttrs)
	if err != nil {
		t.Fatal(err)
	}

	cbc := []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_CBC, make([]byte, 16))}
	start := make(chan struct{})
	done := make(chan error, 2)
	cycle := func(session raw.SessionHandle, foreignKey raw.ObjectHandle) {
		<-start
		for range 40 {
			if err := client.EncryptInit(session, cbc, foreignKey); err != nil {
				done <- err
				return
			}
			if _, err := client.Encrypt(session, []byte("sixteen byte msg!")); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}
	go cycle(first, secondKey)
	go cycle(second, firstKey)
	close(start)
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("mutual foreign-key operation starts deadlocked")
		}
	}
}

// A completed request whose retained response was evicted under memory
// pressure must still prove the request ran: followers get an explicit
// unknown-outcome tombstone instead of a silent re-execution.
func TestDedupLedgerRetainsHistoryAfterPayloadEviction(t *testing.T) {
	ledger := newDedupLedger(8, 1, time.Minute)
	key := dedupKey{principal: "p", client: [16]byte{1}, request: [16]byte{2}}
	fingerprint := [32]byte{9}
	epoch := [16]byte{7}

	entry, leader, _, err := ledger.begin(context.Background(), key, fingerprint, epoch, time.Time{})
	if err != nil || !leader {
		t.Fatalf("leader begin = leader:%v err:%v", leader, err)
	}
	result := response{Version: protocolVersion, Epoch: epoch, Results: []wireValue{{Kind: valueBytes, Bytes: []byte("payload larger than the byte bound")}}}
	ledger.complete(key, entry, result)

	// The byte bound forces eviction of the only retained response.
	_, leader, replay, err := ledger.begin(context.Background(), key, fingerprint, epoch, time.Time{})
	if err != nil {
		t.Fatalf("follower begin: %v", err)
	}
	if leader {
		t.Fatal("pruned-payload request re-executed instead of replayed")
	}
	decoded := decodeError(replay.Error)
	if !errors.Is(decoded, ErrOutcomeUnknown) {
		t.Fatalf("follower replay error = %v, want ErrOutcomeUnknown", decoded)
	}
}

// In-progress executions are never pruned: forgetting a still-running mutation
// would let a late retry execute the request a second time.
func TestDedupLedgerNeverRetiresInProgress(t *testing.T) {
	ledger := newDedupLedger(8, 1<<20, time.Hour)
	key := dedupKey{principal: "p", client: [16]byte{1}, request: [16]byte{3}}
	fingerprint := [32]byte{9}
	epoch := [16]byte{7}

	entry, leader, _, err := ledger.begin(context.Background(), key, fingerprint, epoch, time.Time{})
	if err != nil || !leader {
		t.Fatalf("leader begin = leader:%v err:%v", leader, err)
	}

	// Force the entry's retry horizon into the past while it is still running
	// and prune directly: the execution record must survive regardless.
	ledger.mu.Lock()
	entry.expiresAt = time.Now().Add(-time.Millisecond)
	ledger.pruneLocked(time.Now())
	_, stillTracked := ledger.entries[key]
	ledger.mu.Unlock()
	if !stillTracked {
		t.Fatal("in-progress execution record was pruned past its horizon")
	}

	// A same-key retry must join the running execution, not start a second.
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelWait()
	_, leader, _, err = ledger.begin(waitCtx, key, fingerprint, epoch, time.Now().Add(time.Hour))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("follower begin during in-progress original = leader:%v err:%v", leader, err)
	}

	ledger.complete(key, entry, response{Version: protocolVersion, Epoch: epoch})
	// Completion alone does not re-arm pruning — the record stays until the
	// horizon check sees it. Restore a live horizon and verify clean replay.
	ledger.mu.Lock()
	entry.expiresAt = time.Now().Add(time.Hour)
	ledger.mu.Unlock()
	_, leader, replay, err := ledger.begin(context.Background(), key, fingerprint, epoch, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("post-completion begin: %v", err)
	}
	if leader || replay.Error != nil {
		t.Fatalf("completed request did not replay cleanly: leader:%v error:%v", leader, replay.Error)
	}
}

// A request arriving after its own deadline is rejected instead of executed:
// once its ledger entry could have been pruned, admitting it cannot prove the
// mutation did not already run.
func TestDedupLedgerRejectsExpiredRetryHorizon(t *testing.T) {
	ledger := newDedupLedger(8, 1<<20, time.Minute)
	key := dedupKey{principal: "p", client: [16]byte{1}, request: [16]byte{4}}
	fingerprint := [32]byte{9}
	epoch := [16]byte{7}

	_, leader, _, err := ledger.begin(context.Background(), key, fingerprint, epoch, time.Now().Add(-time.Second))
	if err == nil || leader {
		t.Fatalf("expired request admitted: leader:%v err:%v", leader, err)
	}
	remote, remoteOK := errors.AsType[*RemoteError](err)
	if !remoteOK || remote.Code != "deadline_exceeded" {
		t.Fatalf("expired request error = %v, want deadline_exceeded", err)
	}
}

// Full capacity rejects new work but never evicts retained execution history:
// a follower for an existing key still replays its response.
func TestDedupLedgerCapacityProtectsHistory(t *testing.T) {
	ledger := newDedupLedger(1, 1<<20, time.Minute)
	first := dedupKey{principal: "p", client: [16]byte{1}, request: [16]byte{5}}
	second := dedupKey{principal: "p", client: [16]byte{1}, request: [16]byte{6}}
	fingerprint := [32]byte{9}
	epoch := [16]byte{7}

	entry, leader, _, err := ledger.begin(context.Background(), first, fingerprint, epoch, time.Time{})
	if err != nil || !leader {
		t.Fatalf("leader begin = leader:%v err:%v", leader, err)
	}
	ledger.complete(first, entry, response{Version: protocolVersion, Epoch: epoch})

	_, leader, _, err = ledger.begin(context.Background(), second, fingerprint, epoch, time.Time{})
	remote, remoteOK := errors.AsType[*RemoteError](err)
	if !remoteOK || remote.Code != "dedup_capacity" || leader {
		t.Fatalf("over-capacity begin = leader:%v err:%v, want dedup_capacity", leader, err)
	}
	_, leader, replay, err := ledger.begin(context.Background(), first, fingerprint, epoch, time.Time{})
	if err != nil || leader || replay.Error != nil {
		t.Fatalf("retained history lost under capacity: leader:%v err:%v replay.Error:%v", leader, err, replay.Error)
	}
}

// When the retry budget is exhausted after a transport failure that may have
// carried the request, the client must surface ErrOutcomeUnknown — the caller
// cannot tell whether the non-idempotent operation ran.
func TestNonIdempotentFailureAfterWriteReportsUnknownOutcome(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, nil)
	harness.target.MaxAttempts = 1
	// dropNext arms on the next accepted connection; dial-per-request keeps
	// the drop deterministic instead of writing over a warm pooled conn.
	harness.target.MaxPooledConnections = -1
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)

	harness.listener.dropNext.Store(true)
	err := client.Login(session, raw.CKU_USER, []byte("1234"))
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("dropped non-idempotent response = %v, want ErrOutcomeUnknown", err)
	}
	if !errors.Is(err, ErrTargetLost) {
		t.Fatalf("exhausted retry = %v, want ErrTargetLost", err)
	}
	// The request actually executed; a fresh connection replays the session's
	// post-login state, not a second physical login.
	if got := diagnostic(t, client, slot, mockDiagLoginCalls); got != 1 {
		t.Fatalf("physical logins = %d, want 1", got)
	}
}

// Cancelling the Serve context starts a drain — it must not kill the
// work context of already-established clients. Established clients keep
// issuing requests (each on a fresh TLS connection) until they close.
func TestServingContextCancelKeepsEstablishedClients(t *testing.T) {
	serverTLS, clientTLS := proxyTestTLS(t)
	module := buildProxyMockModule(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{Listener: listener, TLS: serverTLS}, TargetConfig{
		ID: "drain-serve", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 4},
		Login: LoginPolicy{
			PhysicalPIN:      pkcs11.StaticPIN("1234"),
			Authenticate:     func(context.Context, LoginAttempt) error { return nil },
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveContext, cancelServe := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(serveContext) }()
	t.Cleanup(func() {
		cancelServe()
		_ = server.Close(context.Background())
		<-done
	})

	client := openRemoteRaw(t, Target{
		ConfigID: "drain-serve", Revision: "revision-1", Endpoints: []string{listener.Addr().String()}, Route: "drain-serve",
		TLS: clientTLS, SecurityContextID: "proxy-test-mtls", RequestTimeout: 5 * time.Second,
		Vendors: []pkcs11.VendorModule{testProxyVendor},
	})
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)
	if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}

	// Cancelling Serve's context drains the replica: new clients are refused,
	// established clients keep working over fresh connections.
	cancelServe()
	deadline := time.Now().Add(2 * time.Second)
	for server.State() != ServerDraining {
		if time.Now().After(deadline) {
			t.Fatal("server never entered draining state")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := client.GetInfo(); err != nil {
		t.Fatalf("established client broke when serving context cancelled: %v", err)
	}
	// Handle 1 may or may not exist natively; the call must reach the broker
	// and return a Cryptoki verdict rather than a transport/context failure.
	_, err = client.GetObjectSize(session, raw.ObjectHandle(1))
	if err != nil && !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
		t.Fatalf("session method after drain = %v, want a Cryptoki verdict", err)
	}
	if _, err := Open(context.Background(), Target{
		ConfigID: "drain-serve", Revision: "revision-1", Endpoints: []string{listener.Addr().String()}, Route: "drain-serve",
		TLS: clientTLS, SecurityContextID: "proxy-test-mtls", RequestTimeout: 5 * time.Second,
		Vendors: []pkcs11.VendorModule{testProxyVendor},
	}); err == nil {
		t.Fatal("new client established on a draining replica")
	}
}

func TestPhysicalSessionBudgetAndBoundedQueue(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{
		MaxPhysicalTotal: 3, ReservedControlSessions: 1,
		MaxPinned: 1, MaxQueued: 2, QueueTimeout: 50 * time.Millisecond,
	}, nil)
	// The budget assertion models eight truly concurrent requests; the
	// default pool would serialize them four-at-a-time on the client.
	harness.target.MaxPooledConnections = -1
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	sessions := make([]raw.SessionHandle, 8)
	for index := range sessions {
		sessions[index] = openVirtualSession(t, client, slot, false)
	}

	start := make(chan struct{})
	var wait sync.WaitGroup
	errorsSeen := make(chan error, len(sessions))
	var successes atomic.Int64
	for _, session := range sessions {
		wait.Go(func() {
			<-start
			value, err := client.GenerateRandom(session, mockSlowRandomLength)
			if err == nil && len(value) == mockSlowRandomLength {
				successes.Add(1)
				return
			}
			if err == nil {
				err = fmt.Errorf("random length = %d", len(value))
			}
			errorsSeen <- err
		})
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	if successes.Load() == 0 || successes.Load() > 2 {
		t.Fatalf("successful slow operations = %d, want 1..2", successes.Load())
	}
	for err := range errorsSeen {
		if !raw.IsError(err, raw.CKR_TOKEN_RESOURCE_EXCEEDED) && !raw.IsError(err, raw.CKR_SESSION_COUNT) {
			t.Errorf("unexpected backpressure error: %v", err)
		}
	}
	if got := diagnostic(t, client, slot, mockDiagMaxSessions); got > 3 {
		t.Fatalf("physical session high-water mark = %d, maximum 3", got)
	}
	stats, _ := harness.server.TargetStats("mock-hsm")
	if stats.QueuedRequests != 0 || stats.PhysicalOpened > 3 {
		t.Fatalf("post-load target stats = %+v", stats)
	}
}

func TestSessionScopedPhysicalLoginOccursOncePerNativeSession(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, func(config *TargetConfig) {
		config.Client.Vendors = []pkcs11.VendorModule{testProxySessionVendor}
	})
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	first := openVirtualSession(t, client, slot, false)
	second := openVirtualSession(t, client, slot, false)
	if err := client.Login(first, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for _, session := range []raw.SessionHandle{first, second} {
		wait.Go(func() {
			<-start
			_, err := client.GenerateRandom(session, mockSlowRandomLength)
			errorsSeen <- err
		})
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := diagnostic(t, client, slot, mockDiagLoginCalls); got != 3 {
		t.Fatalf("physical login calls after control plus two work sessions = %d, want 3", got)
	}
	if _, err := client.GenerateRandom(first, 32); err != nil {
		t.Fatal(err)
	}
	if got := diagnostic(t, client, slot, mockDiagLoginCalls); got != 3 {
		t.Fatalf("reused physical session was logged in again: %d calls", got)
	}
}

func TestTargetReplacementRejectsStaleEpochAndRevision(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, nil)
	old := openRemoteRaw(t, harness.target)
	if _, err := old.GetInfo(); err != nil {
		t.Fatal(err)
	}

	sameRevision := TargetConfig{
		ID: "mock-hsm", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(harness.module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 4},
		Login: LoginPolicy{
			PhysicalPIN: pkcs11.StaticPIN("1234"),
			Authenticate: func(_ context.Context, attempt LoginAttempt) error {
				if string(attempt.PIN) != "1234" {
					return raw.Error(raw.CKR_PIN_INCORRECT)
				}
				return nil
			},
		},
	}
	if err := harness.server.ReplaceTarget(context.Background(), sameRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := old.GetInfo(); err == nil || !stringsContains(err.Error(), "target_epoch_mismatch") {
		t.Fatalf("stale epoch error = %v", err)
	}

	newTarget := harness.target
	newClient := openRemoteRaw(t, newTarget)
	if _, err := newClient.GetInfo(); err != nil {
		t.Fatal(err)
	}

	revision2 := sameRevision
	revision2.Revision = "revision-2"
	if err := harness.server.ReplaceTarget(context.Background(), revision2); err != nil {
		t.Fatal(err)
	}
	if _, err := newClient.GetInfo(); err == nil || !stringsContains(err.Error(), "revision_mismatch") {
		t.Fatalf("stale revision error = %v", err)
	}
	latestTarget := harness.target
	latestTarget.Revision = "revision-2"
	latest := openRemoteRaw(t, latestTarget)
	if _, err := latest.GetInfo(); err != nil {
		t.Fatal(err)
	}
}

func stringsContains(value, fragment string) bool {
	return len(fragment) == 0 || (len(value) >= len(fragment) && contains(value, fragment))
}

func contains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

func TestManagedClientUsesRemoteModuleSource(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, nil)
	client, err := pkcs11.Open(context.Background(), pkcs11.Config{
		Module:   RemoteModule(harness.target),
		Login:    pkcs11.LoginConfig{Mode: pkcs11.LoginEager},
		PIN:      pkcs11.StaticPIN("1234"),
		Sessions: pkcs11.SessionConfig{Max: 8, MaxTotal: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(context.Background()) }()
	if client.Adapter().Family != testProxyVendor.Definition().ID {
		t.Fatalf("remote adapter = %q", client.Adapter().Family)
	}
	value, err := client.Random(context.Background(), 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != 64 {
		t.Fatalf("random bytes = %d", len(value))
	}
}

func TestDedupLedgerRejectsRequestIDReuse(t *testing.T) {
	ledger := newDedupLedger(2, 1<<20, time.Minute)
	defer ledger.close()
	key := dedupKey{client: [16]byte{1}, request: [16]byte{2}}
	first := [32]byte{3}
	entry, leader, _, err := ledger.begin(context.Background(), key, first, [16]byte{}, time.Now().Add(time.Minute))
	if err != nil || !leader {
		t.Fatalf("first ledger begin = leader:%v err:%v", leader, err)
	}
	ledger.complete(key, entry, response{Version: protocolVersion})
	if _, _, _, err := ledger.begin(context.Background(), key, [32]byte{4}, [16]byte{}, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("request ID reuse with different contents was accepted")
	}
}

func TestTransportRejectsUnknownJSONFields(t *testing.T) {
	payload := []byte(`{"Version":2,"Unknown":true}`)
	var frame []byte
	frame = append(frame, byte(len(payload)>>24), byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)))
	frame = append(frame, payload...)
	var req request
	if err := readMessage(bytesReader(frame), &req, 1024); err == nil {
		t.Fatal("unknown transport field was accepted")
	}
}

type byteReader struct{ value []byte }

func bytesReader(value []byte) *byteReader { return &byteReader{value: value} }
func (reader *byteReader) Read(target []byte) (int, error) {
	if len(reader.value) == 0 {
		return 0, io.EOF
	}
	n := copy(target, reader.value)
	reader.value = reader.value[n:]
	return n, nil
}

func TestTrustTransportIdentityRequiresVerifiedIdentity(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	module := buildProxyMockModule(t)
	_, err = NewServer(context.Background(), ServerConfig{Listener: listener, AllowInsecure: true}, TargetConfig{
		ID: "unsafe", Revision: "1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 2},
		Login:    LoginPolicy{PhysicalPIN: pkcs11.StaticPIN("1234"), TrustTransportIdentity: true},
	})
	if err == nil {
		t.Fatal("unverified transport identity was accepted")
	}
}

func TestLoginErrorIsPreserved(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)
	err := client.Login(session, raw.CKU_USER, []byte("wrong"))
	if !errors.Is(err, raw.Error(raw.CKR_PIN_INCORRECT)) {
		t.Fatalf("login error = %v", err)
	}
}

func TestDestroyReleasesLogicalClientImmediately(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, nil)
	client, err := Open(context.Background(), harness.target)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}
	if stats, _ := harness.server.TargetStats("mock-hsm"); stats.Clients != 1 {
		t.Fatalf("logical clients before Destroy = %d, want 1", stats.Clients)
	}
	client.Destroy()
	deadline := time.Now().Add(time.Second)
	for {
		stats, _ := harness.server.TargetStats("mock-hsm")
		if stats.Clients == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("logical clients after Destroy = %d, want 0", stats.Clients)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTokenObjectWithoutLocatorDoesNotPinPhysicalSession(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4, MaxPinned: 2}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	owner := openVirtualSession(t, client, slot, true)
	peer := openVirtualSession(t, client, slot, true)

	object, err := client.CreateObject(owner, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	stats, _ := harness.server.TargetStats("mock-hsm")
	if stats.PinnedSessions != 0 {
		t.Fatalf("locator-less token object pinned a physical session: %+v", stats)
	}
	if _, err := client.GetObjectSize(peer, object); err != nil {
		t.Fatalf("token object was not reusable from another logical session: %v", err)
	}
}

func TestContextSpecificLoginRequiresLogicalAuthentication(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4, MaxPinned: 2}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)
	// Create the persistent public fixture while logically authenticated. Real
	// HSMs commonly require USER login even when the resulting object is public.
	if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	key, err := client.CreateObject(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Logout(session); err != nil {
		t.Fatal(err)
	}
	if err := client.EncryptInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_CBC, nil)}, key); err != nil {
		t.Fatal(err)
	}
	if err := client.Login(session, raw.CKU_CONTEXT_SPECIFIC, []byte("1234")); !raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("unauthenticated context login error = %v", err)
	}
	if _, err := client.Encrypt(session, []byte("cancel first operation")); err != nil {
		t.Fatal(err)
	}
	if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	if err := client.EncryptInit(session, []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_CBC, nil)}, key); err != nil {
		t.Fatal(err)
	}
	if err := client.Login(session, raw.CKU_CONTEXT_SPECIFIC, []byte("bad")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("wrong context credential error = %v", err)
	}
	if err := client.Login(session, raw.CKU_CONTEXT_SPECIFIC, []byte("1234")); err != nil {
		t.Fatalf("context login: %v", err)
	}
	if _, err := client.Encrypt(session, []byte("context-authenticated")); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteSlotIsStableAndSynthetic(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	if slot != 1 {
		t.Fatalf("remote slot = %d, want stable route-local slot 1", slot)
	}
	if _, err := client.GetTokenInfo(slot); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetTokenInfo(slot + 1); !raw.IsError(err, raw.CKR_SLOT_ID_INVALID) {
		t.Fatalf("unexpected invalid-slot result: %v", err)
	}
}

func TestDedupFollowerSurvivesLedgerReset(t *testing.T) {
	ledger := newDedupLedger(2, 1<<20, time.Minute)
	key := dedupKey{client: [16]byte{1}, request: [16]byte{2}}
	fingerprint := [32]byte{3}
	entry, leader, _, err := ledger.begin(context.Background(), key, fingerprint, [16]byte{}, time.Now().Add(time.Minute))
	if err != nil || !leader {
		t.Fatalf("leader begin = leader:%v err:%v", leader, err)
	}
	result := make(chan response, 1)
	go func() {
		_, follower, replay, beginErr := ledger.begin(context.Background(), key, fingerprint, [16]byte{}, time.Now().Add(time.Minute))
		if beginErr != nil || follower {
			result <- response{Error: encodeError(beginErr)}
			return
		}
		result <- replay
	}()
	deadline := time.Now().Add(time.Second)
	for {
		ledger.mu.Lock()
		waiters := entry.waiters
		ledger.mu.Unlock()
		if waiters == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("follower did not enter dedup wait")
		}
		time.Sleep(time.Millisecond)
	}
	ledger.reset([16]byte{9})
	replay := <-result
	remote, remoteOK := errors.AsType[*RemoteError](decodeError(replay.Error))
	if !remoteOK || remote.Code != "target_epoch_mismatch" {
		t.Fatalf("reset replay error = %#v", replay.Error)
	}
	ledger.close()
}

func TestValidateRequestEnvelopeRejectsMissingIdentity(t *testing.T) {
	req := request{Version: protocolVersion, Target: "target", Revision: "revision", Method: methodDescribe}
	if err := validateRequestEnvelope(req); err == nil {
		t.Fatal("zero client/request IDs were accepted")
	}
	req.ClientID[0], req.RequestID[0] = 1, 1
	if err := validateRequestEnvelope(req); err != nil {
		t.Fatalf("valid describe envelope: %v", err)
	}
	req.Method = "GetInfo"
	if err := validateRequestEnvelope(req); err == nil {
		t.Fatal("non-describe request without epoch was accepted")
	}
	// Established methods must also carry the pinned server identity.
	req.Epoch[0] = 1
	if err := validateRequestEnvelope(req); err == nil {
		t.Fatal("non-describe request without server ID was accepted")
	}
	req.ServerID[0] = 1
	if err := validateRequestEnvelope(req); err != nil {
		t.Fatalf("valid established envelope: %v", err)
	}
	// The route catalog is server-scoped: it needs no target, revision, or epoch.
	req = request{Version: protocolVersion, Method: methodListRoutes}
	if err := validateRequestEnvelope(req); err == nil {
		t.Fatal("@routes with zero client/request IDs was accepted")
	}
	req.ClientID[0], req.RequestID[0] = 1, 1
	if err := validateRequestEnvelope(req); err != nil {
		t.Fatalf("valid @routes envelope: %v", err)
	}
	req.Method = methodDescribe
	if err := validateRequestEnvelope(req); err == nil {
		t.Fatal("describe without target was accepted")
	}
}

func TestServerShutdownDrainsInFlightRequest(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, false)
	done := make(chan error, 1)
	go func() {
		_, err := client.GenerateRandom(session, mockSlowRandomLength)
		done <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for diagnostic(t, client, slot, mockDiagOpenSessions) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("slow request did not acquire a physical session")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := harness.server.Shutdown(ctx); err != nil {
		t.Fatalf("graceful shutdown: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("in-flight request failed during graceful shutdown: %v", err)
	}
}

func TestClientAndSessionQuotasAreEnforced(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{
		MaxPhysicalTotal: 3, MaxClients: 1,
		MaxVirtualSessionsTotal: 2, MaxVirtualSessionsPerClient: 2,
	}, nil)
	first := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, first)
	one := openVirtualSession(t, first, slot, false)
	two := openVirtualSession(t, first, slot, false)
	if _, err := first.OpenSession(slot, raw.CKF_SERIAL_SESSION); !raw.IsError(err, raw.CKR_SESSION_COUNT) {
		t.Fatalf("per-client virtual-session quota error = %v", err)
	}

	second, err := Open(context.Background(), harness.target)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	if err := second.Initialize(); !raw.IsError(err, raw.CKR_TOKEN_RESOURCE_EXCEEDED) {
		t.Fatalf("logical-client quota error = %v", err)
	}

	if err := first.CloseSession(one); err != nil {
		t.Fatal(err)
	}
	if err := first.CloseSession(two); err != nil {
		t.Fatal(err)
	}
}

func TestTotalVirtualSessionQuotaSpansClients(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{
		MaxPhysicalTotal: 3, MaxClients: 2,
		MaxVirtualSessionsTotal: 2, MaxVirtualSessionsPerClient: 2,
	}, nil)
	first := openRemoteRaw(t, harness.target)
	second := openRemoteRaw(t, harness.target)
	firstSlot := remoteSlot(t, first)
	secondSlot := remoteSlot(t, second)
	_ = openVirtualSession(t, first, firstSlot, false)
	_ = openVirtualSession(t, second, secondSlot, false)
	if _, err := second.OpenSession(secondSlot, raw.CKF_SERIAL_SESSION); !raw.IsError(err, raw.CKR_SESSION_COUNT) {
		t.Fatalf("target-wide virtual-session quota error = %v", err)
	}
}

func TestVirtualObjectQuotaCleansNativeObject(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4, MaxObjectsPerClient: 1}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)
	if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	create := func(label string) (raw.ObjectHandle, error) {
		return client.CreateObject(session, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
			raw.NewAttribute(raw.CKA_TOKEN, true),
			raw.NewAttribute(raw.CKA_PRIVATE, false),
			raw.NewAttribute(raw.CKA_LABEL, label),
		})
	}
	first, err := create("object-one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := create("object-two"); !raw.IsError(err, raw.CKR_TOKEN_RESOURCE_EXCEEDED) {
		t.Fatalf("object quota error = %v", err)
	}
	if _, err := client.GetObjectSize(session, first); err != nil {
		t.Fatalf("existing object corrupted by quota rollback: %v", err)
	}
}

func TestMaintenanceOperationsAreDisabledByDefault(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)
	for name, call := range map[string]func() error{
		"InitToken": func() error { return client.InitToken(slot, []byte("1234"), "label") },
		"InitPIN":   func() error { return client.InitPIN(session, []byte("1234")) },
		"SetPIN":    func() error { return client.SetPIN(session, []byte("old"), []byte("new")) },
	} {
		if err := call(); !raw.IsError(err, raw.CKR_FUNCTION_NOT_SUPPORTED) {
			t.Fatalf("%s error = %v", name, err)
		}
	}
}

func TestPinnedSessionIdleExpirationReleasesPhysicalLease(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{
		MaxPhysicalTotal: 4, MaxPinned: 2,
		PinnedOperationIdleTimeout: time.Second,
	}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	sessionHandle := openVirtualSession(t, client, slot, true)
	key, err := client.CreateObject(sessionHandle, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.EncryptInit(sessionHandle, []*raw.Mechanism{raw.NewMechanism(raw.CKM_AES_CBC, nil)}, key); err != nil {
		t.Fatal(err)
	}

	harness.server.targetsMu.RLock()
	target := harness.server.targets["mock-hsm"]
	harness.server.targetsMu.RUnlock()
	target.clientsMu.Lock()
	logical := target.clients[client.id]
	target.clientsMu.Unlock()
	virtual, err := logical.session(sessionHandle)
	if err != nil {
		t.Fatal(err)
	}
	virtual.mu.Lock()
	virtual.lastUsed = time.Now().Add(-2 * time.Hour)
	virtual.mu.Unlock()
	target.sweepClients(context.Background())

	if _, err := client.GetSessionInfo(sessionHandle); !raw.IsError(err, raw.CKR_SESSION_HANDLE_INVALID) {
		t.Fatalf("expired pinned session error = %v", err)
	}
	stats, _ := harness.server.TargetStats("mock-hsm")
	if stats.PinnedSessions != 0 || stats.VirtualSessions != 0 {
		t.Fatalf("expired pinned session leaked resources: %+v", stats)
	}
}

// The reaper must never refresh a client's idle clock: a sessionless client
// whose lastUse has passed ClientIdleTimeout is reclaimed, and one still inside
// the timeout keeps its original timestamp so it can age out later. Refreshing
// lastUsed during the sweep would make sessionless clients immortal and block
// drain accounting forever.
func TestSessionlessClientIdleExpiryClock(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{
		MaxPhysicalTotal: 4, ClientIdleTimeout: time.Hour,
	}, nil)
	client := openRemoteRaw(t, harness.target)

	harness.server.targetsMu.RLock()
	target := harness.server.targets["mock-hsm"]
	harness.server.targetsMu.RUnlock()
	target.clientsMu.Lock()
	logical := target.clients[client.id]
	target.clientsMu.Unlock()
	if logical == nil {
		t.Fatal("remote client did not establish a logical client")
	}

	stale := time.Now().Add(-30 * time.Minute)
	logical.stateMu.Lock()
	logical.lastUsed = stale
	logical.stateMu.Unlock()
	target.sweepClients(context.Background())
	logical.stateMu.Lock()
	lastUsed := logical.lastUsed
	logical.stateMu.Unlock()
	if !lastUsed.Equal(stale) {
		t.Fatal("reaper refreshed the idle clock of a sessionless client")
	}

	logical.stateMu.Lock()
	logical.lastUsed = time.Now().Add(-2 * time.Hour)
	logical.stateMu.Unlock()
	target.sweepClients(context.Background())
	if got := target.clientCount(); got != 0 {
		t.Fatalf("sessionless client past ClientIdleTimeout = %d, want 0", got)
	}
}

func TestCodecHandshakeRejectsMismatchedRegistries(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, func(config *TargetConfig) {
		config.Codecs = []ParameterCodec{proxyTestCodec{}}
	})
	if _, err := Open(context.Background(), harness.target); err == nil || !stringsContains(err.Error(), "parameter codec mismatch") {
		t.Fatalf("codec mismatch error = %v", err)
	}

	matching := harness.target
	matching.Codecs = []ParameterCodec{proxyTestCodec{}}
	client := openRemoteRaw(t, matching)
	if _, err := client.GetInfo(); err != nil {
		t.Fatal(err)
	}
}

func TestCodecHandshakeAcceptsClientCodecSuperset(t *testing.T) {
	// The client drives every invocation, so offering codecs beyond the
	// broker's published set is inert: the server never sends a parameter the
	// client cannot decode, and a client parameter outside the broker's set
	// fails at invoke time rather than at the handshake.
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	superset := harness.target
	superset.Codecs = []ParameterCodec{proxyTestCodec{}}
	client := openRemoteRaw(t, superset)
	if _, err := client.GetInfo(); err != nil {
		t.Fatalf("superset client GetInfo: %v", err)
	}
}

func TestTargetNormalizationDoesNotDuplicateVendorCodecs(t *testing.T) {
	target := Target{
		ConfigID: "config", Revision: "revision", Endpoints: []string{"127.0.0.1:1"}, Route: "route",
		AllowInsecure: true, Vendors: []pkcs11.VendorModule{proxyCodecVendor{}},
	}
	first := target.normalized()
	second := first.normalized()
	for _, candidate := range []Target{first, second} {
		registry, err := NewCodecRegistry(combinedCodecs(candidate.Codecs, candidate.Vendors)...)
		if err != nil {
			t.Fatal(err)
		}
		if descriptors := registry.Descriptors(); len(descriptors) != 1 || descriptors[0].ID != (proxyTestCodec{}).ID() {
			t.Fatalf("codec descriptors = %#v", descriptors)
		}
	}
}

func TestTargetSecurityContextIdentityIsRequiredForOpaqueClientPolicy(t *testing.T) {
	for name, target := range map[string]Target{
		"tls":    {ConfigID: "c", Revision: "r", Endpoints: []string{"e"}, Route: "t", TLS: &tls.Config{}},
		"auth":   {ConfigID: "c", Revision: "r", Endpoints: []string{"e"}, Route: "t", AllowInsecure: true, Auth: func(context.Context) ([]byte, error) { return nil, nil }},
		"dialer": {ConfigID: "c", Revision: "r", Endpoints: []string{"e"}, Route: "t", AllowInsecure: true, Dialer: &net.Dialer{}},
	} {
		if err := target.validate(); err == nil || !stringsContains(err.Error(), "SecurityContextID") {
			t.Fatalf("%s validation error = %v", name, err)
		}
		target.SecurityContextID = "workload-policy-v1"
		if err := target.validate(); err != nil {
			t.Fatalf("%s valid target: %v", name, err)
		}
	}
}

func TestTransportRejectsOversizedFrameBeforeAllocation(t *testing.T) {
	frame := []byte{0, 0, 4, 0}
	var req request
	if err := readMessage(bytesReader(frame), &req, 128); err == nil || !stringsContains(err.Error(), "maximum") {
		t.Fatalf("oversized frame error = %v", err)
	}
}

func TestMultipleTargetsRemainFullyIsolated(t *testing.T) {
	moduleA := buildProxyMockModule(t)
	moduleB := buildProxyMockModule(t)
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &instrumentedListener{Listener: base}
	newConfig := func(id, module string) TargetConfig {
		return TargetConfig{
			ID: id, Revision: "revision-1",
			Client: pkcs11.Config{
				Module:  pkcs11.LocalModule(module),
				Vendors: []pkcs11.VendorModule{testProxyVendor},
			},
			Sessions: SessionBudget{MaxPhysicalTotal: 3},
			Login: LoginPolicy{
				PhysicalPIN: pkcs11.StaticPIN("1234"),
				Authenticate: func(_ context.Context, attempt LoginAttempt) error {
					if string(attempt.PIN) != "1234" {
						return raw.Error(raw.CKR_PIN_INCORRECT)
					}
					return nil
				},
				AllowedUserTypes: []uint{raw.CKU_USER},
			},
		}
	}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener: listener, AllowInsecure: true, MaxConnections: 32,
	}, newConfig("target-a", moduleA), newConfig("target-b", moduleB))
	if err != nil {
		_ = base.Close()
		t.Fatal(err)
	}
	serveContext, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveContext) }()
	t.Cleanup(func() {
		cancel()
		if err := server.Close(context.Background()); err != nil {
			t.Errorf("close multi-target server: %v", err)
		}
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("serve multi-target proxy: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("multi-target proxy Serve did not stop")
		}
	})

	remoteTarget := func(route string) Target {
		return Target{
			ConfigID: "db-" + route, Revision: "revision-1",
			Endpoints: []string{base.Addr().String()}, Route: route,
			AllowInsecure: true, RequestTimeout: 5 * time.Second,
			Vendors: []pkcs11.VendorModule{testProxyVendor},
		}
	}
	clientA := openRemoteRaw(t, remoteTarget("target-a"))
	clientB := openRemoteRaw(t, remoteTarget("target-b"))
	slotA := remoteSlot(t, clientA)
	slotB := remoteSlot(t, clientB)
	sessionA := openVirtualSession(t, clientA, slotA, true)
	sessionB := openVirtualSession(t, clientB, slotB, true)

	if err := clientA.Login(sessionA, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	if got := diagnostic(t, clientA, slotA, mockDiagLoginCalls); got != 1 {
		t.Fatalf("target A physical login calls = %d, want 1", got)
	}
	if got := diagnostic(t, clientB, slotB, mockDiagLoginCalls); got != 0 {
		t.Fatalf("target A login changed target B physical state: %d", got)
	}
	infoB, err := clientB.GetSessionInfo(sessionB)
	if err != nil {
		t.Fatal(err)
	}
	if infoB.State != raw.State(raw.CKS_RW_PUBLIC_SESSION) {
		t.Fatalf("target B logical state = %d, want public", infoB.State)
	}

	objectA, err := clientA.CreateObject(sessionA, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, false),
		raw.NewAttribute(raw.CKA_LABEL, "target-a-object"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientB.GetObjectSize(sessionB, objectA); !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
		t.Fatalf("target A object handle crossed into target B: %v", err)
	}
	statsA, _ := server.TargetStats("target-a")
	statsB, _ := server.TargetStats("target-b")
	if statsA.Authenticated != 1 || statsB.Authenticated != 0 || statsA.VirtualSessions != 1 || statsB.VirtualSessions != 1 {
		t.Fatalf("target stats are not isolated: A=%+v B=%+v", statsA, statsB)
	}
}

func TestContextCancellationClosesRequestConnection(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, false)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := client.WithContext(ctx, func(module raw.Module) error {
		_, callErr := module.GenerateRandom(session, mockSlowRandomLength)
		return callErr
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled request error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 120*time.Millisecond {
		t.Fatalf("canceled request returned after %s; connection was not interrupted", elapsed)
	}

	// The native provider call is not portably cancellable. Give it time to
	// finish and verify its physical lease returns to the bounded pool.
	deadline := time.Now().Add(time.Second)
	for {
		stats, _ := harness.server.TargetStats("mock-hsm")
		if stats.PhysicalActive <= 1 && stats.QueuedRequests == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("canceled request did not drain: %+v", stats)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLogicalClientIDIsBoundToAuthenticatedPrincipal(t *testing.T) {
	module := buildProxyMockModule(t)
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &instrumentedListener{Listener: base}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener:      listener,
		AllowInsecure: true,
		Authorizer: func(_ context.Context, identity RequestIdentity) (string, error) {
			if len(identity.Auth) == 0 {
				return "", errors.New("missing workload identity")
			}
			return string(identity.Auth), nil
		},
	}, TargetConfig{
		ID:       "principal-hsm",
		Revision: "revision-1",
		Client: pkcs11.Config{
			Module:  pkcs11.LocalModule(module),
			Vendors: []pkcs11.VendorModule{testProxyVendor},
		},
		Sessions: SessionBudget{MaxPhysicalTotal: 3},
		Login: LoginPolicy{
			PhysicalPIN: pkcs11.StaticPIN("1234"),
			Authenticate: func(_ context.Context, attempt LoginAttempt) error {
				if string(attempt.PIN) != "1234" {
					return raw.Error(raw.CKR_PIN_INCORRECT)
				}
				return nil
			},
		},
	})
	if err != nil {
		_ = base.Close()
		t.Fatal(err)
	}
	serveContext, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveContext) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close(context.Background())
		<-serveDone
	})

	newTarget := func(principal string) Target {
		return Target{
			ConfigID: "config-" + principal, Revision: "revision-1",
			Endpoints: []string{base.Addr().String()}, Route: "principal-hsm",
			AllowInsecure: true, SecurityContextID: principal,
			Auth:    func(context.Context) ([]byte, error) { return []byte(principal), nil },
			Vendors: []pkcs11.VendorModule{testProxyVendor},
		}
	}
	first := openRemoteRaw(t, newTarget("workload-a"))
	second, err := Open(context.Background(), newTarget("workload-b"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()

	// A client ID is not a standalone bearer credential. Even with the exact ID
	// and target epoch, a different authenticated principal cannot enter the
	// first workload's logical Cryptoki application.
	second.id = first.id
	if err := second.Initialize(); err == nil || !stringsContains(err.Error(), "client_identity_mismatch") {
		t.Fatalf("cross-principal client-ID reuse error = %v", err)
	}
}

func TestClientCloseDrainsInFlightCallsBeforeReleasingSessions(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, false)

	callDone := make(chan error, 1)
	go func() {
		_, err := client.GenerateRandom(session, mockSlowRandomLength)
		callDone <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for diagnostic(t, client, slot, mockDiagOpenSessions) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("slow request did not acquire a physical session")
		}
		time.Sleep(5 * time.Millisecond)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	if err := <-callDone; err != nil {
		t.Fatalf("in-flight call failed during client close: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("client close: %v", err)
	}
	stats, ok := harness.server.TargetStats("mock-hsm")
	if !ok {
		t.Fatal("target stats unavailable")
	}
	if stats.Clients != 0 || stats.VirtualSessions != 0 || stats.PinnedSessions != 0 {
		t.Fatalf("client close leaked broker state: %+v", stats)
	}
}

func TestServeMayBeCalledOnlyOnce(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, nil)
	deadline := time.Now().Add(5 * time.Second)
	for !harness.server.serving.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !harness.server.serving.Load() {
		t.Fatal("initial Serve did not start")
	}
	err := harness.server.Serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "only once") {
		t.Fatalf("second Serve error = %v, want one-shot Serve rejection", err)
	}
}

func TestProtectedAuthenticationPathDoesNotRequirePhysicalPINProvider(t *testing.T) {
	module := buildProxyMockModuleWithFlags(t, "-DMOCK_PROTECTED_AUTH_PATH=1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener:      listener,
		AllowInsecure: true,
	}, TargetConfig{
		ID:       "protected-path",
		Revision: "revision-1",
		Client: pkcs11.Config{
			Module:  pkcs11.LocalModule(module),
			Vendors: []pkcs11.VendorModule{testProxyVendor},
		},
		Sessions: SessionBudget{MaxPhysicalTotal: 4},
		Login: LoginPolicy{
			Authenticate:       func(context.Context, LoginAttempt) error { return nil },
			EagerPhysicalLogin: true,
		},
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		if err := server.Close(context.Background()); err != nil {
			t.Errorf("close server: %v", err)
		}
		if err := <-serveDone; err != nil {
			t.Errorf("serve: %v", err)
		}
	})

	client, err := Open(context.Background(), Target{
		ConfigID: "protected-path-config", Revision: "revision-1",
		Endpoints: []string{listener.Addr().String()}, Route: "protected-path",
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}
	slot := remoteSlot(t, client)
	session, err := client.OpenSession(slot, raw.CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Login(session, raw.CKU_USER, []byte("logical-only")); err != nil {
		t.Fatalf("logical login through protected physical path: %v", err)
	}
}

func TestClientActivatedPhysicalLoginRequiresNoServerPIN(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
	})
	clientA := openRemoteRaw(t, harness.target)
	clientB := openRemoteRaw(t, harness.target)
	slotA := remoteSlot(t, clientA)
	slotB := remoteSlot(t, clientB)
	sessionA := openVirtualSession(t, clientA, slotA, true)
	sessionB := openVirtualSession(t, clientB, slotB, true)

	if got := diagnostic(t, clientA, slotA, mockDiagLoginCalls); got != 0 {
		t.Fatalf("physical logins before client activation = %d, want 0", got)
	}
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatalf("first client activation: %v", err)
	}
	if got := diagnostic(t, clientA, slotA, mockDiagLoginCalls); got != 1 {
		t.Fatalf("physical logins after first activation = %d, want 1", got)
	}
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatalf("second logical login: %v", err)
	}
	if got := diagnostic(t, clientB, slotB, mockDiagLoginCalls); got != 1 {
		t.Fatalf("second pod caused another physical login: %d", got)
	}
	stats, ok := harness.server.TargetStats("mock-hsm")
	if !ok {
		t.Fatal("target stats unavailable")
	}
	if stats.Activation.State != ActivationActive || stats.Activation.Generation == 0 {
		t.Fatalf("activation status = %+v, want active generation", stats.Activation)
	}
	if stats.Authenticated != 2 {
		t.Fatalf("authenticated clients = %d, want 2", stats.Authenticated)
	}
}

func TestConcurrentClientActivationCollapsesToOnePhysicalPINAttempt(t *testing.T) {
	var logicalAuthentications atomic.Int64
	var activationAuthorizations atomic.Int64
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 6, MaxClients: 64}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
		// The client application has already audited the PIN. The HSM itself is
		// authoritative for the first physical activation attempt.
		config.Login.Authenticate = func(context.Context, LoginAttempt) error {
			logicalAuthentications.Add(1)
			return nil
		}
		config.Authorize = func(_ context.Context, request AuthorizationRequest) error {
			if request.PhysicalActivation {
				activationAuthorizations.Add(1)
			}
			return nil
		}
	})

	const pods = 24
	clients := make([]*Client, 0, pods)
	sessions := make([]raw.SessionHandle, 0, pods)
	for range pods {
		client := openRemoteRaw(t, harness.target)
		slot := remoteSlot(t, client)
		clients = append(clients, client)
		sessions = append(sessions, openVirtualSession(t, client, slot, true))
	}

	start := make(chan struct{})
	errs := make(chan error, pods)
	var wait sync.WaitGroup
	for index := range clients {
		wait.Go(func() {
			<-start
			errs <- clients[index].Login(sessions[index], raw.CKU_USER, []byte("1234"))
		})
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent login: %v", err)
		}
	}
	if got := diagnostic(t, clients[0], remoteSlot(t, clients[0]), mockDiagLoginCalls); got != 1 {
		t.Fatalf("concurrent pods caused %d physical PIN attempts, want 1", got)
	}
	if got := logicalAuthentications.Load(); got != pods {
		t.Fatalf("logical authentication callbacks = %d, want %d", got, pods)
	}
	if got := activationAuthorizations.Load(); got != 1 {
		t.Fatalf("physical activation authorization callbacks = %d, want 1", got)
	}
}

func TestConcurrentFailedClientActivationIsCollapsedAndRetryable(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4, MaxClients: 32}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
		config.Login.Authenticate = func(context.Context, LoginAttempt) error { return nil }
		config.Login.ActivationFailureCooldown = 100 * time.Millisecond
	})

	const pods = 12
	clients := make([]*Client, 0, pods)
	sessions := make([]raw.SessionHandle, 0, pods)
	for range pods {
		client := openRemoteRaw(t, harness.target)
		slot := remoteSlot(t, client)
		clients = append(clients, client)
		sessions = append(sessions, openVirtualSession(t, client, slot, true))
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	errs := make(chan error, pods)
	for index := range clients {
		wait.Go(func() {
			<-start
			errs <- clients[index].Login(sessions[index], raw.CKU_USER, []byte("bad!"))
		})
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
			t.Fatalf("failed activation error = %v, want CKR_PIN_INCORRECT", err)
		}
	}
	if got := diagnostic(t, clients[0], remoteSlot(t, clients[0]), mockDiagLoginCalls); got != 1 {
		t.Fatalf("failed activation wave caused %d physical attempts, want 1", got)
	}

	time.Sleep(120 * time.Millisecond)
	if err := clients[0].Login(sessions[0], raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatalf("activation retry with correct PIN: %v", err)
	}
	if got := diagnostic(t, clients[0], remoteSlot(t, clients[0]), mockDiagLoginCalls); got != 2 {
		t.Fatalf("physical attempts after retry = %d, want 2", got)
	}
}

func TestClientActivatedLoginCredentialIsWipedAfterCallbacks(t *testing.T) {
	var retained []byte
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
		config.Login.Authenticate = func(_ context.Context, attempt LoginAttempt) error {
			retained = attempt.PIN
			return nil
		}
	})
	client := openRemoteRaw(t, harness.target)
	session := openVirtualSession(t, client, remoteSlot(t, client), true)
	if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	if len(retained) != 4 {
		t.Fatalf("retained callback buffer length = %d, want 4", len(retained))
	}
	for index, value := range retained {
		if value != 0 {
			t.Fatalf("logical callback PIN byte %d was not wiped", index)
		}
	}
}

func TestClientActivatedTargetRejectsSessionScopedVendor(t *testing.T) {
	module := buildProxyMockModule(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	_, err = NewServer(context.Background(), ServerConfig{Listener: listener, AllowInsecure: true}, TargetConfig{
		ID: "session-login", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxySessionVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 4},
		Login: LoginPolicy{
			Mode:         PhysicalLoginClientActivated,
			Authenticate: func(context.Context, LoginAttempt) error { return nil },
		},
	})
	if !errors.Is(err, ErrClientActivationUnsupported) {
		t.Fatalf("session-scoped client activation error = %v, want ErrClientActivationUnsupported", err)
	}
}

func TestClientActivatedTargetRequiresExplicitMode(t *testing.T) {
	module := buildProxyMockModule(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	_, err = NewServer(context.Background(), ServerConfig{Listener: listener, AllowInsecure: true}, TargetConfig{
		ID: "missing-mode", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 4},
		Login:    LoginPolicy{Authenticate: func(context.Context, LoginAttempt) error { return nil }},
	})
	if err == nil || !strings.Contains(err.Error(), string(PhysicalLoginClientActivated)) {
		t.Fatalf("missing mode error = %v, want explicit client-activated guidance", err)
	}
}

func TestClientActivatedTargetFailsClosedAfterPhysicalLoginLoss(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
	})
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)
	if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	privateObject, err := client.CreateObject(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_PRIVATE, true),
		raw.NewAttribute(raw.CKA_LABEL, "activation-generation-private-object"),
		raw.NewAttribute(raw.CKA_ID, []byte{4, 2}),
	})
	if err != nil {
		t.Fatal(err)
	}

	harness.server.targetsMu.RLock()
	target := harness.server.targets["mock-hsm"]
	harness.server.targetsMu.RUnlock()
	if target == nil {
		t.Fatal("target unavailable")
	}
	// Simulate actual token-wide login loss, then invalidate the broker's
	// activation generation. No PIN is retained for automatic recovery.
	if err := target.control.Call(context.Background(), "test-physical-logout", func(module raw.Module, native raw.SessionHandle) error {
		return module.Logout(native)
	}); err != nil {
		t.Fatal(err)
	}
	target.invalidatePhysicalLogin()

	info, err := client.GetSessionInfo(session)
	if err != nil {
		t.Fatal(err)
	}
	if info.State != raw.State(raw.CKS_RW_PUBLIC_SESSION) {
		t.Fatalf("session state after activation loss = %d, want public", info.State)
	}
	if _, err := client.GetObjectSize(session, privateObject); !errors.Is(err, ErrActivationRequired) || !raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("private operation after activation loss = %v, want ErrActivationRequired and CKR_USER_NOT_LOGGED_IN", err)
	}
	// A private operation cannot silently relogin because the proxy retained no
	// credential. Re-login with a freshly audited PIN establishes a new generation.
	if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatalf("reactivation: %v", err)
	}
	if got := diagnostic(t, client, slot, mockDiagLoginCalls); got != 2 {
		t.Fatalf("physical login calls after reactivation = %d, want 2", got)
	}
}

func TestAuthenticationAndAuthorizationAreSeparateForClientActivation(t *testing.T) {
	module := buildProxyMockModule(t)
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &instrumentedListener{Listener: base}
	const workloadToken = "workload-token"
	var activationAuthorizations atomic.Int64
	server, err := NewServer(context.Background(), ServerConfig{
		Listener: listener, AllowInsecure: true,
		Authenticator: func(_ context.Context, identity RequestIdentity) (string, error) {
			if string(identity.Auth) != workloadToken {
				return "", errors.New("invalid workload token")
			}
			return "issuer-workload", nil
		},
	}, TargetConfig{
		ID: "authorized-activation", Revision: "revision-1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
		Sessions: SessionBudget{MaxPhysicalTotal: 4},
		Authorize: func(_ context.Context, request AuthorizationRequest) error {
			if request.Identity.Principal != "issuer-workload" {
				return errors.New("principal is not allowed")
			}
			if request.PhysicalActivation {
				activationAuthorizations.Add(1)
				if request.Operation != AuthorizationOperationActivateTarget {
					return errors.New("unexpected activation operation")
				}
			}
			return nil
		},
		Login: LoginPolicy{
			Mode:         PhysicalLoginClientActivated,
			Authenticate: func(context.Context, LoginAttempt) error { return nil },
		},
	})
	if err != nil {
		_ = base.Close()
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = server.Close(context.Background())
		if err := <-serveDone; err != nil {
			t.Errorf("serve: %v", err)
		}
	})

	target := Target{
		ConfigID: "authorized-config", Revision: "revision-1", Endpoints: []string{base.Addr().String()}, Route: "authorized-activation",
		AllowInsecure: true, SecurityContextID: "issuer-workload-token",
		Auth:    func(context.Context) ([]byte, error) { return []byte(workloadToken), nil },
		Vendors: []pkcs11.VendorModule{testProxyVendor},
	}
	client := openRemoteRaw(t, target)
	session := openVirtualSession(t, client, remoteSlot(t, client), true)
	if err := client.Login(session, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	if got := activationAuthorizations.Load(); got != 1 {
		t.Fatalf("physical activation authorization calls = %d, want 1", got)
	}
}

func TestManagedClientActivateSuppliesPhysicalPINToClientActivatedTarget(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
	})
	var providerCalls atomic.Int64
	managed, err := pkcs11.Open(context.Background(), pkcs11.Config{
		Module: RemoteModule(harness.target),
		Login:  pkcs11.LoginConfig{Mode: pkcs11.LoginManual},
		PIN: func(context.Context, pkcs11.PINRequest) (pkcs11.Secret, error) {
			providerCalls.Add(1)
			return pkcs11.NewSecret([]byte("1234")), nil
		},
		Sessions: pkcs11.SessionConfig{Max: 4, MaxTotal: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = managed.Close(context.Background()) }()
	if err := managed.Activate(context.Background()); err != nil {
		t.Fatalf("managed Activate: %v", err)
	}
	if got := providerCalls.Load(); got != 1 {
		t.Fatalf("managed PIN provider calls = %d, want exactly 1 audited activation", got)
	}

	rawClient, err := Open(context.Background(), harness.target)
	if err != nil {
		t.Fatal(err)
	}
	defer rawClient.Destroy()
	if err := rawClient.Initialize(); err != nil {
		t.Fatal(err)
	}
	if got := diagnostic(t, rawClient, remoteSlot(t, rawClient), mockDiagLoginCalls); got != 1 {
		t.Fatalf("managed activation physical login calls = %d, want 1", got)
	}
}

func TestActivationAuthorizationDenialPreventsPhysicalPINAttempt(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
		config.Authorize = func(_ context.Context, request AuthorizationRequest) error {
			if request.PhysicalActivation {
				return errors.New("activation requires elevated permission")
			}
			return nil
		}
	})
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)
	err := client.Login(session, raw.CKU_USER, []byte("1234"))
	remote, remoteOK := errors.AsType[*RemoteError](err)
	if !remoteOK || remote.Code != "forbidden" {
		t.Fatalf("activation authorization error = %v, want forbidden RemoteError", err)
	}
	if got := diagnostic(t, client, slot, mockDiagLoginCalls); got != 0 {
		t.Fatalf("denied activation reached physical C_Login %d times, want 0", got)
	}
}

func TestClientActivationAlreadyLoggedInIsInconclusive(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
	})

	harness.server.targetsMu.RLock()
	target := harness.server.targets["mock-hsm"]
	harness.server.targetsMu.RUnlock()
	if target == nil {
		t.Fatal("target unavailable")
	}
	// Create physical login state without updating the activation coordinator.
	// A subsequent client PIN cannot be considered verified when the HSM replies
	// only that the shared application is already logged in.
	if err := target.control.Call(context.Background(), "test-preexisting-login", func(module raw.Module, session raw.SessionHandle) error {
		return module.Login(session, raw.CKU_USER, []byte("1234"))
	}); err != nil {
		t.Fatal(err)
	}

	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)
	err := client.Login(session, raw.CKU_USER, []byte("1234"))
	if !errors.Is(err, ErrActivationInconclusive) || !raw.IsError(err, raw.CKR_USER_ALREADY_LOGGED_IN) {
		t.Fatalf("preexisting-login activation error = %v, want ErrActivationInconclusive and CKR_USER_ALREADY_LOGGED_IN", err)
	}
	stats, ok := harness.server.TargetStats("mock-hsm")
	if !ok {
		t.Fatal("target stats unavailable")
	}
	if stats.Activation.State != ActivationInactive {
		t.Fatalf("activation state = %q, want inactive", stats.Activation.State)
	}
}

func TestClientActivationDefaultCooldownPreventsRapidSequentialPINAttempts(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
		config.Login.Authenticate = func(context.Context, LoginAttempt) error { return nil }
		// Zero deliberately exercises the safe default cooldown.
		config.Login.ActivationFailureCooldown = 0
	})
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, true)
	for attempt := range 2 {
		if err := client.Login(session, raw.CKU_USER, []byte("bad!")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
			t.Fatalf("failed activation %d = %v, want CKR_PIN_INCORRECT", attempt+1, err)
		}
	}
	if got := diagnostic(t, client, slot, mockDiagLoginCalls); got != 1 {
		t.Fatalf("rapid sequential failed activations caused %d physical attempts, want 1", got)
	}
}

// --- Client-PIN verification and rotation ---------------------------------

// testmockPINTarget returns a client-activated route bound to the in-memory
// module with PIN verification enabled, so tests can rotate or drop the token
// PIN through a second locally opened client on the shared module.
func testmockPINTarget(t *testing.T, source pkcs11.ModuleSource, mutate func(*TargetConfig)) TargetConfig {
	t.Helper()
	config := testmockBrokerConfig(source)
	config.Login.Mode = PhysicalLoginClientActivated
	config.Login.PhysicalPIN = nil
	config.Login.VerifyClientPIN = true
	if mutate != nil {
		mutate(&config)
	}
	return config
}

// testmockAdmin opens a direct managed client on the shared test module so a
// test can change the token PIN or drop physical login out-of-band — the same
// module instance the broker drives, resolved through the module registry.
func testmockAdmin(t *testing.T, source pkcs11.ModuleSource) *pkcs11.Client {
	t.Helper()
	slot := raw.SlotID(1)
	client, err := pkcs11.Open(context.Background(), pkcs11.Config{
		Module: source, Token: pkcs11.TokenSelector{SlotID: &slot},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

func TestVerifyClientPINRefusesWrongPINAfterActivation(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
		config.Login.Authenticate = func(context.Context, LoginAttempt) error { return nil }
		config.Login.VerifyClientPIN = true
	})
	clientA := openRemoteRaw(t, harness.target)
	clientB := openRemoteRaw(t, harness.target)
	slotA, slotB := remoteSlot(t, clientA), remoteSlot(t, clientB)
	sessionA := openVirtualSession(t, clientA, slotA, true)
	sessionB := openVirtualSession(t, clientB, slotB, true)

	// The PIN the HSM accepts activates the target and arms the verifier.
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatalf("activation login: %v", err)
	}
	if got := diagnostic(t, clientA, slotA, mockDiagLoginCalls); got != 1 {
		t.Fatalf("physical logins = %d, want 1", got)
	}

	// A wrong PIN is refused in memory: no rotation is configured, so it can
	// never reach the HSM however old the activation is.
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("wrong-PIN login = %v, want CKR_PIN_INCORRECT", err)
	}
	if got := diagnostic(t, clientA, slotA, mockDiagLoginCalls); got != 1 {
		t.Fatalf("wrong PIN reached the HSM: physical logins = %d", got)
	}

	// A granted client re-logging in with a different PIN is verified before
	// the already-logged-in short circuit.
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("granted re-login with wrong PIN = %v, want CKR_PIN_INCORRECT", err)
	}
	if got := diagnostic(t, clientA, slotA, mockDiagLoginCalls); got != 1 {
		t.Fatalf("re-login reached the HSM: physical logins = %d", got)
	}

	// The right PIN earns a grant with no additional physical login; a repeat
	// login with it reports the already-logged-in state.
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatalf("right-PIN login: %v", err)
	}
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte("1234")); !raw.IsError(err, raw.CKR_USER_ALREADY_LOGGED_IN) {
		t.Fatalf("re-login with right PIN = %v, want CKR_USER_ALREADY_LOGGED_IN", err)
	}
	if got := diagnostic(t, clientA, slotA, mockDiagLoginCalls); got != 1 {
		t.Fatalf("physical logins = %d, want 1", got)
	}
}

// A wrong PIN that queues behind another caller's physical activation must not
// receive a grant from the shared result: once the leader's PIN arms the
// verifier, the queued login is rechecked against it and refused.
func TestVerifyClientPINRefusesPINQueuedBehindLeader(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 4}, func(config *TargetConfig) {
		config.Login.Mode = PhysicalLoginClientActivated
		config.Login.PhysicalPIN = nil
		config.Login.Authenticate = func(context.Context, LoginAttempt) error { return nil }
		config.Login.VerifyClientPIN = true
	})
	clientRight := openRemoteRaw(t, harness.target)
	clientWrong := openRemoteRaw(t, harness.target)
	slotRight, slotWrong := remoteSlot(t, clientRight), remoteSlot(t, clientWrong)
	sessionRight := openVirtualSession(t, clientRight, slotRight, true)
	sessionWrong := openVirtualSession(t, clientWrong, slotWrong, true)

	harness.server.targetsMu.RLock()
	broker := harness.server.targets["mock-hsm"]
	harness.server.targetsMu.RUnlock()

	// Occupy the control session so the leader's physical C_Login is held while
	// the wrong-PIN login queues as a follower on the activation attempt.
	release := make(chan struct{})
	held := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	go func() {
		_ = broker.callControl(context.Background(), "test-hold-control", false, func(raw.Module, raw.SessionHandle) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	rightErr := make(chan error, 1)
	go func() { rightErr <- clientRight.Login(sessionRight, raw.CKU_USER, []byte("1234")) }()

	// Wait until the right-PIN login leads the activation attempt, then send the
	// wrong-PIN login which queues on the shared attempt's completion.
	deadline := time.Now().Add(5 * time.Second)
	for broker.activation.snapshot().State != ActivationActivating {
		if time.Now().After(deadline) {
			t.Fatal("leader did not begin activation")
		}
		time.Sleep(time.Millisecond)
	}
	wrongErr := make(chan error, 1)
	go func() { wrongErr <- clientWrong.Login(sessionWrong, raw.CKU_USER, []byte("9999")) }()
	releaseOnce.Do(func() { close(release) })

	if err := <-rightErr; err != nil {
		t.Fatalf("right-PIN leader login: %v", err)
	}
	if err := <-wrongErr; !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("queued wrong PIN = %v, want CKR_PIN_INCORRECT", err)
	}
	if got := diagnostic(t, clientRight, slotRight, mockDiagLoginCalls); got != 1 {
		t.Fatalf("physical logins = %d, want exactly 1", got)
	}

	// The refused client is not locked out: the right PIN still earns a grant
	// with no further physical login, and another wrong PIN is refused.
	if err := clientWrong.Login(sessionWrong, raw.CKU_USER, []byte("1234")); err != nil {
		t.Fatalf("right-PIN login after refusal: %v", err)
	}
	if err := clientWrong.Login(sessionWrong, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("granted client re-login with wrong PIN = %v, want CKR_PIN_INCORRECT", err)
	}
	if got := diagnostic(t, clientRight, slotRight, mockDiagLoginCalls); got != 1 {
		t.Fatalf("physical logins = %d, want exactly 1", got)
	}
}

func TestVerifyClientPINRearmsAfterActivationLoss(t *testing.T) {
	source := testmock.Source{Name: "pin-rearm", Tokens: 1}
	_, address := newTestmockBroker(t, testmockPINTarget(t, source, nil))
	target := haTarget(address)

	clientA := openRemoteRaw(t, target)
	sessionA := openVirtualSession(t, clientA, remoteSlot(t, clientA), true)
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatalf("activation login: %v", err)
	}
	clientB := openRemoteRaw(t, target)
	sessionB := openVirtualSession(t, clientB, remoteSlot(t, clientB), true)
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("wrong PIN = %v, want CKR_PIN_INCORRECT", err)
	}

	// Out-of-band on the shared module: rotate the PIN, then drop the physical
	// login the broker anchored.
	admin := testmockAdmin(t, source)
	lease, err := admin.AcquireRawSession(context.Background(), pkcs11.RawSessionOptions{ReadWrite: true, Operation: "out-of-band-rotation"})
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Call(context.Background(), "oob-setpin", func(module raw.Module, session raw.SessionHandle) error {
		return module.SetPIN(session, []byte(testmock.DefaultPIN), []byte("5678"))
	}); err != nil {
		t.Fatalf("out-of-band SetPIN: %v", err)
	}
	if err := lease.Call(context.Background(), "oob-logout", func(module raw.Module, session raw.SessionHandle) error {
		return module.Logout(session)
	}); err != nil {
		t.Fatalf("out-of-band Logout: %v", err)
	}
	_ = lease.Close(context.Background())

	// The next privileged request discovers the lost login and invalidates the
	// activation — clearing the armed digest.
	_, err = clientA.CreateObject(sessionA, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_PRIVATE, true),
		raw.NewAttribute(raw.CKA_LABEL, "requires-login"),
	})
	if err == nil || !errors.Is(err, ErrActivationRequired) {
		t.Fatalf("post-logout private write = %v, want ErrActivationRequired", err)
	}

	// The verifier is cleared, so the next activation is armed from whatever
	// PIN the HSM accepts now — the rotated one.
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("5678")); err != nil {
		t.Fatalf("re-activation with rotated PIN: %v", err)
	}
	// And the old PIN no longer matches the freshly armed digest.
	clientC := openRemoteRaw(t, target)
	sessionC := openVirtualSession(t, clientC, remoteSlot(t, clientC), true)
	if err := clientC.Login(sessionC, raw.CKU_USER, []byte(testmock.DefaultPIN)); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("old PIN after re-activation = %v, want CKR_PIN_INCORRECT", err)
	}
}

func TestVerifyClientPINBrokeredSetPINRearms(t *testing.T) {
	source := testmock.Source{Name: "pin-setpin", Tokens: 1}
	_, address := newTestmockBroker(t, testmockPINTarget(t, source, func(config *TargetConfig) {
		config.Maintenance.Enabled = true
	}))
	target := haTarget(address)

	clientA := openRemoteRaw(t, target)
	sessionA := openVirtualSession(t, clientA, remoteSlot(t, clientA), true)
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatalf("activation login: %v", err)
	}
	// A successful C_SetPIN through the broker re-arms the verifier with the
	// new PIN without another physical activation.
	if err := clientA.SetPIN(sessionA, []byte(testmock.DefaultPIN), []byte("5678")); err != nil {
		t.Fatalf("brokered SetPIN: %v", err)
	}
	clientB := openRemoteRaw(t, target)
	sessionB := openVirtualSession(t, clientB, remoteSlot(t, clientB), true)
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte(testmock.DefaultPIN)); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("old PIN after SetPIN = %v, want CKR_PIN_INCORRECT", err)
	}
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("5678")); err != nil {
		t.Fatalf("new PIN after SetPIN: %v", err)
	}
}

func TestPINRotationIntervalAdmitsOutOfBandRotation(t *testing.T) {
	source := testmock.Source{Name: "pin-rotation", Tokens: 1}
	var activations atomic.Int64
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener: listener, AllowInsecure: true,
		Audit: AuditSinkFunc(func(_ context.Context, event AuditEvent) {
			if event.Type == "activation" {
				activations.Add(1)
			}
		}),
	}, testmockPINTarget(t, source, func(config *TargetConfig) {
		config.Login.PINRotationInterval = 50 * time.Millisecond
	}))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	go func() { _ = server.Serve(context.Background()) }()
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	target := haTarget(listener.Addr().String())

	clientA := openRemoteRaw(t, target)
	sessionA := openVirtualSession(t, clientA, remoteSlot(t, clientA), true)
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatalf("activation login: %v", err)
	}
	if got := activations.Load(); got != 1 {
		t.Fatalf("physical activations = %d, want 1", got)
	}

	// Inside the interval a mismatch is refused without touching the HSM.
	clientB := openRemoteRaw(t, target)
	sessionB := openVirtualSession(t, clientB, remoteSlot(t, clientB), true)
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("in-interval mismatch = %v, want CKR_PIN_INCORRECT", err)
	}
	if got := activations.Load(); got != 1 {
		t.Fatalf("in-interval mismatch reached the HSM: activations = %d", got)
	}

	// Rotate the token PIN out-of-band while the broker still arms the old one.
	admin := testmockAdmin(t, source)
	lease, err := admin.AcquireRawSession(context.Background(), pkcs11.RawSessionOptions{ReadWrite: true, Operation: "out-of-band-rotation"})
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Call(context.Background(), "oob-setpin", func(module raw.Module, session raw.SessionHandle) error {
		return module.SetPIN(session, []byte(testmock.DefaultPIN), []byte("5678"))
	}); err != nil {
		t.Fatalf("out-of-band SetPIN: %v", err)
	}
	_ = lease.Close(context.Background())

	// Once the last physical attempt is older than the interval, the caller
	// holding the new PIN leads exactly one fresh activation, which re-arms
	// the verifier.
	time.Sleep(75 * time.Millisecond)
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("5678")); err != nil {
		t.Fatalf("rotated-PIN activation: %v", err)
	}
	if got := activations.Load(); got != 2 {
		t.Fatalf("rotation activations = %d, want 2", got)
	}
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte(testmock.DefaultPIN)); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("old PIN after rotation = %v, want CKR_PIN_INCORRECT", err)
	}
}

func TestPINRotationIntervalFailedAttemptEntersCooldown(t *testing.T) {
	source := testmock.Source{Name: "pin-rotation-fail", Tokens: 1}
	var activations atomic.Int64
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener: listener, AllowInsecure: true,
		Audit: AuditSinkFunc(func(_ context.Context, event AuditEvent) {
			if event.Type == "activation" || event.Type == "activation_failure" {
				activations.Add(1)
			}
		}),
	}, testmockPINTarget(t, source, func(config *TargetConfig) {
		config.Login.PINRotationInterval = 50 * time.Millisecond
		config.Login.ActivationFailureCooldown = 75 * time.Millisecond
	}))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	go func() { _ = server.Serve(context.Background()) }()
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	target := haTarget(listener.Addr().String())

	clientA := openRemoteRaw(t, target)
	sessionA := openVirtualSession(t, clientA, remoteSlot(t, clientA), true)
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatalf("activation login: %v", err)
	}

	// The PIN was not rotated, so a stale mismatch spends exactly one physical
	// attempt on the caller's wrong PIN and enters the failure cooldown.
	time.Sleep(75 * time.Millisecond)
	clientB := openRemoteRaw(t, target)
	sessionB := openVirtualSession(t, clientB, remoteSlot(t, clientB), true)
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("stale wrong PIN = %v, want CKR_PIN_INCORRECT", err)
	}
	if got := activations.Load(); got != 2 {
		t.Fatalf("rotation attempts = %d, want exactly 2", got)
	}

	// During the cooldown the right PIN is refused without another attempt —
	// the failed rotation cleared the verifier, so this is the activation
	// cooldown answering, not PIN verification.
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte(testmock.DefaultPIN)); err == nil {
		t.Fatal("login during failure cooldown succeeded")
	}
	if got := activations.Load(); got != 2 {
		t.Fatalf("cooldown allowed another attempt: %d", got)
	}

	// After the cooldown the right PIN activates again and re-arms.
	time.Sleep(100 * time.Millisecond)
	if err := clientA.Login(sessionA, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatalf("post-cooldown right-PIN login: %v", err)
	}
	if got := activations.Load(); got != 3 {
		t.Fatalf("activations = %d, want 3", got)
	}
	if err := clientB.Login(sessionB, raw.CKU_USER, []byte("9999")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("wrong PIN after re-arm = %v, want CKR_PIN_INCORRECT", err)
	}
}

func TestVerifyClientPINRequiresClientActivatedMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*TargetConfig)
	}{
		{"server-managed", func(config *TargetConfig) {
			config.Login.VerifyClientPIN = true // PhysicalPIN remains set
		}},
		{"rotation-without-verify", func(config *TargetConfig) {
			config.Login.Mode = PhysicalLoginClientActivated
			config.Login.PhysicalPIN = nil
			config.Login.PINRotationInterval = time.Minute
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			module := buildProxyMockModule(t)
			config := TargetConfig{
				ID: "bad-policy", Revision: "revision-1",
				Client:   pkcs11.Config{Module: pkcs11.LocalModule(module), Vendors: []pkcs11.VendorModule{testProxyVendor}},
				Sessions: SessionBudget{MaxPhysicalTotal: 3},
				Login: LoginPolicy{
					PhysicalPIN:      pkcs11.StaticPIN("1234"),
					Authenticate:     func(context.Context, LoginAttempt) error { return nil },
					AllowedUserTypes: []uint{raw.CKU_USER},
				},
			}
			tc.mutate(&config)
			server, err := NewServer(context.Background(), ServerConfig{Listener: listener, AllowInsecure: true}, config)
			if err == nil {
				_ = server.Close(context.Background())
				t.Fatalf("NewServer accepted invalid login policy %q", tc.name)
			}
		})
	}
}

// --- Active-active multi-replica behavior ---------------------------------

// testmockBrokerConfig is a complete route binding to the in-memory test
// module. No vendor modules are configured, so both the broker registry and
// the client use the empty codec set — matching is trivially satisfied.
func testmockBrokerConfig(source pkcs11.ModuleSource) TargetConfig {
	slot := raw.SlotID(1)
	return TargetConfig{
		ID:       "shared-hsm",
		Revision: "v1",
		Client:   pkcs11.Config{Module: source, Token: pkcs11.TokenSelector{SlotID: &slot}},
		Sessions: SessionBudget{MaxPhysicalTotal: 8, MaxClients: 1024},
		Login: LoginPolicy{
			PhysicalPIN:      pkcs11.StaticPIN(testmock.DefaultPIN),
			Authenticate:     func(context.Context, LoginAttempt) error { return nil },
			AllowedUserTypes: []uint{raw.CKU_USER},
		},
	}
}

// newTestmockBroker starts a proxy replica on an ephemeral loopback port. The
// same ModuleSource in two brokers shares one virtual HSM through the managed
// registry — the same shape as two proxies in front of one HSM HA cluster.
func newTestmockBroker(t *testing.T, config TargetConfig) (*Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{Listener: listener, AllowInsecure: true}, config)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	go func() { _ = server.Serve(context.Background()) }()
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	return server, listener.Addr().String()
}

func haTarget(endpoints ...string) Target {
	return Target{
		ConfigID: "ha-test", Revision: "v1", Route: "shared-hsm",
		Endpoints: endpoints, AllowInsecure: true,
		ConnectTimeout: 300 * time.Millisecond, RequestTimeout: 5 * time.Second,
		MaxAttempts: 1,
	}
}

func TestMultiEndpointDistributionAndPinning(t *testing.T) {
	source := testmock.Source{Name: "ha-shared", Tokens: 2}
	config := testmockBrokerConfig(source)
	serverA, addrA := newTestmockBroker(t, config)
	serverB, addrB := newTestmockBroker(t, config)
	byEndpoint := map[string]*Server{addrA: serverA, addrB: serverB}

	const total = 60
	counts := map[string]int{}
	clients := make([]*Client, 0, total)
	defer func() {
		for _, client := range clients {
			_ = client.Close()
		}
	}()
	for range total {
		client, err := Open(context.Background(), haTarget(addrA, addrB))
		if err != nil {
			t.Fatal(err)
		}
		server, ok := byEndpoint[client.Endpoint()]
		if !ok {
			t.Fatalf("client pinned to unconfigured endpoint %q", client.Endpoint())
		}
		if client.ServerID() != server.InstanceID() {
			t.Fatalf("client server ID does not match its pinned endpoint")
		}
		counts[client.Endpoint()]++
		clients = append(clients, client)
	}
	if counts[addrA] == 0 || counts[addrB] == 0 {
		t.Fatalf("rendezvous distribution used only one replica: %v", counts)
	}
	if counts[addrA] < 10 || counts[addrB] < 10 {
		t.Fatalf("rendezvous distribution far from balanced: %v", counts)
	}
	// After Initialize each logical client lives on its pinned server only.
	for _, client := range clients {
		if err := client.Initialize(); err != nil {
			t.Fatal(err)
		}
	}
	if got := serverA.LogicalClients(); got != counts[addrA] {
		t.Fatalf("server A logical clients = %d, want %d", got, counts[addrA])
	}
	if got := serverB.LogicalClients(); got != counts[addrB] {
		t.Fatalf("server B logical clients = %d, want %d", got, counts[addrB])
	}
}

func TestOpenFailsOverToNextEndpoint(t *testing.T) {
	source := testmock.Source{Name: "ha-failover"}
	_, alive := newTestmockBroker(t, testmockBrokerConfig(source))
	deadListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := deadListener.Addr().String()
	_ = deadListener.Close()
	for range 8 {
		client, err := Open(context.Background(), haTarget(dead, alive))
		if err != nil {
			t.Fatal(err)
		}
		if client.Endpoint() != alive {
			t.Fatalf("client pinned %q, want surviving endpoint %q", client.Endpoint(), alive)
		}
		_ = client.Close()
	}
}

func TestPinnedClientReportsTargetLost(t *testing.T) {
	source := testmock.Source{Name: "ha-loss"}
	config := testmockBrokerConfig(source)
	serverA, addrA := newTestmockBroker(t, config)
	serverB, addrB := newTestmockBroker(t, config)

	client, err := Open(context.Background(), haTarget(addrA, addrB))
	if err != nil {
		t.Fatal(err)
	}
	pinned := client.Endpoint()
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}
	lost, surviving := serverA, serverB
	survivingAddr := addrB
	if pinned == addrB {
		lost, surviving = serverB, serverA
		survivingAddr = addrA
	}
	if err := lost.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetInfo(); !errors.Is(err, ErrTargetLost) {
		t.Fatalf("operation after replica loss = %v, want ErrTargetLost", err)
	}
	// The client never migrates: its endpoint is still the dead replica.
	if client.Endpoint() != pinned {
		t.Fatalf("client endpoint mutated to %q after replica loss", client.Endpoint())
	}
	// A brand-new logical client establishes against the surviving replica.
	replacement, err := Open(context.Background(), haTarget(addrA, addrB))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.Close() }()
	if replacement.Endpoint() != survivingAddr {
		t.Fatalf("replacement pinned %q, want surviving %q", replacement.Endpoint(), survivingAddr)
	}
	if replacement.ServerID() != surviving.InstanceID() {
		t.Fatal("replacement server ID does not match surviving replica")
	}
	if err := replacement.Initialize(); err != nil {
		t.Fatal(err)
	}
}

func TestWrongServerFencing(t *testing.T) {
	source := testmock.Source{Name: "ha-fence"}
	config := testmockBrokerConfig(source)
	serverA, _ := newTestmockBroker(t, config)
	serverB, addrB := newTestmockBroker(t, config)

	// A request envelope pinned to server A must be refused by server B before
	// it creates or touches logical-client state.
	connection, err := net.Dial("tcp", addrB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	req := request{
		Version: protocolVersion, Target: "shared-hsm", Revision: "v1",
		ClientID: [16]byte{1}, RequestID: [16]byte{2},
		ServerID: serverA.InstanceID(), Epoch: [16]byte{3},
		Method: "GetInfo",
	}
	if err := writeMessage(connection, req, defaultMaximumMessageSize); err != nil {
		t.Fatal(err)
	}
	var resp response
	if err := readMessage(connection, &resp, defaultMaximumMessageSize); err != nil {
		t.Fatal(err)
	}
	err = decodeError(resp.Error)
	remote, remoteOK := errors.AsType[*RemoteError](err)
	if !remoteOK || remote.Code != "wrong_server" {
		t.Fatalf("wrong-server response = %v, want wrong_server", err)
	}
	if !errors.Is(err, ErrTargetLost) {
		t.Fatalf("wrong_server error = %v, want it to map to ErrTargetLost", err)
	}
	if got := serverB.LogicalClients(); got != 0 {
		t.Fatalf("fenced request created %d logical clients on server B", got)
	}
}

func TestEpochFencingMapsTargetLost(t *testing.T) {
	source := testmock.Source{Name: "ha-epoch"}
	config := testmockBrokerConfig(source)
	server, addr := newTestmockBroker(t, config)
	client, err := Open(context.Background(), haTarget(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}
	// Re-publishing the route rotates the target epoch: state owned by the old
	// generation is unrecoverable even though the process itself survived.
	if err := server.ReplaceTarget(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetInfo(); !errors.Is(err, ErrTargetLost) {
		t.Fatalf("operation after epoch rotation = %v, want ErrTargetLost", err)
	}
}

func TestDrainingServerServesExistingAndRefusesNew(t *testing.T) {
	source := testmock.Source{Name: "ha-drain"}
	config := testmockBrokerConfig(source)
	serverA, addrA := newTestmockBroker(t, config)
	serverB, addrB := newTestmockBroker(t, config)

	// Establish one pinned client on A while it is active.
	existing, err := Open(context.Background(), haTarget(addrA))
	if err != nil {
		t.Fatal(err)
	}
	if err := existing.Initialize(); err != nil {
		t.Fatal(err)
	}
	if got := serverA.LogicalClients(); got != 1 {
		t.Fatalf("logical clients = %d, want 1", got)
	}

	serverA.Drain(context.Background())
	if serverA.State() != ServerDraining {
		t.Fatal("server did not enter draining state")
	}
	// The pinned client keeps working — drain refuses only new establishments.
	if _, err := existing.GetInfo(); err != nil {
		t.Fatalf("established request during drain failed: %v", err)
	}
	// New clients skip the draining replica even when it ranks first.
	for range 10 {
		fresh, err := Open(context.Background(), haTarget(addrA, addrB))
		if err != nil {
			t.Fatal(err)
		}
		if fresh.Endpoint() != addrB {
			t.Fatalf("new client pinned draining endpoint %q", fresh.Endpoint())
		}
		_ = fresh.Close()
	}
	// A single-endpoint Open against a draining broker fails without a logical
	// client ever being created.
	if _, err := Open(context.Background(), haTarget(addrA)); err == nil {
		t.Fatal("open against draining-only endpoint succeeded")
	} else if !strings.Contains(err.Error(), "draining") {
		t.Fatalf("draining open error = %v", err)
	}
	if got := serverA.LogicalClients(); got != 1 {
		t.Fatalf("drain probed endpoints created clients: %d", got)
	}
	// WaitDrained releases only when the established client goes away.
	blocked, cancelBlocked := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelBlocked()
	if err := serverA.WaitDrained(blocked); err == nil {
		t.Fatal("WaitDrained returned with a live client")
	}
	if err := existing.Close(); err != nil {
		t.Fatal(err)
	}
	drained, cancelDrained := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDrained()
	if err := serverA.WaitDrained(drained); err != nil {
		t.Fatalf("WaitDrained after client close: %v", err)
	}
	if got := serverA.LogicalClients(); got != 0 {
		t.Fatalf("logical clients after drain = %d", got)
	}
	_ = serverB
}

func TestDrainRaceDuringEstablishmentMapsTargetLost(t *testing.T) {
	source := testmock.Source{Name: "ha-drain-race"}
	config := testmockBrokerConfig(source)
	serverA, addrA := newTestmockBroker(t, config)
	_, addrB := newTestmockBroker(t, config)

	// Open performs only the describe probe: the endpoint is pinned but no
	// logical client exists yet. A drain beginning in that window must surface
	// as ErrTargetLost on the first request so callers reopen instead of
	// retrying a client the replica will never accept.
	client, err := Open(context.Background(), haTarget(addrA))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	serverA.Drain(context.Background())
	if err := client.Initialize(); !errors.Is(err, ErrTargetLost) {
		t.Fatalf("first request racing drain = %v, want ErrTargetLost", err)
	}
	if got := serverA.LogicalClients(); got != 0 {
		t.Fatalf("draining replica created %d logical clients", got)
	}
	// Recovery is a fresh Open, which skips the draining replica.
	replacement, err := Open(context.Background(), haTarget(addrA, addrB))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.Close() }()
	if replacement.Endpoint() != addrB {
		t.Fatalf("replacement pinned %q, want surviving %q", replacement.Endpoint(), addrB)
	}
	if err := replacement.Initialize(); err != nil {
		t.Fatal(err)
	}
}

// A connected client that goes quiet is evicted on the drain idle grace
// instead of pinning the replica for the whole ClientIdleTimeout. Clients
// still making requests keep working until they pause.
func TestDrainEvictsIdleClients(t *testing.T) {
	source := testmock.Source{Name: "ha-drain-idle"}
	config := testmockBrokerConfig(source)
	config.Sessions.ClientDrainIdleTimeout = 150 * time.Millisecond
	server, addr := newTestmockBroker(t, config)

	idle, err := Open(context.Background(), haTarget(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = idle.Close() }()
	if err := idle.Initialize(); err != nil {
		t.Fatal(err)
	}
	busy, err := Open(context.Background(), haTarget(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	if err := busy.Initialize(); err != nil {
		t.Fatal(err)
	}
	if got := server.LogicalClients(); got != 2 {
		t.Fatalf("logical clients = %d, want 2", got)
	}

	server.Drain(context.Background())
	// Keep the second client inside its grace window while the first goes
	// quiet: only the idle one may be reclaimed mid-drain.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := busy.GetInfo(); err != nil {
			t.Fatalf("active client failed during drain: %v", err)
		}
		if got := server.LogicalClients(); got == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := server.LogicalClients(); got != 1 {
		t.Fatalf("drain left %d clients, want only the active one", got)
	}
	if _, err := idle.GetInfo(); !errors.Is(err, ErrTargetLost) {
		t.Fatalf("evicted client request = %v, want ErrTargetLost", err)
	}
	// Once the last client also goes quiet the drain completes well inside
	// the configured drain timeout instead of waiting it out.
	drained, cancelDrained := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDrained()
	if err := server.WaitDrained(drained); err != nil {
		t.Fatalf("drain did not complete after all clients went idle: %v", err)
	}
}

func TestScaleUpKeepsExistingPins(t *testing.T) {
	source := testmock.Source{Name: "ha-scale"}
	config := testmockBrokerConfig(source)
	_, addrA := newTestmockBroker(t, config)
	_, addrB := newTestmockBroker(t, config)
	_, addrC := newTestmockBroker(t, config)

	var established []*Client
	for range 12 {
		client, err := Open(context.Background(), haTarget(addrA, addrB))
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Initialize(); err != nil {
			t.Fatal(err)
		}
		established = append(established, client)
	}
	defer func() {
		for _, client := range established {
			_ = client.Close()
		}
	}()
	// New clients opened after the endpoint set grows may select C, but every
	// established client keeps its original pin and keeps working.
	for _, client := range established {
		pinned := client.Endpoint()
		grown, err := Open(context.Background(), haTarget(addrA, addrB, addrC))
		if err != nil {
			t.Fatal(err)
		}
		switch grown.Endpoint() {
		case addrA, addrB, addrC:
		default:
			t.Fatalf("new client pinned unknown endpoint %q", grown.Endpoint())
		}
		_ = grown.Close()
		if client.Endpoint() != pinned {
			t.Fatalf("existing client endpoint moved %q -> %q", pinned, client.Endpoint())
		}
		if _, err := client.GetInfo(); err != nil {
			t.Fatalf("existing client broken after endpoint growth: %v", err)
		}
	}
}
