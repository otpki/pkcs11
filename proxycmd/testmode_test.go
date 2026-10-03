package proxycmd

import (
	"context"
	"net"
	"testing"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/all"
)

func TestTestModuleSourceParsing(t *testing.T) {
	tests := []struct {
		spec      string
		isTest    bool
		name      string
		tokens    int
		wantError bool
	}{
		{"test", true, "test", 1, false},
		{"test:foo", true, "foo", 1, false},
		{"test:foo:3", true, "foo", 3, false},
		{"test::2", true, "test", 2, false},
		{"test:foo:0", true, "", 0, true},
		{"test:foo:9", true, "", 0, true},
		{"test:foo:x", true, "", 0, true},
		{"test:bad name!", true, "", 0, true},
		{"test:foo:2:extra", true, "", 0, true},
		{"/usr/lib/libpkcs11.so", false, "", 0, false},
		{"./relative/module.so", false, "", 0, false},
	}
	for _, tc := range tests {
		source, isTest, err := testModuleSource(tc.spec)
		if isTest != tc.isTest {
			t.Errorf("%q: isTest = %v, want %v", tc.spec, isTest, tc.isTest)
			continue
		}
		if !tc.isTest {
			continue
		}
		if tc.wantError {
			if err == nil {
				t.Errorf("%q: expected error, got source %+v", tc.spec, source)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.spec, err)
			continue
		}
		mock, ok := source.(testmock.Source)
		if !ok {
			t.Fatalf("source for %q is %T, want testmock.Source", tc.spec, source)
		}
		if mock.Name != tc.name || mock.Tokens != tc.tokens {
			t.Errorf("%q: got %+v", tc.spec, mock)
		}
	}
}

func TestTargetModuleSourceSelectsTestScheme(t *testing.T) {
	source, err := targetModuleSource("test:sel:2")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := source.(testmock.Source); !ok {
		t.Fatalf("test scheme resolved to %T", source)
	}
	source, err = targetModuleSource("/nonexistent/module.so")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := source.(pkcs11.LocalModuleSource); !ok {
		t.Fatalf("path resolved to %T", source)
	}
}

// TestTestModeEndToEnd runs the real broker on the --test topology and drives
// it with the real proxy client: catalog, activation with the fixture PIN, and
// a random-generation operation.
func TestTestModeEndToEnd(t *testing.T) {
	cfg, err := loadOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Insecure = true
	cfg.Targets = testTargets()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := newServerOn(context.Background(), cfg, listener, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	defer func() {
		cancel()
		_ = server.Close(ctx)
		<-serveDone
	}()
	address := listener.Addr().String()

	catalog, err := proxy.ListRoutes(ctx, proxy.Target{
		Endpoints:         []string{address},
		AllowInsecure:     true,
		SecurityContextID: "test-mode-e2e",
		Auth:              func(context.Context) ([]byte, error) { return []byte("dev-workload"), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 3 {
		t.Fatalf("catalog = %d routes, want 3", len(catalog))
	}
	labels := map[string]string{}
	for _, route := range catalog {
		labels[route.ID] = route.TokenLabel
	}
	if labels["test-alpha"] != "demo-hsm-token-1" || labels["test-beta"] != "demo-hsm-token-2" || labels["test-gamma"] != "sidecar-hsm-token-1" {
		t.Fatalf("catalog labels = %v", labels)
	}
	// alpha and beta are two tokens on the same virtual HSM.
	var slotA, slotB raw.SlotID
	for _, route := range catalog {
		switch route.ID {
		case "test-alpha":
			slotA = route.SlotID
		case "test-beta":
			slotB = route.SlotID
		}
	}
	if slotA == slotB {
		t.Fatalf("alpha and beta both bound slot %d", slotA)
	}

	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module: proxy.RemoteModule(proxy.Target{
			ConfigID:          "test-mode-e2e",
			Revision:          targetRevision,
			Endpoints:         []string{address},
			Route:             "test-beta",
			SecurityContextID: "test-mode-e2e",
			AllowInsecure:     true,
			Auth:              func(context.Context) ([]byte, error) { return []byte("dev-workload"), nil },
			Vendors:           all.Modules(),
		}),
		Login: pkcs11.LoginConfig{Mode: pkcs11.LoginManual},
		PIN:   pkcs11.StaticPIN(testmock.DefaultPIN),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(ctx) }()

	if err := client.Activate(ctx); err != nil {
		t.Fatalf("activate with fixture PIN: %v", err)
	}
	if got := client.Device().Fingerprint.Token.Label; got != "demo-hsm-token-2" {
		t.Fatalf("route bound token label = %q", got)
	}
	random, err := client.Random(ctx, 32)
	if err != nil || len(random) != 32 {
		t.Fatalf("random = %d bytes, %v", len(random), err)
	}
	stats, ok := server.TargetStats("test-beta")
	if !ok || stats.Activation.State != proxy.ActivationActive {
		t.Fatalf("route not activated: %+v, %v", stats, ok)
	}
}

// testModeServer brings up the real broker on the --test topology and returns
// its address.
func testModeServer(t *testing.T, cfg options) (string, *proxy.Server) {
	t.Helper()
	cfg.Insecure = true
	cfg.Targets = testTargets()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := newServerOn(context.Background(), cfg, listener, nil)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close(ctx)
		<-serveDone
	})
	return listener.Addr().String(), server
}

// testModeClient opens one proxy client on the serve topology. workload is the
// bearer credential every request authenticates with — replicas of one
// deployment share it and therefore share one principal.
func testModeClient(t *testing.T, address, workload, pin string) *pkcs11.Client {
	t.Helper()
	client, err := pkcs11.Open(context.Background(), pkcs11.Config{
		Module: proxy.RemoteModule(proxy.Target{
			ConfigID:          "test-mode",
			Revision:          targetRevision,
			Endpoints:         []string{address},
			Route:             "test-beta",
			SecurityContextID: "test-mode",
			AllowInsecure:     true,
			Auth:              func(context.Context) ([]byte, error) { return []byte(workload), nil },
			Vendors:           all.Modules(),
		}),
		Login: pkcs11.LoginConfig{Mode: pkcs11.LoginManual},
		PIN:   pkcs11.StaticPIN(pin),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

// Through pkcs11-proxy serve, two clients sharing one workload credential: the
// PIN the HSM accepted at activation is the only PIN later logins may use.
func TestServeVerifyClientPINRefusesPeerPIN(t *testing.T) {
	cfg, err := loadOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	address, _ := testModeServer(t, cfg)

	activator := testModeClient(t, address, "shared-workload", testmock.DefaultPIN)
	if err := activator.Activate(context.Background()); err != nil {
		t.Fatalf("activation with fixture PIN: %v", err)
	}

	peer := testModeClient(t, address, "shared-workload", "9999")
	if err := peer.Activate(context.Background()); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("peer wrong-PIN login = %v, want CKR_PIN_INCORRECT", err)
	}
	// The workload's correct PIN still earns its grant.
	peerRight := testModeClient(t, address, "shared-workload", testmock.DefaultPIN)
	if err := peerRight.Activate(context.Background()); err != nil {
		t.Fatalf("peer right-PIN login: %v", err)
	}
}

// Through pkcs11-proxy serve, a failed activation does not stall another
// principal: once the failure cooldown passes, the right PIN activates
// immediately — no follower waits on a verification timeout.
func TestServeFailedActivationDoesNotStallNextPrincipal(t *testing.T) {
	cfg, err := loadOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Activation.FailureCooldown = 200 * time.Millisecond
	address, _ := testModeServer(t, cfg)

	first := testModeClient(t, address, "workload-wrong-pin", "9999")
	if err := first.Activate(context.Background()); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("first activation = %v, want CKR_PIN_INCORRECT", err)
	}

	time.Sleep(250 * time.Millisecond)
	second := testModeClient(t, address, "workload-right-pin", testmock.DefaultPIN)
	start := time.Now()
	if err := second.Activate(context.Background()); err != nil {
		t.Fatalf("second principal activation after cooldown: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("second principal waited %v — the in-flight gate stall is back", elapsed)
	}
}
