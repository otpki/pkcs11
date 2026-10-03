//go:build !windows

package proxy

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

// probeModule wraps a raw module so health tests can count, delay, fail, or
// block one module call while every other operation behaves normally.
type probeModule struct {
	raw.Module
	tokenInfoCalls atomic.Int64
	tokenInfoDelay time.Duration
	failTokenInfo  atomic.Bool
	blockTokenInfo atomic.Bool
	gate           chan struct{}
	entered        chan struct{}
	enterOnce      sync.Once
}

func (m *probeModule) GetTokenInfo(slot raw.SlotID) (raw.TokenInfo, error) {
	m.tokenInfoCalls.Add(1)
	if m.failTokenInfo.Load() {
		return raw.TokenInfo{}, raw.Error(raw.CKR_DEVICE_REMOVED)
	}
	if m.blockTokenInfo.Load() {
		m.enterOnce.Do(func() { close(m.entered) })
		<-m.gate
	}
	if m.tokenInfoDelay > 0 {
		time.Sleep(m.tokenInfoDelay)
	}
	return m.Module.GetTokenInfo(slot)
}

// probeModuleSource hands one prepared raw.Module to the managed registry under
// a unique sharing key.
type probeModuleSource struct {
	module raw.Module
	key    string
}

func (s probeModuleSource) OpenModule(context.Context) (raw.Module, error) { return s.module, nil }
func (s probeModuleSource) RegistryKey() string                            { return s.key }
func (s probeModuleSource) String() string                                 { return "probe://" + s.key }

// newProbeModule returns a source wrapping a fresh one-token test module.
func newProbeModule(name string) (probeModuleSource, *probeModule) {
	module := &probeModule{Module: testmock.New(name, 1), gate: make(chan struct{}), entered: make(chan struct{})}
	return probeModuleSource{module: module, key: "probe:" + name}, module
}

// healthServer builds a server that is live but not serving: health probes act
// on published targets directly and need no listener traffic.
func healthServer(t *testing.T, config ServerConfig, targets ...TargetConfig) *Server {
	t.Helper()
	if config.Listener == nil && config.Address == "" {
		config.Address = "127.0.0.1:0"
	}
	config.AllowInsecure = true
	server, err := NewServer(context.Background(), config, targets...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	return server
}

func healthBrokerConfig(source pkcs11.ModuleSource, id string, mutate func(*TargetConfig)) TargetConfig {
	config := testmockBrokerConfig(source)
	config.ID = id
	if mutate != nil {
		mutate(&config)
	}
	return config
}

func checkNames(health TargetHealth) map[string]pkcs11.HealthCheck {
	names := make(map[string]pkcs11.HealthCheck, len(health.Checks))
	for _, check := range health.Checks {
		names[check.Name] = check
	}
	return names
}

func TestTargetHealthReportsHealthyRoute(t *testing.T) {
	server, _ := newTestmockBroker(t, testmockBrokerConfig(testmock.Source{Name: "health-ok", Tokens: 1}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	health, ok := server.TargetHealth(ctx, "shared-hsm")
	if !ok {
		t.Fatal("published route reported unknown")
	}
	if health.Status != pkcs11.HealthHealthy {
		t.Fatalf("status = %q, want healthy; checks = %+v", health.Status, health.Checks)
	}
	if health.ID != "shared-hsm" || health.Revision != "v1" {
		t.Fatalf("identity = %q@%q, want shared-hsm@v1", health.ID, health.Revision)
	}
	if health.CheckedAt.IsZero() {
		t.Fatal("CheckedAt is zero")
	}
	// No client has logged in: the route is healthy while its activation state
	// still reports inactive, because the first login performs activation.
	if health.Activation.State != ActivationInactive {
		t.Fatalf("activation = %q, want inactive", health.Activation.State)
	}
	names := checkNames(health)
	for _, want := range []string{"module-info", "slot-info", "token-info", "mechanism-list"} {
		check, found := names[want]
		if !found {
			t.Fatalf("checks %+v missing %q", health.Checks, want)
		}
		if check.Err != nil {
			t.Fatalf("check %q failed: %v", want, check.Err)
		}
	}
	if _, found := names["session"]; found {
		t.Fatal("health probe acquired a session")
	}
	if _, ok := server.TargetHealth(ctx, "missing-route"); ok {
		t.Fatal("unknown route reported health")
	}
}

func TestTargetHealthIsolatesFailingRoute(t *testing.T) {
	failingSource, failing := newProbeModule("health-fail")
	server := healthServer(t, ServerConfig{},
		healthBrokerConfig(failingSource, "a-failing", nil),
		healthBrokerConfig(testmock.Source{Name: "health-peer", Tokens: 1}, "b-healthy", nil),
	)

	// Discovery already fingerprinted the token; fail only the live probes.
	failing.failTokenInfo.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	health, ok := server.TargetHealth(ctx, "a-failing")
	if !ok {
		t.Fatal("published route reported unknown")
	}
	if health.Status != pkcs11.HealthUnhealthy {
		t.Fatalf("status = %q, want unhealthy", health.Status)
	}
	check, found := checkNames(health)["token-info"]
	if !found || check.Err == nil {
		t.Fatalf("checks = %+v, want a failed token-info entry", health.Checks)
	}
	peer, ok := server.TargetHealth(ctx, "b-healthy")
	if !ok || peer.Status != pkcs11.HealthHealthy {
		t.Fatalf("sibling route = %q (ok=%t), want healthy", peer.Status, ok)
	}

	// The broker-wide view reports both routes in catalog order.
	all := server.Health(ctx)
	if len(all) != 2 || all[0].ID != "a-failing" || all[1].ID != "b-healthy" {
		t.Fatalf("Health() = %+v, want catalog order [a-failing b-healthy]", all)
	}
	if all[0].Status != pkcs11.HealthUnhealthy || all[1].Status != pkcs11.HealthHealthy {
		t.Fatalf("Health() statuses = %q,%q", all[0].Status, all[1].Status)
	}
}

func TestTargetHealthSharesInflightProbeAndCachesResult(t *testing.T) {
	source, module := newProbeModule("health-shared")
	module.tokenInfoDelay = 50 * time.Millisecond
	server := healthServer(t, ServerConfig{HealthMaxAge: time.Minute}, healthBrokerConfig(source, "shared-hsm", nil))

	baseline := module.tokenInfoCalls.Load()
	const callers = 8
	start := make(chan struct{})
	results := make(chan TargetHealth, callers)
	for range callers {
		go func() {
			<-start
			health, ok := server.TargetHealth(context.Background(), "shared-hsm")
			if !ok {
				health = TargetHealth{Status: pkcs11.HealthUnhealthy}
			}
			results <- health
		}()
	}
	close(start)
	for range callers {
		if health := <-results; health.Status != pkcs11.HealthHealthy {
			t.Fatalf("concurrent probe = %q, want healthy", health.Status)
		}
	}
	if calls := module.tokenInfoCalls.Load() - baseline; calls != 1 {
		t.Fatalf("token-info calls = %d, want exactly 1 shared probe", calls)
	}

	// A result younger than the max age repeats with no module call.
	if health, ok := server.TargetHealth(context.Background(), "shared-hsm"); !ok || health.Status != pkcs11.HealthHealthy {
		t.Fatalf("cached probe = %q (ok=%t), want healthy", health.Status, ok)
	}
	if calls := module.tokenInfoCalls.Load() - baseline; calls != 1 {
		t.Fatalf("token-info calls after cache hit = %d, want 1", calls)
	}
}

func TestTargetHealthSaturatedPoolAcquiresNoSession(t *testing.T) {
	source, _ := newProbeModule("health-saturated")
	server := healthServer(t, ServerConfig{}, healthBrokerConfig(source, "shared-hsm", func(config *TargetConfig) {
		config.Sessions = SessionBudget{MaxPhysicalTotal: 2, MaxClients: 8}
	}))
	server.targetsMu.RLock()
	target := server.targets["shared-hsm"]
	server.targetsMu.RUnlock()
	if target == nil {
		t.Fatal("target not published")
	}

	// The reserved control session already holds one of two physical handles;
	// one more lease saturates the managed pools completely.
	ctx := context.Background()
	lease, err := target.currentClient().AcquireRawSession(ctx, pkcs11.RawSessionOptions{Operation: "test-saturate"})
	if err != nil {
		t.Fatalf("saturating lease: %v", err)
	}
	defer func() { _ = lease.Close(ctx) }()
	before, _ := server.TargetStats("shared-hsm")
	if before.PhysicalActive != 2 {
		t.Fatalf("PhysicalActive = %d, want saturated at 2", before.PhysicalActive)
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	health, ok := server.TargetHealth(probeCtx, "shared-hsm")
	if !ok || health.Status != pkcs11.HealthHealthy {
		t.Fatalf("saturated probe = %q (ok=%t), want healthy: %+v", health.Status, ok, health.Checks)
	}
	after, _ := server.TargetStats("shared-hsm")
	if after.PhysicalActive != before.PhysicalActive {
		t.Fatalf("PhysicalActive changed %d -> %d during probe", before.PhysicalActive, after.PhysicalActive)
	}
}

func TestTargetHealthHungModuleBindsCallerContextOnly(t *testing.T) {
	source, module := newProbeModule("health-hung")
	server := healthServer(t, ServerConfig{HealthMaxAge: time.Minute}, healthBrokerConfig(source, "shared-hsm", nil))
	module.blockTokenInfo.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	health, ok := server.TargetHealth(ctx, "shared-hsm")
	if !ok {
		t.Fatal("published route reported unknown")
	}
	if health.Status != pkcs11.HealthUnhealthy {
		t.Fatalf("status = %q, want unhealthy while native call is hung", health.Status)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("caller stayed blocked past its context deadline")
	}
	check, found := checkNames(health)["wait"]
	if !found || check.Err == nil {
		t.Fatalf("checks = %+v, want the caller's wait reported", health.Checks)
	}
	select {
	case <-module.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("hung module never received the token-info probe")
	}

	// The hung call owns the single probe goroutine; releasing the module lets
	// it finish and publish a real result for later callers.
	close(module.gate)
	deadline := time.Now().Add(5 * time.Second)
	for {
		health, ok = server.TargetHealth(context.Background(), "shared-hsm")
		if ok && health.Status == pkcs11.HealthHealthy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("probe never completed after module release: %+v", health)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTargetHealthClosingRouteReportsUnhealthy(t *testing.T) {
	source, _ := newProbeModule("health-closing")
	server := healthServer(t, ServerConfig{}, healthBrokerConfig(source, "shared-hsm", nil))
	server.targetsMu.RLock()
	target := server.targets["shared-hsm"]
	server.targetsMu.RUnlock()

	if err := server.RemoveTarget(context.Background(), "shared-hsm"); err != nil {
		t.Fatal(err)
	}
	if _, ok := server.TargetHealth(context.Background(), "shared-hsm"); ok {
		t.Fatal("removed route still reports health")
	}
	health := target.health(context.Background(), time.Second)
	if health.Status != pkcs11.HealthUnhealthy {
		t.Fatalf("closing target = %q, want unhealthy", health.Status)
	}
	if _, found := checkNames(health)["target"]; !found {
		t.Fatalf("closing checks = %+v, want a named entry", health.Checks)
	}
}

func TestTargetHealthJSONIsSecretFree(t *testing.T) {
	server, _ := newTestmockBroker(t, testmockBrokerConfig(testmock.Source{Name: "health-json", Tokens: 1}))
	health, ok := server.TargetHealth(context.Background(), "shared-hsm")
	if !ok {
		t.Fatal("published route reported unknown")
	}
	payload, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, secret := range []string{testmock.DefaultPIN, "testmock://", "testmode-info", "TEST-"} {
		if strings.Contains(text, secret) {
			t.Fatalf("health JSON leaks %q: %s", secret, text)
		}
	}
	for _, want := range []string{`"id":"shared-hsm"`, `"revision":"v1"`, `"status":"healthy"`, `"activation":`, `"checks":`, `"checked_at":`} {
		if !strings.Contains(text, want) {
			t.Fatalf("health JSON missing %s: %s", want, text)
		}
	}
}

// TestTargetHealthIntegration probes a real module — SoftHSM in the
// conformance fixtures — only when PKCS11_MODULE points at one.
func TestTargetHealthIntegration(t *testing.T) {
	modulePath := strings.TrimSpace(os.Getenv("PKCS11_MODULE"))
	if modulePath == "" {
		t.Skip("PKCS11_MODULE is not set")
	}
	// An empty selector is valid when the module reports exactly one token,
	// which is what the SoftHSM conformance fixture initializes.
	selector := pkcs11.TokenSelector{
		Label:        os.Getenv("PKCS11_TOKEN_LABEL"),
		SerialNumber: os.Getenv("PKCS11_TOKEN_SERIAL"),
	}
	config := TargetConfig{
		ID:       "integration",
		Revision: "v1",
		Client:   pkcs11.Config{Module: pkcs11.LocalModule(modulePath), Token: selector},
		Sessions: SessionBudget{MaxPhysicalTotal: 4},
		Login: LoginPolicy{
			Authenticate: func(context.Context, LoginAttempt) error { return nil },
		},
	}
	if pin := os.Getenv("PKCS11_PIN"); pin != "" {
		config.Login.PhysicalPIN = pkcs11.StaticPIN(pin)
	} else {
		config.Login.Mode = PhysicalLoginClientActivated
	}
	server := healthServer(t, ServerConfig{}, config)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	health, ok := server.TargetHealth(ctx, "integration")
	if !ok {
		t.Fatal("published route reported unknown")
	}
	if health.Status != pkcs11.HealthHealthy {
		t.Fatalf("status = %q, want healthy; checks = %+v", health.Status, health.Checks)
	}
}
