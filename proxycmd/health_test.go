//go:build !windows

package proxycmd

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/all"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// fakeHealthSource drives the health handler without a live broker. State and
// addr are atomic because handler goroutines read them while the test mutates.
type fakeHealthSource struct {
	state  atomic.Int32
	addr   atomic.Pointer[net.TCPAddr]
	health func(context.Context) []proxy.TargetHealth
}

func (f *fakeHealthSource) State() proxy.ServerState {
	return proxy.ServerState(f.state.Load())
}

func (f *fakeHealthSource) Addr() net.Addr {
	if addr := f.addr.Load(); addr != nil {
		return addr
	}
	return nil
}

func (f *fakeHealthSource) Health(ctx context.Context) []proxy.TargetHealth {
	if f.health == nil {
		return nil
	}
	return f.health(ctx)
}

func (f *fakeHealthSource) setState(state proxy.ServerState) { f.state.Store(int32(state)) }
func (f *fakeHealthSource) setAddr(addr *net.TCPAddr)        { f.addr.Store(addr) }

func healthyRoute(id string) proxy.TargetHealth {
	return proxy.TargetHealth{
		ID: id, Revision: "v1", Status: pkcs11.HealthHealthy,
		Checks: []pkcs11.HealthCheck{
			{Name: "module-info"},
			{Name: "token-info"},
		},
		CheckedAt: time.Now(),
	}
}

func get(t *testing.T, handler http.Handler, path string) (int, []byte, http.Header) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	response := recorder.Result()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body, response.Header
}

// TestHealthzIsPureLiveness proves /healthz answers from the HTTP stack alone:
// it returns 200 even while a /readyz probe is wedged behind a native call and
// even when the broker is draining.
func TestHealthzIsPureLiveness(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	source := &fakeHealthSource{
		health: func(context.Context) []proxy.TargetHealth {
			<-release // simulates a module wedged inside a native call
			return nil
		},
	}
	source.setState(proxy.ServerActive)
	source.setAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9443})
	handler := (&healthServer{source: source}).Handler()

	// A readiness probe sits blocked on the hung module…
	readyzDone := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		readyzDone <- recorder.Code
	}()

	// …and liveness still answers immediately, through drain as well.
	for _, state := range []proxy.ServerState{proxy.ServerActive, proxy.ServerDraining} {
		source.setState(state)
		started := time.Now()
		code, body, header := get(t, handler, "/healthz")
		if code != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
			t.Fatalf("healthz (%s) = %d %q", state, code, body)
		}
		if !strings.Contains(header.Get("Content-Type"), "text/plain") {
			t.Fatalf("healthz content type = %q", header.Get("Content-Type"))
		}
		if time.Since(started) > 2*time.Second {
			t.Fatal("healthz waited on broker state")
		}
	}
	select {
	case <-readyzDone:
		t.Fatal("readyz returned while the probe was wedged")
	case <-time.After(20 * time.Millisecond):
	}
}

// TestReadyzReportsPerRouteHealth covers the HA contract: one sick route shows
// in the body while the broker stays ready at 200.
func TestReadyzReportsPerRouteHealth(t *testing.T) {
	sick := healthyRoute("b-sick")
	sick.Status = pkcs11.HealthUnhealthy
	sick.Checks[1].Error = "token-info: CKR_DEVICE_REMOVED"
	source := &fakeHealthSource{
		health: func(context.Context) []proxy.TargetHealth {
			return []proxy.TargetHealth{healthyRoute("a-ok"), sick}
		},
	}
	source.setState(proxy.ServerActive)
	source.setAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9443})
	code, body, header := get(t, (&healthServer{source: source}).Handler(), "/readyz")
	if code != http.StatusOK {
		t.Fatalf("readyz = %d, want 200 with one sick route", code)
	}
	if !strings.Contains(header.Get("Content-Type"), "application/json") {
		t.Fatalf("readyz content type = %q", header.Get("Content-Type"))
	}
	var payload readyzResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Ready || payload.State != "active" || payload.Listener != "127.0.0.1:9443" {
		t.Fatalf("readyz header fields = %+v", payload)
	}
	if len(payload.Routes) != 2 || payload.Routes[0].ID != "a-ok" || payload.Routes[1].ID != "b-sick" {
		t.Fatalf("routes = %+v", payload.Routes)
	}
	if payload.Routes[0].Status != pkcs11.HealthHealthy || payload.Routes[1].Status != pkcs11.HealthUnhealthy {
		t.Fatalf("route statuses = %q,%q", payload.Routes[0].Status, payload.Routes[1].Status)
	}
}

// TestReadyzUnavailable verifies the 503 cases: before the broker listener is
// bound and once draining starts.
func TestReadyzUnavailable(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9443}
	source := &fakeHealthSource{
		health: func(context.Context) []proxy.TargetHealth {
			return []proxy.TargetHealth{healthyRoute("hsm")}
		},
	}
	source.setState(proxy.ServerActive)
	source.setAddr(addr)
	handler := (&healthServer{source: source}).Handler()

	// Bound listener + active → ready.
	if code, _, _ := get(t, handler, "/readyz"); code != http.StatusOK {
		t.Fatalf("readyz active+bound = %d", code)
	}
	// Listener not yet bound → not ready.
	source.setAddr(nil)
	code, body, _ := get(t, handler, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("readyz unbound = %d, want 503", code)
	}
	var payload readyzResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Ready {
		t.Fatal("unbound listener reported ready")
	}
	// Draining → not ready regardless of route health.
	source.setAddr(addr)
	source.setState(proxy.ServerDraining)
	if code, _, _ := get(t, handler, "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("readyz draining = %d, want 503", code)
	}
}

// TestReadyzBoundsHungProbes proves the request timeout marks a wedged route
// unhealthy and still answers 200 — the broker stays ready while one module
// hangs.
func TestReadyzBoundsHungProbes(t *testing.T) {
	source := &fakeHealthSource{
		health: func(ctx context.Context) []proxy.TargetHealth {
			<-ctx.Done() // mirrors target.health: caller ctx expiry → unhealthy
			return []proxy.TargetHealth{{
				ID: "hsm", Revision: "v1", Status: pkcs11.HealthUnhealthy,
				Checks:    []pkcs11.HealthCheck{{Name: "wait", Error: ctx.Err().Error()}},
				CheckedAt: time.Now(),
			}}
		},
	}
	source.setState(proxy.ServerActive)
	source.setAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9443})
	handler := (&healthServer{source: source, probeTimeout: 100 * time.Millisecond}).Handler()
	started := time.Now()
	code, body, _ := get(t, handler, "/readyz")
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("readyz blocked for %v", elapsed)
	}
	if code != http.StatusOK {
		t.Fatalf("readyz = %d, want 200 (route unhealthy, broker ready)", code)
	}
	var payload readyzResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Routes) != 1 || payload.Routes[0].Status != pkcs11.HealthUnhealthy {
		t.Fatalf("wedged route = %+v", payload.Routes)
	}
	if !strings.Contains(payload.Routes[0].Checks[0].Error, "deadline") {
		t.Fatalf("wedged route error = %q, want the deadline recorded", payload.Routes[0].Checks[0].Error)
	}
}

// blockingTokenInfo wedged inside GetTokenInfo models a hung native module.
type blockingTokenInfo struct {
	raw.Module
	block   atomic.Bool
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (m *blockingTokenInfo) GetTokenInfo(slot raw.SlotID) (raw.TokenInfo, error) {
	if m.block.Load() {
		m.once.Do(func() { close(m.entered) })
		<-m.gate
	}
	return m.Module.GetTokenInfo(slot)
}

// staticModuleSource hands one prepared module to the registry under a unique
// sharing key.
type staticModuleSource struct {
	module raw.Module
	key    string
}

func (s staticModuleSource) OpenModule(context.Context) (raw.Module, error) { return s.module, nil }
func (s staticModuleSource) RegistryKey() string                            { return s.key }
func (s staticModuleSource) String() string                                 { return "static://" + s.key }

// serveTarget brings up a real broker on one injected module and serves it on
// a bound loopback listener, returning the address and server.
func serveTarget(t *testing.T, source pkcs11.ModuleSource) (string, *proxy.Server) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := proxy.NewServer(context.Background(), proxy.ServerConfig{
		Listener:      listener,
		AllowInsecure: true,
	}, proxy.TargetConfig{
		ID:       "hsm",
		Revision: "v1",
		Client:   pkcs11.Config{Module: source},
		Sessions: proxy.SessionBudget{MaxPhysicalTotal: 4},
		Login: proxy.LoginPolicy{
			Mode:         proxy.PhysicalLoginClientActivated,
			Authenticate: func(context.Context, proxy.LoginAttempt) error { return nil },
		},
	})
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
	waitBound(t, server)
	return listener.Addr().String(), server
}

// waitBound blocks until Serve has installed the broker listener so Addr()
// reports it bound — /readyz treats a nil Addr as not serving.
func waitBound(t *testing.T, server *proxy.Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for server.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if server.Addr() == nil {
		t.Fatal("broker listener never bound")
	}
}

// TestHealthEndpointsOnHungModule is the end-to-end check against a real
// broker: the module wedges inside GetTokenInfo, /healthz stays 200, and
// /readyz still answers within its deadline with the route marked unhealthy.
func TestHealthEndpointsOnHungModule(t *testing.T) {
	module := &blockingTokenInfo{
		Module:  testmock.New("health-hung", 1),
		gate:    make(chan struct{}),
		entered: make(chan struct{}),
	}
	_, server := serveTarget(t, staticModuleSource{module: module, key: "hung"})
	handler := (&healthServer{source: server, probeTimeout: 400 * time.Millisecond}).Handler()

	module.block.Store(true)
	code, body, _ := get(t, handler, "/readyz")
	if code != http.StatusOK {
		t.Fatalf("readyz wedged = %d, want 200", code)
	}
	var payload readyzResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Routes) != 1 || payload.Routes[0].Status != pkcs11.HealthUnhealthy {
		t.Fatalf("wedged route = %+v, want unhealthy", payload.Routes)
	}
	select {
	case <-module.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the hung module never received the probe")
	}
	if code, _, _ := get(t, handler, "/healthz"); code != http.StatusOK {
		t.Fatal("healthz failed while a native call was hung")
	}
	close(module.gate)
	module.block.Store(false)
	// The released probe finishes and the route recovers.
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, body, _ = get(t, handler, "/readyz")
		var next readyzResponse
		if err := json.Unmarshal(body, &next); err != nil {
			t.Fatal(err)
		}
		if code == http.StatusOK && len(next.Routes) == 1 && next.Routes[0].Status == pkcs11.HealthHealthy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("route never recovered: %+v", next.Routes)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestReadyzOnRealBroker exercises the real server: healthy routes in catalog
// order, 503 after Drain, and liveness still 200 while draining.
func TestReadyzOnRealBroker(t *testing.T) {
	cfg, err := loadOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	address, server := testModeServer(t, cfg)
	waitBound(t, server)
	handler := (&healthServer{source: server}).Handler()

	code, body, _ := get(t, handler, "/readyz")
	if code != http.StatusOK {
		t.Fatalf("readyz = %d, want 200", code)
	}
	var payload readyzResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Ready || payload.Listener != address {
		t.Fatalf("readyz = %+v, want ready on %s", payload, address)
	}
	// One entry per published route, in RouteCatalog order.
	catalog := server.RouteCatalog()
	if len(payload.Routes) != len(catalog) {
		t.Fatalf("routes = %d, want %d", len(payload.Routes), len(catalog))
	}
	for index, route := range catalog {
		entry := payload.Routes[index]
		if entry.ID != route.ID || entry.Status != pkcs11.HealthHealthy {
			t.Fatalf("route %d = %+v, want healthy %q", index, entry, route.ID)
		}
	}
	// Secret-free output: no PIN, module source, or serial material.
	if testmock.ContainsDefaultPIN(string(body)) {
		t.Fatalf("readyz body leaks the PIN: %s", body)
	}
	for _, leaked := range []string{"testmock", "TEST-"} {
		if strings.Contains(string(body), leaked) {
			t.Fatalf("readyz body leaks %q: %s", leaked, body)
		}
	}

	server.Drain(context.Background())
	if code, _, _ := get(t, handler, "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("readyz while draining = %d, want 503", code)
	}
	if code, _, _ := get(t, handler, "/healthz"); code != http.StatusOK {
		t.Fatal("healthz failed while draining")
	}
}

// TestHealthListenerLoopbackGuard covers the bind rule shared with the dev UI.
func TestHealthListenerLoopbackGuard(t *testing.T) {
	handler := (&healthServer{source: &fakeHealthSource{}}).Handler()

	bound, err := startHealthListener("127.0.0.1:0", false, handler)
	if err != nil {
		t.Fatalf("loopback bind refused: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer func() { _ = bound.Shutdown(ctx) }()

	// Real HTTP round trips against the bound listener; no proxy, so
	// environment-level HTTP_PROXY vars cannot divert the loopback request.
	direct := &http.Client{Transport: &http.Transport{Proxy: nil}}
	response, err := direct.Get("http://" + bound.Addr() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("healthz over HTTP = %d", response.StatusCode)
	}

	if _, err := startHealthListener("0.0.0.0:0", false, handler); err == nil {
		t.Fatal("wildcard health bind accepted without allow_remote")
	}
	remote, err := startHealthListener("0.0.0.0:0", true, handler)
	if err != nil {
		t.Fatalf("wildcard bind with allow_remote: %v", err)
	}
	defer func() { _ = remote.Shutdown(ctx) }()
	if _, err := startHealthListener("not-an-address", false, handler); err == nil {
		t.Fatal("malformed health.listen accepted")
	}
}

// installPrometheus wires a fresh MeterProvider + Prometheus reader into the
// global OTel meter — the same shape setupOTel produces when health.listen is
// set — and returns the scrape handler.
func installPrometheus(t *testing.T) http.Handler {
	t.Helper()
	registry := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		t.Fatal(err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(previous)
		_ = provider.Shutdown(context.Background())
	})
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

func scrape(t *testing.T, handler http.Handler) string {
	t.Helper()
	code, body, _ := get(t, handler, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("metrics = %d", code)
	}
	return string(body)
}

var physicalLoginSeries = regexp.MustCompile(`pkcs11_operations_total\{[^}]*pkcs11_operation="proxy-physical-login"[^}]*\} ([0-9.]+)`)

// physicalLoginCount sums the proxy-physical-login operation series.
func physicalLoginCount(t *testing.T, body string) float64 {
	t.Helper()
	total := 0.0
	for _, match := range physicalLoginSeries.FindAllStringSubmatch(body, -1) {
		value, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			t.Fatalf("bad metric value %q", match[0])
		}
		total += value
	}
	return total
}

// activateClient performs one full client login through the broker, which
// drives the broker's physical C_Login.
func activateClient(t *testing.T, address, pin string) *pkcs11.Client {
	t.Helper()
	ctx := context.Background()
	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module: proxy.RemoteModule(proxy.Target{
			ConfigID:          "health-metrics",
			Revision:          targetRevision,
			Endpoints:         []string{address},
			Route:             "test-alpha",
			SecurityContextID: "health-metrics",
			AllowInsecure:     true,
			Auth:              func(context.Context) ([]byte, error) { return []byte("dev-workload"), nil },
			Vendors:           all.Modules(),
		}),
		Login: pkcs11.LoginConfig{Mode: pkcs11.LoginManual},
		PIN:   pkcs11.StaticPIN(pin),
	})
	if err != nil {
		t.Fatalf("client open: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

// TestMetricsEndpointExposesProxyAndOperationMetrics scrapes /metrics after a
// real client activation and checks the three acceptance instruments, then
// proves a PIN refused by the broker's verifier never reaches the HSM: the
// proxy-physical-login count does not move.
func TestMetricsEndpointExposesProxyAndOperationMetrics(t *testing.T) {
	metricsHandler := installPrometheus(t)
	cfg, err := loadOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	address, server := testModeServer(t, cfg)
	handler := (&healthServer{source: server, metrics: metricsHandler}).Handler()

	client := activateClient(t, address, testmock.DefaultPIN)
	if err := client.Activate(context.Background()); err != nil {
		t.Fatalf("activate: %v", err)
	}

	body := scrape(t, handler)
	for _, name := range []string{"pkcs11_proxy_requests_total", "pkcs11_proxy_physical_sessions", "pkcs11_operations_total"} {
		if !strings.Contains(body, name) {
			t.Fatalf("scrape missing %s:\n%s", name, body)
		}
	}
	logins := physicalLoginCount(t, body)
	if logins != 1 {
		t.Fatalf("proxy-physical-login = %v after one activation, want 1\n%s", logins, body)
	}

	// A wrong PIN is refused by the in-memory verifier before any HSM call.
	refused := activateClient(t, address, "9999")
	if err := refused.Activate(context.Background()); err == nil {
		t.Fatal("activation with a wrong PIN succeeded")
	}
	if after := physicalLoginCount(t, scrape(t, handler)); after != logins {
		t.Fatalf("refused PIN moved proxy-physical-login %v -> %v", logins, after)
	}
}

// TestSetupOTelSinks verifies the reader wiring: metrics exist when either
// sink is configured, one reader each for OTLP and Prometheus, and traces/logs
// only with an endpoint.
func TestSetupOTelSinks(t *testing.T) {
	prevMeter := otel.GetMeterProvider()
	prevTracer := otel.GetTracerProvider()
	prevLogger := otel.GetLoggerProvider()
	t.Cleanup(func() {
		otel.SetMeterProvider(prevMeter)
		otel.SetTracerProvider(prevTracer)
		otel.SetLoggerProvider(prevLogger)
	})

	cfg := options{}
	cfg.OTel.ServiceName = "test"
	cfg.OTel.MetricInterval = time.Hour // keep the periodic reader idle

	if providers, err := setupOTel(context.Background(), cfg); err != nil || providers != nil {
		t.Fatalf("no sinks: providers=%v err=%v, want nil", providers, err)
	}

	// Health listener only: metrics + prometheus, no OTLP providers.
	cfg.Health.Listen = "127.0.0.1:0"
	providers, err := setupOTel(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if providers.metrics == nil || providers.prometheus == nil || providers.metricsHandler() == nil {
		t.Fatal("health-only setup missing metrics provider, reader, or handler")
	}
	if providers.traces != nil || providers.logs != nil {
		t.Fatal("traces/logs providers installed without an otlp endpoint")
	}
	if err := providers.Shutdown(context.Background()); err != nil {
		t.Fatalf("prometheus-only shutdown: %v", err)
	}

	// Both sinks: OTLP providers join the metrics provider.
	cfg.OTel.Endpoint = "http://127.0.0.1:4318"
	providers, err = setupOTel(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if providers.traces == nil || providers.logs == nil || providers.metrics == nil || providers.prometheus == nil {
		t.Fatalf("combined sinks incomplete: %+v", providers)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = providers.Shutdown(shutdownCtx) // flushing an unreachable collector may fail; wiring is what's under test
}

// TestHealthEndpointIntegration probes and scrapes a real module — SoftHSM in
// the conformance fixtures — only when PKCS11_MODULE points at one.
func TestHealthEndpointIntegration(t *testing.T) {
	modulePath := strings.TrimSpace(os.Getenv("PKCS11_MODULE"))
	if modulePath == "" {
		t.Skip("PKCS11_MODULE is not set")
	}
	metricsHandler := installPrometheus(t)
	cfg, err := loadOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Insecure = true
	cfg.Targets = []targetSpec{{
		Name:        "integration",
		Module:      modulePath,
		TokenLabel:  os.Getenv("PKCS11_TOKEN_LABEL"),
		TokenSerial: os.Getenv("PKCS11_TOKEN_SERIAL"),
	}}
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
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	defer func() {
		cancel()
		_ = server.Close(ctx)
		<-serveDone
	}()
	waitBound(t, server)

	handler := (&healthServer{source: server, metrics: metricsHandler}).Handler()
	code, body, _ := get(t, handler, "/readyz")
	if code != http.StatusOK {
		t.Fatalf("readyz = %d: %s", code, body)
	}
	var payload readyzResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Routes) != 1 || payload.Routes[0].Status != pkcs11.HealthHealthy {
		t.Fatalf("softhsm route = %+v, want healthy", payload.Routes)
	}
	if code, _, _ := get(t, handler, "/healthz"); code != http.StatusOK {
		t.Fatal("healthz failed")
	}
	if body := scrape(t, handler); !strings.Contains(body, "pkcs11_proxy_physical_sessions") {
		t.Fatalf("scrape missing broker gauges:\n%s", body)
	}
}
