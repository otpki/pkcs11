package proxycmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/all"
)

// discoveryHarness runs a real discovery broker over a shared test module so
// tests can add and remove tokens between listings.
type discoveryHarness struct {
	module     *testmock.Module
	discoverer *discoverer
	server     *proxy.Server
	address    string
}

func newDiscoveryHarness(t *testing.T, module *testmock.Module, spec *discoverySpec, cfg options) *discoveryHarness {
	t.Helper()
	source := testmock.SharedSource{Name: spec.Module, Module: module}
	reconciler, err := newDiscoverer(spec, source, nil, cfg.Sessions, cfg.Activation)
	if err != nil {
		t.Fatal(err)
	}
	server, address := serveDiscoverySet(t, reconcilerSet{reconciler})
	return &discoveryHarness{module: module, discoverer: reconciler, server: server, address: address}
}

// serveDiscoverySet runs one broker over a reconciler set, mirroring
// newDiscoveryServer's wiring: attach each discoverer, reconcile strictly at
// startup, then serve with the fan-out listing hook.
func serveDiscoverySet(t *testing.T, set reconcilerSet) (*proxy.Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := proxy.NewServer(context.Background(), proxy.ServerConfig{
		Listener:         listener,
		AllowInsecure:    true,
		Authenticator:    workloadAuthenticator,
		BeforeListRoutes: set.reconcile,
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	for _, d := range set {
		d.attach(server)
		if err := d.reconcileStartup(context.Background()); err != nil {
			_ = server.Close(context.Background())
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close(context.Background())
		<-serveDone
	})
	return server, listener.Addr().String()
}

func listDiscoveryRoutes(t *testing.T, address string) []proxy.RouteInfo {
	t.Helper()
	routes, err := proxy.ListRoutes(context.Background(), proxy.Target{
		Endpoints:         []string{address},
		AllowInsecure:     true,
		SecurityContextID: "discovery-test",
		Auth:              func(context.Context) ([]byte, error) { return []byte("workload"), nil },
		RequestTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return routes
}

func (h *discoveryHarness) listRoutes(t *testing.T) []proxy.RouteInfo {
	t.Helper()
	return listDiscoveryRoutes(t, h.address)
}

func defaultOptions(t *testing.T) options {
	t.Helper()
	cfg, err := loadOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func routeIDs(routes []proxy.RouteInfo) []string {
	ids := make([]string, 0, len(routes))
	for _, route := range routes {
		ids = append(ids, route.ID)
	}
	return ids
}

// One route per token the module reports, each with a derived revision.
func TestDiscoveryPublishesOneRoutePerToken(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	h := newDiscoveryHarness(t, testmock.New("disco", 3), &discoverySpec{Module: "test:disco"}, cfg)

	routes := h.listRoutes(t)
	want := []string{"TEST-DISCO-0001", "TEST-DISCO-0002", "TEST-DISCO-0003"}
	if got := routeIDs(routes); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("route IDs = %v, want %v", got, want)
	}
	for i, route := range routes {
		if !strings.HasPrefix(route.Revision, "d") || len(route.Revision) != 17 {
			t.Fatalf("route %q revision %q is not a derived digest", route.ID, route.Revision)
		}
		if want := fmt.Sprintf("disco-token-%d", i+1); route.TokenLabel != want {
			t.Fatalf("route %q label = %q, want %q", route.ID, route.TokenLabel, want)
		}
		if !route.LoginRequired {
			t.Fatalf("route %q reports LoginRequired=false", route.ID)
		}
	}
}

// A token added on the module is published by the next listing; a removed
// token disappears from it.
func TestDiscoveryReflectsRuntimeTokenChanges(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	h := newDiscoveryHarness(t, testmock.New("disco", 1), &discoverySpec{Module: "test:disco", RefreshInterval: -1}, cfg)

	if got := routeIDs(h.listRoutes(t)); len(got) != 1 || got[0] != "TEST-DISCO-0001" {
		t.Fatalf("initial routes = %v", got)
	}

	h.module.AddToken("disco-token-extra", "TEST-DISCO-EXTRA")
	got := routeIDs(h.listRoutes(t))
	if len(got) != 2 || got[0] != "TEST-DISCO-0001" || got[1] != "TEST-DISCO-EXTRA" {
		t.Fatalf("after add routes = %v", got)
	}

	if err := h.module.RemoveToken(1); err != nil {
		t.Fatal(err)
	}
	got = routeIDs(h.listRoutes(t))
	if len(got) != 1 || got[0] != "TEST-DISCO-EXTRA" {
		t.Fatalf("after remove routes = %v, want [TEST-DISCO-EXTRA]", got)
	}
}

// A route retired mid-call disappears from the listing at once while the
// in-flight native call completes before the target's sessions close.
func TestDiscoveryRouteRetireDrainsInFlightCall(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	h := newDiscoveryHarness(t, testmock.New("drain", 1), &discoverySpec{Module: "test:drain", RefreshInterval: -1}, cfg)

	routes := h.listRoutes(t)
	if len(routes) != 1 {
		t.Fatalf("routes = %v", routeIDs(routes))
	}
	client, err := pkcs11.Open(context.Background(), pkcs11.Config{
		Module: proxy.RemoteModule(proxy.Target{
			ConfigID: "discovery-drain", Revision: routes[0].Revision,
			Endpoints:         []string{h.address},
			Route:             routes[0].ID,
			SecurityContextID: "discovery-test",
			AllowInsecure:     true,
			Auth:              func(context.Context) ([]byte, error) { return []byte("workload"), nil },
		}),
		Login: pkcs11.LoginConfig{Mode: pkcs11.LoginManual},
		PIN:   pkcs11.StaticPIN(testmock.DefaultPIN),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(context.Background()) }()
	if err := client.Activate(context.Background()); err != nil {
		t.Fatalf("activate: %v", err)
	}

	gate := testmock.NewGate()
	h.module.SetGate("GenerateRandom", gate)
	callDone := make(chan error, 1)
	go func() {
		_, callErr := client.Random(context.Background(), 16)
		callDone <- callErr
	}()
	select {
	case <-gate.Entered:
	case <-time.After(5 * time.Second):
		t.Fatal("gated call never reached the module")
	}

	// Removing the token retires the route: it vanishes from the very next
	// listing even though the call above is still parked inside the module.
	if err := h.module.RemoveToken(1); err != nil {
		t.Fatal(err)
	}
	if got := h.listRoutes(t); len(got) != 0 {
		t.Fatalf("routes after token removal = %v, want none", routeIDs(got))
	}
	select {
	case err := <-callDone:
		t.Fatalf("in-flight call ended before release: %v", err)
	default:
	}
	if count := h.module.SessionCount(); count == 0 {
		t.Fatal("retired target released its sessions before the in-flight call finished")
	}

	gate.Open()
	select {
	case err := <-callDone:
		if err != nil {
			t.Fatalf("in-flight call on retired route failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight call did not complete after release")
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if h.module.SessionCount() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retired target still holds %d sessions", h.module.SessionCount())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Concurrent listings wait for the in-flight reconciliation and share its
// single enumeration.
func TestDiscoveryConcurrentListingsShareEnumeration(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	h := newDiscoveryHarness(t, testmock.New("coalesce", 2), &discoverySpec{Module: "test:coalesce"}, cfg)

	baseline := h.module.SlotListCalls()
	gate := testmock.NewGate()
	h.module.SetGate("GetSlotList", gate)

	const listings = 8
	var wg sync.WaitGroup
	results := make(chan error, listings)
	for range listings {
		wg.Go(func() {
			_, err := proxy.ListRoutes(context.Background(), proxy.Target{
				Endpoints:         []string{h.address},
				AllowInsecure:     true,
				SecurityContextID: "discovery-test",
				Auth:              func(context.Context) ([]byte, error) { return []byte("workload"), nil },
				RequestTimeout:    5 * time.Second,
			})
			results <- err
		})
	}
	select {
	case <-gate.Entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no listing reached the enumeration gate")
	}
	// Let every waiter join the in-flight reconciliation before releasing it.
	time.Sleep(100 * time.Millisecond)
	gate.Open()
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("listing failed: %v", err)
		}
	}
	if got := h.module.SlotListCalls(); got != baseline+1 {
		t.Fatalf("GetSlotList calls = %d, want baseline+1 = %d", got, baseline+1)
	}
}

// Two tokens resolving to one route ID are both skipped; an override keyed by
// slot separates them.
func TestDiscoveryCollisionSkipsUntilOverrideSeparates(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	module := testmock.New("clash", 1) // serial TEST-CLASH-0001
	module.AddToken("clash-token-2", "TEST-CLASH-0001")

	h := newDiscoveryHarness(t, module, &discoverySpec{Module: "test:clash"}, cfg)
	if got := h.listRoutes(t); len(got) != 0 {
		t.Fatalf("colliding tokens published %v, want none", routeIDs(got))
	}

	slot2 := uint(2)
	separated := &discoverySpec{
		Module: "test:clash",
		Overrides: []discoveryOverride{
			{Name: "clash-beta", SlotID: &slot2},
		},
	}
	module2 := testmock.New("clash2", 1)
	module2.AddToken("clash2-token-2", "TEST-CLASH2-0001")
	h2 := newDiscoveryHarness(t, module2, separated, cfg)
	routes := h2.listRoutes(t)
	if len(routes) != 2 {
		t.Fatalf("separated routes = %v, want 2", routeIDs(routes))
	}
	ids := map[string]bool{routes[0].ID: true, routes[1].ID: true}
	if !ids["clash-beta"] || !ids["TEST-CLASH2-0001"] {
		t.Fatalf("separated route IDs = %v", routeIDs(routes))
	}
}

// Overrides select their token by serial, label, or slot ID.
func TestDiscoveryOverrideSelectors(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	slot := uint(3)
	spec := &discoverySpec{
		Module: "test:pick",
		Overrides: []discoveryOverride{
			{Name: "by-serial", TokenSerial: "TEST-PICK-0001"},
			{Name: "by-label", TokenLabel: "pick-token-2"},
			{Name: "by-slot", SlotID: &slot},
		},
	}
	h := newDiscoveryHarness(t, testmock.New("pick", 3), spec, cfg)
	routes := h.listRoutes(t)
	ids := routeIDs(routes)
	if len(ids) != 3 {
		t.Fatalf("routes = %v", ids)
	}
	byID := map[string]proxy.RouteInfo{}
	for _, route := range routes {
		byID[route.ID] = route
	}
	if byID["by-serial"].SlotID != 1 || byID["by-label"].SlotID != 2 || byID["by-slot"].SlotID != 3 {
		t.Fatalf("override bindings = %+v", byID)
	}
}

// An override matching no token or several tokens fails startup naming it.
func TestDiscoveryOverrideCardinality(t *testing.T) {
	module := testmock.New("card", 2)
	source := testmock.SharedSource{Name: "card", Module: module}

	zero := &discoverySpec{Module: "test:card", Overrides: []discoveryOverride{
		{Name: "ghost", TokenSerial: "NO-SUCH-SERIAL"},
	}}
	reconciler, err := newDiscoverer(zero, source, nil, sessionSpec{}, activationSpec{})
	if err != nil {
		t.Fatal(err)
	}
	err = reconciler.validateOverrideMatches(mustListTokens(t, source))
	if err == nil || !strings.Contains(err.Error(), `"ghost"`) || !strings.Contains(err.Error(), "0 tokens") {
		t.Fatalf("zero-match error = %v", err)
	}

	twin := testmock.New("card2", 1)
	twin.AddToken("card2-token-2", "TEST-CARD2-0001") // same serial as slot 1
	twinSource := testmock.SharedSource{Name: "card2", Module: twin}
	multi := &discoverySpec{Module: "test:card2", Overrides: []discoveryOverride{
		{Name: "ambiguous", TokenSerial: "TEST-CARD2-0001"},
	}}
	reconciler, err = newDiscoverer(multi, twinSource, nil, sessionSpec{}, activationSpec{})
	if err != nil {
		t.Fatal(err)
	}
	err = reconciler.validateOverrideMatches(mustListTokens(t, twinSource))
	if err == nil || !strings.Contains(err.Error(), `"ambiguous"`) || !strings.Contains(err.Error(), "2 tokens") {
		t.Fatalf("multi-match error = %v", err)
	}

	slot2 := uint(2)
	dupe := &discoverySpec{Module: "test:card", Overrides: []discoveryOverride{
		{Name: "same", TokenSerial: "TEST-CARD-0001"},
		{Name: "same", SlotID: &slot2},
	}}
	if _, err := newDiscoverer(dupe, source, nil, sessionSpec{}, activationSpec{}); err == nil ||
		!strings.Contains(err.Error(), `"same"`) {
		t.Fatalf("duplicate-name error = %v", err)
	}
}

func mustListTokens(t *testing.T, source pkcs11.ModuleSource) []pkcs11.TokenSummary {
	t.Helper()
	summaries, err := pkcs11.ListTokens(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	return summaries
}

// The derived revision is stable across restarts with unchanged config and
// shifts with the template, module, vendor set, or route identity.
func TestDiscoveryRevisionStability(t *testing.T) {
	module := testmock.New("rev", 1)
	summaries := mustListTokens(t, testmock.SharedSource{Name: "rev", Module: module})
	template := sessionSpec{MaxPhysicalTotal: 8, MaxQueued: 64}
	activation := activationSpec{FailureCooldown: time.Second}
	spec := &discoverySpec{Module: "test:rev"}
	source := testmock.SharedSource{Name: "rev", Module: module}

	build := func(t *testing.T, mutate func(*discoverySpec), sessions sessionSpec, act activationSpec, src pkcs11.ModuleSource, vendors []pkcs11.VendorModule) string {
		t.Helper()
		specCopy := *spec
		if mutate != nil {
			mutate(&specCopy)
		}
		d, err := newDiscoverer(&specCopy, src, vendors, sessions, act)
		if err != nil {
			t.Fatal(err)
		}
		return d.routeFor(summaries[0]).revision
	}

	base := build(t, nil, template, activation, source, nil)
	if again := build(t, nil, template, activation, source, nil); again != base {
		t.Fatalf("same config produced %q then %q", base, again)
	}

	changedTemplate := template
	changedTemplate.MaxPhysicalTotal = 4
	if got := build(t, nil, changedTemplate, activation, source, nil); got == base {
		t.Fatal("template change did not move the revision")
	}
	if got := build(t, nil, template, activationSpec{FailureCooldown: 2 * time.Second}, source, nil); got == base {
		t.Fatal("activation change did not move the revision")
	}
	otherModule := testmock.New("rev2", 1)
	otherSource := testmock.SharedSource{Name: "rev2", Module: otherModule}
	otherSummaries := mustListTokens(t, otherSource)
	d2, err := newDiscoverer(spec, otherSource, nil, template, activation)
	if err != nil {
		t.Fatal(err)
	}
	if got := d2.routeFor(otherSummaries[0]).revision; got == base {
		t.Fatal("module change did not move the revision")
	}
	vendors := all.Modules()
	if len(vendors) == 0 {
		t.Skip("no bundled vendor modules")
	}
	if got := build(t, nil, template, activation, source, vendors[:1]); got == base {
		t.Fatal("vendor allowlist change did not move the revision")
	}
	if got := build(t, func(s *discoverySpec) {
		s.Overrides = []discoveryOverride{{Name: "named", TokenSerial: "TEST-REV-0001"}}
	}, template, activation, source, nil); got == base {
		t.Fatal("route identity change did not move the revision")
	}
}

// discovery and targets[] reject each other, and discovery requires a module.
func TestDiscoveryConfigValidation(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	cfg.Discovery = []discoverySpec{{Module: "test:solo"}}
	cfg.Targets = testTargets()
	if _, err := newServerOn(context.Background(), cfg, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("targets+discovery error = %v", err)
	}

	cfg.Targets = nil
	cfg.Discovery = []discoverySpec{{}}
	if _, err := newServerOn(context.Background(), cfg, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "discovery[0]: module") {
		t.Fatalf("missing module error = %v", err)
	}

	cfg.Discovery = []discoverySpec{{Module: "test:solo", Overrides: []discoveryOverride{{Name: "bad"}}}}
	if _, err := newServerOn(context.Background(), cfg, nil, nil); err == nil ||
		!strings.Contains(err.Error(), `"bad"`) {
		t.Fatalf("selector-less override error = %v", err)
	}

	// Two entries over the same module would collide on every route ID.
	cfg.Discovery = []discoverySpec{{Module: "test:dup"}, {Module: "test:dup"}}
	if _, err := newServerOn(context.Background(), cfg, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "discovery[1]") {
		t.Fatalf("duplicate module error = %v", err)
	}
}

// A whole-module enumeration failure at startup aborts the broker.
func TestDiscoveryStartupEnumerationFailure(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	cfg.Discovery = []discoverySpec{{Module: "/nonexistent/pkcs11.so"}}
	if _, err := newServerOn(context.Background(), cfg, nil, nil); err == nil {
		t.Fatal("discovery on an unloadable module started")
	}
}

// A module reporting zero tokens starts and serves an empty catalog.
func TestDiscoveryZeroTokensServesEmptyCatalog(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	module := testmock.New("empty", 1)
	if err := module.RemoveToken(1); err != nil {
		t.Fatal(err)
	}
	h := newDiscoveryHarness(t, module, &discoverySpec{Module: "test:empty"}, cfg)
	if got := h.listRoutes(t); len(got) != 0 {
		t.Fatalf("empty module routes = %v", routeIDs(got))
	}
}

// YAML keys unknown to the schema fail startup, naming the key — at top level
// and nested inside discovery or an override.
func TestUnknownConfigKeysFailStartup(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "pkcs11-proxy.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	load := func(t *testing.T, body string) error {
		t.Helper()
		t.Setenv("PKCS11_PROXY_CONFIG", write(t, body))
		_, err := loadOptions(nil)
		return err
	}

	err := load(t, "insecure: true\ntargets: [{module: test}]\nbogus_key: 1\n")
	if err == nil || !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("top-level unknown key error = %v", err)
	}

	err = load(t, "insecure: true\ndiscovery:\n  - module: test:x\n    bogosity: 1\n")
	if err == nil || !strings.Contains(err.Error(), "bogosity") {
		t.Fatalf("nested discovery key error = %v", err)
	}

	err = load(t, "insecure: true\ndiscovery:\n  - module: test:x\n    overrides:\n    - name: a\n      slot_id: 1\n      bogus_field: 2\n")
	if err == nil || !strings.Contains(err.Error(), "bogus_field") {
		t.Fatalf("nested override key error = %v", err)
	}

	// Bound flags appearing as file keys stay outside the check, and a fully
	// known file loads with its discovery list decoded.
	path := write(t, "config: ignored.yaml\nhelp: true\ninsecure: true\ndiscovery:\n  - module: test:x\n")
	t.Setenv("PKCS11_PROXY_CONFIG", path)
	cfg, err := loadOptions(nil)
	if err != nil {
		t.Fatalf("valid file with flag-named keys failed: %v", err)
	}
	if len(cfg.Discovery) != 1 || cfg.Discovery[0].Module != "test:x" {
		t.Fatalf("discovery section decoded as %+v", cfg.Discovery)
	}
}

// TestDiscoveryIntegration runs the real broker with a discovery config
// against the module PKCS11_MODULE names (SoftHSM in the conformance
// fixtures): the catalog publishes one route per initialised token.
func TestDiscoveryIntegration(t *testing.T) {
	modulePath := strings.TrimSpace(os.Getenv("PKCS11_MODULE"))
	if modulePath == "" {
		t.Skip("PKCS11_MODULE is not set")
	}
	want, err := pkcs11.ListTokens(context.Background(), pkcs11.LocalModule(modulePath))
	if err != nil {
		t.Fatalf("enumerate %s: %v", modulePath, err)
	}
	healthy := 0
	for _, summary := range want {
		if summary.Err == nil {
			healthy++
		}
	}
	if healthy == 0 {
		t.Skip("module reports no readable tokens")
	}

	cfg := defaultOptions(t)
	cfg.Insecure = true
	cfg.Discovery = []discoverySpec{{Module: modulePath}}
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

	routes, err := proxy.ListRoutes(ctx, proxy.Target{
		Endpoints:         []string{listener.Addr().String()},
		AllowInsecure:     true,
		SecurityContextID: "discovery-integration",
		Auth:              func(context.Context) ([]byte, error) { return []byte("workload"), nil },
		RequestTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != healthy {
		t.Fatalf("catalog = %v, want %d routes (one per readable token)", routeIDs(routes), healthy)
	}
	for _, route := range routes {
		if route.Revision == "" || route.Revision == targetRevision {
			t.Fatalf("route %q revision %q is not derived", route.ID, route.Revision)
		}
	}
}

// targets[] configs are unaffected by the discovery machinery.
func TestTargetsConfigStillServesStatically(t *testing.T) {
	cfg := defaultOptions(t)
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
	defer func() { _ = server.Close(context.Background()) }()
	ids := server.TargetIDs()
	if len(ids) != 3 {
		t.Fatalf("targets routes = %v, want 3", ids)
	}
}

// Two discovery[] entries — say a Securosys and a Utimaco library on the same
// host — merge into one catalog; each module keeps reconciling independently,
// so a token added on either appears on the next listing.
func TestDiscoveryMultiModuleMergesCatalogs(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	moduleA := testmock.New("alpha", 2)
	moduleB := testmock.New("beta", 1)
	dA, err := newDiscoverer(&discoverySpec{Module: "test:alpha", RefreshInterval: -1},
		testmock.SharedSource{Name: "alpha", Module: moduleA}, nil, cfg.Sessions, cfg.Activation)
	if err != nil {
		t.Fatal(err)
	}
	dB, err := newDiscoverer(&discoverySpec{Module: "test:beta", RefreshInterval: -1},
		testmock.SharedSource{Name: "beta", Module: moduleB}, nil, cfg.Sessions, cfg.Activation)
	if err != nil {
		t.Fatal(err)
	}
	_, address := serveDiscoverySet(t, reconcilerSet{dA, dB})

	want := []string{"TEST-ALPHA-0001", "TEST-ALPHA-0002", "TEST-BETA-0001"}
	if got := routeIDs(listDiscoveryRoutes(t, address)); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("merged catalog = %v, want %v", got, want)
	}

	moduleB.AddToken("beta-token-extra", "TEST-BETA-EXTRA")
	want = []string{"TEST-ALPHA-0001", "TEST-ALPHA-0002", "TEST-BETA-0001", "TEST-BETA-EXTRA"}
	if got := routeIDs(listDiscoveryRoutes(t, address)); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("after module B add = %v, want %v", got, want)
	}

	if err := moduleA.RemoveToken(1); err != nil {
		t.Fatal(err)
	}
	want = []string{"TEST-ALPHA-0002", "TEST-BETA-0001", "TEST-BETA-EXTRA"}
	if got := routeIDs(listDiscoveryRoutes(t, address)); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("after module A remove = %v, want %v", got, want)
	}
}

// A module whose enumeration fails outright keeps its last published routes
// and does not suppress the other module's reconciliation — the listing still
// answers the merged catalog while the error is logged.
func TestDiscoveryModuleFailureKeepsOthers(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	moduleA := testmock.New("sick", 1)
	moduleB := testmock.New("well", 1)
	dA, err := newDiscoverer(&discoverySpec{Module: "test:sick", RefreshInterval: -1},
		testmock.SharedSource{Name: "sick", Module: moduleA}, nil, cfg.Sessions, cfg.Activation)
	if err != nil {
		t.Fatal(err)
	}
	dB, err := newDiscoverer(&discoverySpec{Module: "test:well", RefreshInterval: -1},
		testmock.SharedSource{Name: "well", Module: moduleB}, nil, cfg.Sessions, cfg.Activation)
	if err != nil {
		t.Fatal(err)
	}
	_, address := serveDiscoverySet(t, reconcilerSet{dA, dB})

	moduleA.SetFault("GetSlotList", raw.Error(raw.CKR_DEVICE_ERROR))
	moduleB.AddToken("well-token-extra", "TEST-WELL-EXTRA")

	want := []string{"TEST-SICK-0001", "TEST-WELL-0001", "TEST-WELL-EXTRA"}
	if got := routeIDs(listDiscoveryRoutes(t, address)); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog with sick module = %v, want %v", got, want)
	}

	moduleA.SetFault("GetSlotList", nil)
	moduleA.AddToken("sick-token-back", "TEST-SICK-BACK")
	want = []string{"TEST-SICK-0001", "TEST-SICK-BACK", "TEST-WELL-0001", "TEST-WELL-EXTRA"}
	if got := routeIDs(listDiscoveryRoutes(t, address)); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog after recovery = %v, want %v", got, want)
	}
}

// name_prefix namespaces a module's derived route IDs so two HSMs cannot
// collide; override names are verbatim and ignore the prefix.
func TestDiscoveryNamePrefix(t *testing.T) {
	cfg := defaultOptions(t)
	cfg.Insecure = true
	spec := &discoverySpec{
		Module:     "test:pfx",
		NamePrefix: "qp-",
		Overrides: []discoveryOverride{
			{Name: "named", TokenSerial: "TEST-PFX-0001"},
		},
	}
	h := newDiscoveryHarness(t, testmock.New("pfx", 2), spec, cfg)

	want := []string{"named", "qp-TEST-PFX-0002"}
	if got := routeIDs(h.listRoutes(t)); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("prefixed routes = %v, want %v", got, want)
	}
}
