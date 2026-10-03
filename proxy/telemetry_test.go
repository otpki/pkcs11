//go:build !windows

package proxy

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Package instruments delegate to the first provider installed and never
// rebind (OTel global delegation is one-shot), so the test suite shares one
// SDK pipeline installed for the whole run. Metrics accumulate across tests;
// assertions therefore check presence, never exact totals.
var (
	testSpanRecorder *tracetest.SpanRecorder
	testMetricReader *sdkmetric.ManualReader
	testLogExporter  *recordingLogExporter
)

func TestMain(m *testing.M) {
	testSpanRecorder = tracetest.NewSpanRecorder()
	testMetricReader = sdkmetric.NewManualReader()
	testLogExporter = &recordingLogExporter{}
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(testSpanRecorder)))
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(testMetricReader)))
	otel.SetLoggerProvider(sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(testLogExporter))))
	os.Exit(m.Run())
}

// recordingLogExporter is the minimal sdk/log Exporter used to capture emitted
// log records in tests.
type recordingLogExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *recordingLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.records = append(e.records, records...)
	return nil
}

func (e *recordingLogExporter) Shutdown(context.Context) error   { return nil }
func (e *recordingLogExporter) ForceFlush(context.Context) error { return nil }

func (e *recordingLogExporter) exported() []sdklog.Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.records)
}

// collectingSink records audit events emitted by the broker.
type collectingSink struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (s *collectingSink) AuditProxy(_ context.Context, event AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *collectingSink) types() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	types := make([]string, len(s.events))
	for i, event := range s.events {
		types[i] = event.Type
	}
	return types
}

func (s *collectingSink) contains(want string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.ContainsFunc(s.events, func(event AuditEvent) bool {
		return event.Type == want
	})
}

func hasAttr(attrs []attribute.KeyValue, key, value string) bool {
	return slices.ContainsFunc(attrs, func(attr attribute.KeyValue) bool {
		return string(attr.Key) == key && attr.Value.AsString() == value
	})
}

func TestTelemetryExportsSpansMetricsAndLogs(t *testing.T) {
	spanRecorder := testSpanRecorder
	metricReader := testMetricReader
	logExporter := testLogExporter

	source := testmock.Source{Name: "telemetry", Tokens: 1}
	server, addr := newTestmockBroker(t, testmockBrokerConfig(source))
	client, err := Open(context.Background(), haTarget(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetInfo(); err != nil {
		t.Fatal(err)
	}

	spans := spanRecorder.Ended()
	var serverSpan, clientSpan bool
	for _, span := range spans {
		// Other tests in this package also serve a "shared-hsm" route, so the
		// server span is identified by this broker's server_id specifically.
		if span.Name() == "pkcs11.proxy GetInfo" &&
			hasAttr(span.Attributes(), "pkcs11.server_id", hexID(server.InstanceID())) {
			serverSpan = true
		}
		if span.Name() == "pkcs11.proxy.client GetInfo" &&
			hasAttr(span.Attributes(), "pkcs11.client_id", hexID(client.id)) {
			clientSpan = true
		}
	}
	if !serverSpan || !clientSpan {
		names := make([]string, len(spans))
		for i, span := range spans {
			names[i] = span.Name()
		}
		t.Fatalf("ended spans = %v, want a pkcs11.proxy GetInfo server span and a client span", names)
	}

	var collected metricdata.ResourceMetrics
	if err := metricReader.Collect(context.Background(), &collected); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	var okRequests bool
	for _, scope := range collected.ScopeMetrics {
		for _, metric := range scope.Metrics {
			found[metric.Name] = true
			if metric.Name != "pkcs11_proxy_requests_total" {
				continue
			}
			if sum, isSum := metric.Data.(metricdata.Sum[int64]); isSum {
				for _, point := range sum.DataPoints {
					for _, attr := range point.Attributes.ToSlice() {
						if string(attr.Key) == "pkcs11.outcome" && attr.Value.AsString() == "ok" && point.Value > 0 {
							okRequests = true
						}
					}
				}
			}
		}
	}
	for _, name := range []string{
		"pkcs11_proxy_requests_total", "pkcs11_proxy_request_duration_seconds",
		"pkcs11_proxy_clients", "pkcs11_proxy_virtual_sessions",
		"pkcs11_proxy_physical_sessions", "pkcs11_proxy_pinned_sessions",
		"pkcs11_proxy_queue_depth", "pkcs11_proxy_dedup_entries",
	} {
		if !found[name] {
			t.Fatalf("metric %s never collected; have %v", name, found)
		}
	}
	if !okRequests {
		t.Fatal("pkcs11_proxy_requests_total has no positive ok outcome point")
	}

	// Request log records carry the §29 identity set; audit events carry their
	// type. The test sink-side exporter saw both through the global logger.
	var requestLog bool
	for _, record := range logExporter.exported() {
		var method, serverID bool
		record.WalkAttributes(func(kv attribute.KeyValue) bool {
			if kv.Key == "pkcs11.method" && kv.Value.AsString() == "GetInfo" {
				method = true
			}
			if kv.Key == "pkcs11.server_id" && kv.Value.AsString() == hexID(server.InstanceID()) {
				serverID = true
			}
			return true
		})
		if method && serverID {
			requestLog = true
		}
	}
	if !requestLog {
		t.Fatal("no emitted log record carried pkcs11.method=GetInfo with the server_id")
	}
}

func TestAuditSinkReceivesLifecycleEvents(t *testing.T) {
	sink := &collectingSink{}
	source := testmock.Source{Name: "audit", Tokens: 1}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener: listener, AllowInsecure: true, Audit: sink,
	}, testmockBrokerConfig(source))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(context.Background()) }()
	defer func() { _ = server.Close(context.Background()) }()

	client, err := Open(context.Background(), haTarget(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}
	session, err := client.OpenSession(1, raw.CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Login(session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatal(err)
	}
	if err := client.Logout(session); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"client_established", "activation", "login_grant", "logout", "client_destroyed"} {
		if !sink.contains(want) {
			t.Fatalf("audit events %v missing %q", sink.types(), want)
		}
	}
	counters := server.Counters()
	if counters.RequestsTotal == 0 {
		t.Fatal("requests_total = 0 after completed calls")
	}
}

func TestFenceRejectionIsCountedAndAudited(t *testing.T) {
	sink := &collectingSink{}
	source := testmock.Source{Name: "audit-fence", Tokens: 1}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener: listener, AllowInsecure: true, Audit: sink,
	}, testmockBrokerConfig(source))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(context.Background()) }()
	defer func() { _ = server.Close(context.Background()) }()

	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	req := request{
		Version: protocolVersion, Target: "shared-hsm", Revision: "v1",
		ClientID: [16]byte{9}, RequestID: [16]byte{10},
		ServerID: [16]byte{0xaa}, Epoch: [16]byte{3},
		Method: "GetInfo",
	}
	if err := writeMessage(connection, req, defaultMaximumMessageSize); err != nil {
		t.Fatal(err)
	}
	var resp response
	if err := readMessage(connection, &resp, defaultMaximumMessageSize); err != nil {
		t.Fatal(err)
	}
	if err := decodeError(resp.Error); !errors.Is(err, ErrTargetLost) {
		t.Fatalf("foreign-server request = %v, want ErrTargetLost", err)
	}
	counters := server.Counters()
	if counters.FenceRejections != 1 || counters.RequestsTotal != 1 {
		t.Fatalf("counters = %+v, want 1 fence rejection among 1 request", counters)
	}
	if !sink.contains("fence_rejection") {
		t.Fatalf("audit events %v missing fence_rejection", sink.types())
	}
}

// The dashboard surfaces mirror the exported metrics in-process: per-client
// table, method×outcome breakdown, recent-request feed, and token
// capabilities.
func TestDashboardSurfaces(t *testing.T) {
	source := testmock.Source{Name: "dashboard", Tokens: 1}
	server, addr := newTestmockBroker(t, testmockBrokerConfig(source))
	client, err := Open(context.Background(), haTarget(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetInfo(); err != nil {
		t.Fatal(err)
	}

	clients := server.ClientInfos()
	if len(clients) != 1 {
		t.Fatalf("ClientInfos = %+v, want one client", clients)
	}
	info := clients[0]
	if info.Target != "shared-hsm" || info.Via != "Initialize" || info.ID != hexID(client.id) ||
		info.Since.IsZero() || info.LastUsed.IsZero() {
		t.Fatalf("ClientInfo = %+v", info)
	}

	var sawGetInfo bool
	for _, cell := range server.MethodOutcomes() {
		if cell.Method == "GetInfo" && cell.Outcome == "ok" && cell.Count > 0 {
			sawGetInfo = true
		}
	}
	if !sawGetInfo {
		t.Fatalf("MethodOutcomes missing GetInfo/ok: %+v", server.MethodOutcomes())
	}

	recent := server.RecentRequests(16)
	if len(recent) == 0 || recent[0].Method == "" || recent[0].Time.IsZero() {
		t.Fatalf("RecentRequests = %+v", recent)
	}

	algorithms, mechanisms, ok := server.RouteCapabilities("shared-hsm")
	if !ok || mechanisms == 0 {
		t.Fatalf("RouteCapabilities = %v, %d, %t", algorithms, mechanisms, ok)
	}
	if _, _, ok := server.RouteCapabilities("missing-route"); ok {
		t.Fatal("RouteCapabilities reported a missing route")
	}
}

func TestClientMetricsOnTargetLoss(t *testing.T) {
	metricReader := testMetricReader
	source := testmock.Source{Name: "telemetry-loss", Tokens: 1}
	config := testmockBrokerConfig(source)
	serverA, addrA := newTestmockBroker(t, config)
	serverB, addrB := newTestmockBroker(t, config)
	client, err := Open(context.Background(), haTarget(addrA, addrB))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}
	// Kill whichever replica this client pinned to — pinning is client-hash
	// random, so target the actual owner rather than guessing.
	pinned := client.Endpoint()
	killable := map[string]*Server{addrA: serverA, addrB: serverB}[pinned]
	if killable == nil {
		t.Fatalf("client pinned to unconfigured endpoint %q", pinned)
	}
	_ = killable.Close(context.Background())
	if _, err := client.GetInfo(); !errors.Is(err, ErrTargetLost) {
		t.Fatalf("call after replica loss = %v, want ErrTargetLost", err)
	}

	var collected metricdata.ResourceMetrics
	if err := metricReader.Collect(context.Background(), &collected); err != nil {
		t.Fatal(err)
	}
	var targetLost bool
	for _, scope := range collected.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != "pkcs11_proxy_target_lost_total" {
				continue
			}
			if sum, isSum := metric.Data.(metricdata.Sum[int64]); isSum {
				for _, point := range sum.DataPoints {
					if point.Value > 0 {
						targetLost = true
					}
				}
			}
		}
	}
	if !targetLost {
		t.Fatal("pkcs11_proxy_target_lost_total was not incremented by ErrTargetLost")
	}
}
