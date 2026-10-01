package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otpki/pkcs11/internal/auditlog"
	"github.com/otpki/pkcs11/proxy"
)

type fakeStatusSource struct {
	ids    []string
	stats  map[string]proxy.TargetStats
	routes []proxy.RouteInfo
}

func (f *fakeStatusSource) TargetIDs() []string { return f.ids }

func (f *fakeStatusSource) TargetStats(id string) (proxy.TargetStats, bool) {
	stats, ok := f.stats[id]
	return stats, ok
}

func (f *fakeStatusSource) RouteCatalog() []proxy.RouteInfo { return f.routes }

func (f *fakeStatusSource) InstanceID() [16]byte { return [16]byte{7} }

func (f *fakeStatusSource) State() proxy.ServerState { return proxy.ServerActive }

func (f *fakeStatusSource) LogicalClients() int { return 3 }

func (f *fakeStatusSource) Counters() proxy.ServerCounters {
	return proxy.ServerCounters{RequestsTotal: 42, AuthFailures: 1, FenceRejections: 2}
}

func (f *fakeStatusSource) ClientInfos() []proxy.ClientInfo {
	return []proxy.ClientInfo{
		{
			ID: "aaaa", Target: "hsm", Principal: "workload-sha256:cc", Via: "Initialize",
			Since: time.Now().Add(-time.Minute), LastUsed: time.Now(), Authenticated: true,
			VirtualSessions: 2, Objects: 5,
		},
	}
}

func testDevUI() *devUI {
	return newDevUI(&fakeStatusSource{
		ids: []string{"hsm"},
		routes: []proxy.RouteInfo{
			{ID: "hsm", Revision: "v1", SlotID: 3, TokenLabel: "mock-token", TokenSerial: "0001", Model: "mockHSM", ManufacturerID: "otpki"},
		},
		stats: map[string]proxy.TargetStats{
			"hsm": {
				Clients:         3,
				Authenticated:   2,
				VirtualSessions: 7,
				PhysicalOpened:  4,
				PhysicalActive:  2,
				MaxPhysical:     8,
				DedupBytes:      512,
				DedupEntries:    2,
				MaxDedupBytes:   65536,
				Activation:      proxy.ActivationStatus{State: proxy.ActivationActive, Generation: 1, ActivatedBy: "workload-sha256:aa"},
			},
		},
	}, "127.0.0.1:9443")
}

func TestDevUIStatusEndpoint(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/dev/api/status", nil)
	testDevUI().Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if ct := recorder.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var payload devStatus
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Server.Address != "127.0.0.1:9443" || payload.Server.GoVersion == "" || payload.Server.PID <= 0 {
		t.Fatalf("server info = %+v", payload.Server)
	}
	if len(payload.Targets) != 1 || payload.Targets[0].ID != "hsm" || payload.Targets[0].Revision != "v1" {
		t.Fatalf("targets = %+v", payload.Targets)
	}
	if payload.Targets[0].TokenLabel != "mock-token" || payload.Targets[0].TokenSerial != "0001" || payload.Targets[0].SlotID != 3 {
		t.Fatalf("route catalog fields = %+v", payload.Targets[0].RouteInfo)
	}
	stats := payload.Targets[0].Stats
	if stats.Clients != 3 || stats.Authenticated != 2 || stats.Activation.State != proxy.ActivationActive {
		t.Fatalf("stats = %+v", stats)
	}
	if payload.Server.Counters.RequestsTotal != 42 || payload.Server.Counters.FenceRejections != 2 {
		t.Fatalf("counters = %+v", payload.Server.Counters)
	}
	if len(payload.Server.Clients) != 1 || payload.Server.Clients[0].Principal != "workload-sha256:cc" {
		t.Fatalf("clients = %+v", payload.Server.Clients)
	}
	if payload.Server.Observability.OTelEnabled || payload.Server.Observability.AuditEnabled {
		t.Fatalf("observability defaults should report disabled = %+v", payload.Server.Observability)
	}
}

func TestDevUIStatusSkipsVanishedTargets(t *testing.T) {
	d := newDevUI(&fakeStatusSource{
		ids:   []string{"gone", "hsm"},
		stats: map[string]proxy.TargetStats{"hsm": {}},
	}, "")
	status := d.status()
	if len(status.Targets) != 1 || status.Targets[0].ID != "hsm" {
		t.Fatalf("targets = %+v", status.Targets)
	}
}

func TestDevUIServesPageAndSecurityHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/dev/", nil)
	testDevUI().Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("/dev/ = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "/dev/api/status") {
		t.Fatal("dashboard page does not reference the status endpoint")
	}
	recorder = httptest.NewRecorder()
	testDevUI().Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/../config.go", nil))
	if recorder.Code == http.StatusOK {
		t.Fatal("path traversal outside embedded assets served")
	}
	recorder = httptest.NewRecorder()
	testDevUI().Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/", nil))
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store cache control")
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff")
	}
	if recorder.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP")
	}
}

func TestDevUIRedirectsRootAndRejectsWrites(t *testing.T) {
	handler := testDevUI().Handler()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/dev/" {
		t.Fatalf("root = %d location %q", recorder.Code, recorder.Header().Get("Location"))
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/dev/api/status", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/other", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d, want 404", recorder.Code)
	}
}

func TestDevUIAddressLoopbackGuard(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:9463", "[::1]:9463", ":9463", "localhost:9463"} {
		if _, err := devUIAddress(listen, false); err != nil {
			t.Fatalf("loopback %q rejected: %v", listen, err)
		}
	}
	if _, err := devUIAddress("0.0.0.0:9463", false); err == nil {
		t.Fatal("wildcard bind accepted without allow_remote")
	}
	if _, err := devUIAddress("0.0.0.0:9463", true); err != nil {
		t.Fatalf("wildcard bind with allow_remote: %v", err)
	}
	if _, err := devUIAddress("not-an-address", false); err == nil {
		t.Fatal("malformed listen accepted")
	}
}

func TestDevUIUptimeAdvances(t *testing.T) {
	d := testDevUI()
	d.startedAt = time.Now().Add(-2 * time.Second)
	if uptime := d.status().Server.UptimeSeconds; uptime < 2 {
		t.Fatalf("uptime = %d", uptime)
	}
}

// TestDevUIAuditEndpoints exercises the audit inspection surface end to end:
// the status payload reports sealed/pending accounting, the events endpoint
// returns decoded records, and the verify endpoint re-derives the signed
// checkpoint chain from the public key.
func TestDevUIAuditEndpoints(t *testing.T) {
	dir := t.TempDir()
	writer, err := auditlog.Open(filepath.Join(dir, "audit.log"), filepath.Join(dir, "audit.key"),
		auditlog.Options{BatchSize: 2, CheckpointInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	d := testDevUI()
	d.audit = writer
	handler := d.Handler()

	for i := range 3 {
		writer.AuditProxy(context.Background(), proxy.AuditEvent{
			Type: "login_grant", Target: "hsm",
			ClientID: fmt.Sprintf("%032x", i+1), Principal: "workload-sha256:bb",
		})
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/api/status", nil))
	var status devStatus
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	obs := status.Server.Observability
	if !obs.AuditEnabled || obs.AuditKeyID == "" || obs.AuditWritten != 3 ||
		obs.AuditSealed != 3 || obs.AuditCheckpoints != 2 || obs.AuditPending != 0 {
		t.Fatalf("audit observability = %+v", obs)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/api/audit/events?tail=2", nil))
	var events struct {
		Enabled bool              `json:"enabled"`
		Pending int               `json:"pending"`
		Events  []auditlog.Record `json:"events"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if !events.Enabled || len(events.Events) != 2 || events.Events[1].Seq != 3 {
		t.Fatalf("audit events = %+v", events)
	}
	if events.Events[0].Principal != "workload-sha256:bb" {
		t.Fatalf("decoded record missing principal: %+v", events.Events[0])
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/api/audit/verify", nil))
	var verify struct {
		OK     bool            `json:"ok"`
		Error  string          `json:"error"`
		Report auditlog.Report `json:"report"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &verify); err != nil {
		t.Fatal(err)
	}
	if !verify.OK || verify.Report.Records != 3 || verify.Report.Checkpoints != 2 {
		t.Fatalf("verify = %+v", verify)
	}

	// A tampered log must surface through the same endpoint as a failure.
	content, _ := os.ReadFile(writer.Path())
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	broken := []byte(lines[0])
	broken[len(broken)/2] ^= 0x40
	lines[0] = string(broken)
	tampered := filepath.Join(dir, "tampered.log")
	if err := os.WriteFile(tampered, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := auditlog.Verify(tampered, writer.PublicKey()); err == nil {
		t.Fatal("tampered log verified cleanly")
	}
}

// TestDevUIPKIEndpoint exercises the in-memory mTLS generator: a POST with
// the form parameters returns downloadable PEM files that verify as a real
// chain, without touching disk or broker state.
func TestDevUIPKIEndpoint(t *testing.T) {
	handler := testDevUI().Handler()
	body := strings.NewReader(`{"ca_cn":"test CA","server_cn":"broker","hosts":["127.0.0.1","broker.test"],"clients":["alice","bob"],"leaf_days":30}`)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/dev/api/pki", body))

	if recorder.Code != http.StatusOK {
		t.Fatalf("pki POST = %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.pem", "ca.key", "server.pem", "server.key", "clients/alice.pem", "clients/alice.key", "clients/bob.pem", "clients/bob.key"} {
		if payload.Files[name] == "" {
			t.Fatalf("bundle missing %s; got %v", name, slices.Sorted(maps.Keys(payload.Files)))
		}
	}
	// The returned server cert must chain to the returned CA.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(payload.Files["ca.pem"])) {
		t.Fatal("ca.pem did not parse")
	}
	block, _ := pem.Decode([]byte(payload.Files["server.pem"]))
	serverCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverCert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "broker.test"}); err != nil {
		t.Fatalf("generated server cert does not verify: %v", err)
	}
	// Over-limit requests reject rather than minting a pile of certs.
	big := strings.NewReader(`{"clients": [` + strings.Repeat(`"x",`, 40) + `"y"]}`)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/dev/api/pki", big))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("over-limit pki POST = %d, want 400", recorder.Code)
	}
	// GET on the POST-only endpoint falls through to the asset file server,
	// which finds no such file.
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/api/pki", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("GET pki = %d, want 404", recorder.Code)
	}
}

func TestDevUIAuditEndpointsDisabled(t *testing.T) {
	handler := testDevUI().Handler()
	for _, path := range []string{"/dev/api/audit/events", "/dev/api/audit/verify"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		var payload struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Enabled {
			t.Fatalf("%s reports audit enabled with no writer", path)
		}
	}
}
