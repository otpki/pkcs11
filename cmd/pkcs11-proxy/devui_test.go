package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/otpki/pkcs11/proxy"
)

type fakeStatusSource struct {
	ids    []string
	stats  map[string]proxy.TargetStats
	orphan string
}

func (f *fakeStatusSource) TargetIDs() []string { return f.ids }

func (f *fakeStatusSource) TargetStats(id string) (proxy.TargetStats, bool) {
	stats, ok := f.stats[id]
	return stats, ok
}

func testDevUI() *devUI {
	return newDevUI(&fakeStatusSource{
		ids: []string{"hsm"},
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
	}, "127.0.0.1:9443", map[string]string{"hsm": "v1"})
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
	stats := payload.Targets[0].Stats
	if stats.Clients != 3 || stats.Authenticated != 2 || stats.Activation.State != proxy.ActivationActive {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestDevUIStatusSkipsVanishedTargets(t *testing.T) {
	d := newDevUI(&fakeStatusSource{
		ids:   []string{"gone", "hsm"},
		stats: map[string]proxy.TargetStats{"hsm": {}},
	}, "", nil)
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
