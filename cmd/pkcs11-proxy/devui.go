package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/otpki/pkcs11/proxy"
)

//go:embed devui
var devUIAssets embed.FS

// statusSource is the slice of *proxy.Server the dev UI reads. It exposes only
// counts and secret-free operational state; the interface keeps the handler
// testable without a live broker.
type statusSource interface {
	TargetIDs() []string
	TargetStats(id string) (proxy.TargetStats, bool)
}

// devStatus is the payload returned by the status endpoint. It deliberately
// contains no PIN material, object identities, or request payloads — the
// underlying TargetStats is already designed secret-free.
type devStatus struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Server      devServerInfo     `json:"server"`
	Targets     []devTargetStatus `json:"targets"`
}

type devServerInfo struct {
	Address       string `json:"address"`
	GoVersion     string `json:"go_version"`
	PID           int    `json:"pid"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

type devTargetStatus struct {
	ID       string            `json:"id"`
	Revision string            `json:"revision"`
	Stats    proxy.TargetStats `json:"stats"`
}

// devUI serves a read-only operational dashboard for one broker. It is a
// development tool: the default bind is loopback only and the handler exposes
// nothing that can mutate broker or token state.
type devUI struct {
	source    statusSource
	address   string
	startedAt time.Time
	revisions map[string]string
}

func newDevUI(source statusSource, address string, revisions map[string]string) *devUI {
	return &devUI{source: source, address: address, startedAt: time.Now(), revisions: revisions}
}

func (d *devUI) status() devStatus {
	ids := d.source.TargetIDs()
	targets := make([]devTargetStatus, 0, len(ids))
	for _, id := range ids {
		stats, ok := d.source.TargetStats(id)
		if !ok {
			continue
		}
		targets = append(targets, devTargetStatus{ID: id, Revision: d.revisions[id], Stats: stats})
	}
	return devStatus{
		GeneratedAt: time.Now(),
		Server: devServerInfo{
			Address:       d.address,
			GoVersion:     runtime.Version(),
			PID:           os.Getpid(),
			UptimeSeconds: int64(time.Since(d.startedAt).Seconds()),
		},
		Targets: targets,
	}
}

// Handler routes under /dev/: the single-page asset at /dev/ and the JSON
// snapshot at /dev/api/status. All other paths return 404.
func (d *devUI) Handler() http.Handler {
	assets, err := fs.Sub(devUIAssets, "devui")
	if err != nil {
		panic(fmt.Sprintf("devui assets: %v", err))
	}
	mux := http.NewServeMux()
	mux.Handle("GET /dev/api/status", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeDevJSON(w, d.status())
	}))
	mux.Handle("GET /dev/", http.StripPrefix("/dev/", http.FileServer(http.FS(assets))))
	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/dev/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Cache-Control", "no-store")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

func writeDevJSON(w http.ResponseWriter, payload any) {
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// startDevUI binds the dashboard listener synchronously — so an invalid
// address or refused non-loopback bind fails startup — then serves in the
// background until ctx ends. The listener must be loopback unless allowRemote
// is set: the page discloses broker operational metadata and must not silently
// land on an external interface.
func startDevUI(ctx context.Context, listen string, allowRemote bool, d *devUI) (string, error) {
	address, err := devUIAddress(listen, allowRemote)
	if err != nil {
		return "", err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return "", fmt.Errorf("dev ui listen %s: %w", address, err)
	}
	server := &http.Server{Handler: d.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	go func() { _ = server.Serve(listener) }()
	return listener.Addr().String(), nil
}

func devUIAddress(listen string, allowRemote bool) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("dev ui listen %q: %w", listen, err)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if allowRemote {
		return net.JoinHostPort(host, port), nil
	}
	ip := net.ParseIP(host)
	loopback := ip != nil && ip.IsLoopback()
	if !loopback && host != "localhost" {
		return "", fmt.Errorf("dev ui listen %q is not loopback; set dev_ui.allow_remote: true to expose it", listen)
	}
	return net.JoinHostPort(host, port), nil
}
