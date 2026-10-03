package proxycmd

import (
	"context"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/otpki/pkcs11/internal/auditlog"
	"github.com/otpki/pkcs11/internal/obslog"
	"github.com/otpki/pkcs11/internal/pki"
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
	RouteCatalog() []proxy.RouteInfo
	// InstanceID and State expose the process identity and drain lifecycle so
	// the dashboard can show which replica produced a status snapshot.
	InstanceID() [16]byte
	State() proxy.ServerState
	// Health returns per-route token health, the same data /readyz reports.
	// Callers pass a bounded context: probes are sessionless and shared, but a
	// hung native module makes the wait reach the deadline.
	Health(context.Context) []proxy.TargetHealth
	LogicalClients() int
	// Counters exposes the process-local §30 request counters.
	Counters() proxy.ServerCounters
	// ClientInfos is the per-logical-client table.
	ClientInfos() []proxy.ClientInfo
}

// devStatus is the payload returned by the status endpoint. It deliberately
// contains no PIN material, object identities, or request payloads — the
// underlying TargetStats and RouteInfo are already designed secret-free.
type devStatus struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Server      devServerInfo     `json:"server"`
	Targets     []devTargetStatus `json:"targets"`
}

type devServerInfo struct {
	Address        string               `json:"address"`
	GoVersion      string               `json:"go_version"`
	PID            int                  `json:"pid"`
	UptimeSeconds  int64                `json:"uptime_seconds"`
	ServerID       string               `json:"server_id"`
	State          string               `json:"state"`
	TLSMode        string               `json:"tls_mode"`
	LogicalClients int                  `json:"logical_clients"`
	Counters       proxy.ServerCounters `json:"counters"`
	Clients        []proxy.ClientInfo   `json:"clients"`
	Observability  devObservability     `json:"observability"`
}

// devObservability reports the health of the telemetry pipeline itself:
// whether OTLP export is configured, the non-blocking log queue's depth and
// drop count, and the signed audit log's chain statistics. Key material is
// never included — only the public key ID.
type devObservability struct {
	OTelEnabled      bool   `json:"otel_enabled"`
	LogQueueDepth    int    `json:"log_queue_depth"`
	LogQueueCap      int    `json:"log_queue_cap"`
	LogDropped       uint64 `json:"log_dropped"`
	LogFlushed       uint64 `json:"log_flushed"`
	AuditEnabled     bool   `json:"audit_enabled"`
	AuditKeyID       string `json:"audit_key_id,omitempty"`
	AuditWritten     uint64 `json:"audit_written"`
	AuditSealed      uint64 `json:"audit_sealed"`
	AuditPending     int    `json:"audit_pending"`
	AuditCheckpoints uint64 `json:"audit_checkpoints"`
	AuditDropped     uint64 `json:"audit_dropped"`
	AuditFailed      uint64 `json:"audit_failed"`
	// HealthListen is the bound probe/metrics listener address, empty when the
	// health listener is disabled.
	HealthListen string `json:"health_listen,omitempty"`
}

// devTargetStatus couples one route's live counters with the broker's
// published descriptor, so the dashboard shows which physical token each
// route is bound to.
type devTargetStatus struct {
	proxy.RouteInfo
	Stats proxy.TargetStats `json:"stats"`
	// Health is the route's last shared token probe — the same entry /readyz
	// reports — so the dashboard shows which token is sick, not just counts.
	Health *proxy.TargetHealth `json:"health,omitempty"`
}

// devUI serves a read-only operational dashboard for one broker. It is a
// development tool: the default bind is loopback only and the handler exposes
// nothing that can mutate broker or token state.
type devUI struct {
	source       statusSource
	address      string
	tlsMode      string
	healthListen string
	startedAt    time.Time
	logHandler   *obslog.AsyncHandler
	audit        *auditlog.Writer
	otel         bool
}

func newDevUI(source statusSource, address string) *devUI {
	return &devUI{source: source, address: address, startedAt: time.Now()}
}

func (d *devUI) status(ctx context.Context) devStatus {
	ids := d.source.TargetIDs()
	catalog := make(map[string]proxy.RouteInfo, len(ids))
	for _, info := range d.source.RouteCatalog() {
		catalog[info.ID] = info
	}
	probeCtx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
	health := d.source.Health(probeCtx)
	cancel()
	healthByID := make(map[string]proxy.TargetHealth, len(health))
	for _, entry := range health {
		healthByID[entry.ID] = entry
	}
	targets := make([]devTargetStatus, 0, len(ids))
	for _, id := range ids {
		stats, ok := d.source.TargetStats(id)
		if !ok {
			continue
		}
		info := catalog[id]
		if info.ID == "" {
			info.ID = id
		}
		entry := devTargetStatus{RouteInfo: info, Stats: stats}
		if probe, found := healthByID[id]; found {
			entry.Health = &probe
		}
		targets = append(targets, entry)
	}
	serverID := d.source.InstanceID()
	obs := devObservability{OTelEnabled: d.otel, HealthListen: d.healthListen}
	if d.logHandler != nil {
		obs.LogQueueDepth = d.logHandler.QueueLen()
		obs.LogQueueCap = d.logHandler.QueueCap()
		obs.LogDropped = d.logHandler.Dropped()
		obs.LogFlushed = d.logHandler.Flushed()
	}
	if d.audit != nil {
		obs.AuditEnabled = true
		obs.AuditKeyID = d.audit.KeyID()
		obs.AuditWritten = d.audit.Written()
		obs.AuditSealed = d.audit.Sealed()
		obs.AuditPending = d.audit.Pending()
		obs.AuditCheckpoints = d.audit.Checkpoints()
		obs.AuditDropped = d.audit.Dropped()
		obs.AuditFailed = d.audit.Failed()
	}
	return devStatus{
		GeneratedAt: time.Now(),
		Server: devServerInfo{
			Address:        d.address,
			GoVersion:      runtime.Version(),
			PID:            os.Getpid(),
			UptimeSeconds:  int64(time.Since(d.startedAt).Seconds()),
			ServerID:       hex.EncodeToString(serverID[:]),
			State:          d.source.State().String(),
			TLSMode:        d.tlsMode,
			LogicalClients: d.source.LogicalClients(),
			Counters:       d.source.Counters(),
			Clients:        d.source.ClientInfos(),
			Observability:  obs,
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
	mux.Handle("GET /dev/api/status", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeDevJSON(w, d.status(r.Context()))
	}))
	mux.Handle("GET /dev/api/audit/events", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d.audit == nil {
			writeDevJSON(w, map[string]any{"enabled": false})
			return
		}
		tail := 50
		if raw := r.URL.Query().Get("tail"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 512 {
				tail = parsed
			}
		}
		writeDevJSON(w, map[string]any{
			"enabled": true,
			"key_id":  d.audit.KeyID(),
			"sealed":  d.audit.Sealed(),
			"pending": d.audit.Pending(),
			"events":  d.audit.Tail(tail),
		})
	}))
	// Verifying reads the whole log on demand, so this is click-triggered
	// rather than polled; the public key alone is all it needs.
	mux.Handle("GET /dev/api/audit/verify", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if d.audit == nil {
			writeDevJSON(w, map[string]any{"enabled": false})
			return
		}
		report, err := auditlog.Verify(d.audit.Path(), d.audit.PublicKey())
		payload := map[string]any{"enabled": true, "key_id": d.audit.KeyID()}
		if err != nil {
			payload["ok"] = false
			payload["error"] = err.Error()
		} else {
			payload["ok"] = true
			payload["report"] = report
		}
		writeDevJSON(w, payload)
	}))
	// The PKI tool mints a development mTLS bundle in memory and returns the
	// PEM files for browser download — it writes nothing to disk and touches
	// no broker state, keeping the dashboard's read-only guarantee.
	mux.Handle("POST /dev/api/pki", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CAName    string   `json:"ca_cn"`
			CADays    int      `json:"ca_days"`
			LeafDays  int      `json:"leaf_days"`
			ServerCN  string   `json:"server_cn"`
			Hosts     []string `json:"hosts"`
			Clients   []string `json:"clients"`
			ServerOff bool     `json:"ca_only"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.CAName == "" {
			req.CAName = "pkcs11-proxy dev CA"
		}
		if len(req.Hosts) > 32 || len(req.Clients) > 32 || req.CADays > 36500 || req.LeafDays > 36500 {
			http.Error(w, "request exceeds dev-tool limits", http.StatusBadRequest)
			return
		}
		ca, err := pki.GenerateCA(req.CAName, req.CADays)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tree := &pki.Tree{CA: ca}
		if !req.ServerOff {
			serverCN := req.ServerCN
			if serverCN == "" {
				serverCN = "pkcs11-proxy"
			}
			server, err := ca.IssueServer(serverCN, req.Hosts, req.LeafDays)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			tree.Server = server
		}
		for _, name := range req.Clients {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			client, err := ca.IssueClient(name, req.LeafDays)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			tree.Clients = append(tree.Clients, client)
		}
		files := map[string]string{}
		for name, content := range tree.Files() {
			files[name] = string(content)
		}
		writeDevJSON(w, map[string]any{"files": files})
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
	//nolint:gosec // Shutdown must outlive the server ctx that triggered it.
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown) //nolint:contextcheck // Shutdown intentionally uses a detached timeout ctx.
	}()
	go func() { _ = server.Serve(listener) }()
	return listener.Addr().String(), nil
}

func devUIAddress(listen string, allowRemote bool) (string, error) {
	return loopbackListenAddress("dev_ui", listen, allowRemote)
}
