package proxycmd

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
)

// healthProbeTimeout bounds how long /readyz and the dev UI wait for per-route
// probes, and /readyz for discovery. A module hung inside a native call
// reports its route unhealthy at this deadline instead of holding the request;
// the shared probe keeps running in the background, capped at one goroutine per route.
const healthProbeTimeout = 5 * time.Second

// healthSource is the slice of *proxy.Server the health listener uses: the
// lifecycle state for the readiness decision, the bound broker address for
// "the listener serves", discovery, and the per-route probe results.
type healthSource interface {
	State() proxy.ServerState
	Addr() net.Addr
	RefreshRoutes(context.Context) error
	Health(context.Context) []proxy.TargetHealth
}

// readyzResponse is the readiness payload. It is secret-free: TargetHealth
// carries status, activation, and per-check outcomes only — never PINs,
// module paths, object identities, or payloads.
type readyzResponse struct {
	Ready          bool                 `json:"ready"`
	State          string               `json:"state"`
	Listener       string               `json:"listener,omitempty"`
	DiscoveryError string               `json:"discovery_error,omitempty"`
	Routes         []proxy.TargetHealth `json:"routes"`
}

// healthServer serves the unauthenticated probe and metrics endpoints used by
// orchestrators. It sees the broker only through healthSource.
type healthServer struct {
	source       healthSource
	metrics      http.Handler
	probeTimeout time.Duration
}

// Handler routes GET /healthz, /readyz, and /metrics; all other paths 404.
func (h *healthServer) Handler() http.Handler {
	timeout := h.probeTimeout
	if timeout <= 0 {
		timeout = healthProbeTimeout
	}
	mux := http.NewServeMux()
	// Liveness answers from the HTTP stack alone: it never reads broker or
	// token state, so a sick or hung module can never trigger a restart, and
	// draining keeps reporting 200 until the process exits.
	mux.Handle("GET /healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	}))
	// Draining and a failed discovery answer 503: the orchestrator must stop
	// routing before the drain timeout, and the failing module's routes may be
	// stale. One sick route shows only in the body.
	mux.Handle("GET /readyz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeCtx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		state := h.source.State()
		listener := h.source.Addr()
		discovered := startDiscovery(probeCtx, h.source)
		routes := h.source.Health(probeCtx)
		discoveryErr := <-discovered
		ready := state == proxy.ServerActive && listener != nil && discoveryErr == nil
		body := readyzResponse{
			Ready:  ready,
			State:  state.String(),
			Routes: routes,
		}
		if listener != nil {
			body.Listener = listener.String()
		}
		if discoveryErr != nil {
			body.DiscoveryError = discoveryFailure(discoveryErr)
		}
		payload, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write(payload)
	}))
	if h.metrics != nil {
		mux.Handle("GET /metrics", h.metrics)
	}
	return securityHeaders(mux)
}

// startDiscovery refreshes the routes beside the route probes, which keep their
// full deadline when a module hangs. The probes can see the catalog from before
// this refresh.
func startDiscovery(ctx context.Context, source healthSource) <-chan error {
	done := make(chan error, 1)
	go func() { done <- source.RefreshRoutes(ctx) }()
	return done
}

const unclassifiedDiscoveryError = "discovery failed"

// discoveryFailure names a failed discovery by its PKCS #11 return value, its
// deadline, or unclassifiedDiscoveryError. The full error carries module paths,
// which the payload omits.
func discoveryFailure(err error) string {
	if code, ok := errors.AsType[raw.Error](err); ok {
		return code.Error()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded.Error()
	}
	return unclassifiedDiscoveryError
}

// healthListener is the bound health HTTP server. Unlike the dev UI it is not
// tied to the serving context: Shutdown runs during process teardown after
// draining completes, so /readyz keeps answering 503 and /healthz 200 through
// graceful scale-down.
type healthListener struct {
	server *http.Server
	addr   string
}

// startHealthListener binds synchronously — an invalid address or a refused
// non-loopback bind fails startup — then serves in the background.
func startHealthListener(listen string, allowRemote bool, handler http.Handler) (*healthListener, error) {
	address, err := loopbackListenAddress("health", listen, allowRemote)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("health listen %s: %w", address, err)
	}
	bound := &healthListener{
		server: &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second},
		addr:   listener.Addr().String(),
	}
	go func() { _ = bound.server.Serve(listener) }()
	return bound, nil
}

func (l *healthListener) Addr() string { return l.addr }

// Shutdown drains in-flight requests; the caller bounds the wait. A hung token
// probe never blocks it: probe goroutines are detached, so at the deadline the
// server is abandoned and dies with the process.
func (l *healthListener) Shutdown(ctx context.Context) error {
	return l.server.Shutdown(ctx)
}

// loopbackListenAddress validates the bind address for a secret-free
// unauthenticated listener: loopback only unless that section's allow_remote
// option is set. kind is the config section name ("health", "dev_ui") used in
// error messages so operators see the exact key to flip.
func loopbackListenAddress(kind, listen string, allowRemote bool) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("%s listen %q: %w", kind, listen, err)
	}
	host = cmp.Or(host, "127.0.0.1")
	if allowRemote {
		return net.JoinHostPort(host, port), nil
	}
	ip := net.ParseIP(host)
	if (ip == nil || !ip.IsLoopback()) && host != "localhost" {
		return "", fmt.Errorf("%s listen %q is not loopback; set %s.allow_remote: true to expose it", kind, listen, kind)
	}
	return net.JoinHostPort(host, port), nil
}
