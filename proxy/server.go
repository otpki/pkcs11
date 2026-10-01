package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RequestIdentity describes the authenticated network peer independently of
// any HSM credential or logical PKCS #11 login.
type RequestIdentity struct {
	// Principal is populated by Server after transport authentication. It must
	// be stable across the same workload's request-scoped connections.
	Principal string
	// RemoteAddress is the transport peer address and is suitable for audit
	// context, not durable authorization identity.
	RemoteAddress string
	// PeerCertificates contains the TLS peer chain presented by the connection.
	// The slice is a per-request copy.
	PeerCertificates []*x509.Certificate
	// Auth is opaque, short-lived material returned by Target.Auth. The
	// transport Authenticator may validate it, but must not retain the byte
	// slice.
	Auth []byte
	// Target and Revision identify the immutable broker route requested by the
	// client.
	Target   string
	Revision string
	// ClientID identifies one logical Cryptoki application. The broker binds it
	// permanently to Principal for the lifetime of the logical client.
	ClientID [16]byte
}

// Authenticator verifies a network peer and returns a stable, non-secret
// principal identifier. The same workload must receive the same principal
// across request-scoped connections; the broker binds each logical PKCS #11
// client ID to that principal so one peer cannot reuse another peer's virtual
// sessions or object handles.
//
// It runs after the transport handshake and fixed-size request framing are
// validated, but before a target is selected or any HSM capacity is consumed.
// TargetConfig.Authorize is the separate target-level authorization hook.
type Authenticator func(context.Context, RequestIdentity) (principal string, err error)

// Authorizer is retained as an alias for the original transport callback name.
// New code should use Authenticator for peer authentication and
// TargetConfig.Authorize for authorization.
type Authorizer = Authenticator

// ServerState reports where the proxy process sits in its lifecycle.
type ServerState int

const (
	// ServerActive accepts new logical clients and serves all established ones.
	ServerActive ServerState = iota
	// ServerDraining refuses new logical clients while established clients
	// continue until they close, idle-expire, or the drain deadline forces the
	// process down.
	ServerDraining
)

func (state ServerState) String() string {
	switch state {
	case ServerActive:
		return "active"
	case ServerDraining:
		return "draining"
	default:
		return "unknown"
	}
}

// ServerConfig controls the connection-facing proxy service. One request is
// accepted per connection and the connection is always closed afterward.
type ServerConfig struct {
	// Listener supplies an already-created listener. When set, Address is ignored.
	Listener net.Listener
	// Address is passed to net.Listen when Listener is nil.
	Address string
	// TLS configures server transport security and is cloned. Targets that trust
	// transport identity require either verified client certificates or an
	// Authenticator.
	TLS *tls.Config
	// AllowInsecure permits plaintext TCP for isolated development tests only.
	AllowInsecure bool
	// MaximumMessageSize bounds request and response frames before allocation.
	MaximumMessageSize int
	// ReadTimeout bounds receipt of one complete framed request.
	ReadTimeout time.Duration
	// WriteTimeout bounds transmission of the corresponding response.
	WriteTimeout time.Duration
	// MaxConnections bounds concurrent accepted sockets before any HSM queue or
	// session capacity is consumed. Excess connections are closed immediately.
	MaxConnections int
	// Authenticator authenticates the peer and returns the stable principal used
	// to isolate logical clients. With verified mTLS and no callback, the leaf
	// certificate digest is used automatically.
	Authenticator Authenticator
	// Authorizer is the legacy name for Authenticator. Configure at most one.
	Authorizer Authorizer
	// DrainTimeout bounds graceful scale-down: after Drain begins, WaitDrained
	// waits for established logical clients to finish before targets are
	// closed. Clients that linger past the deadline observe ErrTargetLost when
	// the process finally stops. Zero selects the default.
	DrainTimeout time.Duration
	// Audit receives secret-free security events (client lifecycle, logins,
	// activations, maintenance, and request rejections). It must be
	// non-blocking; nil disables audit emission.
	Audit AuditSink
}

// Server multiplexes independent client connections onto explicitly configured
// HSM targets. It owns no business configuration beyond immutable TargetConfig
// values supplied by its caller.
type Server struct {
	config ServerConfig

	// instanceID identifies this running proxy process to clients. It is
	// generated at startup and never persisted, so a process restart always
	// changes it — exactly the failure boundary clients fence against.
	instanceID [16]byte
	state      atomic.Int32

	listenerMu sync.RWMutex
	listener   net.Listener

	targetsMu sync.RWMutex
	targets   map[string]*brokerTarget

	connections       chan struct{}
	connectionMu      sync.Mutex
	activeConnections map[net.Conn]struct{}
	handlers          sync.WaitGroup
	serving           atomic.Bool
	closing           atomic.Bool
	obs               serverObs
	stopOnce          sync.Once
	finishOnce        sync.Once
	closed            chan struct{}
	finished          chan struct{}
	closeErr          error
}

// NewServer opens all configured targets before accepting traffic. If any
// target fails, already-opened targets are closed before returning.
func NewServer(ctx context.Context, config ServerConfig, targets ...TargetConfig) (*Server, error) {
	if config.Authenticator != nil && config.Authorizer != nil {
		return nil, errors.New("pkcs11 proxy: configure only one of ServerConfig.Authenticator or ServerConfig.Authorizer")
	}
	if config.Listener == nil && config.Address == "" {
		return nil, errors.New("pkcs11 proxy: listener or address is required")
	}
	if config.TLS == nil && !config.AllowInsecure {
		return nil, errors.New("pkcs11 proxy: server TLS is required unless AllowInsecure is set")
	}
	if config.TLS != nil {
		config.TLS = config.TLS.Clone()
	}
	if config.MaximumMessageSize <= 0 {
		config.MaximumMessageSize = defaultMaximumMessageSize
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 1024
	}
	if config.DrainTimeout <= 0 {
		config.DrainTimeout = 5 * time.Minute
	}
	server := &Server{
		config:            config,
		targets:           make(map[string]*brokerTarget),
		connections:       make(chan struct{}, config.MaxConnections),
		activeConnections: make(map[net.Conn]struct{}),
		closed:            make(chan struct{}),
		finished:          make(chan struct{}),
		obs:               serverObs{audit: config.Audit},
	}
	if _, err := rand.Read(server.instanceID[:]); err != nil {
		return nil, fmt.Errorf("pkcs11 proxy: generate server ID: %w", err)
	}
	server.registerGauges()
	for _, targetConfig := range targets {
		if err := server.AddTarget(ctx, cloneTargetConfig(targetConfig)); err != nil {
			_ = server.Close(ctx)
			return nil, err
		}
	}
	return server, nil
}

func (server *Server) validateTargetSecurity(config TargetConfig) error {
	if !config.Login.TrustTransportIdentity || config.Login.Authenticate != nil {
		return nil
	}
	if server.config.Authenticator != nil || server.config.Authorizer != nil {
		return nil
	}
	if server.config.TLS == nil || server.config.TLS.ClientAuth != tls.RequireAndVerifyClientCert {
		return fmt.Errorf("pkcs11 proxy: target %q trusts transport identity but server has neither an Authenticator nor verified client-certificate authentication", config.ID)
	}
	return nil
}

// AddTarget opens and atomically publishes a new immutable target route.
func (server *Server) AddTarget(ctx context.Context, config TargetConfig) error {
	config = cloneTargetConfig(config)
	if server == nil || server.closing.Load() {
		return errors.New("pkcs11 proxy: server is closed")
	}
	if err := server.validateTargetSecurity(config); err != nil {
		return err
	}
	target, err := newBrokerTarget(ctx, config, &server.obs)
	if err != nil {
		return fmt.Errorf("pkcs11 proxy: open target %q: %w", config.ID, err)
	}
	server.targetsMu.Lock()
	if server.closing.Load() {
		server.targetsMu.Unlock()
		_ = target.close(ctx)
		return errors.New("pkcs11 proxy: server is closed")
	}
	if _, exists := server.targets[target.id]; exists {
		server.targetsMu.Unlock()
		_ = target.close(ctx)
		return fmt.Errorf("pkcs11 proxy: duplicate target %q", target.id)
	}
	server.targets[target.id] = target
	server.targetsMu.Unlock()
	return nil
}

// ReplaceTarget opens replacement before publishing it, so existing routes stay
// available when the new HSM configuration cannot be opened. Requests carrying
// the old revision are rejected after the swap. The previous target drains all
// in-flight work before its physical sessions are closed.
func (server *Server) ReplaceTarget(ctx context.Context, config TargetConfig) error {
	config = cloneTargetConfig(config)
	if server == nil || server.closing.Load() {
		return errors.New("pkcs11 proxy: server is closed")
	}
	if err := server.validateTargetSecurity(config); err != nil {
		return err
	}
	replacement, err := newBrokerTarget(ctx, config, &server.obs)
	if err != nil {
		return fmt.Errorf("pkcs11 proxy: open replacement target %q: %w", config.ID, err)
	}
	server.targetsMu.Lock()
	if server.closing.Load() {
		server.targetsMu.Unlock()
		_ = replacement.close(ctx)
		return errors.New("pkcs11 proxy: server is closed")
	}
	previous := server.targets[replacement.id]
	server.targets[replacement.id] = replacement
	server.targetsMu.Unlock()
	if previous != nil {
		return previous.close(ctx)
	}
	return nil
}

// RemoveTarget unpublishes a route, then drains and closes its physical HSM
// resources. New calls fail with target_not_found immediately after removal.
func (server *Server) RemoveTarget(ctx context.Context, id string) error {
	if server == nil {
		return nil
	}
	server.targetsMu.Lock()
	target := server.targets[id]
	delete(server.targets, id)
	server.targetsMu.Unlock()
	if target == nil {
		return nil
	}
	return target.close(ctx)
}

// TargetIDs returns the currently published route IDs in stable order.
func (server *Server) TargetIDs() []string {
	if server == nil {
		return nil
	}
	server.targetsMu.RLock()
	ids := make([]string, 0, len(server.targets))
	for id := range server.targets {
		ids = append(ids, id)
	}
	server.targetsMu.RUnlock()
	sort.Strings(ids)
	return ids
}

// RouteCatalog describes every published route in stable order. It is the
// payload behind the server-scoped @routes request: clients use it to discover
// which routes exist and which token each is bound to before choosing
// Target.Route and Target.Revision.
func (server *Server) RouteCatalog() []RouteInfo {
	if server == nil {
		return nil
	}
	server.targetsMu.RLock()
	targets := make([]*brokerTarget, 0, len(server.targets))
	for _, target := range server.targets {
		targets = append(targets, target)
	}
	server.targetsMu.RUnlock()
	sort.Slice(targets, func(i, j int) bool { return targets[i].id < targets[j].id })
	routes := make([]RouteInfo, 0, len(targets))
	for _, target := range targets {
		routes = append(routes, target.routeInfo())
	}
	return routes
}

// routeCatalogResponse answers the server-scoped @routes method. It runs after
// transport authentication but is not bound to any route or epoch, so a client
// can discover the catalog before selecting one.
func (server *Server) routeCatalogResponse() response {
	resp := response{Version: protocolVersion}
	encoded, err := encodeWireValue(routeCatalog{Routes: server.RouteCatalog()}, emptyCodecRegistry())
	if err != nil {
		resp.Error = encodeError(err)
		return resp
	}
	resp.Results = []wireValue{encoded}
	return resp
}

// TargetStats returns a route's current bounded-resource usage.
func (server *Server) TargetStats(id string) (TargetStats, bool) {
	if server == nil {
		return TargetStats{}, false
	}
	server.targetsMu.RLock()
	target := server.targets[id]
	server.targetsMu.RUnlock()
	if target == nil {
		return TargetStats{}, false
	}
	return target.stats(), true
}

// InstanceID is the random identity generated for this proxy process. Clients
// fence every established request against it; a restart always changes it.
func (server *Server) InstanceID() [16]byte {
	if server == nil {
		return [16]byte{}
	}
	return server.instanceID
}

// State reports the server lifecycle state.
func (server *Server) State() ServerState {
	if server == nil {
		return ServerDraining
	}
	return ServerState(server.state.Load())
}

// accepting reports whether new logical clients may establish on this process.
// Draining or closing servers keep serving pinned clients but refuse new ones.
func (server *Server) accepting() bool {
	return server != nil && server.state.Load() == int32(ServerActive) && !server.closing.Load()
}

// Drain marks the process draining: new logical clients are refused at
// establishment while every existing client keeps its pinned route until it
// closes or idle-expires. It does not close the listener or in-flight work;
// callers finish scale-down with WaitDrained followed by Shutdown or Close.
func (server *Server) Drain(ctx context.Context) {
	if server == nil {
		return
	}
	if server.state.CompareAndSwap(int32(ServerActive), int32(ServerDraining)) {
		server.obs.emitAudit(context.WithoutCancel(ctx), AuditEvent{Type: "drain"})
	}
}

// Counters returns a snapshot of the process-local request counters backing
// the exported §30 metrics, for status surfaces like the dev UI.
func (server *Server) Counters() ServerCounters {
	if server == nil {
		return ServerCounters{}
	}
	return ServerCounters{
		RequestsTotal:    server.obs.requestsTotal.Load(),
		TransportErrors:  server.obs.transportErrors.Load(),
		AuthFailures:     server.obs.authFailures.Load(),
		FenceRejections:  server.obs.fenceRejections.Load(),
		DrainRejections:  server.obs.drainRejections.Load(),
		StaleGenerations: server.obs.staleGenerations.Load(),
	}
}

// ClientInfos returns a secret-free snapshot of every established logical
// client across all routes, sorted by target then age, for status surfaces
// like the dev UI.
func (server *Server) ClientInfos() []ClientInfo {
	if server == nil {
		return nil
	}
	server.targetsMu.RLock()
	targets := make([]*brokerTarget, 0, len(server.targets))
	for _, target := range server.targets {
		targets = append(targets, target)
	}
	server.targetsMu.RUnlock()
	var out []ClientInfo
	for _, target := range targets {
		out = append(out, target.clientInfos()...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Since.Before(out[j].Since)
	})
	return out
}

// MethodOutcomes returns the process-local request breakdown by route,
// method, and outcome — the same dimensions the exported
// pkcs11_proxy_requests_total metric carries.
func (server *Server) MethodOutcomes() []MethodOutcome {
	if server == nil {
		return nil
	}
	return server.obs.methodOutcomeSnapshot()
}

// RecentRequests returns the newest entries of the bounded in-process request
// feed, most recent first. n <= 0 means the whole buffer.
func (server *Server) RecentRequests(n int) []RequestEvent {
	if server == nil {
		return nil
	}
	return server.obs.recentRequestSnapshot(n)
}

// RouteCapabilities returns the routable algorithm names and mechanism count
// of the token behind one route — the managed client's capability snapshot,
// refreshed as the token is rediscovered.
func (server *Server) RouteCapabilities(id string) (algorithms []string, mechanisms int, ok bool) {
	server.targetsMu.RLock()
	target := server.targets[id]
	server.targetsMu.RUnlock()
	if server == nil || target == nil {
		return nil, 0, false
	}
	algorithms, mechanisms = target.tokenCapabilities()
	return algorithms, mechanisms, true
}

// LogicalClients returns the number of established logical PKCS #11 clients
// retained across all routes. During draining it is the countdown to zero.
func (server *Server) LogicalClients() int {
	if server == nil {
		return 0
	}
	server.targetsMu.RLock()
	targets := make([]*brokerTarget, 0, len(server.targets))
	for _, target := range server.targets {
		targets = append(targets, target)
	}
	server.targetsMu.RUnlock()
	total := 0
	for _, target := range targets {
		total += target.clientCount()
	}
	return total
}

// WaitDrained polls until no logical clients remain or ctx expires. It is the
// graceful scale-down wait: after Drain, established clients finish naturally
// and the caller proceeds to Shutdown once this returns.
//
//nolint:contextcheck // Nil callers intentionally fall back to a detached context.
func (server *Server) WaitDrained(ctx context.Context) error {
	if server == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if server.LogicalClients() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Addr returns the active listener address after Serve begins.
func (server *Server) Addr() net.Addr {
	if server == nil {
		return nil
	}
	server.listenerMu.RLock()
	listener := server.listener
	server.listenerMu.RUnlock()
	if listener == nil {
		return nil
	}
	return listener.Addr()
}

// Serve accepts connections until Close or Shutdown is called, or the listener
// returns a permanent error. Cancellation of ctx marks the server draining —
// the listener stays open so already-pinned clients keep working — and the
// caller is expected to WaitDrained and then Shutdown. That gives scale-down
// the order: stop accepting new logical clients, let existing ones finish,
// then stop the process.
func (server *Server) Serve(ctx context.Context) error {
	if server == nil {
		return errors.New("pkcs11 proxy: nil server")
	}
	if !server.serving.CompareAndSwap(false, true) {
		return errors.New("pkcs11 proxy: Serve may be called only once")
	}
	if ctx == nil {
		ctx = context.Background() //nolint:contextcheck // Fallback for callers that pass no serving context.
	}
	listener := server.config.Listener
	if listener == nil {
		var err error
		listener, err = net.Listen("tcp", server.config.Address)
		if err != nil {
			return err
		}
	}
	if server.config.TLS != nil {
		listener = tls.NewListener(listener, server.config.TLS.Clone())
	}
	server.listenerMu.Lock()
	server.listener = listener
	server.listenerMu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
			server.Drain(ctx)
		case <-server.closed:
		}
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-server.closed:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if server.closing.Load() {
			_ = connection.Close()
			continue
		}
		select {
		case server.connections <- struct{}{}:
			server.connectionMu.Lock()
			if server.closing.Load() {
				server.connectionMu.Unlock()
				<-server.connections
				_ = connection.Close()
				continue
			}
			server.activeConnections[connection] = struct{}{}
			server.handlers.Add(1)
			server.connectionMu.Unlock()
			go func() {
				defer server.handlers.Done()
				defer func() { <-server.connections }()
				defer func() {
					server.connectionMu.Lock()
					delete(server.activeConnections, connection)
					server.connectionMu.Unlock()
				}()
				server.handleConnection(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (server *Server) authenticateIdentity(ctx context.Context, identity RequestIdentity) (string, error) {
	authenticator := server.config.Authenticator
	if authenticator == nil {
		authenticator = server.config.Authorizer
	}
	if authenticator != nil {
		principal, err := authenticator(ctx, identity)
		if err != nil {
			return "", err
		}
		principal = strings.TrimSpace(principal)
		if principal == "" {
			return "", errors.New("authenticator returned an empty principal")
		}
		return principal, nil
	}
	if len(identity.PeerCertificates) != 0 {
		digest := sha256.Sum256(identity.PeerCertificates[0].Raw)
		return "mtls-sha256:" + hex.EncodeToString(digest[:]), nil
	}
	// Server-only TLS and explicitly insecure development listeners do not
	// authenticate the peer. They still receive one stable anonymous principal;
	// targets using this mode must provide a LogicalAuthenticator.
	return "anonymous", nil
}

//nolint:contextcheck // Nil callers intentionally fall back to a detached context.
func (server *Server) handleConnection(parent context.Context, connection net.Conn) {
	defer func() { _ = connection.Close() }()
	if parent == nil {
		parent = context.Background()
	}
	_ = connection.SetDeadline(time.Now().Add(max(server.config.ReadTimeout, server.config.WriteTimeout)))

	identity := RequestIdentity{RemoteAddress: connection.RemoteAddr().String()}
	if tlsConnection, ok := connection.(*tls.Conn); ok {
		if err := tlsConnection.HandshakeContext(parent); err != nil {
			server.obs.transportErrors.Add(1)
			transportErrors.Add(parent, 1)
			return
		}
		state := tlsConnection.ConnectionState()
		identity.PeerCertificates = append([]*x509.Certificate(nil), state.PeerCertificates...)
	}

	_ = connection.SetReadDeadline(time.Now().Add(server.config.ReadTimeout))
	var req request
	if err := readMessage(connection, &req, server.config.MaximumMessageSize); err != nil {
		server.obs.transportErrors.Add(1)
		transportErrors.Add(parent, 1)
		return
	}
	defer func() {
		wipe(req.Auth)
		for index := range req.Arguments {
			wipeWireValue(&req.Arguments[index])
		}
	}()

	ctx, cancelRequest := context.WithCancel(parent)
	defer cancelRequest()
	if req.DeadlineUnixNano != 0 {
		deadline := time.Unix(0, req.DeadlineUnixNano)
		if current, ok := ctx.Deadline(); !ok || deadline.Before(current) {
			var deadlineCancel context.CancelFunc
			ctx, deadlineCancel = context.WithDeadline(ctx, deadline)
			defer deadlineCancel()
		}
	}
	// After the complete framed request has been read, any additional byte is a
	// protocol violation and EOF means the caller disconnected. A dedicated
	// reader lets disconnect cancel queue waits and other context-aware work while
	// the HSM call itself remains subject to the vendor's native cancellation
	// limits. net.Conn and tls.Conn both permit one reader and one writer.
	_ = connection.SetReadDeadline(time.Time{})
	disconnected := make(chan struct{})
	go func() {
		defer close(disconnected)
		var extra [1]byte
		_, _ = connection.Read(extra[:])
		cancelRequest()
	}()

	identity.Auth = append([]byte(nil), req.Auth...)
	identity.Target = req.Target
	identity.Revision = req.Revision
	identity.ClientID = req.ClientID
	defer wipe(identity.Auth)

	spanCtx, span := startRequestSpan(ctx, server.instanceID, identity, req)
	started := time.Now()

	resp := response{Version: protocolVersion}
	if req.Version != protocolVersion {
		resp.Error = encodeError(&RemoteError{Code: "protocol_version", Message: fmt.Sprintf("got %d, want %d", req.Version, protocolVersion)})
	} else if err := validateRequestEnvelope(req); err != nil {
		resp.Error = encodeError(err)
	} else if req.ServerID != ([16]byte{}) && req.ServerID != server.instanceID {
		// A request pinned to a different proxy process must fail closed before
		// it can create or touch logical-client state here.
		resp.Error = encodeError(&RemoteError{Code: "wrong_server", Message: "request belongs to another proxy server instance"})
	} else {
		principal, err := server.authenticateIdentity(spanCtx, identity)
		if err != nil {
			resp.Error = encodeError(&RemoteError{Code: "unauthorized", Message: err.Error()})
		} else {
			identity.Principal = principal
		}
	}
	if resp.Error == nil {
		if req.Method == methodListRoutes {
			resp = server.routeCatalogResponse()
		} else {
			server.targetsMu.RLock()
			target := server.targets[req.Target]
			server.targetsMu.RUnlock()
			switch {
			case target == nil:
				resp.Error = encodeError(&RemoteError{Code: "target_not_found", Message: "target is not configured"})
			case target.revision != req.Revision:
				resp.Error = encodeError(&RemoteError{Code: "revision_mismatch", Message: "target revision does not match server configuration"})
			default:
				resp = target.handle(spanCtx, identity, req, server)
			}
		}
	}
	code := outcomeCode(resp)
	endRequestSpan(span, code)
	server.obs.observeRequest(ctx, server.instanceID, identity, req, code, time.Since(started))
	server.obs.observeRejection(ctx, server.instanceID, identity, req, code)
	defer wipeResponse(&resp)
	_ = connection.SetWriteDeadline(time.Now().Add(server.config.WriteTimeout))
	if err := writeMessage(connection, resp, server.config.MaximumMessageSize); err != nil {
		server.obs.transportErrors.Add(1)
		transportErrors.Add(ctx, 1)
	}
}

// Shutdown stops accepting new connections, allows active requests to finish,
// and then closes all target clients and physical HSM sessions. If ctx expires,
// active connections are force-closed before target shutdown proceeds.
//
//nolint:contextcheck // Nil callers intentionally fall back to a detached context.
func (server *Server) Shutdown(ctx context.Context) error {
	if server == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	server.stopAccepting()
	waitErr := server.waitHandlers(ctx)
	if waitErr != nil {
		server.forceCloseConnections()
		server.handlers.Wait()
	}
	closeErr := server.finishTargets(ctx)
	return errors.Join(waitErr, closeErr)
}

// Close force-closes active client connections, waits for their handlers to
// exit, and then closes all target resources. Use Shutdown for graceful drain.
func (server *Server) Close(ctx context.Context) error {
	if server == nil {
		return nil
	}
	server.stopAccepting()
	server.forceCloseConnections()
	server.handlers.Wait()
	return server.finishTargets(ctx)
}

func (server *Server) stopAccepting() {
	server.stopOnce.Do(func() {
		server.closing.Store(true)
		close(server.closed)
		server.listenerMu.RLock()
		listener := server.listener
		server.listenerMu.RUnlock()
		if listener == nil {
			listener = server.config.Listener
		}
		if listener != nil {
			_ = listener.Close()
		}
	})
}

func (server *Server) forceCloseConnections() {
	server.connectionMu.Lock()
	connections := make([]net.Conn, 0, len(server.activeConnections))
	for connection := range server.activeConnections {
		connections = append(connections, connection)
	}
	server.connectionMu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (server *Server) waitHandlers(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		server.handlers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (server *Server) finishTargets(ctx context.Context) error {
	server.finishOnce.Do(func() {
		server.targetsMu.Lock()
		targets := server.targets
		server.targets = make(map[string]*brokerTarget)
		server.targetsMu.Unlock()
		var errs []error
		for _, target := range targets {
			if err := target.close(ctx); err != nil {
				errs = append(errs, err)
			}
		}
		server.closeErr = errors.Join(errs...)
		close(server.finished)
	})
	<-server.finished
	return server.closeErr
}

func validateRequestEnvelope(req request) error {
	if req.Method == "" {
		return &RemoteError{Code: "invalid_request", Message: "method is required"}
	}
	if req.ClientID == ([16]byte{}) || req.RequestID == ([16]byte{}) {
		return &RemoteError{Code: "invalid_request", Message: "client ID and request ID must be nonzero"}
	}
	// @routes is server-scoped: it is answered before route selection and is
	// not bound to a target name, revision, or epoch.
	if req.Method == methodListRoutes {
		return nil
	}
	if req.Target == "" || req.Revision == "" {
		return &RemoteError{Code: "invalid_request", Message: "target and revision are required"}
	}
	if req.Method != methodDescribe && req.Epoch == ([16]byte{}) {
		return &RemoteError{Code: "invalid_request", Message: "target epoch is required"}
	}
	// Established requests must carry the server identity they learned at
	// describe time; @describe and @routes are probing methods and arrive with
	// a zero ServerID.
	if req.Method != methodDescribe && req.ServerID == ([16]byte{}) {
		return &RemoteError{Code: "invalid_request", Message: "server ID is required"}
	}
	return nil
}
