package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// AuthProvider returns per-request proxy authentication material. Transport
// authentication such as mTLS should remain the primary identity; this hook is
// useful for short-lived workload tokens or capability credentials.
type AuthProvider func(context.Context) ([]byte, error)

// Target is immutable configuration for one remote proxy route.
//
// Target contains no live network connection and may safely be reconstructed
// from a database row on every application instance. RemoteModule copies the
// mutable fields. A configuration change should create a new Revision rather
// than mutating a Client that is already in use.
type Target struct {
	// ConfigID is the stable application or database identity of the HSM
	// configuration. It is diagnostic and participates in managed-module
	// registry identity; it is not sent to the local PKCS #11 module.
	ConfigID string
	// Revision is an immutable row version, ETag, generation, or content hash.
	// The broker rejects a request when its revision no longer matches the
	// published route, preventing stale configuration from silently continuing.
	Revision string
	// Endpoints lists proxy replicas that serve the same routes. A logical client is assigned to one
	// endpoint using rendezvous hashing and stays there for its lifetime.
	Endpoints []string
	// Route selects one broker-side TargetConfig. It is intentionally separate
	// from Endpoints so one broker can expose multiple HSMs or partitions.
	Route string
	// ServerName overrides TLS certificate name verification. When empty, the
	// host portion of the dialed endpoint is used. Set it explicitly when
	// Endpoints are IPs that share one TLS identity.
	ServerName string
	// SecurityContextID is an application-defined, non-secret identity for the
	// TLS roots, client certificate, workload identity, AuthProvider, and custom
	// Dialer policy. It participates in managed-module registry identity so two
	// security contexts never accidentally share one logical remote module.
	SecurityContextID string
	// TLS configures transport encryption and peer verification. It is cloned
	// before use. TLS is required unless AllowInsecure is explicitly enabled.
	TLS *tls.Config
	// AllowInsecure permits plaintext TCP and is intended only for isolated test
	// environments. It does not provide peer authentication or confidentiality.
	AllowInsecure bool
	// ConnectTimeout bounds each independent TCP connection attempt.
	ConnectTimeout time.Duration
	// RequestTimeout is the default end-to-end deadline when the caller context
	// has no earlier deadline.
	RequestTimeout time.Duration
	// MaximumMessageSize bounds both encoded requests and responses before large
	// allocations occur. Zero selects the package default.
	MaximumMessageSize int
	// MaxAttempts bounds transport attempts. Retries reuse the same request ID so
	// the broker can replay a retained non-idempotent response without repeating
	// the HSM operation. Zero selects the default.
	MaxAttempts int
	// MaxPooledConnections bounds transport connections the client keeps open
	// to its pinned endpoint for request reuse. Each connection serves one
	// request at a time, so the bound is also maximum request concurrency.
	// Zero selects the package default (4); a negative value disables pooling
	// and dials a fresh connection per request.
	MaxPooledConnections int
	// ConnectionIdleTimeout discards pooled connections idle longer than this
	// duration, so the client closes before the broker's read timeout does.
	// Zero selects the package default (25s).
	ConnectionIdleTimeout time.Duration
	// RetryInitialBackoff and RetryMaximumBackoff bound full-jitter delays
	// between attempts. Full jitter prevents a large stateless fleet from
	// synchronizing retries against a recovering broker.
	RetryInitialBackoff time.Duration
	RetryMaximumBackoff time.Duration
	// Dialer optionally customizes TCP establishment. The value is copied. A
	// custom dialer requires SecurityContextID because it can alter routing or
	// authentication outside the fields visible to RegistryKey.
	Dialer *net.Dialer
	// Auth returns short-lived per-request authentication material. The returned
	// bytes are copied into one request and wiped afterward. mTLS or another
	// stable transport principal should remain the primary client identity.
	Auth AuthProvider
	// Codecs adds application-owned semantic encoders for vendor mechanism
	// parameters that cannot be represented by the standard wire types.
	Codecs []ParameterCodec
	// Vendors are supplied to the managed client that consumes this source, so
	// remote discovery and vendor routing match the HSM behind the broker. Vendor
	// modules may also contribute ParameterCodec implementations.
	Vendors []pkcs11.VendorModule
}

func (target Target) validate() error {
	if strings.TrimSpace(target.ConfigID) == "" {
		return errors.New("pkcs11 proxy: ConfigID is required")
	}
	if strings.TrimSpace(target.Revision) == "" {
		return errors.New("pkcs11 proxy: Revision is required")
	}
	if len(target.Endpoints) == 0 {
		return errors.New("pkcs11 proxy: at least one endpoint is required")
	}
	for _, endpoint := range target.Endpoints {
		if strings.TrimSpace(endpoint) == "" {
			return errors.New("pkcs11 proxy: endpoints must not be empty")
		}
	}
	if strings.TrimSpace(target.Route) == "" {
		return errors.New("pkcs11 proxy: Route is required")
	}
	if target.TLS == nil && !target.AllowInsecure {
		return errors.New("pkcs11 proxy: TLS is required unless AllowInsecure is set")
	}
	if (target.TLS != nil || target.Auth != nil || target.Dialer != nil) && strings.TrimSpace(target.SecurityContextID) == "" {
		return errors.New("pkcs11 proxy: SecurityContextID is required when TLS, Auth, or a custom Dialer is configured")
	}
	return nil
}

func (target Target) normalized() Target {
	if target.ConnectTimeout <= 0 {
		target.ConnectTimeout = 5 * time.Second
	}
	if target.RequestTimeout <= 0 {
		target.RequestTimeout = 30 * time.Second
	}
	if target.MaximumMessageSize <= 0 {
		target.MaximumMessageSize = defaultMaximumMessageSize
	}
	if target.MaxAttempts <= 0 {
		target.MaxAttempts = 2
	}
	if target.MaxPooledConnections == 0 {
		target.MaxPooledConnections = defaultMaxPooledConns
	}
	if target.ConnectionIdleTimeout <= 0 {
		target.ConnectionIdleTimeout = defaultConnIdleTimeout
	}
	if target.RetryInitialBackoff <= 0 {
		target.RetryInitialBackoff = 20 * time.Millisecond
	}
	if target.RetryMaximumBackoff <= 0 {
		target.RetryMaximumBackoff = 250 * time.Millisecond
	}
	target.RetryMaximumBackoff = max(target.RetryMaximumBackoff, target.RetryInitialBackoff)
	endpoints := make([]string, 0, len(target.Endpoints))
	seen := make(map[string]struct{}, len(target.Endpoints))
	for _, endpoint := range target.Endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		if _, dup := seen[endpoint]; dup {
			continue
		}
		seen[endpoint] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	target.Endpoints = endpoints
	target.Vendors = slices.Clone(target.Vendors)
	target.Codecs = slices.Clone(target.Codecs)
	if target.TLS != nil {
		target.TLS = target.TLS.Clone()
	}
	if target.Dialer != nil {
		dialer := *target.Dialer
		target.Dialer = &dialer
	}
	return target
}

// Source is an immutable pkcs11.ModuleSource for one remote broker route. It
// can be assigned directly to pkcs11.Config.Module.
type Source struct{ Target Target }

// RemoteModule constructs an immutable remote module source.
func RemoteModule(target Target) Source { return Source{Target: target.normalized()} }

// OpenModule establishes a logical proxy client and performs the protocol handshake.
func (source Source) OpenModule(ctx context.Context) (raw.Module, error) {
	return Open(ctx, source.Target)
}

// String returns the immutable proxy target description used in diagnostics.
func (source Source) String() string { return source.Target.modulePath() }

// VendorModules supplies the same candidate vendor modules to the managed
// client so local and remote discovery apply identical adapter behavior.
func (source Source) VendorModules() []pkcs11.VendorModule {
	return slices.Clone(source.Target.Vendors)
}

// RegistryKey returns a stable hash of routing, security-policy identity,
// codec versions, and vendor IDs. Secrets and live callback identities are not
// serialized; SecurityContextID must change whenever opaque security policy
// changes.
func (source Source) RegistryKey() string {
	target := source.Target.normalized()
	registry, err := NewCodecRegistry(combinedCodecs(target.Codecs, target.Vendors)...)
	if err != nil {
		// OpenModule returns the actionable validation error. Keep RegistryKey
		// deterministic even for an invalid source so registry lookup itself does
		// not panic or depend on map iteration.
		registry = emptyCodecRegistry()
	}
	parts := []string{
		target.ConfigID,
		target.Revision,
		strings.Join(target.Endpoints, "\x1f"),
		target.Route,
		target.ServerName,
		target.SecurityContextID,
		fmt.Sprintf("insecure=%t", target.AllowInsecure),
		fmt.Sprintf("connect-timeout=%s", target.ConnectTimeout),
		fmt.Sprintf("request-timeout=%s", target.RequestTimeout),
		fmt.Sprintf("maximum-message-size=%d", target.MaximumMessageSize),
		fmt.Sprintf("attempts=%d", target.MaxAttempts),
		fmt.Sprintf("retry-initial=%s", target.RetryInitialBackoff),
		fmt.Sprintf("retry-max=%s", target.RetryMaximumBackoff),
		fmt.Sprintf("pooled-conns=%d", target.MaxPooledConnections),
		fmt.Sprintf("conn-idle=%s", target.ConnectionIdleTimeout),
	}
	for _, descriptor := range registry.Descriptors() {
		parts = append(parts, fmt.Sprintf("codec=%s@%d", descriptor.ID, descriptor.Version))
	}
	for _, vendor := range target.Vendors {
		if vendor == nil {
			continue
		}
		definition := vendor.Definition()
		parts = append(parts, "vendor="+string(definition.ID))
	}
	hash := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "remote:" + hex.EncodeToString(hash[:])
}

func (target Target) modulePath() string {
	return fmt.Sprintf("p11proxy://%s/%s@%s", strings.Join(target.Endpoints, ","), target.Route, target.Revision)
}

type activeParameterKey struct {
	session   uint64
	operation string
}

type clientState struct {
	closed   atomic.Bool
	epochMu  sync.RWMutex
	epoch    [16]byte
	activeMu sync.Mutex
	active   map[activeParameterKey][]*raw.Mechanism
	// batchUnsupported records a broker that rejected @batch so later calls
	// skip the attempt and run serially.
	batchUnsupported atomic.Bool
}

func (state *clientState) currentEpoch() [16]byte {
	if state == nil {
		return [16]byte{}
	}
	state.epochMu.RLock()
	epoch := state.epoch
	state.epochMu.RUnlock()
	return epoch
}

func (state *clientState) setEpoch(epoch [16]byte) {
	if state == nil || epoch == ([16]byte{}) {
		return
	}
	state.epochMu.Lock()
	state.epoch = epoch
	state.epochMu.Unlock()
}

// Client implements raw.Module over a bounded pool of TCP/TLS connections to
// its pinned endpoint. Once established it is pinned to exactly one proxy
// process: endpoint and serverID are immutable after the describe handshake,
// and a pinned process that is lost can never be substituted by another
// replica. Connections are reused across calls and discarded on transport
// errors; each one serves a single request at a time.
type Client struct {
	target   Target
	registry *CodecRegistry
	id       [16]byte
	endpoint string
	serverID [16]byte
	path     string
	selected raw.InterfaceInfo
	pool     *connPool
	//nolint:containedctx // The client's lifetime context drives pinned-endpoint calls.
	ctx   context.Context
	state *clientState
}

// rankEndpoints orders endpoints by rendezvous (highest-random-weight) score
// for one logical client. Different client IDs produce different orderings, so
// new clients distribute deterministically across the configured proxy
// replicas without any shared state between them.
func rankEndpoints(clientID [16]byte, endpoints []string) []string {
	type rankedEndpoint struct {
		endpoint string
		score    [32]byte
	}
	ranked := make([]rankedEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		digest := sha256.New()
		_, _ = digest.Write(clientID[:])
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(endpoint))
		ranked = append(ranked, rankedEndpoint{endpoint: endpoint, score: [32]byte(digest.Sum(nil))})
	}
	slices.SortFunc(ranked, func(a, b rankedEndpoint) int {
		return bytes.Compare(b.score[:], a.score[:])
	})
	ordered := make([]string, len(ranked))
	for index := range ranked {
		ordered[index] = ranked[index].endpoint
	}
	return ordered
}

// transportError marks a failure that occurred before a complete response was
// received from an endpoint. During establishment it permits trying the next
// ranked endpoint; after establishment it contributes to ErrTargetLost once
// the retry policy is exhausted.
type transportError struct {
	op  string
	err error
}

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

func isEndpointUnavailable(err error) bool {
	_, ok := errors.AsType[*transportError](err)
	return ok
}

// ListRoutes returns the route catalog from the first reachable endpoint. It uses the target's
// transport settings but does not require Target.Route or Target.Revision.
func ListRoutes(ctx context.Context, target Target) ([]RouteInfo, error) {
	target = target.normalized()
	if len(target.Endpoints) == 0 {
		return nil, errors.New("pkcs11 proxy: at least one endpoint is required")
	}
	if target.TLS == nil && !target.AllowInsecure {
		return nil, errors.New("pkcs11 proxy: TLS is required unless AllowInsecure is set")
	}
	client := &Client{
		target: target, registry: emptyCodecRegistry(), ctx: context.Background(),
		state: &clientState{active: make(map[activeParameterKey][]*raw.Mechanism)},
	}
	if _, err := rand.Read(client.id[:]); err != nil {
		return nil, fmt.Errorf("pkcs11 proxy: generate client ID: %w", err)
	}
	var lastErr error
	for _, endpoint := range rankEndpoints(client.id, target.Endpoints) {
		var catalog routeCatalog
		if err := client.invokeEndpoint(ctx, endpoint, methodListRoutes, nil, &catalog); err != nil {
			if !isEndpointUnavailable(err) {
				return nil, err
			}
			lastErr = err
			continue
		}
		return catalog.Routes, nil
	}
	return nil, fmt.Errorf("pkcs11 proxy: no endpoints available: %w", lastErr)
}

// Open connects to the first reachable endpoint in rendezvous order and creates one logical remote
// module. That endpoint and target epoch stay pinned until the module is closed.
func Open(ctx context.Context, target Target) (*Client, error) {
	pooling := target.MaxPooledConnections >= 0
	target = target.normalized()
	if err := target.validate(); err != nil {
		return nil, err
	}
	registry, err := NewCodecRegistry(combinedCodecs(target.Codecs, target.Vendors)...)
	if err != nil {
		return nil, err
	}
	client := &Client{target: target, registry: registry, path: target.modulePath(), ctx: context.Background(), state: &clientState{active: make(map[activeParameterKey][]*raw.Mechanism)}}
	if _, err := rand.Read(client.id[:]); err != nil {
		return nil, fmt.Errorf("pkcs11 proxy: generate client ID: %w", err)
	}
	var lastErr error
	for _, endpoint := range rankEndpoints(client.id, target.Endpoints) {
		var description describeResult
		if err := client.invokeEndpoint(ctx, endpoint, methodDescribe, nil, &description); err != nil {
			// Only transport-level unavailability advances to the next replica;
			// authentication, protocol, and codec failures are returned as-is.
			if !isEndpointUnavailable(err) {
				return nil, err
			}
			lastErr = err
			continue
		}
		if !description.AcceptingNewClients {
			lastErr = fmt.Errorf("pkcs11 proxy: %s is draining and not accepting new clients", endpoint)
			continue
		}
		if missing := codecDescriptorsMissing(registry.Descriptors(), description.Codecs); len(missing) > 0 {
			return nil, fmt.Errorf("pkcs11 proxy: parameter codec mismatch: broker publishes codecs the client does not provide: %v", missing)
		}
		client.endpoint = endpoint
		client.serverID = description.ServerID
		client.selected = description.Interface
		client.state.setEpoch(description.Epoch)
		if description.Path != "" {
			client.path = description.Path
		}
		if pooling {
			client.pool = newConnPool(target, endpoint, target.MaxPooledConnections, target.ConnectionIdleTimeout)
		}
		return client, nil
	}
	return nil, fmt.Errorf("pkcs11 proxy: no endpoints available: %w", lastErr)
}

// Endpoint returns the proxy address this logical client is pinned to. It is
// fixed at Open and never changes: failures surface as ErrTargetLost rather
// than migrating state between replicas.
func (client *Client) Endpoint() string {
	if client == nil {
		return ""
	}
	return client.endpoint
}

// ServerID returns the identity of the proxy process this logical client is
// bound to, learned during the describe handshake.
func (client *Client) ServerID() [16]byte {
	if client == nil {
		return [16]byte{}
	}
	return client.serverID
}

// Path returns the broker-provided diagnostic module path. It never exposes a
// local HSM library path chosen by the server.
func (client *Client) Path() string {
	if client == nil {
		return ""
	}
	return client.path
}

// Interface reports the Cryptoki interface selected by the broker-side local
// module.
func (client *Client) Interface() raw.InterfaceInfo {
	if client == nil {
		return raw.InterfaceInfo{}
	}
	return client.selected
}

// Version returns the selected remote Cryptoki version.
func (client *Client) Version() raw.Version { return client.Interface().Version }

// Supports reports whether the selected remote interface is at least version.
func (client *Client) Supports(version raw.Version) bool { return client.Version().AtLeast(version) }

// WithContext binds ctx to calls made through module during fn without mutating
// the shared logical client or retaining context beyond the callback.
//
//nolint:contextcheck // WithContext intentionally rebinds the lifetime context on a clone.
func (client *Client) WithContext(ctx context.Context, fn func(raw.Module) error) error {
	if fn == nil {
		return errors.New("pkcs11 proxy: nil contextual callback")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	clone := *client
	clone.ctx = ctx
	return fn(&clone)
}

func (client *Client) invoke(method string, arguments []any, results ...any) error {
	ctx := client.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return client.invokeEndpoint(ctx, client.endpoint, method, arguments, results...)
}

// invokeEndpoint issues one request against a specific proxy endpoint. Open
// and ListRoutes pass candidate endpoints during establishment; once a client
// is pinned, invoke routes every call — including retries — to its immutable
// endpoint only.
func (client *Client) invokeEndpoint(ctx context.Context, endpoint string, method string, arguments []any, results ...any) (err error) {
	if client == nil || client.state == nil || client.state.closed.Load() {
		return raw.ErrClosed
	}
	spanCtx, span := telemetryTracer.Start(ctx, "pkcs11.proxy.client "+method,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("pkcs11.endpoint", endpoint),
			attribute.String("pkcs11.method", method),
			attribute.String("pkcs11.route", client.target.Route),
			attribute.String("pkcs11.client_id", hexID(client.id)),
		))
	ctx = spanCtx
	started := time.Now()
	defer func() {
		code := clientOutcome(err)
		endRequestSpan(span, code)
		attrs := metric.WithAttributes(
			attribute.String("pkcs11.role", "client"),
			attribute.String("pkcs11.endpoint", endpoint),
			attribute.String("pkcs11.route", client.target.Route),
			attribute.String("pkcs11.method", method),
			attribute.String("pkcs11.outcome", code),
		)
		requestsTotal.Add(ctx, 1, attrs)
		requestDuration.Record(ctx, time.Since(started).Seconds(), attrs)
		if errors.Is(err, ErrTargetLost) {
			targetLostTotal.Add(ctx, 1, metric.WithAttributes(
				attribute.String("pkcs11.role", "client"),
				attribute.String("pkcs11.route", client.target.Route),
			))
		}
	}()
	if ctx == nil {
		ctx = context.Background() //nolint:contextcheck // Fallback when no lifetime context was bound at Open.
	}
	if _, ok := ctx.Deadline(); !ok && client.target.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, client.target.RequestTimeout)
		defer cancel()
	}
	methodType, ok := rawModuleType.MethodByName(method)
	if !ok && method != methodDescribe && method != methodDestroy && method != methodListRoutes && method != methodBatch {
		return fmt.Errorf("pkcs11 proxy: unknown raw module method %q", method)
	}
	if ok && len(arguments) != methodType.Type.NumIn() {
		return fmt.Errorf("pkcs11 proxy: %s received %d arguments; want %d", method, len(arguments), methodType.Type.NumIn())
	}
	// @batch is opaque to the generated method table: its single argument is
	// the encoded call list, so it is exempt from the zero-argument rule that
	// guards the other special methods.
	if !ok && len(arguments) != 0 && method != methodBatch {
		return fmt.Errorf("pkcs11 proxy: %s received %d arguments; want 0", method, len(arguments))
	}
	encodedArguments := make([]wireValue, len(arguments))
	for i, argument := range arguments {
		declared := reflect.TypeOf(argument)
		if ok {
			declared = methodType.Type.In(i)
		}
		encoded, err := encodeTypedWireValue(argument, declared, client.registry)
		if err != nil {
			return fmt.Errorf("pkcs11 proxy: encode %s argument %d: %w", method, i, err)
		}
		encodedArguments[i] = encoded
	}
	var requestID [16]byte
	if _, err := rand.Read(requestID[:]); err != nil {
		return err
	}
	auth := []byte(nil)
	defer func() {
		wipe(auth)
		for index := range encodedArguments {
			wipeWireValue(&encodedArguments[index])
		}
	}()
	if client.target.Auth != nil {
		var err error
		auth, err = client.target.Auth(ctx)
		if err != nil {
			return fmt.Errorf("pkcs11 proxy: obtain request credential: %w", err)
		}
	} else {
		// Brokers that authenticate workloads by request credential (e.g.
		// proxycmd's workloadAuthenticator) require a non-empty identity even
		// when the caller has no credential provider. The credential derives a
		// workload principal; it is an identifier, not authorization, so the
		// target's stable public identities are a safe default.
		switch {
		case client.target.SecurityContextID != "":
			auth = []byte(client.target.SecurityContextID)
		case client.target.ConfigID != "":
			auth = []byte(client.target.ConfigID)
		default:
			auth = slices.Clone(client.id[:])
		}
	}
	req := request{Version: protocolVersion, Target: client.target.Route, Revision: client.target.Revision, ClientID: client.id, RequestID: requestID, ServerID: client.serverID, Epoch: client.state.currentEpoch(), Method: method, Arguments: encodedArguments, Auth: slices.Clone(auth)}
	if deadline, ok := ctx.Deadline(); ok {
		req.DeadlineUnixNano = deadline.UnixNano()
	}
	var resp response
	attempts := client.target.MaxAttempts
	uncertain := false
	// Once pinned, calls draw from the client's connection pool: a warm pooled
	// connection skips TCP+TLS setup on every request. Establishment calls —
	// describe/listroutes on candidate endpoints — always dial fresh.
	pooled := client.pool != nil && endpoint == client.endpoint
	for attempt := 1; attempt <= attempts; attempt++ {
		resp = response{}
		var connection net.Conn
		var err error
		if pooled {
			connection, err = client.pool.acquire(ctx)
		} else {
			connection, err = dialContext(ctx, client.target, endpoint)
		}
		if err != nil {
			client.observeTransportError(ctx, endpoint)
			if uncertain {
				// An earlier attempt may have reached the server, so a failed
				// reconnect cannot prove the request was not executed. Keep the
				// uncertainty alongside ErrTargetLost or the caller's
				// cancellation instead of letting the terminal path discard it.
				if attempt < attempts {
					if waitErr := client.waitRetry(ctx, attempt); waitErr != nil {
						return errors.Join(ErrOutcomeUnknown, waitErr)
					}
					continue
				}
				return errors.Join(ErrTargetLost, ErrOutcomeUnknown,
					fmt.Errorf("pkcs11 proxy: dial %s: %w", endpoint, &transportError{op: "dial", err: err}))
			}
			if attempt < attempts {
				if waitErr := client.waitRetry(ctx, attempt); waitErr != nil {
					return waitErr
				}
				continue
			}
			// Retries are exhausted and the pinned replica is unreachable. The
			// logical client may still live there, but this process can no
			// longer serve it and no other replica owns its state.
			return errors.Join(ErrTargetLost,
				fmt.Errorf("pkcs11 proxy: dial %s: %w", endpoint, &transportError{op: "dial", err: err}))
		}
		applyConnectionDeadline(ctx, connection, client.target.RequestTimeout)
		stopContextClose := closeConnectionOnContext(ctx, connection)
		writeErr := writeMessage(connection, req, client.target.MaximumMessageSize)
		if writeErr == nil {
			writeErr = readMessage(connection, &resp, client.target.MaximumMessageSize)
		}
		stopContextClose()
		if writeErr == nil {
			if pooled {
				client.pool.release(connection)
			} else {
				_ = connection.Close()
			}
			break
		}
		if pooled {
			client.pool.discard(connection)
		} else {
			_ = connection.Close()
		}
		client.observeTransportError(ctx, endpoint)
		writeErr = &transportError{op: "roundtrip", err: writeErr}
		// Once writing begins, a non-idempotent operation may have completed. Retry
		// only with the same request ID; the broker ledger returns the original
		// response within the same target epoch.
		if !methodIdempotent(method) {
			uncertain = true
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			if uncertain {
				return fmt.Errorf("%w: %s: %w", ErrOutcomeUnknown, method, ctxErr)
			}
			return ctxErr
		}
		if attempt < attempts {
			if waitErr := client.waitRetry(ctx, attempt); waitErr != nil {
				if uncertain {
					return fmt.Errorf("%w: %s: %w", ErrOutcomeUnknown, method, waitErr)
				}
				return waitErr
			}
			continue
		}
		if uncertain {
			return errors.Join(ErrTargetLost,
				fmt.Errorf("%w: %s: %w", ErrOutcomeUnknown, method, writeErr))
		}
		return errors.Join(ErrTargetLost,
			fmt.Errorf("pkcs11 proxy: %s transport: %w", method, writeErr))
	}
	// Keep outcome-unknown when a non-idempotent request may already have run.
	uncertainResult := func(err error) error {
		if err == nil || !uncertain || methodIdempotent(method) || errors.Is(err, ErrOutcomeUnknown) {
			return err
		}
		return errors.Join(ErrOutcomeUnknown, err)
	}
	if resp.Version != protocolVersion {
		return uncertainResult(fmt.Errorf("pkcs11 proxy: protocol version %d, want %d", resp.Version, protocolVersion))
	}
	remoteErr := decodeError(resp.Error)
	remote, isRemote := errors.AsType[*RemoteError](remoteErr)
	if uncertain && !methodIdempotent(method) && remoteErr != nil && !errors.Is(remoteErr, ErrOutcomeUnknown) {
		// These errors reject this attempt without resolving an earlier uncertain one.
		unresolved := errors.Is(remoteErr, context.DeadlineExceeded) || errors.Is(remoteErr, context.Canceled)
		if isRemote {
			switch remote.Code {
			// request_id_reuse means the earlier attempt already claimed this
			// request ID server-side, so its execution may still be in flight.
			case "wrong_server", "target_epoch_mismatch", "revision_mismatch", "target_not_found", "server_draining", "dedup_capacity", "request_id_reuse", "internal":
				unresolved = true
			}
		}
		if unresolved {
			return errors.Join(ErrOutcomeUnknown,
				fmt.Errorf("%s: %w", method, remoteErr))
		}
	}
	if !isRemote || (remote.Code != "target_epoch_mismatch" && remote.Code != "revision_mismatch" && remote.Code != "target_not_found" && remote.Code != "wrong_server") {
		client.state.setEpoch(resp.Epoch)
	}
	if method == methodBatch {
		// Batch results travel in resp.Batch, not Results; the caller decodes
		// each subcall's results, argument updates, and errors itself.
		if remoteErr == nil && len(results) == 1 {
			if destination, isBatch := results[0].(*[]batchResult); isBatch {
				*destination = resp.Batch
			}
		}
		return remoteErr
	}
	if len(resp.Results) != len(results) {
		if remoteErr != nil && len(resp.Results) == 0 {
			return remoteErr
		}
		return uncertainResult(fmt.Errorf("pkcs11 proxy: %s returned %d results; want %d", method, len(resp.Results), len(results)))
	}
	for i := range results {
		if err := validateWireValue(resp.Results[i]); err != nil {
			return uncertainResult(fmt.Errorf("pkcs11 proxy: validate %s result %d: %w", method, i, err))
		}
		if err := assignDecoded(results[i], resp.Results[i], client.registry); err != nil {
			return uncertainResult(fmt.Errorf("pkcs11 proxy: decode %s result %d: %w", method, i, err))
		}
	}
	for _, update := range resp.ArgumentUpdates {
		if update.Index < 0 || update.Index >= len(arguments) {
			return uncertainResult(fmt.Errorf("pkcs11 proxy: %s returned invalid argument update index %d", method, update.Index))
		}
		declared := reflect.TypeOf(arguments[update.Index])
		if ok {
			declared = methodType.Type.In(update.Index)
		}
		if err := validateWireValue(update.Value); err != nil {
			return uncertainResult(fmt.Errorf("pkcs11 proxy: validate %s argument update %d: %w", method, update.Index, err))
		}
		if !argumentMayMutate(method, update.Index, declared) {
			return uncertainResult(fmt.Errorf("pkcs11 proxy: %s returned an update for immutable argument %d", method, update.Index))
		}
		if err := applyArgumentUpdate(method, update.Index, arguments[update.Index], declared, update.Value, client.registry); err != nil {
			return uncertainResult(fmt.Errorf("pkcs11 proxy: decode %s argument update %d: %w", method, update.Index, err))
		}
	}
	client.applyUpdates(resp.Updates)
	client.trackOperation(method, arguments, remoteErr)
	return remoteErr
}

// observeTransportError counts one failed dial or round-trip against the
// §30 transport error metric from the client side.
func (client *Client) observeTransportError(ctx context.Context, endpoint string) {
	transportErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("pkcs11.role", "client"),
		attribute.String("pkcs11.endpoint", endpoint),
		attribute.String("pkcs11.route", client.target.Route),
	))
}

// clientOutcome classifies an invokeEndpoint result for metric labels and
// span status. It mirrors the wire-code taxonomy without ever recording
// request payloads.
func clientOutcome(err error) string {
	if err == nil {
		return "ok"
	}
	if remote, ok := errors.AsType[*RemoteError](err); ok && remote.Code != "" {
		return remote.Code
	}
	switch {
	case errors.Is(err, ErrTargetLost):
		return "target_lost"
	case errors.Is(err, ErrOutcomeUnknown):
		return "outcome_unknown"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, raw.ErrClosed):
		return "closed"
	}
	if _, ok := errors.AsType[raw.Error](err); ok {
		return "ckr"
	}
	return "error"
}

func (client *Client) waitRetry(ctx context.Context, attempt int) error {
	delay := client.retryDelay(attempt)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// retryDelay returns full jitter in [0, exponential-cap]. The attempt value is
// the just-failed one-based attempt, so attempt 1 uses RetryInitialBackoff.
func (client *Client) retryDelay(attempt int) time.Duration {
	if client == nil || attempt <= 0 {
		return 0
	}
	maximum := client.target.RetryInitialBackoff
	for index := 1; index < attempt && maximum < client.target.RetryMaximumBackoff; index++ {
		if maximum > client.target.RetryMaximumBackoff/2 {
			maximum = client.target.RetryMaximumBackoff
			break
		}
		maximum *= 2
	}
	if maximum > client.target.RetryMaximumBackoff {
		maximum = client.target.RetryMaximumBackoff
	}
	if maximum <= 0 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum)+1))
	if err != nil {
		return maximum / 2
	}
	return time.Duration(value.Int64())
}

func (client *Client) trackOperation(method string, arguments []any, callErr error) {
	if method == "Finalize" || method == "CloseAllSessions" {
		client.state.activeMu.Lock()
		client.state.active = make(map[activeParameterKey][]*raw.Mechanism)
		client.state.activeMu.Unlock()
		return
	}
	if method == "CloseSession" && len(arguments) != 0 {
		if session, ok := arguments[0].(raw.SessionHandle); ok {
			client.state.activeMu.Lock()
			maps.DeleteFunc(client.state.active, func(key activeParameterKey, _ []*raw.Mechanism) bool {
				return key.session == uint64(session)
			})
			client.state.activeMu.Unlock()
		}
		return
	}
	descriptor := operationForMethod(method)
	if descriptor.Name == "" || len(arguments) == 0 {
		return
	}
	session, ok := arguments[0].(raw.SessionHandle)
	if !ok {
		return
	}
	key := activeParameterKey{session: uint64(session), operation: descriptor.Name}
	client.state.activeMu.Lock()
	defer client.state.activeMu.Unlock()
	switch descriptor.Transition {
	case operationStart:
		if callErr != nil && !raw.IsError(callErr, raw.CKR_PENDING) {
			return
		}
		for _, argument := range arguments {
			if mechanisms, ok := argument.([]*raw.Mechanism); ok {
				client.state.active[key] = mechanisms
				return
			}
		}
	case operationFinish:
		if callErr == nil || (!raw.IsError(callErr, raw.CKR_PENDING) && !raw.IsError(callErr, raw.CKR_BUFFER_TOO_SMALL)) {
			delete(client.state.active, key)
		}
	}
}

func (client *Client) applyUpdates(updates []parameterUpdate) {
	if len(updates) == 0 {
		return
	}
	client.state.activeMu.Lock()
	defer client.state.activeMu.Unlock()
	for _, update := range updates {
		mechanisms := client.state.active[activeParameterKey{session: update.Session, operation: update.Operation}]
		if len(mechanisms) == 0 {
			continue
		}
		decoded, err := decodeParameter(update.Parameter, client.registry)
		if err != nil {
			continue
		}
		for _, mechanism := range mechanisms {
			if mechanism != nil {
				copyParameterUpdate(mechanism.Parameter, decoded)
			}
		}
	}
}

// Close destroys this logical remote module and releases all of its virtual
// sessions, object mappings, login grants, and pinned physical leases. The
// broker drains in-flight calls for this client before closing those resources.
// Close is idempotent.
func (client *Client) Close() error {
	if client == nil || client.state == nil || !client.state.closed.CompareAndSwap(false, true) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), client.target.RequestTimeout)
	defer cancel()
	// invokeEndpoint observes closed, so issue the final request through a shallow
	// state that remains open only for this cleanup call.
	clone := *client
	clone.state = &clientState{epoch: client.state.currentEpoch(), active: make(map[activeParameterKey][]*raw.Mechanism)}
	err := clone.invokeEndpoint(ctx, client.endpoint, methodDestroy, nil)
	client.pool.close()
	client.state.activeMu.Lock()
	client.state.active = make(map[activeParameterKey][]*raw.Mechanism)
	client.state.activeMu.Unlock()
	return err
}

// Destroy implements raw.Module. It performs the same cleanup as Close and
// intentionally discards a transport error because the raw interface has no
// error return. Direct proxy users should prefer Close when cleanup diagnostics
// matter.
func (client *Client) Destroy() { _ = client.Close() }

// BatchCall describes one raw-module invocation inside an InvokeBatch request.
// Arguments and Results behave exactly as they would on a standalone call;
// Err carries that call's outcome after InvokeBatch returns.
type BatchCall struct {
	Method    string
	Arguments []any
	Results   []any
	Err       error
}

// InvokeBatch executes several raw-module calls in one broker request, saving
// a transport round-trip per call beyond the first. Each subcall is dedup'd
// and authorized by the broker exactly like a standalone request. A broker
// that predates @batch rejects the method once; the client then runs the
// calls serially and keeps doing so on later batches. InvokeBatch itself
// reports only envelope-level failures — per-call outcomes live in Err.
func (client *Client) InvokeBatch(calls []BatchCall) error {
	if client == nil {
		return raw.ErrClosed
	}
	if len(calls) == 0 {
		return nil
	}
	if len(calls) > maxBatchCalls {
		return fmt.Errorf("pkcs11 proxy: batch must carry at most %d calls, got %d", maxBatchCalls, len(calls))
	}
	if client.state.batchUnsupported.Load() {
		return client.invokeBatchSerial(calls)
	}
	encoded := make([]batchCall, len(calls))
	for index, call := range calls {
		method, ok := rawModuleType.MethodByName(call.Method)
		if !ok {
			return fmt.Errorf("pkcs11 proxy: cannot batch unknown method %q", call.Method)
		}
		if len(call.Arguments) != method.Type.NumIn() {
			return fmt.Errorf("pkcs11 proxy: %s received %d arguments; want %d", call.Method, len(call.Arguments), method.Type.NumIn())
		}
		arguments := make([]wireValue, len(call.Arguments))
		for i, argument := range call.Arguments {
			value, err := encodeTypedWireValue(argument, method.Type.In(i), client.registry)
			if err != nil {
				return fmt.Errorf("pkcs11 proxy: encode %s argument %d: %w", call.Method, i, err)
			}
			arguments[i] = value
		}
		encoded[index] = batchCall{Method: call.Method, Arguments: arguments}
	}
	defer func() {
		for index := range encoded {
			for i := range encoded[index].Arguments {
				wipeWireValue(&encoded[index].Arguments[i])
			}
		}
	}()
	payload, err := json.Marshal(encoded)
	if err != nil {
		return fmt.Errorf("pkcs11 proxy: encode batch payload: %w", err)
	}
	defer wipe(payload)
	var batch []batchResult
	err = client.invoke(methodBatch, []any{payload}, &batch)
	if err != nil {
		if remote, isRemote := errors.AsType[*RemoteError](err); isRemote && remote.Code == "unknown_method" {
			client.state.batchUnsupported.Store(true)
			return client.invokeBatchSerial(calls)
		}
		return err
	}
	if len(batch) != len(calls) {
		return fmt.Errorf("pkcs11 proxy: batch returned %d results; want %d", len(batch), len(calls))
	}
	for index := range calls {
		calls[index].Err = client.decodeBatchCall(&calls[index], batch[index])
	}
	return nil
}

// invokeBatchSerial runs the calls as standalone requests. It is the fallback
// for brokers that predate @batch.
func (client *Client) invokeBatchSerial(calls []BatchCall) error {
	for index := range calls {
		calls[index].Err = client.invoke(calls[index].Method, calls[index].Arguments, calls[index].Results...)
	}
	return nil
}

// decodeBatchCall unpacks one batchResult into the caller's result
// destinations and in-place argument updates, mirroring invokeEndpoint's
// per-call decode for a standalone request.
func (client *Client) decodeBatchCall(call *BatchCall, result batchResult) error {
	method, _ := rawModuleType.MethodByName(call.Method)
	remoteErr := decodeError(result.Error)
	if len(result.Results) != len(call.Results) {
		if remoteErr != nil && len(result.Results) == 0 {
			return remoteErr
		}
		return fmt.Errorf("pkcs11 proxy: %s returned %d results; want %d", call.Method, len(result.Results), len(call.Results))
	}
	for i := range call.Results {
		if err := validateWireValue(result.Results[i]); err != nil {
			return fmt.Errorf("pkcs11 proxy: validate %s result %d: %w", call.Method, i, err)
		}
		if err := assignDecoded(call.Results[i], result.Results[i], client.registry); err != nil {
			return fmt.Errorf("pkcs11 proxy: decode %s result %d: %w", call.Method, i, err)
		}
	}
	for _, update := range result.ArgumentUpdates {
		if update.Index < 0 || update.Index >= len(call.Arguments) {
			return fmt.Errorf("pkcs11 proxy: %s returned invalid argument update index %d", call.Method, update.Index)
		}
		declared := method.Type.In(update.Index)
		if err := validateWireValue(update.Value); err != nil {
			return fmt.Errorf("pkcs11 proxy: validate %s argument update %d: %w", call.Method, update.Index, err)
		}
		if !argumentMayMutate(call.Method, update.Index, declared) {
			return fmt.Errorf("pkcs11 proxy: %s returned an update for immutable argument %d", call.Method, update.Index)
		}
		if err := applyArgumentUpdate(call.Method, update.Index, call.Arguments[update.Index], declared, update.Value, client.registry); err != nil {
			return fmt.Errorf("pkcs11 proxy: decode %s argument update %d: %w", call.Method, update.Index, err)
		}
	}
	client.applyUpdates(result.Updates)
	client.trackOperation(call.Method, call.Arguments, remoteErr)
	return remoteErr
}

// GetMechanismInfos resolves many mechanism descriptors in one batched broker
// request. Per-mechanism failures ride in errs; a non-nil returned error means
// the batch itself failed and every entry is unresolved, letting callers fall
// back to individual GetMechanismInfo calls.
func (client *Client) GetMechanismInfos(slot raw.SlotID, mechanisms []raw.MechanismType) ([]raw.MechanismInfo, []error, error) {
	infos := make([]raw.MechanismInfo, len(mechanisms))
	errs := make([]error, len(mechanisms))
	for start := 0; start < len(mechanisms); start += maxBatchCalls {
		chunk := mechanisms[start:min(start+maxBatchCalls, len(mechanisms))]
		calls := make([]BatchCall, len(chunk))
		for i, mechanism := range chunk {
			calls[i] = BatchCall{Method: "GetMechanismInfo", Arguments: []any{slot, mechanism}, Results: []any{&infos[start+i]}}
		}
		if err := client.InvokeBatch(calls); err != nil {
			return nil, nil, err
		}
		for i := range calls {
			errs[start+i] = calls[i].Err
		}
	}
	return infos, errs, nil
}

var (
	_ raw.Module           = (*Client)(nil)
	_ raw.ContextualModule = (*Client)(nil)
)
