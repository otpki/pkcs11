package proxy

import (
	"cmp"
	"context"
	"encoding/hex"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Telemetry is emitted through the global OpenTelemetry providers: with no SDK
// installed every call is a no-op, so the library carries no exporter
// dependency. The pkcs11-proxy command wires OTLP providers when configured;
// embedders may install any compatible SDK.
var (
	telemetryMeter  = otel.Meter("github.com/otpki/pkcs11/proxy")
	telemetryTracer = otel.Tracer("github.com/otpki/pkcs11/proxy")
	telemetryLogger = otel.Logger("github.com/otpki/pkcs11/proxy")

	requestsTotal, _ = telemetryMeter.Int64Counter("pkcs11_proxy_requests_total",
		metric.WithDescription("Proxy requests completed, by route, method, and outcome"))
	requestDuration, _ = telemetryMeter.Float64Histogram("pkcs11_proxy_request_duration_seconds",
		metric.WithDescription("Proxy request handling duration"), metric.WithUnit("s"))
	transportErrors, _ = telemetryMeter.Int64Counter("pkcs11_proxy_transport_errors_total",
		metric.WithDescription("Connections or framed messages lost before a complete exchange"))
	targetLostTotal, _ = telemetryMeter.Int64Counter("pkcs11_proxy_target_lost_total",
		metric.WithDescription("Logical clients that lost their pinned proxy replica"))
)

// AuditEvent is a secret-free record of a security-relevant transition on the
// broker. PINs, keys, plaintext, and attribute values are never included.
type AuditEvent struct {
	// Type is the stable event kind: client_established, client_destroyed,
	// client_expired, login_grant, logout, activation, activation_failure,
	// maintenance, auth_failure, fence_rejection, drain_rejection,
	// stale_generation, drain, shutdown.
	Type string
	// Target is the route name, empty for server-scoped events.
	Target string
	// Method is the request method when the event came from one.
	Method string
	// ClientID is the logical client identity as lowercase hex.
	ClientID string
	// Principal is the authenticated workload identity, never a credential.
	Principal string
	// Code is the protocol error code for rejections, or empty on success.
	Code string
}

// AuditSink receives broker security events. Implementations must be fast and
// non-blocking; the signed audit writer in pkcs11-proxy satisfies that by
// queueing records for a background flusher.
type AuditSink interface {
	AuditProxy(context.Context, AuditEvent)
}

// AuditSinkFunc adapts a function to AuditSink.
type AuditSinkFunc func(context.Context, AuditEvent)

// AuditProxy implements AuditSink.
func (f AuditSinkFunc) AuditProxy(ctx context.Context, event AuditEvent) { f(ctx, event) }

// ServerCounters is the process-local in-memory mirror of the exported
// metrics, exposed for the dev dashboard without requiring an SDK.
type ServerCounters struct {
	RequestsTotal    int64 `json:"requests_total"`
	TransportErrors  int64 `json:"transport_errors_total"`
	AuthFailures     int64 `json:"auth_failures_total"`
	FenceRejections  int64 `json:"fence_rejections_total"`
	DrainRejections  int64 `json:"drain_rejections_total"`
	StaleGenerations int64 `json:"stale_generations_total"`
}

// MethodOutcome is one request-counter cell broken down by route, method, and
// outcome — the same dimensions the exported pkcs11_proxy_requests_total
// metric carries, kept in-process for the dev dashboard.
type MethodOutcome struct {
	Target  string `json:"target"`
	Method  string `json:"method"`
	Outcome string `json:"outcome"`
	Count   int64  `json:"count"`
}

// RequestEvent is one recent completed request for the dashboard feed. It
// carries only secret-free metadata — never credentials or payloads.
type RequestEvent struct {
	Time       time.Time `json:"time"`
	Target     string    `json:"target"`
	Method     string    `json:"method"`
	Outcome    string    `json:"outcome"`
	ClientID   string    `json:"client_id"`
	Principal  string    `json:"principal"`
	RequestID  string    `json:"request_id"`
	DurationMS int64     `json:"duration_ms"`
}

// recentRequestCap bounds the dashboard's request feed; it is a rolling
// window, not a log.
const recentRequestCap = 256

// serverObs is the per-server telemetry state: the audit sink, the atomic
// counters behind ServerCounters, the method×outcome breakdown, and the
// recent-request ring the dev dashboard renders.
type serverObs struct {
	audit AuditSink

	requestsTotal    atomic.Int64
	transportErrors  atomic.Int64
	authFailures     atomic.Int64
	fenceRejections  atomic.Int64
	drainRejections  atomic.Int64
	staleGenerations atomic.Int64

	// Rejected requests also reach telemetry, so route and method names may
	// come from an untrusted caller. Bound new label combinations explicitly.
	methodOutcomes     sync.Map // methodOutcomeKey -> *atomic.Int64
	methodOutcomesMu   sync.Mutex
	methodOutcomeCount int

	recentMu       sync.Mutex
	recentRequests []RequestEvent
}

type methodOutcomeKey struct {
	target, method, outcome string
}

func hexID(id [16]byte) string {
	return hex.EncodeToString(id[:])
}

// spanAttrs links a trace or log entry to its broker, route, client, and request.
func spanAttrs(serverID [16]byte, identity RequestIdentity, req request) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("pkcs11.server_id", hexID(serverID)),
		attribute.String("pkcs11.target_epoch", hexID(req.Epoch)),
		attribute.String("pkcs11.client_id", hexID(req.ClientID)),
		attribute.String("pkcs11.request_id", hexID(req.RequestID)),
		attribute.String("pkcs11.target", req.Target),
		attribute.String("pkcs11.method", req.Method),
		attribute.String("pkcs11.principal", identity.Principal),
	}
}

// emitRequestLog records the route, client, and request IDs for troubleshooting.
// Failed requests use WARN. Successful requests use DEBUG to keep normal logs quiet.
func emitRequestLog(ctx context.Context, serverID [16]byte, identity RequestIdentity, req request, code string) {
	severity := otellog.SeverityDebug
	if code != "" && code != "ok" {
		severity = otellog.SeverityWarn
	}
	var record otellog.Record
	record.SetTimestamp(time.Now())
	record.SetSeverity(severity)
	record.SetBody(attribute.StringValue("pkcs11 proxy request"))
	record.AddAttributes(
		attribute.String("pkcs11.server_id", hexID(serverID)),
		attribute.String("pkcs11.target_epoch", hexID(req.Epoch)),
		attribute.String("pkcs11.client_id", hexID(req.ClientID)),
		attribute.String("pkcs11.request_id", hexID(req.RequestID)),
		attribute.String("pkcs11.target", req.Target),
		attribute.String("pkcs11.method", req.Method),
		attribute.String("pkcs11.principal", identity.Principal),
		attribute.String("pkcs11.outcome", code),
	)
	telemetryLogger.Emit(ctx, record)
}

func emitEventLog(ctx context.Context, event AuditEvent) {
	var record otellog.Record
	record.SetTimestamp(time.Now())
	record.SetSeverity(otellog.SeverityInfo)
	record.SetBody(attribute.StringValue("pkcs11 proxy audit: " + event.Type))
	record.AddAttributes(
		attribute.String("pkcs11.audit.type", event.Type),
		attribute.String("pkcs11.target", event.Target),
		attribute.String("pkcs11.method", event.Method),
		attribute.String("pkcs11.client_id", event.ClientID),
		attribute.String("pkcs11.principal", event.Principal),
		attribute.String("pkcs11.outcome", event.Code),
	)
	telemetryLogger.Emit(ctx, record)
}

// emitWarnLog writes one operational warning record for failures that are not
// security events — route reconciliation falling back to the last published
// catalog, and similar degradations. Routine failures stay off the audit
// stream; the record carries the same trace correlation as request logs.
func emitWarnLog(ctx context.Context, message string, attrs ...attribute.KeyValue) {
	var record otellog.Record
	record.SetTimestamp(time.Now())
	record.SetSeverity(otellog.SeverityWarn)
	record.SetBody(attribute.StringValue(message))
	record.AddAttributes(attrs...)
	telemetryLogger.Emit(ctx, record)
}

// audit forwards one event to the configured sink (if any) and mirrors it into
// the OTel log stream so collectors see the same security trail.
func (obs *serverObs) emitAudit(ctx context.Context, event AuditEvent) {
	if obs == nil {
		return
	}
	emitEventLog(ctx, event)
	if obs.audit != nil {
		obs.audit.AuditProxy(ctx, event)
	}
}

const maxMethodOutcomes = 4096

// telemetryLabel avoids retaining a large caller-supplied string in a metric
// label or dashboard entry. Normal route and method names are left unchanged.
func telemetryLabel(value string) string {
	if len(value) > 128 {
		return "<too-long>"
	}
	return value
}

// noteOutcome returns the labels used by both the local counters and OTel.
// Once the table fills, new combinations share one overflow bucket.
func (obs *serverObs) noteOutcome(target, method, code string) methodOutcomeKey {
	key := methodOutcomeKey{telemetryLabel(target), telemetryLabel(method), telemetryLabel(code)}
	if counter, ok := obs.methodOutcomes.Load(key); ok {
		if value, ok := counter.(*atomic.Int64); ok {
			value.Add(1)
		}
		return key
	}
	obs.methodOutcomesMu.Lock()
	defer obs.methodOutcomesMu.Unlock()
	if counter, ok := obs.methodOutcomes.Load(key); ok {
		if value, ok := counter.(*atomic.Int64); ok {
			value.Add(1)
		}
		return key
	}
	if obs.methodOutcomeCount >= maxMethodOutcomes {
		key = methodOutcomeKey{"<overflow>", "<overflow>", "<overflow>"}
	}
	counter, loaded := obs.methodOutcomes.LoadOrStore(key, &atomic.Int64{})
	if !loaded {
		obs.methodOutcomeCount++
	}
	if value, ok := counter.(*atomic.Int64); ok {
		value.Add(1)
	}
	return key
}

// noteRequest appends one entry to the bounded recent-request ring.
func (obs *serverObs) noteRequest(event RequestEvent) {
	obs.recentMu.Lock()
	if len(obs.recentRequests) >= recentRequestCap {
		copy(obs.recentRequests, obs.recentRequests[1:])
		obs.recentRequests = obs.recentRequests[:recentRequestCap-1]
	}
	obs.recentRequests = append(obs.recentRequests, event)
	obs.recentMu.Unlock()
}

// methodOutcomeSnapshot copies the breakdown into a stable-sorted slice.
func (obs *serverObs) methodOutcomeSnapshot() []MethodOutcome {
	var out []MethodOutcome
	obs.methodOutcomes.Range(func(key, value any) bool {
		k, ok := key.(methodOutcomeKey)
		count, okCount := value.(*atomic.Int64)
		if !ok || !okCount {
			return true
		}
		out = append(out, MethodOutcome{
			Target: k.target, Method: k.method, Outcome: k.outcome,
			Count: count.Load(),
		})
		return true
	})
	slices.SortFunc(out, func(a, b MethodOutcome) int {
		return cmp.Or(
			cmp.Compare(a.Target, b.Target),
			cmp.Compare(a.Method, b.Method),
			cmp.Compare(a.Outcome, b.Outcome),
		)
	})
	return out
}

// recentRequestSnapshot returns the newest n entries, most recent first.
func (obs *serverObs) recentRequestSnapshot(n int) []RequestEvent {
	obs.recentMu.Lock()
	defer obs.recentMu.Unlock()
	count := len(obs.recentRequests)
	if n <= 0 || n > count {
		n = count
	}
	out := make([]RequestEvent, 0, n)
	for _, request := range slices.Backward(obs.recentRequests[count-n : count]) {
		out = append(out, request)
	}
	return out
}

// observeRequest records one completed request's metric and in-process count.
func (obs *serverObs) observeRequest(ctx context.Context, serverID [16]byte, identity RequestIdentity, req request, code string, elapsed time.Duration) {
	obs.requestsTotal.Add(1)
	labels := obs.noteOutcome(req.Target, req.Method, code)
	obs.noteRequest(RequestEvent{
		Time:       time.Now(),
		Target:     telemetryLabel(req.Target),
		Method:     telemetryLabel(req.Method),
		Outcome:    telemetryLabel(code),
		ClientID:   hexID(req.ClientID),
		Principal:  telemetryLabel(identity.Principal),
		RequestID:  hexID(req.RequestID),
		DurationMS: elapsed.Milliseconds(),
	})
	attrs := metric.WithAttributes(
		attribute.String("pkcs11.server_id", hexID(serverID)),
		attribute.String("pkcs11.target", labels.target),
		attribute.String("pkcs11.method", labels.method),
		attribute.String("pkcs11.outcome", labels.outcome),
	)
	requestsTotal.Add(ctx, 1, attrs)
	requestDuration.Record(ctx, elapsed.Seconds(), attrs)
	emitRequestLog(ctx, serverID, identity, req, code)
}

// observeRejection bumps the matching counter and emits an audit event for
// request-level rejections (before any logical-client state is involved).
func (obs *serverObs) observeRejection(ctx context.Context, _ [16]byte, identity RequestIdentity, req request, code string) {
	var eventType string
	switch code {
	case "unauthorized":
		obs.authFailures.Add(1)
		eventType = "auth_failure"
	case "wrong_server":
		obs.fenceRejections.Add(1)
		eventType = "fence_rejection"
	case "server_draining":
		obs.drainRejections.Add(1)
		eventType = "drain_rejection"
	case "target_epoch_mismatch", "revision_mismatch", "target_not_found", "client_identity_mismatch":
		obs.staleGenerations.Add(1)
		eventType = "stale_generation"
	default:
		return
	}
	obs.emitAudit(ctx, AuditEvent{
		Type: eventType, Target: req.Target, Method: req.Method,
		ClientID: hexID(req.ClientID), Principal: identity.Principal, Code: code,
	})
}

// outcomeCode extracts a stable protocol code for metrics from a wire error.
func outcomeCode(resp response) string {
	if resp.Error == nil {
		return "ok"
	}
	if resp.Error.Code != "" {
		return resp.Error.Code
	}
	if resp.Error.HasRV {
		return "ckr"
	}
	return "error"
}

// startRequestSpan opens a server-side span for one request dispatch.
func startRequestSpan(ctx context.Context, serverID [16]byte, identity RequestIdentity, req request) (context.Context, trace.Span) {
	//nolint:spancheck // endRequestSpan ends the span after dispatch completes.
	return telemetryTracer.Start(ctx, "pkcs11.proxy "+req.Method,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(spanAttrs(serverID, identity, req)...))
}

func endRequestSpan(span trace.Span, code string) {
	if code != "ok" {
		span.SetStatus(codes.Error, code)
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}

// registerGauges publishes the §30 per-process gauges from TargetStats. The
// callback reads live targets at each collection, so the values always reflect
// this process alone — fleet aggregates belong to the collector.
func (server *Server) registerGauges() {
	serverID := hexID(server.instanceID)
	register := func(name, description string, value func(TargetStats) int64) {
		gauge, err := telemetryMeter.Int64ObservableGauge(name, metric.WithDescription(description))
		if err != nil {
			return
		}
		_, _ = telemetryMeter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
			server.targetsMu.RLock()
			targets := make([]*brokerTarget, 0, len(server.targets))
			for _, target := range server.targets {
				targets = append(targets, target)
			}
			server.targetsMu.RUnlock()
			for _, target := range targets {
				observer.ObserveInt64(gauge, value(target.stats()), metric.WithAttributes(
					attribute.String("pkcs11.server_id", serverID),
					attribute.String("pkcs11.target", target.id),
				))
			}
			return nil
		}, gauge)
	}
	register("pkcs11_proxy_clients", "Established logical PKCS #11 clients", func(s TargetStats) int64 { return int64(s.Clients) })
	register("pkcs11_proxy_virtual_sessions", "Open virtual sessions", func(s TargetStats) int64 { return int64(s.VirtualSessions) })
	register("pkcs11_proxy_physical_sessions", "Open physical HSM sessions", func(s TargetStats) int64 { return int64(s.PhysicalOpened) })
	register("pkcs11_proxy_pinned_sessions", "Sessions pinned by in-flight multipart operations", func(s TargetStats) int64 { return int64(s.PinnedSessions) })
	register("pkcs11_proxy_queue_depth", "Requests queued on the HSM session pool", func(s TargetStats) int64 { return int64(s.QueuedRequests) })
	register("pkcs11_proxy_dedup_entries", "Deduplication ledger entries", func(s TargetStats) int64 { return int64(s.DedupEntries) })
}
