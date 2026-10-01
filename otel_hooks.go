package pkcs11

import (
	"context"
	"errors"
	"time"

	"github.com/otpki/pkcs11/raw"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otellog "go.opentelemetry.io/otel/log"
	otellogglobal "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Managed-client operation telemetry rides the global OpenTelemetry providers:
// with no SDK installed every call is a no-op, so the driver carries no
// exporter dependency.
var (
	hooksMeter  = otel.Meter("github.com/otpki/pkcs11")
	hooksTracer = otel.Tracer("github.com/otpki/pkcs11")
	hooksLogger = otellogglobal.Logger("github.com/otpki/pkcs11")

	operationsTotal, _ = hooksMeter.Int64Counter("pkcs11_operations_total",
		metric.WithDescription("Managed PKCS #11 operations, by operation and outcome"))
	operationDuration, _ = hooksMeter.Float64Histogram("pkcs11_operation_duration_seconds",
		metric.WithDescription("Managed PKCS #11 operation duration"), metric.WithUnit("s"))
)

// OTelHooks returns a Hooks trio that emits one span, one counter increment,
// one duration point, and one log record per managed PKCS #11 operation through
// the global OpenTelemetry providers. Metrics are labeled only by operation,
// outcome, read/write mode, and vendor — never by session handle, module path,
// or any payload.
func OTelHooks() Hooks {
	return Hooks{
		Metrics: otelOperationMetrics{},
		Audit:   otelOperationAudit{},
		Tracer:  otelOperationTracer{},
	}
}

func operationOutcome(err error) string {
	if err == nil {
		return "ok"
	}
	if rv, ok := errors.AsType[raw.Error](err); ok {
		return rv.Error()
	}
	return "error"
}

func operationAttrs(event OperationEvent) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("pkcs11.operation", event.Operation),
		attribute.String("pkcs11.vendor", event.Vendor),
		attribute.String("pkcs11.module", event.ModulePath),
		//nolint:gosec // G115: vendor-assigned slot IDs fit int64 in practice.
		attribute.Int64("pkcs11.slot_id", int64(event.SlotID)),
		attribute.Bool("pkcs11.read_write", event.ReadWrite),
		attribute.Int("pkcs11.attempt", event.Attempt),
		//nolint:gosec // G115: vendor-assigned session handles fit int64 in practice.
		attribute.Int64("pkcs11.session", int64(event.Session)),
	}
}

// otelOperationTracer opens one span per managed operation.
type otelOperationTracer struct{}

//nolint:spancheck // The caller owns ending the span via the returned Span.
func (otelOperationTracer) StartPKCS11(ctx context.Context, event OperationEvent) (context.Context, Span) {
	ctx, span := hooksTracer.Start(ctx, "pkcs11."+event.Operation,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(operationAttrs(event)...))
	return ctx, otelOperationSpan{span: span}
}

type otelOperationSpan struct{ span trace.Span }

func (s otelOperationSpan) End(err error) {
	if err != nil {
		s.span.RecordError(err)
		s.span.SetStatus(codes.Error, operationOutcome(err))
	} else {
		s.span.SetStatus(codes.Ok, "")
	}
	s.span.End()
}

// otelOperationMetrics records the operation counter and duration histogram.
type otelOperationMetrics struct{}

func (otelOperationMetrics) ObservePKCS11(ctx context.Context, event OperationEvent) {
	attrs := metric.WithAttributes(
		attribute.String("pkcs11.operation", event.Operation),
		attribute.String("pkcs11.vendor", event.Vendor),
		attribute.Bool("pkcs11.read_write", event.ReadWrite),
		attribute.String("pkcs11.outcome", operationOutcome(event.Err)),
	)
	operationsTotal.Add(ctx, 1, attrs)
	operationDuration.Record(ctx, event.Duration.Seconds(), attrs)
}

// otelOperationAudit emits an OTel log record per completed operation at
// debug severity, warn on failure — matching the request-log convention.
type otelOperationAudit struct{}

func (otelOperationAudit) AuditPKCS11(ctx context.Context, event OperationEvent) {
	var record otellog.Record
	record.SetTimestamp(time.Now())
	record.SetBody(attribute.StringValue("pkcs11 operation"))
	if event.Err != nil {
		record.SetSeverity(otellog.SeverityWarn)
	} else {
		record.SetSeverity(otellog.SeverityDebug)
	}
	record.AddAttributes(
		attribute.String("pkcs11.operation", event.Operation),
		attribute.String("pkcs11.vendor", event.Vendor),
		attribute.String("pkcs11.outcome", operationOutcome(event.Err)),
		attribute.Bool("pkcs11.read_write", event.ReadWrite),
		attribute.Int("pkcs11.attempt", event.Attempt),
		attribute.Float64("pkcs11.duration_seconds", event.Duration.Seconds()),
	)
	hooksLogger.Emit(ctx, record)
}
