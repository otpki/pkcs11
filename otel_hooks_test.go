package pkcs11

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/otpki/pkcs11/raw"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Global instruments delegate to the first provider installed and never
// rebind, so the whole test binary shares one SDK pipeline installed here.
var (
	hooksTestSpans   *tracetest.SpanRecorder
	hooksTestMetrics *sdkmetric.ManualReader
	hooksTestLogs    *hookLogExporter
)

func TestMain(m *testing.M) {
	hooksTestSpans = tracetest.NewSpanRecorder()
	hooksTestMetrics = sdkmetric.NewManualReader()
	hooksTestLogs = &hookLogExporter{}
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(hooksTestSpans)))
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(hooksTestMetrics)))
	otel.SetLoggerProvider(sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(hooksTestLogs))))
	os.Exit(m.Run())
}

type hookLogExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *hookLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.records = append(e.records, records...)
	return nil
}

func (e *hookLogExporter) Shutdown(context.Context) error   { return nil }
func (e *hookLogExporter) ForceFlush(context.Context) error { return nil }

func TestOTelHooksEmitSpanMetricAndLog(t *testing.T) {
	hooks := OTelHooks()
	if hooks.Tracer == nil || hooks.Metrics == nil || hooks.Audit == nil {
		t.Fatal("OTelHooks must populate all three sinks")
	}
	_, done := hooks.begin(context.Background(), OperationEvent{
		Operation:  "C_Sign",
		ModulePath: "/opt/hsm/lib.so",
		Vendor:     "testvendor",
		SlotID:     7,
		Session:    42,
		ReadWrite:  true,
		Attempt:    1,
	})
	done(raw.Error(0xa0)) // CKR_PIN_INCORRECT-ish: a raw error exercises the rv path

	var span sdktrace.ReadOnlySpan
	for _, s := range hooksTestSpans.Ended() {
		if s.Name() == "pkcs11.C_Sign" {
			span = s
		}
	}
	if span == nil {
		t.Fatal("no pkcs11.C_Sign span recorded")
	}
	if span.Status().Code != codes.Error {
		t.Fatalf("operation error must mark the span failed, got %v", span.Status().Code)
	}

	var rm metricdata.ResourceMetrics
	if err := hooksTestMetrics.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "pkcs11_operations_total" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("pkcs11_operations_total not exported")
	}

	hooksTestLogs.mu.Lock()
	defer hooksTestLogs.mu.Unlock()
	found = false
	for _, r := range hooksTestLogs.records {
		if r.Body().AsString() == "pkcs11 operation" {
			found = true
		}
	}
	if !found {
		t.Fatal("no operation log record exported")
	}
}
