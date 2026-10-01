package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/otpki/pkcs11/internal/auditlog"
	"github.com/otpki/pkcs11/internal/obslog"
	"github.com/otpki/pkcs11/proxy"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otlploghttp "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otlpmetrichttp "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otlptracehttp "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellogglobal "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

// setupLogging installs the process-wide slog logger: a bounded, non-blocking
// queue in front of the stderr handler so request paths never stall on I/O.
func setupLogging(cfg options) (*obslog.AsyncHandler, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToUpper(cfg.Logging.Level))); err != nil {
		return nil, fmt.Errorf("logging.level %q: %w", cfg.Logging.Level, err)
	}
	options := &slog.HandlerOptions{Level: level}
	var delegate slog.Handler
	switch strings.ToLower(cfg.Logging.Format) {
	case "json":
		delegate = slog.NewJSONHandler(os.Stderr, options)
	case "text", "":
		delegate = slog.NewTextHandler(os.Stderr, options)
	default:
		return nil, fmt.Errorf("logging.format %q: want text or json", cfg.Logging.Format)
	}
	handler := obslog.NewAsyncHandler(delegate, cfg.Logging.QueueSize)
	slog.SetDefault(slog.New(handler))
	return handler, nil
}

// setupAudit opens the signed audit log. An empty audit.path disables it;
// audit.key_file defaults to <path>.key and is generated on first run, with
// the public key written next to it for offline verification.
func setupAudit(cfg options) (*auditlog.Writer, error) {
	if cfg.Audit.Path == "" {
		return nil, nil
	}
	keyFile := cfg.Audit.KeyFile
	if keyFile == "" {
		keyFile = cfg.Audit.Path + ".key"
	}
	writer, err := auditlog.Open(cfg.Audit.Path, keyFile, auditlog.Options{
		QueueSize:          cfg.Audit.QueueSize,
		BatchSize:          cfg.Audit.BatchSize,
		CheckpointInterval: cfg.Audit.CheckpointInterval,
	})
	if err != nil {
		return nil, err
	}
	slog.Info("audit log active", "path", cfg.Audit.Path, "key_id", writer.KeyID(), "public_key", writer.PublicKeyPath())
	return writer, nil
}

// otelProviders bundles the three SDK providers for one shutdown.
type otelProviders struct {
	traces  *trace.TracerProvider
	metrics *metric.MeterProvider
	logs    *log.LoggerProvider
}

// setupOTel wires the OTLP/HTTP exporters into the global OpenTelemetry
// providers the proxy instruments against. An empty otel.endpoint leaves the
// default no-op providers installed and disables export.
func setupOTel(ctx context.Context, cfg options) (*otelProviders, error) {
	if cfg.OTel.Endpoint == "" {
		return nil, nil
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", cfg.OTel.ServiceName),
		attribute.String("service.namespace", "pkcs11"),
	))
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}
	endpoint := strings.TrimPrefix(strings.TrimPrefix(cfg.OTel.Endpoint, "http://"), "https://")
	var traceOpts []otlptracehttp.Option
	var metricOpts []otlpmetrichttp.Option
	var logOpts []otlploghttp.Option
	// Bare host:port and https:// endpoints default to TLS; insecure transports
	// must opt in with an http:// scheme or the insecure flag.
	if strings.HasPrefix(cfg.OTel.Endpoint, "http://") || cfg.OTel.Insecure {
		traceOpts = append(traceOpts, otlptracehttp.WithInsecure())
		metricOpts = append(metricOpts, otlpmetrichttp.WithInsecure())
		logOpts = append(logOpts, otlploghttp.WithInsecure())
	}
	traceOpts = append(traceOpts, otlptracehttp.WithEndpoint(endpoint))
	metricOpts = append(metricOpts, otlpmetrichttp.WithEndpoint(endpoint))
	logOpts = append(logOpts, otlploghttp.WithEndpoint(endpoint))

	traceExporter, err := otlptracehttp.New(ctx, traceOpts...)
	if err != nil {
		return nil, fmt.Errorf("otel traces exporter: %w", err)
	}
	metricExporter, err := otlpmetrichttp.New(ctx, metricOpts...)
	if err != nil {
		return nil, fmt.Errorf("otel metrics exporter: %w", err)
	}
	logExporter, err := otlploghttp.New(ctx, logOpts...)
	if err != nil {
		return nil, fmt.Errorf("otel logs exporter: %w", err)
	}
	providers := &otelProviders{
		traces: trace.NewTracerProvider(
			trace.WithBatcher(traceExporter),
			trace.WithResource(res),
		),
		metrics: metric.NewMeterProvider(
			metric.WithResource(res),
			metric.WithReader(metric.NewPeriodicReader(metricExporter, metric.WithInterval(cfg.OTel.MetricInterval))),
		),
		logs: log.NewLoggerProvider(
			log.WithResource(res),
			log.WithProcessor(log.NewBatchProcessor(logExporter)),
		),
	}
	otel.SetTracerProvider(providers.traces)
	otel.SetMeterProvider(providers.metrics)
	otellogglobal.SetLoggerProvider(providers.logs)
	slog.Info("opentelemetry export active",
		"endpoint", cfg.OTel.Endpoint, "insecure", cfg.OTel.Insecure,
		"service", cfg.OTel.ServiceName, "metric_interval", cfg.OTel.MetricInterval)
	return providers, nil
}

// Shutdown flushes exporters in reverse signal order: logs and traces first,
// metrics last, so shutdown-time observations still export.
func (providers *otelProviders) Shutdown(ctx context.Context) error {
	if providers == nil {
		return nil
	}
	var errs []error
	if err := providers.logs.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := providers.traces.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := providers.metrics.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 0 {
		return errs[0]
	}
	return nil
}

// auditSink adapts the writer to the proxy sink interface, keeping a nil
// writer as a nil interface so the server does not call a missing sink.
func auditSink(writer *auditlog.Writer) proxy.AuditSink {
	if writer == nil {
		return nil
	}
	return writer
}
