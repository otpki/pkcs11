package proxycmd

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/otpki/pkcs11/internal/auditlog"
	"github.com/otpki/pkcs11/internal/obslog"
	"github.com/otpki/pkcs11/proxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otlploghttp "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otlpmetrichttp "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otlptracehttp "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
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
	keyFile = cmp.Or(keyFile, cfg.Audit.Path+".key")
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

// otelProviders bundles the SDK providers and scrape handler for one
// shutdown. Traces and logs exist only with otel.endpoint; the metrics
// provider exists whenever either sink is configured, with one reader per
// sink — the OTLP periodic reader and/or the Prometheus pull reader.
type otelProviders struct {
	traces  *trace.TracerProvider
	metrics *metric.MeterProvider
	logs    *log.LoggerProvider
	// prometheus is the pull reader backing metricsHandler; it lives on the
	// same MeterProvider as the OTLP reader, so both sinks see every
	// instrument under its existing name.
	prometheus *otelprom.Exporter
	scrape     http.Handler
}

// metricsHandler returns the Prometheus scrape handler for /metrics, or nil
// when no health listener is configured.
func (providers *otelProviders) metricsHandler() http.Handler {
	if providers == nil {
		return nil
	}
	return providers.scrape
}

// setupOTel installs the OpenTelemetry metric, trace, and log providers used by the proxy. Metrics
// are enabled for OTLP export or the local Prometheus endpoint.
func setupOTel(ctx context.Context, cfg options) (*otelProviders, error) {
	wantOTLP := cfg.OTel.Endpoint != ""
	wantPrometheus := cfg.Health.Listen != ""
	if !wantOTLP && !wantPrometheus {
		return nil, nil
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", cfg.OTel.ServiceName),
		attribute.String("service.namespace", "pkcs11"),
	))
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}
	providers := &otelProviders{}
	var readers []metric.Reader
	if wantPrometheus {
		// A dedicated registry keeps /metrics scoped to the proxy's
		// instruments — the process-wide default registry could carry
		// unrelated collectors in embedded deployments.
		registry := prometheus.NewRegistry()
		exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
		if err != nil {
			return nil, fmt.Errorf("otel prometheus exporter: %w", err)
		}
		providers.prometheus = exporter
		providers.scrape = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		readers = append(readers, exporter)
	}
	if wantOTLP {
		endpoint := strings.TrimPrefix(strings.TrimPrefix(cfg.OTel.Endpoint, "http://"), "https://")
		var traceOpts []otlptracehttp.Option
		var metricOpts []otlpmetrichttp.Option
		var logOpts []otlploghttp.Option
		// Bare host:port and https:// endpoints default to TLS; insecure
		// transports must opt in with an http:// scheme or the insecure flag.
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
		providers.traces = trace.NewTracerProvider(
			trace.WithBatcher(traceExporter),
			trace.WithResource(res),
		)
		providers.logs = log.NewLoggerProvider(
			log.WithResource(res),
			log.WithProcessor(log.NewBatchProcessor(logExporter)),
		)
		readers = append(readers,
			metric.NewPeriodicReader(metricExporter, metric.WithInterval(cfg.OTel.MetricInterval)))
	}
	meterOpts := []metric.Option{metric.WithResource(res)}
	for _, reader := range readers {
		meterOpts = append(meterOpts, metric.WithReader(reader))
	}
	providers.metrics = metric.NewMeterProvider(meterOpts...)
	otel.SetMeterProvider(providers.metrics)
	if providers.traces != nil {
		otel.SetTracerProvider(providers.traces)
		otel.SetLoggerProvider(providers.logs)
		slog.Info("opentelemetry export active",
			"endpoint", cfg.OTel.Endpoint, "insecure", cfg.OTel.Insecure,
			"service", cfg.OTel.ServiceName, "metric_interval", cfg.OTel.MetricInterval)
	}
	return providers, nil
}

// Shutdown flushes exporters in reverse signal order: logs and traces first,
// metrics last, so shutdown-time observations still export.
func (providers *otelProviders) Shutdown(ctx context.Context) error {
	if providers == nil {
		return nil
	}
	var errs []error
	if providers.logs != nil {
		if err := providers.logs.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if providers.traces != nil {
		if err := providers.traces.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if providers.metrics != nil {
		if err := providers.metrics.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
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
