package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// TracingConfig configures StartTracing.
type TracingConfig struct {
	ServiceName string
	// Namespace groups the resource under one service.namespace attribute. It
	// is optional; when empty, no namespace attribute is set.
	Namespace    string
	BuildDigest  string
	Environment  string
	Enabled      bool
	OTLPEndpoint string
	OTLPInsecure bool
	SampleRatio  float64
}

// StartTracing configures the OpenTelemetry tracer provider.
//
// Correlation identifiers propagate through HTTP, the outbox, the queue and
// provider callbacks, so one trace can span a request and the downstream
// effect it eventually causes.
func StartTracing(ctx context.Context, cfg TracingConfig) (func(context.Context) error, error) {
	if !cfg.Enabled {
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{}))
		return func(context.Context) error { return nil }, nil
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(cfg.OTLPEndpoint)}
	if cfg.OTLPInsecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	attrs := []attribute.KeyValue{
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.version", cfg.BuildDigest),
		attribute.String("deployment.environment.name", cfg.Environment),
	}
	if cfg.Namespace != "" {
		attrs = append(attrs, attribute.String("service.namespace", cfg.Namespace))
	}

	// A schemaless resource merges cleanly with the SDK default, whose semantic
	// convention version moves independently of the one this module imports.
	res, err := sdkresource.Merge(sdkresource.Default(), sdkresource.NewSchemaless(attrs...))
	if err != nil {
		return nil, err
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	return func(shutdownCtx context.Context) error {
		return provider.Shutdown(shutdownCtx)
	}, nil
}
