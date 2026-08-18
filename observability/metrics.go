package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Registry is the process metric registry. A dedicated registry keeps the
// exposed surface explicit instead of relying on the global default.
//
// It is exported so that a process composing its own, service specific
// metrics — reusing this package's factory pattern — registers them against
// the same registry the /metrics endpoint serves.
var Registry = func() *prometheus.Registry {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector())
	r.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return r
}()

var factory = promauto.With(Registry)

// HTTP golden signals.
var (
	HTTPRequestsTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_http_requests_total",
		Help: "HTTP requests handled, by route, method and status class.",
	}, []string{"service", "route", "method", "status"})

	HTTPRequestDuration = factory.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "moribox_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1, 1.5, 3, 5, 10},
	}, []string{"service", "route", "method"})

	HTTPInFlight = factory.NewGaugeVec(prometheus.GaugeOpts{
		Name: "moribox_http_in_flight_requests",
		Help: "HTTP requests currently being served.",
	}, []string{"service"})

	HTTPRejectedTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_http_rejected_total",
		Help: "Requests rejected before handler execution.",
	}, []string{"service", "reason"})
)

// Database signals.
var (
	DBConnectionsInUse = factory.NewGaugeVec(prometheus.GaugeOpts{
		Name: "moribox_db_connections_in_use",
		Help: "Database connections currently checked out of the pool.",
	}, []string{"service", "role"})

	DBConnectionsIdle = factory.NewGaugeVec(prometheus.GaugeOpts{
		Name: "moribox_db_connections_idle",
		Help: "Idle database connections in the pool.",
	}, []string{"service", "role"})

	DBWaitCount = factory.NewGaugeVec(prometheus.GaugeOpts{
		Name: "moribox_db_wait_count",
		Help: "Cumulative number of connection waits.",
	}, []string{"service", "role"})

	DBQueryDuration = factory.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "moribox_db_query_duration_seconds",
		Help:    "Database statement latency in seconds.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 3},
	}, []string{"service", "operation"})

	DBDeadlocksTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_db_deadlocks_total",
		Help: "Transactions aborted by deadlock or lock wait timeout.",
	}, []string{"service", "operation"})

	DBRetriesTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_db_retries_total",
		Help: "Transaction retries triggered by transient database errors.",
	}, []string{"service", "operation"})
)

// Outbound provider signals.
var (
	ProviderRequestsTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_provider_requests_total",
		Help: "Outbound provider calls by taxonomy outcome.",
	}, []string{"provider", "operation", "outcome"})

	ProviderRequestDuration = factory.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "moribox_provider_request_duration_seconds",
		Help:    "Outbound provider latency in seconds.",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10},
	}, []string{"provider", "operation"})

	ProviderCircuitState = factory.NewGaugeVec(prometheus.GaugeOpts{
		Name: "moribox_provider_circuit_state",
		Help: "Circuit breaker state: 0 closed, 1 half-open, 2 open.",
	}, []string{"provider", "operation"})
)

// Queue signals.
var (
	QueueMessagesTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_queue_messages_total",
		Help: "Queue messages published or consumed.",
	}, []string{"queue", "direction", "outcome"})

	QueueOldestMessageAge = factory.NewGaugeVec(prometheus.GaugeOpts{
		Name: "moribox_queue_oldest_message_age_seconds",
		Help: "Age of the oldest visible message.",
	}, []string{"queue"})

	QueueDepth = factory.NewGaugeVec(prometheus.GaugeOpts{
		Name: "moribox_queue_depth",
		Help: "Visible plus in-flight messages.",
	}, []string{"queue"})

	DLQDepth = factory.NewGaugeVec(prometheus.GaugeOpts{
		Name: "moribox_dlq_depth",
		Help: "Messages waiting in a dead letter queue.",
	}, []string{"queue"})
)

// Transactional outbox signals.
var (
	OutboxLagSeconds = factory.NewGauge(prometheus.GaugeOpts{
		Name: "moribox_outbox_lag_seconds",
		Help: "Age of the oldest unpublished outbox event.",
	})

	OutboxUnpublished = factory.NewGauge(prometheus.GaugeOpts{
		Name: "moribox_outbox_unpublished_events",
		Help: "Outbox events not yet published.",
	})

	OutboxPublishedTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_outbox_published_total",
		Help: "Outbox events published to a queue.",
	}, []string{"event_type", "outcome"})
)

// Idempotency, rate limiting and cache signals.
var (
	IdempotencyConflictsTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_idempotency_conflicts_total",
		Help: "Requests rejected because a key was replayed with a different body.",
	}, []string{"route"})

	IdempotencyReplayTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_idempotency_replay_total",
		Help: "Requests served from a stored idempotent response.",
	}, []string{"route"})

	RateLimitedTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_rate_limited_total",
		Help: "Requests rejected by a rate limiter.",
	}, []string{"route", "dimension"})

	CacheErrorsTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_cache_errors_total",
		Help: "Cache backend operations that failed.",
	}, []string{"operation"})

	CacheHitsTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_cache_hits_total",
		Help: "Cache lookups by outcome.",
	}, []string{"namespace", "outcome"})
)

// Audit and security signals.
var (
	AuditAppendFailuresTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "moribox_audit_append_failures_total",
		Help: "Audit events that could not be appended.",
	})

	// AuditChainIntact is a gauge rather than a counter because the question an
	// alert asks is "is the chain broken right now", not "how often has a scan
	// noticed". A counter would keep firing after the chain was repaired.
	AuditChainIntact = factory.NewGauge(prometheus.GaugeOpts{
		Name: "moribox_audit_chain_intact",
		Help: "1 when the last chain verification found no broken link, 0 otherwise.",
	})

	AuditChainVerifiedEvents = factory.NewGauge(prometheus.GaugeOpts{
		Name: "moribox_audit_chain_verified_events",
		Help: "Events examined by the most recent chain verification.",
	})

	SecurityAlertsTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "moribox_security_alerts_total",
		Help: "Security relevant events raised by the application.",
	}, []string{"kind", "severity"})

	BuildInfo = factory.NewGaugeVec(prometheus.GaugeOpts{
		Name: "moribox_build_info",
		Help: "Build metadata, always 1.",
	}, []string{"service", "version", "env"})
)
