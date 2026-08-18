// Package health exposes startup, readiness and liveness probes.
//
// The three probes differ deliberately: liveness never touches a dependency,
// readiness answers from a cached dependency verdict refreshed in the
// background, and startup blocks until the first successful check.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Check is one named dependency probe.
type Check struct {
	Name     string
	Critical bool
	Probe    func(ctx context.Context) error
}

// Status is the cached outcome of one check.
type Status struct {
	Name      string    `json:"name"`
	Healthy   bool      `json:"healthy"`
	Critical  bool      `json:"critical"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Registry evaluates checks on a schedule and serves the probe endpoints.
type Registry struct {
	service string
	version string

	mu       sync.RWMutex
	checks   []Check
	status   map[string]Status
	started  atomic.Bool
	draining atomic.Bool
	interval time.Duration
}

// NewRegistry builds a registry.
func NewRegistry(service, version string, interval time.Duration) *Registry {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Registry{
		service:  service,
		version:  version,
		status:   map[string]Status{},
		interval: interval,
	}
}

// Register adds a dependency check.
func (r *Registry) Register(c Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks = append(r.checks, c)
}

// Start runs the first evaluation and then refreshes in the background. The
// readiness endpoint therefore never issues a database query per request.
func (r *Registry) Start(ctx context.Context) {
	r.evaluate(ctx)
	r.started.Store(true)
	go func() {
		t := time.NewTicker(r.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.evaluate(ctx)
			}
		}
	}()
}

// BeginDraining flips readiness to false so that the load balancer removes the
// pod before the HTTP server stops accepting connections.
func (r *Registry) BeginDraining() { r.draining.Store(true) }

func (r *Registry) evaluate(ctx context.Context) {
	r.mu.RLock()
	checks := make([]Check, len(r.checks))
	copy(checks, r.checks)
	r.mu.RUnlock()

	results := make(map[string]Status, len(checks))
	for _, c := range checks {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := c.Probe(probeCtx)
		cancel()
		st := Status{Name: c.Name, Critical: c.Critical, Healthy: err == nil, CheckedAt: time.Now().UTC()}
		if err != nil {
			st.Error = err.Error()
		}
		results[c.Name] = st
	}

	r.mu.Lock()
	r.status = results
	r.mu.Unlock()
}

// Snapshot returns the cached check results.
func (r *Registry) Snapshot() []Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Status, 0, len(r.status))
	for _, s := range r.status {
		out = append(out, s)
	}
	return out
}

// Ready reports whether every critical dependency is healthy.
func (r *Registry) Ready() bool {
	if r.draining.Load() || !r.started.Load() {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.status {
		if s.Critical && !s.Healthy {
			return false
		}
	}
	return true
}

type probeResponse struct {
	Service string   `json:"service"`
	Version string   `json:"version"`
	Status  string   `json:"status"`
	Checks  []Status `json:"checks,omitempty"`
}

// LivenessHandler answers without touching any dependency: a failing database
// must not cause the orchestrator to restart an otherwise healthy process.
func (r *Registry) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, probeResponse{Service: r.service, Version: r.version, Status: "alive"})
	}
}

// ReadinessHandler answers from the cached verdict.
func (r *Registry) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if r.Ready() {
			writeJSON(w, http.StatusOK, probeResponse{Service: r.service, Version: r.version, Status: "ready", Checks: r.Snapshot()})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, probeResponse{Service: r.service, Version: r.version, Status: "not_ready", Checks: r.Snapshot()})
	}
}

// StartupHandler reports whether the first evaluation has completed.
func (r *Registry) StartupHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if r.started.Load() {
			writeJSON(w, http.StatusOK, probeResponse{Service: r.service, Version: r.version, Status: "started"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, probeResponse{Service: r.service, Version: r.version, Status: "starting"})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
