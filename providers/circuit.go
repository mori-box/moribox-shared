package providers

import (
	"sync"
	"time"

	"github.com/mori-box/moribox-shared/observability"
)

// CircuitState is the breaker state.
type CircuitState string

// Circuit states.
const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

// CircuitBreaker protects a provider operation from retry amplification.
//
// Failures are counted inside a sliding window. Once the threshold is crossed
// the circuit opens and new work stays in the queue rather than hammering a
// provider that is already struggling; after the cooldown a single probe decides
// whether to close again.
type CircuitBreaker struct {
	name      string
	threshold int
	window    time.Duration
	cooldown  time.Duration

	mu          sync.Mutex
	state       CircuitState
	failures    []time.Time
	openedAt    time.Time
	halfOpenUse bool
}

// NewCircuitBreaker builds a breaker.
func NewCircuitBreaker(name string, threshold int, window, cooldown time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 10
	}
	if window <= 0 {
		window = 30 * time.Second
	}
	if cooldown <= 0 {
		cooldown = 20 * time.Second
	}
	b := &CircuitBreaker{
		name: name, threshold: threshold, window: window, cooldown: cooldown, state: CircuitClosed,
	}
	b.publish()
	return b
}

// Allow reports whether a call may proceed.
func (b *CircuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(b.openedAt) >= b.cooldown {
			b.state = CircuitHalfOpen
			b.halfOpenUse = false
			b.publish()
		} else {
			return false
		}
		fallthrough
	case CircuitHalfOpen:
		// Exactly one probe is admitted; its outcome decides the next state.
		if b.halfOpenUse {
			return false
		}
		b.halfOpenUse = true
		return true
	default:
		return true
	}
}

// RecordSuccess closes the circuit.
func (b *CircuitBreaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = nil
	if b.state != CircuitClosed {
		b.state = CircuitClosed
		b.publish()
	}
}

// RecordFailure counts a failure and may open the circuit.
func (b *CircuitBreaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-b.window)
	kept := b.failures[:0]
	for _, t := range b.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.failures = append(kept, now)

	if b.state == CircuitHalfOpen || len(b.failures) >= b.threshold {
		b.state = CircuitOpen
		b.openedAt = now
		b.halfOpenUse = false
		b.publish()
	}
}

// State returns the current breaker state.
func (b *CircuitBreaker) State() CircuitState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

func (b *CircuitBreaker) publish() {
	var value float64
	switch b.state {
	case CircuitClosed:
		value = 0
	case CircuitHalfOpen:
		value = 1
	case CircuitOpen:
		value = 2
	}
	observability.ProviderCircuitState.WithLabelValues(b.name, "all").Set(value)
}
