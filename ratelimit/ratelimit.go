// Package ratelimit implements multi dimensional quotas: a request is
// evaluated against a set of rules, each scoped to a dimension (user, IP,
// device, ...), and the first rule it exceeds wins.
//
// A fast backend (a Redis/Valkey-protocol cache, see the cache package) holds
// the short lived counters. When it is unavailable the limiter falls back to a
// conservative database backed counter; if that also fails, a critical
// mutation is refused (fail closed) while reads continue, per the failClosed
// flag passed to New.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mori-box/moribox-shared/cache"
	"github.com/mori-box/moribox-shared/database"
	"github.com/mori-box/moribox-shared/observability"
)

// Dimension names one axis of a quota.
type Dimension string

// Common quota dimensions. A caller is free to define additional ones: any
// string value works, these just name the axes this package's callers use
// most often.
const (
	DimUser    Dimension = "user"
	DimSubject Dimension = "subject"
	DimDevice  Dimension = "device"
	DimIP      Dimension = "ip"
	DimRoute   Dimension = "route"
)

// Rule is one quota: at most Limit events per Window on a dimension.
type Rule struct {
	Dimension Dimension
	Limit     int64
	Window    time.Duration
}

// Decision is the limiter verdict.
type Decision struct {
	Allowed    bool
	Dimension  Dimension
	RetryAfter time.Duration
	Remaining  int64
}

// ErrFailClosed reports that no counter store was reachable and the request was
// refused because it mutates state.
var ErrFailClosed = errors.New("rate limiter unavailable and configured to fail closed")

// Limiter evaluates quotas.
type Limiter struct {
	cache      *cache.Client
	db         *database.DB
	failClosed bool
}

// New builds a limiter.
func New(c *cache.Client, db *database.DB, failClosed bool) *Limiter {
	return &Limiter{cache: c, db: db, failClosed: failClosed}
}

// Key identifies a subject on one dimension.
type Key struct {
	Dimension Dimension
	Value     string
}

// Allow evaluates every rule whose dimension has a supplied key. The first
// exceeded rule wins so that the response names the actual limiting axis.
func (l *Limiter) Allow(ctx context.Context, route string, keys []Key, rules []Rule) (Decision, error) {
	values := make(map[Dimension]string, len(keys))
	for _, k := range keys {
		if k.Value != "" {
			values[k.Dimension] = k.Value
		}
	}

	for _, rule := range rules {
		value, ok := values[rule.Dimension]
		if !ok {
			continue
		}
		bucket := fmt.Sprintf("%s|%s|%s", route, rule.Dimension, value)

		count, ttl, err := l.increment(ctx, bucket, rule.Window)
		if err != nil {
			if l.failClosed {
				observability.CacheErrorsTotal.WithLabelValues("ratelimit_fail_closed").Inc()
				return Decision{Allowed: false, Dimension: rule.Dimension, RetryAfter: time.Second}, ErrFailClosed
			}
			continue
		}
		if count > rule.Limit {
			observability.RateLimitedTotal.WithLabelValues(route, string(rule.Dimension)).Inc()
			retry := ttl
			if retry <= 0 {
				retry = rule.Window
			}
			return Decision{Allowed: false, Dimension: rule.Dimension, RetryAfter: retry}, nil
		}
	}
	return Decision{Allowed: true, Remaining: -1}, nil
}

func (l *Limiter) increment(ctx context.Context, bucket string, window time.Duration) (int64, time.Duration, error) {
	if l.cache != nil && l.cache.Enabled() {
		count, ttl, err := l.cache.IncrementWindow(ctx, bucket, window)
		if err == nil {
			return count, ttl, nil
		}
	}
	if l.db == nil {
		return 0, 0, errors.New("no counter store available")
	}
	return l.incrementDB(ctx, bucket, window)
}

// incrementDB implements the conservative fallback. The window is truncated so
// that concurrent processes agree on the bucket without coordination.
func (l *Limiter) incrementDB(ctx context.Context, bucket string, window time.Duration) (int64, time.Duration, error) {
	windowStart := time.Now().UTC().Truncate(window)
	const stmt = `
INSERT INTO rate_limit_counters (bucket_key, window_start, counter)
VALUES (?, ?, 1)
ON DUPLICATE KEY UPDATE counter = counter + 1`

	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	if _, err := l.db.Writer().ExecContext(ctx, stmt, bucket, windowStart); err != nil {
		return 0, 0, err
	}
	var counter int64
	err := l.db.Writer().QueryRowContext(ctx,
		`SELECT counter FROM rate_limit_counters WHERE bucket_key = ? AND window_start = ?`,
		bucket, windowStart).Scan(&counter)
	if err != nil {
		return 0, 0, err
	}
	return counter, time.Until(windowStart.Add(window)), nil
}

// Cleanup removes expired database counters. The reconciler calls it so that
// the fallback table cannot grow without bound after an outage.
func (l *Limiter) Cleanup(ctx context.Context, olderThan time.Duration) (int64, error) {
	res, err := l.db.Writer().ExecContext(ctx,
		`DELETE FROM rate_limit_counters WHERE window_start < ? LIMIT 5000`,
		time.Now().UTC().Add(-olderThan))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
