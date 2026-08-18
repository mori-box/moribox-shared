// Package cache wraps a Redis-protocol cache (Amazon ElastiCache, Valkey, or
// a plain Redis/Valkey container in development).
//
// It is meant for short lived, reconstructible state: rate counters, read
// caches, distributed single-flight locks, feature flag snapshots. Anything a
// caller cannot afford to lose belongs in the system of record instead:
// losing the cache must never change durable state, only latency.
package cache

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/mori-box/moribox-shared/observability"
	"github.com/redis/go-redis/v9"
)

// Config holds Redis-protocol cache connection settings.
type Config struct {
	Endpoint string
	TLS      bool
	Username string
	Password string
	DB       int
	Enabled  bool
	// FailClosed decides whether critical mutations are rejected when the
	// cache is unavailable and a conservative fallback also fails.
	FailClosed bool
}

// ErrDisabled is returned when no cache endpoint is configured.
var ErrDisabled = errors.New("cache is not configured")

// ErrMiss reports a cache miss.
var ErrMiss = errors.New("cache miss")

// Client is the narrow cache surface used by the application.
type Client struct {
	rdb     *redis.Client
	enabled bool
}

// New builds a cache client. A disabled client answers every call with
// ErrDisabled so that callers exercise their degraded path in development.
func New(cfg Config) *Client {
	if !cfg.Enabled {
		return &Client{enabled: false}
	}
	opts := &redis.Options{
		Addr:            cfg.Endpoint,
		Username:        cfg.Username,
		Password:        cfg.Password,
		DB:              cfg.DB,
		DialTimeout:     2 * time.Second,
		ReadTimeout:     500 * time.Millisecond,
		WriteTimeout:    500 * time.Millisecond,
		PoolSize:        32,
		MinIdleConns:    4,
		MaxRetries:      1,
		ConnMaxIdleTime: 5 * time.Minute,
	}
	if cfg.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &Client{rdb: redis.NewClient(opts), enabled: true}
}

// Enabled reports whether a cache endpoint is configured.
func (c *Client) Enabled() bool { return c.enabled }

// Close releases the connection pool.
func (c *Client) Close() error {
	if !c.enabled {
		return nil
	}
	return c.rdb.Close()
}

// Ping verifies connectivity.
func (c *Client) Ping(ctx context.Context) error {
	if !c.enabled {
		return ErrDisabled
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return c.rdb.Ping(ctx).Err()
}

// Get reads a value.
func (c *Client) Get(ctx context.Context, namespace, key string) ([]byte, error) {
	if !c.enabled {
		return nil, ErrDisabled
	}
	v, err := c.rdb.Get(ctx, namespace+":"+key).Bytes()
	switch {
	case errors.Is(err, redis.Nil):
		observability.CacheHitsTotal.WithLabelValues(namespace, "miss").Inc()
		return nil, ErrMiss
	case err != nil:
		observability.CacheErrorsTotal.WithLabelValues("get").Inc()
		return nil, err
	default:
		observability.CacheHitsTotal.WithLabelValues(namespace, "hit").Inc()
		return v, nil
	}
}

// Set writes a value with a mandatory TTL. The cache never holds durable state,
// so an unbounded key is a bug rather than an optimisation.
func (c *Client) Set(ctx context.Context, namespace, key string, value []byte, ttl time.Duration) error {
	if !c.enabled {
		return ErrDisabled
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	if err := c.rdb.Set(ctx, namespace+":"+key, value, ttl).Err(); err != nil {
		observability.CacheErrorsTotal.WithLabelValues("set").Inc()
		return err
	}
	return nil
}

// Delete removes a key.
func (c *Client) Delete(ctx context.Context, namespace, key string) error {
	if !c.enabled {
		return ErrDisabled
	}
	if err := c.rdb.Del(ctx, namespace+":"+key).Err(); err != nil {
		observability.CacheErrorsTotal.WithLabelValues("del").Inc()
		return err
	}
	return nil
}

// IncrementWindow increments a fixed window counter and returns the new value
// together with the remaining window. It is the primitive behind rate limits.
func (c *Client) IncrementWindow(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	if !c.enabled {
		return 0, 0, ErrDisabled
	}
	pipe := c.rdb.TxPipeline()
	incr := pipe.Incr(ctx, "rl:"+key)
	pipe.Expire(ctx, "rl:"+key, window)
	ttl := pipe.TTL(ctx, "rl:"+key)
	if _, err := pipe.Exec(ctx); err != nil {
		observability.CacheErrorsTotal.WithLabelValues("incr").Inc()
		return 0, 0, err
	}
	return incr.Val(), ttl.Val(), nil
}

// AcquireLock takes a single-flight lock. The returned release function is safe
// to call even when the lock was not held.
func (c *Client) AcquireLock(ctx context.Context, key, token string, ttl time.Duration) (bool, func(context.Context), error) {
	noop := func(context.Context) {}
	if !c.enabled {
		return false, noop, ErrDisabled
	}
	ok, err := c.rdb.SetNX(ctx, "lock:"+key, token, ttl).Result()
	if err != nil {
		observability.CacheErrorsTotal.WithLabelValues("lock").Inc()
		return false, noop, err
	}
	if !ok {
		return false, noop, nil
	}
	release := func(rctx context.Context) {
		// Compare-and-delete so that an expired lock held by another worker is
		// never released by this one.
		const script = `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`
		_ = c.rdb.Eval(rctx, script, []string{"lock:" + key}, token).Err()
	}
	return true, release, nil
}
