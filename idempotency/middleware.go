package idempotency

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/mori-box/moribox-shared/httpx"
	"github.com/mori-box/moribox-shared/ids"
	"github.com/mori-box/moribox-shared/observability"
)

type contextKey int

const (
	keyContextKey contextKey = iota
	scopeContextKey
	hashContextKey
)

// KeyFromContext returns the idempotency key claimed for this request.
func KeyFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(keyContextKey).(string); ok {
		return v
	}
	return ""
}

// ScopeFromContext returns the actor scope for this request.
func ScopeFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(scopeContextKey).(string); ok {
		return v
	}
	return ""
}

// RequestHashFromContext returns the canonical request digest.
func RequestHashFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(hashContextKey).(string); ok {
		return v
	}
	return ""
}

// ScopeFunc derives the actor scope of a request, for example "user:01J..." or
// "admin:01J...". Scoping by actor prevents one caller from probing or
// colliding with another caller's keys.
type ScopeFunc func(r *http.Request) (string, error)

// bufferingWriter captures the handler response so that it can be stored.
type bufferingWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
	wrote  bool
}

func (w *bufferingWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.status = status
	w.wrote = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *bufferingWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	w.buf.Write(b)
	return w.ResponseWriter.Write(b)
}

// maxStoredBody bounds what is replayed. A response larger than this is served
// normally but not stored, and a retry re-executes against the same unique
// constraints, which still cannot create a second business effect.
const maxStoredBody = 64 * 1024

// Middleware enforces and applies idempotency for mutation routes.
func Middleware(store *Store, scope ScopeFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			route := r.Method + " " + httpx.RoutePattern(r)
			key := strings.TrimSpace(r.Header.Get(httpx.HeaderIdempotency))
			if key == "" {
				httpx.WriteProblem(w, r, httpx.New(http.StatusBadRequest, httpx.CodeIdempotencyKeyRequired,
					"Idempotency-Key required",
					"every mutation must carry an Idempotency-Key header"))
				return
			}
			if len(key) > 255 {
				httpx.WriteProblem(w, r, httpx.ErrValidation("Idempotency-Key must not exceed 255 characters"))
				return
			}

			actorScope, err := scope(r)
			if err != nil {
				httpx.WriteProblem(w, r, err)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				httpx.WriteProblem(w, r, httpx.ErrValidation("request body could not be read"))
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))

			requestHash, err := RequestHash(actorScope, route, body)
			if err != nil {
				httpx.WriteProblem(w, r, httpx.ErrInternal(err))
				return
			}

			existing, err := store.Begin(r.Context(), actorScope, key, route, requestHash)
			switch {
			case errors.Is(err, ErrConflict):
				observability.IdempotencyConflictsTotal.WithLabelValues(route).Inc()
				observability.SecurityAlertsTotal.WithLabelValues("idempotency_conflict", "high").Inc()
				observability.LoggerFromContext(r.Context()).Warn("idempotency conflict",
					"route", route, "actor_scope", actorScope)
				httpx.WriteProblem(w, r, httpx.ErrConflict(httpx.CodeIdempotencyConflict,
					"this Idempotency-Key was already used with a different request body"))
				return
			case errors.Is(err, ErrInProgress):
				httpx.WriteProblem(w, r, httpx.ErrConflict(httpx.CodeRequestInProgress,
					"an identical request is still being processed").
					WithHeader("Retry-After", "1"))
				return
			case err != nil:
				httpx.WriteProblem(w, r, httpx.ErrInternal(err))
				return
			}

			if existing != nil {
				observability.IdempotencyReplayTotal.WithLabelValues(route).Inc()
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Idempotency-Replayed", "true")
				w.Header().Set("Cache-Control", "no-store")
				status := existing.Status
				if status == 0 {
					status = http.StatusOK
				}
				w.WriteHeader(status)
				_, _ = w.Write(existing.Body)
				return
			}

			ctx := r.Context()
			ctx = contextWithValues(ctx, key, actorScope, requestHash)

			buffered := &bufferingWriter{ResponseWriter: w}
			next.ServeHTTP(buffered, r.WithContext(ctx))

			status := buffered.status
			if status == 0 {
				status = http.StatusOK
			}
			switch {
			case status >= 200 && status < 400:
				payload := buffered.buf.Bytes()
				if len(payload) > maxStoredBody {
					payload = nil
				}
				if err := store.Complete(ctx, actorScope, key, status, payload, resourceIDFromContext(ctx)); err != nil {
					observability.LoggerFromContext(ctx).Error("failed to store idempotent response",
						"route", route, "error", err.Error())
				}
			case status == http.StatusTooManyRequests || status >= 500:
				// Transient: allow the client to retry with the same key.
				if err := store.Fail(ctx, actorScope, key); err != nil {
					observability.LoggerFromContext(ctx).Error("failed to mark idempotency record retryable",
						"route", route, "error", err.Error())
				}
			default:
				// A deterministic client error is stored so that a retry gets
				// the same answer instead of racing the same broken request.
				payload := buffered.buf.Bytes()
				if len(payload) > maxStoredBody {
					payload = nil
				}
				if err := store.Complete(ctx, actorScope, key, status, payload, ids.None()); err != nil {
					observability.LoggerFromContext(ctx).Error("failed to store idempotent error",
						"route", route, "error", err.Error())
				}
			}
		})
	}
}
