package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mori-box/moribox-shared/ids"
	"github.com/mori-box/moribox-shared/observability"
	"go.opentelemetry.io/otel/trace"
)

// HeaderRequestID is the correlation header accepted and echoed by every API.
const (
	HeaderRequestID    = "X-Request-Id"
	HeaderTraceID      = "X-Trace-Id"
	HeaderIdempotency  = "Idempotency-Key"
	HeaderReason       = "X-Reason"
	HeaderStepUp       = "X-Step-Up-Token"
	HeaderDeviceID     = "X-Device-Id"
	HeaderRetryAfterMs = "X-Retry-After-Ms"
	// The value is an HTTP header name, not a token. G101 matched the constant's
	// name, which has to contain "Token" because the header does.
	HeaderCSRFToken    = "X-CSRF-Token" //nolint:gosec // G101: this is an HTTP header name, not a credential; the constant's name is what the rule matched
	HeaderProviderSig  = "X-JWS-Signature"
	HeaderProviderTime = "X-Timestamp"
)

// responseWriter captures the status code and byte count for telemetry.
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (w *responseWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.status = status
	w.wrote = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Status returns the response status, defaulting to 200.
func (w *responseWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// RequestContext installs the request id, trace id and scoped logger.
func RequestContext(service string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := sanitiseCorrelationID(r.Header.Get(HeaderRequestID))
			if requestID == "" {
				requestID = ids.New().String()
			}
			ctx := observability.ContextWithRequestID(r.Context(), requestID)

			traceID := ""
			if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
				traceID = sc.TraceID().String()
			}
			if traceID == "" {
				traceID = sanitiseCorrelationID(r.Header.Get(HeaderTraceID))
			}
			if traceID != "" {
				ctx = observability.ContextWithTraceID(ctx, traceID)
			}

			logger := observability.LoggerFromContext(ctx)
			ctx = observability.ContextWithLogger(ctx, logger)

			w.Header().Set(HeaderRequestID, requestID)
			if traceID != "" {
				w.Header().Set(HeaderTraceID, traceID)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func sanitiseCorrelationID(v string) string {
	v = strings.TrimSpace(v)
	if len(v) == 0 || len(v) > 128 {
		return ""
	}
	for _, r := range v {
		if r < 0x20 || r > 0x7e {
			return ""
		}
	}
	return v
}

// AccessLog records one structured line per request plus golden signal metrics.
func AccessLog(service string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			observability.HTTPInFlight.WithLabelValues(service).Inc()
			defer observability.HTTPInFlight.WithLabelValues(service).Dec()

			rw := &responseWriter{ResponseWriter: w}
			next.ServeHTTP(rw, r)

			route := RoutePattern(r)
			elapsed := time.Since(start)
			observability.HTTPRequestsTotal.WithLabelValues(service, route, r.Method, statusClass(rw.Status())).Inc()
			observability.HTTPRequestDuration.WithLabelValues(service, route, r.Method).Observe(elapsed.Seconds())

			observability.LoggerFromContext(r.Context()).Info("http request",
				"method", r.Method,
				"route", route,
				"status", rw.Status(),
				"duration_ms", elapsed.Milliseconds(),
				"bytes", rw.bytes,
			)
		})
	}
}

// RoutePattern returns the chi route template, falling back to a safe literal.
func RoutePattern(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if p := rctx.RoutePattern(); p != "" {
			return p
		}
	}
	return "unmatched"
}

func statusClass(status int) string {
	switch {
	case status < 200:
		return "1xx"
	case status < 300:
		return "2xx"
	case status < 400:
		return "3xx"
	case status < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

// Recoverer converts a panic into a 500 problem document without leaking the
// stack trace to the client.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The recovery runs while the handler's stack is unwinding, so it has no
		// context of its own to thread anywhere: it logs through the request's
		// context and writes the response through the request it already holds.
		// There is no call here that should be given a different one.
		defer func() { //nolint:contextcheck // panic recovery unwinds a request and writes its response through the request it already holds
			if rec := recover(); rec != nil {
				if errors.Is(fmt.Errorf("%v", rec), http.ErrAbortHandler) {
					panic(rec)
				}
				observability.LoggerFromContext(r.Context()).Error("panic recovered",
					"panic", fmt.Sprintf("%v", rec),
					"stack", string(debug.Stack()),
					"path", r.URL.Path,
				)
				WriteProblem(w, r, ErrInternal(fmt.Errorf("panic: %v", rec)))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Timeout bounds the total handler time.
func Timeout(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// MaxBody rejects oversized payloads before the handler reads them.
func MaxBody(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				WriteProblem(w, r, New(http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
					"Payload too large", "request body exceeds the configured limit"))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}

// Concurrency applies a bounded semaphore so that an overloaded process sheds
// load deterministically instead of exhausting the database pool.
func Concurrency(service string, limit int) func(http.Handler) http.Handler {
	sem := make(chan struct{}, limit)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				next.ServeHTTP(w, r)
			default:
				observability.HTTPRejectedTotal.WithLabelValues(service, "concurrency_limit").Inc()
				WriteProblem(w, r, New(http.StatusServiceUnavailable, CodeServiceUnavailable,
					"Service busy", "the service is shedding load; retry shortly").
					WithHeader("Retry-After", "1"))
			}
		})
	}
}

// SecurityHeaders sets the baseline response headers for API responses.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// PrivateCache marks user specific responses as non cacheable.
func PrivateCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Vary", "Authorization")
		next.ServeHTTP(w, r)
	})
}

// CORS applies a strict origin allowlist. An empty allowlist disables CORS.
//
// extraHeaders lists request headers, beyond the platform baseline below, that
// this deployment's CORS preflight must allow. A browser silently drops a
// header the preflight did not permit, so a caller-specific header (an
// application invite token, for example) has to be named here or it vanishes
// on the way in.
func CORS(allowed []string, allowCredentials bool, extraHeaders ...string) func(http.Handler) http.Handler {
	set := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		set[strings.ToLower(strings.TrimSpace(o))] = struct{}{}
	}
	allowedHeaders := append([]string{
		"Authorization", "Content-Type", HeaderIdempotency, HeaderRequestID,
		HeaderReason, HeaderCSRFToken, HeaderDeviceID, HeaderStepUp,
	}, extraHeaders...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if _, ok := set[strings.ToLower(origin)]; ok {
					h := w.Header()
					h.Set("Access-Control-Allow-Origin", origin)
					h.Add("Vary", "Origin")
					h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
					h.Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
					h.Set("Access-Control-Max-Age", "600")
					if allowCredentials {
						h.Set("Access-Control-Allow-Credentials", "true")
					}
				} else if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// DecodeJSON reads a strict JSON body into dst. Unknown fields are rejected so
// that server owned attributes cannot be mass assigned.
func DecodeJSON(r *http.Request, dst any) error {
	ct := r.Header.Get("Content-Type")
	if ct != "" {
		mediaType := strings.TrimSpace(strings.Split(ct, ";")[0])
		if !strings.EqualFold(mediaType, "application/json") {
			return New(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
				"Unsupported media type", "Content-Type must be application/json")
		}
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return New(http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
				"Payload too large", "request body exceeds the configured limit")
		}
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return ErrValidation(fmt.Sprintf("malformed JSON at byte %d", syntaxErr.Offset))
		}
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			return ErrValidation("invalid field type", FieldError{
				Field:   typeErr.Field,
				Message: fmt.Sprintf("expected %s", typeErr.Type.String()),
			})
		}
		if strings.Contains(err.Error(), "unknown field") {
			field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
			return ErrValidation("unknown field in request body", FieldError{
				Field:   field,
				Message: "this field is server owned and must not be supplied",
			})
		}
		if errors.Is(err, io.EOF) {
			return ErrValidation("request body must not be empty")
		}
		return ErrValidation("request body could not be parsed")
	}
	if dec.More() {
		return ErrValidation("request body must contain exactly one JSON document")
	}
	return nil
}

// WriteJSON writes a success response.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(emptyCollections(body))
}

// emptyCollections replaces nil slices and maps in a response envelope with
// empty ones.
//
// Go marshals a nil slice as null, and a query that matched nothing naturally
// returns a nil slice, so "no results" and "no such field" become the same
// value on the wire. A client that reads .length on the result then throws —
// which is exactly how the admin console came to render a blank page when the
// platform was healthy and simply had no open incidents. An empty collection is
// the normal state of a healthy system, so it must serialise as one.
//
// The rewrite deliberately reaches only into a map envelope, which is the shape
// every list endpoint here uses. Walking arbitrary structs would mean rewriting
// values the handler did not intend this function to touch, and a field that is
// genuinely optional is expressed with a pointer or omitempty rather than a nil
// slice. Structs therefore fix this at the source; see the constructors in
// internal/admin/app.
func emptyCollections(body any) any {
	envelope, ok := body.(map[string]any)
	if !ok {
		return body
	}
	for key, value := range envelope {
		if value == nil {
			continue
		}
		v := reflect.ValueOf(value)
		switch v.Kind() {
		case reflect.Slice:
			if v.IsNil() {
				envelope[key] = reflect.MakeSlice(v.Type(), 0, 0).Interface()
			}
		case reflect.Map:
			if v.IsNil() {
				envelope[key] = reflect.MakeMap(v.Type()).Interface()
			}
		}
	}
	return envelope
}

// WriteAccepted writes a 202 with the polling contract clients expect.
func WriteAccepted(w http.ResponseWriter, statusURL string, retryAfter time.Duration, body any) {
	w.Header().Set("Location", statusURL)
	w.Header().Set(HeaderRetryAfterMs, strconv.FormatInt(retryAfter.Milliseconds(), 10))
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
	WriteJSON(w, http.StatusAccepted, body)
}

// PathID parses a ULID path parameter.
func PathID(r *http.Request, name string) (ids.ID, error) {
	raw := chi.URLParam(r, name)
	id, err := ids.Parse(raw)
	if err != nil {
		return ids.Nil, ErrValidation("invalid identifier", FieldError{Field: name, Message: "must be a ULID"})
	}
	return id, nil
}

// QueryInt reads a bounded integer query parameter.
func QueryInt(r *http.Request, name string, def, min, max int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, ErrValidation("invalid query parameter", FieldError{Field: name, Message: "must be an integer"})
	}
	if v < min || v > max {
		return 0, ErrValidation("query parameter out of range",
			FieldError{Field: name, Message: fmt.Sprintf("must be within [%d, %d]", min, max)})
	}
	return v, nil
}
