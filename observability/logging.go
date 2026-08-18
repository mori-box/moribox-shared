// Package observability wires structured logging, metrics and tracing.
//
// Logging uses slog with a JSON handler and a central redaction pass. Values
// that must never reach logs, traces or metrics — bearer tokens, provider
// secrets, raw VPN keys, assignment plaintext or ciphertext, contact details,
// payment provider bodies and admin export contents — are replaced before the
// record is emitted, regardless of which call site produced them.
package observability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
)

// Redacted is the replacement value written instead of a sensitive field.
const Redacted = "[redacted]"

type contextKey int

const (
	loggerKey contextKey = iota
	requestIDKey
	traceIDKey
)

// deniedKeys is the allowlist complement: any log attribute whose key matches
// one of these fragments is redacted.
var deniedKeys = []string{
	"authorization",
	"cookie",
	"set-cookie",
	"token",
	"secret",
	"password",
	"passphrase",
	"client_secret",
	"api_key",
	"apikey",
	"private_key",
	"vpn_key",
	"license_key",
	"activation_key",
	// A promo code is a bearer secret: whoever reads it can redeem the prize.
	// The code paths never put one in a log attribute or an audit metadata
	// field, and this makes a careless future call site fail safe. "prize_code"
	// is deliberately unaffected — it names a catalog entry, not a secret.
	"promo_code",
	"redemption_code",
	"assignment",
	"ciphertext",
	"plaintext",
	"seed",
	"dek",
	"credentials",
	"email",
	"phone",
	"address",
	"full_name",
	"response_body",
	"payload_body",
	"export_content",
	"card",
	"iban",
}

// redactingHandler applies the deny rules to every attribute.
type redactingHandler struct{ inner slog.Handler }

func (h redactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	clone := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	if id := RequestIDFromContext(ctx); id != "" {
		clone.AddAttrs(slog.String("request_id", id))
	}
	if id := TraceIDFromContext(ctx); id != "" {
		clone.AddAttrs(slog.String("trace_id", id))
	}
	r.Attrs(func(a slog.Attr) bool {
		clone.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, clone)
}

func (h redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, redactAttr(a))
	}
	return redactingHandler{inner: h.inner.WithAttrs(out)}
}

func (h redactingHandler) WithGroup(name string) slog.Handler {
	return redactingHandler{inner: h.inner.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		grouped := a.Value.Group()
		out := make([]any, 0, len(grouped))
		for _, g := range grouped {
			out = append(out, redactAttr(g))
		}
		return slog.Group(a.Key, out...)
	}
	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	return a
}

// IsSensitiveKey reports whether a field name must never be logged verbatim.
func IsSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, denied := range deniedKeys {
		if strings.Contains(k, denied) {
			return true
		}
	}
	return false
}

// NewLogger builds the process logger.
func NewLogger(level, service, env, build string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	base := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.String("ts", a.Value.Time().UTC().Format("2006-01-02T15:04:05.000000Z"))
			}
			return a
		},
	})
	return slog.New(redactingHandler{inner: base}).With(
		slog.String("service", service),
		slog.String("env", env),
		slog.String("build", build),
	)
}

// ContextWithLogger stores a request scoped logger.
func ContextWithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// LoggerFromContext returns the request scoped logger or the default one.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// ContextWithRequestID stores the inbound request identifier.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext returns the inbound request identifier.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// ContextWithTraceID stores the current trace identifier.
func ContextWithTraceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, traceIDKey, id)
}

// TraceIDFromContext returns the current trace identifier.
func TraceIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(traceIDKey).(string); ok {
		return v
	}
	return ""
}

var pseudonymSalt = []byte(func() string {
	if v := os.Getenv("TELEMETRY_PSEUDONYM_SALT"); v != "" {
		return v
	}
	return "moribox-telemetry-pseudonym"
}())

// Pseudonym maps a user identifier to a stable, non-reversible telemetry
// label so that dashboards can correlate activity without carrying identity.
func Pseudonym(userID string) string {
	if userID == "" {
		return ""
	}
	mac := hmac.New(sha256.New, pseudonymSalt)
	mac.Write([]byte(userID))
	return "u_" + hex.EncodeToString(mac.Sum(nil))[:16]
}
