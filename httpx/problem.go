// Package httpx contains the shared HTTP surface: problem+json errors,
// middleware, request decoding and response helpers.
package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/mori-box/moribox-shared/observability"
)

// ProblemContentType is the media type used for every error response.
const ProblemContentType = "application/problem+json"

// ProblemTypeBaseURL, when non-empty, is prepended to a problem's Code to form
// its RFC 9457 "type" member, e.g. "https://docs.example.com/errors/" +
// "NOT_FOUND". A deployment that documents its error codes at a stable URL
// sets this once during startup; left empty, Type is just the bare Code.
var ProblemTypeBaseURL string

// Problem is an RFC 9457 problem detail document extended with the fields
// clients rely on.
type Problem struct {
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	Status    int            `json:"status"`
	Detail    string         `json:"detail,omitempty"`
	Instance  string         `json:"instance,omitempty"`
	Code      string         `json:"code"`
	RequestID string         `json:"request_id,omitempty"`
	TraceID   string         `json:"trace_id,omitempty"`
	Errors    []FieldError   `json:"errors,omitempty"`
	Extra     map[string]any `json:"extra,omitempty"`
}

// FieldError describes one validation failure.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error codes generic enough to apply to any HTTP API. A deployment adds its
// own domain codes as plain string constants; APIError.Code accepts any
// string, so nothing here needs to know them.
const (
	CodeValidationFailed       = "VALIDATION_FAILED"
	CodeUnauthenticated        = "UNAUTHENTICATED"
	CodeForbidden              = "FORBIDDEN"
	CodeNotFound               = "NOT_FOUND"
	CodeConflict               = "CONFLICT"
	CodeIdempotencyConflict    = "IDEMPOTENCY_CONFLICT"
	CodeRequestInProgress      = "REQUEST_IN_PROGRESS"
	CodeIdempotencyKeyRequired = "IDEMPOTENCY_KEY_REQUIRED"
	CodeRateLimited            = "RATE_LIMITED"
	CodeProviderUnavailable    = "PROVIDER_UNAVAILABLE"
	CodeInternal               = "INTERNAL_ERROR"
	CodePayloadTooLarge        = "PAYLOAD_TOO_LARGE"
	CodeUnsupportedMedia       = "UNSUPPORTED_MEDIA_TYPE"
	CodeStepUpRequired         = "STEP_UP_REQUIRED"
	CodeSignatureInvalid       = "SIGNATURE_INVALID"
	CodeStateConflict          = "STATE_CONFLICT"
	CodeServiceUnavailable     = "SERVICE_UNAVAILABLE"
	CodeTimeout                = "REQUEST_TIMEOUT"
)

// APIError is a domain error that carries an HTTP representation.
type APIError struct {
	Status  int
	Code    string
	Title   string
	Detail  string
	Fields  []FieldError
	Extra   map[string]any
	Headers map[string]string
	cause   error
}

// Error implements error.
func (e *APIError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Detail, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

// Unwrap exposes the underlying cause for errors.Is and errors.As.
func (e *APIError) Unwrap() error { return e.cause }

// WithCause attaches an internal cause that is logged but never serialised.
func (e *APIError) WithCause(err error) *APIError {
	clone := *e
	clone.cause = err
	return &clone
}

// WithExtra attaches machine readable context to the problem document.
func (e *APIError) WithExtra(key string, value any) *APIError {
	clone := *e
	clone.Extra = map[string]any{}
	for k, v := range e.Extra {
		clone.Extra[k] = v
	}
	clone.Extra[key] = value
	return &clone
}

// WithFields attaches per field messages to a problem that was not built by
// ErrValidation. They are serialised as the problem document's "errors" array,
// which is what tells a caller which entry of a batch was refused.
func (e *APIError) WithFields(fields ...FieldError) *APIError {
	clone := *e
	clone.Fields = append(append([]FieldError(nil), e.Fields...), fields...)
	return &clone
}

// WithHeader adds a response header, for example Retry-After.
func (e *APIError) WithHeader(key, value string) *APIError {
	clone := *e
	clone.Headers = map[string]string{}
	for k, v := range e.Headers {
		clone.Headers[k] = v
	}
	clone.Headers[key] = value
	return &clone
}

// WithDetail overrides the human readable detail.
func (e *APIError) WithDetail(detail string) *APIError {
	clone := *e
	clone.Detail = detail
	return &clone
}

// New builds an APIError.
func New(status int, code, title, detail string) *APIError {
	return &APIError{Status: status, Code: code, Title: title, Detail: detail}
}

// Common constructors.
func ErrValidation(detail string, fields ...FieldError) *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: CodeValidationFailed, Title: "Validation failed", Detail: detail, Fields: fields}
}

func ErrUnauthenticated(detail string) *APIError {
	return New(http.StatusUnauthorized, CodeUnauthenticated, "Authentication required", detail)
}

func ErrForbidden(detail string) *APIError {
	return New(http.StatusForbidden, CodeForbidden, "Forbidden", detail)
}

func ErrNotFound(detail string) *APIError {
	return New(http.StatusNotFound, CodeNotFound, "Not found", detail)
}

func ErrConflict(code, detail string) *APIError {
	return New(http.StatusConflict, code, "Conflict", detail)
}

func ErrUnprocessable(code, detail string) *APIError {
	return New(http.StatusUnprocessableEntity, code, "Unprocessable request", detail)
}

func ErrRateLimited(retryAfterSeconds int) *APIError {
	return New(http.StatusTooManyRequests, CodeRateLimited, "Rate limited", "too many requests").
		WithHeader("Retry-After", strconv.Itoa(retryAfterSeconds))
}

func ErrProviderUnavailable(detail string) *APIError {
	return New(http.StatusServiceUnavailable, CodeProviderUnavailable, "Provider unavailable", detail)
}

func ErrInternal(cause error) *APIError {
	return (&APIError{
		Status: http.StatusInternalServerError,
		Code:   CodeInternal,
		Title:  "Internal server error",
		Detail: "the request could not be completed",
	}).WithCause(cause)
}

// AsAPIError converts any error into an APIError, defaulting to 500.
func AsAPIError(err error) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return ErrInternal(err)
}

// WriteProblem serialises an error as application/problem+json.
func WriteProblem(w http.ResponseWriter, r *http.Request, err error) {
	apiErr := AsAPIError(err)
	ctx := r.Context()

	if apiErr.Status >= http.StatusInternalServerError {
		observability.LoggerFromContext(ctx).Error("request failed",
			"code", apiErr.Code,
			"status", apiErr.Status,
			"error", apiErr.Error(),
			"path", r.URL.Path,
		)
	} else {
		observability.LoggerFromContext(ctx).Info("request rejected",
			"code", apiErr.Code,
			"status", apiErr.Status,
			"detail", apiErr.Detail,
			"path", r.URL.Path,
		)
	}

	problem := Problem{
		Type:      ProblemTypeBaseURL + apiErr.Code,
		Title:     apiErr.Title,
		Status:    apiErr.Status,
		Detail:    apiErr.Detail,
		Instance:  r.URL.Path,
		Code:      apiErr.Code,
		RequestID: observability.RequestIDFromContext(ctx),
		TraceID:   observability.TraceIDFromContext(ctx),
		Errors:    apiErr.Fields,
		Extra:     apiErr.Extra,
	}

	for k, v := range apiErr.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", ProblemContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(apiErr.Status)
	_ = json.NewEncoder(w).Encode(problem)
}
