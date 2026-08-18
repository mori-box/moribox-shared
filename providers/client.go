// Package providers contains the shared outbound HTTP machinery: a hardened
// client, OAuth2 client credentials with mTLS, a circuit breaker, a rate limiter
// and the signed callback verifier.
//
// Base URLs come from validated configuration only. An admin request can never
// choose a destination, which removes the server side request forgery surface.
package providers

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mori-box/moribox-shared/observability"
	"golang.org/x/time/rate"
)

// Errors returned by the outbound client.
var (
	ErrCircuitOpen = errors.New("provider circuit is open")
	ErrTimeout     = errors.New("provider call timed out")
)

// Endpoint describes one outbound provider integration.
type Endpoint struct {
	BaseURL          string
	OAuthTokenURL    string
	OAuthClientID    string
	ClientSecretARN  string
	MTLSCertARN      string
	MTLSKeyARN       string
	CACertPEMPath    string
	Timeout          time.Duration
	MaxRetries       int
	CallbackAudience string
	CallbackJWKSURL  string
	// SharedCallbackSecret verifies detached signatures when the provider
	// cannot publish a JWKS document.
	SharedCallbackSecret string
	CircuitThreshold     int
	CircuitWindow        time.Duration
	CircuitCooldown      time.Duration
	RateLimitPerSecond   int
	Insecure             bool
}

// DefaultUserAgent is sent when Options.UserAgent is empty.
const DefaultUserAgent = "moribox/1.0"

// Client is a configured outbound provider client.
type Client struct {
	name      string
	baseURL   *url.URL
	http      *http.Client
	tokens    *TokenSource
	breaker   *CircuitBreaker
	limiter   *rate.Limiter
	timeout   time.Duration
	maxRetry  int
	userAgent string
}

// Options configures a provider client.
type Options struct {
	Name         string
	Endpoint     Endpoint
	ClientSecret string
	MTLSCert     []byte
	MTLSKey      []byte
	CACert       []byte
	// UserAgent overrides DefaultUserAgent.
	UserAgent string
}

// New builds a provider client with mTLS, OAuth2 and a circuit breaker.
func New(opts Options) (*Client, error) {
	base, err := url.Parse(opts.Endpoint.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("%s base URL: %w", opts.Name, err)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("%s base URL has no host", opts.Name)
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(opts.MTLSCert) > 0 && len(opts.MTLSKey) > 0 {
		cert, cerr := tls.X509KeyPair(opts.MTLSCert, opts.MTLSKey)
		if cerr != nil {
			return nil, fmt.Errorf("%s mTLS key pair: %w", opts.Name, cerr)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if len(opts.CACert) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(opts.CACert) {
			return nil, fmt.Errorf("%s CA bundle could not be parsed", opts.Name)
		}
		tlsConfig.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: true,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   opts.Endpoint.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// A redirect could move the call to an unvalidated host.
			return http.ErrUseLastResponse
		},
	}

	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}

	c := &Client{
		name:      opts.Name,
		baseURL:   base,
		http:      httpClient,
		timeout:   opts.Endpoint.Timeout,
		maxRetry:  opts.Endpoint.MaxRetries,
		userAgent: userAgent,
		breaker: NewCircuitBreaker(opts.Name, opts.Endpoint.CircuitThreshold,
			opts.Endpoint.CircuitWindow, opts.Endpoint.CircuitCooldown),
		limiter: rate.NewLimiter(rate.Limit(opts.Endpoint.RateLimitPerSecond), opts.Endpoint.RateLimitPerSecond),
	}
	if opts.Endpoint.OAuthTokenURL != "" {
		c.tokens = NewTokenSource(httpClient, opts.Endpoint.OAuthTokenURL,
			opts.Endpoint.OAuthClientID, opts.ClientSecret, opts.Endpoint.CallbackAudience)
	}
	return c, nil
}

// Request is one outbound provider call.
type Request struct {
	Operation      string
	Method         string
	Path           string
	Body           any
	IdempotencyKey string
	RequestID      string
	Query          url.Values
}

// Response is the raw provider answer.
type Response struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
	RetryAfter time.Duration
}

// Do performs a provider call through the circuit breaker and rate limiter.
//
// The response body is returned to the caller for typed decoding but is never
// logged: payment and licence bodies are on the prohibited telemetry list.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	if !c.breaker.Allow() {
		observability.ProviderRequestsTotal.WithLabelValues(c.name, req.Operation, "circuit_open").Inc()
		return nil, ErrCircuitOpen
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	endpoint := *c.baseURL
	endpoint.Path = strings.TrimSuffix(c.baseURL.Path, "/") + req.Path
	if len(req.Query) > 0 {
		endpoint.RawQuery = req.Query.Encode()
	}

	var body io.Reader
	if req.Body != nil {
		encoded, err := json.Marshal(req.Body)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}

	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, req.Method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/json")
	if req.Body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if req.IdempotencyKey != "" {
		httpReq.Header.Set("Idempotency-Key", req.IdempotencyKey)
	}
	if req.RequestID != "" {
		httpReq.Header.Set("X-Request-Id", req.RequestID)
	}
	httpReq.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	httpReq.Header.Set("User-Agent", c.userAgent)

	if c.tokens != nil {
		token, terr := c.tokens.Token(callCtx)
		if terr != nil {
			c.breaker.RecordFailure()
			return nil, fmt.Errorf("%s token: %w", c.name, terr)
		}
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	start := time.Now()
	resp, err := c.http.Do(httpReq)
	elapsed := time.Since(start)
	observability.ProviderRequestDuration.WithLabelValues(c.name, req.Operation).Observe(elapsed.Seconds())

	if err != nil {
		c.breaker.RecordFailure()
		observability.ProviderRequestsTotal.WithLabelValues(c.name, req.Operation, "transport_error").Inc()
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %s %s", ErrTimeout, req.Method, req.Path)
		}
		return nil, err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.breaker.RecordFailure()
		return nil, err
	}

	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		c.breaker.RecordFailure()
	} else {
		c.breaker.RecordSuccess()
	}
	observability.ProviderRequestsTotal.WithLabelValues(c.name, req.Operation,
		strconv.Itoa(resp.StatusCode/100)+"xx").Inc()

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       payload,
		Headers:    resp.Header,
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}, nil
}

func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}

// Name returns the provider identifier used in telemetry.
func (c *Client) Name() string { return c.name }

// Healthy reports whether the circuit is closed.
func (c *Client) Healthy() bool { return c.breaker.State() != CircuitOpen }

// CircuitState exposes the breaker state for the providers dashboard.
func (c *Client) CircuitState() string { return string(c.breaker.State()) }

// TokenSource caches an OAuth2 client credentials token.
type TokenSource struct {
	http     *http.Client
	tokenURL string
	clientID string
	secret   string
	audience string

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewTokenSource builds a client credentials token source.
func NewTokenSource(client *http.Client, tokenURL, clientID, secret, audience string) *TokenSource {
	return &TokenSource{http: client, tokenURL: tokenURL, clientID: clientID, secret: secret, audience: audience}
}

// Token returns a cached or freshly minted access token.
func (t *TokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Refresh a minute early so that a token never expires mid-flight.
	if t.token != "" && time.Now().Before(t.expiresAt.Add(-time.Minute)) {
		return t.token, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", t.clientID)
	form.Set("client_secret", t.secret)
	if t.audience != "" {
		form.Set("audience", t.audience)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		return "", errors.New("token endpoint returned no access token")
	}
	expiresIn := payload.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300
	}
	t.token = payload.AccessToken
	t.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return t.token, nil
}
