// Package secrets resolves credentials from AWS Secrets Manager, from OCI Vault
// Secrets, or — for local development and tests only — from the process
// environment.
//
// Credentials never appear in container images, Helm values or plain
// environment variables in staging and production: only the reference does, an
// ARN or an OCID. Configuration validation refuses the environment provider
// outside development for that reason.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/mori-box/moribox-shared/oci"
)

// Secret source selectors.
const (
	ProviderAWS      = "aws"
	ProviderOCIVault = "oci-vault"
	ProviderEnv      = "env"
)

// Config selects the secret source.
type Config struct {
	Provider string // aws | oci-vault | env
	Region   string
	Endpoint string
	// VaultOCID is required only to resolve a reference given as a secret
	// *name*; a reference given as a secret OCID needs no vault.
	VaultOCID string
}

// ErrNotFound is returned when a reference cannot be resolved.
var ErrNotFound = errors.New("secret not found")

// Provider resolves a secret reference to its value.
type Provider interface {
	Get(ctx context.Context, reference string) (string, error)
}

// EnvProvider resolves references of the form "env:NAME" or a bare name.
type EnvProvider struct{}

// Get implements Provider.
func (EnvProvider) Get(_ context.Context, reference string) (string, error) {
	name := strings.TrimPrefix(reference, "env:")
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%w: %s", ErrNotFound, name)
}

// ttlCache holds resolved secrets for a short while so that a rotation is picked
// up without a restart and a hot path does not call the secret store on every
// request. It is shared by every remote provider.
type ttlCache struct {
	ttl time.Duration

	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

func newTTLCache(ttl time.Duration) *ttlCache {
	return &ttlCache{ttl: ttl, entries: map[string]cacheEntry{}}
}

func (c *ttlCache) get(key string) (string, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.value, true
	}
	return "", false
}

func (c *ttlCache) put(key, value string) {
	c.mu.Lock()
	c.entries[key] = cacheEntry{value: value, expiresAt: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

// AWSProvider resolves Secrets Manager ARNs.
type AWSProvider struct {
	client *secretsmanager.Client
	cache  *ttlCache
}

// NewAWSProvider builds a Secrets Manager backed provider.
func NewAWSProvider(client *secretsmanager.Client, ttl time.Duration) *AWSProvider {
	return &AWSProvider{client: client, cache: newTTLCache(ttl)}
}

// Get implements Provider.
func (p *AWSProvider) Get(ctx context.Context, reference string) (string, error) {
	if strings.HasPrefix(reference, "env:") {
		return EnvProvider{}.Get(ctx, reference)
	}
	if value, ok := p.cache.get(reference); ok {
		return value, nil
	}

	out, err := p.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(reference),
	})
	if err != nil {
		return "", fmt.Errorf("get secret: %w", err)
	}
	value := aws.ToString(out.SecretString)
	if value == "" && len(out.SecretBinary) > 0 {
		value = string(out.SecretBinary)
	}
	if value == "" {
		return "", fmt.Errorf("%w: %s", ErrNotFound, reference)
	}

	p.cache.put(reference, value)
	return value, nil
}

// Option configures provider construction.
type Option func(*options)

type options struct {
	principal *oci.Principal
}

// WithOCI supplies the resolved OCI identity. It is required when the provider
// is oci-vault and ignored otherwise.
func WithOCI(p *oci.Principal) Option {
	return func(o *options) { o.principal = p }
}

// New builds the provider selected by configuration.
//
// It returns an error only for a provider it cannot construct. The environment
// provider is the fallback for an unrecognised name in the same way it was
// before, but configuration validation now rejects an unrecognised name at
// startup, so that fallback is unreachable in practice.
func New(cfg Config, awsCfg aws.Config, opts ...Option) (Provider, error) {
	var o options
	for _, apply := range opts {
		apply(&o)
	}
	switch cfg.Provider {
	case ProviderAWS:
		smOpts := func(s *secretsmanager.Options) {
			if cfg.Endpoint != "" {
				s.BaseEndpoint = aws.String(cfg.Endpoint)
			}
		}
		return NewAWSProvider(secretsmanager.NewFromConfig(awsCfg, smOpts), 5*time.Minute), nil
	case ProviderOCIVault:
		return NewOCIProvider(o.principal, cfg.VaultOCID, cfg.Endpoint, 5*time.Minute)
	default:
		return EnvProvider{}, nil
	}
}

// Resolve returns the secret behind reference, or fallback when the reference
// is empty. It exists so that a process can accept either an inline development
// value or a production ARN without branching at every call site.
func Resolve(ctx context.Context, p Provider, reference, fallback string) (string, error) {
	if reference == "" {
		if fallback == "" {
			return "", fmt.Errorf("%w: no reference and no fallback", ErrNotFound)
		}
		return fallback, nil
	}
	return p.Get(ctx, reference)
}
