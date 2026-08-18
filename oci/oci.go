// Package oci resolves how a process proves its identity to Oracle Cloud
// Infrastructure, and shares that one identity across every OCI backed adapter:
// the queue, the key wrapper and the secret store.
//
// It is deliberately the only place in the tree that knows about OCI
// credentials. A workload in OKE presents a service account token and gets a
// short lived security token back; a compute instance presents its instance
// certificate; a developer's machine falls back to ~/.oci/config. Which of those
// happened is recorded on the returned Principal and logged during startup,
// because "the process could not read the secret" and "the process is not who it
// thinks it is" look identical from the call site and are diagnosed completely
// differently.
package oci

import (
	"errors"
	"fmt"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
)

// Authentication methods. workload is what a pod in OKE uses; instance is what
// a compute instance uses; config_file and env are the local fallbacks.
const (
	AuthAuto       = "auto"
	AuthWorkload   = "workload"
	AuthInstance   = "instance"
	AuthConfigFile = "config_file"
	AuthEnv        = "env"
)

// Config holds the settings every OCI backed adapter shares: how the process
// proves who it is, and where.
type Config struct {
	// AuthMethod is auto | workload | instance | config_file | env.
	//
	// It defaults to workload in staging and production, which is how a pod in
	// OKE authenticates, and to config_file elsewhere, which is the explicit
	// fallback for a developer's machine. It is never defaulted to auto,
	// because auto probes the instance metadata service and a probe that has to
	// time out is a bad thing to inflict on a local run by default.
	AuthMethod string
	Region     string
	ConfigFile string
	Profile    string
}

// ErrNoPrincipal is returned by an adapter that was asked for an OCI backed
// implementation without a resolved principal to sign its requests. It is a
// wiring mistake rather than a runtime condition, so it fails at construction.
var ErrNoPrincipal = errors.New("no OCI principal was resolved; an OCI backed adapter cannot be built")

// Principal is a resolved OCI identity together with how it was obtained.
type Principal struct {
	// Provider signs every request made by an OCI client built from it.
	Provider common.ConfigurationProvider
	// Method is the Auth* value that produced Provider. When
	// OCI_AUTH_METHOD is auto this is the method that actually succeeded, not
	// the one that was asked for.
	Method string
	// Region is the region the clients will talk to.
	Region string
}

// String renders the principal for a log line. It names the method and the
// region and nothing else: a configuration provider holds a private key.
func (p *Principal) String() string {
	if p == nil {
		return "oci principal: none"
	}
	return fmt.Sprintf("oci principal: method=%s region=%s", p.Method, p.Region)
}

// ClientConfiguration is the retry behaviour every OCI client in this tree uses.
//
// The SDK's own default is eight attempts with exponential backoff, up to about
// a minute and a half of sleeping inside one call. That is wrong for every caller
// here: a polling loop retries on its own short interval, a periodic scan comes
// round again in seconds, and each of those already
// retries at a layer that can be reasoned about. A call that sits in the SDK for
// a minute does not become more likely to succeed; it just stops the loop above
// it from making progress and hides the failure from the logs for that long.
//
// Three attempts a quarter of a second apart absorbs a genuine blip and gives up
// fast enough for the outer loop to be the thing that decides what happens next.
func ClientConfiguration() common.CustomClientConfiguration {
	policy := common.NewRetryPolicyWithOptions(
		common.ReplaceWithValuesFromRetryPolicy(common.DefaultRetryPolicyWithoutEventualConsistency()),
		common.WithMaximumNumberAttempts(3),
		common.WithFixedBackoff(250*time.Millisecond),
	)
	return common.CustomClientConfiguration{RetryPolicy: &policy}
}

// builder produces a configuration provider for one authentication method.
type builder func(Config) (common.ConfigurationProvider, error)

func builderFor(method string) (builder, error) {
	switch method {
	case AuthWorkload:
		return workload, nil
	case AuthInstance:
		return instance, nil
	case AuthConfigFile:
		return configFile, nil
	case AuthEnv:
		return environment, nil
	default:
		return nil, fmt.Errorf("OCI_AUTH_METHOD %q is not supported", method)
	}
}

// autoOrder is the sequence auto walks: the two methods a real workload uses,
// then the developer fallback.
var autoOrder = []string{AuthWorkload, AuthInstance, AuthConfigFile}

// Resolve builds the configuration provider selected by cfg.
//
// auto tries workload, then instance, then the config file, and reports which
// one worked. It is never the default: the instance attempt talks to the
// instance metadata service, and on a machine that has none that is a timeout
// rather than an immediate failure.
func Resolve(cfg Config) (*Principal, error) {
	method := cfg.AuthMethod
	if method == "" {
		method = AuthAuto
	}

	if method != AuthAuto {
		build, err := builderFor(method)
		if err != nil {
			return nil, err
		}
		provider, err := build(cfg)
		if err != nil {
			return nil, fmt.Errorf("oci %s authentication: %w", method, err)
		}
		return principalFor(cfg, method, provider)
	}

	var errs []error
	for _, candidate := range autoOrder {
		build, err := builderFor(candidate)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		provider, err := build(cfg)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", candidate, err))
			continue
		}
		p, err := principalFor(cfg, candidate, provider)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", candidate, err))
			continue
		}
		return p, nil
	}
	return nil, fmt.Errorf("no OCI authentication method succeeded: %w", errors.Join(errs...))
}

// principalFor applies the configured region override and reads the region back,
// so that a caller can log where the process is about to send its requests.
func principalFor(cfg Config, method string, provider common.ConfigurationProvider) (*Principal, error) {
	region := cfg.Region
	if region == "" {
		// A principal knows its own region, and so does a config file profile.
		// The override exists for the cases where neither is right.
		if r, err := provider.Region(); err == nil {
			region = r
		}
	}
	if region == "" {
		return nil, fmt.Errorf("oci %s authentication succeeded but no region is known; set OCI_REGION", method)
	}
	return &Principal{Provider: provider, Method: method, Region: region}, nil
}

func workload(Config) (common.ConfigurationProvider, error) {
	p, err := auth.OkeWorkloadIdentityConfigurationProvider()
	if err != nil {
		return nil, err
	}
	return p, nil
}

func instance(Config) (common.ConfigurationProvider, error) {
	return auth.InstancePrincipalConfigurationProvider()
}

func configFile(cfg Config) (common.ConfigurationProvider, error) {
	if cfg.ConfigFile == "" && cfg.Profile == "" {
		return common.DefaultConfigProvider(), nil
	}
	path := cfg.ConfigFile
	if path == "" {
		path = "~/.oci/config"
	}
	profile := cfg.Profile
	if profile == "" {
		profile = "DEFAULT"
	}
	return common.CustomProfileConfigProvider(path, profile), nil
}

func environment(Config) (common.ConfigurationProvider, error) {
	return common.ConfigurationProviderEnvironmentVariables("OCI", ""), nil
}
