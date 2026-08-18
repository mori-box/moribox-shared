package secrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/mori-box/moribox-shared/oci"
	"github.com/oracle/oci-go-sdk/v65/common"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
)

// OCIProvider resolves OCI Vault secrets.
//
// A reference is one of three things, and which one it is can be told from the
// value alone:
//
//   - "env:NAME" — the development escape hatch, handled by EnvProvider. It
//     works here for the same reason it works on the AWS provider: a single
//     process can be pointed at a real vault for one credential and at the
//     environment for another while a migration is in progress.
//   - an OCID beginning "ocid1.vaultsecret" — read directly, no vault needed.
//   - anything else — treated as a secret *name*, which OCI can only resolve
//     within a vault, so OCI_VAULT_OCID must be configured.
//
// The AWS provider has no third case because a Secrets Manager name is resolved
// account-wide. Requiring the vault for a name is the one place where an OCI
// deployment needs a configuration value that an AWS one does not.
type OCIProvider struct {
	client    ocisecrets.SecretsClient
	vaultOCID string
	cache     *ttlCache
}

// NewOCIProvider builds an OCI Vault Secrets backed provider.
//
// endpoint overrides the regional secret retrieval endpoint. It is the same knob
// SECRETS_ENDPOINT already is for the AWS provider, and it exists for the same
// two reasons: a private service endpoint, and a test that needs a stand-in.
func NewOCIProvider(principal *oci.Principal, vaultOCID, endpoint string, ttl time.Duration) (*OCIProvider, error) {
	if principal == nil {
		return nil, oci.ErrNoPrincipal
	}
	client, err := ocisecrets.NewSecretsClientWithConfigurationProvider(principal.Provider)
	if err != nil {
		return nil, fmt.Errorf("oci vault secrets client: %w", err)
	}
	client.SetRegion(principal.Region)
	if endpoint != "" {
		client.Host = endpoint
	}
	client.SetCustomClientConfiguration(oci.ClientConfiguration())
	return &OCIProvider{client: client, vaultOCID: vaultOCID, cache: newTTLCache(ttl)}, nil
}

// IsSecretOCID reports whether a reference is an OCI Vault secret OCID.
func IsSecretOCID(reference string) bool {
	return strings.HasPrefix(reference, "ocid1.vaultsecret")
}

// Get implements Provider.
func (p *OCIProvider) Get(ctx context.Context, reference string) (string, error) {
	if strings.HasPrefix(reference, "env:") {
		return EnvProvider{}.Get(ctx, reference)
	}
	if value, ok := p.cache.get(reference); ok {
		return value, nil
	}

	var bundle ocisecrets.SecretBundle
	if IsSecretOCID(reference) {
		out, err := p.client.GetSecretBundle(ctx, ocisecrets.GetSecretBundleRequest{
			SecretId: common.String(reference),
			Stage:    ocisecrets.GetSecretBundleStageCurrent,
		})
		if err != nil {
			return "", fmt.Errorf("get secret bundle: %w", err)
		}
		bundle = out.SecretBundle
	} else {
		if p.vaultOCID == "" {
			return "", fmt.Errorf(
				"%w: %s is a secret name and OCI_VAULT_OCID is not configured", ErrNotFound, reference)
		}
		out, err := p.client.GetSecretBundleByName(ctx, ocisecrets.GetSecretBundleByNameRequest{
			SecretName: common.String(reference),
			VaultId:    common.String(p.vaultOCID),
			Stage:      ocisecrets.GetSecretBundleByNameStageCurrent,
		})
		if err != nil {
			return "", fmt.Errorf("get secret bundle by name: %w", err)
		}
		bundle = out.SecretBundle
	}

	value, err := secretValue(bundle)
	if err != nil {
		return "", fmt.Errorf("%s: %w", reference, err)
	}
	if value == "" {
		return "", fmt.Errorf("%w: %s", ErrNotFound, reference)
	}
	p.cache.put(reference, value)
	return value, nil
}

// secretValue decodes the one content representation OCI Vault offers.
//
// The content is always base64, including for a plain string secret, so a
// deployment that stores a DSN gets the DSN back and not its encoding. An
// unrecognised content type is an error rather than an empty string: returning
// "" here would surface as "the DSN is not valid", which sends the reader to
// entirely the wrong place.
func secretValue(bundle ocisecrets.SecretBundle) (string, error) {
	switch content := bundle.SecretBundleContent.(type) {
	case ocisecrets.Base64SecretBundleContentDetails:
		if content.Content == nil {
			return "", nil
		}
		decoded, err := base64.StdEncoding.DecodeString(*content.Content)
		if err != nil {
			return "", fmt.Errorf("secret content is not valid base64: %w", err)
		}
		return string(decoded), nil
	case nil:
		return "", nil
	default:
		return "", fmt.Errorf("unsupported OCI secret content type %T", bundle.SecretBundleContent)
	}
}
