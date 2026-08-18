package secrets_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mori-box/moribox-shared/oci"
	"github.com/mori-box/moribox-shared/secrets"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/stretchr/testify/require"
)

func testPrincipal(t *testing.T) *oci.Principal {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	provider := common.NewRawConfigurationProvider(
		"ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "eu-frankfurt-1",
		"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", string(pemBytes), nil)
	return &oci.Principal{Provider: provider, Method: oci.AuthConfigFile, Region: "eu-frankfurt-1"}
}

func TestNewSelectsTheConfiguredProvider(t *testing.T) {
	t.Run("env", func(t *testing.T) {
		p, err := secrets.New(secrets.Config{Provider: secrets.ProviderEnv}, aws.Config{})
		require.NoError(t, err)
		require.IsType(t, secrets.EnvProvider{}, p)
	})

	t.Run("aws", func(t *testing.T) {
		p, err := secrets.New(secrets.Config{Provider: secrets.ProviderAWS}, aws.Config{})
		require.NoError(t, err)
		require.IsType(t, &secrets.AWSProvider{}, p)
	})

	t.Run("oci-vault without a principal is a wiring error", func(t *testing.T) {
		_, err := secrets.New(secrets.Config{Provider: secrets.ProviderOCIVault}, aws.Config{})
		require.ErrorIs(t, err, oci.ErrNoPrincipal)
	})

	t.Run("oci-vault", func(t *testing.T) {
		p, err := secrets.New(secrets.Config{Provider: secrets.ProviderOCIVault}, aws.Config{},
			secrets.WithOCI(testPrincipal(t)))
		require.NoError(t, err)
		require.IsType(t, &secrets.OCIProvider{}, p)
	})
}

// TestOCISecretIsBase64Decoded matters because OCI returns every secret base64
// encoded, including a plain string. A provider that returned the encoded form
// would surface as "the database DSN is not valid", which points a reader at
// entirely the wrong thing.
func TestOCISecretIsBase64Decoded(t *testing.T) {
	const dsn = "moribox:pw@tcp(mysql:3306)/moribox?parseTime=true"

	var requestedPath, requestedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath, requestedQuery = r.URL.Path, r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secretId":"ocid1.vaultsecret.oc1..dsn","versionNumber":3,
			"secretBundleContent":{"contentType":"BASE64","content":"` +
			base64.StdEncoding.EncodeToString([]byte(dsn)) + `"}}`))
	}))
	defer server.Close()

	provider, err := secrets.NewOCIProvider(testPrincipal(t), "", server.URL, time.Minute)
	require.NoError(t, err)

	value, err := provider.Get(context.Background(), "ocid1.vaultsecret.oc1..dsn")
	require.NoError(t, err)
	require.Equal(t, dsn, value)
	require.Contains(t, requestedPath, "/secretbundles/ocid1.vaultsecret.oc1..dsn")
	require.Contains(t, requestedQuery, "stage=CURRENT")

	// The second read is served from the cache: the endpoint is not called again.
	requestedPath = ""
	value, err = provider.Get(context.Background(), "ocid1.vaultsecret.oc1..dsn")
	require.NoError(t, err)
	require.Equal(t, dsn, value)
	require.Empty(t, requestedPath, "a resolved secret is cached for its TTL")
}

// TestOCINameNeedsAVault records the one configuration value an OCI deployment
// needs that an AWS one does not: a secret *name* can only be resolved inside a
// vault. The error says which value is missing rather than reporting the secret
// as absent.
func TestOCINameNeedsAVault(t *testing.T) {
	provider, err := secrets.NewOCIProvider(testPrincipal(t), "", "", time.Minute)
	require.NoError(t, err)

	_, err = provider.Get(context.Background(), "moribox/mysql/dsn")
	require.ErrorIs(t, err, secrets.ErrNotFound)
	require.ErrorContains(t, err, "OCI_VAULT_OCID")
}

// TestOCIProviderStillHonoursTheEnvEscapeHatch keeps the AWS provider's behaviour:
// one process can read one credential from a vault and another from the
// environment while a migration is in progress.
func TestOCIProviderStillHonoursTheEnvEscapeHatch(t *testing.T) {
	t.Setenv("MORIBOX_TEST_SECRET", "value-from-env")
	provider, err := secrets.NewOCIProvider(testPrincipal(t), "ocid1.vault.oc1..v", "", time.Minute)
	require.NoError(t, err)

	value, err := provider.Get(context.Background(), "env:MORIBOX_TEST_SECRET")
	require.NoError(t, err)
	require.Equal(t, "value-from-env", value)
}

func TestIsSecretOCID(t *testing.T) {
	require.True(t, secrets.IsSecretOCID("ocid1.vaultsecret.oc1..abc"))
	require.False(t, secrets.IsSecretOCID("moribox/mysql/dsn"))
	require.False(t, secrets.IsSecretOCID("ocid1.vault.oc1..abc"),
		"a vault OCID is not a secret OCID")
}
