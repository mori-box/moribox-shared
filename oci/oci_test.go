package oci_test

import (
	"testing"

	"github.com/mori-box/moribox-shared/oci"
	"github.com/stretchr/testify/require"
)

func TestResolveRefusesAnUnknownMethod(t *testing.T) {
	_, err := oci.Resolve(oci.Config{AuthMethod: "iam-role"})
	require.ErrorContains(t, err, "OCI_AUTH_METHOD")
}

// TestResolveRefusesAPrincipalWithNoRegion keeps a half-configured process from
// starting. Every OCI client needs a region to build an endpoint from, and a
// client with no endpoint fails on its first call rather than at startup.
func TestResolveRefusesAPrincipalWithNoRegion(t *testing.T) {
	t.Setenv("OCI_TENANCY_OCID", "ocid1.tenancy.oc1..test")
	t.Setenv("OCI_USER_OCID", "ocid1.user.oc1..test")
	t.Setenv("OCI_REGION", "")

	_, err := oci.Resolve(oci.Config{AuthMethod: oci.AuthEnv})
	require.ErrorContains(t, err, "OCI_REGION")
}

// TestPrincipalStringNamesTheMethodAndNothingSecret guards the startup log line: a
// configuration provider holds a private key, so String must never render it.
func TestPrincipalStringNamesTheMethodAndNothingSecret(t *testing.T) {
	p := &oci.Principal{Method: oci.AuthWorkload, Region: "eu-frankfurt-1"}
	require.Equal(t, "oci principal: method=workload region=eu-frankfurt-1", p.String())

	var missing *oci.Principal
	require.Equal(t, "oci principal: none", missing.String())
}
