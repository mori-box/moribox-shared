package idempotency_test

import (
	"testing"

	"github.com/mori-box/moribox-shared/idempotency"
	"github.com/stretchr/testify/require"
)

// TestRequestHashIgnoresInsignificantFormatting is what makes the conflict rule
// usable: a client that reorders JSON keys or reformats whitespace is replaying
// the same request, not a different one.
func TestRequestHashIgnoresInsignificantFormatting(t *testing.T) {
	const (
		scope = "user:01J8ZC3K9T7QX2M4N6P8R0S2TV"
		route = "POST /v1/box-openings"
	)
	a, err := idempotency.RequestHash(scope, route,
		[]byte(`{"campaign_id":"01J","source":"PAID","price_version":1}`))
	require.NoError(t, err)

	b, err := idempotency.RequestHash(scope, route,
		[]byte("{\n  \"price_version\": 1,\n  \"source\": \"PAID\",\n  \"campaign_id\": \"01J\"\n}"))
	require.NoError(t, err)

	require.Equal(t, a, b, "key order and whitespace must not change the digest")
}

// TestRequestHashDetectsRealChanges is the other half: any semantic difference
// must be caught so the same key with a different body returns 409.
func TestRequestHashDetectsRealChanges(t *testing.T) {
	const (
		scope = "user:01J"
		route = "POST /v1/box-openings"
	)
	base, err := idempotency.RequestHash(scope, route, []byte(`{"amount":"30.00"}`))
	require.NoError(t, err)

	for _, variant := range []string{
		`{"amount":"30.01"}`,
		`{"amount":"30.0"}`,
		`{"amount":30.00}`,
		`{"amount":"30.00","extra":true}`,
		`{}`,
	} {
		other, err := idempotency.RequestHash(scope, route, []byte(variant))
		require.NoError(t, err)
		require.NotEqual(t, base, other, "variant %s must hash differently", variant)
	}
}

// TestRequestHashIsScopedPerActorAndRoute stops one caller's key from colliding
// with another's, and the same key from being reused across endpoints.
func TestRequestHashIsScopedPerActorAndRoute(t *testing.T) {
	body := []byte(`{"campaign_id":"01J"}`)

	alice, err := idempotency.RequestHash("user:alice", "POST /v1/box-openings", body)
	require.NoError(t, err)
	bob, err := idempotency.RequestHash("user:bob", "POST /v1/box-openings", body)
	require.NoError(t, err)
	other, err := idempotency.RequestHash("user:alice", "POST /v1/me/fragments/redemptions", body)
	require.NoError(t, err)

	require.NotEqual(t, alice, bob)
	require.NotEqual(t, alice, other)
}

func TestRequestHashHandlesNestedStructures(t *testing.T) {
	a, err := idempotency.RequestHash("s", "r",
		[]byte(`{"contact":{"city":"Almaty","full_name":"A"},"choice":"PHYSICAL"}`))
	require.NoError(t, err)
	b, err := idempotency.RequestHash("s", "r",
		[]byte(`{"choice":"PHYSICAL","contact":{"full_name":"A","city":"Almaty"}}`))
	require.NoError(t, err)
	require.Equal(t, a, b)

	// Array order is significant, because it carries meaning.
	c, err := idempotency.RequestHash("s", "r", []byte(`{"items":[1,2]}`))
	require.NoError(t, err)
	d, err := idempotency.RequestHash("s", "r", []byte(`{"items":[2,1]}`))
	require.NoError(t, err)
	require.NotEqual(t, c, d)
}

func TestRequestHashHandlesEmptyAndNonJSONBodies(t *testing.T) {
	empty, err := idempotency.RequestHash("s", "POST /v1/box-openings/{id}/reveal", nil)
	require.NoError(t, err)
	require.Len(t, empty, 64)

	sameEmpty, err := idempotency.RequestHash("s", "POST /v1/box-openings/{id}/reveal", []byte("  "))
	require.NoError(t, err)
	require.Equal(t, empty, sameEmpty)

	// A body that is not JSON is hashed verbatim rather than rejected here; the
	// handler's decoder is what refuses it.
	raw, err := idempotency.RequestHash("s", "r", []byte("not json"))
	require.NoError(t, err)
	require.Len(t, raw, 64)
}
