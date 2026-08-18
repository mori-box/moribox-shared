package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"github.com/mori-box/moribox-shared/ratelimit"
	"github.com/stretchr/testify/require"
)

// The behaviour under test is what happens when the counter store is gone.
// A limiter with neither a cache nor a database cannot count, so every call
// takes the failure path — which is exactly the state a deployment is in when
// its fast counter store is lost, and the state an attacker would try to
// create deliberately.

func TestFailClosedRefusesWhenNoCounterStoreIsReachable(t *testing.T) {
	limiter := ratelimit.New(nil, nil, true)

	decision, err := limiter.Allow(context.Background(), "POST /v1/box-openings",
		[]ratelimit.Key{{Dimension: ratelimit.DimUser, Value: "user-1"}},
		[]ratelimit.Rule{{Dimension: ratelimit.DimUser, Limit: 12, Window: time.Minute}})

	require.ErrorIs(t, err, ratelimit.ErrFailClosed)
	require.False(t, decision.Allowed,
		"an uncountable request must be refused, not admitted")
	require.Equal(t, ratelimit.DimUser, decision.Dimension)
	require.Equal(t, time.Second, decision.RetryAfter,
		"a refused caller needs a retry hint or it will spin")
}

// TestFailOpenAdmitsWhenNoCounterStoreIsReachable is the read side of the same
// decision: read traffic keeps working while the cache is down, because
// refusing it would turn a cache outage into a full outage.
func TestFailOpenAdmitsWhenNoCounterStoreIsReachable(t *testing.T) {
	limiter := ratelimit.New(nil, nil, false)

	decision, err := limiter.Allow(context.Background(), "GET /v1/campaigns/{id}/prizes",
		[]ratelimit.Key{{Dimension: ratelimit.DimIP, Value: "203.0.113.9"}},
		[]ratelimit.Rule{{Dimension: ratelimit.DimIP, Limit: 240, Window: time.Minute}})

	require.NoError(t, err)
	require.True(t, decision.Allowed)
}

// TestFailClosedNamesTheDimensionItCouldNotCount matters for the response: the
// caller is told which axis stopped them, and a rule with no key is skipped
// before the store is consulted at all.
func TestFailClosedNamesTheDimensionItCouldNotCount(t *testing.T) {
	limiter := ratelimit.New(nil, nil, true)

	decision, err := limiter.Allow(context.Background(), "POST /v1/box-openings",
		// No user key is supplied, so the user rule cannot apply.
		[]ratelimit.Key{{Dimension: ratelimit.DimDevice, Value: "device-1"}},
		[]ratelimit.Rule{
			{Dimension: ratelimit.DimUser, Limit: 12, Window: time.Minute},
			{Dimension: ratelimit.DimDevice, Limit: 20, Window: time.Minute},
		})

	require.ErrorIs(t, err, ratelimit.ErrFailClosed)
	require.Equal(t, ratelimit.DimDevice, decision.Dimension,
		"the reported dimension must be the one that was actually evaluated")
}

// TestRuleWithoutAKeyIsSkippedEntirely proves the skip happens before the
// counter store is touched. If it did not, an anonymous request would fail
// closed on a user rule it can never satisfy, and the endpoint would be dead.
func TestRuleWithoutAKeyIsSkippedEntirely(t *testing.T) {
	limiter := ratelimit.New(nil, nil, true)

	decision, err := limiter.Allow(context.Background(), "POST /v1/referrals/resolve",
		[]ratelimit.Key{{Dimension: ratelimit.DimIP, Value: "203.0.113.9"}},
		[]ratelimit.Rule{{Dimension: ratelimit.DimUser, Limit: 12, Window: time.Minute}})

	require.NoError(t, err, "a rule with no key must not reach the counter store")
	require.True(t, decision.Allowed)
}

// TestEmptyKeyValueIsTreatedAsAbsent stops a blank header from becoming a
// shared bucket that every anonymous caller counts against.
func TestEmptyKeyValueIsTreatedAsAbsent(t *testing.T) {
	limiter := ratelimit.New(nil, nil, true)

	decision, err := limiter.Allow(context.Background(), "POST /v1/box-openings",
		[]ratelimit.Key{{Dimension: ratelimit.DimUser, Value: ""}},
		[]ratelimit.Rule{{Dimension: ratelimit.DimUser, Limit: 12, Window: time.Minute}})

	require.NoError(t, err)
	require.True(t, decision.Allowed)
}

func TestNoRulesMeansNoLimit(t *testing.T) {
	limiter := ratelimit.New(nil, nil, true)

	decision, err := limiter.Allow(context.Background(), "GET /v1/faq",
		[]ratelimit.Key{{Dimension: ratelimit.DimIP, Value: "203.0.113.9"}}, nil)

	require.NoError(t, err)
	require.True(t, decision.Allowed)
}
