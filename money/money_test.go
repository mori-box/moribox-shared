package money_test

import (
	"encoding/json"
	"testing"

	"github.com/mori-box/moribox-shared/money"
	"github.com/stretchr/testify/require"
)

// TestAmountsNeverBecomeFloats is the property the whole money type exists for:
// a JSON number would silently lose precision on a value like 0.1, so amounts
// are transported as strings in both directions.
func TestAmountsNeverBecomeFloats(t *testing.T) {
	amount := money.MustFromString("30.00")
	encoded, err := json.Marshal(amount)
	require.NoError(t, err)
	require.Equal(t, `"30.00"`, string(encoded))

	var decoded money.Amount
	require.NoError(t, json.Unmarshal([]byte(`"30.00"`), &decoded))
	require.True(t, decoded.Equal(amount))

	// A numeric literal is rejected rather than silently accepted.
	require.Error(t, json.Unmarshal([]byte(`30.00`), &decoded))
}

func TestExactDecimalArithmetic(t *testing.T) {
	// The classic float failure: 0.1 + 0.2 must be exactly 0.3.
	sum := money.MustFromString("0.1").Add(money.MustFromString("0.2"))
	require.Equal(t, "0.3", sum.StringExact())
	require.True(t, sum.Equal(money.MustFromString("0.3")))

	// 32 600 000 MORI at the modelled rate, from the launch economy.
	value := money.MustFromString("0.0057").MulInt(32_600_000)
	require.Equal(t, "185820", value.StringExact())
	require.Equal(t, "185820.00", value.String())
}

func TestFromStringRejectsBadInput(t *testing.T) {
	for _, input := range []string{"", "  ", "abc", "1.2.3", "30,00", "1e5"} {
		_, err := money.FromString(input)
		require.ErrorIs(t, err, money.ErrInvalidAmount, "input %q", input)
	}
}

func TestFromStringRejectsExcessivePrecision(t *testing.T) {
	// Nine decimal places cannot be stored in DECIMAL(20,8) without silent
	// truncation, so it is refused at the boundary.
	_, err := money.FromString("1.000000001")
	require.ErrorIs(t, err, money.ErrInvalidAmount)

	_, err = money.FromString("1.00000001")
	require.NoError(t, err)
}

func TestValueUsesFullDatabaseScale(t *testing.T) {
	value, err := money.MustFromString("30.5").Value()
	require.NoError(t, err)
	require.Equal(t, "30.50000000", value)
}

func TestScanRoundTrip(t *testing.T) {
	var amount money.Amount
	require.NoError(t, amount.Scan([]byte("1234.56780000")))
	require.Equal(t, "1234.5678", amount.StringExact())

	require.NoError(t, amount.Scan(nil))
	require.True(t, amount.IsZero())

	require.Error(t, amount.Scan(12.5))
}

func TestAssetCodeValidation(t *testing.T) {
	code, err := money.ParseAsset(" usd ")
	require.NoError(t, err)
	require.Equal(t, money.AssetUSD, code)

	for _, bad := range []string{"", "us d", "US$", "TOOLONGASSETCODE!"} {
		_, err := money.ParseAsset(bad)
		require.ErrorIs(t, err, money.ErrInvalidAsset, "input %q", bad)
	}
}

func TestMoneyRefusesMixedAssets(t *testing.T) {
	usd := money.MustNew("10.00", "USD")
	usdt := money.MustNew("10.00", "USDT")

	_, err := usd.Add(usdt)
	require.ErrorIs(t, err, money.ErrAssetMismatch)

	sum, err := usd.Add(money.MustNew("5.50", "USD"))
	require.NoError(t, err)
	require.Equal(t, "15.50 USD", sum.String())
}

func TestComparisons(t *testing.T) {
	require.True(t, money.MustFromString("0").IsZero())
	require.True(t, money.MustFromString("-1").IsNegative())
	require.True(t, money.MustFromString("0.00000001").IsPositive())
	require.Equal(t, 1, money.MustFromString("2").Cmp(money.MustFromString("1")))
	require.Equal(t, 0, money.MustFromString("1.0").Cmp(money.MustFromString("1")))
}
