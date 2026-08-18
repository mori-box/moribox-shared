// Package money carries exact monetary amounts.
//
// Amounts are always transported as decimal strings paired with an asset code
// and stored as DECIMAL(20,8). Floating point representations are never used.
package money

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/shopspring/decimal"
)

// Scale is the fixed database scale for every monetary column.
const Scale int32 = 8

// Errors returned by this package.
var (
	ErrInvalidAmount = errors.New("invalid amount")
	ErrInvalidAsset  = errors.New("invalid asset code")
	ErrAssetMismatch = errors.New("asset code mismatch")
	ErrNegative      = errors.New("amount must not be negative")
)

// Asset identifies a unit of account. Asset codes are versioned configuration,
// not code constants; the values below are the bootstrap set documented in the
// specification and validated against the asset registry at startup.
type Asset string

// Bootstrap asset codes.
const (
	AssetUSD      Asset = "USD"
	AssetRUB      Asset = "RUB"
	AssetUSDT     Asset = "USDT"
	AssetMoricoin Asset = "MORICOIN"
)

// SettlementAssets are the currencies a player may hold in the MORI BOX balance
// and pay for a box with. They are two independent units of account: a price is
// declared in each, and nothing in the platform converts between them.
var SettlementAssets = []Asset{AssetRUB, AssetUSD}

// IsSettlement reports whether an asset can be deposited and spent.
func (a Asset) IsSettlement() bool {
	for _, candidate := range SettlementAssets {
		if a == candidate {
			return true
		}
	}
	return false
}

// String returns the raw asset code.
func (a Asset) String() string { return string(a) }

// ParseAsset normalises and validates an asset code.
func ParseAsset(s string) (Asset, error) {
	v := strings.TrimSpace(strings.ToUpper(s))
	if v == "" || len(v) > 16 {
		return "", fmt.Errorf("%w: %q", ErrInvalidAsset, s)
	}
	for _, r := range v {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return "", fmt.Errorf("%w: %q", ErrInvalidAsset, s)
		}
	}
	return Asset(v), nil
}

// Amount is an exact decimal amount without an asset code. It is used for
// database columns where the asset code lives in a sibling column.
type Amount struct {
	d decimal.Decimal
}

// Zero is the additive identity.
var Zero = Amount{}

// FromString parses a decimal string such as "30.00".
func FromString(s string) (Amount, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return Zero, fmt.Errorf("%w: empty", ErrInvalidAmount)
	}
	// Scientific notation is refused: "1e5" is ambiguous in a money field and
	// the API contract documents a plain decimal string.
	if strings.ContainsAny(t, "eE") {
		return Zero, fmt.Errorf("%w: scientific notation is not accepted", ErrInvalidAmount)
	}
	d, err := decimal.NewFromString(t)
	if err != nil {
		return Zero, fmt.Errorf("%w: %q", ErrInvalidAmount, s)
	}
	if d.Exponent() < -Scale {
		return Zero, fmt.Errorf("%w: more than %d decimal places", ErrInvalidAmount, Scale)
	}
	if d.Abs().GreaterThan(decimal.NewFromInt(1_000_000_000_000)) {
		return Zero, fmt.Errorf("%w: out of range", ErrInvalidAmount)
	}
	return Amount{d: d}, nil
}

// MustFromString parses s and panics on failure. Test and seed use only.
func MustFromString(s string) Amount {
	a, err := FromString(s)
	if err != nil {
		panic(err)
	}
	return a
}

// FromInt builds an amount from a whole number.
func FromInt(v int64) Amount { return Amount{d: decimal.NewFromInt(v)} }

// String renders the amount with the canonical database scale trimmed to at
// least two decimal places.
func (a Amount) String() string {
	return a.d.StringFixed(2)
}

// StringExact renders the amount at full stored precision.
func (a Amount) StringExact() string { return a.d.String() }

// Decimal exposes the underlying value for arithmetic helpers.
func (a Amount) Decimal() decimal.Decimal { return a.d }

// Add returns a+b.
func (a Amount) Add(b Amount) Amount { return Amount{d: a.d.Add(b.d)} }

// Sub returns a-b.
func (a Amount) Sub(b Amount) Amount { return Amount{d: a.d.Sub(b.d)} }

// Mul multiplies by a whole number, used for pool value aggregation.
func (a Amount) MulInt(n int64) Amount { return Amount{d: a.d.Mul(decimal.NewFromInt(n))} }

// IsZero reports whether the amount equals zero.
func (a Amount) IsZero() bool { return a.d.IsZero() }

// IsNegative reports whether the amount is below zero.
func (a Amount) IsNegative() bool { return a.d.IsNegative() }

// IsPositive reports whether the amount is above zero.
func (a Amount) IsPositive() bool { return a.d.IsPositive() }

// Equal compares two amounts numerically.
func (a Amount) Equal(b Amount) bool { return a.d.Equal(b.d) }

// Cmp compares two amounts.
func (a Amount) Cmp(b Amount) int { return a.d.Cmp(b.d) }

// Value implements driver.Valuer.
func (a Amount) Value() (driver.Value, error) { return a.d.StringFixed(Scale), nil }

// Scan implements sql.Scanner.
func (a *Amount) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*a = Zero
		return nil
	case []byte:
		d, err := decimal.NewFromString(string(v))
		if err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidAmount, v)
		}
		a.d = d
		return nil
	case string:
		d, err := decimal.NewFromString(v)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidAmount, v)
		}
		a.d = d
		return nil
	default:
		return fmt.Errorf("%w: unsupported scan type %T", ErrInvalidAmount, src)
	}
}

// MarshalJSON encodes the amount as a JSON string, never a float.
func (a Amount) MarshalJSON() ([]byte, error) { return json.Marshal(a.String()) }

// UnmarshalJSON decodes a JSON string amount. Numeric JSON is rejected so that
// a client cannot silently lose precision.
func (a *Amount) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("%w: amounts must be JSON strings", ErrInvalidAmount)
	}
	parsed, err := FromString(s)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// Money couples an amount with its asset code.
type Money struct {
	Amount Amount `json:"amount"`
	Asset  Asset  `json:"asset_code"`
}

// New builds a Money value from a decimal string and asset code.
func New(amount string, asset string) (Money, error) {
	a, err := FromString(amount)
	if err != nil {
		return Money{}, err
	}
	code, err := ParseAsset(asset)
	if err != nil {
		return Money{}, err
	}
	return Money{Amount: a, Asset: code}, nil
}

// MustNew builds a Money value and panics on failure. Test and seed use only.
func MustNew(amount string, asset string) Money {
	m, err := New(amount, asset)
	if err != nil {
		panic(err)
	}
	return m
}

// Add returns the sum of two same-asset amounts.
func (m Money) Add(o Money) (Money, error) {
	if m.Asset != o.Asset {
		return Money{}, fmt.Errorf("%w: %s vs %s", ErrAssetMismatch, m.Asset, o.Asset)
	}
	return Money{Amount: m.Amount.Add(o.Amount), Asset: m.Asset}, nil
}

// String renders "30.00 USD".
func (m Money) String() string { return m.Amount.String() + " " + m.Asset.String() }
