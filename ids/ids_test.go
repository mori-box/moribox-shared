package ids_test

import (
	"database/sql/driver"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/mori-box/moribox-shared/ids"
	"github.com/stretchr/testify/require"
)

// Identifiers cross three boundaries: the wire (26 character strings), the
// database (BINARY(16)) and JSON. A value that survives all three unchanged is
// the whole contract, because an identifier that mutates in transit points at
// the wrong player's prize.

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

func TestStringRoundTrip(t *testing.T) {
	original := ids.New()

	parsed, err := ids.Parse(original.String())
	require.NoError(t, err)
	require.Equal(t, original, parsed)
	require.Len(t, original.String(), 26, "the canonical form is 26 characters")
}

func TestBytesRoundTrip(t *testing.T) {
	original := ids.New()

	restored, err := ids.FromBytes(original.Bytes())
	require.NoError(t, err)
	require.Equal(t, original, restored)
	require.Len(t, original.Bytes(), 16, "the stored form is BINARY(16)")
}

// TestBytesReturnsACopy stops a caller from reaching into the identifier and
// changing it, which would silently repoint a foreign key.
func TestBytesReturnsACopy(t *testing.T) {
	original := ids.New()

	b := original.Bytes()
	b[0] ^= 0xFF

	require.NotEqual(t, b, original.Bytes(), "mutating the copy changed the identifier")
}

func TestJSONRoundTrip(t *testing.T) {
	original := ids.New()

	encoded, err := json.Marshal(original)
	require.NoError(t, err)
	require.JSONEq(t, `"`+original.String()+`"`, string(encoded),
		"an identifier is a JSON string, never an object or a number")

	var decoded ids.ID
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, original, decoded)
}

func TestDatabaseRoundTrip(t *testing.T) {
	original := ids.New()

	value, err := original.Value()
	require.NoError(t, err)
	require.IsType(t, []byte{}, value)

	var scanned ids.ID
	require.NoError(t, scanned.Scan(value))
	require.Equal(t, original, scanned)
}

// TestScanAcceptsTheStringFormTooBecauseSomeDriversReturnIt keeps a query that
// went through a text protocol from failing at the scan.
func TestScanAcceptsTheStringForm(t *testing.T) {
	original := ids.New()

	var scanned ids.ID
	require.NoError(t, scanned.Scan(original.String()))
	require.Equal(t, original, scanned)
}

// ---------------------------------------------------------------------------
// The zero identifier
// ---------------------------------------------------------------------------

// TestZeroIdentifierIsStoredAsNull is what keeps an unset foreign key out of the
// database as a real all-zero value that would match another unset row.
func TestZeroIdentifierIsStoredAsNull(t *testing.T) {
	value, err := ids.Nil.Value()
	require.NoError(t, err)
	require.Nil(t, value, "the zero identifier must be written as SQL NULL")
}

func TestScanningNullYieldsTheZeroIdentifier(t *testing.T) {
	id := ids.New()
	require.NoError(t, id.Scan(nil))
	require.True(t, id.IsZero())
}

func TestIsZero(t *testing.T) {
	require.True(t, ids.Nil.IsZero())
	require.False(t, ids.New().IsZero())
}

func TestScanRejectsAnUnusableType(t *testing.T) {
	var id ids.ID
	require.ErrorIs(t, id.Scan(42), ids.ErrInvalidID)
	require.ErrorIs(t, id.Scan(3.5), ids.ErrInvalidID)
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// TestParseRejectsAnythingThatIsNotACanonicalULID is a boundary control. A
// permissive parser would let a caller probe with truncated or padded values.
func TestParseRejectsAnythingThatIsNotACanonicalULID(t *testing.T) {
	valid := ids.New().String()

	invalid := []string{
		"",
		"not-an-id",
		valid[:25],                    // too short
		valid + "0",                   // too long
		"00000000000000000000000000!", // illegal character
		"ZZZZZZZZZZZZZZZZZZZZZZZZZZ",  // overflows the 48 bit timestamp
	}

	for _, raw := range invalid {
		_, err := ids.Parse(raw)
		require.ErrorIs(t, err, ids.ErrInvalidID, "%q was accepted", raw)
	}
}

// TestParseErrorQuotesTheInput makes a bad identifier debuggable without having
// to reproduce the request.
func TestParseErrorQuotesTheInput(t *testing.T) {
	_, err := ids.Parse("nonsense")
	require.ErrorContains(t, err, `"nonsense"`)
}

func TestFromBytesRejectsTheWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 15, 17, 32} {
		_, err := ids.FromBytes(make([]byte, n))
		require.ErrorIs(t, err, ids.ErrInvalidID, "%d bytes was accepted", n)
	}
}

func TestMustParsePanicsOnBadInput(t *testing.T) {
	require.Panics(t, func() { ids.MustParse("nonsense") })
	require.NotPanics(t, func() { ids.MustParse(ids.New().String()) })
}

func TestUnmarshalJSONRejectsBadValues(t *testing.T) {
	var id ids.ID

	require.Error(t, json.Unmarshal([]byte(`"nonsense"`), &id))
	require.Error(t, json.Unmarshal([]byte(`12345`), &id), "a number is not an identifier")
	require.Error(t, json.Unmarshal([]byte(`{"id":"x"}`), &id))
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

// TestIdentifiersSortByCreationTime is the property the history endpoints rely
// on: ordering by id is ordering by time, so cursor pagination needs no second
// sort key and no timestamp column in the index.
func TestIdentifiersSortByCreationTime(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	var generated []ids.ID
	for i := 0; i < 50; i++ {
		generated = append(generated, ids.NewAt(base.Add(time.Duration(i)*time.Millisecond)))
	}

	sorted := make([]ids.ID, len(generated))
	copy(sorted, generated)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].String() < sorted[j].String() })

	require.Equal(t, generated, sorted,
		"sorting the string form must reproduce creation order")
}

// TestByteOrderMatchesStringOrder is the same guarantee on the database side,
// where the column is BINARY(16) and the index sorts bytes.
func TestByteOrderMatchesStringOrder(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	earlier := ids.NewAt(base)
	later := ids.NewAt(base.Add(time.Second))

	require.Less(t, earlier.String(), later.String())
	require.Less(t, string(earlier.Bytes()), string(later.Bytes()),
		"a BINARY(16) index must order identifiers the same way the API does")
}

// TestIdentifiersGeneratedInTheSameMillisecondAreDistinct. Ordering within a
// millisecond is not guaranteed, but uniqueness is, and that is what the
// primary key depends on.
func TestIdentifiersGeneratedInTheSameMillisecondAreDistinct(t *testing.T) {
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	seen := make(map[ids.ID]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := ids.NewAt(at)
		require.False(t, seen[id], "a duplicate identifier was generated")
		seen[id] = true
	}
}

func TestTimeRecoversTheCreationInstant(t *testing.T) {
	at := time.Date(2026, 3, 1, 12, 30, 45, 0, time.UTC)

	id := ids.NewAt(at)

	require.WithinDuration(t, at, id.Time(), time.Millisecond,
		"the embedded timestamp must survive to millisecond resolution")
	require.Equal(t, time.UTC, id.Time().Location())
}

func TestNewIsStampedWithTheCurrentTime(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	id := ids.New()
	after := time.Now().UTC().Add(time.Second)

	require.WithinRange(t, id.Time(), before, after)
}

// ---------------------------------------------------------------------------
// Opt: the nullable identifier
// ---------------------------------------------------------------------------

func TestSomeWrapsAPresentIdentifier(t *testing.T) {
	id := ids.New()

	opt := ids.Some(id)

	require.True(t, opt.Valid)
	require.Equal(t, id, opt.ID)
}

// TestSomeOfTheZeroIdentifierIsNotValid is the guard that stops an unset field
// from being written as a present-but-empty foreign key.
func TestSomeOfTheZeroIdentifierIsNotValid(t *testing.T) {
	opt := ids.Some(ids.Nil)

	require.False(t, opt.Valid, "wrapping the zero identifier must not produce a present value")

	value, err := opt.Value()
	require.NoError(t, err)
	require.Nil(t, value)
}

func TestNoneIsAbsent(t *testing.T) {
	opt := ids.None()

	require.False(t, opt.Valid)
	require.True(t, opt.ID.IsZero())
	require.Nil(t, opt.StringPtr())
}

func TestOptDatabaseRoundTrip(t *testing.T) {
	id := ids.New()

	value, err := ids.Some(id).Value()
	require.NoError(t, err)

	var scanned ids.Opt
	require.NoError(t, scanned.Scan(value))
	require.True(t, scanned.Valid)
	require.Equal(t, id, scanned.ID)
}

func TestScanningNullProducesAnAbsentOpt(t *testing.T) {
	opt := ids.Some(ids.New())

	require.NoError(t, opt.Scan(nil))
	require.False(t, opt.Valid)
	require.True(t, opt.ID.IsZero(), "an absent value must not keep the old identifier")
}

// TestOptMarshalsAbsenceAsJSONNull is what the API contract promises: an
// optional identifier is either a 26 character string or null, never "" or a
// zero-filled ULID.
func TestOptMarshalsAbsenceAsJSONNull(t *testing.T) {
	encoded, err := json.Marshal(ids.None())
	require.NoError(t, err)
	require.Equal(t, "null", string(encoded))

	id := ids.New()
	encoded, err = json.Marshal(ids.Some(id))
	require.NoError(t, err)
	require.JSONEq(t, `"`+id.String()+`"`, string(encoded))
}

func TestOptUnmarshalsNull(t *testing.T) {
	opt := ids.Some(ids.New())

	require.NoError(t, json.Unmarshal([]byte("null"), &opt))
	require.False(t, opt.Valid)
	require.True(t, opt.ID.IsZero())
}

func TestOptUnmarshalsAPresentIdentifier(t *testing.T) {
	id := ids.New()

	var opt ids.Opt
	require.NoError(t, json.Unmarshal([]byte(`"`+id.String()+`"`), &opt))
	require.True(t, opt.Valid)
	require.Equal(t, id, opt.ID)
}

func TestOptUnmarshalRejectsABadIdentifier(t *testing.T) {
	var opt ids.Opt
	require.Error(t, json.Unmarshal([]byte(`"nonsense"`), &opt))
}

// TestOptInAStructRendersTheWayTheAPIDocuments checks the shape a client
// actually receives, since that is where a nullable field is easy to get wrong.
func TestOptInAStructRendersTheWayTheAPIDocuments(t *testing.T) {
	type response struct {
		BoxProductID  ids.Opt `json:"box_product_id"`
		EntitlementID ids.Opt `json:"entitlement_id"`
	}

	id := ids.New()
	encoded, err := json.Marshal(response{BoxProductID: ids.Some(id), EntitlementID: ids.None()})
	require.NoError(t, err)

	require.JSONEq(t,
		`{"box_product_id":"`+id.String()+`","entitlement_id":null}`,
		string(encoded))
}

func TestStringPtrRendersThePresentValue(t *testing.T) {
	id := ids.New()

	ptr := ids.Some(id).StringPtr()

	require.NotNil(t, ptr)
	require.Equal(t, id.String(), *ptr)
}

// TestOptSatisfiesTheDatabaseInterfaces is a compile-time guarantee that Opt can
// be passed to a query and scanned from a row without a wrapper.
func TestOptSatisfiesTheDatabaseInterfaces(t *testing.T) {
	var (
		_ driver.Valuer = ids.Opt{}
		_ driver.Valuer = ids.Nil
	)
	require.Implements(t, (*json.Marshaler)(nil), ids.Opt{})
	require.Implements(t, (*json.Unmarshaler)(nil), &ids.Opt{})
}
