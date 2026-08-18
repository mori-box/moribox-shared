// Package ids provides a canonical, sortable identifier type.
//
// Identifiers are ULIDs. On the transport boundary they are opaque
// 26-character Crockford base32 strings; in a MySQL-family database they are
// stored as BINARY(16). Conversion happens only at those two boundaries.
package ids

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// ErrInvalidID is returned when a value cannot be decoded into an ID.
var ErrInvalidID = errors.New("invalid id")

// ID is a 16 byte ULID.
type ID [16]byte

// Nil is the zero identifier.
var Nil ID

// New returns a new lexicographically sortable identifier seeded from
// crypto/rand.
func New() ID {
	u := ulid.MustNew(ulid.Timestamp(time.Now().UTC()), rand.Reader)
	return ID(u)
}

// NewAt returns a new identifier with an explicit timestamp component.
func NewAt(t time.Time) ID {
	u := ulid.MustNew(ulid.Timestamp(t.UTC()), rand.Reader)
	return ID(u)
}

// Parse decodes the canonical string representation.
func Parse(s string) (ID, error) {
	u, err := ulid.ParseStrict(s)
	if err != nil {
		return Nil, fmt.Errorf("%w: %q", ErrInvalidID, s)
	}
	return ID(u), nil
}

// MustParse decodes s and panics on failure. Test and seed use only.
func MustParse(s string) ID {
	id, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return id
}

// FromBytes builds an ID from its 16 byte binary representation.
func FromBytes(b []byte) (ID, error) {
	if len(b) != 16 {
		return Nil, fmt.Errorf("%w: expected 16 bytes, got %d", ErrInvalidID, len(b))
	}
	var id ID
	copy(id[:], b)
	return id, nil
}

// String returns the 26 character canonical representation.
func (id ID) String() string { return ulid.ULID(id).String() }

// Bytes returns a copy of the binary representation.
func (id ID) Bytes() []byte {
	b := make([]byte, 16)
	copy(b, id[:])
	return b
}

// IsZero reports whether the identifier is unset.
func (id ID) IsZero() bool { return id == Nil }

// Time returns the embedded creation timestamp.
func (id ID) Time() time.Time { return ulid.Time(ulid.ULID(id).Time()).UTC() }

// MarshalJSON implements json.Marshaler.
func (id ID) MarshalJSON() ([]byte, error) { return json.Marshal(id.String()) }

// UnmarshalJSON implements json.Unmarshaler.
func (id *ID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := Parse(s)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// Value implements driver.Valuer, storing BINARY(16).
func (id ID) Value() (driver.Value, error) {
	if id.IsZero() {
		return nil, nil
	}
	return id.Bytes(), nil
}

// Scan implements sql.Scanner.
func (id *ID) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*id = Nil
		return nil
	case []byte:
		parsed, err := FromBytes(v)
		if err != nil {
			return err
		}
		*id = parsed
		return nil
	case string:
		parsed, err := Parse(v)
		if err != nil {
			return err
		}
		*id = parsed
		return nil
	default:
		return fmt.Errorf("%w: unsupported scan type %T", ErrInvalidID, src)
	}
}

// Opt is a nullable identifier for optional foreign keys.
type Opt struct {
	ID    ID
	Valid bool
}

// Some wraps a present identifier.
func Some(id ID) Opt { return Opt{ID: id, Valid: !id.IsZero()} }

// None returns an absent identifier.
func None() Opt { return Opt{} }

// Value implements driver.Valuer.
func (o Opt) Value() (driver.Value, error) {
	if !o.Valid || o.ID.IsZero() {
		return nil, nil
	}
	return o.ID.Bytes(), nil
}

// Scan implements sql.Scanner.
func (o *Opt) Scan(src any) error {
	if src == nil {
		*o = Opt{}
		return nil
	}
	var id ID
	if err := id.Scan(src); err != nil {
		return err
	}
	*o = Opt{ID: id, Valid: true}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (o Opt) MarshalJSON() ([]byte, error) {
	if !o.Valid {
		return []byte("null"), nil
	}
	return o.ID.MarshalJSON()
}

// UnmarshalJSON implements json.Unmarshaler.
func (o *Opt) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*o = Opt{}
		return nil
	}
	var id ID
	if err := id.UnmarshalJSON(b); err != nil {
		return err
	}
	*o = Opt{ID: id, Valid: true}
	return nil
}

// StringPtr renders the optional identifier for API responses.
func (o Opt) StringPtr() *string {
	if !o.Valid {
		return nil
	}
	s := o.ID.String()
	return &s
}
