// Package idempotency stores and replays the result of a mutation.
//
// Idempotency does not replace unique constraints: it removes the duplicate
// work and returns a stable answer, while the database keeps the invariant.
package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mori-box/moribox-shared/database"
	"github.com/mori-box/moribox-shared/ids"
)

// State of a stored record.
const (
	StateInProgress      = "IN_PROGRESS"
	StateCompleted       = "COMPLETED"
	StateFailedRetryable = "FAILED_RETRYABLE"
)

// Errors returned by the store.
var (
	// ErrConflict means the same key arrived with a different request body.
	ErrConflict = errors.New("idempotency key reused with a different request")
	// ErrInProgress means an identical request is still being processed.
	ErrInProgress = errors.New("an identical request is already in progress")
)

// Record is a stored idempotent outcome.
type Record struct {
	ID          ids.ID
	ActorScope  string
	Key         string
	Route       string
	RequestHash string
	State       string
	Status      int
	Body        []byte
	ResourceID  ids.Opt
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Store persists idempotency records.
type Store struct {
	db  *database.DB
	ttl time.Duration
}

// NewStore builds a store.
func NewStore(db *database.DB, ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Store{db: db, ttl: ttl}
}

// Begin claims the key for this request.
//
// It returns a non-nil record when the same request already completed, in which
// case the caller replays the stored response. It returns ErrConflict when the
// key was used with a different body and ErrInProgress when an identical
// request is still running.
func (s *Store) Begin(ctx context.Context, actorScope, key, route, requestHash string) (*Record, error) {
	now := time.Now().UTC()

	// Fast path: the unique index decides the race. Exactly one concurrent
	// request inserts the row and therefore owns the key.
	_, err := s.db.Writer().ExecContext(ctx, `
INSERT INTO idempotency_records
    (id, actor_scope, idempotency_key, route, request_hash, state, created_at, updated_at, expires_at)
VALUES (?, ?, ?, ?, ?, 'IN_PROGRESS', ?, ?, ?)`,
		ids.New(), actorScope, key, route, requestHash, now, now, now.Add(s.ttl))
	if err == nil {
		return nil, nil
	}
	if !database.IsDuplicate(err) {
		return nil, fmt.Errorf("claim idempotency key: %w", err)
	}

	// Slow path: the key already exists. Take the row lock so that two
	// simultaneous retries cannot both decide they own it.
	var (
		record *Record
		owned  bool
	)
	txErr := s.db.InTx(ctx, "idempotency_begin", func(ctx context.Context, tx *sql.Tx) error {
		var (
			r      Record
			status sql.NullInt64
			body   []byte
		)
		scanErr := tx.QueryRowContext(ctx, `
SELECT id, actor_scope, idempotency_key, route, request_hash, state,
       response_status, response_body, resource_id, created_at, expires_at
FROM idempotency_records
WHERE actor_scope = ? AND idempotency_key = ?
FOR UPDATE`, actorScope, key).
			Scan(&r.ID, &r.ActorScope, &r.Key, &r.Route, &r.RequestHash, &r.State,
				&status, &body, &r.ResourceID, &r.CreatedAt, &r.ExpiresAt)
		if database.IsNoRows(scanErr) {
			// The record expired and was purged between the two statements.
			_, insErr := tx.ExecContext(ctx, `
INSERT INTO idempotency_records
    (id, actor_scope, idempotency_key, route, request_hash, state, created_at, updated_at, expires_at)
VALUES (?, ?, ?, ?, ?, 'IN_PROGRESS', ?, ?, ?)`,
				ids.New(), actorScope, key, route, requestHash, now, now, now.Add(s.ttl))
			if insErr != nil {
				return insErr
			}
			owned = true
			return nil
		}
		if scanErr != nil {
			return fmt.Errorf("load idempotency record: %w", scanErr)
		}
		if status.Valid {
			r.Status = int(status.Int64)
		}
		r.Body = body

		takeOwnership := func() error {
			_, uerr := tx.ExecContext(ctx, `
UPDATE idempotency_records
SET route = ?, request_hash = ?, state = 'IN_PROGRESS', response_status = NULL,
    response_body = NULL, resource_id = NULL, created_at = ?, updated_at = ?, expires_at = ?
WHERE actor_scope = ? AND idempotency_key = ?`,
				route, requestHash, now, now, now.Add(s.ttl), actorScope, key)
			if uerr == nil {
				owned = true
			}
			return uerr
		}

		if r.ExpiresAt.Before(now) {
			return takeOwnership()
		}
		if r.RequestHash != requestHash {
			return ErrConflict
		}
		switch r.State {
		case StateCompleted:
			record = &r
			return nil
		case StateFailedRetryable:
			return takeOwnership()
		default:
			return ErrInProgress
		}
	})
	if txErr != nil {
		if errors.Is(txErr, ErrConflict) || errors.Is(txErr, ErrInProgress) {
			return nil, txErr
		}
		return nil, txErr
	}
	if owned {
		return nil, nil
	}
	return record, nil
}

// Load reads a record.
func (s *Store) Load(ctx context.Context, actorScope, key string) (*Record, error) {
	var (
		r      Record
		status sql.NullInt64
		body   []byte
	)
	err := s.db.Writer().QueryRowContext(ctx, `
SELECT id, actor_scope, idempotency_key, route, request_hash, state,
       response_status, response_body, resource_id, created_at, expires_at
FROM idempotency_records
WHERE actor_scope = ? AND idempotency_key = ?`, actorScope, key).
		Scan(&r.ID, &r.ActorScope, &r.Key, &r.Route, &r.RequestHash, &r.State,
			&status, &body, &r.ResourceID, &r.CreatedAt, &r.ExpiresAt)
	if database.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load idempotency record: %w", err)
	}
	if status.Valid {
		r.Status = int(status.Int64)
	}
	r.Body = body
	return &r, nil
}

// Complete stores the response so that a retry replays it verbatim.
func (s *Store) Complete(ctx context.Context, actorScope, key string, status int, body []byte, resourceID ids.Opt) error {
	_, err := s.db.Writer().ExecContext(ctx, `
UPDATE idempotency_records
SET state = 'COMPLETED', response_status = ?, response_body = ?, resource_id = ?, updated_at = ?
WHERE actor_scope = ? AND idempotency_key = ?`,
		status, body, resourceID, time.Now().UTC(), actorScope, key)
	if err != nil {
		return fmt.Errorf("complete idempotency record: %w", err)
	}
	return nil
}

// CompleteTx stores the response inside the caller's transaction so that the
// business effect and its replayable answer commit together.
func (s *Store) CompleteTx(ctx context.Context, tx *sql.Tx, actorScope, key string, status int, body []byte, resourceID ids.Opt) error {
	_, err := tx.ExecContext(ctx, `
UPDATE idempotency_records
SET state = 'COMPLETED', response_status = ?, response_body = ?, resource_id = ?, updated_at = ?
WHERE actor_scope = ? AND idempotency_key = ?`,
		status, body, resourceID, time.Now().UTC(), actorScope, key)
	return err
}

// Fail marks the record retryable so that a transient failure does not poison
// the key for its whole lifetime.
func (s *Store) Fail(ctx context.Context, actorScope, key string) error {
	_, err := s.db.Writer().ExecContext(ctx, `
UPDATE idempotency_records
SET state = 'FAILED_RETRYABLE', updated_at = ?
WHERE actor_scope = ? AND idempotency_key = ? AND state = 'IN_PROGRESS'`,
		time.Now().UTC(), actorScope, key)
	return err
}

// Purge removes expired records.
func (s *Store) Purge(ctx context.Context, limit int) (int64, error) {
	res, err := s.db.Writer().ExecContext(ctx,
		`DELETE FROM idempotency_records WHERE expires_at < ? LIMIT ?`, time.Now().UTC(), limit)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RequestHash computes the canonical request digest. The digest covers the
// actor, the route and the semantic body, so the same key with a different body
// is detected regardless of key ordering or insignificant whitespace.
func RequestHash(actorScope, route string, body []byte) (string, error) {
	canonical, err := canonicalJSON(body)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(actorScope))
	h.Write([]byte{0})
	h.Write([]byte(route))
	h.Write([]byte{0})
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CanonicalHash digests a JSON document independently of who sent it or where.
//
// RequestHash deliberately binds a body to one actor and one route, which is
// what makes an idempotency key safe to reuse. An approval payload needs the
// opposite property: the person who submits it and the person who approves it
// call different endpoints, and both must arrive at the same value or the
// approval can never be matched to the action it authorises.
func CanonicalHash(body []byte) (string, error) {
	canonical, err := canonicalJSON(body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// canonicalJSON renders a JSON document with sorted object keys. A non JSON
// body is hashed verbatim.
func canonicalJSON(body []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}
	var parsed any
	if err := json.Unmarshal(trimmed, &parsed); err != nil {
		// As the doc comment above says: a non JSON body is hashed verbatim. The
		// digest has to be defined for every request, and a body this function
		// cannot canonicalise is still perfectly comparable byte for byte.
		return trimmed, nil //nolint:nilerr // a non-JSON body is hashed verbatim by design; the parse failure is not an outcome
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, parsed); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch value := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for k := range value {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encoded, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(encoded)
			buf.WriteByte(':')
			if err := writeCanonical(buf, value[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(encoded)
		return nil
	}
}
