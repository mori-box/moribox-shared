// Package audit appends the tamper evident administrative trail.
//
// Every privileged mutation writes exactly one event carrying the actor, the
// role, the reason, the request id and the before/after hashes. Entries are
// hash chained: each row commits to the previous entry hash, so a row removed
// or edited directly in the database breaks verification.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mori-box/moribox-shared/database"
	"github.com/mori-box/moribox-shared/ids"
	"github.com/mori-box/moribox-shared/observability"
)

// ActorType classifies who performed an action.
type ActorType string

// Actor types.
const (
	ActorAdmin    ActorType = "ADMIN"
	ActorUser     ActorType = "USER"
	ActorSystem   ActorType = "SYSTEM"
	ActorProvider ActorType = "PROVIDER"
)

// ErrReasonRequired is returned when a privileged mutation has no reason.
var ErrReasonRequired = errors.New("a reason is required for this action")

// Event is one audit record.
type Event struct {
	ID           ids.ID         `json:"id"`
	SequenceNo   uint64         `json:"sequence_no"`
	ActorType    ActorType      `json:"actor_type"`
	ActorID      ids.Opt        `json:"actor_id"`
	Role         string         `json:"role"`
	Action       string         `json:"action"`
	TargetType   string         `json:"target_type"`
	TargetID     ids.Opt        `json:"target_id"`
	Reason       string         `json:"reason"`
	RequestID    string         `json:"request_id"`
	TraceID      string         `json:"trace_id"`
	Metadata     map[string]any `json:"metadata"`
	BeforeHash   string         `json:"before_hash"`
	AfterHash    string         `json:"after_hash"`
	PreviousHash string         `json:"previous_hash"`
	EntryHash    string         `json:"entry_hash"`
	CreatedAt    time.Time      `json:"created_at"`
}

// Logger appends audit events.
type Logger struct {
	db *database.DB
}

// New builds an audit logger.
func New(db *database.DB) *Logger { return &Logger{db: db} }

// Append writes an event inside the caller's transaction so that the audit
// record and the mutation it describes commit or roll back together.
func (l *Logger) Append(ctx context.Context, tx *sql.Tx, e Event) error {
	if strings.TrimSpace(e.Action) == "" {
		return errors.New("audit action must not be empty")
	}
	if e.ID.IsZero() {
		e.ID = ids.New()
	}
	// DATETIME(6) stores microseconds. Hashing a nanosecond timestamp would
	// produce a digest that no re-read could reproduce, which would make the
	// chain permanently unverifiable.
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	e.CreatedAt = e.CreatedAt.UTC().Truncate(time.Microsecond)
	if e.RequestID == "" {
		e.RequestID = observability.RequestIDFromContext(ctx)
	}
	if e.TraceID == "" {
		e.TraceID = observability.TraceIDFromContext(ctx)
	}

	// The head is taken from a singleton row, not from the chain itself.
	//
	// Locking the chain's own head could not serialise appends: the locking read
	// locks the row it finds, so while a second writer waited, the first inserted
	// a new head and committed, and the second — released — still read the older
	// row. Both chained to the same predecessor. A chain that concurrency alone
	// can break makes a legitimate break indistinguishable from tampering, which
	// is the whole property it exists to provide; it reproduced about one run in
	// three under the integration suite.
	//
	// This row always exists, so the lock target never moves and whoever holds it
	// sees the true head.
	var previous sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT entry_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE`).Scan(&previous)
	if err != nil {
		observability.AuditAppendFailuresTotal.Inc()
		return fmt.Errorf("read audit chain head: %w", err)
	}
	e.PreviousHash = previous.String

	var metadata any
	if len(e.Metadata) > 0 {
		encoded, merr := json.Marshal(redactMetadata(e.Metadata))
		if merr != nil {
			return merr
		}
		metadata = string(encoded)
	}
	// Defence in depth: the column is wide enough for every role combination,
	// but an over-long value must never be the reason an audit append fails.
	e.Role = truncate(e.Role, 200)
	e.Reason = truncate(e.Reason, 400)
	e.EntryHash = entryHash(e)

	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_events
    (id, actor_type, actor_id, role, action, target_type, target_id, reason,
     request_id, trace_id, metadata, before_hash, after_hash, previous_hash, entry_hash, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), ?, ?, ?, ?, ?)`,
		e.ID, e.ActorType, e.ActorID, nullIfEmpty(e.Role), e.Action, e.TargetType, e.TargetID,
		nullIfEmpty(e.Reason), nullIfEmpty(e.RequestID), nullIfEmpty(e.TraceID), metadata,
		nullIfEmpty(e.BeforeHash), nullIfEmpty(e.AfterHash), nullIfEmpty(e.PreviousHash),
		e.EntryHash, e.CreatedAt)
	if err != nil {
		observability.AuditAppendFailuresTotal.Inc()
		return fmt.Errorf("append audit event: %w", err)
	}

	// Advancing the head in the same transaction is what makes the lock mean
	// anything: a writer that inserted without moving the head would leave the
	// next one chaining to a predecessor that is no longer last.
	if _, err = tx.ExecContext(ctx, `
UPDATE audit_chain_head
SET sequence_no = sequence_no + 1, entry_hash = ?
WHERE id = 1`, e.EntryHash); err != nil {
		observability.AuditAppendFailuresTotal.Inc()
		return fmt.Errorf("advance audit chain head: %w", err)
	}
	return nil
}

// AppendStandalone opens its own transaction. It is used by background workers
// that have no surrounding transaction to join.
func (l *Logger) AppendStandalone(ctx context.Context, e Event) error {
	return l.db.InTx(ctx, "audit_append", func(ctx context.Context, tx *sql.Tx) error {
		return l.Append(ctx, tx, e)
	})
}

func entryHash(e Event) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
	}
	write(e.ID.String(), string(e.ActorType))
	if e.ActorID.Valid {
		write(e.ActorID.ID.String())
	} else {
		write("")
	}
	write(e.Role, e.Action, e.TargetType)
	if e.TargetID.Valid {
		write(e.TargetID.ID.String())
	} else {
		write("")
	}
	write(e.Reason, e.RequestID, e.BeforeHash, e.AfterHash, e.PreviousHash,
		e.CreatedAt.UTC().Format(time.RFC3339Nano))
	return hex.EncodeToString(h.Sum(nil))
}

// redactMetadata removes any field whose name marks it as sensitive, so a
// careless call site cannot push a token or a raw key into the trail.
func redactMetadata(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if observability.IsSensitiveKey(k) {
			out[k] = observability.Redacted
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = redactMetadata(nested)
			continue
		}
		out[k] = v
	}
	return out
}

// HashOf renders a stable digest of a value for the before/after fields.
func HashOf(v any) string {
	if v == nil {
		return ""
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// Query filters the audit trail.
type Query struct {
	ActorID    ids.Opt
	Action     string
	TargetType string
	TargetID   ids.Opt
	From       *time.Time
	To         *time.Time
	Limit      int
	AfterSeq   uint64
}

// List returns audit events for the admin console.
func (l *Logger) List(ctx context.Context, q Query) ([]Event, error) {
	conditions := []string{"1 = 1"}
	args := []any{}
	if q.ActorID.Valid {
		conditions = append(conditions, "actor_id = ?")
		args = append(args, q.ActorID)
	}
	if q.Action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, q.Action)
	}
	if q.TargetType != "" {
		conditions = append(conditions, "target_type = ?")
		args = append(args, q.TargetType)
	}
	if q.TargetID.Valid {
		conditions = append(conditions, "target_id = ?")
		args = append(args, q.TargetID)
	}
	if q.From != nil {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, q.From.UTC())
	}
	if q.To != nil {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, q.To.UTC())
	}
	if q.AfterSeq > 0 {
		conditions = append(conditions, "sequence_no < ?")
		args = append(args, q.AfterSeq)
	}
	limit := q.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	args = append(args, limit)

	rows, err := l.db.Reader().QueryContext(ctx, `
SELECT id, sequence_no, actor_type, actor_id, COALESCE(role, ''), action, target_type, target_id,
       COALESCE(reason, ''), COALESCE(request_id, ''), COALESCE(trace_id, ''), metadata,
       COALESCE(before_hash, ''), COALESCE(after_hash, ''), COALESCE(previous_hash, ''), entry_hash, created_at
FROM audit_events
WHERE `+strings.Join(conditions, " AND ")+`
ORDER BY sequence_no DESC
LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var (
			e        Event
			metadata []byte
		)
		if err := rows.Scan(&e.ID, &e.SequenceNo, &e.ActorType, &e.ActorID, &e.Role, &e.Action,
			&e.TargetType, &e.TargetID, &e.Reason, &e.RequestID, &e.TraceID, &metadata,
			&e.BeforeHash, &e.AfterHash, &e.PreviousHash, &e.EntryHash, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &e.Metadata)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyChain walks the trail forward and reports the first broken link. The
// reconciler runs it periodically and the auditor screen exposes the result.
func (l *Logger) VerifyChain(ctx context.Context, limit int) (checked int, brokenAt uint64, err error) {
	rows, qerr := l.db.Reader().QueryContext(ctx, `
SELECT id, sequence_no, actor_type, actor_id, COALESCE(role, ''), action, target_type, target_id,
       COALESCE(reason, ''), COALESCE(request_id, ''), COALESCE(before_hash, ''), COALESCE(after_hash, ''),
       COALESCE(previous_hash, ''), entry_hash, created_at
FROM audit_events
ORDER BY sequence_no
LIMIT ?`, limit)
	if qerr != nil {
		return 0, 0, qerr
	}
	defer rows.Close()

	var expectedPrevious string
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.SequenceNo, &e.ActorType, &e.ActorID, &e.Role, &e.Action,
			&e.TargetType, &e.TargetID, &e.Reason, &e.RequestID, &e.BeforeHash, &e.AfterHash,
			&e.PreviousHash, &e.EntryHash, &e.CreatedAt); err != nil {
			return checked, 0, err
		}
		if e.PreviousHash != expectedPrevious {
			return checked, e.SequenceNo, nil
		}
		if entryHash(e) != e.EntryHash {
			return checked, e.SequenceNo, nil
		}
		expectedPrevious = e.EntryHash
		checked++
	}
	return checked, 0, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
