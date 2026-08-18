// Package outbox implements the transactional outbox.
//
// An event is inserted in the same transaction as the row it describes, so a
// commit either contains both or neither. The relay publishes committed events
// to the queue and records the resulting message id; a duplicate publish is safe
// because every worker reloads the authoritative row before acting.
package outbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mori-box/moribox-shared/database"
	"github.com/mori-box/moribox-shared/ids"
)

// Event types published by the platform.
const (
	EventPrizeWon             = "PrizeWon"
	EventOpeningReady         = "OpeningReady"
	EventFulfillmentRetry     = "FulfillmentRetryRequested"
	EventPhysicalClaimChanged = "PhysicalClaimStateChanged"
	EventReferralQualified    = "ReferralQualified"
	EventFreeBoxGranted       = "FreeBoxEntitlementGranted"
	EventFragmentRedeemed     = "FragmentsRedeemed"
	EventCampaignStateChanged = "CampaignStateChanged"
	EventIntegrityIncident    = "IntegrityIncidentRaised"
	EventBuybackObligation    = "BuybackObligationCreated"
	EventNotification         = "NotificationRequested"
	EventAnalytics            = "AnalyticsEvent"
)

// Event is a row awaiting publication.
type Event struct {
	ID              ids.ID
	AggregateType   string
	AggregateID     ids.ID
	EventType       string
	QueueName       string
	MessageGroupID  string
	DeduplicationID string
	Payload         json.RawMessage
	OccurredAt      time.Time
	Attempts        int
}

// Envelope is the JSON body written to the queue. Correlation identifiers
// travel with the message so that a trace spans HTTP, database, queue and
// provider callback.
type Envelope struct {
	EventID     string          `json:"event_id"`
	EventType   string          `json:"event_type"`
	Aggregate   string          `json:"aggregate_type"`
	AggregateID string          `json:"aggregate_id"`
	OccurredAt  time.Time       `json:"occurred_at"`
	RequestID   string          `json:"request_id,omitempty"`
	TraceID     string          `json:"trace_id,omitempty"`
	Data        json.RawMessage `json:"data"`
}

// Writer appends events inside an existing transaction.
type Writer struct{}

// NewWriter builds an outbox writer.
func NewWriter() *Writer { return &Writer{} }

// Append inserts one event. It must be called with the same *sql.Tx that
// persists the aggregate.
func (w *Writer) Append(ctx context.Context, tx *sql.Tx, e Event) error {
	if e.ID.IsZero() {
		e.ID = ids.New()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	const stmt = `
INSERT INTO outbox_events
    (id, aggregate_type, aggregate_id, event_type, queue_name, message_group_id, dedup_id, payload, occurred_at)
VALUES (?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), ?)`

	_, err := tx.ExecContext(ctx, stmt,
		e.ID, e.AggregateType, e.AggregateID, e.EventType, e.QueueName,
		nullable(e.MessageGroupID), nullable(e.DeduplicationID), string(e.Payload), e.OccurredAt)
	if err != nil {
		return fmt.Errorf("append outbox event %s: %w", e.EventType, err)
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Store reads and acknowledges outbox rows for the relay.
type Store struct {
	db *database.DB
}

// NewStore builds an outbox store.
func NewStore(db *database.DB) *Store { return &Store{db: db} }

// ClaimBatch locks a batch of unpublished events with SKIP LOCKED so that
// multiple relay replicas make progress without contending on the same rows.
func (s *Store) ClaimBatch(ctx context.Context, limit int, fn func(context.Context, []Event) ([]Published, error)) (int, error) {
	var processed int
	err := s.db.InTx(ctx, "outbox_claim_batch", func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
SELECT id, aggregate_type, aggregate_id, event_type, queue_name,
       COALESCE(message_group_id, ''), COALESCE(dedup_id, ''), payload, occurred_at, attempts
FROM outbox_events
WHERE published_at IS NULL
ORDER BY id
LIMIT ?
FOR UPDATE SKIP LOCKED`, limit)
		if err != nil {
			return fmt.Errorf("select outbox batch: %w", err)
		}
		defer rows.Close()

		var batch []Event
		for rows.Next() {
			var e Event
			var payload []byte
			if err := rows.Scan(&e.ID, &e.AggregateType, &e.AggregateID, &e.EventType, &e.QueueName,
				&e.MessageGroupID, &e.DeduplicationID, &payload, &e.OccurredAt, &e.Attempts); err != nil {
				return fmt.Errorf("scan outbox row: %w", err)
			}
			e.Payload = json.RawMessage(payload)
			batch = append(batch, e)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}

		results, err := fn(ctx, batch)
		if err != nil {
			return err
		}
		for _, r := range results {
			if r.Err != nil {
				if _, uerr := tx.ExecContext(ctx,
					`UPDATE outbox_events SET attempts = attempts + 1, last_error = ? WHERE id = ?`,
					truncate(r.Err.Error(), 380), r.EventID); uerr != nil {
					return uerr
				}
				continue
			}
			if _, uerr := tx.ExecContext(ctx,
				`UPDATE outbox_events SET published_at = ?, queue_message_id = ?, attempts = attempts + 1 WHERE id = ? AND published_at IS NULL`,
				time.Now().UTC(), r.MessageID, r.EventID); uerr != nil {
				return uerr
			}
			processed++
		}
		return nil
	})
	return processed, err
}

// Published is the outcome of one publish attempt.
type Published struct {
	EventID   ids.ID
	MessageID string
	Err       error
}

// Lag returns the number of unpublished events and the age of the oldest one.
func (s *Store) Lag(ctx context.Context) (int64, time.Duration, error) {
	var count int64
	var oldest sql.NullTime
	err := s.db.Reader().QueryRowContext(ctx, `
SELECT COUNT(*), MIN(occurred_at) FROM outbox_events WHERE published_at IS NULL`).Scan(&count, &oldest)
	if err != nil {
		return 0, 0, err
	}
	if !oldest.Valid {
		return count, 0, nil
	}
	return count, time.Since(oldest.Time.UTC()), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
