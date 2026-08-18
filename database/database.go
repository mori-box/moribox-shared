// Package database owns Aurora MySQL connectivity.
//
// Every process opens a bounded pool against the RDS Proxy writer endpoint and,
// optionally, a reader pool used only for tolerably stale catalog and history
// reads. Transactions are short, take row locks on specific candidates and never
// perform network calls to KMS, S3 or a provider while open.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/mori-box/moribox-shared/observability"
)

// Config holds MySQL connection settings.
type Config struct {
	DSN               string
	DSNSecretRef      string
	ReaderDSN         string
	MaxOpenConns      int
	MaxIdleConns      int
	ConnMaxLifetime   time.Duration
	ConnMaxIdleTime   time.Duration
	QueryTimeout      time.Duration
	TxTimeout         time.Duration
	MigrateOnStartup  bool
	ConnectionBudget  int
	StatementTimeoutS int
}

// Role distinguishes the writer pool from the reader pool.
type Role string

// Pool roles.
const (
	RoleWriter Role = "writer"
	RoleReader Role = "reader"
)

// DB wraps the writer and reader pools.
type DB struct {
	writer  *sql.DB
	reader  *sql.DB
	service string
	cfg     Config
}

// Open builds the pools and verifies connectivity.
func Open(ctx context.Context, service string, cfg Config) (*DB, error) {
	writer, err := openPool(ctx, cfg.DSN, cfg)
	if err != nil {
		return nil, fmt.Errorf("open writer pool: %w", err)
	}
	db := &DB{writer: writer, service: service, cfg: cfg}

	if cfg.ReaderDSN != "" {
		reader, err := openPool(ctx, cfg.ReaderDSN, cfg)
		if err != nil {
			_ = writer.Close()
			return nil, fmt.Errorf("open reader pool: %w", err)
		}
		db.reader = reader
	}
	return db, nil
}

func openPool(ctx context.Context, dsn string, cfg Config) (*sql.DB, error) {
	parsed, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid DSN: %w", err)
	}
	// The session must be UTC and strict so that TIMESTAMP(6) round trips and
	// silent truncation never happens.
	parsed.Loc = time.UTC
	parsed.ParseTime = true
	parsed.MultiStatements = false
	parsed.InterpolateParams = false
	parsed.CheckConnLiveness = true
	if parsed.Params == nil {
		parsed.Params = map[string]string{}
	}
	parsed.Params["time_zone"] = "'+00:00'"
	parsed.Params["sql_mode"] = "'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,ERROR_FOR_DIVISION_BY_ZERO'"
	parsed.Params["transaction_isolation"] = "'READ-COMMITTED'"
	parsed.Params["charset"] = "utf8mb4"

	pool, err := sql.Open("mysql", parsed.FormatDSN())
	if err != nil {
		return nil, err
	}
	pool.SetMaxOpenConns(cfg.MaxOpenConns)
	pool.SetMaxIdleConns(cfg.MaxIdleConns)
	pool.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	pool.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.PingContext(pingCtx); err != nil {
		_ = pool.Close()
		return nil, err
	}
	return pool, nil
}

// Writer returns the primary pool. Read-your-write paths must use it.
func (d *DB) Writer() *sql.DB { return d.writer }

// Reader returns the replica pool, falling back to the writer when no reader
// endpoint is configured.
func (d *DB) Reader() *sql.DB {
	if d.reader != nil {
		return d.reader
	}
	return d.writer
}

// Close releases both pools.
func (d *DB) Close() error {
	var errs []error
	if d.reader != nil {
		errs = append(errs, d.reader.Close())
	}
	errs = append(errs, d.writer.Close())
	return errors.Join(errs...)
}

// Ping verifies the writer pool.
func (d *DB) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return d.writer.PingContext(ctx)
}

// QueryTimeout returns the configured per statement budget.
func (d *DB) QueryTimeout() time.Duration { return d.cfg.QueryTimeout }

// TxTimeout returns the configured per transaction budget.
func (d *DB) TxTimeout() time.Duration { return d.cfg.TxTimeout }

// ExportPoolStats publishes pool saturation gauges.
func (d *DB) ExportPoolStats() {
	publish := func(role Role, pool *sql.DB) {
		if pool == nil {
			return
		}
		s := pool.Stats()
		observability.DBConnectionsInUse.WithLabelValues(d.service, string(role)).Set(float64(s.InUse))
		observability.DBConnectionsIdle.WithLabelValues(d.service, string(role)).Set(float64(s.Idle))
		observability.DBWaitCount.WithLabelValues(d.service, string(role)).Set(float64(s.WaitCount))
	}
	publish(RoleWriter, d.writer)
	publish(RoleReader, d.reader)
}

// StartPoolStatsExporter periodically publishes pool gauges until ctx ends.
func (d *DB) StartPoolStatsExporter(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				d.ExportPoolStats()
			}
		}
	}()
}

// Querier is satisfied by *sql.DB and *sql.Tx so that repositories can be used
// inside and outside a transaction without duplication.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// TxFunc is the body of a transaction.
type TxFunc func(ctx context.Context, tx *sql.Tx) error

// maxTxAttempts bounds retries of transient transaction failures.
const maxTxAttempts = 4

// InTx runs fn inside a short READ COMMITTED transaction, retrying only the
// transient MySQL failures that are safe to replay because the transaction is
// fully rolled back and contains no external side effects.
func (d *DB) InTx(ctx context.Context, operation string, fn TxFunc) error {
	var lastErr error
	for attempt := 1; attempt <= maxTxAttempts; attempt++ {
		err := d.runTx(ctx, operation, fn)
		if err == nil {
			return nil
		}
		if !IsRetryable(err) || ctx.Err() != nil {
			return err
		}
		lastErr = err
		observability.DBRetriesTotal.WithLabelValues(d.service, operation).Inc()
		if IsDeadlock(err) {
			observability.DBDeadlocksTotal.WithLabelValues(d.service, operation).Inc()
		}
		backoff := time.Duration(attempt*attempt) * 15 * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("transaction %q exhausted retries: %w", operation, lastErr)
}

func (d *DB) runTx(ctx context.Context, operation string, fn TxFunc) (err error) {
	txCtx, cancel := context.WithTimeout(ctx, d.cfg.TxTimeout)
	defer cancel()

	start := time.Now()
	tx, err := d.writer.BeginTx(txCtx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin %s: %w", operation, err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		}
		observability.DBQueryDuration.WithLabelValues(d.service, operation).Observe(time.Since(start).Seconds())
	}()

	if err = fn(txCtx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", operation, err)
	}
	return nil
}

// Observe records the latency of a non transactional statement.
func (d *DB) Observe(operation string, start time.Time) {
	observability.DBQueryDuration.WithLabelValues(d.service, operation).Observe(time.Since(start).Seconds())
}

// MySQL error numbers the platform reacts to explicitly.
const (
	errDuplicateEntry  = 1062
	errDeadlock        = 1213
	errLockWaitTimeout = 1205
	errCheckConstraint = 3819
	errRowIsReferenced = 1451
	errNoReferencedRow = 1452
	errQueryInterrupt  = 1317
)

// IsDuplicate reports whether err is a unique constraint violation. Unique
// indexes are a correctness mechanism, not an optimisation, so callers translate
// this into a domain conflict rather than a 500.
func IsDuplicate(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == errDuplicateEntry
}

// DuplicateIndex returns the index name reported by MySQL for a duplicate key
// error, which lets callers distinguish which invariant was hit.
func DuplicateIndex(err error) string {
	var me *mysql.MySQLError
	if !errors.As(err, &me) || me.Number != errDuplicateEntry {
		return ""
	}
	// Message form: Duplicate entry 'x' for key 'table.index_name'
	const marker = "for key '"
	idx := strings.LastIndex(me.Message, marker)
	if idx < 0 {
		return ""
	}
	rest := me.Message[idx+len(marker):]
	rest = strings.TrimSuffix(rest, "'")
	if dot := strings.LastIndex(rest, "."); dot >= 0 {
		rest = rest[dot+1:]
	}
	return rest
}

// IsDeadlock reports whether err is a deadlock or lock wait timeout.
func IsDeadlock(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && (me.Number == errDeadlock || me.Number == errLockWaitTimeout)
}

// IsCheckConstraint reports whether err violated a CHECK constraint.
func IsCheckConstraint(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == errCheckConstraint
}

// IsForeignKey reports whether err violated a foreign key constraint.
func IsForeignKey(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && (me.Number == errRowIsReferenced || me.Number == errNoReferencedRow)
}

// IsRetryable reports whether a fully rolled back transaction may be replayed.
func IsRetryable(err error) bool {
	if IsDeadlock(err) {
		return true
	}
	var me *mysql.MySQLError
	if errors.As(err, &me) && me.Number == errQueryInterrupt {
		return true
	}
	return errors.Is(err, mysql.ErrInvalidConn) || errors.Is(err, sql.ErrConnDone)
}

// IsNoRows is a convenience wrapper.
func IsNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// NullTime converts an optional timestamp for parameter binding.
func NullTime(t *time.Time) sql.NullTime {
	if t == nil || t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}

// TimePtr converts a scanned nullable timestamp.
func TimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

// NullString converts an optional string for parameter binding.
func NullString(s *string) sql.NullString {
	if s == nil || *s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

// StringPtr converts a scanned nullable string.
func StringPtr(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.String
	return &v
}

// PrefixColumns qualifies every column in a projection with a table alias.
//
// Splitting must respect parentheses: a naive split on commas would break
// COALESCE(subtitle, ”) into two fragments and prefix the string literal as if
// it were a column, producing invalid SQL. Sharing one implementation keeps
// every repository's joined queries correct.
func PrefixColumns(columns, alias string) string {
	parts := splitTopLevel(columns)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, qualify(trimmed, alias))
	}
	return strings.Join(out, ", ")
}

// qualify prefixes the first bare identifier of an expression.
func qualify(expression, alias string) string {
	open := strings.IndexByte(expression, '(')
	if open < 0 {
		return alias + "." + expression
	}
	// A function call such as COALESCE(col, ''): qualify its first argument.
	head := expression[:open+1]
	rest := expression[open+1:]
	return head + alias + "." + rest
}

// splitTopLevel splits on commas that are not inside parentheses or quotes.
func splitTopLevel(input string) []string {
	var (
		parts   []string
		current strings.Builder
		depth   int
		inQuote bool
	)
	for i := 0; i < len(input); i++ {
		c := input[i]
		switch {
		case c == '\'' && (i == 0 || input[i-1] != '\\'):
			inQuote = !inQuote
		case c == '(' && !inQuote:
			depth++
		case c == ')' && !inQuote:
			depth--
		case c == ',' && depth == 0 && !inQuote:
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(c)
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}
