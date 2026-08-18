package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// ResetTestSchema drops and recreates every table in the connected schema.
//
// It refuses any schema whose name does not mark it as a test schema. The cost
// of this function being pointed at the wrong database is total and permanent,
// so the guard is a hard error rather than a convention.
func ResetTestSchema(ctx context.Context, conn *sql.DB) error {
	var schema string
	if err := conn.QueryRowContext(ctx, `SELECT DATABASE()`).Scan(&schema); err != nil {
		return fmt.Errorf("determine current schema: %w", err)
	}
	if !strings.Contains(strings.ToLower(schema), "test") {
		return fmt.Errorf("refusing to reset %q: only a schema named as a test schema may be dropped", schema)
	}

	// Foreign keys are disabled for the drop rather than the tables sorted into
	// dependency order, which would have to be maintained by hand forever.
	if _, err := conn.ExecContext(ctx, `SET FOREIGN_KEY_CHECKS = 0`); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SET FOREIGN_KEY_CHECKS = 1`) }()

	rows, err := conn.QueryContext(ctx, `
SELECT table_name FROM information_schema.tables WHERE table_schema = ?`, schema)
	if err != nil {
		return err
	}
	// The table names are drained into memory before anything is dropped, so the
	// result set is exhausted and closed before the first DROP. The defer covers
	// the scan error path.
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, table := range tables {
		if _, err := conn.ExecContext(ctx, "DROP TABLE IF EXISTS `"+table+"`"); err != nil {
			return fmt.Errorf("drop %s: %w", table, err)
		}
	}
	return nil
}
