package server

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// VulnerabilityState represents the lifecycle state of a vulnerability.
type VulnerabilityState string

const (
	StateOpen  VulnerabilityState = "OPEN"
	StateFixed VulnerabilityState = "FIXED"
)

// VulnerabilityRecord represents a vulnerability in the database.
type VulnerabilityRecord struct {
	ID        string // hash(cve + workload)
	CVE       string
	Workload  string // namespace/kind/name
	Severity  string
	Image     string
	State     VulnerabilityState
	FirstSeen time.Time
	LastSeen  time.Time
	FixedAt   *time.Time
}

// DB wraps the PostgreSQL connection and provides vulnerability operations.
type DB struct {
	conn *sql.DB
}

// NewDB creates a new database connection and ensures schema exists.
func NewDB(ctx context.Context, databaseURL string) (*DB, error) {
	conn, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := conn.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db := &DB{conn: conn}

	// Ensure schema exists
	if err := db.migrate(ctx); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// migrate ensures the database schema exists.
func (db *DB) migrate(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		cve TEXT NOT NULL,
		workload TEXT NOT NULL,
		severity TEXT NOT NULL,
		image TEXT,
		state TEXT NOT NULL DEFAULT 'OPEN',
		first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		fixed_at TIMESTAMPTZ
	);

	CREATE INDEX IF NOT EXISTS idx_vuln_state ON vulnerabilities(state);
	CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
	CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve);
	CREATE INDEX IF NOT EXISTS idx_vuln_workload ON vulnerabilities(workload);
	`

	_, err := db.conn.ExecContext(ctx, schema)
	return err
}

// UpsertVulnerability inserts or updates a vulnerability record.
// Returns true if this is a new vulnerability.
func (db *DB) UpsertVulnerability(ctx context.Context, v *VulnerabilityRecord) (isNew bool, err error) {
	// Check if exists
	var existingState string
	err = db.conn.QueryRowContext(ctx,
		"SELECT state FROM vulnerabilities WHERE id = $1",
		v.ID,
	).Scan(&existingState)

	if err == sql.ErrNoRows {
		// New vulnerability - insert
		_, err = db.conn.ExecContext(ctx, `
			INSERT INTO vulnerabilities (id, cve, workload, severity, image, state, first_seen, last_seen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
		`, v.ID, v.CVE, v.Workload, v.Severity, v.Image, StateOpen, time.Now())
		return true, err
	}

	if err != nil {
		return false, err
	}

	// Existing vulnerability - update last_seen, reopen if was fixed
	if existingState == string(StateFixed) {
		// Reopened!
		_, err = db.conn.ExecContext(ctx, `
			UPDATE vulnerabilities
			SET state = $1, last_seen = $2, fixed_at = NULL, severity = $3, image = $4
			WHERE id = $5
		`, StateOpen, time.Now(), v.Severity, v.Image, v.ID)
		return true, err // Treat reopen as "new" for notification purposes
	}

	// Just update last_seen
	_, err = db.conn.ExecContext(ctx, `
		UPDATE vulnerabilities SET last_seen = $1, severity = $2, image = $3 WHERE id = $4
	`, time.Now(), v.Severity, v.Image, v.ID)
	return false, err
}

// MarkFixed marks vulnerabilities as fixed if they weren't seen in the current scan.
// Returns the list of vulnerabilities that were marked as fixed.
func (db *DB) MarkFixed(ctx context.Context, currentIDs []string) ([]VulnerabilityRecord, error) {
	if len(currentIDs) == 0 {
		// No vulnerabilities in current scan - mark all as fixed
		return db.markAllFixed(ctx)
	}

	// Build query to find OPEN vulnerabilities not in current scan
	query := `
		UPDATE vulnerabilities
		SET state = $1, fixed_at = $2
		WHERE state = $3 AND id != ALL($4)
		RETURNING id, cve, workload, severity, image, first_seen
	`

	now := time.Now()
	rows, err := db.conn.QueryContext(ctx, query, StateFixed, now, StateOpen, pq.Array(currentIDs))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var fixed []VulnerabilityRecord
	for rows.Next() {
		var v VulnerabilityRecord
		if err := rows.Scan(&v.ID, &v.CVE, &v.Workload, &v.Severity, &v.Image, &v.FirstSeen); err != nil {
			return nil, err
		}
		v.State = StateFixed
		v.FixedAt = &now
		fixed = append(fixed, v)
	}

	return fixed, rows.Err()
}

func (db *DB) markAllFixed(ctx context.Context) ([]VulnerabilityRecord, error) {
	query := `
		UPDATE vulnerabilities
		SET state = $1, fixed_at = $2
		WHERE state = $3
		RETURNING id, cve, workload, severity, image, first_seen
	`

	now := time.Now()
	rows, err := db.conn.QueryContext(ctx, query, StateFixed, now, StateOpen)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var fixed []VulnerabilityRecord
	for rows.Next() {
		var v VulnerabilityRecord
		if err := rows.Scan(&v.ID, &v.CVE, &v.Workload, &v.Severity, &v.Image, &v.FirstSeen); err != nil {
			return nil, err
		}
		v.State = StateFixed
		v.FixedAt = &now
		fixed = append(fixed, v)
	}

	return fixed, rows.Err()
}

// GetOpenVulnerabilities returns all open vulnerabilities.
func (db *DB) GetOpenVulnerabilities(ctx context.Context) ([]VulnerabilityRecord, error) {
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, cve, workload, severity, image, state, first_seen, last_seen, fixed_at
		FROM vulnerabilities WHERE state = $1
		ORDER BY
			CASE severity
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH' THEN 2
				WHEN 'MEDIUM' THEN 3
				WHEN 'LOW' THEN 4
				ELSE 5
			END,
			first_seen DESC
	`, StateOpen)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var vulns []VulnerabilityRecord
	for rows.Next() {
		var v VulnerabilityRecord
		if err := rows.Scan(&v.ID, &v.CVE, &v.Workload, &v.Severity, &v.Image, &v.State, &v.FirstSeen, &v.LastSeen, &v.FixedAt); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}

	return vulns, rows.Err()
}

// Stats returns counts of vulnerabilities by state and severity.
type Stats struct {
	TotalOpen  int
	TotalFixed int
	BySeverity map[string]int
}

// GetStats returns vulnerability statistics.
func (db *DB) GetStats(ctx context.Context) (*Stats, error) {
	stats := &Stats{
		BySeverity: make(map[string]int),
	}

	// Count by state
	err := db.conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM vulnerabilities WHERE state = $1", StateOpen,
	).Scan(&stats.TotalOpen)
	if err != nil {
		return nil, err
	}

	err = db.conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM vulnerabilities WHERE state = $1", StateFixed,
	).Scan(&stats.TotalFixed)
	if err != nil {
		return nil, err
	}

	// Count by severity (open only)
	rows, err := db.conn.QueryContext(ctx, `
		SELECT severity, COUNT(*) FROM vulnerabilities
		WHERE state = $1 GROUP BY severity
	`, StateOpen)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		stats.BySeverity[sev] = count
	}

	return stats, rows.Err()
}
