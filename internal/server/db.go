package server

import (
	"context"
	"database/sql"
	"fmt"
	"log"
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
	ID              string // hash(cve + workload + package + container)
	CVE             string
	Workload        string // namespace/kind/name
	Severity        string
	Image           string // package:version (legacy, kept for compatibility)
	ContainerName   string
	ImageRepository string
	ImageTag        string
	ImageDigest     string
	State           VulnerabilityState
	FirstSeen       time.Time
	LastSeen        time.Time
	FixedAt         *time.Time
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
	// Create base table if not exists
	baseSchema := `
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

	if _, err := db.conn.ExecContext(ctx, baseSchema); err != nil {
		return err
	}

	// Migration: add saas_synced column if it doesn't exist (for existing databases)
	if _, err := db.conn.ExecContext(ctx, `
		ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS saas_synced BOOLEAN NOT NULL DEFAULT FALSE
	`); err != nil {
		log.Printf("migration warning: add saas_synced column: %v", err)
	}

	// Create index on saas_synced (after column exists)
	if _, err := db.conn.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_vuln_saas_synced ON vulnerabilities(saas_synced) WHERE NOT saas_synced
	`); err != nil {
		log.Printf("migration warning: create saas_synced index: %v", err)
	}

	// Migration: add container/image tracking columns
	if _, err := db.conn.ExecContext(ctx, `
		ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS container_name TEXT;
		ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS image_repository TEXT;
		ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS image_tag TEXT;
		ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS image_digest TEXT;
	`); err != nil {
		log.Printf("migration warning: add container tracking columns: %v", err)
	}

	// Create index on image_digest for tracking
	if _, err := db.conn.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_vuln_image_digest ON vulnerabilities(image_digest) WHERE image_digest IS NOT NULL
	`); err != nil {
		log.Printf("migration warning: create image_digest index: %v", err)
	}

	return nil
}

// MarkSaasSynced marks vulnerabilities as synced to SaaS.
func (db *DB) MarkSaasSynced(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := db.conn.ExecContext(ctx,
		"UPDATE vulnerabilities SET saas_synced = TRUE WHERE id = ANY($1)",
		pq.Array(ids),
	)
	return err
}

// GetUnsyncedVulnerabilities returns vulnerabilities that haven't been synced to SaaS.
func (db *DB) GetUnsyncedVulnerabilities(ctx context.Context) ([]VulnerabilityRecord, error) {
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, cve, workload, severity, image,
		       COALESCE(container_name, ''), COALESCE(image_repository, ''), COALESCE(image_tag, ''), COALESCE(image_digest, ''),
		       state, first_seen, last_seen, fixed_at
		FROM vulnerabilities
		WHERE NOT saas_synced
		ORDER BY first_seen ASC
		LIMIT 500
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var vulns []VulnerabilityRecord
	for rows.Next() {
		var v VulnerabilityRecord
		if err := rows.Scan(&v.ID, &v.CVE, &v.Workload, &v.Severity, &v.Image,
			&v.ContainerName, &v.ImageRepository, &v.ImageTag, &v.ImageDigest,
			&v.State, &v.FirstSeen, &v.LastSeen, &v.FixedAt); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}

	return vulns, rows.Err()
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
			INSERT INTO vulnerabilities (id, cve, workload, severity, image, container_name, image_repository, image_tag, image_digest, state, first_seen, last_seen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
		`, v.ID, v.CVE, v.Workload, v.Severity, v.Image, v.ContainerName, v.ImageRepository, v.ImageTag, v.ImageDigest, StateOpen, time.Now())
		return true, err
	}

	if err != nil {
		return false, err
	}

	// Existing vulnerability - update last_seen, reopen if was fixed
	if existingState == string(StateFixed) {
		// Reopened! Reset saas_synced so reopen event gets sent to SaaS
		_, err = db.conn.ExecContext(ctx, `
			UPDATE vulnerabilities
			SET state = $1, last_seen = $2, fixed_at = NULL, severity = $3, image = $4,
			    container_name = $5, image_repository = $6, image_tag = $7, image_digest = $8,
			    saas_synced = FALSE
			WHERE id = $9
		`, StateOpen, time.Now(), v.Severity, v.Image, v.ContainerName, v.ImageRepository, v.ImageTag, v.ImageDigest, v.ID)
		return true, err // Treat reopen as "new" for notification purposes
	}

	// Just update last_seen and image info
	_, err = db.conn.ExecContext(ctx, `
		UPDATE vulnerabilities
		SET last_seen = $1, severity = $2, image = $3, container_name = $4, image_repository = $5, image_tag = $6, image_digest = $7
		WHERE id = $8
	`, time.Now(), v.Severity, v.Image, v.ContainerName, v.ImageRepository, v.ImageTag, v.ImageDigest, v.ID)
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
		RETURNING id, cve, workload, severity, image,
		          COALESCE(container_name, ''), COALESCE(image_repository, ''), COALESCE(image_tag, ''), COALESCE(image_digest, ''),
		          first_seen
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
		if err := rows.Scan(&v.ID, &v.CVE, &v.Workload, &v.Severity, &v.Image,
			&v.ContainerName, &v.ImageRepository, &v.ImageTag, &v.ImageDigest,
			&v.FirstSeen); err != nil {
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
		RETURNING id, cve, workload, severity, image,
		          COALESCE(container_name, ''), COALESCE(image_repository, ''), COALESCE(image_tag, ''), COALESCE(image_digest, ''),
		          first_seen
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
		if err := rows.Scan(&v.ID, &v.CVE, &v.Workload, &v.Severity, &v.Image,
			&v.ContainerName, &v.ImageRepository, &v.ImageTag, &v.ImageDigest,
			&v.FirstSeen); err != nil {
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
		SELECT id, cve, workload, severity, image,
		       COALESCE(container_name, ''), COALESCE(image_repository, ''), COALESCE(image_tag, ''), COALESCE(image_digest, ''),
		       state, first_seen, last_seen, fixed_at
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
		if err := rows.Scan(&v.ID, &v.CVE, &v.Workload, &v.Severity, &v.Image,
			&v.ContainerName, &v.ImageRepository, &v.ImageTag, &v.ImageDigest,
			&v.State, &v.FirstSeen, &v.LastSeen, &v.FixedAt); err != nil {
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
