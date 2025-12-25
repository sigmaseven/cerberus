package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

// =============================================================================
// SQLite IOC Storage Implementation
// =============================================================================

// SQLiteIOCStorage implements core.IOCStorage using SQLite
type SQLiteIOCStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteIOCStorage creates a new IOC storage instance
func NewSQLiteIOCStorage(sqlite *SQLite, logger *zap.SugaredLogger) (*SQLiteIOCStorage, error) {
	storage := &SQLiteIOCStorage{
		sqlite: sqlite,
		logger: logger,
	}

	if err := storage.ensureTables(); err != nil {
		return nil, fmt.Errorf("failed to ensure IOC tables: %w", err)
	}

	return storage, nil
}

// ensureTables creates IOC tables if they don't exist
func (s *SQLiteIOCStorage) ensureTables() error {
	schema := `
	-- IOC main table
	CREATE TABLE IF NOT EXISTS iocs (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL CHECK(type IN ('ip','cidr','domain','hash','url','email','filename','registry_key','cve','ja3')),
		value TEXT NOT NULL,
		normalized TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','deprecated','archived','whitelist')),
		severity TEXT NOT NULL DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),
		confidence REAL NOT NULL DEFAULT 50.0 CHECK(confidence >= 0 AND confidence <= 100),
		description TEXT DEFAULT '',
		tags TEXT DEFAULT '[]',
		source TEXT DEFAULT '',
		refs TEXT DEFAULT '[]',
		mitre_techniques TEXT DEFAULT '[]',
		threat_intel TEXT DEFAULT '{}',
		created_by TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		first_seen DATETIME,
		last_seen DATETIME,
		expires_at DATETIME,
		hit_count INTEGER NOT NULL DEFAULT 0
	);

	-- Performance indexes
	CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
	CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status);
	CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
	CREATE INDEX IF NOT EXISTS idx_iocs_normalized ON iocs(normalized);
	CREATE INDEX IF NOT EXISTS idx_iocs_created_at ON iocs(created_at);
	CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_type_normalized ON iocs(type, normalized);

	-- IOC-Investigation relationship table
	CREATE TABLE IF NOT EXISTS ioc_investigations (
		ioc_id TEXT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
		investigation_id TEXT NOT NULL,
		linked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		linked_by TEXT DEFAULT '',
		PRIMARY KEY (ioc_id, investigation_id)
	);
	CREATE INDEX IF NOT EXISTS idx_ioc_inv_investigation ON ioc_investigations(investigation_id);

	-- IOC-Alert relationship table
	CREATE TABLE IF NOT EXISTS ioc_alerts (
		ioc_id TEXT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
		alert_id TEXT NOT NULL,
		linked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (ioc_id, alert_id)
	);
	CREATE INDEX IF NOT EXISTS idx_ioc_alerts_alert ON ioc_alerts(alert_id);

	-- IOC Hunt jobs table
	CREATE TABLE IF NOT EXISTS ioc_hunts (
		id TEXT PRIMARY KEY,
		status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','cancelled')),
		ioc_ids TEXT NOT NULL DEFAULT '[]',
		time_range_start DATETIME NOT NULL,
		time_range_end DATETIME NOT NULL,
		created_by TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		started_at DATETIME,
		completed_at DATETIME,
		progress REAL NOT NULL DEFAULT 0,
		total_events INTEGER NOT NULL DEFAULT 0,
		match_count INTEGER NOT NULL DEFAULT 0,
		error TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_ioc_hunts_status ON ioc_hunts(status);
	CREATE INDEX IF NOT EXISTS idx_ioc_hunts_created_at ON ioc_hunts(created_at);

	-- IOC Match results table
	CREATE TABLE IF NOT EXISTS ioc_matches (
		id TEXT PRIMARY KEY,
		ioc_id TEXT NOT NULL,
		hunt_id TEXT DEFAULT '',
		event_id TEXT NOT NULL,
		matched_field TEXT NOT NULL,
		matched_value TEXT NOT NULL,
		event_timestamp DATETIME NOT NULL,
		detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_ioc_matches_ioc ON ioc_matches(ioc_id);
	CREATE INDEX IF NOT EXISTS idx_ioc_matches_hunt ON ioc_matches(hunt_id);
	CREATE INDEX IF NOT EXISTS idx_ioc_matches_detected ON ioc_matches(detected_at);
	`

	_, err := s.sqlite.DB.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create IOC tables: %w", err)
	}

	s.logger.Info("IOC tables ensured in SQLite")
	return nil
}

// =============================================================================
// JSON Size Limits (GATEKEEPER FIX BLOCKER-3: Prevent memory exhaustion)
// =============================================================================

const (
	// Maximum size for JSON fields to prevent memory exhaustion attacks
	maxJSONFieldSize = 1 << 20 // 1MB limit for JSON fields
)

// safeUnmarshalJSON unmarshals JSON with size validation
// GATEKEEPER FIX (BLOCKER-3): Prevent memory exhaustion from oversized JSON
func safeUnmarshalJSON(data string, v interface{}) error {
	if len(data) > maxJSONFieldSize {
		return fmt.Errorf("JSON field exceeds maximum size (%d > %d bytes)", len(data), maxJSONFieldSize)
	}
	if data == "" || data == "null" {
		return nil
	}
	return json.Unmarshal([]byte(data), v)
}

// =============================================================================
// Allowed Sort Fields (GATEKEEPER FIX: Prevent SQL injection in ORDER BY)
// =============================================================================

var allowedIOCSortFields = map[string]string{
	"created_at": "created_at",
	"updated_at": "updated_at",
	"last_seen":  "last_seen",
	"first_seen": "first_seen",
	"hit_count":  "hit_count",
	"confidence": "confidence",
	"severity":   "severity",
	"type":       "type",
	"status":     "status",
}

var allowedSortOrders = map[string]bool{
	"asc":  true,
	"desc": true,
	"ASC":  true,
	"DESC": true,
}

func validateSortParams(sortBy, sortOrder string) (string, string, error) {
	if sortBy == "" {
		sortBy = "created_at"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}

	field, ok := allowedIOCSortFields[sortBy]
	if !ok {
		return "", "", fmt.Errorf("invalid sort field: %s", sortBy)
	}

	if !allowedSortOrders[sortOrder] {
		return "", "", fmt.Errorf("invalid sort order: %s", sortOrder)
	}

	return field, strings.ToUpper(sortOrder), nil
}

// =============================================================================
// CRUD Operations
// =============================================================================

// CreateIOC stores a new IOC in the database
func (s *SQLiteIOCStorage) CreateIOC(ctx context.Context, ioc *core.IOC) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Validate before insert
	if err := ioc.Validate(); err != nil {
		return fmt.Errorf("IOC validation failed: %w", err)
	}

	// Ensure normalized value is set
	if ioc.Normalized == "" {
		ioc.Normalized = core.NormalizeIOCValue(ioc.Type, ioc.Value)
	}

	// Serialize JSON fields
	tagsJSON, _ := json.Marshal(ioc.Tags)
	refsJSON, _ := json.Marshal(ioc.References)
	mitreJSON, _ := json.Marshal(ioc.MitreTechniques)
	threatIntelJSON, _ := json.Marshal(ioc.ThreatIntel)

	query := `
		INSERT INTO iocs (
			id, type, value, normalized, status, severity, confidence,
			description, tags, source, refs, mitre_techniques, threat_intel,
			created_by, created_at, updated_at, first_seen, last_seen, expires_at, hit_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.sqlite.DB.ExecContext(ctx, query,
		ioc.ID, ioc.Type, ioc.Value, ioc.Normalized, ioc.Status, ioc.Severity, ioc.Confidence,
		ioc.Description, string(tagsJSON), ioc.Source, string(refsJSON), string(mitreJSON), string(threatIntelJSON),
		ioc.CreatedBy, ioc.CreatedAt, ioc.UpdatedAt, ioc.FirstSeen, ioc.LastSeen, ioc.ExpiresAt, ioc.HitCount,
	)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("IOC with this type and value already exists")
		}
		return fmt.Errorf("failed to create IOC: %w", err)
	}

	s.logger.Infow("IOC created",
		"ioc_id", ioc.ID,
		"type", ioc.Type,
		"status", ioc.Status,
		"created_by", ioc.CreatedBy,
	)

	return nil
}

// GetIOC retrieves an IOC by ID
func (s *SQLiteIOCStorage) GetIOC(ctx context.Context, id string) (*core.IOC, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, type, value, normalized, status, severity, confidence,
			description, tags, source, refs, mitre_techniques, threat_intel,
			created_by, created_at, updated_at, first_seen, last_seen, expires_at, hit_count
		FROM iocs WHERE id = ?
	`

	var ioc core.IOC
	var tagsJSON, refsJSON, mitreJSON, threatIntelJSON string
	var firstSeen, lastSeen, expiresAt sql.NullTime

	err := s.sqlite.DB.QueryRowContext(ctx, query, id).Scan(
		&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Normalized, &ioc.Status, &ioc.Severity, &ioc.Confidence,
		&ioc.Description, &tagsJSON, &ioc.Source, &refsJSON, &mitreJSON, &threatIntelJSON,
		&ioc.CreatedBy, &ioc.CreatedAt, &ioc.UpdatedAt, &firstSeen, &lastSeen, &expiresAt, &ioc.HitCount,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get IOC: %w", err)
	}

	// Parse JSON fields (GATEKEEPER FIX BLOCKER-3: Safe unmarshal with size limits)
	if err := safeUnmarshalJSON(tagsJSON, &ioc.Tags); err != nil {
		s.logger.Warnw("Failed to parse IOC tags JSON", "ioc_id", ioc.ID, "error", err)
	}
	if err := safeUnmarshalJSON(refsJSON, &ioc.References); err != nil {
		s.logger.Warnw("Failed to parse IOC references JSON", "ioc_id", ioc.ID, "error", err)
	}
	if err := safeUnmarshalJSON(mitreJSON, &ioc.MitreTechniques); err != nil {
		s.logger.Warnw("Failed to parse IOC MITRE JSON", "ioc_id", ioc.ID, "error", err)
	}
	if err := safeUnmarshalJSON(threatIntelJSON, &ioc.ThreatIntel); err != nil {
		s.logger.Warnw("Failed to parse IOC threat intel JSON", "ioc_id", ioc.ID, "error", err)
	}

	if firstSeen.Valid {
		ioc.FirstSeen = &firstSeen.Time
	}
	if lastSeen.Valid {
		ioc.LastSeen = &lastSeen.Time
	}
	if expiresAt.Valid {
		ioc.ExpiresAt = &expiresAt.Time
	}

	return &ioc, nil
}

// UpdateIOC updates an existing IOC
func (s *SQLiteIOCStorage) UpdateIOC(ctx context.Context, ioc *core.IOC) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Validate before update
	if err := ioc.Validate(); err != nil {
		return fmt.Errorf("IOC validation failed: %w", err)
	}

	// Update timestamp
	ioc.UpdatedAt = time.Now().UTC()

	// Serialize JSON fields
	tagsJSON, _ := json.Marshal(ioc.Tags)
	refsJSON, _ := json.Marshal(ioc.References)
	mitreJSON, _ := json.Marshal(ioc.MitreTechniques)
	threatIntelJSON, _ := json.Marshal(ioc.ThreatIntel)

	query := `
		UPDATE iocs SET
			type = ?, value = ?, normalized = ?, status = ?, severity = ?, confidence = ?,
			description = ?, tags = ?, source = ?, refs = ?, mitre_techniques = ?, threat_intel = ?,
			updated_at = ?, first_seen = ?, last_seen = ?, expires_at = ?, hit_count = ?
		WHERE id = ?
	`

	result, err := s.sqlite.DB.ExecContext(ctx, query,
		ioc.Type, ioc.Value, ioc.Normalized, ioc.Status, ioc.Severity, ioc.Confidence,
		ioc.Description, string(tagsJSON), ioc.Source, string(refsJSON), string(mitreJSON), string(threatIntelJSON),
		ioc.UpdatedAt, ioc.FirstSeen, ioc.LastSeen, ioc.ExpiresAt, ioc.HitCount,
		ioc.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update IOC: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}

	s.logger.Infow("IOC updated", "ioc_id", ioc.ID, "status", ioc.Status)
	return nil
}

// DeleteIOC removes an IOC by ID
func (s *SQLiteIOCStorage) DeleteIOC(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result, err := s.sqlite.DB.ExecContext(ctx, "DELETE FROM iocs WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete IOC: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}

	s.logger.Infow("IOC deleted", "ioc_id", id)
	return nil
}

// =============================================================================
// Listing and Search
// =============================================================================

// ListIOCs retrieves IOCs with filtering and pagination
func (s *SQLiteIOCStorage) ListIOCs(ctx context.Context, filters *core.IOCFilters) ([]*core.IOC, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Build WHERE clause
	var conditions []string
	var args []interface{}

	if len(filters.Types) > 0 {
		placeholders := make([]string, len(filters.Types))
		for i, t := range filters.Types {
			placeholders[i] = "?"
			args = append(args, string(t))
		}
		conditions = append(conditions, fmt.Sprintf("type IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filters.Statuses) > 0 {
		placeholders := make([]string, len(filters.Statuses))
		for i, s := range filters.Statuses {
			placeholders[i] = "?"
			args = append(args, string(s))
		}
		conditions = append(conditions, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filters.Severities) > 0 {
		placeholders := make([]string, len(filters.Severities))
		for i, sev := range filters.Severities {
			placeholders[i] = "?"
			args = append(args, string(sev))
		}
		conditions = append(conditions, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ",")))
	}

	if filters.Source != "" {
		conditions = append(conditions, "source = ?")
		args = append(args, filters.Source)
	}

	if filters.Search != "" {
		conditions = append(conditions, "(normalized LIKE ? OR description LIKE ?)")
		searchPattern := "%" + filters.Search + "%"
		args = append(args, searchPattern, searchPattern)
	}

	if filters.MinConfidence > 0 {
		conditions = append(conditions, "confidence >= ?")
		args = append(args, filters.MinConfidence)
	}

	if filters.CreatedAfter != nil {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, *filters.CreatedAfter)
	}

	if filters.CreatedBefore != nil {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, *filters.CreatedBefore)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Validate and build ORDER BY (GATEKEEPER FIX: Prevent SQL injection)
	sortField, sortOrder, err := validateSortParams(filters.SortBy, filters.SortOrder)
	if err != nil {
		return nil, 0, err
	}
	orderBy := fmt.Sprintf("ORDER BY %s %s", sortField, sortOrder)

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM iocs %s", whereClause)
	var total int64
	if err := s.sqlite.DB.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count IOCs: %w", err)
	}

	// Apply pagination
	limit := filters.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := filters.Offset
	if offset < 0 {
		offset = 0
	}

	// Query IOCs
	query := fmt.Sprintf(`
		SELECT id, type, value, normalized, status, severity, confidence,
			description, tags, source, refs, mitre_techniques, threat_intel,
			created_by, created_at, updated_at, first_seen, last_seen, expires_at, hit_count
		FROM iocs %s %s LIMIT ? OFFSET ?
	`, whereClause, orderBy)

	args = append(args, limit, offset)
	rows, err := s.sqlite.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list IOCs: %w", err)
	}
	defer rows.Close()

	return s.scanIOCRows(rows), total, nil
}

// scanIOCRows scans multiple IOC rows into a slice
func (s *SQLiteIOCStorage) scanIOCRows(rows *sql.Rows) []*core.IOC {
	var iocs []*core.IOC

	for rows.Next() {
		var ioc core.IOC
		var tagsJSON, refsJSON, mitreJSON, threatIntelJSON string
		var firstSeen, lastSeen, expiresAt sql.NullTime

		err := rows.Scan(
			&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Normalized, &ioc.Status, &ioc.Severity, &ioc.Confidence,
			&ioc.Description, &tagsJSON, &ioc.Source, &refsJSON, &mitreJSON, &threatIntelJSON,
			&ioc.CreatedBy, &ioc.CreatedAt, &ioc.UpdatedAt, &firstSeen, &lastSeen, &expiresAt, &ioc.HitCount,
		)
		if err != nil {
			s.logger.Warnw("Failed to scan IOC row", "error", err)
			continue
		}

		// Parse JSON fields (GATEKEEPER FIX BLOCKER-3: Safe unmarshal)
		safeUnmarshalJSON(tagsJSON, &ioc.Tags)
		safeUnmarshalJSON(refsJSON, &ioc.References)
		safeUnmarshalJSON(mitreJSON, &ioc.MitreTechniques)
		safeUnmarshalJSON(threatIntelJSON, &ioc.ThreatIntel)

		if firstSeen.Valid {
			ioc.FirstSeen = &firstSeen.Time
		}
		if lastSeen.Valid {
			ioc.LastSeen = &lastSeen.Time
		}
		if expiresAt.Valid {
			ioc.ExpiresAt = &expiresAt.Time
		}

		iocs = append(iocs, &ioc)
	}

	return iocs
}

// FindByValue finds an IOC by its normalized value
func (s *SQLiteIOCStorage) FindByValue(ctx context.Context, iocType core.IOCType, normalizedValue string) (*core.IOC, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, type, value, normalized, status, severity, confidence,
			description, tags, source, refs, mitre_techniques, threat_intel,
			created_by, created_at, updated_at, first_seen, last_seen, expires_at, hit_count
		FROM iocs WHERE type = ? AND normalized = ?
	`

	var ioc core.IOC
	var tagsJSON, refsJSON, mitreJSON, threatIntelJSON string
	var firstSeen, lastSeen, expiresAt sql.NullTime

	err := s.sqlite.DB.QueryRowContext(ctx, query, string(iocType), normalizedValue).Scan(
		&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Normalized, &ioc.Status, &ioc.Severity, &ioc.Confidence,
		&ioc.Description, &tagsJSON, &ioc.Source, &refsJSON, &mitreJSON, &threatIntelJSON,
		&ioc.CreatedBy, &ioc.CreatedAt, &ioc.UpdatedAt, &firstSeen, &lastSeen, &expiresAt, &ioc.HitCount,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find IOC: %w", err)
	}

	// Parse JSON fields (GATEKEEPER FIX BLOCKER-3: Safe unmarshal)
	safeUnmarshalJSON(tagsJSON, &ioc.Tags)
	safeUnmarshalJSON(refsJSON, &ioc.References)
	safeUnmarshalJSON(mitreJSON, &ioc.MitreTechniques)
	safeUnmarshalJSON(threatIntelJSON, &ioc.ThreatIntel)

	if firstSeen.Valid {
		ioc.FirstSeen = &firstSeen.Time
	}
	if lastSeen.Valid {
		ioc.LastSeen = &lastSeen.Time
	}
	if expiresAt.Valid {
		ioc.ExpiresAt = &expiresAt.Time
	}

	return &ioc, nil
}

// SearchIOCs performs a text search on IOC values
func (s *SQLiteIOCStorage) SearchIOCs(ctx context.Context, query string, limit int) ([]*core.IOC, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	filters := &core.IOCFilters{
		Search: query,
		Limit:  limit,
		SortBy: "hit_count",
		SortOrder: "desc",
	}

	iocs, _, err := s.ListIOCs(ctx, filters)
	return iocs, err
}

// =============================================================================
// Bulk Operations (GATEKEEPER FIX: Use transactions)
// =============================================================================

// BulkCreateIOCs creates multiple IOCs in a single transaction
func (s *SQLiteIOCStorage) BulkCreateIOCs(ctx context.Context, iocs []*core.IOC) (created int, skipped int, err error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	if len(iocs) == 0 {
		return 0, 0, nil
	}

	// GATEKEEPER FIX: Use transaction for atomicity
	tx, err := s.sqlite.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // Auto-rollback on error or panic

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO iocs (
			id, type, value, normalized, status, severity, confidence,
			description, tags, source, refs, mitre_techniques, threat_intel,
			created_by, created_at, updated_at, first_seen, last_seen, expires_at, hit_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, ioc := range iocs {
		// Validate each IOC
		if err := ioc.Validate(); err != nil {
			skipped++
			continue
		}

		// Ensure normalized value
		if ioc.Normalized == "" {
			ioc.Normalized = core.NormalizeIOCValue(ioc.Type, ioc.Value)
		}

		// Serialize JSON fields
		tagsJSON, _ := json.Marshal(ioc.Tags)
		refsJSON, _ := json.Marshal(ioc.References)
		mitreJSON, _ := json.Marshal(ioc.MitreTechniques)
		threatIntelJSON, _ := json.Marshal(ioc.ThreatIntel)

		_, execErr := stmt.ExecContext(ctx,
			ioc.ID, ioc.Type, ioc.Value, ioc.Normalized, ioc.Status, ioc.Severity, ioc.Confidence,
			ioc.Description, string(tagsJSON), ioc.Source, string(refsJSON), string(mitreJSON), string(threatIntelJSON),
			ioc.CreatedBy, ioc.CreatedAt, ioc.UpdatedAt, ioc.FirstSeen, ioc.LastSeen, ioc.ExpiresAt, ioc.HitCount,
		)

		if execErr != nil {
			if strings.Contains(execErr.Error(), "UNIQUE constraint failed") {
				skipped++
				continue
			}
			return created, skipped, fmt.Errorf("bulk insert failed at item %d: %w", created, execErr)
		}
		created++
	}

	// GATEKEEPER FIX: Commit transaction
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("transaction commit failed: %w", err)
	}

	s.logger.Infow("Bulk IOC import completed", "created", created, "skipped", skipped)
	return created, skipped, nil
}

// BulkUpdateStatus updates the status of multiple IOCs
func (s *SQLiteIOCStorage) BulkUpdateStatus(ctx context.Context, ids []string, status core.IOCStatus) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if len(ids) == 0 {
		return nil
	}

	if !status.IsValid() {
		return fmt.Errorf("invalid status: %s", status)
	}

	// GATEKEEPER FIX: Use transaction
	tx, err := s.sqlite.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids)+2)
	args[0] = status
	args[1] = time.Now().UTC()

	for i, id := range ids {
		placeholders[i] = "?"
		args[i+2] = id
	}

	query := fmt.Sprintf(
		"UPDATE iocs SET status = ?, updated_at = ? WHERE id IN (%s)",
		strings.Join(placeholders, ","),
	)

	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update IOC statuses: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("transaction commit failed: %w", err)
	}

	s.logger.Infow("Bulk IOC status update", "count", len(ids), "new_status", status)
	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetIOCStats returns aggregated IOC statistics
func (s *SQLiteIOCStorage) GetIOCStats(ctx context.Context) (*core.IOCStatistics, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	stats := &core.IOCStatistics{
		ByType:     make(map[string]int64),
		ByStatus:   make(map[string]int64),
		BySeverity: make(map[string]int64),
	}

	// Total count
	s.sqlite.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM iocs").Scan(&stats.TotalCount)

	// By type
	rows, _ := s.sqlite.DB.QueryContext(ctx, "SELECT type, COUNT(*) FROM iocs GROUP BY type")
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t string
			var count int64
			rows.Scan(&t, &count)
			stats.ByType[t] = count
		}
	}

	// By status
	rows, _ = s.sqlite.DB.QueryContext(ctx, "SELECT status, COUNT(*) FROM iocs GROUP BY status")
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var st string
			var count int64
			rows.Scan(&st, &count)
			stats.ByStatus[st] = count
			if st == "active" {
				stats.ActiveCount = count
			}
			if st == "whitelist" {
				stats.WhitelistCount = count
			}
		}
	}

	// By severity
	rows, _ = s.sqlite.DB.QueryContext(ctx, "SELECT severity, COUNT(*) FROM iocs GROUP BY severity")
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var count int64
			rows.Scan(&sev, &count)
			stats.BySeverity[sev] = count
		}
	}

	// Recent matches (24h)
	s.sqlite.DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM ioc_matches WHERE detected_at >= datetime('now', '-24 hours')",
	).Scan(&stats.RecentMatches24h)

	return stats, nil
}

// =============================================================================
// Relationship Management
// =============================================================================

// LinkToInvestigation links an IOC to an investigation
func (s *SQLiteIOCStorage) LinkToInvestigation(ctx context.Context, iocID, investigationID, linkedBy string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := s.sqlite.DB.ExecContext(ctx,
		"INSERT OR IGNORE INTO ioc_investigations (ioc_id, investigation_id, linked_by) VALUES (?, ?, ?)",
		iocID, investigationID, linkedBy,
	)
	return err
}

// UnlinkFromInvestigation removes a link between IOC and investigation
func (s *SQLiteIOCStorage) UnlinkFromInvestigation(ctx context.Context, iocID, investigationID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := s.sqlite.DB.ExecContext(ctx,
		"DELETE FROM ioc_investigations WHERE ioc_id = ? AND investigation_id = ?",
		iocID, investigationID,
	)
	return err
}

// GetLinkedInvestigations returns all investigation IDs linked to an IOC
func (s *SQLiteIOCStorage) GetLinkedInvestigations(ctx context.Context, iocID string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := s.sqlite.DB.QueryContext(ctx,
		"SELECT investigation_id FROM ioc_investigations WHERE ioc_id = ?",
		iocID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids, nil
}

// LinkToAlert links an IOC to an alert
func (s *SQLiteIOCStorage) LinkToAlert(ctx context.Context, iocID, alertID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := s.sqlite.DB.ExecContext(ctx,
		"INSERT OR IGNORE INTO ioc_alerts (ioc_id, alert_id) VALUES (?, ?)",
		iocID, alertID,
	)
	return err
}

// GetLinkedAlerts returns all alert IDs linked to an IOC
func (s *SQLiteIOCStorage) GetLinkedAlerts(ctx context.Context, iocID string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := s.sqlite.DB.QueryContext(ctx,
		"SELECT alert_id FROM ioc_alerts WHERE ioc_id = ?",
		iocID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids, nil
}

// =============================================================================
// Hunt Management
// =============================================================================

// CreateHunt creates a new hunt job
func (s *SQLiteIOCStorage) CreateHunt(ctx context.Context, hunt *core.IOCHunt) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	iocIDsJSON, _ := json.Marshal(hunt.IOCIDs)

	_, err := s.sqlite.DB.ExecContext(ctx, `
		INSERT INTO ioc_hunts (
			id, status, ioc_ids, time_range_start, time_range_end,
			created_by, created_at, progress, total_events, match_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		hunt.ID, hunt.Status, string(iocIDsJSON), hunt.TimeRangeStart, hunt.TimeRangeEnd,
		hunt.CreatedBy, hunt.CreatedAt, hunt.Progress, hunt.TotalEvents, hunt.MatchCount,
	)

	if err != nil {
		return fmt.Errorf("failed to create hunt: %w", err)
	}

	s.logger.Infow("Hunt created", "hunt_id", hunt.ID, "ioc_count", len(hunt.IOCIDs))
	return nil
}

// GetHunt retrieves a hunt by ID
func (s *SQLiteIOCStorage) GetHunt(ctx context.Context, id string) (*core.IOCHunt, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var hunt core.IOCHunt
	var iocIDsJSON string
	var startedAt, completedAt sql.NullTime
	var errStr sql.NullString

	err := s.sqlite.DB.QueryRowContext(ctx, `
		SELECT id, status, ioc_ids, time_range_start, time_range_end,
			created_by, created_at, started_at, completed_at, progress, total_events, match_count, error
		FROM ioc_hunts WHERE id = ?
	`, id).Scan(
		&hunt.ID, &hunt.Status, &iocIDsJSON, &hunt.TimeRangeStart, &hunt.TimeRangeEnd,
		&hunt.CreatedBy, &hunt.CreatedAt, &startedAt, &completedAt, &hunt.Progress, &hunt.TotalEvents, &hunt.MatchCount, &errStr,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get hunt: %w", err)
	}

	// GATEKEEPER FIX (BLOCKER-3): Safe unmarshal with size limits
	safeUnmarshalJSON(iocIDsJSON, &hunt.IOCIDs)

	if startedAt.Valid {
		hunt.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		hunt.CompletedAt = &completedAt.Time
	}
	if errStr.Valid {
		hunt.Error = errStr.String
	}

	return &hunt, nil
}

// UpdateHuntStatus updates the status of a hunt
func (s *SQLiteIOCStorage) UpdateHuntStatus(ctx context.Context, id string, status core.HuntStatus) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var startedAt interface{}
	if status == core.HuntStatusRunning {
		now := time.Now().UTC()
		startedAt = now
	}

	_, err := s.sqlite.DB.ExecContext(ctx,
		"UPDATE ioc_hunts SET status = ?, started_at = COALESCE(?, started_at) WHERE id = ?",
		status, startedAt, id,
	)
	return err
}

// UpdateHuntProgress updates hunt progress
func (s *SQLiteIOCStorage) UpdateHuntProgress(ctx context.Context, id string, progress float64, matchCount, totalEvents int64) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := s.sqlite.DB.ExecContext(ctx,
		"UPDATE ioc_hunts SET progress = ?, match_count = ?, total_events = ? WHERE id = ?",
		progress, matchCount, totalEvents, id,
	)
	return err
}

// CompleteHunt marks a hunt as completed or failed
func (s *SQLiteIOCStorage) CompleteHunt(ctx context.Context, id string, matchCount, totalEvents int64, huntErr error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	status := core.HuntStatusCompleted
	var errStr string
	if huntErr != nil {
		status = core.HuntStatusFailed
		errStr = huntErr.Error()
	}

	now := time.Now().UTC()
	_, err := s.sqlite.DB.ExecContext(ctx, `
		UPDATE ioc_hunts SET
			status = ?, completed_at = ?, progress = 100,
			match_count = ?, total_events = ?, error = ?
		WHERE id = ?
	`, status, now, matchCount, totalEvents, errStr, id)

	return err
}

// ListHunts lists all hunts with pagination
func (s *SQLiteIOCStorage) ListHunts(ctx context.Context, limit, offset int) ([]*core.IOCHunt, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	var total int64
	s.sqlite.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM ioc_hunts").Scan(&total)

	rows, err := s.sqlite.DB.QueryContext(ctx, `
		SELECT id, status, ioc_ids, time_range_start, time_range_end,
			created_by, created_at, started_at, completed_at, progress, total_events, match_count, error
		FROM ioc_hunts ORDER BY created_at DESC LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list hunts: %w", err)
	}
	defer rows.Close()

	var hunts []*core.IOCHunt
	for rows.Next() {
		var hunt core.IOCHunt
		var iocIDsJSON string
		var startedAt, completedAt sql.NullTime
		var errStr sql.NullString

		rows.Scan(
			&hunt.ID, &hunt.Status, &iocIDsJSON, &hunt.TimeRangeStart, &hunt.TimeRangeEnd,
			&hunt.CreatedBy, &hunt.CreatedAt, &startedAt, &completedAt, &hunt.Progress, &hunt.TotalEvents, &hunt.MatchCount, &errStr,
		)

		// GATEKEEPER FIX (BLOCKER-3): Safe unmarshal with size limits
		safeUnmarshalJSON(iocIDsJSON, &hunt.IOCIDs)

		if startedAt.Valid {
			hunt.StartedAt = &startedAt.Time
		}
		if completedAt.Valid {
			hunt.CompletedAt = &completedAt.Time
		}
		if errStr.Valid {
			hunt.Error = errStr.String
		}

		hunts = append(hunts, &hunt)
	}

	return hunts, total, nil
}

// =============================================================================
// Match Recording
// =============================================================================

// RecordMatch records an IOC match
func (s *SQLiteIOCStorage) RecordMatch(ctx context.Context, match *core.IOCMatch) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := s.sqlite.DB.ExecContext(ctx, `
		INSERT INTO ioc_matches (id, ioc_id, hunt_id, event_id, matched_field, matched_value, event_timestamp, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		match.ID, match.IOCID, match.HuntID, match.EventID, match.MatchedField, match.MatchedValue, match.EventTimestamp, match.DetectedAt,
	)

	return err
}

// BulkRecordMatches records multiple IOC matches in a single transaction
// GATEKEEPER RECOMMENDATION: Bulk insert for performance optimization
func (s *SQLiteIOCStorage) BulkRecordMatches(ctx context.Context, matches []*core.IOCMatch) (int, error) {
	if len(matches) == 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	tx, err := s.sqlite.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO ioc_matches (id, ioc_id, hunt_id, event_id, matched_field, matched_value, event_timestamp, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	recorded := 0
	for _, match := range matches {
		_, err := stmt.ExecContext(ctx,
			match.ID, match.IOCID, match.HuntID, match.EventID,
			match.MatchedField, match.MatchedValue, match.EventTimestamp, match.DetectedAt,
		)
		if err != nil {
			s.logger.Warnw("Failed to insert match in bulk operation", "match_id", match.ID, "error", err)
			continue
		}
		recorded++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("transaction commit failed: %w", err)
	}

	return recorded, nil
}

// GetMatchesByHunt retrieves matches for a hunt
func (s *SQLiteIOCStorage) GetMatchesByHunt(ctx context.Context, huntID string, limit, offset int) ([]*core.IOCMatch, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// GATEKEEPER FIX: Enforce max limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var total int64
	s.sqlite.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM ioc_matches WHERE hunt_id = ?", huntID).Scan(&total)

	rows, err := s.sqlite.DB.QueryContext(ctx, `
		SELECT id, ioc_id, hunt_id, event_id, matched_field, matched_value, event_timestamp, detected_at
		FROM ioc_matches WHERE hunt_id = ? ORDER BY detected_at DESC LIMIT ? OFFSET ?
	`, huntID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var matches []*core.IOCMatch
	for rows.Next() {
		var m core.IOCMatch
		rows.Scan(&m.ID, &m.IOCID, &m.HuntID, &m.EventID, &m.MatchedField, &m.MatchedValue, &m.EventTimestamp, &m.DetectedAt)
		matches = append(matches, &m)
	}

	return matches, total, nil
}

// GetMatchesByIOC retrieves matches for an IOC
func (s *SQLiteIOCStorage) GetMatchesByIOC(ctx context.Context, iocID string, limit, offset int) ([]*core.IOCMatch, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var total int64
	s.sqlite.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM ioc_matches WHERE ioc_id = ?", iocID).Scan(&total)

	rows, err := s.sqlite.DB.QueryContext(ctx, `
		SELECT id, ioc_id, hunt_id, event_id, matched_field, matched_value, event_timestamp, detected_at
		FROM ioc_matches WHERE ioc_id = ? ORDER BY detected_at DESC LIMIT ? OFFSET ?
	`, iocID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var matches []*core.IOCMatch
	for rows.Next() {
		var m core.IOCMatch
		rows.Scan(&m.ID, &m.IOCID, &m.HuntID, &m.EventID, &m.MatchedField, &m.MatchedValue, &m.EventTimestamp, &m.DetectedAt)
		matches = append(matches, &m)
	}

	return matches, total, nil
}

// =============================================================================
// Maintenance
// =============================================================================

// ArchiveExpiredIOCs archives IOCs that have passed their expiration date
func (s *SQLiteIOCStorage) ArchiveExpiredIOCs(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := s.sqlite.DB.ExecContext(ctx, `
		UPDATE iocs
		SET status = 'archived', updated_at = CURRENT_TIMESTAMP
		WHERE expires_at IS NOT NULL
		  AND expires_at < CURRENT_TIMESTAMP
		  AND status = 'active'
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to archive expired IOCs: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows > 0 {
		s.logger.Infow("Archived expired IOCs", "count", rows)
	}
	return rows, nil
}

// IncrementHitCount increments the hit count for an IOC and updates last_seen
func (s *SQLiteIOCStorage) IncrementHitCount(ctx context.Context, iocID string, lastSeen time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := s.sqlite.DB.ExecContext(ctx, `
		UPDATE iocs
		SET hit_count = hit_count + 1,
		    last_seen = ?,
		    first_seen = COALESCE(first_seen, ?),
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, lastSeen, lastSeen, iocID)

	return err
}

// =============================================================================
// Feed-Specific IOC Operations
// =============================================================================

// FindByFeedExternalID finds an IOC by its feed ID and external ID
func (s *SQLiteIOCStorage) FindByFeedExternalID(ctx context.Context, feedID, externalID string) (*core.IOC, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT id, type, value, normalized, status, severity, confidence,
			description, tags, source, refs, mitre_techniques, threat_intel,
			created_by, created_at, updated_at, first_seen, last_seen, expires_at, hit_count,
			feed_id, external_id, imported_at
		FROM iocs WHERE feed_id = ? AND external_id = ?
	`

	row := s.sqlite.ReadDB.QueryRowContext(ctx, query, feedID, externalID)
	return s.scanIOCWithFeedFields(row)
}

// GetIOCsByFeed retrieves all IOCs for a specific feed
func (s *SQLiteIOCStorage) GetIOCsByFeed(ctx context.Context, feedID string, limit, offset int) ([]*core.IOC, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	// Get total count
	var total int64
	err := s.sqlite.ReadDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM iocs WHERE feed_id = ?", feedID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count IOCs by feed: %w", err)
	}

	// Get IOCs
	query := `
		SELECT id, type, value, normalized, status, severity, confidence,
			description, tags, source, refs, mitre_techniques, threat_intel,
			created_by, created_at, updated_at, first_seen, last_seen, expires_at, hit_count,
			feed_id, external_id, imported_at
		FROM iocs
		WHERE feed_id = ?
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := s.sqlite.ReadDB.QueryContext(ctx, query, feedID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query IOCs by feed: %w", err)
	}
	defer rows.Close()

	var iocs []*core.IOC
	for rows.Next() {
		ioc, err := s.scanIOCRowWithFeedFields(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan IOC: %w", err)
		}
		iocs = append(iocs, ioc)
	}

	return iocs, total, nil
}

// DeleteIOCsByFeed deletes all IOCs for a specific feed
func (s *SQLiteIOCStorage) DeleteIOCsByFeed(ctx context.Context, feedID string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	result, err := s.sqlite.DB.ExecContext(ctx, "DELETE FROM iocs WHERE feed_id = ?", feedID)
	if err != nil {
		return 0, fmt.Errorf("failed to delete IOCs by feed: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		s.logger.Infow("Deleted IOCs by feed", "feed_id", feedID, "count", rowsAffected)
	}
	return rowsAffected, nil
}

// CountIOCsByFeed counts IOCs for a specific feed
func (s *SQLiteIOCStorage) CountIOCsByFeed(ctx context.Context, feedID string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var count int64
	err := s.sqlite.ReadDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM iocs WHERE feed_id = ?", feedID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count IOCs by feed: %w", err)
	}
	return count, nil
}

// scanIOCWithFeedFields scans a single row including feed fields
func (s *SQLiteIOCStorage) scanIOCWithFeedFields(row *sql.Row) (*core.IOC, error) {
	ioc := &core.IOC{}
	var tagsJSON, refsJSON, mitreTechJSON, threatIntelJSON sql.NullString
	var description, source, createdBy sql.NullString
	var firstSeen, lastSeen, expiresAt, importedAt sql.NullString
	var feedID, externalID sql.NullString
	var createdAt, updatedAt string

	err := row.Scan(
		&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Normalized, &ioc.Status, &ioc.Severity, &ioc.Confidence,
		&description, &tagsJSON, &source, &refsJSON, &mitreTechJSON, &threatIntelJSON,
		&createdBy, &createdAt, &updatedAt, &firstSeen, &lastSeen, &expiresAt, &ioc.HitCount,
		&feedID, &externalID, &importedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan IOC: %w", err)
	}

	// Parse nullable strings
	ioc.Description = description.String
	ioc.Source = source.String
	ioc.CreatedBy = createdBy.String
	ioc.FeedID = feedID.String
	ioc.ExternalID = externalID.String

	// Parse timestamps
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		ioc.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
		ioc.UpdatedAt = t
	}
	if firstSeen.Valid {
		if t, err := time.Parse(time.RFC3339, firstSeen.String); err == nil {
			ioc.FirstSeen = &t
		}
	}
	if lastSeen.Valid {
		if t, err := time.Parse(time.RFC3339, lastSeen.String); err == nil {
			ioc.LastSeen = &t
		}
	}
	if expiresAt.Valid {
		if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil {
			ioc.ExpiresAt = &t
		}
	}
	if importedAt.Valid {
		if t, err := time.Parse(time.RFC3339, importedAt.String); err == nil {
			ioc.ImportedAt = &t
		}
	}

	// Parse JSON fields with size limits
	if tagsJSON.Valid {
		safeUnmarshalJSON(tagsJSON.String, &ioc.Tags)
	}
	if refsJSON.Valid {
		safeUnmarshalJSON(refsJSON.String, &ioc.References)
	}
	if mitreTechJSON.Valid {
		safeUnmarshalJSON(mitreTechJSON.String, &ioc.MitreTechniques)
	}
	if threatIntelJSON.Valid {
		safeUnmarshalJSON(threatIntelJSON.String, &ioc.ThreatIntel)
	}

	return ioc, nil
}

// scanIOCRowWithFeedFields scans a row from a result set including feed fields
func (s *SQLiteIOCStorage) scanIOCRowWithFeedFields(rows *sql.Rows) (*core.IOC, error) {
	ioc := &core.IOC{}
	var tagsJSON, refsJSON, mitreTechJSON, threatIntelJSON sql.NullString
	var description, source, createdBy sql.NullString
	var firstSeen, lastSeen, expiresAt, importedAt sql.NullString
	var feedID, externalID sql.NullString
	var createdAt, updatedAt string

	err := rows.Scan(
		&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Normalized, &ioc.Status, &ioc.Severity, &ioc.Confidence,
		&description, &tagsJSON, &source, &refsJSON, &mitreTechJSON, &threatIntelJSON,
		&createdBy, &createdAt, &updatedAt, &firstSeen, &lastSeen, &expiresAt, &ioc.HitCount,
		&feedID, &externalID, &importedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan IOC row: %w", err)
	}

	// Parse nullable strings
	ioc.Description = description.String
	ioc.Source = source.String
	ioc.CreatedBy = createdBy.String
	ioc.FeedID = feedID.String
	ioc.ExternalID = externalID.String

	// Parse timestamps
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		ioc.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
		ioc.UpdatedAt = t
	}
	if firstSeen.Valid {
		if t, err := time.Parse(time.RFC3339, firstSeen.String); err == nil {
			ioc.FirstSeen = &t
		}
	}
	if lastSeen.Valid {
		if t, err := time.Parse(time.RFC3339, lastSeen.String); err == nil {
			ioc.LastSeen = &t
		}
	}
	if expiresAt.Valid {
		if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil {
			ioc.ExpiresAt = &t
		}
	}
	if importedAt.Valid {
		if t, err := time.Parse(time.RFC3339, importedAt.String); err == nil {
			ioc.ImportedAt = &t
		}
	}

	// Parse JSON fields with size limits
	if tagsJSON.Valid {
		safeUnmarshalJSON(tagsJSON.String, &ioc.Tags)
	}
	if refsJSON.Valid {
		safeUnmarshalJSON(refsJSON.String, &ioc.References)
	}
	if mitreTechJSON.Valid {
		safeUnmarshalJSON(mitreTechJSON.String, &ioc.MitreTechniques)
	}
	if threatIntelJSON.Valid {
		safeUnmarshalJSON(threatIntelJSON.String, &ioc.ThreatIntel)
	}

	return ioc, nil
}
