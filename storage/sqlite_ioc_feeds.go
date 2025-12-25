package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"cerberus/core"
	"cerberus/threat/feeds"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// =============================================================================
// SQLite IOC Feed Storage
// =============================================================================

// SQLiteIOCFeedStorage implements IOC feed storage using SQLite
type SQLiteIOCFeedStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteIOCFeedStorage creates a new SQLite-based IOC feed storage
func NewSQLiteIOCFeedStorage(sqlite *SQLite, logger *zap.SugaredLogger) (*SQLiteIOCFeedStorage, error) {
	storage := &SQLiteIOCFeedStorage{
		sqlite: sqlite,
		logger: logger,
	}

	if err := storage.ensureTables(); err != nil {
		return nil, fmt.Errorf("failed to ensure IOC feed tables: %w", err)
	}

	logger.Info("IOC feed storage tables ensured in SQLite")
	return storage, nil
}

// ensureTables creates the necessary tables for IOC feed storage
func (s *SQLiteIOCFeedStorage) ensureTables() error {
	// IOC Feeds table
	iocFeedsTable := `
	CREATE TABLE IF NOT EXISTS ioc_feeds (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		type TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		enabled INTEGER NOT NULL DEFAULT 1,
		url TEXT,
		auth_config TEXT,

		-- STIX/TAXII specific
		collection_id TEXT,
		api_root TEXT,

		-- MISP specific
		org_id TEXT,
		event_filters TEXT,

		-- OTX specific
		pulse_ids TEXT,

		-- CSV/JSON specific
		field_mapping TEXT,
		delimiter TEXT,
		skip_header INTEGER DEFAULT 0,
		comment_char TEXT,
		value_column INTEGER DEFAULT 0,
		type_column INTEGER DEFAULT -1,

		-- Filesystem specific
		path TEXT,
		file_patterns TEXT,

		-- Import configuration
		include_types TEXT,
		exclude_types TEXT,
		default_type TEXT,
		min_confidence REAL DEFAULT 0,
		default_severity TEXT DEFAULT 'medium',
		default_status TEXT DEFAULT 'active',
		auto_expire_days INTEGER DEFAULT 0,
		tags TEXT,
		priority INTEGER NOT NULL DEFAULT 100,

		-- Update configuration
		update_strategy TEXT NOT NULL DEFAULT 'manual',
		update_schedule TEXT,
		last_sync TEXT,
		next_sync TEXT,

		-- Statistics and metadata
		stats TEXT,
		metadata TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		created_by TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_ioc_feeds_status ON ioc_feeds(status);
	CREATE INDEX IF NOT EXISTS idx_ioc_feeds_enabled ON ioc_feeds(enabled);
	CREATE INDEX IF NOT EXISTS idx_ioc_feeds_type ON ioc_feeds(type);
	`

	if _, err := s.sqlite.DB.Exec(iocFeedsTable); err != nil {
		return fmt.Errorf("failed to create ioc_feeds table: %w", err)
	}

	// IOC Feed Sync History table
	syncHistoryTable := `
	CREATE TABLE IF NOT EXISTS ioc_feed_sync_history (
		id TEXT PRIMARY KEY,
		feed_id TEXT NOT NULL,
		feed_name TEXT,
		start_time TEXT NOT NULL,
		end_time TEXT NOT NULL,
		duration REAL,
		success INTEGER NOT NULL,
		stats TEXT,
		errors TEXT,
		ioc_results TEXT,
		FOREIGN KEY (feed_id) REFERENCES ioc_feeds(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_ioc_sync_history_feed_id ON ioc_feed_sync_history(feed_id);
	CREATE INDEX IF NOT EXISTS idx_ioc_sync_history_start_time ON ioc_feed_sync_history(start_time DESC);
	`

	if _, err := s.sqlite.DB.Exec(syncHistoryTable); err != nil {
		return fmt.Errorf("failed to create ioc_feed_sync_history table: %w", err)
	}

	// Add comment_char column if it doesn't exist (for existing databases)
	s.sqlite.DB.Exec("ALTER TABLE ioc_feeds ADD COLUMN comment_char TEXT")

	// Add feed columns to iocs table if they don't exist
	alterIOCsTable := `
	ALTER TABLE iocs ADD COLUMN feed_id TEXT REFERENCES ioc_feeds(id) ON DELETE SET NULL;
	ALTER TABLE iocs ADD COLUMN external_id TEXT;
	ALTER TABLE iocs ADD COLUMN imported_at TEXT;
	`
	// These will fail if columns already exist, which is fine
	s.sqlite.DB.Exec("ALTER TABLE iocs ADD COLUMN feed_id TEXT REFERENCES ioc_feeds(id) ON DELETE SET NULL")
	s.sqlite.DB.Exec("ALTER TABLE iocs ADD COLUMN external_id TEXT")
	s.sqlite.DB.Exec("ALTER TABLE iocs ADD COLUMN imported_at TEXT")

	// Create index for feed lookups
	s.sqlite.DB.Exec("CREATE INDEX IF NOT EXISTS idx_iocs_feed_id ON iocs(feed_id)")
	s.sqlite.DB.Exec("CREATE INDEX IF NOT EXISTS idx_iocs_feed_external_id ON iocs(feed_id, external_id)")

	_ = alterIOCsTable // Suppress unused variable warning

	return nil
}

// =============================================================================
// Feed CRUD Operations
// =============================================================================

// CreateFeed creates a new IOC feed
func (s *SQLiteIOCFeedStorage) CreateFeed(ctx context.Context, feed *feeds.IOCFeed) error {
	// Check for duplicate ID
	var count int
	err := s.sqlite.ReadDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM ioc_feeds WHERE id = ?", feed.ID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for duplicate feed: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("feed with ID %s already exists", feed.ID)
	}

	// Set timestamps
	now := time.Now().UTC()
	if feed.CreatedAt.IsZero() {
		feed.CreatedAt = now
	}
	feed.UpdatedAt = now

	// Set default status
	if feed.Status == "" {
		feed.Status = feeds.IOCFeedStatusActive
	}

	// Serialize complex fields
	authConfig, _ := json.Marshal(feed.AuthConfig)
	pulseIDs, _ := json.Marshal(feed.PulseIDs)
	fieldMapping, _ := json.Marshal(feed.FieldMapping)
	filePatterns, _ := json.Marshal(feed.FilePatterns)
	includeTypes, _ := json.Marshal(feed.IncludeTypes)
	excludeTypes, _ := json.Marshal(feed.ExcludeTypes)
	tags, _ := json.Marshal(feed.Tags)
	stats, _ := json.Marshal(feed.Stats)
	metadata, _ := json.Marshal(feed.Metadata)

	query := `
		INSERT INTO ioc_feeds (
			id, name, description, type, status, enabled, url, auth_config,
			collection_id, api_root, org_id, event_filters, pulse_ids,
			field_mapping, delimiter, skip_header, comment_char, value_column, type_column,
			path, file_patterns,
			include_types, exclude_types, default_type, min_confidence,
			default_severity, default_status, auto_expire_days, tags, priority,
			update_strategy, update_schedule, last_sync, next_sync,
			stats, metadata, created_at, updated_at, created_by
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var lastSync, nextSync *string
	if feed.LastSync != nil {
		ls := feed.LastSync.Format(time.RFC3339)
		lastSync = &ls
	}
	if feed.NextSync != nil {
		ns := feed.NextSync.Format(time.RFC3339)
		nextSync = &ns
	}

	_, err = s.sqlite.DB.ExecContext(ctx, query,
		feed.ID, feed.Name, feed.Description, string(feed.Type), string(feed.Status), boolToInt(feed.Enabled),
		feed.URL, string(authConfig),
		feed.CollectionID, feed.APIRoot, feed.OrgID, feed.EventFilters, string(pulseIDs),
		string(fieldMapping), feed.Delimiter, boolToInt(feed.SkipHeader), feed.CommentChar, feed.ValueColumn, feed.TypeColumn,
		feed.Path, string(filePatterns),
		string(includeTypes), string(excludeTypes), string(feed.DefaultType), feed.MinConfidence,
		string(feed.DefaultSeverity), string(feed.DefaultStatus), feed.AutoExpireDays, string(tags), feed.Priority,
		string(feed.UpdateStrategy), feed.UpdateSchedule, lastSync, nextSync,
		string(stats), string(metadata), feed.CreatedAt.Format(time.RFC3339), feed.UpdatedAt.Format(time.RFC3339), feed.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create IOC feed: %w", err)
	}

	s.logger.Infow("IOC feed created", "feed_id", feed.ID, "name", feed.Name, "type", feed.Type)
	return nil
}

// GetFeed retrieves a feed by ID
func (s *SQLiteIOCFeedStorage) GetFeed(ctx context.Context, id string) (*feeds.IOCFeed, error) {
	query := `
		SELECT id, name, description, type, status, enabled, url, auth_config,
			collection_id, api_root, org_id, event_filters, pulse_ids,
			field_mapping, delimiter, skip_header, comment_char, value_column, type_column,
			path, file_patterns,
			include_types, exclude_types, default_type, min_confidence,
			default_severity, default_status, auto_expire_days, tags, priority,
			update_strategy, update_schedule, last_sync, next_sync,
			stats, metadata, created_at, updated_at, created_by
		FROM ioc_feeds WHERE id = ?
	`

	feed := &feeds.IOCFeed{}
	var enabled, skipHeader int
	var authConfig, pulseIDs, fieldMapping, filePatterns, includeTypes, excludeTypes, tags, stats, metadata sql.NullString
	var collectionID, apiRoot, orgID, eventFilters, delimiter, commentChar, path, defaultType, defaultSeverity, defaultStatus sql.NullString
	var updateSchedule, lastSync, nextSync, createdBy sql.NullString
	var createdAt, updatedAt string
	var valueColumn, typeColumn int

	err := s.sqlite.ReadDB.QueryRowContext(ctx, query, id).Scan(
		&feed.ID, &feed.Name, &feed.Description, &feed.Type, &feed.Status, &enabled,
		&feed.URL, &authConfig,
		&collectionID, &apiRoot, &orgID, &eventFilters, &pulseIDs,
		&fieldMapping, &delimiter, &skipHeader, &commentChar, &valueColumn, &typeColumn,
		&path, &filePatterns,
		&includeTypes, &excludeTypes, &defaultType, &feed.MinConfidence,
		&defaultSeverity, &defaultStatus, &feed.AutoExpireDays, &tags, &feed.Priority,
		&feed.UpdateStrategy, &updateSchedule, &lastSync, &nextSync,
		&stats, &metadata, &createdAt, &updatedAt, &createdBy,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get IOC feed: %w", err)
	}

	feed.Enabled = enabled == 1
	feed.SkipHeader = skipHeader == 1
	feed.ValueColumn = valueColumn
	feed.TypeColumn = typeColumn
	feed.CollectionID = collectionID.String
	feed.APIRoot = apiRoot.String
	feed.OrgID = orgID.String
	feed.EventFilters = eventFilters.String
	feed.Delimiter = delimiter.String
	feed.CommentChar = commentChar.String
	feed.Path = path.String
	feed.CreatedBy = createdBy.String

	if defaultType.Valid {
		feed.DefaultType = core.IOCType(defaultType.String)
	}
	if defaultSeverity.Valid {
		feed.DefaultSeverity = core.IOCSeverity(defaultSeverity.String)
	}
	if defaultStatus.Valid {
		feed.DefaultStatus = core.IOCStatus(defaultStatus.String)
	}
	if updateSchedule.Valid {
		feed.UpdateSchedule = updateSchedule.String
	}

	// Parse timestamps
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		feed.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
		feed.UpdatedAt = t
	}
	if lastSync.Valid {
		if t, err := time.Parse(time.RFC3339, lastSync.String); err == nil {
			feed.LastSync = &t
		}
	}
	if nextSync.Valid {
		if t, err := time.Parse(time.RFC3339, nextSync.String); err == nil {
			feed.NextSync = &t
		}
	}

	// Parse JSON fields
	if authConfig.Valid {
		json.Unmarshal([]byte(authConfig.String), &feed.AuthConfig)
	}
	if pulseIDs.Valid {
		json.Unmarshal([]byte(pulseIDs.String), &feed.PulseIDs)
	}
	if fieldMapping.Valid {
		json.Unmarshal([]byte(fieldMapping.String), &feed.FieldMapping)
	}
	if filePatterns.Valid {
		json.Unmarshal([]byte(filePatterns.String), &feed.FilePatterns)
	}
	if includeTypes.Valid {
		json.Unmarshal([]byte(includeTypes.String), &feed.IncludeTypes)
	}
	if excludeTypes.Valid {
		json.Unmarshal([]byte(excludeTypes.String), &feed.ExcludeTypes)
	}
	if tags.Valid {
		json.Unmarshal([]byte(tags.String), &feed.Tags)
	}
	if stats.Valid {
		json.Unmarshal([]byte(stats.String), &feed.Stats)
	}
	if metadata.Valid {
		json.Unmarshal([]byte(metadata.String), &feed.Metadata)
	}

	return feed, nil
}

// GetAllFeeds retrieves all IOC feeds
func (s *SQLiteIOCFeedStorage) GetAllFeeds(ctx context.Context) ([]*feeds.IOCFeed, error) {
	query := `
		SELECT id FROM ioc_feeds ORDER BY priority DESC, name ASC
	`

	rows, err := s.sqlite.ReadDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query IOC feeds: %w", err)
	}
	defer rows.Close()

	var feedList []*feeds.IOCFeed
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan feed ID: %w", err)
		}

		feed, err := s.GetFeed(ctx, id)
		if err != nil {
			s.logger.Warnw("Failed to get feed", "id", id, "error", err)
			continue
		}
		feedList = append(feedList, feed)
	}

	return feedList, nil
}

// UpdateFeed updates an existing IOC feed
func (s *SQLiteIOCFeedStorage) UpdateFeed(ctx context.Context, id string, feed *feeds.IOCFeed) error {
	feed.UpdatedAt = time.Now().UTC()

	// Serialize complex fields
	authConfig, _ := json.Marshal(feed.AuthConfig)
	pulseIDs, _ := json.Marshal(feed.PulseIDs)
	fieldMapping, _ := json.Marshal(feed.FieldMapping)
	filePatterns, _ := json.Marshal(feed.FilePatterns)
	includeTypes, _ := json.Marshal(feed.IncludeTypes)
	excludeTypes, _ := json.Marshal(feed.ExcludeTypes)
	tags, _ := json.Marshal(feed.Tags)
	stats, _ := json.Marshal(feed.Stats)
	metadata, _ := json.Marshal(feed.Metadata)

	var lastSync, nextSync *string
	if feed.LastSync != nil {
		ls := feed.LastSync.Format(time.RFC3339)
		lastSync = &ls
	}
	if feed.NextSync != nil {
		ns := feed.NextSync.Format(time.RFC3339)
		nextSync = &ns
	}

	query := `
		UPDATE ioc_feeds SET
			name = ?, description = ?, type = ?, status = ?, enabled = ?, url = ?, auth_config = ?,
			collection_id = ?, api_root = ?, org_id = ?, event_filters = ?, pulse_ids = ?,
			field_mapping = ?, delimiter = ?, skip_header = ?, comment_char = ?, value_column = ?, type_column = ?,
			path = ?, file_patterns = ?,
			include_types = ?, exclude_types = ?, default_type = ?, min_confidence = ?,
			default_severity = ?, default_status = ?, auto_expire_days = ?, tags = ?, priority = ?,
			update_strategy = ?, update_schedule = ?, last_sync = ?, next_sync = ?,
			stats = ?, metadata = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := s.sqlite.DB.ExecContext(ctx, query,
		feed.Name, feed.Description, string(feed.Type), string(feed.Status), boolToInt(feed.Enabled),
		feed.URL, string(authConfig),
		feed.CollectionID, feed.APIRoot, feed.OrgID, feed.EventFilters, string(pulseIDs),
		string(fieldMapping), feed.Delimiter, boolToInt(feed.SkipHeader), feed.CommentChar, feed.ValueColumn, feed.TypeColumn,
		feed.Path, string(filePatterns),
		string(includeTypes), string(excludeTypes), string(feed.DefaultType), feed.MinConfidence,
		string(feed.DefaultSeverity), string(feed.DefaultStatus), feed.AutoExpireDays, string(tags), feed.Priority,
		string(feed.UpdateStrategy), feed.UpdateSchedule, lastSync, nextSync,
		string(stats), string(metadata), feed.UpdatedAt.Format(time.RFC3339),
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to update IOC feed: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// DeleteFeed deletes an IOC feed and its associated IOCs
func (s *SQLiteIOCFeedStorage) DeleteFeed(ctx context.Context, id string) error {
	// First, clear feed_id from associated IOCs (or delete them)
	_, err := s.sqlite.DB.ExecContext(ctx, "UPDATE iocs SET feed_id = NULL WHERE feed_id = ?", id)
	if err != nil {
		s.logger.Warnw("Failed to clear feed_id from IOCs", "feed_id", id, "error", err)
	}

	// Delete the feed (sync history will cascade)
	result, err := s.sqlite.DB.ExecContext(ctx, "DELETE FROM ioc_feeds WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete IOC feed: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}

	s.logger.Infow("IOC feed deleted", "feed_id", id)
	return nil
}

// =============================================================================
// Status and Stats Updates
// =============================================================================

// UpdateFeedStatus updates just the status of a feed
func (s *SQLiteIOCFeedStorage) UpdateFeedStatus(ctx context.Context, id string, status feeds.IOCFeedStatus) error {
	query := "UPDATE ioc_feeds SET status = ?, updated_at = ? WHERE id = ?"
	result, err := s.sqlite.DB.ExecContext(ctx, query, string(status), time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("failed to update feed status: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateFeedStats updates the statistics for a feed
func (s *SQLiteIOCFeedStorage) UpdateFeedStats(ctx context.Context, id string, stats feeds.IOCFeedStats) error {
	statsJSON, _ := json.Marshal(stats)
	query := "UPDATE ioc_feeds SET stats = ?, updated_at = ? WHERE id = ?"
	result, err := s.sqlite.DB.ExecContext(ctx, query, string(statsJSON), time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("failed to update feed stats: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateLastSync updates the last sync time and optionally next sync time
func (s *SQLiteIOCFeedStorage) UpdateLastSync(ctx context.Context, id string, syncTime time.Time) error {
	query := "UPDATE ioc_feeds SET last_sync = ?, updated_at = ? WHERE id = ?"
	result, err := s.sqlite.DB.ExecContext(ctx, query,
		syncTime.Format(time.RFC3339),
		time.Now().UTC().Format(time.RFC3339),
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to update last sync: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// =============================================================================
// Sync History
// =============================================================================

// SaveSyncResult saves a sync result to history
func (s *SQLiteIOCFeedStorage) SaveSyncResult(ctx context.Context, result *feeds.IOCFeedSyncResult) error {
	if result.ID == "" {
		result.ID = uuid.New().String()
	}

	statsJSON, _ := json.Marshal(result.Stats)
	errorsJSON, _ := json.Marshal(result.Errors)

	// Limit IOC results to first 100 for storage efficiency
	iocResults := result.IOCResults
	if len(iocResults) > 100 {
		iocResults = iocResults[:100]
	}
	iocResultsJSON, _ := json.Marshal(iocResults)

	query := `
		INSERT INTO ioc_feed_sync_history (
			id, feed_id, feed_name, start_time, end_time, duration, success, stats, errors, ioc_results
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.sqlite.DB.ExecContext(ctx, query,
		result.ID, result.FeedID, result.FeedName,
		result.StartTime.Format(time.RFC3339), result.EndTime.Format(time.RFC3339),
		result.Duration, boolToInt(result.Success),
		string(statsJSON), string(errorsJSON), string(iocResultsJSON),
	)
	if err != nil {
		return fmt.Errorf("failed to save sync result: %w", err)
	}

	return nil
}

// GetSyncHistory retrieves sync history for a feed
func (s *SQLiteIOCFeedStorage) GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*feeds.IOCFeedSyncResult, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	query := `
		SELECT id, feed_id, feed_name, start_time, end_time, duration, success, stats, errors, ioc_results
		FROM ioc_feed_sync_history
		WHERE feed_id = ?
		ORDER BY start_time DESC
		LIMIT ?
	`

	rows, err := s.sqlite.ReadDB.QueryContext(ctx, query, feedID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query sync history: %w", err)
	}
	defer rows.Close()

	var results []*feeds.IOCFeedSyncResult
	for rows.Next() {
		result := &feeds.IOCFeedSyncResult{}
		var startTime, endTime string
		var success int
		var statsJSON, errorsJSON, iocResultsJSON sql.NullString

		err := rows.Scan(
			&result.ID, &result.FeedID, &result.FeedName,
			&startTime, &endTime, &result.Duration, &success,
			&statsJSON, &errorsJSON, &iocResultsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan sync result: %w", err)
		}

		result.Success = success == 1
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			result.StartTime = t
		}
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			result.EndTime = t
		}
		if statsJSON.Valid {
			json.Unmarshal([]byte(statsJSON.String), &result.Stats)
		}
		if errorsJSON.Valid {
			json.Unmarshal([]byte(errorsJSON.String), &result.Errors)
		}
		if iocResultsJSON.Valid {
			json.Unmarshal([]byte(iocResultsJSON.String), &result.IOCResults)
		}

		results = append(results, result)
	}

	return results, nil
}

// =============================================================================
// Summary and Aggregations
// =============================================================================

// GetFeedsSummary returns aggregate statistics for all IOC feeds
func (s *SQLiteIOCFeedStorage) GetFeedsSummary(ctx context.Context) (*feeds.IOCFeedsSummary, error) {
	summary := &feeds.IOCFeedsSummary{}

	// Count feeds
	err := s.sqlite.ReadDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM ioc_feeds").Scan(&summary.TotalFeeds)
	if err != nil {
		return nil, fmt.Errorf("failed to count feeds: %w", err)
	}

	// Count active feeds
	err = s.sqlite.ReadDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM ioc_feeds WHERE enabled = 1 AND status = 'active'").Scan(&summary.ActiveFeeds)
	if err != nil {
		return nil, fmt.Errorf("failed to count active feeds: %w", err)
	}

	// Count error feeds
	err = s.sqlite.ReadDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM ioc_feeds WHERE status = 'error'").Scan(&summary.ErrorCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count error feeds: %w", err)
	}

	// Count total IOCs from feeds
	err = s.sqlite.ReadDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM iocs WHERE feed_id IS NOT NULL").Scan(&summary.TotalIOCs)
	if err != nil {
		// Table might not have feed_id column yet
		summary.TotalIOCs = 0
	}

	// Get most recent sync
	var lastSyncStr sql.NullString
	err = s.sqlite.ReadDB.QueryRowContext(ctx,
		"SELECT MAX(last_sync) FROM ioc_feeds WHERE last_sync IS NOT NULL").Scan(&lastSyncStr)
	if err == nil && lastSyncStr.Valid {
		if t, err := time.Parse(time.RFC3339, lastSyncStr.String); err == nil {
			summary.LastSync = &t
		}
	}

	// Determine health status
	if summary.ErrorCount > 0 {
		summary.HealthStatus = "error"
	} else if summary.ActiveFeeds < summary.TotalFeeds && summary.TotalFeeds > 0 {
		summary.HealthStatus = "warning"
	} else {
		summary.HealthStatus = "healthy"
	}

	return summary, nil
}

// GetEnabledFeeds returns all enabled feeds that need scheduling
func (s *SQLiteIOCFeedStorage) GetEnabledFeeds(ctx context.Context) ([]*feeds.IOCFeed, error) {
	query := `
		SELECT id FROM ioc_feeds
		WHERE enabled = 1 AND status != 'syncing'
		ORDER BY priority DESC
	`

	rows, err := s.sqlite.ReadDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query enabled feeds: %w", err)
	}
	defer rows.Close()

	var feedList []*feeds.IOCFeed
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan feed ID: %w", err)
		}

		feed, err := s.GetFeed(ctx, id)
		if err != nil {
			continue
		}
		feedList = append(feedList, feed)
	}

	return feedList, nil
}

// Close closes the storage (noop for SQLite, managed by parent)
func (s *SQLiteIOCFeedStorage) Close() error {
	return nil
}
