package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"cerberus/sigma/feeds"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SQLiteFeedStorage implements feed storage using SQLite
type SQLiteFeedStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteFeedStorage creates a new SQLite-based feed storage
func NewSQLiteFeedStorage(sqlite *SQLite, logger *zap.SugaredLogger) (*SQLiteFeedStorage, error) {
	storage := &SQLiteFeedStorage{
		sqlite: sqlite,
		logger: logger,
	}

	if err := storage.ensureTables(); err != nil {
		return nil, fmt.Errorf("failed to ensure feed tables: %w", err)
	}

	logger.Info("Feed storage tables ensured in SQLite")
	return storage, nil
}

// ensureTables creates the necessary tables for feed storage
func (s *SQLiteFeedStorage) ensureTables() error {
	// Feeds table
	feedsTable := `
	CREATE TABLE IF NOT EXISTS rule_feeds (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		type TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		enabled INTEGER NOT NULL DEFAULT 1,
		url TEXT,
		branch TEXT,
		path TEXT,
		auth_config TEXT,
		include_paths TEXT,
		exclude_paths TEXT,
		include_tags TEXT,
		exclude_tags TEXT,
		min_severity TEXT,
		auto_enable_rules INTEGER NOT NULL DEFAULT 0,
		priority INTEGER NOT NULL DEFAULT 100,
		update_strategy TEXT NOT NULL DEFAULT 'manual',
		update_schedule TEXT,
		last_sync TEXT,
		next_sync TEXT,
		stats TEXT,
		tags TEXT,
		metadata TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		created_by TEXT
	);
	`

	if _, err := s.sqlite.DB.Exec(feedsTable); err != nil {
		return fmt.Errorf("failed to create rule_feeds table: %w", err)
	}

	// Sync history table
	syncHistoryTable := `
	CREATE TABLE IF NOT EXISTS feed_sync_history (
		id TEXT PRIMARY KEY,
		feed_id TEXT NOT NULL,
		feed_name TEXT,
		start_time TEXT NOT NULL,
		end_time TEXT NOT NULL,
		duration REAL,
		success INTEGER NOT NULL,
		stats TEXT,
		errors TEXT,
		rule_results TEXT,
		FOREIGN KEY (feed_id) REFERENCES rule_feeds(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_sync_history_feed_id ON feed_sync_history(feed_id);
	CREATE INDEX IF NOT EXISTS idx_sync_history_start_time ON feed_sync_history(start_time DESC);
	`

	if _, err := s.sqlite.DB.Exec(syncHistoryTable); err != nil {
		return fmt.Errorf("failed to create feed_sync_history table: %w", err)
	}

	return nil
}

// CreateFeed creates a new feed
func (s *SQLiteFeedStorage) CreateFeed(ctx context.Context, feed *feeds.RuleFeed) error {
	if err := feed.Validate(); err != nil {
		return err
	}

	// Check for duplicate ID
	var count int
	err := s.sqlite.ReadDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM rule_feeds WHERE id = ?", feed.ID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for duplicate feed: %w", err)
	}
	if count > 0 {
		return feeds.ErrDuplicateFeedID
	}

	// Set timestamps
	now := time.Now()
	if feed.CreatedAt.IsZero() {
		feed.CreatedAt = now
	}
	feed.UpdatedAt = now

	// Serialize complex fields
	authConfig, _ := json.Marshal(feed.AuthConfig)
	includePaths, _ := json.Marshal(feed.IncludePaths)
	excludePaths, _ := json.Marshal(feed.ExcludePaths)
	includeTags, _ := json.Marshal(feed.IncludeTags)
	excludeTags, _ := json.Marshal(feed.ExcludeTags)
	stats, _ := json.Marshal(feed.Stats)
	tags, _ := json.Marshal(feed.Tags)
	metadata, _ := json.Marshal(feed.Metadata)

	query := `
		INSERT INTO rule_feeds (
			id, name, description, type, status, enabled,
			url, branch, path, auth_config,
			include_paths, exclude_paths, include_tags, exclude_tags,
			min_severity, auto_enable_rules, priority,
			update_strategy, update_schedule, last_sync, next_sync,
			stats, tags, metadata,
			created_at, updated_at, created_by
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.sqlite.DB.ExecContext(ctx, query,
		feed.ID, feed.Name, feed.Description, feed.Type, feed.Status, boolToInt(feed.Enabled),
		feed.URL, feed.Branch, feed.Path, string(authConfig),
		string(includePaths), string(excludePaths), string(includeTags), string(excludeTags),
		feed.MinSeverity, boolToInt(feed.AutoEnableRules), feed.Priority,
		feed.UpdateStrategy, feed.UpdateSchedule, timeToString(feed.LastSync), timeToString(feed.NextSync),
		string(stats), string(tags), string(metadata),
		feed.CreatedAt.Format(time.RFC3339), feed.UpdatedAt.Format(time.RFC3339), feed.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create feed: %w", err)
	}

	s.logger.Infof("Created feed: %s (ID: %s)", feed.Name, feed.ID)
	return nil
}

// GetFeed retrieves a feed by ID
func (s *SQLiteFeedStorage) GetFeed(ctx context.Context, id string) (*feeds.RuleFeed, error) {
	query := `
		SELECT id, name, description, type, status, enabled,
			url, branch, path, auth_config,
			include_paths, exclude_paths, include_tags, exclude_tags,
			min_severity, auto_enable_rules, priority,
			update_strategy, update_schedule, last_sync, next_sync,
			stats, tags, metadata,
			created_at, updated_at, created_by
		FROM rule_feeds WHERE id = ?
	`

	var feed feeds.RuleFeed
	var authConfig, includePaths, excludePaths, includeTags, excludeTags, stats, tags, metadata string
	var enabled, autoEnableRules int
	var lastSync, nextSync, createdAt, updatedAt string

	err := s.sqlite.ReadDB.QueryRowContext(ctx, query, id).Scan(
		&feed.ID, &feed.Name, &feed.Description, &feed.Type, &feed.Status, &enabled,
		&feed.URL, &feed.Branch, &feed.Path, &authConfig,
		&includePaths, &excludePaths, &includeTags, &excludeTags,
		&feed.MinSeverity, &autoEnableRules, &feed.Priority,
		&feed.UpdateStrategy, &feed.UpdateSchedule, &lastSync, &nextSync,
		&stats, &tags, &metadata,
		&createdAt, &updatedAt, &feed.CreatedBy,
	)

	if err == sql.ErrNoRows {
		return nil, feeds.ErrFeedNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get feed: %w", err)
	}

	// Deserialize complex fields
	feed.Enabled = intToBool(enabled)
	feed.AutoEnableRules = intToBool(autoEnableRules)
	json.Unmarshal([]byte(authConfig), &feed.AuthConfig)
	json.Unmarshal([]byte(includePaths), &feed.IncludePaths)
	json.Unmarshal([]byte(excludePaths), &feed.ExcludePaths)
	json.Unmarshal([]byte(includeTags), &feed.IncludeTags)
	json.Unmarshal([]byte(excludeTags), &feed.ExcludeTags)
	json.Unmarshal([]byte(stats), &feed.Stats)
	json.Unmarshal([]byte(tags), &feed.Tags)
	json.Unmarshal([]byte(metadata), &feed.Metadata)

	// Parse timestamps
	feed.LastSync, _ = time.Parse(time.RFC3339, lastSync)
	feed.NextSync, _ = time.Parse(time.RFC3339, nextSync)
	feed.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	feed.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	return &feed, nil
}

// GetAllFeeds retrieves all feeds
func (s *SQLiteFeedStorage) GetAllFeeds(ctx context.Context) ([]*feeds.RuleFeed, error) {
	query := `
		SELECT id, name, description, type, status, enabled,
			url, branch, path, auth_config,
			include_paths, exclude_paths, include_tags, exclude_tags,
			min_severity, auto_enable_rules, priority,
			update_strategy, update_schedule, last_sync, next_sync,
			stats, tags, metadata,
			created_at, updated_at, created_by
		FROM rule_feeds
		ORDER BY priority DESC, name ASC
	`

	rows, err := s.sqlite.ReadDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list feeds: %w", err)
	}
	defer rows.Close()

	var feedsList []*feeds.RuleFeed
	for rows.Next() {
		var feed feeds.RuleFeed
		var authConfig, includePaths, excludePaths, includeTags, excludeTags, stats, tags, metadata string
		var enabled, autoEnableRules int
		var lastSync, nextSync, createdAt, updatedAt string

		err := rows.Scan(
			&feed.ID, &feed.Name, &feed.Description, &feed.Type, &feed.Status, &enabled,
			&feed.URL, &feed.Branch, &feed.Path, &authConfig,
			&includePaths, &excludePaths, &includeTags, &excludeTags,
			&feed.MinSeverity, &autoEnableRules, &feed.Priority,
			&feed.UpdateStrategy, &feed.UpdateSchedule, &lastSync, &nextSync,
			&stats, &tags, &metadata,
			&createdAt, &updatedAt, &feed.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan feed: %w", err)
		}

		// Deserialize complex fields
		feed.Enabled = intToBool(enabled)
		feed.AutoEnableRules = intToBool(autoEnableRules)
		json.Unmarshal([]byte(authConfig), &feed.AuthConfig)
		json.Unmarshal([]byte(includePaths), &feed.IncludePaths)
		json.Unmarshal([]byte(excludePaths), &feed.ExcludePaths)
		json.Unmarshal([]byte(includeTags), &feed.IncludeTags)
		json.Unmarshal([]byte(excludeTags), &feed.ExcludeTags)
		json.Unmarshal([]byte(stats), &feed.Stats)
		json.Unmarshal([]byte(tags), &feed.Tags)
		json.Unmarshal([]byte(metadata), &feed.Metadata)

		// Parse timestamps
		feed.LastSync, _ = time.Parse(time.RFC3339, lastSync)
		feed.NextSync, _ = time.Parse(time.RFC3339, nextSync)
		feed.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		feed.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

		feedsList = append(feedsList, &feed)
	}

	return feedsList, nil
}

// UpdateFeed updates an existing feed
func (s *SQLiteFeedStorage) UpdateFeed(ctx context.Context, id string, feed *feeds.RuleFeed) error {
	if err := feed.Validate(); err != nil {
		return err
	}

	// Ensure ID matches
	feed.ID = id
	feed.UpdatedAt = time.Now()

	// Serialize complex fields
	authConfig, _ := json.Marshal(feed.AuthConfig)
	includePaths, _ := json.Marshal(feed.IncludePaths)
	excludePaths, _ := json.Marshal(feed.ExcludePaths)
	includeTags, _ := json.Marshal(feed.IncludeTags)
	excludeTags, _ := json.Marshal(feed.ExcludeTags)
	stats, _ := json.Marshal(feed.Stats)
	tags, _ := json.Marshal(feed.Tags)
	metadata, _ := json.Marshal(feed.Metadata)

	query := `
		UPDATE rule_feeds SET
			name = ?, description = ?, type = ?, status = ?, enabled = ?,
			url = ?, branch = ?, path = ?, auth_config = ?,
			include_paths = ?, exclude_paths = ?, include_tags = ?, exclude_tags = ?,
			min_severity = ?, auto_enable_rules = ?, priority = ?,
			update_strategy = ?, update_schedule = ?, last_sync = ?, next_sync = ?,
			stats = ?, tags = ?, metadata = ?,
			updated_at = ?
		WHERE id = ?
	`

	result, err := s.sqlite.DB.ExecContext(ctx, query,
		feed.Name, feed.Description, feed.Type, feed.Status, boolToInt(feed.Enabled),
		feed.URL, feed.Branch, feed.Path, string(authConfig),
		string(includePaths), string(excludePaths), string(includeTags), string(excludeTags),
		feed.MinSeverity, boolToInt(feed.AutoEnableRules), feed.Priority,
		feed.UpdateStrategy, feed.UpdateSchedule, timeToString(feed.LastSync), timeToString(feed.NextSync),
		string(stats), string(tags), string(metadata),
		feed.UpdatedAt.Format(time.RFC3339),
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update feed: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check update result: %w", err)
	}
	if rows == 0 {
		return feeds.ErrFeedNotFound
	}

	s.logger.Infof("Updated feed: %s (ID: %s)", feed.Name, id)
	return nil
}

// DeleteFeed deletes a feed
func (s *SQLiteFeedStorage) DeleteFeed(ctx context.Context, id string) error {
	result, err := s.sqlite.DB.ExecContext(ctx, "DELETE FROM rule_feeds WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete feed: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check delete result: %w", err)
	}
	if rows == 0 {
		return feeds.ErrFeedNotFound
	}

	s.logger.Infof("Deleted feed: %s", id)
	return nil
}

// UpdateFeedStatus updates the status of a feed
func (s *SQLiteFeedStorage) UpdateFeedStatus(ctx context.Context, id string, status string) error {
	result, err := s.sqlite.DB.ExecContext(ctx,
		"UPDATE rule_feeds SET status = ?, updated_at = ? WHERE id = ?",
		status, time.Now().Format(time.RFC3339), id,
	)
	if err != nil {
		return fmt.Errorf("failed to update feed status: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check update result: %w", err)
	}
	if rows == 0 {
		return feeds.ErrFeedNotFound
	}

	return nil
}

// UpdateFeedStats updates the statistics of a feed
func (s *SQLiteFeedStorage) UpdateFeedStats(ctx context.Context, id string, stats *feeds.FeedStats) error {
	statsJSON, _ := json.Marshal(stats)

	result, err := s.sqlite.DB.ExecContext(ctx,
		"UPDATE rule_feeds SET stats = ?, updated_at = ? WHERE id = ?",
		string(statsJSON), time.Now().Format(time.RFC3339), id,
	)
	if err != nil {
		return fmt.Errorf("failed to update feed stats: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check update result: %w", err)
	}
	if rows == 0 {
		return feeds.ErrFeedNotFound
	}

	return nil
}

// UpdateLastSync updates the last sync time of a feed
func (s *SQLiteFeedStorage) UpdateLastSync(ctx context.Context, id string, syncTime time.Time) error {
	result, err := s.sqlite.DB.ExecContext(ctx,
		"UPDATE rule_feeds SET last_sync = ?, updated_at = ? WHERE id = ?",
		syncTime.Format(time.RFC3339), time.Now().Format(time.RFC3339), id,
	)
	if err != nil {
		return fmt.Errorf("failed to update last sync: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check update result: %w", err)
	}
	if rows == 0 {
		return feeds.ErrFeedNotFound
	}

	return nil
}

// SaveSyncResult saves a feed synchronization result
func (s *SQLiteFeedStorage) SaveSyncResult(ctx context.Context, result *feeds.FeedSyncResult) error {
	id := uuid.New().String()

	stats, _ := json.Marshal(result.Stats)
	errors, _ := json.Marshal(result.Errors)
	ruleResults, _ := json.Marshal(result.RuleResults)

	query := `
		INSERT INTO feed_sync_history (
			id, feed_id, feed_name, start_time, end_time, duration,
			success, stats, errors, rule_results
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.sqlite.DB.ExecContext(ctx, query,
		id, result.FeedID, result.FeedName,
		result.StartTime.Format(time.RFC3339), result.EndTime.Format(time.RFC3339),
		result.Duration, boolToInt(result.Success),
		string(stats), string(errors), string(ruleResults),
	)

	if err != nil {
		return fmt.Errorf("failed to save sync result: %w", err)
	}

	return nil
}

// GetSyncHistory retrieves sync history for a feed
func (s *SQLiteFeedStorage) GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*feeds.FeedSyncResult, error) {
	query := `
		SELECT id, feed_id, feed_name, start_time, end_time, duration,
			success, stats, errors, rule_results
		FROM feed_sync_history
		WHERE feed_id = ?
		ORDER BY start_time DESC
		LIMIT ?
	`

	rows, err := s.sqlite.ReadDB.QueryContext(ctx, query, feedID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync history: %w", err)
	}
	defer rows.Close()

	var history []*feeds.FeedSyncResult
	for rows.Next() {
		var result feeds.FeedSyncResult
		var id, startTime, endTime, stats, errors, ruleResults string
		var success int

		err := rows.Scan(
			&id, &result.FeedID, &result.FeedName, &startTime, &endTime,
			&result.Duration, &success, &stats, &errors, &ruleResults,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan sync result: %w", err)
		}

		result.Success = intToBool(success)
		result.StartTime, _ = time.Parse(time.RFC3339, startTime)
		result.EndTime, _ = time.Parse(time.RFC3339, endTime)
		json.Unmarshal([]byte(stats), &result.Stats)
		json.Unmarshal([]byte(errors), &result.Errors)
		json.Unmarshal([]byte(ruleResults), &result.RuleResults)

		history = append(history, &result)
	}

	return history, nil
}

// GetSyncResult retrieves a specific sync result
func (s *SQLiteFeedStorage) GetSyncResult(ctx context.Context, syncID string) (*feeds.FeedSyncResult, error) {
	query := `
		SELECT id, feed_id, feed_name, start_time, end_time, duration,
			success, stats, errors, rule_results
		FROM feed_sync_history
		WHERE id = ?
	`

	var result feeds.FeedSyncResult
	var id, startTime, endTime, stats, errors, ruleResults string
	var success int

	err := s.sqlite.ReadDB.QueryRowContext(ctx, query, syncID).Scan(
		&id, &result.FeedID, &result.FeedName, &startTime, &endTime,
		&result.Duration, &success, &stats, &errors, &ruleResults,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("sync result not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get sync result: %w", err)
	}

	result.Success = intToBool(success)
	result.StartTime, _ = time.Parse(time.RFC3339, startTime)
	result.EndTime, _ = time.Parse(time.RFC3339, endTime)
	json.Unmarshal([]byte(stats), &result.Stats)
	json.Unmarshal([]byte(errors), &result.Errors)
	json.Unmarshal([]byte(ruleResults), &result.RuleResults)

	return &result, nil
}

// Close closes the storage
func (s *SQLiteFeedStorage) Close() error {
	// DB is managed externally, don't close here
	return nil
}

// Helper functions
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func intToBool(i int) bool {
	return i != 0
}

func timeToString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
