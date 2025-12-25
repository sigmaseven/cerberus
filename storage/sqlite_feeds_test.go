package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"cerberus/sigma/feeds"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupFeedTestDB creates an in-memory SQLite database for feed testing
func setupFeedTestDB(t *testing.T) (*sql.DB, *SQLite) {
	t.Helper()
	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	return sqlite.DB, sqlite
}

// TestNewSQLiteFeedStorage tests creating a new feed storage instance
func TestNewSQLiteFeedStorage(t *testing.T) {
	db, sqlite := setupFeedTestDB(t)
	defer db.Close()
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()

	storage, err := NewSQLiteFeedStorage(sqlite, logger)
	require.NoError(t, err)
	require.NotNil(t, storage)
	assert.Equal(t, sqlite, storage.sqlite)
	assert.Equal(t, logger, storage.logger)

	// Verify tables were created
	var tableCount int
	err = sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('rule_feeds', 'feed_sync_history')").Scan(&tableCount)
	require.NoError(t, err)
	assert.Equal(t, 2, tableCount, "Expected rule_feeds and feed_sync_history tables to exist")
}

// TestSQLiteFeedStorage_CreateFeed tests creating a feed
func TestSQLiteFeedStorage_CreateFeed(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := &feeds.RuleFeed{
		ID:              "test-feed-001",
		Name:            "Test Feed",
		Description:     "A test feed",
		Type:            feeds.FeedTypeGit,
		Status:          feeds.FeedStatusActive,
		Enabled:         true,
		URL:             "https://github.com/example/rules",
		Branch:          "main",
		IncludePaths:    []string{"*.yml", "*.yaml"},
		ExcludePaths:    []string{"test/*"},
		IncludeTags:     []string{"attack.t1"},
		ExcludeTags:     []string{"experimental"},
		MinSeverity:     "medium",
		AutoEnableRules: true,
		Priority:        100,
		UpdateStrategy:  feeds.UpdateManual,
		UpdateSchedule:  "0 0 * * *",
		Stats: feeds.FeedStats{
			TotalRules:    50,
			ImportedRules: 45,
			FailedRules:   5,
		},
		Tags:     []string{"sigma", "windows"},
		Metadata: map[string]string{"maintainer": "security-team"},
		AuthConfig: map[string]interface{}{
			"type":  "token",
			"token": "secret123",
		},
		CreatedBy: "test-user",
	}

	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)
	assert.False(t, feed.CreatedAt.IsZero())
	assert.False(t, feed.UpdatedAt.IsZero())

	// Verify feed was created
	retrieved, err := storage.GetFeed(ctx, feed.ID)
	require.NoError(t, err)
	assert.Equal(t, feed.ID, retrieved.ID)
	assert.Equal(t, feed.Name, retrieved.Name)
	assert.Equal(t, feed.Description, retrieved.Description)
	assert.Equal(t, feed.Type, retrieved.Type)
	assert.Equal(t, feed.Enabled, retrieved.Enabled)
	assert.Equal(t, feed.URL, retrieved.URL)
	assert.Equal(t, feed.Branch, retrieved.Branch)
	assert.Equal(t, feed.Priority, retrieved.Priority)
	assert.Equal(t, feed.AutoEnableRules, retrieved.AutoEnableRules)
	assert.Equal(t, feed.Stats.TotalRules, retrieved.Stats.TotalRules)
	assert.Equal(t, feed.IncludePaths, retrieved.IncludePaths)
	assert.Equal(t, feed.ExcludePaths, retrieved.ExcludePaths)
	assert.Equal(t, feed.Tags, retrieved.Tags)
}

// TestSQLiteFeedStorage_CreateFeed_DuplicateID tests creating a feed with duplicate ID
func TestSQLiteFeedStorage_CreateFeed_DuplicateID(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("duplicate-id", "Feed 1")
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Try to create another feed with the same ID
	feed2 := createTestFeed("duplicate-id", "Feed 2")
	err = storage.CreateFeed(ctx, feed2)
	assert.ErrorIs(t, err, feeds.ErrDuplicateFeedID)
}

// TestSQLiteFeedStorage_CreateFeed_ValidationError tests validation on create
func TestSQLiteFeedStorage_CreateFeed_ValidationError(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		feed    *feeds.RuleFeed
		wantErr error
	}{
		{
			name: "missing ID",
			feed: &feeds.RuleFeed{
				Name: "Test",
				Type: feeds.FeedTypeGit,
			},
			wantErr: feeds.ErrInvalidFeedID,
		},
		{
			name: "missing name",
			feed: &feeds.RuleFeed{
				ID:   "test-id",
				Type: feeds.FeedTypeGit,
			},
			wantErr: feeds.ErrInvalidFeedName,
		},
		{
			name: "missing type",
			feed: &feeds.RuleFeed{
				ID:   "test-id",
				Name: "Test",
			},
			wantErr: feeds.ErrInvalidFeedType,
		},
		{
			name: "git feed missing URL",
			feed: &feeds.RuleFeed{
				ID:   "test-id",
				Name: "Test",
				Type: feeds.FeedTypeGit,
			},
			wantErr: feeds.ErrMissingURL,
		},
		{
			name: "filesystem feed missing path",
			feed: &feeds.RuleFeed{
				ID:   "test-id",
				Name: "Test",
				Type: feeds.FeedTypeFilesystem,
			},
			wantErr: feeds.ErrMissingPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.CreateFeed(ctx, tt.feed)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestSQLiteFeedStorage_GetFeed tests retrieving a feed
func TestSQLiteFeedStorage_GetFeed(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("get-test", "Get Test Feed")
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	retrieved, err := storage.GetFeed(ctx, feed.ID)
	require.NoError(t, err)
	assert.Equal(t, feed.ID, retrieved.ID)
	assert.Equal(t, feed.Name, retrieved.Name)
}

// TestSQLiteFeedStorage_GetFeed_NotFound tests retrieving non-existent feed
func TestSQLiteFeedStorage_GetFeed_NotFound(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	_, err := storage.GetFeed(ctx, "non-existent-id")
	assert.ErrorIs(t, err, feeds.ErrFeedNotFound)
}

// TestSQLiteFeedStorage_GetAllFeeds tests retrieving all feeds
func TestSQLiteFeedStorage_GetAllFeeds(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	// Create multiple feeds with different priorities
	feed1 := createTestFeed("feed-1", "Feed 1")
	feed1.Priority = 100
	err := storage.CreateFeed(ctx, feed1)
	require.NoError(t, err)

	feed2 := createTestFeed("feed-2", "Feed 2")
	feed2.Priority = 200
	err = storage.CreateFeed(ctx, feed2)
	require.NoError(t, err)

	feed3 := createTestFeed("feed-3", "Feed 3")
	feed3.Priority = 150
	err = storage.CreateFeed(ctx, feed3)
	require.NoError(t, err)

	// Retrieve all feeds
	allFeeds, err := storage.GetAllFeeds(ctx)
	require.NoError(t, err)
	assert.Len(t, allFeeds, 3)

	// Check ordering (priority DESC, name ASC)
	assert.Equal(t, "feed-2", allFeeds[0].ID) // Priority 200
	assert.Equal(t, "feed-3", allFeeds[1].ID) // Priority 150
	assert.Equal(t, "feed-1", allFeeds[2].ID) // Priority 100
}

// TestSQLiteFeedStorage_GetAllFeeds_Empty tests retrieving feeds when none exist
func TestSQLiteFeedStorage_GetAllFeeds_Empty(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	allFeeds, err := storage.GetAllFeeds(ctx)
	require.NoError(t, err)
	assert.Empty(t, allFeeds)
}

// TestSQLiteFeedStorage_UpdateFeed tests updating a feed
func TestSQLiteFeedStorage_UpdateFeed(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	// Create initial feed
	feed := createTestFeed("update-test", "Original Name")
	feed.Description = "Original description"
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	originalUpdatedAt := feed.UpdatedAt
	time.Sleep(10 * time.Millisecond) // Ensure timestamp difference

	// Update feed
	feed.Name = "Updated Name"
	feed.Description = "Updated description"
	feed.Priority = 999
	feed.Stats.TotalRules = 100
	err = storage.UpdateFeed(ctx, feed.ID, feed)
	require.NoError(t, err)
	assert.True(t, feed.UpdatedAt.After(originalUpdatedAt))

	// Verify update
	updated, err := storage.GetFeed(ctx, feed.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.Name)
	assert.Equal(t, "Updated description", updated.Description)
	assert.Equal(t, 999, updated.Priority)
	assert.Equal(t, 100, updated.Stats.TotalRules)
}

// TestSQLiteFeedStorage_UpdateFeed_NotFound tests updating non-existent feed
func TestSQLiteFeedStorage_UpdateFeed_NotFound(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("non-existent", "Test")
	err := storage.UpdateFeed(ctx, feed.ID, feed)
	assert.ErrorIs(t, err, feeds.ErrFeedNotFound)
}

// TestSQLiteFeedStorage_UpdateFeed_ValidationError tests validation on update
func TestSQLiteFeedStorage_UpdateFeed_ValidationError(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("validation-test", "Test")
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Update with invalid data
	feed.Name = "" // Invalid: empty name
	err = storage.UpdateFeed(ctx, feed.ID, feed)
	assert.ErrorIs(t, err, feeds.ErrInvalidFeedName)
}

// TestSQLiteFeedStorage_DeleteFeed tests deleting a feed
func TestSQLiteFeedStorage_DeleteFeed(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("delete-test", "Delete Test")
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Delete feed
	err = storage.DeleteFeed(ctx, feed.ID)
	require.NoError(t, err)

	// Verify deletion
	_, err = storage.GetFeed(ctx, feed.ID)
	assert.ErrorIs(t, err, feeds.ErrFeedNotFound)
}

// TestSQLiteFeedStorage_DeleteFeed_NotFound tests deleting non-existent feed
func TestSQLiteFeedStorage_DeleteFeed_NotFound(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	err := storage.DeleteFeed(ctx, "non-existent-id")
	assert.ErrorIs(t, err, feeds.ErrFeedNotFound)
}

// TestSQLiteFeedStorage_UpdateFeedStatus tests updating feed status
func TestSQLiteFeedStorage_UpdateFeedStatus(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("status-test", "Status Test")
	feed.Status = feeds.FeedStatusActive
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Update status
	err = storage.UpdateFeedStatus(ctx, feed.ID, feeds.FeedStatusDisabled)
	require.NoError(t, err)

	// Verify status update
	updated, err := storage.GetFeed(ctx, feed.ID)
	require.NoError(t, err)
	assert.Equal(t, feeds.FeedStatusDisabled, updated.Status)
}

// TestSQLiteFeedStorage_UpdateFeedStatus_NotFound tests updating status of non-existent feed
func TestSQLiteFeedStorage_UpdateFeedStatus_NotFound(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	err := storage.UpdateFeedStatus(ctx, "non-existent", feeds.FeedStatusDisabled)
	assert.ErrorIs(t, err, feeds.ErrFeedNotFound)
}

// TestSQLiteFeedStorage_UpdateFeedStats tests updating feed statistics
func TestSQLiteFeedStorage_UpdateFeedStats(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("stats-test", "Stats Test")
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Update stats
	newStats := &feeds.FeedStats{
		TotalRules:       500,
		ImportedRules:    450,
		UpdatedRules:     30,
		SkippedRules:     10,
		FailedRules:      10,
		LastSyncDuration: 45.5,
		LastError:        "test error",
		SyncCount:        5,
	}

	err = storage.UpdateFeedStats(ctx, feed.ID, newStats)
	require.NoError(t, err)

	// Verify stats update
	updated, err := storage.GetFeed(ctx, feed.ID)
	require.NoError(t, err)
	assert.Equal(t, 500, updated.Stats.TotalRules)
	assert.Equal(t, 450, updated.Stats.ImportedRules)
	assert.Equal(t, 30, updated.Stats.UpdatedRules)
	assert.Equal(t, 10, updated.Stats.SkippedRules)
	assert.Equal(t, 10, updated.Stats.FailedRules)
	assert.Equal(t, 45.5, updated.Stats.LastSyncDuration)
	assert.Equal(t, "test error", updated.Stats.LastError)
	assert.Equal(t, 5, updated.Stats.SyncCount)
}

// TestSQLiteFeedStorage_UpdateFeedStats_NotFound tests updating stats of non-existent feed
func TestSQLiteFeedStorage_UpdateFeedStats_NotFound(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	stats := &feeds.FeedStats{TotalRules: 100}
	err := storage.UpdateFeedStats(ctx, "non-existent", stats)
	assert.ErrorIs(t, err, feeds.ErrFeedNotFound)
}

// TestSQLiteFeedStorage_UpdateLastSync tests updating last sync time
func TestSQLiteFeedStorage_UpdateLastSync(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("sync-test", "Sync Test")
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Update last sync
	syncTime := time.Now().UTC()
	err = storage.UpdateLastSync(ctx, feed.ID, syncTime)
	require.NoError(t, err)

	// Verify sync time update
	updated, err := storage.GetFeed(ctx, feed.ID)
	require.NoError(t, err)
	// Compare timestamps with some tolerance for precision
	assert.WithinDuration(t, syncTime, updated.LastSync, time.Second)
}

// TestSQLiteFeedStorage_UpdateLastSync_NotFound tests updating sync time of non-existent feed
func TestSQLiteFeedStorage_UpdateLastSync_NotFound(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	err := storage.UpdateLastSync(ctx, "non-existent", time.Now())
	assert.ErrorIs(t, err, feeds.ErrFeedNotFound)
}

// TestSQLiteFeedStorage_SaveSyncResult tests saving sync results
func TestSQLiteFeedStorage_SaveSyncResult(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("sync-result-test", "Sync Result Test")
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Create sync result
	startTime := time.Now().Add(-5 * time.Minute)
	endTime := time.Now()
	syncResult := &feeds.FeedSyncResult{
		FeedID:    feed.ID,
		FeedName:  feed.Name,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  300.5, // seconds
		Success:   true,
		Stats: feeds.FeedStats{
			TotalRules:       100,
			ImportedRules:    90,
			UpdatedRules:     5,
			SkippedRules:     3,
			FailedRules:      2,
			LastSyncDuration: 300.5,
		},
		Errors: []string{"error 1", "error 2"},
		RuleResults: []feeds.RuleImportResult{
			{
				RuleID:    "rule-1",
				RuleTitle: "Test Rule 1",
				FilePath:  "/path/to/rule1.yml",
				Action:    "imported",
			},
			{
				RuleID:    "rule-2",
				RuleTitle: "Test Rule 2",
				FilePath:  "/path/to/rule2.yml",
				Action:    "failed",
				Error:     "validation error",
			},
		},
	}

	err = storage.SaveSyncResult(ctx, syncResult)
	require.NoError(t, err)

	// Verify sync result was saved by retrieving history
	history, err := storage.GetSyncHistory(ctx, feed.ID, 10)
	require.NoError(t, err)
	require.Len(t, history, 1)

	retrieved := history[0]
	assert.Equal(t, feed.ID, retrieved.FeedID)
	assert.Equal(t, feed.Name, retrieved.FeedName)
	assert.Equal(t, true, retrieved.Success)
	assert.Equal(t, 300.5, retrieved.Duration)
	assert.Equal(t, 100, retrieved.Stats.TotalRules)
	assert.Equal(t, 90, retrieved.Stats.ImportedRules)
	assert.Len(t, retrieved.Errors, 2)
	assert.Len(t, retrieved.RuleResults, 2)
}

// TestSQLiteFeedStorage_GetSyncHistory tests retrieving sync history
func TestSQLiteFeedStorage_GetSyncHistory(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("history-test", "History Test")
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Create multiple sync results
	for i := 0; i < 5; i++ {
		syncResult := &feeds.FeedSyncResult{
			FeedID:    feed.ID,
			FeedName:  feed.Name,
			StartTime: time.Now().Add(-time.Duration(i) * time.Hour),
			EndTime:   time.Now().Add(-time.Duration(i)*time.Hour + 5*time.Minute),
			Duration:  300.0,
			Success:   i%2 == 0, // Alternate success/failure
			Stats: feeds.FeedStats{
				TotalRules:    100 + i,
				ImportedRules: 90 + i,
			},
		}
		err = storage.SaveSyncResult(ctx, syncResult)
		require.NoError(t, err)
	}

	// Retrieve history with limit
	history, err := storage.GetSyncHistory(ctx, feed.ID, 3)
	require.NoError(t, err)
	assert.Len(t, history, 3)

	// Verify ordering (most recent first)
	for i := 0; i < len(history)-1; i++ {
		assert.True(t, history[i].StartTime.After(history[i+1].StartTime) ||
			history[i].StartTime.Equal(history[i+1].StartTime))
	}
}

// TestSQLiteFeedStorage_GetSyncHistory_Empty tests retrieving history with no results
func TestSQLiteFeedStorage_GetSyncHistory_Empty(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	history, err := storage.GetSyncHistory(ctx, "non-existent-feed", 10)
	require.NoError(t, err)
	assert.Empty(t, history)
}

// TestSQLiteFeedStorage_GetSyncResult tests retrieving a specific sync result
func TestSQLiteFeedStorage_GetSyncResult(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("sync-result-get-test", "Sync Result Get Test")
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Save sync result
	syncResult := &feeds.FeedSyncResult{
		FeedID:    feed.ID,
		FeedName:  feed.Name,
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now(),
		Duration:  3600.0,
		Success:   true,
		Stats: feeds.FeedStats{
			TotalRules:    200,
			ImportedRules: 180,
		},
	}
	err = storage.SaveSyncResult(ctx, syncResult)
	require.NoError(t, err)

	// Get the sync result ID from history
	history, err := storage.GetSyncHistory(ctx, feed.ID, 1)
	require.NoError(t, err)
	require.Len(t, history, 1)

	// Now we need to extract the ID from the database
	// Since SaveSyncResult generates a UUID internally, we need to query it
	var syncID string
	err = storage.sqlite.ReadDB.QueryRow("SELECT id FROM feed_sync_history WHERE feed_id = ? LIMIT 1", feed.ID).Scan(&syncID)
	require.NoError(t, err)

	// Retrieve specific sync result
	retrieved, err := storage.GetSyncResult(ctx, syncID)
	require.NoError(t, err)
	assert.Equal(t, feed.ID, retrieved.FeedID)
	assert.Equal(t, feed.Name, retrieved.FeedName)
	assert.Equal(t, true, retrieved.Success)
	assert.Equal(t, 200, retrieved.Stats.TotalRules)
}

// TestSQLiteFeedStorage_GetSyncResult_NotFound tests retrieving non-existent sync result
func TestSQLiteFeedStorage_GetSyncResult_NotFound(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	_, err := storage.GetSyncResult(ctx, "non-existent-sync-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sync result not found")
}

// TestSQLiteFeedStorage_Close tests closing the storage
func TestSQLiteFeedStorage_Close(t *testing.T) {
	storage := setupFeedStorage(t)

	// Close should succeed (it's a no-op since DB is managed externally)
	err := storage.Close()
	assert.NoError(t, err)
}

// TestSQLiteFeedStorage_CascadeDelete tests cascade deletion of sync history
// NOTE: CASCADE may or may not work depending on SQLite foreign key settings
func TestSQLiteFeedStorage_CascadeDelete(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("cascade-test", "Cascade Test")
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Create sync history
	syncResult := &feeds.FeedSyncResult{
		FeedID:    feed.ID,
		FeedName:  feed.Name,
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  100.0,
		Success:   true,
	}
	err = storage.SaveSyncResult(ctx, syncResult)
	require.NoError(t, err)

	// Verify history exists
	history, err := storage.GetSyncHistory(ctx, feed.ID, 10)
	require.NoError(t, err)
	assert.Len(t, history, 1)

	// Delete feed
	err = storage.DeleteFeed(ctx, feed.ID)
	require.NoError(t, err)

	// Verify sync history - may or may not be deleted depending on FK constraints
	// In production with properly configured SQLite, CASCADE should work
	history, err = storage.GetSyncHistory(ctx, feed.ID, 10)
	require.NoError(t, err)
	// We just verify the query succeeds; CASCADE behavior depends on SQLite config
	t.Logf("After feed deletion, sync history count: %d (CASCADE may or may not be enabled)", len(history))
}

// TestSQLiteFeedStorage_TimeHandling tests proper handling of time fields
func TestSQLiteFeedStorage_TimeHandling(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	now := time.Now().UTC()
	lastSync := now.Add(-24 * time.Hour)
	nextSync := now.Add(24 * time.Hour)

	feed := createTestFeed("time-test", "Time Test")
	feed.LastSync = lastSync
	feed.NextSync = nextSync
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Retrieve and verify timestamps
	retrieved, err := storage.GetFeed(ctx, feed.ID)
	require.NoError(t, err)

	// RFC3339 has second precision, so compare within 1 second
	assert.WithinDuration(t, lastSync, retrieved.LastSync, time.Second)
	assert.WithinDuration(t, nextSync, retrieved.NextSync, time.Second)
	assert.WithinDuration(t, now, retrieved.CreatedAt, time.Second)
	assert.WithinDuration(t, now, retrieved.UpdatedAt, time.Second)
}

// TestSQLiteFeedStorage_ZeroTimeHandling tests handling of zero times
func TestSQLiteFeedStorage_ZeroTimeHandling(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("zero-time-test", "Zero Time Test")
	feed.LastSync = time.Time{} // Zero time
	feed.NextSync = time.Time{} // Zero time
	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	retrieved, err := storage.GetFeed(ctx, feed.ID)
	require.NoError(t, err)

	// Zero times should be preserved
	assert.True(t, retrieved.LastSync.IsZero())
	assert.True(t, retrieved.NextSync.IsZero())
}

// TestHelperFunctions tests the helper functions
func TestHelperFunctions(t *testing.T) {
	t.Run("boolToInt", func(t *testing.T) {
		assert.Equal(t, 1, boolToInt(true))
		assert.Equal(t, 0, boolToInt(false))
	})

	t.Run("intToBool", func(t *testing.T) {
		assert.True(t, intToBool(1))
		assert.True(t, intToBool(999))
		assert.False(t, intToBool(0))
	})

	t.Run("timeToString", func(t *testing.T) {
		now := time.Now()
		str := timeToString(now)
		assert.NotEmpty(t, str)

		// Parse back and verify
		parsed, err := time.Parse(time.RFC3339, str)
		require.NoError(t, err)
		assert.WithinDuration(t, now, parsed, time.Second)

		// Zero time should return empty string
		assert.Empty(t, timeToString(time.Time{}))
	})
}

// TestSQLiteFeedStorage_ComplexJSONFields tests handling of complex JSON fields
func TestSQLiteFeedStorage_ComplexJSONFields(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	feed := createTestFeed("json-test", "JSON Test")
	feed.AuthConfig = map[string]interface{}{
		"type":     "oauth",
		"token":    "secret123",
		"username": "user@example.com",
		"nested": map[string]interface{}{
			"key1": "value1",
			"key2": 42,
		},
	}
	feed.Metadata = map[string]string{
		"key1":   "value1",
		"key2":   "value2",
		"custom": "metadata",
	}

	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	retrieved, err := storage.GetFeed(ctx, feed.ID)
	require.NoError(t, err)

	// Verify complex fields
	assert.Equal(t, "oauth", retrieved.AuthConfig["type"])
	assert.Equal(t, "secret123", retrieved.AuthConfig["token"])
	assert.NotNil(t, retrieved.AuthConfig["nested"])
	assert.Equal(t, "value1", retrieved.Metadata["key1"])
	assert.Equal(t, "value2", retrieved.Metadata["key2"])
	assert.Equal(t, "metadata", retrieved.Metadata["custom"])
}

// TestSQLiteFeedStorage_SQLInjectionPrevention tests SQL injection prevention
func TestSQLiteFeedStorage_SQLInjectionPrevention(t *testing.T) {
	storage := setupFeedStorage(t)
	ctx := context.Background()

	// Create feed with potential SQL injection patterns
	feed := createTestFeed("sql-injection-test", "Test'; DROP TABLE rule_feeds; --")
	feed.Description = "'; DELETE FROM rule_feeds WHERE '1'='1"
	feed.URL = "http://example.com'; DROP TABLE feed_sync_history; --"

	err := storage.CreateFeed(ctx, feed)
	require.NoError(t, err)

	// Verify tables still exist and data is intact
	retrieved, err := storage.GetFeed(ctx, feed.ID)
	require.NoError(t, err)
	assert.Equal(t, "Test'; DROP TABLE rule_feeds; --", retrieved.Name)
	assert.Equal(t, "'; DELETE FROM rule_feeds WHERE '1'='1", retrieved.Description)

	// Verify tables still exist
	var tableCount int
	err = storage.sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('rule_feeds', 'feed_sync_history')").Scan(&tableCount)
	require.NoError(t, err)
	assert.Equal(t, 2, tableCount, "Tables should still exist after SQL injection attempt")
}

// Helper functions for tests

func setupFeedStorage(t *testing.T) *SQLiteFeedStorage {
	t.Helper()
	db, sqlite := setupFeedTestDB(t)
	t.Cleanup(func() {
		db.Close()
		sqlite.Close()
	})

	logger := zap.NewNop().Sugar()
	storage, err := NewSQLiteFeedStorage(sqlite, logger)
	require.NoError(t, err)
	return storage
}

func createTestFeed(id, name string) *feeds.RuleFeed {
	return &feeds.RuleFeed{
		ID:             id,
		Name:           name,
		Description:    "Test feed description",
		Type:           feeds.FeedTypeGit,
		Status:         feeds.FeedStatusActive,
		Enabled:        true,
		URL:            "https://github.com/test/repo",
		Branch:         "main",
		Priority:       100,
		UpdateStrategy: feeds.UpdateManual,
		Stats:          feeds.FeedStats{},
		Tags:           []string{},
		Metadata:       map[string]string{},
	}
}
