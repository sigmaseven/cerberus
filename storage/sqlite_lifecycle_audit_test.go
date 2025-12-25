package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestLifecycleAuditStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Run migrations
	runner, err := NewMigrationRunner(sqlite.WriteDB, logger)
	require.NoError(t, err)
	RegisterSQLiteMigrations(runner)
	require.NoError(t, runner.RunMigrations())

	storage := NewSQLiteLifecycleAuditStorage(sqlite, logger)

	t.Run("CreateAuditEntry", func(t *testing.T) {
		entry := &LifecycleAuditEntry{
			RuleID:    "test-rule-1",
			OldStatus: "experimental",
			NewStatus: "test",
			Reason:    "Promoted after testing",
			ChangedBy: "user1",
			ChangedAt: time.Now().UTC(),
			AdditionalData: map[string]interface{}{
				"test_results": "passed",
			},
		}

		err := storage.CreateAuditEntry(entry)
		require.NoError(t, err)
		assert.NotZero(t, entry.ID)
	})

	t.Run("CreateAuditEntry_Validation", func(t *testing.T) {
		tests := []struct {
			name          string
			entry         *LifecycleAuditEntry
			expectedError string
		}{
			{
				name:          "Nil entry",
				entry:         nil,
				expectedError: "audit entry cannot be nil",
			},
			{
				name: "Missing rule_id",
				entry: &LifecycleAuditEntry{
					OldStatus: "test",
					NewStatus: "stable",
					ChangedBy: "user1",
				},
				expectedError: "rule_id is required",
			},
			{
				name: "Missing old_status",
				entry: &LifecycleAuditEntry{
					RuleID:    "test-rule",
					NewStatus: "stable",
					ChangedBy: "user1",
				},
				expectedError: "old_status is required",
			},
			{
				name: "Missing new_status",
				entry: &LifecycleAuditEntry{
					RuleID:    "test-rule",
					OldStatus: "test",
					ChangedBy: "user1",
				},
				expectedError: "new_status is required",
			},
			{
				name: "Missing changed_by",
				entry: &LifecycleAuditEntry{
					RuleID:    "test-rule",
					OldStatus: "test",
					NewStatus: "stable",
				},
				expectedError: "changed_by is required",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := storage.CreateAuditEntry(tt.entry)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			})
		}
	})

	t.Run("GetAuditHistory", func(t *testing.T) {
		// Create multiple audit entries
		entries := []LifecycleAuditEntry{
			{
				RuleID:    "test-rule-2",
				OldStatus: "experimental",
				NewStatus: "test",
				Reason:    "First transition",
				ChangedBy: "user1",
				ChangedAt: time.Now().UTC().Add(-48 * time.Hour),
			},
			{
				RuleID:    "test-rule-2",
				OldStatus: "test",
				NewStatus: "stable",
				Reason:    "Second transition",
				ChangedBy: "user2",
				ChangedAt: time.Now().UTC().Add(-24 * time.Hour),
			},
			{
				RuleID:    "test-rule-2",
				OldStatus: "stable",
				NewStatus: "deprecated",
				Reason:    "Third transition",
				ChangedBy: "user1",
				ChangedAt: time.Now().UTC(),
			},
		}

		for _, entry := range entries {
			e := entry
			require.NoError(t, storage.CreateAuditEntry(&e))
		}

		// Retrieve history
		history, err := storage.GetAuditHistory("test-rule-2", 10, 0)
		require.NoError(t, err)
		assert.Len(t, history, 3)

		// Verify chronological order (newest first)
		assert.Equal(t, "deprecated", history[0].NewStatus)
		assert.Equal(t, "stable", history[1].NewStatus)
		assert.Equal(t, "test", history[2].NewStatus)
	})

	t.Run("GetAuditHistoryCount", func(t *testing.T) {
		count, err := storage.GetAuditHistoryCount("test-rule-2")
		require.NoError(t, err)
		assert.Equal(t, int64(3), count)
	})

	t.Run("GetAuditHistoryPagination", func(t *testing.T) {
		// Test pagination
		page1, err := storage.GetAuditHistory("test-rule-2", 2, 0)
		require.NoError(t, err)
		assert.Len(t, page1, 2)

		page2, err := storage.GetAuditHistory("test-rule-2", 2, 2)
		require.NoError(t, err)
		assert.Len(t, page2, 1)

		// Verify no overlap
		assert.NotEqual(t, page1[0].ID, page2[0].ID)
	})

	t.Run("GetAuditEntriesByUser", func(t *testing.T) {
		entries, err := storage.GetAuditEntriesByUser("user1", 10, 0)
		require.NoError(t, err)
		assert.NotEmpty(t, entries)

		// Verify all entries are from user1
		for _, entry := range entries {
			assert.Equal(t, "user1", entry.ChangedBy)
		}
	})

	t.Run("GetRecentAuditEntries", func(t *testing.T) {
		entries, err := storage.GetRecentAuditEntries(10, 0)
		require.NoError(t, err)
		assert.NotEmpty(t, entries)

		// Verify chronological order
		for i := 1; i < len(entries); i++ {
			assert.True(t, entries[i-1].ChangedAt.After(entries[i].ChangedAt) ||
				entries[i-1].ChangedAt.Equal(entries[i].ChangedAt))
		}
	})

	t.Run("DeleteAuditEntriesForRule", func(t *testing.T) {
		// Create test entries
		entry := &LifecycleAuditEntry{
			RuleID:    "test-rule-delete",
			OldStatus: "experimental",
			NewStatus: "test",
			Reason:    "Test",
			ChangedBy: "user1",
			ChangedAt: time.Now().UTC(),
		}
		require.NoError(t, storage.CreateAuditEntry(entry))

		// Verify entry exists
		entries, err := storage.GetAuditHistory("test-rule-delete", 10, 0)
		require.NoError(t, err)
		assert.NotEmpty(t, entries)

		// Delete entries
		err = storage.DeleteAuditEntriesForRule("test-rule-delete")
		require.NoError(t, err)

		// Verify deletion
		entries, err = storage.GetAuditHistory("test-rule-delete", 10, 0)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}

func TestLifecycleManager(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Run migrations
	runner, err := NewMigrationRunner(sqlite.WriteDB, logger)
	require.NoError(t, err)
	RegisterSQLiteMigrations(runner)
	require.NoError(t, runner.RunMigrations())

	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)
	auditStorage := NewSQLiteLifecycleAuditStorage(sqlite, logger)
	manager := NewLifecycleManager(ruleStorage, auditStorage, sqlite, logger)

	t.Run("EnforceSunsetDates", func(t *testing.T) {
		// Create test rules with different sunset dates
		now := time.Now().UTC()
		pastSunset := now.Add(-24 * time.Hour)
		futureSunset := now.Add(24 * time.Hour)

		// Rule past sunset (should be disabled)
		_, err := sqlite.WriteDB.Exec(`
			INSERT INTO rules (id, type, name, description, severity, enabled, version, lifecycle_status, sunset_date, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, "rule-past", "sigma", "Past Sunset Rule", "Test", "low", 1, 1, "deprecated", pastSunset.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339))
		require.NoError(t, err)

		// Rule with future sunset (should remain enabled)
		_, err = sqlite.WriteDB.Exec(`
			INSERT INTO rules (id, type, name, description, severity, enabled, version, lifecycle_status, sunset_date, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, "rule-future", "sigma", "Future Sunset Rule", "Test", "low", 1, 1, "deprecated", futureSunset.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339))
		require.NoError(t, err)

		// Rule without sunset (should remain enabled)
		_, err = sqlite.WriteDB.Exec(`
			INSERT INTO rules (id, type, name, description, severity, enabled, version, lifecycle_status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, "rule-no-sunset", "sigma", "No Sunset Rule", "Test", "low", 1, 1, "deprecated", now.Format(time.RFC3339), now.Format(time.RFC3339))
		require.NoError(t, err)

		// Run sunset enforcement
		manager.enforceSunsetDates()

		// Verify past sunset rule is disabled
		var enabled bool
		err = sqlite.ReadDB.QueryRow("SELECT enabled FROM rules WHERE id = ?", "rule-past").Scan(&enabled)
		require.NoError(t, err)
		assert.False(t, enabled, "Rule past sunset should be disabled")

		// Verify future sunset rule is still enabled
		err = sqlite.ReadDB.QueryRow("SELECT enabled FROM rules WHERE id = ?", "rule-future").Scan(&enabled)
		require.NoError(t, err)
		assert.True(t, enabled, "Rule with future sunset should remain enabled")

		// Verify no sunset rule is still enabled
		err = sqlite.ReadDB.QueryRow("SELECT enabled FROM rules WHERE id = ?", "rule-no-sunset").Scan(&enabled)
		require.NoError(t, err)
		assert.True(t, enabled, "Rule without sunset should remain enabled")

		// Verify audit entry was created
		entries, err := auditStorage.GetAuditHistory("rule-past", 10, 0)
		require.NoError(t, err)
		assert.NotEmpty(t, entries)
		assert.Equal(t, "system", entries[0].ChangedBy)
		assert.Contains(t, entries[0].Reason, "sunset date")
	})

	t.Run("GetSunsetStatus", func(t *testing.T) {
		status, err := manager.GetSunsetStatus()
		require.NoError(t, err)
		assert.NotNil(t, status)
		assert.Greater(t, status.TotalDeprecated, int64(0))
	})
}
