package storage

import (
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// setupExceptionTestDB creates an in-memory SQLite database with exceptions table
func setupExceptionTestDB(t *testing.T) (*SQLite, *SQLiteExceptionStorage) {
	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)

	storage := NewSQLiteExceptionStorage(sqlite)
	return sqlite, storage
}

// TestNewSQLiteExceptionStorage tests storage creation
func TestNewSQLiteExceptionStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteExceptionStorage(sqlite)
	require.NotNil(t, storage)
	assert.Equal(t, sqlite, storage.sqlite)
}

// TestEnsureIndexes_Exceptions tests index creation
func TestEnsureIndexes_Exceptions(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	err := storage.EnsureIndexes()
	require.NoError(t, err)

	// Verify indexes exist by querying sqlite_master
	rows, err := sqlite.ReadDB.Query("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='exceptions'")
	require.NoError(t, err)
	defer rows.Close()

	indexes := make(map[string]bool)
	for rows.Next() {
		var name string
		err := rows.Scan(&name)
		require.NoError(t, err)
		indexes[name] = true
	}

	assert.True(t, indexes["idx_exceptions_rule_id"])
	assert.True(t, indexes["idx_exceptions_enabled"])
	assert.True(t, indexes["idx_exceptions_priority"])
}

// TestCreateException_Success tests successful exception creation
func TestCreateException_Success(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	exception := &core.Exception{
		Name:          "Test Exception",
		Description:   "Test Description",
		RuleID:        "rule-001",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "source_ip == '192.168.1.1'",
		Enabled:       true,
		Priority:      10,
		Tags:          []string{"test", "dev"},
		CreatedBy:     "admin",
		Justification: "Testing purposes",
	}

	err := storage.CreateException(exception)
	require.NoError(t, err)

	// Verify exception was created
	assert.NotEmpty(t, exception.ID)
	assert.False(t, exception.CreatedAt.IsZero())
	assert.False(t, exception.UpdatedAt.IsZero())

	// Retrieve and verify
	retrieved, err := storage.GetException(exception.ID)
	require.NoError(t, err)
	assert.Equal(t, exception.Name, retrieved.Name)
	assert.Equal(t, exception.RuleID, retrieved.RuleID)
	assert.Equal(t, exception.Type, retrieved.Type)
	assert.Equal(t, exception.Tags, retrieved.Tags)
}

// TestCreateException_AutoGenerateID tests ID auto-generation
func TestCreateException_AutoGenerateID(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	exception := &core.Exception{
		Name:          "Auto ID Test",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
	}

	err := storage.CreateException(exception)
	require.NoError(t, err)
	assert.NotEmpty(t, exception.ID)
}

// TestCreateException_WithExpiresAt tests exception with expiration
func TestCreateException_WithExpiresAt(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	expiresAt := time.Now().Add(24 * time.Hour)
	exception := &core.Exception{
		Name:          "Expiring Exception",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
		ExpiresAt:     &expiresAt,
	}

	err := storage.CreateException(exception)
	require.NoError(t, err)

	retrieved, err := storage.GetException(exception.ID)
	require.NoError(t, err)
	assert.NotNil(t, retrieved.ExpiresAt)
	assert.True(t, retrieved.ExpiresAt.Sub(expiresAt) < time.Second)
}

// TestGetException_Success tests retrieving existing exception
func TestGetException_Success(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	exception := &core.Exception{
		ID:            "test-001",
		Name:          "Get Test",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
	}

	err := storage.CreateException(exception)
	require.NoError(t, err)

	retrieved, err := storage.GetException("test-001")
	require.NoError(t, err)
	assert.Equal(t, "Get Test", retrieved.Name)
}

// TestGetException_NotFound tests retrieving non-existent exception
func TestGetException_NotFound(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	exception, err := storage.GetException("nonexistent")
	assert.Error(t, err)
	assert.Nil(t, exception)
	assert.Contains(t, err.Error(), "not found")
}

// TestGetAllExceptions_Success tests listing exceptions
func TestGetAllExceptions_Success(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	// Create multiple exceptions
	for i := 0; i < 5; i++ {
		exception := &core.Exception{
			Name:          "Exception " + string(rune('A'+i)),
			Type:          core.ExceptionSuppress,
			ConditionType: core.ConditionTypeCQL,
			Condition:     "test",
			Priority:      i,
		}
		err := storage.CreateException(exception)
		require.NoError(t, err)
	}

	exceptions, total, err := storage.GetAllExceptions(nil)
	require.NoError(t, err)
	assert.Len(t, exceptions, 5)
	assert.Equal(t, int64(5), total)
}

// TestGetAllExceptions_Pagination tests pagination
func TestGetAllExceptions_Pagination(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	// Create 25 exceptions
	for i := 0; i < 25; i++ {
		exception := &core.Exception{
			Name:          "Exception",
			Type:          core.ExceptionSuppress,
			ConditionType: core.ConditionTypeCQL,
			Condition:     "test",
		}
		err := storage.CreateException(exception)
		require.NoError(t, err)
	}

	// Test pagination
	filters := &core.ExceptionFilters{
		Page:  1,
		Limit: 10,
	}

	exceptions, total, err := storage.GetAllExceptions(filters)
	require.NoError(t, err)
	assert.Len(t, exceptions, 10)
	assert.Equal(t, int64(25), total)

	// Get second page
	filters.Page = 2
	exceptions, total, err = storage.GetAllExceptions(filters)
	require.NoError(t, err)
	assert.Len(t, exceptions, 10)
	assert.Equal(t, int64(25), total)
}

// TestGetAllExceptions_FilterByRuleID tests filtering by rule ID
func TestGetAllExceptions_FilterByRuleID(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	// Create exceptions for different rules
	for _, ruleID := range []string{"rule-001", "rule-002", "rule-003"} {
		exception := &core.Exception{
			Name:          "Exception for " + ruleID,
			RuleID:        ruleID,
			Type:          core.ExceptionSuppress,
			ConditionType: core.ConditionTypeCQL,
			Condition:     "test",
		}
		err := storage.CreateException(exception)
		require.NoError(t, err)
	}

	filters := &core.ExceptionFilters{
		RuleID: "rule-001",
		Page:   1,
		Limit:  100,
	}

	exceptions, total, err := storage.GetAllExceptions(filters)
	require.NoError(t, err)
	assert.Len(t, exceptions, 1)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, "rule-001", exceptions[0].RuleID)
}

// TestGetAllExceptions_FilterByEnabled tests filtering by enabled status
func TestGetAllExceptions_FilterByEnabled(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	// Create enabled and disabled exceptions
	for i := 0; i < 5; i++ {
		exception := &core.Exception{
			Name:          "Exception",
			Type:          core.ExceptionSuppress,
			ConditionType: core.ConditionTypeCQL,
			Condition:     "test",
			Enabled:       i%2 == 0,
		}
		err := storage.CreateException(exception)
		require.NoError(t, err)
	}

	enabled := true
	filters := &core.ExceptionFilters{
		Enabled: &enabled,
		Page:    1,
		Limit:   100,
	}

	exceptions, total, err := storage.GetAllExceptions(filters)
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	for _, ex := range exceptions {
		assert.True(t, ex.Enabled)
	}
}

// TestGetAllExceptions_FilterByExpired tests filtering expired exceptions
func TestGetAllExceptions_FilterByExpired(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	past := time.Now().Add(-24 * time.Hour)
	future := time.Now().Add(24 * time.Hour)

	// Create expired exception
	expiredException := &core.Exception{
		Name:          "Expired",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
		ExpiresAt:     &past,
	}
	err := storage.CreateException(expiredException)
	require.NoError(t, err)

	// Create active exception
	activeException := &core.Exception{
		Name:          "Active",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
		ExpiresAt:     &future,
	}
	err = storage.CreateException(activeException)
	require.NoError(t, err)

	// Filter for expired
	expired := true
	filters := &core.ExceptionFilters{
		Expired: &expired,
		Page:    1,
		Limit:   100,
	}

	exceptions, total, err := storage.GetAllExceptions(filters)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, "Expired", exceptions[0].Name)
}

// TestGetAllExceptions_Search tests search functionality
func TestGetAllExceptions_Search(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	exceptions := []*core.Exception{
		{
			Name:          "SQL Injection Exception",
			Description:   "Allows specific SQL patterns",
			Type:          core.ExceptionSuppress,
			ConditionType: core.ConditionTypeCQL,
			Condition:     "test",
		},
		{
			Name:          "XSS Exception",
			Description:   "Cross-site scripting whitelist",
			Type:          core.ExceptionSuppress,
			ConditionType: core.ConditionTypeCQL,
			Condition:     "test",
		},
	}

	for _, ex := range exceptions {
		err := storage.CreateException(ex)
		require.NoError(t, err)
	}

	filters := &core.ExceptionFilters{
		Search: "SQL",
		Page:   1,
		Limit:  100,
	}

	results, total, err := storage.GetAllExceptions(filters)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Contains(t, results[0].Name, "SQL")
}

// TestGetAllExceptions_Sorting tests sorting functionality
func TestGetAllExceptions_Sorting(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	// Create exceptions with different priorities
	for i := 0; i < 5; i++ {
		exception := &core.Exception{
			Name:          "Exception",
			Type:          core.ExceptionSuppress,
			ConditionType: core.ConditionTypeCQL,
			Condition:     "test",
			Priority:      i,
		}
		err := storage.CreateException(exception)
		require.NoError(t, err)
	}

	// Sort by priority ascending
	filters := &core.ExceptionFilters{
		Page:      1,
		Limit:     100,
		SortBy:    "priority",
		SortOrder: "asc",
	}

	exceptions, _, err := storage.GetAllExceptions(filters)
	require.NoError(t, err)
	assert.Equal(t, 0, exceptions[0].Priority)
	assert.Equal(t, 4, exceptions[4].Priority)

	// Sort by priority descending
	filters.SortOrder = "desc"
	exceptions, _, err = storage.GetAllExceptions(filters)
	require.NoError(t, err)
	assert.Equal(t, 4, exceptions[0].Priority)
	assert.Equal(t, 0, exceptions[4].Priority)
}

// TestGetAllExceptions_SQLInjectionPrevention tests SQL injection protection
func TestGetAllExceptions_SQLInjectionPrevention(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	// Create a normal exception
	exception := &core.Exception{
		Name:          "Normal Exception",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
	}
	err := storage.CreateException(exception)
	require.NoError(t, err)

	// Try SQL injection in sort fields
	maliciousSortBy := []string{
		"priority; DROP TABLE exceptions; --",
		"name' OR '1'='1",
		"priority UNION SELECT * FROM users",
	}

	for _, malicious := range maliciousSortBy {
		filters := &core.ExceptionFilters{
			Page:      1,
			Limit:     100,
			SortBy:    malicious,
			SortOrder: "asc",
		}

		// Should default to safe sort field
		exceptions, _, err := storage.GetAllExceptions(filters)
		require.NoError(t, err)
		assert.NotEmpty(t, exceptions)
	}

	// Verify table still exists
	var count int
	err = sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM exceptions").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestGetAllExceptions_ExcessiveOffset tests protection against resource exhaustion
func TestGetAllExceptions_ExcessiveOffset(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	filters := &core.ExceptionFilters{
		Page:  100001, // Would cause offset > 100000
		Limit: 100,
	}

	exceptions, total, err := storage.GetAllExceptions(filters)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pagination offset too large")
	assert.Nil(t, exceptions)
	assert.Equal(t, int64(0), total)
}

// TestGetExceptionsByRuleID tests getting exceptions for a specific rule
func TestGetExceptionsByRuleID(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	// Create exceptions for rule-001
	for i := 0; i < 3; i++ {
		exception := &core.Exception{
			Name:          "Exception",
			RuleID:        "rule-001",
			Type:          core.ExceptionSuppress,
			ConditionType: core.ConditionTypeCQL,
			Condition:     "test",
			Priority:      i,
		}
		err := storage.CreateException(exception)
		require.NoError(t, err)
	}

	exceptions, err := storage.GetExceptionsByRuleID("rule-001")
	require.NoError(t, err)
	assert.Len(t, exceptions, 3)
	// Should be sorted by priority
	assert.Equal(t, 0, exceptions[0].Priority)
	assert.Equal(t, 2, exceptions[2].Priority)
}

// TestGetGlobalExceptions tests getting global exceptions
func TestGetGlobalExceptions(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	// Create global exception (empty rule_id)
	globalException := &core.Exception{
		Name:          "Global Exception",
		RuleID:        "",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
	}
	err := storage.CreateException(globalException)
	require.NoError(t, err)

	// Create rule-specific exception
	ruleException := &core.Exception{
		Name:          "Rule Exception",
		RuleID:        "rule-001",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
	}
	err = storage.CreateException(ruleException)
	require.NoError(t, err)

	globals, err := storage.GetGlobalExceptions()
	require.NoError(t, err)
	assert.Len(t, globals, 1)
	assert.Equal(t, "Global Exception", globals[0].Name)
}

// TestGetActiveExceptions tests getting active exceptions
func TestGetActiveExceptions(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)

	// Active enabled exception
	activeException := &core.Exception{
		Name:          "Active",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
		Enabled:       true,
		ExpiresAt:     &future,
	}
	err := storage.CreateException(activeException)
	require.NoError(t, err)

	// Disabled exception
	disabledException := &core.Exception{
		Name:          "Disabled",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
		Enabled:       false,
	}
	err = storage.CreateException(disabledException)
	require.NoError(t, err)

	// Expired exception
	expiredException := &core.Exception{
		Name:          "Expired",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
		Enabled:       true,
		ExpiresAt:     &past,
	}
	err = storage.CreateException(expiredException)
	require.NoError(t, err)

	actives, err := storage.GetActiveExceptions()
	require.NoError(t, err)
	assert.Len(t, actives, 1)
	assert.Equal(t, "Active", actives[0].Name)
}

// TestUpdateException_Success tests updating exception
func TestUpdateException_Success(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	exception := &core.Exception{
		ID:            "update-001",
		Name:          "Original Name",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
		Priority:      5,
	}
	err := storage.CreateException(exception)
	require.NoError(t, err)

	// Update exception
	exception.Name = "Updated Name"
	exception.Priority = 10
	err = storage.UpdateException("update-001", exception)
	require.NoError(t, err)

	// Verify update
	updated, err := storage.GetException("update-001")
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.Name)
	assert.Equal(t, 10, updated.Priority)
}

// TestUpdateException_NotFound tests updating non-existent exception
func TestUpdateException_NotFound(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	exception := &core.Exception{
		Name:          "Test",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
	}

	err := storage.UpdateException("nonexistent", exception)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestDeleteException_Success tests deleting exception
func TestDeleteException_Success(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	exception := &core.Exception{
		ID:            "delete-001",
		Name:          "To Delete",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
	}
	err := storage.CreateException(exception)
	require.NoError(t, err)

	err = storage.DeleteException("delete-001")
	require.NoError(t, err)

	// Verify deleted
	_, err = storage.GetException("delete-001")
	assert.Error(t, err)
}

// TestDeleteException_NotFound tests deleting non-existent exception
func TestDeleteException_NotFound(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	err := storage.DeleteException("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestIncrementHitCount tests incrementing hit count
func TestIncrementHitCount(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	exception := &core.Exception{
		ID:            "hit-001",
		Name:          "Hit Counter",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
	}
	err := storage.CreateException(exception)
	require.NoError(t, err)

	// Increment multiple times
	for i := 0; i < 5; i++ {
		err = storage.IncrementHitCount("hit-001")
		require.NoError(t, err)
	}

	// Verify count
	retrieved, err := storage.GetException("hit-001")
	require.NoError(t, err)
	assert.Equal(t, int64(5), retrieved.HitCount)
}

// TestUpdateLastHit tests updating last hit timestamp
func TestUpdateLastHit(t *testing.T) {
	sqlite, storage := setupExceptionTestDB(t)
	defer sqlite.Close()

	exception := &core.Exception{
		ID:            "lasthit-001",
		Name:          "Last Hit Test",
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeCQL,
		Condition:     "test",
	}
	err := storage.CreateException(exception)
	require.NoError(t, err)

	timestamp := time.Now()
	err = storage.UpdateLastHit("lasthit-001", timestamp)
	require.NoError(t, err)

	retrieved, err := storage.GetException("lasthit-001")
	require.NoError(t, err)
	assert.NotNil(t, retrieved.LastHit)
	assert.True(t, retrieved.LastHit.Sub(timestamp) < time.Second)
}
