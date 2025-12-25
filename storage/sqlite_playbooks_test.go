package storage

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cerberus/soar"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Helper to create test playbook
func createTestPlaybook(id, name string) *soar.Playbook {
	return &soar.Playbook{
		ID:          id,
		Name:        name,
		Description: "Test playbook description",
		Enabled:     true,
		Priority:    10,
		Triggers: []soar.PlaybookTrigger{
			{
				Type: "alert",
				Conditions: []soar.PlaybookCondition{
					{Field: "severity", Operator: "eq", Value: "critical"},
				},
			},
		},
		Steps: []soar.PlaybookStep{
			{
				ID:         "step-1",
				Name:       "Send notification",
				ActionType: soar.ActionTypeNotify,
				Parameters: map[string]interface{}{"channel": "#security"},
				Timeout:    30 * time.Second,
			},
		},
		Tags:      []string{"incident-response", "critical"},
		CreatedBy: "admin",
	}
}

// TestNewSQLitePlaybookStorage_Success tests successful storage creation
func TestNewSQLitePlaybookStorage_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	storage, err := NewSQLitePlaybookStorage(sqlite, logger)

	require.NoError(t, err)
	require.NotNil(t, storage)
	assert.Equal(t, sqlite, storage.db)
	assert.NotNil(t, storage.logger)
}

// TestCreatePlaybook_Success tests successful playbook creation
func TestCreatePlaybook_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbook := createTestPlaybook("pb-001", "Critical Alert Response")

	err = storage.CreatePlaybook(playbook)
	require.NoError(t, err)

	// Verify playbook was created
	var count int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM playbooks WHERE id = ?", "pb-001").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify timestamps were set
	assert.False(t, playbook.CreatedAt.IsZero())
	assert.False(t, playbook.UpdatedAt.IsZero())
}

// TestCreatePlaybook_DuplicateName tests name uniqueness constraint
func TestCreatePlaybook_DuplicateName(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create first playbook
	playbook1 := createTestPlaybook("pb-001", "Duplicate Name")
	err = storage.CreatePlaybook(playbook1)
	require.NoError(t, err)

	// Create second playbook with same name but different ID
	playbook2 := createTestPlaybook("pb-002", "Duplicate Name")
	err = storage.CreatePlaybook(playbook2)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPlaybookNameExists)
}

// TestGetPlaybook_Success tests successful playbook retrieval
func TestGetPlaybook_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	original := createTestPlaybook("pb-get-test", "Get Test Playbook")
	err = storage.CreatePlaybook(original)
	require.NoError(t, err)

	// Retrieve the playbook
	retrieved, err := storage.GetPlaybook("pb-get-test")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	// Verify all fields
	assert.Equal(t, original.ID, retrieved.ID)
	assert.Equal(t, original.Name, retrieved.Name)
	assert.Equal(t, original.Description, retrieved.Description)
	assert.Equal(t, original.Enabled, retrieved.Enabled)
	assert.Equal(t, original.Priority, retrieved.Priority)
	assert.Equal(t, original.CreatedBy, retrieved.CreatedBy)
	assert.Len(t, retrieved.Triggers, 1)
	assert.Len(t, retrieved.Steps, 1)
	assert.Len(t, retrieved.Tags, 2)
}

// TestGetPlaybook_NotFound tests retrieving non-existent playbook
func TestGetPlaybook_NotFound(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbook, err := storage.GetPlaybook("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPlaybookNotFound)
	assert.Nil(t, playbook)
}

// TestGetPlaybooks_Pagination tests pagination
func TestGetPlaybooks_Pagination(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create 10 playbooks
	for i := 1; i <= 10; i++ {
		playbook := createTestPlaybook(fmt.Sprintf("pb-%02d", i), fmt.Sprintf("Playbook %d", i))
		playbook.Priority = i // Different priorities for ordering
		err := storage.CreatePlaybook(playbook)
		require.NoError(t, err)
	}

	// Get first page
	page1, err := storage.GetPlaybooks(5, 0)
	require.NoError(t, err)
	assert.Len(t, page1, 5)

	// Get second page
	page2, err := storage.GetPlaybooks(5, 5)
	require.NoError(t, err)
	assert.Len(t, page2, 5)

	// Verify no duplicates between pages
	page1IDs := make(map[string]bool)
	for _, p := range page1 {
		page1IDs[p.ID] = true
	}
	for _, p := range page2 {
		assert.False(t, page1IDs[p.ID], "Duplicate playbook ID across pages")
	}
}

// TestGetAllPlaybooks tests retrieving all playbooks
func TestGetAllPlaybooks(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create multiple playbooks
	for i := 1; i <= 5; i++ {
		playbook := createTestPlaybook(fmt.Sprintf("pb-%d", i), fmt.Sprintf("Playbook %d", i))
		err := storage.CreatePlaybook(playbook)
		require.NoError(t, err)
	}

	playbooks, err := storage.GetAllPlaybooks()
	require.NoError(t, err)
	assert.Len(t, playbooks, 5)
}

// TestGetPlaybookCount tests playbook counting
func TestGetPlaybookCount(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Initially empty
	count, err := storage.GetPlaybookCount()
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// Add playbooks
	for i := 1; i <= 3; i++ {
		playbook := createTestPlaybook(fmt.Sprintf("pb-%d", i), fmt.Sprintf("Playbook %d", i))
		err := storage.CreatePlaybook(playbook)
		require.NoError(t, err)
	}

	count, err = storage.GetPlaybookCount()
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

// TestUpdatePlaybook_Success tests successful playbook update
func TestUpdatePlaybook_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create original
	original := createTestPlaybook("pb-update", "Original Name")
	err = storage.CreatePlaybook(original)
	require.NoError(t, err)
	originalCreatedAt := original.CreatedAt

	time.Sleep(10 * time.Millisecond)

	// Update
	updated := createTestPlaybook("pb-update", "Updated Name")
	updated.Description = "Updated description"
	updated.Priority = 99
	err = storage.UpdatePlaybook("pb-update", updated)
	require.NoError(t, err)

	// Retrieve and verify
	retrieved, err := storage.GetPlaybook("pb-update")
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", retrieved.Name)
	assert.Equal(t, "Updated description", retrieved.Description)
	assert.Equal(t, 99, retrieved.Priority)
	// CreatedAt should be preserved
	assert.Equal(t, originalCreatedAt.Unix(), retrieved.CreatedAt.Unix())
	// UpdatedAt should be >= CreatedAt (may be same second in fast test)
	assert.True(t, !retrieved.UpdatedAt.Before(retrieved.CreatedAt))
}

// TestUpdatePlaybook_NotFound tests updating non-existent playbook
func TestUpdatePlaybook_NotFound(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbook := createTestPlaybook("non-existent", "Test")
	err = storage.UpdatePlaybook("non-existent", playbook)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPlaybookNotFound)
}

// TestUpdatePlaybook_DuplicateName tests name conflict on update
func TestUpdatePlaybook_DuplicateName(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create two playbooks
	pb1 := createTestPlaybook("pb-1", "First Playbook")
	err = storage.CreatePlaybook(pb1)
	require.NoError(t, err)

	pb2 := createTestPlaybook("pb-2", "Second Playbook")
	err = storage.CreatePlaybook(pb2)
	require.NoError(t, err)

	// Try to rename pb2 to pb1's name
	pb2.Name = "First Playbook"
	err = storage.UpdatePlaybook("pb-2", pb2)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPlaybookNameExists)
}

// TestDeletePlaybook_Success tests successful deletion
func TestDeletePlaybook_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbook := createTestPlaybook("pb-delete", "Delete Test")
	err = storage.CreatePlaybook(playbook)
	require.NoError(t, err)

	err = storage.DeletePlaybook("pb-delete")
	require.NoError(t, err)

	// Verify deletion
	_, err = storage.GetPlaybook("pb-delete")
	assert.ErrorIs(t, err, ErrPlaybookNotFound)
}

// TestDeletePlaybook_NotFound tests deleting non-existent playbook
func TestDeletePlaybook_NotFound(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	err = storage.DeletePlaybook("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPlaybookNotFound)
}

// TestEnablePlaybook tests enabling a playbook
func TestEnablePlaybook(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbook := createTestPlaybook("pb-enable", "Enable Test")
	playbook.Enabled = false
	err = storage.CreatePlaybook(playbook)
	require.NoError(t, err)

	err = storage.EnablePlaybook("pb-enable")
	require.NoError(t, err)

	retrieved, err := storage.GetPlaybook("pb-enable")
	require.NoError(t, err)
	assert.True(t, retrieved.Enabled)
}

// TestDisablePlaybook tests disabling a playbook
func TestDisablePlaybook(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbook := createTestPlaybook("pb-disable", "Disable Test")
	playbook.Enabled = true
	err = storage.CreatePlaybook(playbook)
	require.NoError(t, err)

	err = storage.DisablePlaybook("pb-disable")
	require.NoError(t, err)

	retrieved, err := storage.GetPlaybook("pb-disable")
	require.NoError(t, err)
	assert.False(t, retrieved.Enabled)
}

// TestEnablePlaybook_NotFound tests enabling non-existent playbook
func TestEnablePlaybook_NotFound(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	err = storage.EnablePlaybook("non-existent")
	assert.ErrorIs(t, err, ErrPlaybookNotFound)
}

// TestGetPlaybooksByStatus tests filtering by enabled status
func TestGetPlaybooksByStatus(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create enabled and disabled playbooks
	for i := 1; i <= 3; i++ {
		pb := createTestPlaybook(fmt.Sprintf("pb-enabled-%d", i), fmt.Sprintf("Enabled %d", i))
		pb.Enabled = true
		err := storage.CreatePlaybook(pb)
		require.NoError(t, err)
	}
	for i := 1; i <= 2; i++ {
		pb := createTestPlaybook(fmt.Sprintf("pb-disabled-%d", i), fmt.Sprintf("Disabled %d", i))
		pb.Enabled = false
		err := storage.CreatePlaybook(pb)
		require.NoError(t, err)
	}

	enabled, err := storage.GetPlaybooksByStatus(true)
	require.NoError(t, err)
	assert.Len(t, enabled, 3)

	disabled, err := storage.GetPlaybooksByStatus(false)
	require.NoError(t, err)
	assert.Len(t, disabled, 2)
}

// TestGetPlaybooksByTag tests filtering by tag
func TestGetPlaybooksByTag(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create playbooks with different tags
	pb1 := createTestPlaybook("pb-1", "Playbook 1")
	pb1.Tags = []string{"incident-response", "critical"}
	err = storage.CreatePlaybook(pb1)
	require.NoError(t, err)

	pb2 := createTestPlaybook("pb-2", "Playbook 2")
	pb2.Tags = []string{"incident-response", "low"}
	err = storage.CreatePlaybook(pb2)
	require.NoError(t, err)

	pb3 := createTestPlaybook("pb-3", "Playbook 3")
	pb3.Tags = []string{"automation"}
	err = storage.CreatePlaybook(pb3)
	require.NoError(t, err)

	// Search by tag
	results, err := storage.GetPlaybooksByTag("incident-response")
	require.NoError(t, err)
	assert.Len(t, results, 2)

	results, err = storage.GetPlaybooksByTag("critical")
	require.NoError(t, err)
	assert.Len(t, results, 1)

	results, err = storage.GetPlaybooksByTag("non-existent")
	require.NoError(t, err)
	assert.Len(t, results, 0)
}

// TestSearchPlaybooks tests search functionality
func TestSearchPlaybooks(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create playbooks
	pb1 := createTestPlaybook("pb-1", "Critical Alert Response")
	pb1.Description = "Handles critical security alerts"
	err = storage.CreatePlaybook(pb1)
	require.NoError(t, err)

	pb2 := createTestPlaybook("pb-2", "Low Priority Handler")
	pb2.Description = "Handles low priority events"
	err = storage.CreatePlaybook(pb2)
	require.NoError(t, err)

	pb3 := createTestPlaybook("pb-3", "Incident Escalation")
	pb3.Description = "Escalates critical incidents"
	err = storage.CreatePlaybook(pb3)
	require.NoError(t, err)

	// Search by name (case-insensitive - SQLite LIKE behavior)
	results, err := storage.SearchPlaybooks("Critical")
	require.NoError(t, err)
	assert.Len(t, results, 2) // pb-1 name and pb-3 description both match "critical"

	// Search with unique term
	results, err = storage.SearchPlaybooks("Low Priority")
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "pb-2", results[0].ID)

	// No results
	results, err = storage.SearchPlaybooks("nonexistent")
	require.NoError(t, err)
	assert.Len(t, results, 0)
}

// TestSearchPlaybooks_SpecialCharacters tests LIKE escaping
func TestSearchPlaybooks_SpecialCharacters(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create playbook with special characters
	pb := createTestPlaybook("pb-special", "Test_Playbook%Special")
	err = storage.CreatePlaybook(pb)
	require.NoError(t, err)

	// Search with special characters - should be escaped
	results, err := storage.SearchPlaybooks("_Playbook%")
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

// TestPlaybookNameExists tests name existence check
func TestPlaybookNameExists(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbook := createTestPlaybook("pb-exists", "Existing Playbook")
	err = storage.CreatePlaybook(playbook)
	require.NoError(t, err)

	// Name exists
	exists, err := storage.PlaybookNameExists("Existing Playbook", "")
	require.NoError(t, err)
	assert.True(t, exists)

	// Name exists but excluding self
	exists, err = storage.PlaybookNameExists("Existing Playbook", "pb-exists")
	require.NoError(t, err)
	assert.False(t, exists)

	// Name doesn't exist
	exists, err = storage.PlaybookNameExists("Non-existent Playbook", "")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestGetPlaybookStats tests statistics retrieval
func TestGetPlaybookStats(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Empty stats
	stats, err := storage.GetPlaybookStats()
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.TotalPlaybooks)
	assert.Equal(t, int64(0), stats.EnabledPlaybooks)
	assert.Equal(t, int64(0), stats.DisabledPlaybooks)

	// Create enabled playbooks
	for i := 1; i <= 3; i++ {
		pb := createTestPlaybook(fmt.Sprintf("pb-enabled-%d", i), fmt.Sprintf("Enabled %d", i))
		pb.Enabled = true
		err := storage.CreatePlaybook(pb)
		require.NoError(t, err)
	}

	// Create disabled playbooks
	for i := 1; i <= 2; i++ {
		pb := createTestPlaybook(fmt.Sprintf("pb-disabled-%d", i), fmt.Sprintf("Disabled %d", i))
		pb.Enabled = false
		err := storage.CreatePlaybook(pb)
		require.NoError(t, err)
	}

	stats, err = storage.GetPlaybookStats()
	require.NoError(t, err)
	assert.Equal(t, int64(5), stats.TotalPlaybooks)
	assert.Equal(t, int64(3), stats.EnabledPlaybooks)
	assert.Equal(t, int64(2), stats.DisabledPlaybooks)
}

// TestEnsureIndexes tests index creation
func TestEnsureIndexes_Playbooks(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	err = storage.EnsureIndexes()
	assert.NoError(t, err)
}

// TestPlaybookCRUD_Sequence tests complete CRUD sequence
func TestPlaybookCRUD_Sequence(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// 1. Create
	playbook := createTestPlaybook("pb-crud", "CRUD Test Playbook")
	err = storage.CreatePlaybook(playbook)
	require.NoError(t, err)

	// 2. Read
	retrieved, err := storage.GetPlaybook("pb-crud")
	require.NoError(t, err)
	assert.Equal(t, "CRUD Test Playbook", retrieved.Name)

	// 3. Update
	time.Sleep(10 * time.Millisecond)
	updated := createTestPlaybook("pb-crud", "Updated CRUD Playbook")
	err = storage.UpdatePlaybook("pb-crud", updated)
	require.NoError(t, err)

	retrieved, err = storage.GetPlaybook("pb-crud")
	require.NoError(t, err)
	assert.Equal(t, "Updated CRUD Playbook", retrieved.Name)

	// 4. Delete
	err = storage.DeletePlaybook("pb-crud")
	require.NoError(t, err)

	_, err = storage.GetPlaybook("pb-crud")
	assert.ErrorIs(t, err, ErrPlaybookNotFound)
}

// TestGetPlaybooks_Empty tests empty results serialization
func TestGetPlaybooks_Empty(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbooks, err := storage.GetPlaybooks(10, 0)
	require.NoError(t, err)
	assert.Len(t, playbooks, 0)
	assert.NotNil(t, playbooks) // Must not be nil for JSON serialization
}

// TestGetPlaybooks_JSONSerializationContract verifies empty results serialize to []
func TestGetPlaybooks_JSONSerializationContract(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbooks, err := storage.GetAllPlaybooks()
	require.NoError(t, err)

	// Critical: Verify JSON serialization produces [], not null
	jsonBytes, err := json.Marshal(playbooks)
	require.NoError(t, err)

	if string(jsonBytes) != "[]" {
		t.Errorf("Expected JSON '[]', got '%s' - nil slices break frontend contract", string(jsonBytes))
	}
}

// TestPlaybook_ComplexSteps tests playbooks with multiple complex steps
func TestPlaybook_ComplexSteps(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbook := &soar.Playbook{
		ID:          "pb-complex",
		Name:        "Complex Multi-Step Playbook",
		Description: "Tests complex step serialization",
		Enabled:     true,
		Priority:    100,
		Triggers: []soar.PlaybookTrigger{
			{
				Type: "alert",
				Conditions: []soar.PlaybookCondition{
					{Field: "severity", Operator: "eq", Value: "critical"},
					{Field: "source", Operator: "contains", Value: "firewall"},
				},
			},
			{
				Type: "rule_id",
				Conditions: []soar.PlaybookCondition{
					{Field: "rule_id", Operator: "eq", Value: "RULE-001"},
				},
			},
		},
		Steps: []soar.PlaybookStep{
			{
				ID:         "step-1",
				Name:       "Block IP",
				ActionType: soar.ActionTypeBlock,
				Parameters: map[string]interface{}{
					"ip":       "{{.SourceIP}}",
					"duration": 3600,
				},
				Timeout:         60 * time.Second,
				ContinueOnError: true,
			},
			{
				ID:         "step-2",
				Name:       "Create Ticket",
				ActionType: soar.ActionTypeCreateTicket,
				Parameters: map[string]interface{}{
					"project":  "SEC",
					"priority": "high",
					"title":    "Critical Alert: {{.RuleName}}",
				},
				Timeout: 30 * time.Second,
				Conditions: []soar.PlaybookCondition{
					{Field: "step-1.status", Operator: "eq", Value: "completed"},
				},
			},
			{
				ID:         "step-3",
				Name:       "Notify Team",
				ActionType: soar.ActionTypeNotify,
				Parameters: map[string]interface{}{
					"channel": "#security-alerts",
					"message": "Blocked IP {{.SourceIP}} due to {{.RuleName}}",
				},
				Timeout: 10 * time.Second,
			},
		},
		Tags:      []string{"blocking", "ticketing", "notification"},
		CreatedBy: "admin",
	}

	err = storage.CreatePlaybook(playbook)
	require.NoError(t, err)

	retrieved, err := storage.GetPlaybook("pb-complex")
	require.NoError(t, err)

	assert.Len(t, retrieved.Triggers, 2)
	assert.Len(t, retrieved.Steps, 3)
	assert.Len(t, retrieved.Tags, 3)

	// Verify step details preserved
	assert.Equal(t, "Block IP", retrieved.Steps[0].Name)
	assert.Equal(t, soar.ActionTypeBlock, retrieved.Steps[0].ActionType)
	assert.True(t, retrieved.Steps[0].ContinueOnError)
	assert.Equal(t, 60*time.Second, retrieved.Steps[0].Timeout)
}

// TestPlaybook_PriorityOrdering tests ordering by priority
func TestPlaybook_PriorityOrdering(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create playbooks with different priorities
	priorities := []int{5, 10, 1, 20, 15}
	for i, p := range priorities {
		pb := createTestPlaybook(fmt.Sprintf("pb-%d", i), fmt.Sprintf("Priority %d", p))
		pb.Priority = p
		err := storage.CreatePlaybook(pb)
		require.NoError(t, err)
	}

	playbooks, err := storage.GetAllPlaybooks()
	require.NoError(t, err)
	assert.Len(t, playbooks, 5)

	// Verify ordering is by priority DESC
	assert.Equal(t, 20, playbooks[0].Priority)
	assert.Equal(t, 15, playbooks[1].Priority)
	assert.Equal(t, 10, playbooks[2].Priority)
}

// TestGetPlaybook_CorruptedTimestamp tests handling of corrupted timestamps
func TestGetPlaybook_CorruptedTimestamp(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Insert playbook with invalid timestamp directly
	_, err = sqlite.DB.Exec(`
		INSERT INTO playbooks (id, name, description, enabled, priority, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, "pb-corrupt", "Corrupt Playbook", "Test", true, 10, "invalid-timestamp", "2024-01-01T00:00:00Z")
	require.NoError(t, err)

	// GetPlaybook should fail with corrupted timestamp error
	_, err = storage.GetPlaybook("pb-corrupt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "corrupted created_at timestamp")
}

// TestGetAllPlaybooks_CorruptedJSON tests handling of corrupted JSON fields
func TestGetAllPlaybooks_CorruptedJSON(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	now := time.Now().Format(time.RFC3339)

	// Insert playbook with invalid JSON in triggers
	_, err = sqlite.DB.Exec(`
		INSERT INTO playbooks (id, name, description, enabled, priority, triggers, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "pb-badjson", "Bad JSON Playbook", "Test", true, 10, "{invalid-json}", now, now)
	require.NoError(t, err)

	// GetAllPlaybooks should fail with corrupted triggers error
	_, err = storage.GetAllPlaybooks()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "corrupted triggers field")
}

func TestUpdatePlaybook_CorruptedCreatedAt(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	now := time.Now().Format(time.RFC3339)

	// Insert playbook with invalid created_at timestamp
	_, err = sqlite.DB.Exec(`
		INSERT INTO playbooks (id, name, description, enabled, priority, triggers, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "pb-badtime", "Bad Timestamp Playbook", "Test", true, 10, "[]", "not-a-valid-timestamp", now)
	require.NoError(t, err)

	// UpdatePlaybook should fail with corrupted timestamp error
	updatePlaybook := createTestPlaybook("pb-badtime", "Updated Name")
	err = storage.UpdatePlaybook("pb-badtime", updatePlaybook)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "corrupted created_at timestamp")
}

// TestEnableDisablePlaybook_Concurrent tests concurrent enable/disable operations
func TestEnableDisablePlaybook_Concurrent(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create a playbook
	playbook := createTestPlaybook("pb-concurrent", "Concurrent Test")
	err = storage.CreatePlaybook(playbook)
	require.NoError(t, err)

	// Run 10 concurrent enable/disable operations
	const numGoroutines = 10
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			var opErr error
			if idx%2 == 0 {
				opErr = storage.EnablePlaybook("pb-concurrent")
			} else {
				opErr = storage.DisablePlaybook("pb-concurrent")
			}
			done <- opErr
		}(i)
	}

	// Collect results - all operations should succeed
	for i := 0; i < numGoroutines; i++ {
		opErr := <-done
		assert.NoError(t, opErr)
	}

	// Verify playbook is still accessible and has valid state
	retrieved, err := storage.GetPlaybook("pb-concurrent")
	require.NoError(t, err)
	// Final state is either enabled or disabled (deterministic based on last operation)
	assert.NotNil(t, retrieved)
}

// TestGetPlaybooksByTag_EscapeSequence tests LIKE injection protection
func TestGetPlaybooksByTag_EscapeSequence(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	// Create playbook with SQL LIKE special characters in tag
	pb := createTestPlaybook("pb-escape", "Escape Test")
	pb.Tags = []string{"test%tag", "test_tag", "normal"}
	err = storage.CreatePlaybook(pb)
	require.NoError(t, err)

	// Create another playbook that could match if wildcards aren't escaped
	pb2 := createTestPlaybook("pb-other", "Other Test")
	pb2.Tags = []string{"testXtag", "testYtag"}
	err = storage.CreatePlaybook(pb2)
	require.NoError(t, err)

	// Search for literal % should only match first playbook (not wildcard match)
	results, err := storage.GetPlaybooksByTag("test%tag")
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "pb-escape", results[0].ID)

	// Search for literal _ should only match first playbook (not single-char wildcard)
	results, err = storage.GetPlaybooksByTag("test_tag")
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "pb-escape", results[0].ID)
}

// Benchmark tests

// ============================================================================
// Empty ID Validation Tests
// ============================================================================

func TestCreatePlaybook_EmptyID(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbook := createTestPlaybook("", "Test Playbook")
	err = storage.CreatePlaybook(playbook)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "playbook ID cannot be empty")
}

func TestGetPlaybook_EmptyID(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	_, err = storage.GetPlaybook("")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "playbook ID cannot be empty")
}

func TestUpdatePlaybook_EmptyID(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	playbook := createTestPlaybook("valid-id", "Test Playbook")
	err = storage.UpdatePlaybook("", playbook)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "playbook ID cannot be empty")
}

func TestDeletePlaybook_EmptyID(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	err = storage.DeletePlaybook("")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "playbook ID cannot be empty")
}

func TestEnablePlaybook_EmptyID(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	err = storage.EnablePlaybook("")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "playbook ID cannot be empty")
}

func TestDisablePlaybook_EmptyID(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage, err := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())
	require.NoError(t, err)

	err = storage.DisablePlaybook("")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "playbook ID cannot be empty")
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkCreatePlaybook(b *testing.B) {
	_, sqlite := setupTestDB(&testing.T{})
	defer sqlite.Close()

	storage, _ := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		playbook := createTestPlaybook(fmt.Sprintf("pb-bench-%d", i), fmt.Sprintf("Bench Playbook %d", i))
		_ = storage.CreatePlaybook(playbook)
	}
}

func BenchmarkGetPlaybook(b *testing.B) {
	_, sqlite := setupTestDB(&testing.T{})
	defer sqlite.Close()

	storage, _ := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())

	// Setup
	playbook := createTestPlaybook("pb-bench-get", "Bench Get Playbook")
	_ = storage.CreatePlaybook(playbook)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = storage.GetPlaybook("pb-bench-get")
	}
}

func BenchmarkSearchPlaybooks(b *testing.B) {
	_, sqlite := setupTestDB(&testing.T{})
	defer sqlite.Close()

	storage, _ := NewSQLitePlaybookStorage(sqlite, zap.NewNop().Sugar())

	// Setup: create 100 playbooks
	for i := 0; i < 100; i++ {
		playbook := createTestPlaybook(fmt.Sprintf("pb-%d", i), fmt.Sprintf("Playbook %d description", i))
		_ = storage.CreatePlaybook(playbook)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = storage.SearchPlaybooks("description")
	}
}
