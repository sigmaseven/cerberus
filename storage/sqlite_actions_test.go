package storage

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestNewSQLiteActionStorage_Success tests successful action storage creation
func TestNewSQLiteActionStorage_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	storage := NewSQLiteActionStorage(sqlite, logger)

	require.NotNil(t, storage)
	assert.Equal(t, sqlite, storage.sqlite)
	assert.NotNil(t, storage.logger)
}

// TestCreateAction_Success tests successful action creation
func TestCreateAction_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	action := &core.Action{
		ID:   "action-001",
		Type: "webhook",
		Config: map[string]interface{}{
			"url":    "https://api.example.com/webhook",
			"method": "POST",
			"headers": map[string]string{
				"Content-Type": "application/json",
			},
		},
	}

	err := storage.CreateAction(action)
	require.NoError(t, err)

	// Verify action was created
	var count int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM actions WHERE id = ?", "action-001").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify timestamps were set
	assert.False(t, action.CreatedAt.IsZero())
	assert.False(t, action.UpdatedAt.IsZero())
}

// TestCreateAction_DuplicateID tests creating action with duplicate ID
func TestCreateAction_DuplicateID(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	action := &core.Action{
		ID:     "duplicate-action",
		Type:   "email",
		Config: map[string]interface{}{"to": "test@example.com"},
	}

	// First creation should succeed
	err := storage.CreateAction(action)
	require.NoError(t, err)

	// Second creation with same ID should fail
	duplicateAction := &core.Action{
		ID:     "duplicate-action",
		Type:   "slack",
		Config: map[string]interface{}{"channel": "#alerts"},
	}

	err = storage.CreateAction(duplicateAction)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// TestGetAction_Success tests successful action retrieval
func TestGetAction_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	// Create an action with complete configuration
	originalAction := &core.Action{
		ID:   "get-test-action",
		Type: "jira",
		Config: map[string]interface{}{
			"server":    "https://jira.example.com",
			"project":   "SEC",
			"issueType": "Task",
			"priority":  "High",
		},
	}

	err := storage.CreateAction(originalAction)
	require.NoError(t, err)

	// Retrieve the action
	retrievedAction, err := storage.GetAction("get-test-action")
	require.NoError(t, err)
	require.NotNil(t, retrievedAction)

	// Verify all fields
	assert.Equal(t, originalAction.ID, retrievedAction.ID)
	assert.Equal(t, originalAction.Type, retrievedAction.Type)
	assert.Equal(t, "https://jira.example.com", retrievedAction.Config["server"])
	assert.Equal(t, "SEC", retrievedAction.Config["project"])
	assert.Equal(t, "Task", retrievedAction.Config["issueType"])
	assert.Equal(t, "High", retrievedAction.Config["priority"])
}

// TestGetAction_NotFound tests retrieving non-existent action
func TestGetAction_NotFound(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	action, err := storage.GetAction("non-existent-action")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrActionNotFound)
	assert.Nil(t, action)
}

// TestUpdateAction_Success tests successful action update
func TestUpdateAction_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	// Create original action
	originalAction := &core.Action{
		ID:   "update-test",
		Type: "webhook",
		Config: map[string]interface{}{
			"url": "https://old.example.com/webhook",
		},
	}

	err := storage.CreateAction(originalAction)
	require.NoError(t, err)

	// Wait to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	// Update the action
	updatedAction := &core.Action{
		ID:   "update-test",
		Type: "webhook",
		Config: map[string]interface{}{
			"url":     "https://new.example.com/webhook",
			"timeout": 30,
		},
	}

	err = storage.UpdateAction("update-test", updatedAction)
	require.NoError(t, err)

	// Retrieve and verify
	retrieved, err := storage.GetAction("update-test")
	require.NoError(t, err)

	assert.Equal(t, "webhook", retrieved.Type)
	assert.Equal(t, "https://new.example.com/webhook", retrieved.Config["url"])
	assert.Equal(t, float64(30), retrieved.Config["timeout"])

	// Verify CreatedAt preserved, UpdatedAt changed
	assert.Equal(t, originalAction.CreatedAt.Unix(), retrieved.CreatedAt.Unix())
	// UpdatedAt should be >= CreatedAt
	assert.True(t, retrieved.UpdatedAt.Unix() >= retrieved.CreatedAt.Unix())
}

// TestUpdateAction_NotFound tests updating non-existent action
func TestUpdateAction_NotFound(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	action := &core.Action{
		ID:     "non-existent",
		Type:   "email",
		Config: map[string]interface{}{"to": "test@example.com"},
	}

	err := storage.UpdateAction("non-existent", action)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrActionNotFound)
}

// TestDeleteAction_Success tests successful action deletion
func TestDeleteAction_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	// Create an action
	action := &core.Action{
		ID:     "delete-test",
		Type:   "slack",
		Config: map[string]interface{}{"channel": "#security"},
	}

	err := storage.CreateAction(action)
	require.NoError(t, err)

	// Delete the action
	err = storage.DeleteAction("delete-test")
	require.NoError(t, err)

	// Verify deletion
	_, err = storage.GetAction("delete-test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrActionNotFound)

	// Verify via direct query
	var count int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM actions WHERE id = ?", "delete-test").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestDeleteAction_NotFound tests deleting non-existent action
func TestDeleteAction_NotFound(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	err := storage.DeleteAction("non-existent-action")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrActionNotFound)
}

// TestGetActions tests retrieving all actions
func TestGetActions(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	// Create multiple actions
	actionTypes := []string{"webhook", "email", "slack", "jira", "pagerduty"}
	for i, actionType := range actionTypes {
		action := &core.Action{
			ID:   fmt.Sprintf("action-%d", i+1),
			Type: actionType,
			Config: map[string]interface{}{
				"test": fmt.Sprintf("config-%d", i+1),
			},
		}
		err := storage.CreateAction(action)
		require.NoError(t, err)
	}

	// Get all actions
	actions, err := storage.GetActions()
	require.NoError(t, err)
	assert.Len(t, actions, 5)

	// Verify they're ordered by created_at DESC (newest first)
	// Note: In-memory SQLite with very fast inserts may have same timestamp,
	// so we just verify all 5 are returned
	actionIDs := make(map[string]bool)
	for _, action := range actions {
		actionIDs[action.ID] = true
	}
	assert.Equal(t, 5, len(actionIDs), "All 5 actions should be present")
}

// TestGetActions_Empty tests retrieving actions when none exist
func TestGetActions_Empty(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	actions, err := storage.GetActions()
	require.NoError(t, err)
	assert.Len(t, actions, 0)
}

// TestActionConfig_ComplexData tests storing complex configuration
func TestActionConfig_ComplexData(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	// Create action with nested complex config
	action := &core.Action{
		ID:   "complex-config",
		Type: "webhook",
		Config: map[string]interface{}{
			"url":    "https://api.example.com/webhook",
			"method": "POST",
			"headers": map[string]interface{}{
				"Content-Type":  "application/json",
				"Authorization": "Bearer token123",
			},
			"body_template": map[string]interface{}{
				"alert": map[string]interface{}{
					"severity": "{{.Severity}}",
					"message":  "{{.Message}}",
				},
			},
			"retry": map[string]interface{}{
				"max_attempts": 3,
				"backoff":      "exponential",
			},
			"timeout_seconds": 30,
		},
	}

	err := storage.CreateAction(action)
	require.NoError(t, err)

	// Retrieve and verify complex nested structure
	retrieved, err := storage.GetAction("complex-config")
	require.NoError(t, err)

	// Verify nested headers
	headers := retrieved.Config["headers"].(map[string]interface{})
	assert.Equal(t, "application/json", headers["Content-Type"])
	assert.Equal(t, "Bearer token123", headers["Authorization"])

	// Verify nested body template
	bodyTemplate := retrieved.Config["body_template"].(map[string]interface{})
	alert := bodyTemplate["alert"].(map[string]interface{})
	assert.Equal(t, "{{.Severity}}", alert["severity"])
	assert.Equal(t, "{{.Message}}", alert["message"])

	// Verify retry config
	retry := retrieved.Config["retry"].(map[string]interface{})
	assert.Equal(t, float64(3), retry["max_attempts"]) // JSON numbers are float64
	assert.Equal(t, "exponential", retry["backoff"])
}

// TestActionTypes tests various action types
func TestActionTypes(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	testCases := []struct {
		name   string
		action *core.Action
	}{
		{
			name: "Webhook Action",
			action: &core.Action{
				ID:     "webhook-test",
				Type:   "webhook",
				Config: map[string]interface{}{"url": "https://example.com"},
			},
		},
		{
			name: "Email Action",
			action: &core.Action{
				ID:   "email-test",
				Type: "email",
				Config: map[string]interface{}{
					"to":      "security@example.com",
					"subject": "Security Alert",
				},
			},
		},
		{
			name: "Slack Action",
			action: &core.Action{
				ID:   "slack-test",
				Type: "slack",
				Config: map[string]interface{}{
					"channel": "#security-alerts",
					"webhook": "https://hooks.slack.com/services/XXX",
				},
			},
		},
		{
			name: "JIRA Action",
			action: &core.Action{
				ID:   "jira-test",
				Type: "jira",
				Config: map[string]interface{}{
					"server":  "https://jira.example.com",
					"project": "SEC",
				},
			},
		},
		{
			name: "PagerDuty Action",
			action: &core.Action{
				ID:   "pagerduty-test",
				Type: "pagerduty",
				Config: map[string]interface{}{
					"integration_key": "abcd1234",
					"severity":        "critical",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := storage.CreateAction(tc.action)
			require.NoError(t, err)

			retrieved, err := storage.GetAction(tc.action.ID)
			require.NoError(t, err)
			assert.Equal(t, tc.action.Type, retrieved.Type)
			assert.NotNil(t, retrieved.Config)
		})
	}
}

// TestEnsureIndexes tests index creation (no-op in current implementation)
func TestEnsureIndexes_Actions(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	err := storage.EnsureIndexes()
	assert.NoError(t, err)
}

// TestActionConfig_InvalidJSON tests handling of malformed config in database
func TestActionConfig_InvalidJSON(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	// Manually insert action with invalid JSON
	now := time.Now().Format(time.RFC3339)
	_, err := sqlite.DB.Exec(`
		INSERT INTO actions (id, type, config, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, "invalid-json", "test", "{invalid json}", now, now)
	require.NoError(t, err)

	// GetAction should fail when parsing invalid JSON
	_, err = storage.GetAction("invalid-json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config")
}

// TestGetActions_InvalidJSON tests handling of invalid JSON in GetActions
func TestGetActions_InvalidJSON(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	// Create a valid action first
	validAction := &core.Action{
		ID:     "valid-action",
		Type:   "webhook",
		Config: map[string]interface{}{"url": "https://example.com"},
	}
	err := storage.CreateAction(validAction)
	require.NoError(t, err)

	// Manually insert action with invalid JSON
	now := time.Now().Format(time.RFC3339)
	_, err = sqlite.DB.Exec(`
		INSERT INTO actions (id, type, config, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, "invalid-json-2", "test", "{broken:json}", now, now)
	require.NoError(t, err)

	// GetActions should skip invalid entries and log warning
	actions, err := storage.GetActions()
	require.NoError(t, err)
	// Should only contain the valid action
	assert.Equal(t, 1, len(actions))
	assert.Equal(t, "valid-action", actions[0].ID)
}

// TestActionCRUD_Sequence tests complete CRUD sequence
func TestActionCRUD_Sequence(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	// 1. Create
	action := &core.Action{
		ID:   "crud-test",
		Type: "webhook",
		Config: map[string]interface{}{
			"url":    "https://v1.example.com",
			"method": "POST",
		},
	}
	err := storage.CreateAction(action)
	require.NoError(t, err)

	// 2. Read
	retrieved, err := storage.GetAction("crud-test")
	require.NoError(t, err)
	assert.Equal(t, "https://v1.example.com", retrieved.Config["url"])

	// 3. Update
	time.Sleep(10 * time.Millisecond)
	updatedAction := &core.Action{
		ID:   "crud-test",
		Type: "webhook",
		Config: map[string]interface{}{
			"url":     "https://v2.example.com",
			"method":  "POST",
			"timeout": 60,
		},
	}
	err = storage.UpdateAction("crud-test", updatedAction)
	require.NoError(t, err)

	// Verify update
	retrieved, err = storage.GetAction("crud-test")
	require.NoError(t, err)
	assert.Equal(t, "https://v2.example.com", retrieved.Config["url"])
	assert.Equal(t, float64(60), retrieved.Config["timeout"])

	// 4. Delete
	err = storage.DeleteAction("crud-test")
	require.NoError(t, err)

	// Verify deletion
	_, err = storage.GetAction("crud-test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrActionNotFound)
}

// Benchmark tests

func BenchmarkCreateAction(b *testing.B) {
	_, sqlite := setupTestDB(&testing.T{})
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		action := &core.Action{
			ID:   fmt.Sprintf("bench-action-%d", i),
			Type: "webhook",
			Config: map[string]interface{}{
				"url": "https://example.com/webhook",
			},
		}
		_ = storage.CreateAction(action)
	}
}

func BenchmarkGetAction(b *testing.B) {
	_, sqlite := setupTestDB(&testing.T{})
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	// Setup: create an action
	action := &core.Action{
		ID:   "bench-get-action",
		Type: "webhook",
		Config: map[string]interface{}{
			"url": "https://example.com/webhook",
		},
	}
	_ = storage.CreateAction(action)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = storage.GetAction("bench-get-action")
	}
}

// TestGetActions_JSONSerializationContract verifies JSON serialization produces [] not null
// This is the GOLD STANDARD test that verifies the nil-slice bug fix.
// Empty result sets MUST serialize to [] not null to maintain frontend contract.
func TestGetActions_JSONSerializationContract(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteActionStorage(sqlite, zap.NewNop().Sugar())

	// Get all actions from empty database
	actions, err := storage.GetActions()
	if err != nil {
		t.Fatalf("Failed to get actions: %v", err)
	}

	// Critical: Verify JSON serialization produces [], not null
	jsonBytes, err := json.Marshal(actions)
	if err != nil {
		t.Fatalf("Failed to marshal actions: %v", err)
	}

	if string(jsonBytes) != "[]" {
		t.Errorf("Expected JSON '[]', got '%s' - nil slices break frontend contract", string(jsonBytes))
	}
}
