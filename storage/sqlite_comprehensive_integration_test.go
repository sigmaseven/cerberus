package storage

import (
	"fmt"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// createTestSigmaRuleInteg creates a valid SIGMA rule with SigmaYAML for integration testing
func createTestSigmaRuleInteg(id, name string) *core.Rule {
	return &core.Rule{
		ID:          id,
		Name:        name,
		Description: "Test rule description",
		Severity:    "High",
		Enabled:     true,
		Type:        "sigma",
		SigmaYAML: `title: ` + name + `
id: ` + id + `
status: stable
description: Test rule description
author: Test Suite
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\test.exe'
  condition: selection
level: high`,
		LogsourceCategory: "process_creation",
		LogsourceProduct:  "windows",
		Actions:           []core.Action{{ID: "act-1", Type: "alert"}},
	}
}

// TestSQLiteRuleStorage_GetRulesByType tests filtering by type
func TestSQLiteRuleStorage_GetRulesByType(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create sigma rules
	for i := 0; i < 3; i++ {
		rule := createTestSigmaRuleInteg(fmt.Sprintf("sigma-rule-%d", i), fmt.Sprintf("Sigma Rule %d", i))
		require.NoError(t, ruleStorage.CreateRule(rule))
	}

	// Create CQL rules
	for i := 0; i < 2; i++ {
		rule := &core.Rule{
			ID:       fmt.Sprintf("cql-rule-%d", i),
			Type:     "cql",
			Name:     fmt.Sprintf("CQL Rule %d", i),
			Severity: "Medium",
			Enabled:  true,
			Query:    "SELECT * FROM events",
		}
		require.NoError(t, ruleStorage.CreateRule(rule))
	}

	// Get sigma rules with pagination
	sigmaRules, err := ruleStorage.GetRulesByType("sigma", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 3, len(sigmaRules))

	// Get CQL rules with pagination
	cqlRules, err := ruleStorage.GetRulesByType("cql", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, len(cqlRules))
}

// TestSQLiteRuleStorage_GetEnabledRules tests getting only enabled rules
func TestSQLiteRuleStorage_GetEnabledRules(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create enabled rules
	for i := 0; i < 3; i++ {
		rule := createTestSigmaRuleInteg(fmt.Sprintf("enabled-rule-%d", i), fmt.Sprintf("Enabled Rule %d", i))
		require.NoError(t, ruleStorage.CreateRule(rule))
	}

	// Create disabled rules
	for i := 0; i < 2; i++ {
		rule := createTestSigmaRuleInteg(fmt.Sprintf("disabled-rule-%d", i), fmt.Sprintf("Disabled Rule %d", i))
		rule.Enabled = false
		rule.Severity = "Low"
		require.NoError(t, ruleStorage.CreateRule(rule))
	}

	// Get only enabled rules
	enabledRules, err := ruleStorage.GetEnabledRules()
	require.NoError(t, err)
	assert.Equal(t, 3, len(enabledRules))

	for _, rule := range enabledRules {
		assert.True(t, rule.Enabled)
	}
}

// TestSQLiteRuleStorage_SearchRules tests rule search
func TestSQLiteRuleStorage_SearchRules(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create searchable rules
	rule1 := createTestSigmaRuleInteg("search-rule-1", "Failed Login Detection")
	rule1.Description = "Detects failed login attempts"
	require.NoError(t, ruleStorage.CreateRule(rule1))

	rule2 := createTestSigmaRuleInteg("search-rule-2", "Successful Login")
	rule2.Description = "Tracks successful logins"
	rule2.Severity = "Low"
	require.NoError(t, ruleStorage.CreateRule(rule2))

	// Search for "login"
	results, err := ruleStorage.SearchRules("login")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 2)

	// Search for "failed"
	results, err = ruleStorage.SearchRules("failed")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1)
}

// TestSQLiteActionStorage_CreateAction tests action creation
func TestSQLiteActionStorage_CreateAction(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	actionStorage := NewSQLiteActionStorage(sqlite, logger)

	action := &core.Action{
		ID:   "action-001",
		Type: "webhook",
		Config: map[string]interface{}{
			"url":    "https://example.com/webhook",
			"method": "POST",
		},
	}

	err := actionStorage.CreateAction(action)
	require.NoError(t, err)

	// Verify action exists
	retrieved, err := actionStorage.GetAction(action.ID)
	require.NoError(t, err)
	assert.Equal(t, action.ID, retrieved.ID)
	assert.Equal(t, action.Type, retrieved.Type)
	assert.NotNil(t, retrieved.Config)
}

// TestSQLiteActionStorage_GetActions tests retrieving actions
func TestSQLiteActionStorage_GetActions(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	actionStorage := NewSQLiteActionStorage(sqlite, logger)

	// Create test actions
	for i := 0; i < 5; i++ {
		action := &core.Action{
			ID:   fmt.Sprintf("action-%d", i),
			Type: "email",
			Config: map[string]interface{}{
				"to": "admin@example.com",
			},
		}
		require.NoError(t, actionStorage.CreateAction(action))
	}

	// Get actions
	actions, err := actionStorage.GetActions()
	require.NoError(t, err)
	assert.Equal(t, 5, len(actions))
}

// TestSQLiteActionStorage_UpdateAction tests action update
func TestSQLiteActionStorage_UpdateAction(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	actionStorage := NewSQLiteActionStorage(sqlite, logger)

	action := &core.Action{
		ID:   "update-action-001",
		Type: "webhook",
		Config: map[string]interface{}{
			"url": "https://old.example.com",
		},
	}

	require.NoError(t, actionStorage.CreateAction(action))

	// Update action
	action.Type = "slack"
	action.Config = map[string]interface{}{
		"channel": "#security",
	}

	err := actionStorage.UpdateAction(action.ID, action)
	require.NoError(t, err)

	// Verify update
	retrieved, err := actionStorage.GetAction(action.ID)
	require.NoError(t, err)
	assert.Equal(t, "slack", retrieved.Type)
}

// TestSQLiteActionStorage_DeleteAction tests action deletion
func TestSQLiteActionStorage_DeleteAction(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	actionStorage := NewSQLiteActionStorage(sqlite, logger)

	action := &core.Action{
		ID:   "delete-action-001",
		Type: "jira",
		Config: map[string]interface{}{
			"project": "SEC",
		},
	}

	require.NoError(t, actionStorage.CreateAction(action))

	// Delete action
	err := actionStorage.DeleteAction(action.ID)
	require.NoError(t, err)

	// Verify deletion
	_, err = actionStorage.GetAction(action.ID)
	assert.Error(t, err)
}

// TestSQLiteCorrelationRuleStorage_CreateCorrelationRule tests correlation rule creation
func TestSQLiteCorrelationRuleStorage_CreateCorrelationRule(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	corrStorage := NewSQLiteCorrelationRuleStorage(sqlite, logger)

	corrRule := &core.CorrelationRule{
		ID:          "corr-001",
		Name:        "Brute Force Detection",
		Description: "Multiple failed logins",
		Severity:    "high",
		Window:      5 * time.Minute,
		Sequence:    []string{"login_failed", "login_failed", "login_failed"},
		Actions:     []core.Action{{ID: "act-1", Type: "alert"}},
	}

	err := corrStorage.CreateCorrelationRule(corrRule)
	require.NoError(t, err)

	// Verify correlation rule exists
	retrieved, err := corrStorage.GetCorrelationRule(corrRule.ID)
	require.NoError(t, err)
	assert.Equal(t, corrRule.ID, retrieved.ID)
	assert.Equal(t, corrRule.Name, retrieved.Name)
}
