package storage

import (
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Test SQL injection prevention for rules operations
func TestSQLiteRuleStorage_SQLInjectionPrevention(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create rule with SQL injection attempt in ID
	maliciousRule := &core.Rule{
		ID:          "'; DROP TABLE rules; --",
		Type:        "sigma",
		Name:        "Malicious Rule",
		Description: "Test SQL injection",
		Severity:    "high",
		Enabled:     true,
		SigmaYAML: `title: Malicious Rule
detection:
  selection:
    test: value
  condition: selection
level: high`,
		Actions:    []core.Action{{ID: "act-1", Type: "alert"}},
	}

	// Should safely create rule without executing SQL injection
	err := ruleStorage.CreateRule(maliciousRule)
	require.NoError(t, err, "Should handle malicious input safely")

	// Verify rule was created with malicious string as data
	retrieved, err := ruleStorage.GetRule("'; DROP TABLE rules; --")
	require.NoError(t, err)
	assert.Equal(t, maliciousRule.ID, retrieved.ID)

	// Verify rules table still exists
	count, err := ruleStorage.GetRuleCount()
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Test SQL injection in name field
	maliciousRule2 := &core.Rule{
		ID:          "rule-002",
		Type:        "sigma",
		Name:        "'; DELETE FROM rules WHERE '1'='1",
		Description: "Test",
		Severity:    "medium",
		Enabled:     true,
		SigmaYAML: `title: Test
detection:
  selection:
    test: value
  condition: selection
level: medium`,
		Actions:    []core.Action{{ID: "act-1", Type: "alert"}},
	}

	err = ruleStorage.CreateRule(maliciousRule2)
	require.NoError(t, err)

	// Both rules should still exist
	count, err = ruleStorage.GetRuleCount()
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

// TestSQLiteRuleStorage_CreateRule tests rule creation
func TestSQLiteRuleStorage_CreateRule(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	rule := &core.Rule{
		ID:              "test-rule-001",
		Type:            "sigma",
		Name:            "Test Rule",
		Description:     "Test rule description",
		Severity:        "high",
		Enabled:         true,
		Version:         1,
		Tags:            []string{"test", "authentication"},
		MitreTactics:    []string{"TA0001"},
		MitreTechniques: []string{"T1078"},
		Author:          "Test Author",
		References:      []string{"https://example.com"},
		FalsePositives:  []string{"Known admin activity"},
		Metadata: map[string]interface{}{
			"category": "authentication",
		},
		SigmaYAML: `title: Test Rule
detection:
  condition: selection
  selection:
    EventID: 4624`,
		Actions: []core.Action{
			{ID: "action-001", Type: "alert"},
		},
	}

	err := ruleStorage.CreateRule(rule)
	require.NoError(t, err, "Should create rule")

	// Verify rule exists
	retrieved, err := ruleStorage.GetRule(rule.ID)
	require.NoError(t, err)
	assert.Equal(t, rule.ID, retrieved.ID)
	assert.Equal(t, rule.Name, retrieved.Name)
	assert.Equal(t, rule.Severity, retrieved.Severity)
	assert.Equal(t, rule.Enabled, retrieved.Enabled)
	assert.Equal(t, rule.Author, retrieved.Author)
	assert.Equal(t, len(rule.Tags), len(retrieved.Tags))
	assert.Equal(t, len(rule.MitreTactics), len(retrieved.MitreTactics))
	// Conditions field verification removed - legacy field deprecated in favor of SIGMA YAML
}

// TestSQLiteRuleStorage_CreateRule_Duplicate tests duplicate rule creation
func TestSQLiteRuleStorage_CreateRule_Duplicate(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	rule := &core.Rule{
		ID:       "dup-rule-001",
		Type:     "sigma",
		Name:     "Duplicate Rule",
		Severity: "medium",
		Enabled:  true,
		SigmaYAML: `title: Duplicate Rule
detection:
  selection:
    test: value
  condition: selection
level: medium`,
		Actions:    []core.Action{{ID: "act-1", Type: "alert"}},
	}

	// Create first time - should succeed
	err := ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Create again - should fail
	err = ruleStorage.CreateRule(rule)
	assert.Error(t, err, "Should not allow duplicate rule")
}

// TestSQLiteRuleStorage_GetRule tests retrieving a single rule
func TestSQLiteRuleStorage_GetRule(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create test rule
	rule := &core.Rule{
		ID:          "get-rule-001",
		Type:        "cql",
		Name:        "Get Test Rule",
		Description: "Testing GetRule",
		Severity:    "low",
		Enabled:     false,
		Query:       "SELECT * FROM events",
		Correlation: map[string]interface{}{"timeWindow": "5m"},
	}

	err := ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Get rule
	retrieved, err := ruleStorage.GetRule(rule.ID)
	require.NoError(t, err)
	assert.Equal(t, rule.ID, retrieved.ID)
	assert.Equal(t, rule.Type, retrieved.Type)
	assert.Equal(t, rule.Query, retrieved.Query)
	assert.NotNil(t, retrieved.Correlation)
}

// TestSQLiteRuleStorage_GetRule_NotFound tests retrieving non-existent rule
func TestSQLiteRuleStorage_GetRule_NotFound(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	_, err := ruleStorage.GetRule("non-existent-rule")
	assert.Error(t, err)
	assert.Equal(t, ErrRuleNotFound, err)
}

// TestSQLiteRuleStorage_GetRules tests pagination
func TestSQLiteRuleStorage_GetRules(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create 25 test rules
	for i := 0; i < 25; i++ {
		rule := &core.Rule{
			ID:       createID("pagination-rule", i),
			Type:     "sigma",
			Name:     createName("Pagination Rule", i),
			Severity: "medium",
			Enabled:  true,
			SigmaYAML: `title: Pagination Rule
detection:
  selection:
    test: value
  condition: selection
level: medium`,
			Actions:    []core.Action{{ID: "act-1", Type: "alert"}},
		}
		err := ruleStorage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Test first page
	rules, err := ruleStorage.GetRules(10, 0)
	require.NoError(t, err)
	assert.Equal(t, 10, len(rules))

	// Test second page
	rules, err = ruleStorage.GetRules(10, 10)
	require.NoError(t, err)
	assert.Equal(t, 10, len(rules))

	// Test third page
	rules, err = ruleStorage.GetRules(10, 20)
	require.NoError(t, err)
	assert.Equal(t, 5, len(rules))

	// Test beyond available rules
	rules, err = ruleStorage.GetRules(10, 30)
	require.NoError(t, err)
	assert.Equal(t, 0, len(rules))
}

// TestSQLiteRuleStorage_GetAllRules tests retrieving all rules
func TestSQLiteRuleStorage_GetAllRules(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create 5 test rules
	for i := 0; i < 5; i++ {
		rule := &core.Rule{
			ID:       createID("all-rules", i),
			Type:     "sigma",
			Name:     createName("All Rules Test", i),
			Severity: "high",
			Enabled:  true,
			SigmaYAML: `title: All Rules Test
detection:
  selection:
    test: value
  condition: selection
level: high`,
			Actions:    []core.Action{{ID: "act-1", Type: "alert"}},
		}
		err := ruleStorage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Get all rules
	rules, err := ruleStorage.GetAllRules()
	require.NoError(t, err)
	assert.Equal(t, 5, len(rules))
}

// TestSQLiteRuleStorage_GetRuleCount tests rule counting
func TestSQLiteRuleStorage_GetRuleCount(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Initially empty
	count, err := ruleStorage.GetRuleCount()
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// Create rules
	for i := 0; i < 15; i++ {
		rule := &core.Rule{
			ID:       createID("count-rule", i),
			Type:     "sigma",
			Name:     createName("Count Test", i),
			Severity: "low",
			Enabled:  true,
			SigmaYAML: `title: Count Test
detection:
  selection:
    test: value
  condition: selection
level: low`,
			Actions:    []core.Action{{ID: "act-1", Type: "alert"}},
		}
		err := ruleStorage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Verify count
	count, err = ruleStorage.GetRuleCount()
	require.NoError(t, err)
	assert.Equal(t, int64(15), count)
}

// TestSQLiteRuleStorage_UpdateRule tests rule update
func TestSQLiteRuleStorage_UpdateRule(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create original rule
	rule := &core.Rule{
		ID:          "update-rule-001",
		Type:        "sigma",
		Name:        "Original Name",
		Description: "Original Description",
		Severity:    "low",
		Enabled:     true,
		Version:     1,
		SigmaYAML: `title: Original Name
detection:
  selection:
    test: original
  condition: selection
level: low`,
		Actions:    []core.Action{{ID: "act-1", Type: "alert"}},
	}

	err := ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Update rule
	rule.Name = "Updated Name"
	rule.Description = "Updated Description"
	rule.Severity = "critical"
	rule.Enabled = false
	rule.Version = 2
	rule.SigmaYAML = `title: Updated Name
detection:
  selection:
    test: updated
  condition: selection
level: critical`

	err = ruleStorage.UpdateRule(rule.ID, rule)
	require.NoError(t, err)

	// Verify updates
	retrieved, err := ruleStorage.GetRule(rule.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", retrieved.Name)
	assert.Equal(t, "Updated Description", retrieved.Description)
	assert.Equal(t, "Critical", retrieved.Severity) // Severity is normalized to title case
	assert.Equal(t, false, retrieved.Enabled)
	assert.Equal(t, 2, retrieved.Version)
}

// TestSQLiteRuleStorage_DeleteRule tests rule deletion
func TestSQLiteRuleStorage_DeleteRule(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create rule
	rule := &core.Rule{
		ID:       "delete-rule-001",
		Type:     "sigma",
		Name:     "To Be Deleted",
		Severity: "medium",
		Enabled:  true,
		SigmaYAML: `title: To Be Deleted
detection:
  selection:
    test: value
  condition: selection
level: medium`,
		Actions:    []core.Action{{ID: "act-1", Type: "alert"}},
	}

	err := ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Verify rule exists
	_, err = ruleStorage.GetRule(rule.ID)
	require.NoError(t, err)

	// Delete rule
	err = ruleStorage.DeleteRule(rule.ID)
	require.NoError(t, err)

	// Verify rule is gone
	_, err = ruleStorage.GetRule(rule.ID)
	assert.Error(t, err)
	assert.Equal(t, ErrRuleNotFound, err)
}

// TestSQLiteRuleStorage_EnableDisableRule tests enable/disable operations
func TestSQLiteRuleStorage_EnableDisableRule(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create enabled rule
	rule := &core.Rule{
		ID:       "enable-disable-001",
		Type:     "sigma",
		Name:     "Toggle Rule",
		Severity: "high",
		Enabled:  true,
		SigmaYAML: `title: Toggle Rule
detection:
  selection:
    test: value
  condition: selection
level: high`,
		Actions:    []core.Action{{ID: "act-1", Type: "alert"}},
	}

	err := ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Disable rule
	err = ruleStorage.DisableRule(rule.ID)
	require.NoError(t, err)

	retrieved, err := ruleStorage.GetRule(rule.ID)
	require.NoError(t, err)
	assert.False(t, retrieved.Enabled)

	// Enable rule
	err = ruleStorage.EnableRule(rule.ID)
	require.NoError(t, err)

	retrieved, err = ruleStorage.GetRule(rule.ID)
	require.NoError(t, err)
	assert.True(t, retrieved.Enabled)
}

// TestSQLiteRuleStorage_ComplexJSONFields tests complex JSON field handling
func TestSQLiteRuleStorage_ComplexJSONFields(t *testing.T) {
	sqlite := setupTestSQLite(t)
	defer sqlite.Close()

	logger := zap.NewNop().Sugar()
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create rule with complex nested structures
	rule := &core.Rule{
		ID:              "complex-json-001",
		Type:            "sigma",
		Name:            "Complex JSON Test",
		Severity:        "high",
		Enabled:         true,
		Tags:            []string{"tag1", "tag2", "tag3"},
		MitreTactics:    []string{"TA0001", "TA0002"},
		MitreTechniques: []string{"T1078", "T1110"},
		References:      []string{"ref1", "ref2", "ref3"},
		FalsePositives:  []string{"fp1", "fp2"},
		Metadata: map[string]interface{}{
			"key1": "value1",
			"key2": 123,
			"key3": map[string]interface{}{
				"nested": "data",
			},
		},
		SigmaYAML: `title: Complex JSON Test
detection:
  condition: selection
  selection:
    field1: value1`,
		Actions: []core.Action{
			{ID: "act-1", Type: "alert", Config: map[string]interface{}{"severity": "high"}},
			{ID: "act-2", Type: "webhook", Config: map[string]interface{}{"url": "https://example.com"}},
		},
		Correlation: map[string]interface{}{
			"timeWindow": "5m",
			"threshold":  10,
			"groupBy":    []string{"field1", "field2"},
		},
	}

	err := ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Retrieve and verify all complex fields
	retrieved, err := ruleStorage.GetRule(rule.ID)
	require.NoError(t, err)

	assert.Equal(t, len(rule.Tags), len(retrieved.Tags))
	assert.Equal(t, len(rule.MitreTactics), len(retrieved.MitreTactics))
	assert.Equal(t, len(rule.MitreTechniques), len(retrieved.MitreTechniques))
	assert.Equal(t, len(rule.References), len(retrieved.References))
	assert.Equal(t, len(rule.FalsePositives), len(retrieved.FalsePositives))
	assert.NotNil(t, retrieved.Metadata)
	// Legacy field verification removed - Conditions and Actions deprecated in favor of SIGMA YAML
	// Actions are now derived from SigmaYAML detection rules, not stored separately
	assert.NotNil(t, retrieved.Correlation)
}

// Helper functions
func createID(prefix string, index int) string {
	return prefix + "-" + string(rune(index))
}

func createName(prefix string, index int) string {
	return prefix + " " + string(rune(index))
}
