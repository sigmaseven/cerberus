package storage

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestCreateRule_SIGMA_WithYAML tests creating a SIGMA rule with sigma_yaml field
func TestCreateRule_SIGMA_WithYAML(t *testing.T) {
	// Create test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_sigma_yaml.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Valid SIGMA YAML
	sigmaYAML := `title: Test Process Creation
level: high
description: Detects suspicious process creation
logsource:
  category: process_creation
  product: windows
  service: sysmon
detection:
  selection:
    Image|endswith: '.exe'
    User: SYSTEM
  condition: selection
tags:
  - attack.execution
  - attack.t1059
author: Test Author
references:
  - https://example.com/reference
falsepositives:
  - Legitimate system processes`

	rule := &core.Rule{
		ID:        "test-sigma-yaml-rule",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
		Enabled:   true,
		Version:   1,
	}

	// Create rule
	err = storage.CreateRule(rule)
	require.NoError(t, err, "CreateRule should succeed with valid SIGMA YAML")

	// Retrieve rule and verify all fields were extracted
	retrieved, err := storage.GetRule("test-sigma-yaml-rule")
	require.NoError(t, err)
	assert.NotNil(t, retrieved)

	// Verify SIGMA YAML is stored
	assert.Equal(t, sigmaYAML, retrieved.SigmaYAML)

	// Verify metadata extraction
	assert.Equal(t, "Test Process Creation", retrieved.Name, "Title should be extracted to Name")
	assert.Equal(t, "High", retrieved.Severity, "Level should be mapped to Severity")
	assert.Equal(t, "Test Author", retrieved.Author)
	assert.Contains(t, retrieved.Tags, "attack.execution")
	assert.Contains(t, retrieved.Tags, "attack.t1059")
	assert.Contains(t, retrieved.References, "https://example.com/reference")
	assert.Contains(t, retrieved.FalsePositives, "Legitimate system processes")

	// Verify denormalized logsource fields
	assert.Equal(t, "process_creation", retrieved.LogsourceCategory)
	assert.Equal(t, "windows", retrieved.LogsourceProduct)
	assert.Equal(t, "sysmon", retrieved.LogsourceService)

	// Verify MITRE extraction
	assert.Contains(t, retrieved.MitreTechniques, "T1059", "MITRE technique should be extracted from tags")
}

// TestCreateRule_CQL_WithQuery tests creating a CQL rule with query field
func TestCreateRule_CQL_WithQuery(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_cql.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	rule := &core.Rule{
		ID:       "test-cql-rule",
		Type:     "cql",
		Name:     "Test CQL Rule",
		Severity: "Medium",
		Query:    "SELECT * FROM events WHERE severity = 'high'",
		Enabled:  true,
		Version:  1,
	}

	// Create rule
	err = storage.CreateRule(rule)
	require.NoError(t, err, "CreateRule should succeed with valid CQL rule")

	// Retrieve rule
	retrieved, err := storage.GetRule("test-cql-rule")
	require.NoError(t, err)
	assert.NotNil(t, retrieved)

	// Verify query is stored
	assert.Equal(t, "SELECT * FROM events WHERE severity = 'high'", retrieved.Query)
	assert.Empty(t, retrieved.SigmaYAML, "SigmaYAML should be empty for CQL rules")
}

// TestCreateRule_ValidationErrors tests that validation catches mutual exclusion violations
func TestCreateRule_ValidationErrors(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_validation.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	tests := []struct {
		name        string
		rule        *core.Rule
		expectError bool
		errorMsg    string
	}{
		{
			name: "SIGMA rule with query field",
			rule: &core.Rule{
				ID:        "invalid-sigma",
				Type:      "sigma",
				SigmaYAML: "title: Test\ndetection:\n  condition: true",
				Query:     "SELECT * FROM events", // Invalid: SIGMA can't have query
				Enabled:   true,
				Version:   1,
			},
			expectError: true,
			errorMsg:    "SIGMA rules must have sigma_yaml field and cannot have query field",
		},
		{
			name: "CQL rule with sigma_yaml field",
			rule: &core.Rule{
				ID:        "invalid-cql",
				Type:      "cql",
				Query:     "SELECT * FROM events",
				SigmaYAML: "title: Test\ndetection:\n  condition: true", // Invalid: CQL can't have sigma_yaml
				Enabled:   true,
				Version:   1,
			},
			expectError: true,
			errorMsg:    "CQL rules must have query field and cannot have sigma_yaml field",
		},
		{
			name: "SIGMA rule without sigma_yaml",
			rule: &core.Rule{
				ID:      "sigma-no-yaml",
				Type:    "sigma",
				Enabled: true,
				Version: 1,
			},
			expectError: true,
			errorMsg:    "SIGMA rules must have sigma_yaml field",
		},
		{
			name: "CQL rule without query",
			rule: &core.Rule{
				ID:      "cql-no-query",
				Type:    "cql",
				Enabled: true,
				Version: 1,
			},
			expectError: true,
			errorMsg:    "CQL rules must have query field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.CreateRule(tt.rule)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestUpdateRule_WithSigmaYAML tests updating a SIGMA rule with new YAML
func TestUpdateRule_WithSigmaYAML(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_update.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create initial rule
	initialYAML := `title: Initial Title
level: medium
logsource:
  category: process_creation
  product: windows
detection:
  condition: true`

	rule := &core.Rule{
		ID:        "test-update-rule",
		Type:      "sigma",
		SigmaYAML: initialYAML,
		Enabled:   true,
		Version:   1,
	}

	err = storage.CreateRule(rule)
	require.NoError(t, err)

	// Update with new YAML
	updatedYAML := `title: Updated Title
level: critical
logsource:
  category: network_connection
  product: linux
  service: auditd
detection:
  condition: false
author: New Author
tags:
  - attack.discovery
  - attack.t1046`

	updatedRule := &core.Rule{
		ID:        "test-update-rule",
		Type:      "sigma",
		SigmaYAML: updatedYAML,
		Enabled:   false,
		Version:   2,
	}

	err = storage.UpdateRule("test-update-rule", updatedRule)
	require.NoError(t, err)

	// Retrieve and verify updates
	retrieved, err := storage.GetRule("test-update-rule")
	require.NoError(t, err)

	assert.Equal(t, "Updated Title", retrieved.Name)
	assert.Equal(t, "Critical", retrieved.Severity)
	assert.Equal(t, "network_connection", retrieved.LogsourceCategory)
	assert.Equal(t, "linux", retrieved.LogsourceProduct)
	assert.Equal(t, "auditd", retrieved.LogsourceService)
	assert.Equal(t, "New Author", retrieved.Author)
	assert.Contains(t, retrieved.Tags, "attack.discovery")
	assert.Contains(t, retrieved.Tags, "attack.t1046")
	assert.False(t, retrieved.Enabled)
	assert.Equal(t, 2, retrieved.Version)
}

// TestCacheInvalidation tests that cache is invalidated on update
func TestCacheInvalidation(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_cache.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Mock cache invalidator
	invalidatedIDs := make([]string, 0)
	mockInvalidator := &mockCacheInvalidator{
		invalidatedIDs: &invalidatedIDs,
	}
	storage.SetCacheInvalidator(mockInvalidator)

	// Create rule
	rule := &core.Rule{
		ID:        "test-cache-rule",
		Type:      "sigma",
		SigmaYAML: "title: Test\ndetection:\n  condition: true",
		Enabled:   true,
		Version:   1,
	}
	err = storage.CreateRule(rule)
	require.NoError(t, err)

	// Update rule
	updatedRule := &core.Rule{
		ID:        "test-cache-rule",
		Type:      "sigma",
		SigmaYAML: "title: Updated\ndetection:\n  condition: false",
		Enabled:   true,
		Version:   2,
	}
	err = storage.UpdateRule("test-cache-rule", updatedRule)
	require.NoError(t, err)

	// Verify cache was invalidated
	assert.Contains(t, invalidatedIDs, "test-cache-rule", "Cache should be invalidated on update")
}

// TestLogsourceFiltering tests filtering rules by logsource
func TestLogsourceFiltering(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_filter.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create rules with different logsources
	rules := []*core.Rule{
		{
			ID:        "rule-windows-process",
			Type:      "sigma",
			SigmaYAML: "title: Windows Process\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  condition: true",
			Enabled:   true,
			Version:   1,
		},
		{
			ID:        "rule-linux-network",
			Type:      "sigma",
			SigmaYAML: "title: Linux Network\nlogsource:\n  category: network_connection\n  product: linux\ndetection:\n  condition: true",
			Enabled:   true,
			Version:   1,
		},
		{
			ID:        "rule-windows-sysmon",
			Type:      "sigma",
			SigmaYAML: "title: Windows Sysmon\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  condition: true",
			Enabled:   true,
			Version:   1,
		},
	}

	for _, rule := range rules {
		err = storage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Test filtering by product
	filters := &core.RuleFilters{
		LogSources: []string{"windows"},
		Limit:      10,
		Page:       1,
	}
	results, total, err := storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	assert.Equal(t, int64(2), total, "Should find 2 Windows rules")
	assert.Len(t, results, 2)

	// Test filtering by category
	filters.LogSources = []string{"process_creation"}
	results, total, err = storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total, "Should find 1 process_creation rule")
	assert.Len(t, results, 1)
	assert.Equal(t, "rule-windows-process", results[0].ID)

	// Test filtering by service
	filters.LogSources = []string{"sysmon"}
	results, total, err = storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total, "Should find 1 sysmon rule")
	assert.Len(t, results, 1)
	assert.Equal(t, "rule-windows-sysmon", results[0].ID)
}

// TestBackwardCompatibility tests that legacy rules without sigma_yaml still work
func TestBackwardCompatibility(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_legacy.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// TASK #184: Legacy Detection/Logsource fields have been removed.
	// All SIGMA rules must now use SigmaYAML field.
	// Create a simple SIGMA rule to test basic functionality instead.
	_ = &core.Rule{
		ID:          "legacy-rule",
		Type:        "sigma",
		Name:        "Legacy Rule",
		Description: "Old format rule",
		Severity:    "High",
		Enabled:     true,
		Version:     1,
		SigmaYAML: `title: Legacy Rule
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4688
  condition: selection`,
	}

	// Note: Legacy rules without sigma_yaml are no longer supported.
	// All rules must have the SigmaYAML field populated.

	// Create new SIGMA rule with sigma_yaml
	newRule := &core.Rule{
		ID:        "new-sigma-rule",
		Type:      "sigma",
		SigmaYAML: "title: New Format\nlogsource:\n  category: process_creation\ndetection:\n  condition: true",
		Enabled:   true,
		Version:   1,
	}

	err = storage.CreateRule(newRule)
	require.NoError(t, err)

	// Create CQL rule (different type)
	cqlRule := &core.Rule{
		ID:       "cql-rule",
		Type:     "cql",
		Name:     "CQL Rule",
		Severity: "Medium",
		Query:    "SELECT * FROM events",
		Enabled:  true,
		Version:  1,
	}

	err = storage.CreateRule(cqlRule)
	require.NoError(t, err)

	// Retrieve all rules - both should coexist
	allRules, err := storage.GetAllRules()
	require.NoError(t, err)
	assert.Len(t, allRules, 2, "Both SIGMA and CQL rules should be retrieved")

	// Verify each rule has correct fields populated
	for _, rule := range allRules {
		if rule.Type == "sigma" {
			assert.NotEmpty(t, rule.SigmaYAML, "SIGMA rule should have sigma_yaml")
			assert.Empty(t, rule.Query, "SIGMA rule should not have query")
		} else if rule.Type == "cql" {
			assert.NotEmpty(t, rule.Query, "CQL rule should have query")
			assert.Empty(t, rule.SigmaYAML, "CQL rule should not have sigma_yaml")
		}
	}

}

// TestInvalidSigmaYAML tests that invalid YAML is rejected
func TestInvalidSigmaYAML(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_invalid.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	tests := []struct {
		name        string
		sigmaYAML   string
		expectError bool
	}{
		{
			name:        "Missing title",
			sigmaYAML:   "detection:\n  condition: true",
			expectError: true,
		},
		{
			name:        "Missing detection",
			sigmaYAML:   "title: Test",
			expectError: true,
		},
		{
			name:        "Missing condition in detection",
			sigmaYAML:   "title: Test\ndetection:\n  selection:\n    field: value",
			expectError: true,
		},
		{
			name:        "Invalid YAML syntax",
			sigmaYAML:   "title: Test\n  invalid: - unclosed",
			expectError: true,
		},
		{
			name:        "Valid minimal SIGMA",
			sigmaYAML:   "title: Test\ndetection:\n  condition: true",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &core.Rule{
				ID:        "test-yaml-" + tt.name,
				Type:      "sigma",
				SigmaYAML: tt.sigmaYAML,
				Enabled:   true,
				Version:   1,
			}

			err := storage.CreateRule(rule)
			if tt.expectError {
				require.Error(t, err, "Invalid YAML should be rejected")
			} else {
				require.NoError(t, err, "Valid YAML should be accepted")
			}
		})
	}
}

// mockCacheInvalidator implements CacheInvalidator for testing
type mockCacheInvalidator struct {
	invalidatedIDs *[]string
}

func (m *mockCacheInvalidator) InvalidateCache(ruleID string) {
	*m.invalidatedIDs = append(*m.invalidatedIDs, ruleID)
}

// BLOCKING FIX #4: Test extractMetadataFromYAML error paths
func TestExtractMetadataFromYAML_NilRule(t *testing.T) {
	err := extractMetadataFromYAML(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil rule")
}

func TestExtractMetadataFromYAML_InvalidYAML(t *testing.T) {
	rule := &core.Rule{
		Type:      "sigma",
		SigmaYAML: "not: valid: yaml: syntax:",
	}
	err := extractMetadataFromYAML(rule)
	require.Error(t, err, "Invalid YAML syntax should fail")
}

func TestExtractMetadataFromYAML_EmptyYAML(t *testing.T) {
	rule := &core.Rule{
		Type:      "sigma",
		SigmaYAML: "",
	}
	err := extractMetadataFromYAML(rule)
	require.NoError(t, err, "Empty YAML should be skipped, not error")
}

func TestExtractMetadataFromYAML_NonSigmaRule(t *testing.T) {
	rule := &core.Rule{
		Type:      "cql",
		SigmaYAML: "title: Test\ndetection:\n  condition: true",
	}
	err := extractMetadataFromYAML(rule)
	require.NoError(t, err, "Non-SIGMA rules should be skipped")
}

// BLOCKING FIX #5: Test cache invalidator nil case
func TestUpdateRule_WithoutCacheInvalidator(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_no_cache.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Create storage WITHOUT SetCacheInvalidator
	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)
	// Intentionally DO NOT call storage.SetCacheInvalidator()

	// Create rule
	rule := &core.Rule{
		ID:        "test-no-cache",
		Type:      "sigma",
		SigmaYAML: "title: Initial\ndetection:\n  condition: true",
		Enabled:   true,
		Version:   1,
	}
	err = storage.CreateRule(rule)
	require.NoError(t, err)

	// Update rule - should succeed without panic even if cache invalidator is nil
	updatedRule := &core.Rule{
		ID:        "test-no-cache",
		Type:      "sigma",
		SigmaYAML: "title: Updated\ndetection:\n  condition: false",
		Enabled:   false,
		Version:   2,
	}
	err = storage.UpdateRule("test-no-cache", updatedRule)
	require.NoError(t, err, "Update should succeed without cache invalidator")

	// Verify update succeeded
	retrieved, err := storage.GetRule("test-no-cache")
	require.NoError(t, err)
	assert.Equal(t, "Updated", retrieved.Name)
	assert.False(t, retrieved.Enabled)
}

// BLOCKING FIX #6: Concurrency test
func TestConcurrentRuleUpdates(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_concurrent.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Create initial rule
	rule := &core.Rule{
		ID:        "concurrent-rule",
		Type:      "sigma",
		SigmaYAML: "title: Initial\ndetection:\n  condition: true",
		Enabled:   true,
		Version:   1,
	}
	err = storage.CreateRule(rule)
	require.NoError(t, err)

	// Spawn 10 goroutines updating the same rule concurrently
	const numGoroutines = 10
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(version int) {
			updatedRule := &core.Rule{
				ID:        "concurrent-rule",
				Type:      "sigma",
				SigmaYAML: fmt.Sprintf("title: Update %d\ndetection:\n  condition: true", version),
				Enabled:   true,
				Version:   version + 1,
			}
			err := storage.UpdateRule("concurrent-rule", updatedRule)
			done <- err
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		err := <-done
		require.NoError(t, err, "Concurrent update should not error")
	}

	// Verify final state is consistent (no data corruption)
	retrieved, err := storage.GetRule("concurrent-rule")
	require.NoError(t, err)
	assert.NotEmpty(t, retrieved.Name, "Rule name should be populated")
	assert.Contains(t, retrieved.Name, "Update", "Rule should have been updated")
	assert.Equal(t, "sigma", retrieved.Type)
}

// BLOCKING FIX #7: Migration rollback test - verify rule operations work after rollback
func TestRuleOperations_AfterMigrationIndexRollback(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_rollback.db")
	logger := zaptest.NewLogger(t).Sugar()

	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, logger)

	// Verify indexes exist after initial migration
	var indexCount int
	err = sqlite.DB.QueryRow(`
		SELECT COUNT(*) FROM sqlite_master
		WHERE type='index' AND name IN ('idx_rules_logsource_category', 'idx_rules_logsource_product', 'idx_rules_logsource_service')
	`).Scan(&indexCount)
	require.NoError(t, err)
	assert.Equal(t, 3, indexCount, "All 3 logsource indexes should exist")

	// Create rule before rollback
	ruleBeforeRollback := &core.Rule{
		ID:        "before-rollback",
		Type:      "sigma",
		SigmaYAML: "title: Before Rollback\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  condition: true",
		Enabled:   true,
		Version:   1,
	}
	err = storage.CreateRule(ruleBeforeRollback)
	require.NoError(t, err)

	// Simulate rollback by dropping indexes
	_, err = sqlite.DB.Exec("DROP INDEX IF EXISTS idx_rules_logsource_category")
	require.NoError(t, err)
	_, err = sqlite.DB.Exec("DROP INDEX IF EXISTS idx_rules_logsource_product")
	require.NoError(t, err)
	_, err = sqlite.DB.Exec("DROP INDEX IF EXISTS idx_rules_logsource_service")
	require.NoError(t, err)

	// Verify indexes are dropped
	err = sqlite.DB.QueryRow(`
		SELECT COUNT(*) FROM sqlite_master
		WHERE type='index' AND name IN ('idx_rules_logsource_category', 'idx_rules_logsource_product', 'idx_rules_logsource_service')
	`).Scan(&indexCount)
	require.NoError(t, err)
	assert.Equal(t, 0, indexCount, "Indexes should be dropped after rollback")

	// Verify rule operations still work after index rollback
	// This ensures the application is resilient to index removal
	ruleAfterRollback := &core.Rule{
		ID:        "after-rollback",
		Type:      "sigma",
		SigmaYAML: "title: After Rollback\nlogsource:\n  category: network_connection\n  product: linux\ndetection:\n  condition: true",
		Enabled:   true,
		Version:   1,
	}
	err = storage.CreateRule(ruleAfterRollback)
	require.NoError(t, err, "Rule creation should work without indexes")

	// Verify filtering still works (slower, but functional)
	filters := &core.RuleFilters{
		LogSources: []string{"windows"},
		Limit:      10,
		Page:       1,
	}
	results, total, err := storage.GetRulesWithFilters(filters)
	require.NoError(t, err, "Filtering should work without indexes")
	assert.Equal(t, int64(1), total, "Should find 1 Windows rule")
	assert.Len(t, results, 1)
	assert.Equal(t, "before-rollback", results[0].ID)
}
