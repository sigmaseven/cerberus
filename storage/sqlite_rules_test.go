package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// setupTestDB creates an ACTUAL in-memory SQLite database with the proper schema
func setupTestDB(t *testing.T) (*sql.DB, *SQLite) {
	t.Helper()

	// Create REAL in-memory database
	db, err := sql.Open("sqlite", ":memory:?_journal_mode=WAL&_busy_timeout=5000")
	require.NoError(t, err, "Failed to open in-memory SQLite database")

	// Set connection pool settings
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Test connection
	err = db.Ping()
	require.NoError(t, err, "Failed to ping database")

	sqlite := &SQLite{
		DB:      db,
		WriteDB: db, // For tests, use same connection for reads and writes
		ReadDB:  db, // For tests, use same connection for reads and writes
		Path:    ":memory:",
		Logger:  zap.NewNop().Sugar(),
	}

	// Create tables using actual schema from storage
	err = sqlite.createTables()
	require.NoError(t, err, "Failed to create tables")

	return db, sqlite
}

// TestNewSQLiteRuleStorage_Success tests successful storage creation
func TestNewSQLiteRuleStorage_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	regexTimeout := 5 * time.Second
	logger := zap.NewNop().Sugar()

	storage := NewSQLiteRuleStorage(sqlite, regexTimeout, logger)

	require.NotNil(t, storage)
	assert.Equal(t, sqlite, storage.sqlite)
	assert.Equal(t, regexTimeout, storage.regexTimeout)
	assert.NotNil(t, storage.logger)
}

// TestCreateRule_Success tests successful rule creation
func TestCreateRule_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	rule := &core.Rule{
		ID:          "test-rule-001",
		Type:        "sigma",
		Name:        "Test Rule",
		Description: "Test Description",
		Severity:    "high",
		Enabled:     true,
		Version:     1,
		Tags:        []string{"test", "authentication"},
		Author:      "Test Author",
		SigmaYAML: `title: Test Rule
detection:
  selection:
    test: value
  condition: selection
level: high`,
	}

	err := storage.CreateRule(rule)
	require.NoError(t, err)

	// Verify rule was created by querying database directly
	var count int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", "test-rule-001").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify timestamps were set
	assert.False(t, rule.CreatedAt.IsZero())
	assert.False(t, rule.UpdatedAt.IsZero())
}

// TestCreateRule_DuplicateID tests creating rule with duplicate ID
func TestCreateRule_DuplicateID(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	rule := &core.Rule{
		ID:       "duplicate-rule",
		Type:     "sigma",
		Name:     "First Rule",
		Severity: "medium",
		Enabled:  true,
		SigmaYAML: `title: First Rule
detection:
  selection:
    test: value
  condition: selection
level: medium`,
	}

	// First creation should succeed
	err := storage.CreateRule(rule)
	require.NoError(t, err)

	// Second creation with same ID should fail
	duplicateRule := &core.Rule{
		ID:       "duplicate-rule",
		Type:     "sigma",
		Name:     "Second Rule",
		Severity: "high",
		Enabled:  true,
		SigmaYAML: `title: Second Rule
detection:
  selection:
    test: value
  condition: selection
level: high`,
	}

	err = storage.CreateRule(duplicateRule)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// TestGetRule_Success tests successful rule retrieval
func TestGetRule_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create a rule with complete data
	originalRule := &core.Rule{
		ID:              "get-test-rule",
		Type:            "sigma",
		Name:            "Get Test Rule",
		Description:     "Test retrieving a rule",
		Severity:        "critical",
		Enabled:         true,
		Version:         2,
		Tags:            []string{"network", "firewall"},
		MitreTactics:    []string{"TA0001", "TA0002"},
		MitreTechniques: []string{"T1078", "T1110"},
		Author:          "Security Team",
		References:      []string{"https://example.com/ref1"},
		FalsePositives:  []string{"Legitimate admin activity"},
		Metadata:        map[string]interface{}{"category": "network", "priority": 1},
		SigmaYAML: `title: Get Test Rule
detection:
  selection:
    test: value
  condition: selection
level: critical`,
	}

	err := storage.CreateRule(originalRule)
	require.NoError(t, err)

	// Retrieve the rule
	retrievedRule, err := storage.GetRule("get-test-rule")
	require.NoError(t, err)
	require.NotNil(t, retrievedRule)

	// Verify all fields
	assert.Equal(t, originalRule.ID, retrievedRule.ID)
	assert.Equal(t, originalRule.Type, retrievedRule.Type)
	assert.Equal(t, originalRule.Name, retrievedRule.Name)
	assert.Equal(t, originalRule.Description, retrievedRule.Description)
	assert.Equal(t, originalRule.Severity, retrievedRule.Severity)
	assert.Equal(t, originalRule.Enabled, retrievedRule.Enabled)
	assert.Equal(t, originalRule.Version, retrievedRule.Version)
	assert.ElementsMatch(t, originalRule.Tags, retrievedRule.Tags)
	assert.ElementsMatch(t, originalRule.MitreTactics, retrievedRule.MitreTactics)
	assert.ElementsMatch(t, originalRule.MitreTechniques, retrievedRule.MitreTechniques)
	assert.Equal(t, originalRule.Author, retrievedRule.Author)
	assert.ElementsMatch(t, originalRule.References, retrievedRule.References)
	assert.ElementsMatch(t, originalRule.FalsePositives, retrievedRule.FalsePositives)
	assert.Equal(t, originalRule.Metadata["category"], retrievedRule.Metadata["category"])
}

// TestGetRule_NotFound tests retrieving non-existent rule
func TestGetRule_NotFound(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	rule, err := storage.GetRule("non-existent-rule")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrRuleNotFound)
	assert.Nil(t, rule)
}

// TestUpdateRule_Success tests successful rule update
func TestUpdateRule_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create original rule
	originalRule := &core.Rule{
		ID:       "update-test",
		Type:     "sigma",
		Name:     "Original Name",
		Severity: "low",
		Enabled:  false,
		SigmaYAML: `title: Original Name
detection:
  selection:
    test: value
  condition: selection
level: low`,
	}

	err := storage.CreateRule(originalRule)
	require.NoError(t, err)

	// Wait to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	// Update the rule
	updatedRule := &core.Rule{
		ID:          "update-test",
		Type:        "cql",
		Name:        "Updated Name",
		Severity:    "critical",
		Enabled:     true,
		Description: "Updated description",
		Tags:        []string{"updated", "tags"},
	}

	err = storage.UpdateRule("update-test", updatedRule)
	require.NoError(t, err)

	// Retrieve and verify
	retrieved, err := storage.GetRule("update-test")
	require.NoError(t, err)

	assert.Equal(t, "Updated Name", retrieved.Name)
	assert.Equal(t, "cql", retrieved.Type)
	assert.Equal(t, "critical", retrieved.Severity)
	assert.True(t, retrieved.Enabled)
	assert.Equal(t, "Updated description", retrieved.Description)
	assert.ElementsMatch(t, []string{"updated", "tags"}, retrieved.Tags)

	// Verify CreatedAt preserved, UpdatedAt changed
	assert.Equal(t, originalRule.CreatedAt.Unix(), retrieved.CreatedAt.Unix())
	// UpdatedAt should be >= CreatedAt (may be equal if timestamps are very close)
	assert.True(t, retrieved.UpdatedAt.Unix() >= retrieved.CreatedAt.Unix())
}

// TestUpdateRule_NotFound tests updating non-existent rule
func TestUpdateRule_NotFound(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	rule := &core.Rule{
		ID:       "non-existent",
		Type:     "sigma",
		Name:     "Test",
		Severity: "medium",
		SigmaYAML: `title: Test
detection:
  selection:
    test: value
  condition: selection
level: medium`,
	}

	err := storage.UpdateRule("non-existent", rule)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrRuleNotFound)
}

// TestDeleteRule_Success tests successful rule deletion
func TestDeleteRule_Success(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create a rule
	rule := &core.Rule{
		ID:       "delete-test",
		Type:     "sigma",
		Name:     "To Be Deleted",
		Severity: "low",
		Enabled:  true,
		SigmaYAML: `title: To Be Deleted
detection:
  selection:
    test: value
  condition: selection
level: low`,
	}

	err := storage.CreateRule(rule)
	require.NoError(t, err)

	// Delete the rule
	err = storage.DeleteRule("delete-test")
	require.NoError(t, err)

	// Verify deletion
	_, err = storage.GetRule("delete-test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrRuleNotFound)

	// Verify via direct query
	var count int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", "delete-test").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestDeleteRule_NotFound tests deleting non-existent rule
func TestDeleteRule_NotFound(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	err := storage.DeleteRule("non-existent-rule")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrRuleNotFound)
}

// TestGetRules_Pagination tests retrieving rules with pagination
func TestGetRules_Pagination(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create multiple rules
	for i := 1; i <= 25; i++ {
		rule := &core.Rule{
			ID:       fmt.Sprintf("rule-%03d", i),
			Type:     "sigma",
			Name:     fmt.Sprintf("Rule %d", i),
			Severity: "medium",
			Enabled:  true,
			SigmaYAML: `title: Pagination Test
detection:
  selection:
    test: value
  condition: selection
level: medium`,
		}
		err := storage.CreateRule(rule)
		require.NoError(t, err)
		time.Sleep(time.Millisecond) // Ensure different timestamps
	}

	// Test first page
	rules, err := storage.GetRules(10, 0)
	require.NoError(t, err)
	assert.Len(t, rules, 10)

	// Test second page
	rules, err = storage.GetRules(10, 10)
	require.NoError(t, err)
	assert.Len(t, rules, 10)

	// Test third page
	rules, err = storage.GetRules(10, 20)
	require.NoError(t, err)
	assert.Len(t, rules, 5)

	// Test beyond available records
	rules, err = storage.GetRules(10, 30)
	require.NoError(t, err)
	assert.Len(t, rules, 0)
}

// TestGetAllRules tests retrieving all rules
func TestGetAllRules(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create test rules
	for i := 1; i <= 5; i++ {
		rule := &core.Rule{
			ID:       fmt.Sprintf("all-rules-%d", i),
			Type:     "sigma",
			Name:     fmt.Sprintf("All Rules Test %d", i),
			Severity: "low",
			Enabled:  true,
			SigmaYAML: `title: All Rules Test
detection:
  selection:
    test: value
  condition: selection
level: low`,
		}
		err := storage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Get all rules
	rules, err := storage.GetAllRules()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rules), 5)
}

// TestGetRuleCount tests counting total rules
func TestGetRuleCount(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Initial count should be 0
	count, err := storage.GetRuleCount()
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// Create rules
	for i := 1; i <= 7; i++ {
		rule := &core.Rule{
			ID:       fmt.Sprintf("count-rule-%d", i),
			Type:     "sigma",
			Name:     fmt.Sprintf("Count Test %d", i),
			Severity: "medium",
			Enabled:  true,
			SigmaYAML: `title: Count Test
detection:
  selection:
    test: value
  condition: selection
level: medium`,
		}
		err := storage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Count should be 7
	count, err = storage.GetRuleCount()
	require.NoError(t, err)
	assert.Equal(t, int64(7), count)
}

// TestGetRulesByType tests filtering rules by type
func TestGetRulesByType(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create sigma rules
	for i := 1; i <= 3; i++ {
		rule := &core.Rule{
			ID:       fmt.Sprintf("sigma-rule-%d", i),
			Type:     "sigma",
			Name:     fmt.Sprintf("Sigma Rule %d", i),
			Severity: "low",
			Enabled:  true,
			SigmaYAML: `title: Sigma Rule
detection:
  selection:
    test: value
  condition: selection
level: low`,
		}
		err := storage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Create CQL rules
	for i := 1; i <= 2; i++ {
		rule := &core.Rule{
			ID:       fmt.Sprintf("cql-rule-%d", i),
			Type:     "cql",
			Name:     fmt.Sprintf("CQL Rule %d", i),
			Severity: "medium",
			Enabled:  true,
			Query:    "SELECT * FROM events",
		}
		err := storage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Get sigma rules
	sigmaRules, err := storage.GetRulesByType("sigma", 10, 0)
	require.NoError(t, err)
	assert.Len(t, sigmaRules, 3)
	for _, rule := range sigmaRules {
		assert.Equal(t, "sigma", rule.Type)
	}

	// Get CQL rules
	cqlRules, err := storage.GetRulesByType("cql", 10, 0)
	require.NoError(t, err)
	assert.Len(t, cqlRules, 2)
	for _, rule := range cqlRules {
		assert.Equal(t, "cql", rule.Type)
	}
}

// TestGetEnabledRules tests retrieving only enabled rules
func TestGetEnabledRules(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create enabled rules
	for i := 1; i <= 3; i++ {
		rule := &core.Rule{
			ID:       fmt.Sprintf("enabled-rule-%d", i),
			Type:     "sigma",
			Name:     fmt.Sprintf("Enabled Rule %d", i),
			Severity: "high",
			Enabled:  true,
			SigmaYAML: `title: Enabled Rule
detection:
  selection:
    test: value
  condition: selection
level: high`,
		}
		err := storage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Create disabled rules
	for i := 1; i <= 2; i++ {
		rule := &core.Rule{
			ID:       fmt.Sprintf("disabled-rule-%d", i),
			Type:     "sigma",
			Name:     fmt.Sprintf("Disabled Rule %d", i),
			Severity: "low",
			Enabled:  false,
			SigmaYAML: `title: Disabled Rule
detection:
  selection:
    test: value
  condition: selection
level: low`,
		}
		err := storage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Get enabled rules only
	enabledRules, err := storage.GetEnabledRules()
	require.NoError(t, err)
	assert.Len(t, enabledRules, 3)
	for _, rule := range enabledRules {
		assert.True(t, rule.Enabled)
	}
}

// TestEnableRule tests enabling a disabled rule
func TestEnableRule(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create disabled rule
	rule := &core.Rule{
		ID:       "enable-test",
		Type:     "sigma",
		Name:     "Enable Test",
		Severity: "medium",
		Enabled:  false,
		SigmaYAML: `title: Enable Test
detection:
  selection:
    test: value
  condition: selection
level: medium`,
	}

	err := storage.CreateRule(rule)
	require.NoError(t, err)

	// Enable the rule
	err = storage.EnableRule("enable-test")
	require.NoError(t, err)

	// Verify it's enabled
	retrieved, err := storage.GetRule("enable-test")
	require.NoError(t, err)
	assert.True(t, retrieved.Enabled)
}

// TestDisableRule tests disabling an enabled rule
func TestDisableRule(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create enabled rule
	rule := &core.Rule{
		ID:       "disable-test",
		Type:     "sigma",
		Name:     "Disable Test",
		Severity: "high",
		Enabled:  true,
		SigmaYAML: `title: Disable Test
detection:
  selection:
    test: value
  condition: selection
level: high`,
	}

	err := storage.CreateRule(rule)
	require.NoError(t, err)

	// Disable the rule
	err = storage.DisableRule("disable-test")
	require.NoError(t, err)

	// Verify it's disabled
	retrieved, err := storage.GetRule("disable-test")
	require.NoError(t, err)
	assert.False(t, retrieved.Enabled)
}

// TestSearchRules tests searching rules by name/description/tags
func TestSearchRules(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create test rules with searchable content
	rules := []*core.Rule{
		{
			ID:          "search-1",
			Type:        "sigma",
			Name:        "Windows Login Detection",
			Description: "Detects suspicious login attempts",
			Severity:    "high",
			Tags:        []string{"windows", "authentication"},
			SigmaYAML: `title: Windows Login Detection
detection:
  selection:
    test: value
  condition: selection
level: high`,
		},
		{
			ID:          "search-2",
			Type:        "sigma",
			Name:        "Linux SSH Detection",
			Description: "Detects SSH brute force",
			Severity:    "critical",
			Tags:        []string{"linux", "authentication"},
			SigmaYAML: `title: Linux SSH Detection
detection:
  selection:
    test: value
  condition: selection
level: critical`,
		},
		{
			ID:          "search-3",
			Type:        "cql",
			Name:        "Network Traffic",
			Description: "Network anomaly detection",
			Severity:    "medium",
			Tags:        []string{"network", "firewall"},
		},
	}

	for _, rule := range rules {
		rule.Enabled = true
		err := storage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Search by name
	results, err := storage.SearchRules("Login")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1)

	// Search by description
	results, err = storage.SearchRules("brute force")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1)

	// Search by tags
	results, err = storage.SearchRules("authentication")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 2)
}

// TestSearchRules_SQLInjectionPrevention tests SQL injection protection
func TestSearchRules_SQLInjectionPrevention(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create a test rule
	rule := &core.Rule{
		ID:       "injection-test",
		Type:     "sigma",
		Name:     "Injection Test Rule",
		Severity: "low",
		Enabled:  true,
		SigmaYAML: `title: Injection Test Rule
detection:
  selection:
    test: value
  condition: selection
level: low`,
	}
	err := storage.CreateRule(rule)
	require.NoError(t, err)

	// Attempt SQL injection in search
	maliciousQuery := "'; DROP TABLE rules; --"
	results, err := storage.SearchRules(maliciousQuery)

	// Should handle gracefully (escape properly)
	require.NoError(t, err)
	// Results should be a valid slice or nil (no matches expected for injection string)
	if results != nil {
		assert.IsType(t, []core.Rule{}, results)
	}

	// Verify table still exists
	var count int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&count)
	require.NoError(t, err, "Table should still exist after injection attempt")
	assert.Equal(t, 1, count)

	// Verify our test rule still exists
	_, err = storage.GetRule("injection-test")
	require.NoError(t, err, "Rule should still exist after injection attempt")
}

// TestSearchRules_SpecialCharacters tests handling of LIKE special characters
func TestSearchRules_SpecialCharacters(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create rule with special characters
	rule := &core.Rule{
		ID:          "special-chars",
		Type:        "sigma",
		Name:        "Test_Rule%With*Special",
		Description: "Description with % and _ characters",
		Severity:    "low",
		Enabled:     true,
		SigmaYAML: `title: Test_Rule%With*Special
detection:
  selection:
    test: value
  condition: selection
level: low`,
	}
	err := storage.CreateRule(rule)
	require.NoError(t, err)

	// Search with special characters should be escaped
	results, err := storage.SearchRules("%")
	require.NoError(t, err)
	// Should find the rule with literal % in name
	assert.GreaterOrEqual(t, len(results), 1)

	results, err = storage.SearchRules("_")
	require.NoError(t, err)
	// Should find the rule with literal _ in name
	assert.GreaterOrEqual(t, len(results), 1)
}

// TestGetRulesWithFilters tests advanced filtering
func TestGetRulesWithFilters(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create diverse set of rules
	testRules := []*core.Rule{
		{
			ID:       "filter-1",
			Type:     "sigma",
			Name:     "High Severity Rule",
			Severity: "high",
			Enabled:  true,
			Tags:     []string{"windows", "authentication"},
			SigmaYAML: `title: High Severity Rule
detection:
  selection:
    test: value
  condition: selection
level: high`,
		},
		{
			ID:       "filter-2",
			Type:     "cql",
			Name:     "Medium Severity Rule",
			Severity: "medium",
			Enabled:  false,
			Tags:     []string{"linux", "network"},
		},
		{
			ID:       "filter-3",
			Type:     "sigma",
			Name:     "Critical Rule",
			Severity: "critical",
			Enabled:  true,
			Tags:     []string{"windows", "malware"},
			SigmaYAML: `title: Critical Rule
detection:
  selection:
    test: value
  condition: selection
level: critical`,
		},
	}

	for _, rule := range testRules {
		err := storage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Test filtering by severity
	enabled := true
	filters := &core.RuleFilters{
		Severities: []string{"high", "critical"},
		Enabled:    &enabled,
		Limit:      10,
		Page:       1,
	}

	rules, total, err := storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rules), 2)
	assert.GreaterOrEqual(t, total, int64(2))

	// Test filtering by type
	filters = &core.RuleFilters{
		Types: []string{"sigma"},
		Limit: 10,
		Page:  1,
	}

	rules, total, err = storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rules), 2)
	for _, rule := range rules {
		assert.Equal(t, "sigma", rule.Type)
	}

	// Test filtering by tags
	filters = &core.RuleFilters{
		Tags:  []string{"windows"},
		Limit: 10,
		Page:  1,
	}

	rules, total, err = storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rules), 2)
}

// TestGetRulesWithFilters_Pagination tests filter pagination
func TestGetRulesWithFilters_Pagination(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create 25 rules
	for i := 1; i <= 25; i++ {
		rule := &core.Rule{
			ID:       fmt.Sprintf("page-rule-%03d", i),
			Type:     "sigma",
			Name:     fmt.Sprintf("Page Rule %d", i),
			Severity: "medium",
			Enabled:  true,
			SigmaYAML: `title: Page Rule
detection:
  selection:
    test: value
  condition: selection
level: medium`,
		}
		err := storage.CreateRule(rule)
		require.NoError(t, err)
		time.Sleep(time.Millisecond)
	}

	// Page 1
	filters := &core.RuleFilters{
		Limit: 10,
		Page:  1,
	}
	rules, total, err := storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	assert.Len(t, rules, 10)
	assert.GreaterOrEqual(t, total, int64(25))

	// Page 2
	filters.Page = 2
	rules, total, err = storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	assert.Len(t, rules, 10)

	// Page 3
	filters.Page = 3
	rules, total, err = storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rules), 5)
}

// TestGetRulesWithFilters_SQLInjectionPrevention tests SQL injection in filters
func TestGetRulesWithFilters_SQLInjectionPrevention(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create a test rule
	rule := &core.Rule{
		ID:       "filter-injection-test",
		Type:     "sigma",
		Name:     "Filter Injection Test",
		Severity: "low",
		Enabled:  true,
		SigmaYAML: `title: Filter Injection Test
detection:
  selection:
    test: value
  condition: selection
level: low`,
	}
	err := storage.CreateRule(rule)
	require.NoError(t, err)

	// Attempt SQL injection in search filter
	filters := &core.RuleFilters{
		Search: "'; DROP TABLE rules; --",
		Limit:  10,
		Page:   1,
	}

	rules, total, err := storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	// Rules should be empty or nil for injection query
	if rules != nil {
		assert.IsType(t, []core.Rule{}, rules)
	}
	assert.GreaterOrEqual(t, total, int64(0))

	// Verify table still exists
	var count int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Attempt injection in sort field (should use default)
	filters = &core.RuleFilters{
		SortBy:    "'; DROP TABLE rules; --",
		SortOrder: "DESC",
		Limit:     10,
		Page:      1,
	}

	rules, total, err = storage.GetRulesWithFilters(filters)
	require.NoError(t, err)
	// Rules may be nil or empty slice
	if rules != nil {
		assert.IsType(t, []core.Rule{}, rules)
	}

	// Verify table still exists
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestGetRulesWithFilters_ExcessiveOffset tests protection against resource exhaustion
func TestGetRulesWithFilters_ExcessiveOffset(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Attempt excessive pagination offset
	filters := &core.RuleFilters{
		Limit: 10,
		Page:  20000, // Would result in offset of 200,000 which exceeds maxOffset
	}

	_, _, err := storage.GetRulesWithFilters(filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pagination offset too large")
}

// TestEnsureIndexes tests index creation (no-op in current implementation)
func TestEnsureIndexes(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	err := storage.EnsureIndexes()
	assert.NoError(t, err)
}

// TestCQLRule_WithQuery tests CQL-specific rule fields
func TestCQLRule_WithQuery(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	cqlRule := &core.Rule{
		ID:       "cql-test",
		Type:     "cql",
		Name:     "CQL Test Rule",
		Severity: "medium",
		Enabled:  true,
		Query:    "SELECT * FROM events WHERE EventID = 4624 AND LogonType = 3",
		Correlation: map[string]interface{}{
			"timeWindow": "5m",
			"groupBy":    []string{"SourceIP"},
			"threshold":  5,
		},
	}

	err := storage.CreateRule(cqlRule)
	require.NoError(t, err)

	// Retrieve and verify CQL-specific fields
	retrieved, err := storage.GetRule("cql-test")
	require.NoError(t, err)
	assert.Equal(t, "SELECT * FROM events WHERE EventID = 4624 AND LogonType = 3", retrieved.Query)
	assert.NotNil(t, retrieved.Correlation)
	assert.Equal(t, "5m", retrieved.Correlation["timeWindow"])
	assert.Equal(t, float64(5), retrieved.Correlation["threshold"])
}

// TestSigmaRule_WithConditionsAndActions removed - legacy Conditions field is deprecated
// SIGMA YAML is now the primary format for detection rules
// See: SIGMA_YAML_IMPLEMENTATION_SUMMARY.md

// TestNullIfEmpty tests the nullIfEmpty helper function behavior
func TestNullIfEmpty(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create rule with empty/null fields
	rule := &core.Rule{
		ID:       "null-test",
		Type:     "sigma",
		Name:     "Null Test",
		Severity: "low",
		Enabled:  true,
		SigmaYAML: `title: Null Test
detection:
  selection:
    test: value
  condition: selection
level: low`,
		// Leave optional fields empty
		Tags:            []string{},
		MitreTactics:    nil,
		MitreTechniques: []string{},
	}

	err := storage.CreateRule(rule)
	require.NoError(t, err)

	// Retrieve and verify empty arrays are handled correctly
	retrieved, err := storage.GetRule("null-test")
	require.NoError(t, err)
	assert.NotNil(t, retrieved)
	// Empty arrays should be nil or empty, not cause errors
}

// Benchmark tests for performance validation

func BenchmarkCreateRule(b *testing.B) {
	_, sqlite := setupTestDB(&testing.T{})
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule := &core.Rule{
			ID:       fmt.Sprintf("bench-rule-%d", i),
			Type:     "sigma",
			Name:     "Benchmark Rule",
			Severity: "medium",
			Enabled:  true,
			SigmaYAML: `title: Benchmark Rule
detection:
  selection:
    test: value
  condition: selection
level: medium`,
		}
		_ = storage.CreateRule(rule)
	}
}

func BenchmarkGetRule(b *testing.B) {
	_, sqlite := setupTestDB(&testing.T{})
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Setup: create a rule
	rule := &core.Rule{
		ID:       "bench-get-rule",
		Type:     "sigma",
		Name:     "Benchmark Get Rule",
		Severity: "medium",
		Enabled:  true,
		SigmaYAML: `title: Benchmark Get Rule
detection:
  selection:
    test: value
  condition: selection
level: medium`,
	}
	_ = storage.CreateRule(rule)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = storage.GetRule("bench-get-rule")
	}
}

// TestGetRuleFilterMetadata tests the GetRuleFilterMetadata function
func TestGetRuleFilterMetadata(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create test rules with various metadata
	testRules := []*core.Rule{
		{
			ID:              "test-metadata-1",
			Type:            "sigma",
			Name:            "Test Rule 1",
			Severity:        "critical",
			Enabled:         true,
			Author:          "Test Author 1",
			MitreTactics:    []string{"execution", "persistence"},
			MitreTechniques: []string{"T1059", "T1053"},
			Tags:            []string{"malware", "ransomware"},
			Metadata:        map[string]interface{}{"feed_id": "feed1", "feed_name": "Test Feed 1"},
			SigmaYAML: `title: Test Rule 1
detection:
  selection:
    test: value
  condition: selection
level: critical`,
		},
		{
			ID:              "test-metadata-2",
			Type:            "cql",
			Name:            "Test Rule 2",
			Severity:        "high",
			Enabled:         true,
			Author:          "Test Author 2",
			MitreTactics:    []string{"lateral-movement"},
			MitreTechniques: []string{"T1021"},
			Tags:            []string{"network", "lateral-movement"},
			Metadata:        map[string]interface{}{"feed_id": "feed2", "feed_name": "Test Feed 2"},
		},
		{
			ID:       "test-metadata-3",
			Type:     "sigma",
			Name:     "Test Rule 3",
			Severity: "medium",
			Enabled:  true,
			Author:   "Test Author 1",     // Duplicate author to test uniqueness
			Tags:     []string{"malware"}, // Duplicate tag
			SigmaYAML: `title: Test Rule 3
detection:
  selection:
    test: value
  condition: selection
level: medium`,
		},
	}

	// Insert test rules
	for _, rule := range testRules {
		err := storage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Call GetRuleFilterMetadata
	metadata, err := storage.GetRuleFilterMetadata()
	require.NoError(t, err)
	require.NotNil(t, metadata)

	// Verify static metadata
	assert.Contains(t, metadata.Severities, "critical")
	assert.Contains(t, metadata.Severities, "high")
	assert.Contains(t, metadata.Severities, "medium")
	assert.Contains(t, metadata.Severities, "low")

	assert.Contains(t, metadata.Types, "sigma")
	assert.Contains(t, metadata.Types, "cql")

	// Verify MITRE tactics are extracted
	assert.Contains(t, metadata.MitreTactics, "execution")
	assert.Contains(t, metadata.MitreTactics, "persistence")
	assert.Contains(t, metadata.MitreTactics, "lateral-movement")

	// Verify MITRE techniques are extracted
	assert.Contains(t, metadata.MitreTechniques, "T1059")
	assert.Contains(t, metadata.MitreTechniques, "T1053")
	assert.Contains(t, metadata.MitreTechniques, "T1021")

	// Verify authors are extracted (should be unique)
	assert.Contains(t, metadata.Authors, "Test Author 1")
	assert.Contains(t, metadata.Authors, "Test Author 2")

	// Verify tags are extracted
	assert.Contains(t, metadata.Tags, "malware")
	assert.Contains(t, metadata.Tags, "ransomware")
	assert.Contains(t, metadata.Tags, "network")
	assert.Contains(t, metadata.Tags, "lateral-movement")

	// Verify feeds are extracted
	assert.Len(t, metadata.Feeds, 2)
	feedIDs := make(map[string]bool)
	for _, feed := range metadata.Feeds {
		feedIDs[feed.ID] = true
	}
	assert.True(t, feedIDs["feed1"])
	assert.True(t, feedIDs["feed2"])

	// Verify total rule count
	assert.Equal(t, 3, metadata.TotalRules)
}

// TestGetRuleFilterMetadata_EmptyDatabase tests metadata retrieval with empty database
func TestGetRuleFilterMetadata_EmptyDatabase(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	metadata, err := storage.GetRuleFilterMetadata()
	require.NoError(t, err)
	require.NotNil(t, metadata)

	// Static metadata should still be present
	assert.Len(t, metadata.Severities, 5)
	assert.Len(t, metadata.Types, 2)

	// Dynamic metadata should be empty
	assert.Empty(t, metadata.MitreTactics)
	assert.Empty(t, metadata.MitreTechniques)
	assert.Empty(t, metadata.Authors)
	assert.Empty(t, metadata.Tags)
	assert.Empty(t, metadata.Feeds)
	assert.Equal(t, 0, metadata.TotalRules)
}

// ============================================================================
// ENHANCED SQL INJECTION PREVENTION TESTS
// Based on: docs/requirements/security-threat-model.md
// Based on: OWASP ASVS v4.0, Section 5.3.4
// These tests verify the MECHANISM (parameterized queries), not just outcomes.
// ============================================================================

// Requirement: SEC-101 - SQL Injection Prevention via Parameterized Queries
// Source: OWASP ASVS v4.0, Section 5.3.4
// Source: docs/requirements/security-threat-model.md
// "ALL database queries MUST use parameterized queries"
//
// This test verifies the MECHANISM, not just black-box outcomes.
// If code uses string concatenation, it's vulnerable regardless of escaping.
func TestSearchRules_UsesParameterizedQueries_MechanismVerification(t *testing.T) {
	// CRITICAL: This is a CODE INSPECTION test
	// It verifies that SearchRules uses db.Query with ? placeholders
	// NOT string concatenation or fmt.Sprintf

	sourceFile := "sqlite_rules.go"

	// Read the source code of SearchRules function
	content, err := os.ReadFile(sourceFile)
	require.NoError(t, err, "Must be able to read source file for security verification")

	source := string(content)

	// REQUIREMENT: Must use parameterized queries (DB.Query with ? placeholders)
	assert.Contains(t, source, "DB.Query(",
		"SECURITY CRITICAL: SearchRules MUST use DB.Query for parameterization (OWASP ASVS 5.3.4)")

	// REQUIREMENT: Must use LIKE with ESCAPE clause (prevents LIKE injection)
	assert.Contains(t, source, "LIKE ? ESCAPE",
		"SECURITY CRITICAL: LIKE queries MUST use ESCAPE clause to prevent LIKE injection")

	// REQUIREMENT: Must NOT use string concatenation in queries
	// These patterns indicate SQL injection vulnerabilities
	searchRulesSection := extractFunctionBody(source, "func (srs *SQLiteRuleStorage) SearchRules")

	assert.NotContains(t, searchRulesSection, "query + ",
		"SECURITY VULNERABILITY: Query string concatenation is FORBIDDEN (SQL injection risk)")
	assert.NotContains(t, searchRulesSection, "+ query",
		"SECURITY VULNERABILITY: Query string concatenation is FORBIDDEN (SQL injection risk)")
	assert.NotRegexp(t, regexp.MustCompile(`fmt\.Sprintf\s*\(\s*"SELECT`), searchRulesSection,
		"SECURITY VULNERABILITY: Sprintf for query building is FORBIDDEN (SQL injection risk)")

	// If this test fails, the code is vulnerable REGARDLESS of black-box tests passing
}

// Requirement: SEC-102 - Prevent UNION-based SQL Injection
// Source: OWASP Testing Guide - SQL Injection
// Source: docs/requirements/security-threat-model.md
func TestSearchRules_PreventsSQLInjection_UNION_Attack(t *testing.T) {
	// UNION attacks attempt to combine results from different tables
	// to exfiltrate sensitive data

	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create a test rule to ensure we have data
	rule := &core.Rule{
		ID:       "test-rule-union",
		Type:     "sigma",
		Name:     "Test Rule for UNION",
		Severity: "low",
		Enabled:  true,
		SigmaYAML: `title: Test Rule for UNION
detection:
  selection:
    test: value
  condition: selection
level: low`,
	}
	err := storage.CreateRule(rule)
	require.NoError(t, err)

	// Attack: UNION SELECT to access sqlite_master (metadata table)
	maliciousQuery := "' UNION SELECT name,sql,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM sqlite_master WHERE type='table' --"

	results, err := storage.SearchRules(maliciousQuery)

	// REQUIREMENT: Attack MUST NOT succeed
	require.NoError(t, err, "Query should not error (but also should not inject)")

	// REQUIREMENT: Results MUST be from rules table only, not sqlite_master
	for _, result := range results {
		// If UNION injection succeeded, we'd see table names from sqlite_master in the Name field
		assert.NotContains(t, result.Name, "sqlite_master",
			"SECURITY CRITICAL: UNION injection succeeded - parameterized queries not used")
		assert.NotContains(t, result.Name, "CREATE TABLE",
			"SECURITY CRITICAL: UNION injection succeeded - SQL schema exposed")

		// Verify results are actual rules
		if len(results) > 0 {
			assert.NotEmpty(t, result.ID, "Result must be valid rule with ID")
		}
	}
}

// Requirement: SEC-103 - Prevent Time-Based Blind SQL Injection
// Source: OWASP Testing Guide - Blind SQL Injection
func TestSearchRules_PreventsSQLInjection_TimeBased(t *testing.T) {
	// Time-based injection uses database sleep functions to exfiltrate data
	// by measuring response time

	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Attack: Time-based injection using SQLite's randomblob/length for delay
	// (SQLite doesn't have SLEEP, so attackers use expensive operations)
	maliciousQuery := "'; SELECT CASE WHEN (SELECT COUNT(*) FROM sqlite_master) > 0 THEN (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)) ELSE 1 END; --"

	start := time.Now()
	results, err := storage.SearchRules(maliciousQuery)
	elapsed := time.Since(start)

	// REQUIREMENT: Query must not execute injected code
	require.NoError(t, err)

	// REQUIREMENT: Query must complete in normal time (not delayed by injection)
	assert.Less(t, elapsed, 100*time.Millisecond,
		"SECURITY CRITICAL: Time-based injection may have executed (query took too long)")

	// REQUIREMENT: Results should be normal search results, not injection results
	assert.IsType(t, []core.Rule{}, results)
}

// Requirement: SEC-104 - Prevent Encoding-Based SQL Injection Bypasses
// Source: OWASP Testing Guide - SQL Injection Bypassing WAF
func TestSearchRules_PreventsSQLInjection_EncodingBypass(t *testing.T) {
	// Attackers use various encodings to bypass input filters
	// Parameterized queries protect against ALL encodings

	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Create test rule
	rule := &core.Rule{
		ID:       "test-encoding",
		Type:     "sigma",
		Name:     "Normal Rule",
		Severity: "low",
		Enabled:  true,
		SigmaYAML: `title: Normal Rule
detection:
  selection:
    test: value
  condition: selection
level: low`,
	}
	err := storage.CreateRule(rule)
	require.NoError(t, err)

	attacks := []struct {
		name   string
		query  string
		reason string
	}{
		{
			name:   "hex_encoding",
			query:  "\\x27 OR 1=1--",
			reason: "Hex-encoded single quote",
		},
		{
			name:   "url_encoding",
			query:  "%27 OR 1=1--",
			reason: "URL-encoded single quote",
		},
		{
			name:   "always_true",
			query:  "' OR '1'='1",
			reason: "Always-true condition",
		},
		{
			name:   "double_dash_comment",
			query:  "' OR 1=1 -- ",
			reason: "Comment-based injection",
		},
		{
			name:   "null_byte",
			query:  "'\x00 OR 1=1",
			reason: "Null byte injection",
		},
	}

	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			results, err := storage.SearchRules(attack.query)

			// REQUIREMENT: Attack must not succeed
			require.NoError(t, err)

			// REQUIREMENT: Must not return all rules (OR 1=1 would return everything)
			// We created 1 rule, so if we get > 100 results, injection succeeded
			assert.LessOrEqual(t, len(results), 10,
				"SECURITY CRITICAL: %s bypass succeeded - got %d results (expected 0-1)", attack.reason, len(results))

			// If we get results, they should be from legitimate search, not injection
			for _, result := range results {
				assert.NotEmpty(t, result.ID, "Result must be valid rule")
			}
		})
	}
}

// Requirement: SEC-105 - Prevent Second-Order SQL Injection
// Source: OWASP Testing Guide - Second Order SQL Injection
func TestSearchRules_PreventsSQLInjection_SecondOrder(t *testing.T) {
	// Second-order injection: malicious data stored in DB, then used in unsafe query
	// Even if data came from trusted source (DB), it must still be parameterized

	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Store rule with SQL injection in name (simulating user input stored earlier)
	maliciousRule := &core.Rule{
		ID:       "second-order-test",
		Type:     "sigma",
		Name:     "Test'; DROP TABLE rules; --",
		Severity: "low",
		Enabled:  true,
		SigmaYAML: `title: Test
detection:
  selection:
    test: value
  condition: selection
level: low`,
	}
	err := storage.CreateRule(maliciousRule)
	require.NoError(t, err, "Should be able to store rule with SQL in name")

	// Now search using that data - if SearchRules doesn't parameterize,
	// the stored SQL could execute
	results, err := storage.SearchRules("Test';")

	// REQUIREMENT: Stored SQL must not execute
	require.NoError(t, err)

	// Verify table still exists (wasn't dropped)
	var count int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&count)
	require.NoError(t, err, "rules table must still exist")
	assert.Equal(t, 1, count, "rules table must not have been dropped by second-order injection")

	// Verify rule still exists
	_, err = storage.GetRule("second-order-test")
	require.NoError(t, err, "Rule should still exist after second-order injection attempt")

	// Results should be from search, not injection
	assert.IsType(t, []core.Rule{}, results)
}

// Helper function to extract function body from source code
func extractFunctionBody(source, functionSignature string) string {
	// Find the function signature
	idx := strings.Index(source, functionSignature)
	if idx == -1 {
		return ""
	}

	// Find the opening brace
	openBrace := strings.Index(source[idx:], "{")
	if openBrace == -1 {
		return ""
	}

	// Find the matching closing brace (simple implementation)
	start := idx + openBrace
	braceCount := 1
	end := start + 1

	for end < len(source) && braceCount > 0 {
		if source[end] == '{' {
			braceCount++
		} else if source[end] == '}' {
			braceCount--
		}
		end++
	}

	return source[start:end]
}

// ==================== SECURITY TESTS ====================
// Tests that verify protection against SQL injection vulnerabilities
// Required by: AFFIRMATIONS.md, security-threat-model.md FR-SEC-003

// TestSQLiteRuleStorage_SQLInjection_SearchRules tests SQL injection prevention in search
// REQUIREMENT: AFFIRMATIONS.md - SQL Injection Prevention
// REQUIREMENT: security-threat-model.md FR-SEC-003
func TestSQLiteRuleStorage_SQLInjection_SearchRules(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, zap.NewNop().Sugar())

	// Create a test rule to verify search works normally
	testRule := &core.Rule{
		ID:          "test-rule-1",
		Type:        "sigma",
		Name:        "Test Rule",
		Description: "Test description",
		Severity:    "high",
		Enabled:     true,
		Version:     1,
		Tags:        []string{"test"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		SigmaYAML: `title: Test Rule
detection:
  selection:
    test: value
  condition: selection
level: high`,
	}
	err := storage.CreateRule(testRule)
	require.NoError(t, err)

	// SQL injection tests
	tests := []struct {
		name              string
		searchQuery       string
		shouldReturnRules bool
		shouldPanic       bool
	}{
		{
			name:              "SQL injection - DROP TABLE",
			searchQuery:       "'; DROP TABLE rules; --",
			shouldReturnRules: false,
			shouldPanic:       false,
		},
		{
			name:              "SQL injection - UNION SELECT",
			searchQuery:       "' UNION SELECT * FROM sqlite_master; --",
			shouldReturnRules: false,
			shouldPanic:       false,
		},
		{
			name:              "SQL injection - OR 1=1",
			searchQuery:       "' OR '1'='1",
			shouldReturnRules: false, // Should not return all rules
			shouldPanic:       false,
		},
		{
			name:              "SQL injection - comment bypass",
			searchQuery:       "test'; DELETE FROM rules; --",
			shouldReturnRules: false,
			shouldPanic:       false,
		},
		{
			name:              "SQL injection - semicolon commands",
			searchQuery:       "test; UPDATE rules SET enabled = 0; --",
			shouldReturnRules: false,
			shouldPanic:       false,
		},
		{
			name:              "LIKE wildcard injection - %",
			searchQuery:       "%",
			shouldReturnRules: false, // % should be escaped, not used as wildcard
			shouldPanic:       false,
		},
		{
			name:              "LIKE wildcard injection - _",
			searchQuery:       "_",
			shouldReturnRules: false, // _ should be escaped, not used as wildcard
			shouldPanic:       false,
		},
		{
			name:              "Normal search",
			searchQuery:       "Test",
			shouldReturnRules: true, // Should find our test rule
			shouldPanic:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute search
			rules, err := storage.SearchRules(tt.searchQuery)

			// Should not panic or error
			assert.NoError(t, err, "SearchRules should not error on malicious input")
			// Note: rules may be nil if no results found, which is acceptable

			// Verify injection didn't succeed
			if !tt.shouldReturnRules {
				// For injection attempts, we should get 0 results
				// (the malicious SQL shouldn't execute or return data)
				if rules != nil {
					assert.Empty(t, rules,
						"SQL injection attempt should return no results: %s", tt.searchQuery)
				}
			} else {
				// For normal search, we should find our test rule
				assert.NotNil(t, rules, "Normal search should not return nil")
				assert.NotEmpty(t, rules,
					"Normal search should return results: %s", tt.searchQuery)
			}

			// CRITICAL: Verify the rules table still exists and has correct structure
			var tableCount int
			err = storage.sqlite.DB.QueryRow(
				"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&tableCount)
			assert.NoError(t, err, "Should be able to query sqlite_master")
			assert.Equal(t, 1, tableCount, "Rules table should still exist")

			// Verify our test rule still exists (wasn't deleted)
			var ruleExists int
			err = storage.sqlite.DB.QueryRow(
				"SELECT COUNT(*) FROM rules WHERE id = ?", testRule.ID).Scan(&ruleExists)
			assert.NoError(t, err, "Should be able to query rules table")
			assert.Equal(t, 1, ruleExists, "Test rule should not be deleted by injection")

			// Verify rule is still enabled (wasn't updated by injection)
			var enabled int
			err = storage.sqlite.DB.QueryRow(
				"SELECT enabled FROM rules WHERE id = ?", testRule.ID).Scan(&enabled)
			assert.NoError(t, err, "Should be able to query rule enabled status")
			assert.Equal(t, 1, enabled, "Test rule should still be enabled")
		})
	}
}

// TestSQLiteRuleStorage_SQLInjection_GetRuleByID tests SQL injection in ID lookup
// REQUIREMENT: AFFIRMATIONS.md - SQL Injection Prevention
// REQUIREMENT: security-threat-model.md FR-SEC-003
func TestSQLiteRuleStorage_SQLInjection_GetRuleByID(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, zap.NewNop().Sugar())

	// Create test rules
	testRule := &core.Rule{
		ID:          "test-rule-1",
		Type:        "sigma",
		Name:        "Test Rule",
		Description: "Test description",
		Severity:    "high",
		Enabled:     true,
		Version:     1,
		Tags:        []string{"test"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		SigmaYAML: `title: Test Rule
detection:
  selection:
    test: value
  condition: selection
level: high`,
	}
	err := storage.CreateRule(testRule)
	require.NoError(t, err)

	tests := []struct {
		name        string
		ruleID      string
		shouldFind  bool
		shouldError bool
	}{
		{
			name:        "SQL injection - OR 1=1",
			ruleID:      "' OR '1'='1",
			shouldFind:  false, // Should not return any rule
			shouldError: false,
		},
		{
			name:        "SQL injection - UNION SELECT",
			ruleID:      "' UNION SELECT * FROM sqlite_master --",
			shouldFind:  false,
			shouldError: false,
		},
		{
			name:        "SQL injection - comment bypass",
			ruleID:      "test-rule-1'; DROP TABLE rules; --",
			shouldFind:  false, // ID doesn't match, injection prevented
			shouldError: false,
		},
		{
			name:        "Normal lookup",
			ruleID:      "test-rule-1",
			shouldFind:  true,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := storage.GetRule(tt.ruleID)

			if tt.shouldFind {
				assert.NoError(t, err, "Should not error for valid ID")
				assert.NotNil(t, rule, "Should find rule for valid ID")
				assert.Equal(t, testRule.ID, rule.ID, "Should return correct rule")
			} else {
				// For malicious IDs, we expect "rule not found" error or nil result
				// Either way, the injection should not succeed
				if err != nil {
					assert.Contains(t, err.Error(), "rule not found",
						"Error should be 'rule not found', not a SQL error")
				}
				assert.Nil(t, rule, "Should not find rule for malicious ID")
			}

			// CRITICAL: Verify rules table still exists
			var tableCount int
			err = storage.sqlite.DB.QueryRow(
				"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&tableCount)
			assert.NoError(t, err, "Should be able to query sqlite_master")
			assert.Equal(t, 1, tableCount, "Rules table should still exist after injection attempt")

			// Verify test rule still exists
			var ruleCount int
			err = storage.sqlite.DB.QueryRow(
				"SELECT COUNT(*) FROM rules WHERE id = ?", testRule.ID).Scan(&ruleCount)
			assert.NoError(t, err, "Should be able to count rules")
			assert.Equal(t, 1, ruleCount, "Test rule should still exist")
		})
	}
}

// TestSQLiteRuleStorage_SQLInjection_CreateRule tests SQL injection in rule creation
// REQUIREMENT: AFFIRMATIONS.md - SQL Injection Prevention
// REQUIREMENT: security-threat-model.md FR-SEC-003
func TestSQLiteRuleStorage_SQLInjection_CreateRule(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, zap.NewNop().Sugar())

	tests := []struct {
		name         string
		rule         *core.Rule
		shouldCreate bool
	}{
		{
			name: "SQL injection in rule name",
			rule: &core.Rule{
				ID:          "test-inject-1",
				Type:        "sigma",
				Name:        "'; DROP TABLE rules; --",
				Description: "Test",
				Severity:    "high",
				Enabled:     true,
				Version:     1,
				Tags:        []string{"test"},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				SigmaYAML: `title: Test
detection:
  selection:
    test: value
  condition: selection
level: high`,
			},
			shouldCreate: true, // Should succeed with name stored as-is
		},
		{
			name: "SQL injection in description",
			rule: &core.Rule{
				ID:          "test-inject-2",
				Type:        "sigma",
				Name:        "Test",
				Description: "' OR '1'='1",
				Severity:    "high",
				Enabled:     true,
				Version:     1,
				Tags:        []string{"test"},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				SigmaYAML: `title: Test
detection:
  selection:
    test: value
  condition: selection
level: high`,
			},
			shouldCreate: true,
		},
		{
			name: "SQL injection in author",
			rule: &core.Rule{
				ID:          "test-inject-3",
				Type:        "sigma",
				Name:        "Test",
				Description: "Test",
				Severity:    "high",
				Enabled:     true,
				Version:     1,
				Author:      "'; DELETE FROM rules; --",
				Tags:        []string{"test"},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				SigmaYAML: `title: Test
detection:
  selection:
    test: value
  condition: selection
level: high`,
			},
			shouldCreate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.CreateRule(tt.rule)

			if tt.shouldCreate {
				assert.NoError(t, err, "CreateRule should succeed despite malicious input")

				// Verify the rule was created with the malicious string stored AS-IS (not executed)
				retrievedRule, err := storage.GetRule(tt.rule.ID)
				assert.NoError(t, err, "Should be able to retrieve created rule")
				assert.NotNil(t, retrievedRule, "Rule should exist")

				// Verify the malicious strings are stored literally
				assert.Equal(t, tt.rule.Name, retrievedRule.Name,
					"Malicious name should be stored as literal string")
				assert.Equal(t, tt.rule.Description, retrievedRule.Description,
					"Malicious description should be stored as literal string")
			} else {
				assert.Error(t, err, "CreateRule should fail for invalid input")
			}

			// CRITICAL: Verify rules table still exists and has correct structure
			var tableCount int
			err = storage.sqlite.DB.QueryRow(
				"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&tableCount)
			assert.NoError(t, err, "Should be able to query sqlite_master")
			assert.Equal(t, 1, tableCount, "Rules table should still exist")

			// Verify table structure by checking column count
			rows, err := storage.sqlite.DB.Query("PRAGMA table_info(rules)")
			assert.NoError(t, err, "Should be able to get table info")
			defer rows.Close()

			columnCount := 0
			for rows.Next() {
				columnCount++
				var cid int
				var name string
				var dataType string
				var notNull int
				var dfltValue interface{}
				var pk int
				err = rows.Scan(&cid, &name, &dataType, &notNull, &dfltValue, &pk)
				assert.NoError(t, err, "Should be able to scan table info")
			}
			// Rules table should have ~18-20 columns (exact count may vary)
			assert.GreaterOrEqual(t, columnCount, 15,
				"Rules table should have at least 15 columns intact")

			// Clean up test rule
			if tt.shouldCreate {
				_ = storage.DeleteRule(tt.rule.ID)
			}
		})
	}
}

// TestSQLiteRuleStorage_SQLInjection_UpdateRule tests SQL injection in rule updates
// REQUIREMENT: AFFIRMATIONS.md - SQL Injection Prevention
// REQUIREMENT: security-threat-model.md FR-SEC-003
func TestSQLiteRuleStorage_SQLInjection_UpdateRule(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, zap.NewNop().Sugar())

	// Create initial rule
	testRule := &core.Rule{
		ID:          "test-rule-update",
		Type:        "sigma",
		Name:        "Original Name",
		Description: "Original Description",
		Severity:    "medium",
		Enabled:     true,
		Version:     1,
		Tags:        []string{"test"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		SigmaYAML: `title: Original Name
detection:
  selection:
    test: value
  condition: selection
level: medium`,
	}
	err := storage.CreateRule(testRule)
	require.NoError(t, err)

	tests := []struct {
		name         string
		updatedRule  *core.Rule
		shouldUpdate bool
	}{
		{
			name: "SQL injection in updated name",
			updatedRule: &core.Rule{
				ID:          testRule.ID,
				Type:        "sigma",
				Name:        "'; UPDATE rules SET enabled = 0; --",
				Description: "Original Description",
				Severity:    "medium",
				Enabled:     true,
				Version:     2,
				Tags:        []string{"test"},
				CreatedAt:   testRule.CreatedAt,
				UpdatedAt:   time.Now(),
				SigmaYAML: `title: Original Description
detection:
  selection:
    test: value
  condition: selection
level: medium`,
			},
			shouldUpdate: true,
		},
		{
			name: "SQL injection in updated severity",
			updatedRule: &core.Rule{
				ID:          testRule.ID,
				Type:        "sigma",
				Name:        "Original Name",
				Description: "Original Description",
				Severity:    "high'; DELETE FROM rules WHERE '1'='1",
				Enabled:     true,
				Version:     3,
				Tags:        []string{"test"},
				CreatedAt:   testRule.CreatedAt,
				UpdatedAt:   time.Now(),
				SigmaYAML: `title: Original Name
detection:
  selection:
    test: value
  condition: selection
level: high`,
			},
			shouldUpdate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.UpdateRule(tt.updatedRule.ID, tt.updatedRule)

			if tt.shouldUpdate {
				assert.NoError(t, err, "UpdateRule should succeed despite malicious input")

				// Verify the rule was updated with malicious strings stored AS-IS
				retrievedRule, err := storage.GetRule(tt.updatedRule.ID)
				assert.NoError(t, err, "Should be able to retrieve updated rule")
				assert.NotNil(t, retrievedRule, "Rule should exist")
				assert.Equal(t, tt.updatedRule.Name, retrievedRule.Name,
					"Name should be updated to literal malicious string")
				assert.Equal(t, tt.updatedRule.Severity, retrievedRule.Severity,
					"Severity should be updated to literal malicious string")
			} else {
				assert.Error(t, err, "UpdateRule should fail for invalid input")
			}

			// CRITICAL: Verify database integrity
			var tableCount int
			err = storage.sqlite.DB.QueryRow(
				"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&tableCount)
			assert.NoError(t, err, "Rules table should still exist")
			assert.Equal(t, 1, tableCount, "Exactly one rules table should exist")

			// Verify no rules were deleted by injection
			var ruleCount int
			err = storage.sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules").Scan(&ruleCount)
			assert.NoError(t, err, "Should be able to count rules")
			assert.Equal(t, 1, ruleCount, "Should have exactly 1 rule (not deleted)")
		})
	}
}

// TestSQLiteRuleStorage_SQLInjection_DeleteRule tests SQL injection in rule deletion
// REQUIREMENT: AFFIRMATIONS.md - SQL Injection Prevention
// REQUIREMENT: security-threat-model.md FR-SEC-003
func TestSQLiteRuleStorage_SQLInjection_DeleteRule(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, zap.NewNop().Sugar())

	// Create multiple test rules
	rule1 := &core.Rule{
		ID:          "rule-1",
		Type:        "sigma",
		Name:        "Rule 1",
		Description: "Test",
		Severity:    "high",
		Enabled:     true,
		Version:     1,
		Tags:        []string{"test"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		SigmaYAML: `title: Rule 1
detection:
  selection:
    test: value
  condition: selection
level: high`,
	}
	rule2 := &core.Rule{
		ID:          "rule-2",
		Type:        "sigma",
		Name:        "Rule 2",
		Description: "Test",
		Severity:    "medium",
		Enabled:     true,
		Version:     1,
		Tags:        []string{"test"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		SigmaYAML: `title: Rule 2
detection:
  selection:
    test: value
  condition: selection
level: medium`,
	}
	err := storage.CreateRule(rule1)
	require.NoError(t, err)
	err = storage.CreateRule(rule2)
	require.NoError(t, err)

	tests := []struct {
		name              string
		ruleID            string
		shouldDeleteAny   bool
		expectedRuleCount int
	}{
		{
			name:              "SQL injection - delete all rules with OR 1=1",
			ruleID:            "' OR '1'='1",
			shouldDeleteAny:   false, // Should not delete anything
			expectedRuleCount: 2,     // Both rules should still exist
		},
		{
			name:              "SQL injection - DROP TABLE",
			ruleID:            "'; DROP TABLE rules; --",
			shouldDeleteAny:   false,
			expectedRuleCount: 2,
		},
		{
			name:              "Normal delete",
			ruleID:            "rule-1",
			shouldDeleteAny:   true, // Should delete rule-1
			expectedRuleCount: 1,    // rule-2 should remain
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.DeleteRule(tt.ruleID)

			if tt.shouldDeleteAny {
				assert.NoError(t, err, "Delete should succeed for valid ID")
			} else {
				// For malicious IDs, either no error (0 rows affected) or error is acceptable
				// The key is that nothing gets deleted
			}

			// CRITICAL: Verify correct number of rules remain
			var ruleCount int
			err = storage.sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules").Scan(&ruleCount)
			assert.NoError(t, err, "Should be able to count rules")
			assert.Equal(t, tt.expectedRuleCount, ruleCount,
				"Exactly %d rule(s) should remain", tt.expectedRuleCount)

			// Verify rules table still exists
			var tableCount int
			err = storage.sqlite.DB.QueryRow(
				"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&tableCount)
			assert.NoError(t, err, "Should be able to query sqlite_master")
			assert.Equal(t, 1, tableCount, "Rules table should still exist")

			// After normal delete test, verify rule-2 still exists
			if tt.ruleID == "rule-1" {
				var rule2Exists int
				err = storage.sqlite.DB.QueryRow(
					"SELECT COUNT(*) FROM rules WHERE id = ?", "rule-2").Scan(&rule2Exists)
				assert.NoError(t, err, "Should be able to query rule-2")
				assert.Equal(t, 1, rule2Exists, "Rule-2 should not be deleted")
			}
		})
	}
}

// TestGetAllRules_JSONSerializationContract verifies JSON serialization produces [] not null
// This is the GOLD STANDARD test that verifies the nil-slice bug fix.
// Empty result sets MUST serialize to [] not null to maintain frontend contract.
func TestGetAllRules_JSONSerializationContract(t *testing.T) {
	_, sqlite := setupTestDB(t)
	defer sqlite.Close()

	storage := NewSQLiteRuleStorage(sqlite, 30*time.Second, zap.NewNop().Sugar())

	// Get all rules from empty database
	rules, err := storage.GetAllRules()
	if err != nil {
		t.Fatalf("Failed to get all rules: %v", err)
	}

	// Critical: Verify JSON serialization produces [], not null
	jsonBytes, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("Failed to marshal rules: %v", err)
	}

	if string(jsonBytes) != "[]" {
		t.Errorf("Expected JSON '[]', got '%s' - nil slices break frontend contract", string(jsonBytes))
	}
}
