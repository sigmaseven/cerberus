package storage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"cerberus/core"
	"go.uber.org/zap"
)

func setupCorrelationRuleTestDB(t *testing.T) *SQLiteCorrelationRuleStorage {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	db, err := NewSQLite(":memory:", sugar)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	storage := NewSQLiteCorrelationRuleStorage(db, sugar)
	return storage
}

func createTestCorrelationRule(id, name string) *core.CorrelationRule {
	return &core.CorrelationRule{
		ID:          id,
		Name:        name,
		Description: "Test correlation rule " + name,
		Severity:    "high",
		Version:     1,
		Window:      5 * time.Minute,
		Sequence:    []string{"event1", "event2"},
		Actions: []core.Action{
			{ID: "action1", Type: "webhook", Config: map[string]interface{}{"url": "https://example.com"}},
		},
	}
}

func TestGetCorrelationRules(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create test rules
	for i := 1; i <= 5; i++ {
		rule := createTestCorrelationRule("rule"+string(rune('0'+i)), "Test Rule "+string(rune('0'+i)))
		storage.CreateCorrelationRule(rule)
	}

	// Get all rules
	rules, err := storage.GetCorrelationRules(10, 0)
	if err != nil {
		t.Errorf("Failed to get correlation rules: %v", err)
	}
	if len(rules) != 5 {
		t.Errorf("Expected 5 rules, got %d", len(rules))
	}
}

func TestGetCorrelationRules_Pagination(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create 10 rules
	for i := 1; i <= 10; i++ {
		rule := createTestCorrelationRule("rule_page_"+string(rune('0'+i)), "Page Rule "+string(rune('0'+i)))
		storage.CreateCorrelationRule(rule)
	}

	// Get first page
	page1, err := storage.GetCorrelationRules(5, 0)
	if err != nil {
		t.Errorf("Failed to get page 1: %v", err)
	}
	if len(page1) != 5 {
		t.Errorf("Expected 5 rules on page 1, got %d", len(page1))
	}

	// Get second page
	page2, err := storage.GetCorrelationRules(5, 5)
	if err != nil {
		t.Errorf("Failed to get page 2: %v", err)
	}
	if len(page2) != 5 {
		t.Errorf("Expected 5 rules on page 2, got %d", len(page2))
	}
}

func TestGetAllCorrelationRules(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create test rules
	for i := 1; i <= 3; i++ {
		rule := createTestCorrelationRule("all_rule_"+string(rune('0'+i)), "All Rule "+string(rune('0'+i)))
		storage.CreateCorrelationRule(rule)
	}

	// Get all rules
	rules, err := storage.GetAllCorrelationRules()
	if err != nil {
		t.Errorf("Failed to get all correlation rules: %v", err)
	}
	if len(rules) != 3 {
		t.Errorf("Expected 3 rules, got %d", len(rules))
	}
}

func TestGetCorrelationRuleCount(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create test rules
	for i := 1; i <= 7; i++ {
		rule := createTestCorrelationRule("count_rule_"+string(rune('0'+i)), "Count Rule "+string(rune('0'+i)))
		storage.CreateCorrelationRule(rule)
	}

	// Get count
	count, err := storage.GetCorrelationRuleCount()
	if err != nil {
		t.Errorf("Failed to get correlation rule count: %v", err)
	}
	if count != 7 {
		t.Errorf("Expected count 7, got %d", count)
	}
}

func TestUpdateCorrelationRule(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create rule
	rule := createTestCorrelationRule("update_rule", "Original Name")
	storage.CreateCorrelationRule(rule)

	// Update rule
	rule.Name = "Updated Name"
	rule.Description = "Updated Description"
	rule.Severity = "critical"

	err := storage.UpdateCorrelationRule(rule.ID, rule)
	if err != nil {
		t.Errorf("Failed to update correlation rule: %v", err)
	}

	// Verify update
	retrieved, err := storage.GetCorrelationRule(rule.ID)
	if err != nil {
		t.Errorf("Failed to retrieve updated rule: %v", err)
	}
	if retrieved.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got %s", retrieved.Name)
	}
	if retrieved.Severity != "critical" {
		t.Errorf("Expected severity 'critical', got %s", retrieved.Severity)
	}
}

func TestUpdateCorrelationRule_NotFound(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	rule := createTestCorrelationRule("nonexistent", "Test")
	err := storage.UpdateCorrelationRule("nonexistent", rule)
	if err == nil {
		t.Error("Expected error when updating nonexistent rule")
	}
}

func TestUpdateCorrelationRule_SQLInjection(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create rule
	rule := createTestCorrelationRule("sql_update", "Original")
	err := storage.CreateCorrelationRule(rule)
	if err != nil {
		t.Fatalf("Failed to create rule: %v", err)
	}

	// Attempt SQL injection
	rule.Name = "'; DELETE FROM correlation_rules WHERE '1'='1"
	rule.Description = "'; DROP TABLE correlation_rules; --"

	err = storage.UpdateCorrelationRule(rule.ID, rule)
	if err != nil {
		t.Fatalf("Failed to update rule: %v", err)
	}

	// Verify SQL injection was stored as literal text
	retrieved, err := storage.GetCorrelationRule(rule.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve rule: %v", err)
	}
	if !strings.Contains(retrieved.Name, "DELETE FROM") {
		t.Error("SQL injection should be stored as literal text")
	}
}

func TestDeleteCorrelationRule(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create rule
	rule := createTestCorrelationRule("delete_rule", "To Delete")
	storage.CreateCorrelationRule(rule)

	// Delete rule
	err := storage.DeleteCorrelationRule(rule.ID)
	if err != nil {
		t.Errorf("Failed to delete correlation rule: %v", err)
	}

	// Verify deletion
	_, err = storage.GetCorrelationRule(rule.ID)
	if err == nil {
		t.Error("Expected error when retrieving deleted rule")
	}
}

func TestDeleteCorrelationRule_NotFound(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	err := storage.DeleteCorrelationRule("nonexistent")
	if err == nil {
		t.Error("Expected error when deleting nonexistent rule")
	}
}

func TestDeleteCorrelationRule_SQLInjection(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Attempt SQL injection in delete
	err := storage.DeleteCorrelationRule("' OR '1'='1")
	if err == nil {
		t.Error("Expected error for SQL injection attempt")
	}
}

func TestCorrelationRuleEnsureIndexes(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	err := storage.EnsureIndexes()
	if err != nil {
		t.Errorf("EnsureIndexes failed: %v", err)
	}
}

// TestGetCorrelationRules_EmptyDatabase tests pagination on empty database
func TestGetCorrelationRules_EmptyDatabase(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	rules, err := storage.GetCorrelationRules(10, 0)
	if err != nil {
		t.Errorf("Failed to get rules from empty database: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules from empty database, got %d", len(rules))
	}
}

// TestGetCorrelationRules_LargeOffset tests offset beyond available data
func TestGetCorrelationRules_LargeOffset(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create only 5 rules
	for i := 1; i <= 5; i++ {
		rule := createTestCorrelationRule("offset_rule_"+string(rune('0'+i)), "Offset Rule "+string(rune('0'+i)))
		storage.CreateCorrelationRule(rule)
	}

	// Request with offset beyond available data
	rules, err := storage.GetCorrelationRules(10, 100)
	if err != nil {
		t.Errorf("Failed to get rules with large offset: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules with offset beyond data, got %d", len(rules))
	}
}

// TestGetCorrelationRules_NegativeOffset tests negative offset handling
func TestGetCorrelationRules_NegativeOffset(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create test rules
	for i := 1; i <= 5; i++ {
		rule := createTestCorrelationRule("neg_rule_"+string(rune('0'+i)), "Neg Rule "+string(rune('0'+i)))
		storage.CreateCorrelationRule(rule)
	}

	// Request with negative offset (should be handled as 0)
	rules, err := storage.GetCorrelationRules(10, -5)
	if err != nil {
		t.Errorf("Failed to get rules with negative offset: %v", err)
	}
	if len(rules) == 0 {
		t.Error("Should return rules even with negative offset")
	}
}

// TestGetCorrelationRules_ZeroLimit tests zero limit edge case
func TestGetCorrelationRules_ZeroLimit(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create test rules
	for i := 1; i <= 5; i++ {
		rule := createTestCorrelationRule("zero_rule_"+string(rune('0'+i)), "Zero Rule "+string(rune('0'+i)))
		storage.CreateCorrelationRule(rule)
	}

	// Request with zero limit
	_, err := storage.GetCorrelationRules(0, 0)
	if err != nil {
		t.Errorf("Failed to get rules with zero limit: %v", err)
	}
	// Zero limit might return all or none depending on implementation
}

// TestGetAllCorrelationRules_EmptyDatabase tests GetAll on empty database
func TestGetAllCorrelationRules_EmptyDatabase(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	rules, err := storage.GetAllCorrelationRules()
	if err != nil {
		t.Errorf("Failed to get all rules from empty database: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules from empty database, got %d", len(rules))
	}
}

// TestGetAllCorrelationRules_LargeDataset tests GetAll with many rules
func TestGetAllCorrelationRules_LargeDataset(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create many rules
	for i := 1; i <= 100; i++ {
		rule := createTestCorrelationRule("large_rule_"+string(rune('0'+i)), "Large Rule "+string(rune('0'+i)))
		storage.CreateCorrelationRule(rule)
	}

	rules, err := storage.GetAllCorrelationRules()
	if err != nil {
		t.Errorf("Failed to get all rules from large dataset: %v", err)
	}
	if len(rules) != 100 {
		t.Errorf("Expected 100 rules, got %d", len(rules))
	}
}

// TestCreateCorrelationRule_InvalidJSON tests handling of invalid JSON in fields
func TestCreateCorrelationRule_InvalidJSON(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create rule with empty/invalid JSON-able structures
	rule := &core.CorrelationRule{
		ID:          "invalid_json_rule",
		Name:        "Invalid JSON Test",
		Description: "Test",
		Severity:    "high",
		Version:     1,
		Window:      5 * time.Minute,
		Sequence:    []string{},      // Empty is valid
		Actions:     []core.Action{}, // Empty is valid
	}

	err := storage.CreateCorrelationRule(rule)
	if err != nil {
		t.Errorf("Failed to create rule with empty arrays: %v", err)
	}

	// Verify it was stored
	retrieved, err := storage.GetCorrelationRule(rule.ID)
	if err != nil {
		t.Errorf("Failed to retrieve rule: %v", err)
	}
	if len(retrieved.Sequence) != 0 {
		t.Error("Empty sequence should remain empty")
	}
}

// TestCreateCorrelationRule_DuplicateID tests creating rule with duplicate ID
func TestCreateCorrelationRule_DuplicateID(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	rule1 := createTestCorrelationRule("dup_id", "First")
	err := storage.CreateCorrelationRule(rule1)
	if err != nil {
		t.Errorf("Failed to create first rule: %v", err)
	}

	// Attempt to create rule with same ID
	rule2 := createTestCorrelationRule("dup_id", "Second")
	err = storage.CreateCorrelationRule(rule2)
	if err == nil {
		t.Error("Expected error when creating rule with duplicate ID")
	}
}

// TestCreateCorrelationRule_SpecialCharacters tests creating rule with special characters
func TestCreateCorrelationRule_SpecialCharacters(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	rule := &core.CorrelationRule{
		ID:          "special_char_rule",
		Name:        "Rule with 'quotes' and \"double quotes\"",
		Description: "Description with\nnewlines\tand\ttabs",
		Severity:    "high",
		Version:     1,
		Window:      5 * time.Minute,
		Sequence:    []string{"event1", "event2"},
		Actions:     []core.Action{},
	}

	err := storage.CreateCorrelationRule(rule)
	if err != nil {
		t.Errorf("Failed to create rule with special characters: %v", err)
	}

	retrieved, err := storage.GetCorrelationRule(rule.ID)
	if err != nil {
		t.Errorf("Failed to retrieve rule: %v", err)
	}
	if retrieved.Name != rule.Name {
		t.Errorf("Name mismatch after retrieval")
	}
}

// TestUpdateCorrelationRule_ChangeAllFields tests updating all fields
func TestUpdateCorrelationRule_ChangeAllFields(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	rule := createTestCorrelationRule("full_update", "Original")
	storage.CreateCorrelationRule(rule)

	// Update all fields
	rule.Name = "New Name"
	rule.Description = "New Description"
	rule.Severity = "critical"
	rule.Version = 2
	rule.Window = 10 * time.Minute
	rule.Sequence = []string{"event3", "event4", "event5"}
	rule.Actions = []core.Action{
		{ID: "action2", Type: "email", Config: map[string]interface{}{"to": "admin@example.com"}},
	}

	err := storage.UpdateCorrelationRule(rule.ID, rule)
	if err != nil {
		t.Errorf("Failed to update all fields: %v", err)
	}

	retrieved, err := storage.GetCorrelationRule(rule.ID)
	if err != nil {
		t.Errorf("Failed to retrieve updated rule: %v", err)
	}
	if retrieved.Version != 2 {
		t.Errorf("Expected version 2, got %d", retrieved.Version)
	}
	if len(retrieved.Sequence) != 3 {
		t.Errorf("Expected 3 sequence items, got %d", len(retrieved.Sequence))
	}
}

// TestUpdateCorrelationRule_EmptyFields tests updating with empty values
func TestUpdateCorrelationRule_EmptyFields(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	rule := createTestCorrelationRule("empty_update", "Original")
	storage.CreateCorrelationRule(rule)

	// Update with empty arrays
	rule.Sequence = []string{}
	rule.Actions = []core.Action{}

	err := storage.UpdateCorrelationRule(rule.ID, rule)
	if err != nil {
		t.Errorf("Failed to update with empty fields: %v", err)
	}

	retrieved, err := storage.GetCorrelationRule(rule.ID)
	if err != nil {
		t.Errorf("Failed to retrieve rule: %v", err)
	}
	if len(retrieved.Sequence) != 0 {
		t.Error("Sequence should be empty")
	}
}

// TestGetCorrelationRuleCount_EmptyDatabase tests count on empty database
func TestGetCorrelationRuleCount_EmptyDatabase(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	count, err := storage.GetCorrelationRuleCount()
	if err != nil {
		t.Errorf("Failed to get count from empty database: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected count 0 from empty database, got %d", count)
	}
}

// TestGetCorrelationRuleCount_AfterDelete tests count after deletions
func TestGetCorrelationRuleCount_AfterDelete(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create 5 rules
	for i := 1; i <= 5; i++ {
		rule := createTestCorrelationRule("count_del_"+string(rune('0'+i)), "Count Del "+string(rune('0'+i)))
		storage.CreateCorrelationRule(rule)
	}

	// Verify count is 5
	count, _ := storage.GetCorrelationRuleCount()
	if count != 5 {
		t.Errorf("Expected count 5, got %d", count)
	}

	// Delete 2 rules
	storage.DeleteCorrelationRule("count_del_1")
	storage.DeleteCorrelationRule("count_del_2")

	// Verify count is now 3
	count, err := storage.GetCorrelationRuleCount()
	if err != nil {
		t.Errorf("Failed to get count after delete: %v", err)
	}
	if count != 3 {
		t.Errorf("Expected count 3 after delete, got %d", count)
	}
}

// TestGetCorrelationRule_ValidID tests retrieving rule by ID
func TestGetCorrelationRule_ValidID(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	rule := createTestCorrelationRule("valid_id", "Valid")
	storage.CreateCorrelationRule(rule)

	retrieved, err := storage.GetCorrelationRule("valid_id")
	if err != nil {
		t.Errorf("Failed to get rule by ID: %v", err)
	}
	if retrieved.ID != "valid_id" {
		t.Errorf("Expected ID 'valid_id', got %s", retrieved.ID)
	}
}

// TestGetCorrelationRule_InvalidID tests retrieving with invalid ID
func TestGetCorrelationRule_InvalidID(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	_, err := storage.GetCorrelationRule("nonexistent_id")
	if err == nil {
		t.Error("Expected error when getting nonexistent rule")
	}
}

// TestGetCorrelationRule_SQLInjection tests SQL injection protection in Get
func TestGetCorrelationRule_SQLInjection(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Create a normal rule
	rule := createTestCorrelationRule("normal", "Normal")
	storage.CreateCorrelationRule(rule)

	// Attempt SQL injection in Get
	_, err := storage.GetCorrelationRule("' OR '1'='1")
	if err == nil {
		t.Error("SQL injection should not return data")
	}
}

// TestCorrelationRule_WindowSerialization tests Window duration serialization
func TestCorrelationRule_WindowSerialization(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	testWindows := []time.Duration{
		1 * time.Second,
		5 * time.Minute,
		1 * time.Hour,
		24 * time.Hour,
		7 * 24 * time.Hour,
	}

	for i, window := range testWindows {
		rule := &core.CorrelationRule{
			ID:          "window_" + string(rune('0'+i)),
			Name:        "Window Test",
			Description: "Test",
			Severity:    "high",
			Version:     1,
			Window:      window,
			Sequence:    []string{},
			Actions:     []core.Action{},
		}

		err := storage.CreateCorrelationRule(rule)
		if err != nil {
			t.Errorf("Failed to create rule with window %v: %v", window, err)
		}

		retrieved, err := storage.GetCorrelationRule(rule.ID)
		if err != nil {
			t.Errorf("Failed to retrieve rule: %v", err)
		}
		if retrieved.Window != window {
			t.Errorf("Expected window %v, got %v", window, retrieved.Window)
		}
	}
}

// TestCorrelationRule_ComplexConditions removed - legacy Conditions field is deprecated
// Correlation rules now use SIGMA YAML for detection logic and rely on Sequence/Window fields
// for correlation-specific behavior. See: SIGMA_YAML_IMPLEMENTATION_SUMMARY.md

// TestEnsureIndexes_MultipleCalls tests calling EnsureIndexes multiple times
func TestEnsureIndexes_MultipleCalls(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Call multiple times to ensure idempotency
	for i := 0; i < 3; i++ {
		err := storage.EnsureIndexes()
		if err != nil {
			t.Errorf("EnsureIndexes failed on call %d: %v", i+1, err)
		}
	}
}

// TestGetAllCorrelationRules_JSONSerializationContract verifies JSON serialization produces [] not null
// This is the GOLD STANDARD test that verifies the nil-slice bug fix.
// Empty result sets MUST serialize to [] not null to maintain frontend contract.
func TestGetAllCorrelationRules_JSONSerializationContract(t *testing.T) {
	storage := setupCorrelationRuleTestDB(t)

	// Get all correlation rules from empty database
	rules, err := storage.GetAllCorrelationRules()
	if err != nil {
		t.Fatalf("Failed to get all correlation rules: %v", err)
	}

	// Critical: Verify JSON serialization produces [], not null
	jsonBytes, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("Failed to marshal correlation rules: %v", err)
	}

	if string(jsonBytes) != "[]" {
		t.Errorf("Expected JSON '[]', got '%s' - nil slices break frontend contract", string(jsonBytes))
	}
}
