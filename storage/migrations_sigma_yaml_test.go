package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// TestMigrateToSigmaYAML_Success tests successful migration of SIGMA rules
func TestMigrateToSigmaYAML_Success(t *testing.T) {
	db, logger := setupMigrationTestDB(t)
	defer db.Close()

	// Insert test SIGMA rules with JSON detection and logsource
	testRules := []struct {
		id        string
		name      string
		detection map[string]interface{}
		logsource map[string]interface{}
	}{
		{
			id:   "rule1",
			name: "Windows Process Creation",
			detection: map[string]interface{}{
				"selection": map[string]interface{}{
					"EventID": 1,
					"Image":   "*.exe",
				},
				"condition": "selection",
			},
			logsource: map[string]interface{}{
				"category": "process_creation",
				"product":  "windows",
				"service":  "sysmon",
			},
		},
		{
			id:   "rule2",
			name: "Linux Network Connection",
			detection: map[string]interface{}{
				"selection": map[string]interface{}{
					"type": "connection",
					"port": 443,
				},
				"condition": "selection",
			},
			logsource: map[string]interface{}{
				"category": "network_connection",
				"product":  "linux",
			},
		},
	}

	for _, tr := range testRules {
		insertTestRule(t, db, tr.id, tr.name, tr.detection, tr.logsource)
	}

	// Run migration
	opts := MigrationOptions{
		DryRun:          false,
		ValidateOnly:    false,
		ContinueOnError: false,
		BatchSize:       10,
	}

	result, err := MigrateToSigmaYAML(db, logger, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify result statistics
	if result.Total != 2 {
		t.Errorf("Expected 2 total rules, got %d", result.Total)
	}
	if result.Migrated != 2 {
		t.Errorf("Expected 2 migrated rules, got %d", result.Migrated)
	}
	if result.Skipped != 0 {
		t.Errorf("Expected 0 skipped rules, got %d", result.Skipped)
	}
	if result.Failed != 0 {
		t.Errorf("Expected 0 failed rules, got %d", result.Failed)
	}

	// Verify database was updated correctly
	for _, tr := range testRules {
		verifyRuleMigrated(t, db, tr.id, tr.name, tr.logsource)
	}
}

// TestMigrateToSigmaYAML_DryRun tests dry-run mode doesn't commit changes
func TestMigrateToSigmaYAML_DryRun(t *testing.T) {
	db, logger := setupMigrationTestDB(t)
	defer db.Close()

	// Insert test rule
	detection := map[string]interface{}{
		"selection": map[string]interface{}{"EventID": 1},
		"condition": "selection",
	}
	logsource := map[string]interface{}{"product": "windows"}
	insertTestRule(t, db, "rule1", "Test Rule", detection, logsource)

	// Run migration in dry-run mode
	opts := MigrationOptions{
		DryRun: true,
	}

	result, err := MigrateToSigmaYAML(db, logger, opts)
	if err != nil {
		t.Fatalf("DryRun migration failed: %v", err)
	}

	if result.Migrated != 1 {
		t.Errorf("Expected 1 migrated rule in dry-run, got %d", result.Migrated)
	}

	// Verify database was NOT updated (sigma_yaml should still be NULL)
	var sigmaYAML sql.NullString
	err = db.QueryRow("SELECT sigma_yaml FROM rules WHERE id = ?", "rule1").Scan(&sigmaYAML)
	if err != nil {
		t.Fatalf("Failed to query rule: %v", err)
	}

	if sigmaYAML.Valid && sigmaYAML.String != "" {
		t.Errorf("DryRun mode should not commit changes, but sigma_yaml was updated")
	}
}

// TestMigrateToSigmaYAML_ValidateOnly tests validate-only mode
func TestMigrateToSigmaYAML_ValidateOnly(t *testing.T) {
	db, logger := setupMigrationTestDB(t)
	defer db.Close()

	// Insert valid rule
	validDetection := map[string]interface{}{
		"selection": map[string]interface{}{"EventID": 1},
		"condition": "selection",
	}
	insertTestRule(t, db, "valid_rule", "Valid Rule", validDetection, nil)

	// Insert rule with invalid JSON detection (will cause validation error)
	_, err := db.Exec(`
		INSERT INTO rules (id, type, name, detection, created_at, updated_at)
		VALUES (?, 'sigma', ?, ?, ?, ?)
	`, "invalid_rule", "Invalid Rule", "{invalid json}", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("Failed to insert invalid rule: %v", err)
	}

	// Run validation only
	opts := MigrationOptions{
		ValidateOnly: true,
	}

	_, migErr := MigrateToSigmaYAML(db, logger, opts)
	// ValidateOnly mode returns error if validation fails (and doesn't return result)
	if migErr == nil {
		t.Errorf("Expected validation to fail with invalid rules")
		return
	}

	// When validation fails in ValidateOnly mode, err is returned
	// The error message should indicate validation failure
	if !strings.Contains(migErr.Error(), "validation failed") {
		t.Errorf("Expected validation failed error, got: %v", migErr)
	}

	// Verify no rules were migrated
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM rules WHERE sigma_yaml IS NOT NULL").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count migrated rules: %v", err)
	}
	if count != 0 {
		t.Errorf("ValidateOnly mode should not update database, but %d rules were updated", count)
	}
}

// TestMigrateToSigmaYAML_ContinueOnError tests error handling modes
func TestMigrateToSigmaYAML_ContinueOnError(t *testing.T) {
	db, logger := setupMigrationTestDB(t)
	defer db.Close()

	// Insert valid and invalid rules
	validDetection := map[string]interface{}{
		"selection": map[string]interface{}{"EventID": 1},
		"condition": "selection",
	}
	insertTestRule(t, db, "valid_rule", "Valid Rule", validDetection, nil)

	// Insert rule with invalid JSON detection (will cause conversion error)
	_, err := db.Exec(`
		INSERT INTO rules (id, type, name, detection, created_at, updated_at)
		VALUES (?, 'sigma', ?, ?, ?, ?)
	`, "invalid_rule", "Invalid Rule", "{invalid json}", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("Failed to insert invalid rule: %v", err)
	}

	t.Run("ContinueOnError=false (fail-fast)", func(t *testing.T) {
		opts := MigrationOptions{
			ContinueOnError: false,
		}

		result, err := MigrateToSigmaYAML(db, logger, opts)
		if err == nil {
			t.Errorf("Expected migration to fail with invalid rule, but succeeded")
		}

		// Should have failed without migrating any rules (transaction rolled back)
		if result != nil && result.Migrated > 0 {
			t.Errorf("Fail-fast mode should rollback all changes, but %d rules were migrated", result.Migrated)
		}

		// Verify database was not modified (rollback worked)
		var count int
		db.QueryRow("SELECT COUNT(*) FROM rules WHERE sigma_yaml IS NOT NULL").Scan(&count)
		if count > 0 {
			t.Errorf("Fail-fast rollback failed: %d rules were migrated", count)
		}
	})

	t.Run("ContinueOnError=true (skip invalid)", func(t *testing.T) {
		// Re-setup database to clear previous migration attempt
		db, logger = setupMigrationTestDB(t)
		defer db.Close()

		insertTestRule(t, db, "valid_rule", "Valid Rule", validDetection, nil)

		// Insert rule with invalid JSON
		_, err := db.Exec(`
			INSERT INTO rules (id, type, name, detection, created_at, updated_at)
			VALUES (?, 'sigma', ?, ?, ?, ?)
		`, "invalid_rule", "Invalid Rule", "{invalid json}", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
		if err != nil {
			t.Fatalf("Failed to insert invalid rule: %v", err)
		}

		opts := MigrationOptions{
			ContinueOnError: true,
		}

		result, err := MigrateToSigmaYAML(db, logger, opts)
		if err != nil {
			t.Fatalf("ContinueOnError migration failed: %v", err)
		}

		// Should have migrated valid rules
		// Invalid rule errors are caught during validation phase
		// In ContinueOnError mode, we skip invalid rules found during validation
		if result.Migrated != 1 {
			t.Errorf("Expected 1 migrated rule, got %d", result.Migrated)
		}
		// Validation errors are tracked from the validation phase
		if len(result.Errors) == 0 {
			t.Errorf("Expected error list to contain invalid rule errors from validation")
		}
	})
}

// TestMigrateToSigmaYAML_AlreadyMigrated tests skipping already-migrated rules
func TestMigrateToSigmaYAML_AlreadyMigrated(t *testing.T) {
	db, logger := setupMigrationTestDB(t)
	defer db.Close()

	// Insert rule with sigma_yaml already populated
	detection := map[string]interface{}{
		"selection": map[string]interface{}{"EventID": 1},
		"condition": "selection",
	}
	id := "already_migrated"
	insertTestRule(t, db, id, "Already Migrated", detection, nil)

	// Manually set sigma_yaml to simulate already-migrated rule
	_, err := db.Exec("UPDATE rules SET sigma_yaml = ? WHERE id = ?", "title: Test\ndetection:\n  selection:\n    EventID: 1", id)
	if err != nil {
		t.Fatalf("Failed to update rule: %v", err)
	}

	// Run migration
	opts := MigrationOptions{}
	result, err := MigrateToSigmaYAML(db, logger, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Should skip already-migrated rule
	if result.Total != 0 {
		t.Errorf("Expected 0 total rules (already migrated should be skipped), got %d", result.Total)
	}
}

// TestMigrateToSigmaYAML_BatchProcessing tests batch logging
func TestMigrateToSigmaYAML_BatchProcessing(t *testing.T) {
	db, logger := setupMigrationTestDB(t)
	defer db.Close()

	// Insert multiple rules
	detection := map[string]interface{}{
		"selection": map[string]interface{}{"EventID": 1},
		"condition": "selection",
	}

	for i := 0; i < 25; i++ {
		id := fmt.Sprintf("rule%d", i)
		insertTestRule(t, db, id, fmt.Sprintf("Rule %d", i), detection, nil)
	}

	// Run migration with small batch size
	opts := MigrationOptions{
		BatchSize: 10,
	}

	result, err := MigrateToSigmaYAML(db, logger, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	if result.Total != 25 {
		t.Errorf("Expected 25 total rules, got %d", result.Total)
	}
	if result.Migrated != 25 {
		t.Errorf("Expected 25 migrated rules, got %d", result.Migrated)
	}
}

// TestConvertRuleToYAML_ValidConversion tests YAML conversion logic
func TestConvertRuleToYAML_ValidConversion(t *testing.T) {
	logger := zap.NewNop().Sugar()

	tests := []struct {
		name             string
		detection        map[string]interface{}
		logsource        map[string]interface{}
		wantCategory     string
		wantProduct      string
		wantService      string
		wantYAMLContains []string
		wantErr          bool
	}{
		{
			name: "Complete logsource",
			detection: map[string]interface{}{
				"selection": map[string]interface{}{"EventID": 1},
				"condition": "selection",
			},
			logsource: map[string]interface{}{
				"category": "process_creation",
				"product":  "windows",
				"service":  "sysmon",
			},
			wantCategory:     "process_creation",
			wantProduct:      "windows",
			wantService:      "sysmon",
			wantYAMLContains: []string{"title:", "detection:", "logsource:", "category: process_creation"},
			wantErr:          false,
		},
		{
			name: "Partial logsource",
			detection: map[string]interface{}{
				"selection": map[string]interface{}{"type": "connection"},
				"condition": "selection",
			},
			logsource: map[string]interface{}{
				"product": "linux",
			},
			wantCategory:     "",
			wantProduct:      "linux",
			wantService:      "",
			wantYAMLContains: []string{"title:", "detection:", "product: linux"},
			wantErr:          false,
		},
		{
			name: "No logsource",
			detection: map[string]interface{}{
				"selection": map[string]interface{}{"field": "value"},
				"condition": "selection",
			},
			logsource:        nil,
			wantCategory:     "",
			wantProduct:      "",
			wantService:      "",
			wantYAMLContains: []string{"title:", "detection:"},
			wantErr:          false,
		},
		{
			name:      "Missing detection (error)",
			detection: nil,
			logsource: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create SQL null strings from maps
			var detectionJSON, logsourceJSON sql.NullString

			if tt.detection != nil {
				detectionBytes, _ := json.Marshal(tt.detection)
				detectionJSON = sql.NullString{String: string(detectionBytes), Valid: true}
			}

			if tt.logsource != nil {
				logsourceBytes, _ := json.Marshal(tt.logsource)
				logsourceJSON = sql.NullString{String: string(logsourceBytes), Valid: true}
			}

			// Test conversion
			sigmaYAML, category, product, service, err := convertRuleToYAML(
				"test_rule", "Test Rule", detectionJSON, logsourceJSON, logger,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("convertRuleToYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return // Expected error, test passed
			}

			// Verify extracted logsource fields
			if category != tt.wantCategory {
				t.Errorf("category = %q, want %q", category, tt.wantCategory)
			}
			if product != tt.wantProduct {
				t.Errorf("product = %q, want %q", product, tt.wantProduct)
			}
			if service != tt.wantService {
				t.Errorf("service = %q, want %q", service, tt.wantService)
			}

			// Verify YAML content
			for _, want := range tt.wantYAMLContains {
				if !strings.Contains(sigmaYAML, want) {
					t.Errorf("YAML missing expected content: %q\nGot: %s", want, sigmaYAML)
				}
			}

			// Verify YAML is parseable
			var parsed map[string]interface{}
			if err := yaml.Unmarshal([]byte(sigmaYAML), &parsed); err != nil {
				t.Errorf("Generated invalid YAML: %v", err)
			}

			// Verify required SIGMA fields
			if _, ok := parsed["title"]; !ok {
				t.Errorf("YAML missing required 'title' field")
			}
			if _, ok := parsed["detection"]; !ok {
				t.Errorf("YAML missing required 'detection' field")
			}
		})
	}
}

// TestConvertRuleToYAML_InvalidJSON tests error handling for malformed JSON
func TestConvertRuleToYAML_InvalidJSON(t *testing.T) {
	logger := zap.NewNop().Sugar()

	tests := []struct {
		name          string
		detectionJSON sql.NullString
		logsourceJSON sql.NullString
		wantErrMsg    string
	}{
		{
			name:          "Invalid detection JSON",
			detectionJSON: sql.NullString{String: "{invalid json", Valid: true},
			logsourceJSON: sql.NullString{},
			wantErrMsg:    "invalid detection JSON",
		},
		{
			name:          "Invalid logsource JSON",
			detectionJSON: sql.NullString{String: `{"selection":{"field":"value"},"condition":"selection"}`, Valid: true},
			logsourceJSON: sql.NullString{String: "{invalid json", Valid: true},
			wantErrMsg:    "invalid logsource JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := convertRuleToYAML("test_rule", "Test Rule", tt.detectionJSON, tt.logsourceJSON, logger)

			if err == nil {
				t.Errorf("Expected error containing %q, got nil", tt.wantErrMsg)
				return
			}

			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("Error = %q, want error containing %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

// TestConvertRuleToYAML_YAMLBombProtection tests YAML size limits
func TestConvertRuleToYAML_YAMLBombProtection(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// Create extremely large detection to trigger size limit
	hugeDetection := map[string]interface{}{
		"selection": map[string]interface{}{},
		"condition": "selection",
	}

	// Add many fields to exceed 1MB YAML limit
	for i := 0; i < 100000; i++ {
		key := fmt.Sprintf("field%d", i)
		hugeDetection["selection"].(map[string]interface{})[key] = strings.Repeat("x", 100)
	}

	detectionBytes, _ := json.Marshal(hugeDetection)
	detectionJSON := sql.NullString{String: string(detectionBytes), Valid: true}

	_, _, _, _, err := convertRuleToYAML("test_rule", "Huge Rule", detectionJSON, sql.NullString{}, logger)

	if err == nil {
		t.Errorf("Expected error for YAML exceeding size limit, got nil")
		return
	}

	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("Error = %q, want error containing 'exceeds maximum size'", err.Error())
	}
}

// TestRollbackSigmaYAMLMigration tests migration rollback
func TestRollbackSigmaYAMLMigration(t *testing.T) {
	db, logger := setupMigrationTestDB(t)
	defer db.Close()

	// Migrate a rule first
	detection := map[string]interface{}{
		"selection": map[string]interface{}{"EventID": 1},
		"condition": "selection",
	}
	logsource := map[string]interface{}{
		"category": "process_creation",
		"product":  "windows",
	}
	insertTestRule(t, db, "rule1", "Test Rule", detection, logsource)

	opts := MigrationOptions{}
	_, err := MigrateToSigmaYAML(db, logger, opts)
	if err != nil {
		t.Fatalf("Initial migration failed: %v", err)
	}

	// Verify rule was migrated
	var sigmaYAML sql.NullString
	err = db.QueryRow("SELECT sigma_yaml FROM rules WHERE id = ?", "rule1").Scan(&sigmaYAML)
	if err != nil {
		t.Fatalf("Failed to query migrated rule: %v", err)
	}
	if !sigmaYAML.Valid || sigmaYAML.String == "" {
		t.Fatalf("Rule was not migrated")
	}

	// Rollback migration
	count, err := RollbackSigmaYAMLMigration(db, logger, false)
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 rule rolled back, got %d", count)
	}

	// Verify sigma_yaml was cleared
	var rolledBackYAML, category, product, service sql.NullString
	err = db.QueryRow("SELECT sigma_yaml, logsource_category, logsource_product, logsource_service FROM rules WHERE id = ?", "rule1").
		Scan(&rolledBackYAML, &category, &product, &service)
	if err != nil {
		t.Fatalf("Failed to query rolled back rule: %v", err)
	}

	if rolledBackYAML.Valid && rolledBackYAML.String != "" {
		t.Errorf("sigma_yaml was not cleared after rollback")
	}
	if category.Valid && category.String != "" {
		t.Errorf("logsource_category was not cleared after rollback")
	}
	if product.Valid && product.String != "" {
		t.Errorf("logsource_product was not cleared after rollback")
	}
	if service.Valid && service.String != "" {
		t.Errorf("logsource_service was not cleared after rollback")
	}

	// Verify original JSON was preserved
	var detectionJSON, logsourceJSON sql.NullString
	err = db.QueryRow("SELECT detection, logsource FROM rules WHERE id = ?", "rule1").
		Scan(&detectionJSON, &logsourceJSON)
	if err != nil {
		t.Fatalf("Failed to query rule JSON: %v", err)
	}

	if !detectionJSON.Valid || detectionJSON.String == "" {
		t.Errorf("Original detection JSON was lost after rollback")
	}
	if !logsourceJSON.Valid || logsourceJSON.String == "" {
		t.Errorf("Original logsource JSON was lost after rollback")
	}
}

// TestRollbackSigmaYAMLMigration_DryRun tests rollback dry-run mode
func TestRollbackSigmaYAMLMigration_DryRun(t *testing.T) {
	db, logger := setupMigrationTestDB(t)
	defer db.Close()

	// Migrate a rule
	detection := map[string]interface{}{
		"selection": map[string]interface{}{"EventID": 1},
		"condition": "selection",
	}
	insertTestRule(t, db, "rule1", "Test Rule", detection, nil)

	opts := MigrationOptions{}
	_, err := MigrateToSigmaYAML(db, logger, opts)
	if err != nil {
		t.Fatalf("Initial migration failed: %v", err)
	}

	// Rollback in dry-run mode
	count, err := RollbackSigmaYAMLMigration(db, logger, true)
	if err != nil {
		t.Fatalf("DryRun rollback failed: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 rule to be rolled back in dry-run, got %d", count)
	}

	// Verify sigma_yaml was NOT cleared (dry-run)
	var sigmaYAML sql.NullString
	err = db.QueryRow("SELECT sigma_yaml FROM rules WHERE id = ?", "rule1").Scan(&sigmaYAML)
	if err != nil {
		t.Fatalf("Failed to query rule: %v", err)
	}

	if !sigmaYAML.Valid || sigmaYAML.String == "" {
		t.Errorf("DryRun rollback should not commit changes, but sigma_yaml was cleared")
	}
}

// TestNullIfEmptyString tests nullIfEmptyString helper function
func TestNullIfEmptyString(t *testing.T) {
	tests := []struct {
		input string
		want  interface{}
	}{
		{"", nil},
		{"   ", nil},
		{"value", "value"},
		{"  value  ", "  value  "}, // Doesn't trim, just checks if empty after trim
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%q", tt.input), func(t *testing.T) {
			got := nullIfEmptyString(tt.input)
			if got != tt.want {
				t.Errorf("nullIfEmptyString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// Helper functions for tests

// setupMigrationTestDB creates an in-memory SQLite database for migration testing
func setupMigrationTestDB(t *testing.T) (*sql.DB, *zap.SugaredLogger) {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Enable foreign keys
	_, err = db.Exec("PRAGMA foreign_keys=ON")
	if err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	// Create rules table schema
	schema := `
		CREATE TABLE rules (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL DEFAULT 'sigma',
			name TEXT NOT NULL,
			description TEXT,
			severity TEXT NOT NULL DEFAULT 'medium',
			enabled INTEGER NOT NULL DEFAULT 1,
			version INTEGER NOT NULL DEFAULT 1,
			detection TEXT,
			logsource TEXT,
			sigma_yaml TEXT,
			logsource_category TEXT,
			logsource_product TEXT,
			logsource_service TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`

	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	logger := zap.NewNop().Sugar()
	return db, logger
}

// insertTestRule inserts a test SIGMA rule into the database
func insertTestRule(t *testing.T, db *sql.DB, id, name string, detection, logsource map[string]interface{}) {
	t.Helper()

	var detectionJSON, logsourceJSON interface{}

	if detection != nil {
		detectionBytes, err := json.Marshal(detection)
		if err != nil {
			t.Fatalf("Failed to marshal detection: %v", err)
		}
		detectionJSON = string(detectionBytes)
	}

	if logsource != nil {
		logsourceBytes, err := json.Marshal(logsource)
		if err != nil {
			t.Fatalf("Failed to marshal logsource: %v", err)
		}
		logsourceJSON = string(logsourceBytes)
	}

	now := time.Now().Format(time.RFC3339)
	_, err := db.Exec(`
		INSERT INTO rules (id, type, name, detection, logsource, created_at, updated_at)
		VALUES (?, 'sigma', ?, ?, ?, ?, ?)
	`, id, name, detectionJSON, logsourceJSON, now, now)

	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}
}

// verifyRuleMigrated verifies a rule was migrated correctly
func verifyRuleMigrated(t *testing.T, db *sql.DB, id, expectedName string, expectedLogsource map[string]interface{}) {
	t.Helper()

	var sigmaYAML, category, product, service sql.NullString
	err := db.QueryRow(`
		SELECT sigma_yaml, logsource_category, logsource_product, logsource_service
		FROM rules WHERE id = ?
	`, id).Scan(&sigmaYAML, &category, &product, &service)

	if err != nil {
		t.Fatalf("Failed to query migrated rule %s: %v", id, err)
	}

	// Verify sigma_yaml was populated
	if !sigmaYAML.Valid || sigmaYAML.String == "" {
		t.Errorf("Rule %s: sigma_yaml was not populated", id)
	}

	// Verify YAML is parseable
	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(sigmaYAML.String), &parsed); err != nil {
		t.Errorf("Rule %s: generated invalid YAML: %v", id, err)
	}

	// Verify title matches
	if title, ok := parsed["title"].(string); !ok || title != expectedName {
		t.Errorf("Rule %s: title = %q, want %q", id, title, expectedName)
	}

	// Verify logsource fields if expected
	if expectedLogsource != nil {
		if expectedCat, ok := expectedLogsource["category"].(string); ok {
			if !category.Valid || category.String != expectedCat {
				t.Errorf("Rule %s: logsource_category = %q, want %q", id, category.String, expectedCat)
			}
		}
		if expectedProd, ok := expectedLogsource["product"].(string); ok {
			if !product.Valid || product.String != expectedProd {
				t.Errorf("Rule %s: logsource_product = %q, want %q", id, product.String, expectedProd)
			}
		}
		if expectedServ, ok := expectedLogsource["service"].(string); ok {
			if !service.Valid || service.String != expectedServ {
				t.Errorf("Rule %s: logsource_service = %q, want %q", id, service.String, expectedServ)
			}
		}
	}
}
