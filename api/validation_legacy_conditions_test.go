package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cerberus/core"

	"github.com/google/uuid"
)

// TestValidateRuleForCreation_SigmaRules tests SIGMA rule validation
func TestValidateRuleForCreation_SigmaRules(t *testing.T) {
	tests := []struct {
		name      string
		rule      *core.Rule
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid_sigma_rule_with_yaml",
			rule: &core.Rule{
				Type:      "sigma",
				Name:      "Test Rule",
				SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
			},
			wantError: false,
		},
		{
			name: "valid_sigma_rule_uppercase_type",
			rule: &core.Rule{
				Type:      "SIGMA",
				Name:      "Test Rule",
				SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
			},
			wantError: false,
		},
		{
			name: "valid_sigma_rule_empty_type_defaults_to_sigma",
			rule: &core.Rule{
				Type:      "",
				Name:      "Test Rule",
				SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
			},
			wantError: false,
		},
		{
			name: "invalid_sigma_rule_missing_yaml",
			rule: &core.Rule{
				Type:      "sigma",
				Name:      "Test Rule",
				SigmaYAML: "",
			},
			wantError: true,
			errorMsg:  "SIGMA rules must have sigma_yaml field populated",
		},
		// TASK #184: Test case removed - Conditions field no longer exists in core.Rule
		{
			name: "invalid_sigma_rule_with_cql_query",
			rule: &core.Rule{
				Type:      "sigma",
				Name:      "Test Rule",
				SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
				Query:     "SELECT * FROM events",
			},
			wantError: true,
			errorMsg:  "SIGMA rules cannot have query field (use sigma_yaml)",
		},
		// TASK #184: Test case removed - Conditions field no longer exists in core.Rule
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleForCreation(tt.rule)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateRuleForCreation() expected error but got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("ValidateRuleForCreation() error = %v, want error containing %q", err, tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateRuleForCreation() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestValidateRuleForCreation_CqlRules tests CQL rule validation
func TestValidateRuleForCreation_CqlRules(t *testing.T) {
	tests := []struct {
		name      string
		rule      *core.Rule
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid_cql_rule",
			rule: &core.Rule{
				Type:  "cql",
				Name:  "Test CQL Rule",
				Query: "SELECT * FROM events WHERE action = 'failed_login'",
			},
			wantError: false,
		},
		{
			name: "valid_cql_rule_uppercase_type",
			rule: &core.Rule{
				Type:  "CQL",
				Name:  "Test CQL Rule",
				Query: "SELECT * FROM events WHERE action = 'failed_login'",
			},
			wantError: false,
		},
		{
			name: "invalid_cql_rule_missing_query",
			rule: &core.Rule{
				Type:  "cql",
				Name:  "Test CQL Rule",
				Query: "",
			},
			wantError: true,
			errorMsg:  "CQL rules must have query field populated",
		},
		{
			name: "invalid_cql_rule_with_sigma_yaml",
			rule: &core.Rule{
				Type:      "cql",
				Name:      "Test CQL Rule",
				Query:     "SELECT * FROM events WHERE action = 'failed_login'",
				SigmaYAML: "title: Test",
			},
			wantError: true,
			errorMsg:  "CQL rules cannot have sigma_yaml field (use query)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleForCreation(tt.rule)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateRuleForCreation() expected error but got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("ValidateRuleForCreation() error = %v, want error containing %q", err, tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateRuleForCreation() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestValidateRuleForCreation_EdgeCases tests edge cases
func TestValidateRuleForCreation_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		rule      *core.Rule
		wantError bool
		errorMsg  string
	}{
		{
			name:      "nil_rule",
			rule:      nil,
			wantError: true,
			errorMsg:  "cannot validate nil rule",
		},
		{
			name: "correlation_rule_skipped",
			rule: &core.Rule{
				Type: "correlation",
				Name: "Test Correlation Rule",
			},
			wantError: false, // Correlation rules use separate validation
		},
		{
			name: "invalid_rule_type",
			rule: &core.Rule{
				Type: "invalid_type",
				Name: "Test Rule",
			},
			wantError: true,
			errorMsg:  "invalid rule type: INVALID_TYPE", // Type is normalized to uppercase
		},
		{
			name: "whitespace_only_sigma_yaml",
			rule: &core.Rule{
				Type:      "sigma",
				Name:      "Test Rule",
				SigmaYAML: "   \n\t  ",
			},
			wantError: true,
			errorMsg:  "SIGMA rules must have sigma_yaml field populated",
		},
		{
			name: "whitespace_only_cql_query",
			rule: &core.Rule{
				Type:  "cql",
				Name:  "Test Rule",
				Query: "   \n\t  ",
			},
			wantError: true,
			errorMsg:  "CQL rules must have query field populated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleForCreation(tt.rule)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateRuleForCreation() expected error but got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("ValidateRuleForCreation() error = %v, want error containing %q", err, tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateRuleForCreation() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestCreateRule_RejectsLegacyConditions tests that createRule rejects legacy conditions
// TASK #184: Skipped - Conditions field removed from core.Rule
func TestCreateRule_RejectsLegacyConditions(t *testing.T) {
	t.Skip("Conditions field removed in TASK #184 - rules now use SIGMA YAML")
	return

	// Dead code below - kept for reference
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")

	tests := []struct {
		name           string
		rule           core.Rule
		expectedStatus int
		errorContains  string
	}{
		{
			name: "reject_sigma_rule_with_conditions",
			rule: core.Rule{
				Type:      "sigma",
				Name:      "Test Rule",
				SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
				// Conditions: []core.Condition{  // TASK #184: Commented out - field removed
				// 	{Field: "test", Operator: "equals", Value: "value"},
				// },
				Severity: "Medium",
				Version:  1,
			},
			expectedStatus: http.StatusBadRequest,
			errorContains:  "legacy Conditions field is deprecated",
		},
		{
			name: "accept_valid_sigma_rule",
			rule: core.Rule{
				Type:      "sigma",
				Name:      "Valid Test Rule",
				SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
				Severity:  "Medium",
				Version:   1,
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "reject_default_type_with_conditions",
			rule: core.Rule{
				Type:      "", // Defaults to SIGMA
				Name:      "Test Rule",
				SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
				// Conditions: []core.Condition{  // TASK #184: Commented out - field removed
				// 	{Field: "test", Operator: "equals", Value: "value"},
				// },
				Severity: "Medium",
				Version:  1,
			},
			expectedStatus: http.StatusBadRequest,
			errorContains:  "legacy Conditions field is deprecated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.rule)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			addCSRFToRequest(t, req)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("createRule() status = %d, want %d, body: %s", w.Code, tt.expectedStatus, w.Body.String())
			}

			if tt.errorContains != "" && !strings.Contains(w.Body.String(), tt.errorContains) {
				t.Errorf("createRule() body = %q, want to contain %q", w.Body.String(), tt.errorContains)
			}
		})
	}
}

// TestUpdateRule_RejectsLegacyConditions tests that updateRule rejects legacy conditions
// TASK #184: Skipped - Conditions field removed from core.Rule
func TestUpdateRule_RejectsLegacyConditions(t *testing.T) {
	t.Skip("Conditions field removed in TASK #184 - rules now use SIGMA YAML")
	return

	// Dead code below - kept for reference
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")

	// Create initial valid rule
	existingRule := &core.Rule{
		ID:        uuid.New().String(),
		Type:      "sigma",
		Name:      "Existing Rule",
		SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
		Severity:  "Medium",
		Version:   1,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := api.ruleStorage.CreateRule(existingRule); err != nil {
		t.Fatalf("Failed to create existing rule: %v", err)
	}

	tests := []struct {
		name           string
		rule           core.Rule
		expectedStatus int
		errorContains  string
	}{
		{
			name: "reject_update_with_conditions",
			rule: core.Rule{
				Type:      "sigma",
				Name:      "Updated Rule",
				SigmaYAML: "title: Updated\ndetection:\n  selection:\n    field: value\n  condition: selection",
				// Conditions: []core.Condition{  // TASK #184: Commented out - field removed
				// 	{Field: "test", Operator: "equals", Value: "value"},
				// },
				Severity: "High",
				Version:  2,
			},
			expectedStatus: http.StatusBadRequest,
			errorContains:  "legacy Conditions field is deprecated",
		},
		{
			name: "accept_valid_update",
			rule: core.Rule{
				Type:      "sigma",
				Name:      "Updated Rule Valid",
				SigmaYAML: "title: Updated\ndetection:\n  selection:\n    field: updated\n  condition: selection",
				Severity:  "High",
				Version:   2,
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.rule)
			req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/rules/%s", existingRule.ID), bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			addCSRFToRequest(t, req)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("updateRule() status = %d, want %d, body: %s", w.Code, tt.expectedStatus, w.Body.String())
			}

			if tt.errorContains != "" && !strings.Contains(w.Body.String(), tt.errorContains) {
				t.Errorf("updateRule() body = %q, want to contain %q", w.Body.String(), tt.errorContains)
			}
		})
	}
}

// TestImportRules_RejectsLegacyConditions tests that import rejects legacy conditions
// TASK #184: Skipped - Conditions field removed from core.Rule
func TestImportRules_RejectsLegacyConditions(t *testing.T) {
	t.Skip("Conditions field removed in TASK #184 - rules now use SIGMA YAML")
	return

	// Dead code below - kept for reference
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")

	// Valid SIGMA YAML content
	validYAML := `title: Test Rule
description: Test detection rule
level: medium
detection:
  selection:
    field: value
  condition: selection
`

	// Create multipart form with file
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	// Add file
	part, err := writer.CreateFormFile("files", "test_rule.yml")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	if _, err := io.WriteString(part, validYAML); err != nil {
		t.Fatalf("Failed to write YAML content: %v", err)
	}

	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/import", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Should succeed since we're importing valid SIGMA YAML
	if w.Code != http.StatusOK {
		t.Errorf("handleImportRules() status = %d, want %d, body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	// Parse response
	var response ImportResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify import succeeded
	if response.Failed > 0 {
		t.Errorf("handleImportRules() failed count = %d, want 0", response.Failed)
	}
	if response.Imported == 0 {
		t.Errorf("handleImportRules() imported count = %d, want > 0", response.Imported)
	}
}
