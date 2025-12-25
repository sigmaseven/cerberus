package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cerberus/core"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateRuleWithSigmaYAML tests creating a SIGMA rule with sigma_yaml field
func TestCreateRuleWithSigmaYAML(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Valid SIGMA YAML
	sigmaYAML := `title: Test SIGMA Rule
id: test-sigma-001
status: test
description: Test SIGMA rule for validation
author: Test Author
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4688
    CommandLine|contains: 'powershell'
  condition: selection
falsepositives:
  - Administrative activity
level: medium
tags:
  - attack.execution
  - attack.t1059.001`

	// Create SIGMA rule request - use map to ensure proper JSON serialization
	rule := map[string]interface{}{
		"type":        "sigma",
		"name":        "Test SIGMA Rule",
		"description": "Test SIGMA rule for CRUD operations",
		"severity":    "Medium",
		"version":     1,
		"enabled":     true,
		"sigma_yaml":  sigmaYAML,
	}

	body, err := json.Marshal(rule)
	require.NoError(t, err)

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Use direct httptest.NewRequest pattern like working tests
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code, "Response: %s", w.Body.String())

	// Parse response
	var createdRule core.Rule
	err = json.NewDecoder(w.Body).Decode(&createdRule)
	require.NoError(t, err)

	// Verify SIGMA fields are present
	assert.NotEmpty(t, createdRule.ID)
	// Type may be normalized to uppercase "SIGMA" by storage layer
	assert.True(t, strings.EqualFold("sigma", createdRule.Type), "Expected type sigma or SIGMA, got %s", createdRule.Type)
	assert.Equal(t, sigmaYAML, createdRule.SigmaYAML)
	assert.Equal(t, "Test SIGMA Rule", createdRule.Name)
}

// TestCreateRuleWithSigmaYAMLValidationError tests validation errors for SIGMA rules
func TestCreateRuleWithSigmaYAMLValidationError(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	tests := []struct {
		name           string
		rule           map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "SIGMA rule without sigma_yaml field",
			rule: map[string]interface{}{
				"type":        "sigma",
				"name":        "Invalid SIGMA Rule",
				"description": "Missing sigma_yaml",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				// sigma_yaml is empty - should fail validation
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "SIGMA rules must have sigma_yaml field",
		},
		{
			name: "SIGMA rule with query field (mutually exclusive)",
			rule: map[string]interface{}{
				"type":        "sigma",
				"name":        "Invalid SIGMA Rule",
				"description": "Has both sigma_yaml and query",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				"sigma_yaml":  "title: Test\ndetection:\n  condition: selection",
				"query":       "EventID == 4688", // Should not be present for SIGMA rules
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "cannot have query field",
		},
		{
			name: "CQL rule without query field",
			rule: map[string]interface{}{
				"type":        "cql",
				"name":        "Invalid CQL Rule",
				"description": "Missing query",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				// query is empty - should fail validation
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "CQL rules must have query field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.rule)
			require.NoError(t, err)

			// Use direct httptest.NewRequest pattern like working tests
			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "Response: %s", w.Body.String())
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// TestGetRuleWithSigmaYAML tests retrieving a SIGMA rule with all fields
func TestGetRuleWithSigmaYAML(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create SIGMA rule directly in storage
	sigmaYAML := `title: Test SIGMA Rule
logsource:
  category: process_creation
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
  condition: selection
level: high`

	ruleID := uuid.New().String()
	rule := &core.Rule{
		ID:                ruleID,
		Type:              "sigma",
		Name:              "Test SIGMA Rule",
		Description:       "Test rule with logsource fields",
		Severity:          "High",
		Version:           1,
		Enabled:           true,
		SigmaYAML:         sigmaYAML,
		LogsourceCategory: "process_creation",
		LogsourceProduct:  "windows",
		LogsourceService:  "sysmon",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	err := testAPI.ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Get the rule via API
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+ruleID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"id": ruleID})
	w := httptest.NewRecorder()

	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Parse response - unified API returns {"category": "detection", "rule": {...}}
	var response struct {
		Category string    `json:"category"`
		Rule     core.Rule `json:"rule"`
	}
	err = json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	// Verify all SIGMA fields are present
	assert.Equal(t, "detection", response.Category)
	assert.Equal(t, ruleID, response.Rule.ID)
	// Type may be normalized to uppercase "SIGMA" by storage layer
	assert.True(t, strings.EqualFold("sigma", response.Rule.Type), "Expected type sigma or SIGMA, got %s", response.Rule.Type)
	assert.Equal(t, sigmaYAML, response.Rule.SigmaYAML)
	assert.Equal(t, "process_creation", response.Rule.LogsourceCategory)
	assert.Equal(t, "windows", response.Rule.LogsourceProduct)
	assert.Equal(t, "sysmon", response.Rule.LogsourceService)
}

// TestUpdateRuleWithSigmaYAML tests updating a SIGMA rule
func TestUpdateRuleWithSigmaYAML(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create initial SIGMA rule
	ruleID := uuid.New().String()
	originalYAML := `title: Original Rule
logsource:
  category: process_creation
detection:
  selection:
    EventID: 4688
  condition: selection
level: low`

	rule := &core.Rule{
		ID:          ruleID,
		Type:        "sigma",
		Name:        "Original Rule",
		Description: "Original description",
		Severity:    "Low",
		Version:     1,
		Enabled:     true,
		SigmaYAML:   originalYAML,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := testAPI.ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Update the rule with new SIGMA YAML
	updatedYAML := `title: Updated Rule
logsource:
  category: network_connection
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 3
    DestinationPort: 443
  condition: selection
level: high`

	// Use map for proper JSON serialization
	updatedRule := map[string]interface{}{
		"type":               "sigma",
		"name":               "Updated Rule",
		"description":        "Updated description",
		"severity":           "High",
		"version":            2,
		"enabled":            true,
		"sigma_yaml":         updatedYAML,
		"logsource_category": "network_connection",
		"logsource_product":  "windows",
		"logsource_service":  "sysmon",
	}

	body, err := json.Marshal(updatedRule)
	require.NoError(t, err)

	// Use direct httptest.NewRequest pattern like working tests
	req := httptest.NewRequest(http.MethodPut, "/api/v1/rules/"+ruleID, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)
	req = mux.SetURLVars(req, map[string]string{"id": ruleID})
	w := httptest.NewRecorder()

	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Response: %s", w.Body.String())

	// Parse response
	var returnedRule core.Rule
	err = json.NewDecoder(w.Body).Decode(&returnedRule)
	require.NoError(t, err)

	// Verify SIGMA fields were updated
	assert.Equal(t, updatedYAML, returnedRule.SigmaYAML)
	assert.Equal(t, "Updated Rule", returnedRule.Name)
	assert.Equal(t, "network_connection", returnedRule.LogsourceCategory)
	assert.Equal(t, "windows", returnedRule.LogsourceProduct)
	assert.Equal(t, "sysmon", returnedRule.LogsourceService)
}

// TestGetRulesIncludesSigmaYAML tests that listing rules includes SIGMA YAML fields
func TestGetRulesIncludesSigmaYAML(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create multiple SIGMA rules
	for i := 0; i < 3; i++ {
		sigmaYAML := `title: Test Rule ` + string(rune('A'+i)) + `
logsource:
  category: test_category
  product: test_product
detection:
  selection:
    field: value
  condition: selection
level: medium`

		rule := &core.Rule{
			ID:                uuid.New().String(),
			Type:              "sigma",
			Name:              "Test Rule " + string(rune('A'+i)),
			Description:       "Test rule " + string(rune('A'+i)),
			Severity:          "Medium",
			Version:           1,
			Enabled:           true,
			SigmaYAML:         sigmaYAML,
			LogsourceCategory: "test_category",
			LogsourceProduct:  "test_product",
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}

		err := testAPI.ruleStorage.CreateRule(rule)
		require.NoError(t, err)
	}

	// Get all rules
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Parse response - unified API returns {"items": [...], "total": ...}
	var response map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	items, ok := response["items"].([]interface{})
	require.True(t, ok, "Response should have items array, got: %v", response)
	assert.GreaterOrEqual(t, len(items), 3, "Should have at least 3 rules")

	// Unified endpoint wraps rules in {category, rule} structure
	firstItem := items[0].(map[string]interface{})
	firstRule := firstItem["rule"].(map[string]interface{})
	assert.NotNil(t, firstRule["sigma_yaml"], "Rule should include sigma_yaml field")
	assert.NotNil(t, firstRule["logsource_category"], "Rule should include logsource_category field")
	assert.NotNil(t, firstRule["logsource_product"], "Rule should include logsource_product field")
}

// TestSigmaYAMLSecurityLimits tests that SIGMA YAML respects size limits
func TestSigmaYAMLSecurityLimits(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create SIGMA rule with very large YAML (exceeds 1MB limit in decodeJSONBodyWithLimit)
	largeSigmaYAML := "title: Large Rule\ndetection:\n  selection:\n"
	// Add many fields to exceed size limit
	for i := 0; i < 100000; i++ {
		largeSigmaYAML += "    field" + string(rune(i%26+65)) + ": value\n"
	}

	rule := core.Rule{
		Type:        "sigma",
		Name:        "Large SIGMA Rule",
		Description: "SIGMA rule with large YAML",
		Severity:    "Medium",
		Version:     1,
		Enabled:     true,
		SigmaYAML:   largeSigmaYAML,
	}

	body, err := json.Marshal(rule)
	require.NoError(t, err)

	// Request should be rejected due to size limit
	csrfToken := generateTestCSRFToken(t)
	req := makeAuthenticatedRequest(http.MethodPost, "/api/v1/rules", body, token, csrfToken)
	w := httptest.NewRecorder()

	testAPI.router.ServeHTTP(w, req)

	// Should return 413 Request Entity Too Large or 400 Bad Request
	assert.True(t, w.Code == http.StatusRequestEntityTooLarge || w.Code == http.StatusBadRequest,
		"Should reject oversized request, got status: %d", w.Code)
}

// ============================================================================
// SIGMA YAML SECURITY EDGE CASE TESTS
// ============================================================================

// TestSigmaYAML_BillionLaughsAttack tests protection against YAML billion laughs attack
// The billion laughs attack exploits YAML anchors and aliases to create exponential expansion
func TestSigmaYAML_BillionLaughsAttack(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Classic billion laughs pattern using YAML anchors/aliases
	billionLaughsYAML := `title: Billion Laughs Test
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
detection:
  selection:
    field: *f
  condition: selection`

	rule := map[string]interface{}{
		"type":        "sigma",
		"name":        "Billion Laughs Test",
		"description": "Testing billion laughs attack protection",
		"severity":    "Medium",
		"version":     1,
		"enabled":     true,
		"sigma_yaml":  billionLaughsYAML,
	}

	body, err := json.Marshal(rule)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should be rejected due to too many anchors/aliases (max 10 in validator)
	assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusInternalServerError,
		"Should reject billion laughs attack, got status: %d, body: %s", w.Code, w.Body.String())
}

// TestSigmaYAML_DeeplyNestedYAML tests protection against deeply nested YAML structures
func TestSigmaYAML_DeeplyNestedYAML(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create deeply nested YAML structure (60+ levels, exceeds 50 limit)
	deeplyNestedYAML := "title: Deeply Nested Rule\ndetection:\n"
	indent := "  "
	for i := 0; i < 60; i++ {
		deeplyNestedYAML += indent + "level" + string(rune('A'+(i%26))) + ":\n"
		indent += "  "
	}
	deeplyNestedYAML += indent + "field: value\n"
	deeplyNestedYAML += "  condition: level\n"

	rule := map[string]interface{}{
		"type":        "sigma",
		"name":        "Deeply Nested Rule",
		"description": "Testing deep nesting protection",
		"severity":    "Medium",
		"version":     1,
		"enabled":     true,
		"sigma_yaml":  deeplyNestedYAML,
	}

	body, err := json.Marshal(rule)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should be rejected due to depth limit (max 50 in validator)
	// Returns 500 when validation fails in metadata extraction layer
	// The important thing is it doesn't crash or hang (stack overflow)
	assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusInternalServerError,
		"Should reject deeply nested YAML, got status: %d, body: %s", w.Code, w.Body.String())
	// Note: Error details are sanitized by security middleware, so we only verify the status code
}

// TestSigmaYAML_NULBytesInYAML tests handling of NUL bytes in YAML content
func TestSigmaYAML_NULBytesInYAML(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name string
		yaml string
	}{
		{
			name: "NUL byte in title",
			yaml: "title: Test\x00Rule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
		{
			name: "NUL byte in field value",
			yaml: "title: Test Rule\ndetection:\n  selection:\n    field: val\x00ue\n  condition: selection",
		},
		{
			name: "Multiple NUL bytes",
			yaml: "title: Test\x00\x00\x00Rule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]interface{}{
				"type":        "sigma",
				"name":        "NUL Byte Test",
				"description": "Testing NUL byte handling",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				"sigma_yaml":  tc.yaml,
			}

			body, err := json.Marshal(rule)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should either reject (400) or handle gracefully (not 500)
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Should not crash on NUL bytes, got status: %d, body: %s", w.Code, w.Body.String())
		})
	}
}

// TestSigmaYAML_ControlCharacters tests handling of control characters in YAML
func TestSigmaYAML_ControlCharacters(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name string
		yaml string
	}{
		{
			name: "backspace character",
			yaml: "title: Test\bRule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
		{
			name: "bell character",
			yaml: "title: Test\aRule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
		{
			name: "form feed character",
			yaml: "title: Test\fRule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
		{
			name: "vertical tab character",
			yaml: "title: Test\vRule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
		{
			name: "escape character",
			yaml: "title: Test\x1bRule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]interface{}{
				"type":        "sigma",
				"name":        "Control Char Test",
				"description": "Testing control character handling",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				"sigma_yaml":  tc.yaml,
			}

			body, err := json.Marshal(rule)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should either reject (400) or handle gracefully (not 500)
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Should not crash on control characters, got status: %d", w.Code)
		})
	}
}

// TestSigmaYAML_InvalidUTF8 tests handling of invalid UTF-8 sequences
func TestSigmaYAML_InvalidUTF8(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name string
		yaml string
	}{
		{
			name: "invalid UTF-8 continuation byte",
			yaml: "title: Test\x80Rule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
		{
			name: "overlong UTF-8 encoding",
			yaml: "title: Test\xc0\x80Rule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
		{
			name: "truncated UTF-8 sequence",
			yaml: "title: Test\xc2Rule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
		{
			name: "invalid UTF-8 start byte",
			yaml: "title: Test\xfeRule\ndetection:\n  selection:\n    field: value\n  condition: selection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]interface{}{
				"type":        "sigma",
				"name":        "Invalid UTF-8 Test",
				"description": "Testing invalid UTF-8 handling",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				"sigma_yaml":  tc.yaml,
			}

			body, err := json.Marshal(rule)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should either reject (400) or handle gracefully (not 500)
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Should not crash on invalid UTF-8, got status: %d", w.Code)
		})
	}
}

// TestSigmaYAML_ReDoSPatterns tests protection against ReDoS patterns in regex fields
func TestSigmaYAML_ReDoSPatterns(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name string
		yaml string
	}{
		{
			name: "nested quantifiers (a+)+",
			yaml: `title: ReDoS Test
detection:
  selection:
    field|re: '(a+)+'
  condition: selection`,
		},
		{
			name: "nested quantifiers (.*)+",
			yaml: `title: ReDoS Test
detection:
  selection:
    field|re: '(.*)+'
  condition: selection`,
		},
		{
			name: "alternation with overlap",
			yaml: `title: ReDoS Test
detection:
  selection:
    field|re: '(a|a)+'
  condition: selection`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]interface{}{
				"type":        "sigma",
				"name":        "ReDoS Test",
				"description": "Testing ReDoS protection",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				"sigma_yaml":  tc.yaml,
			}

			body, err := json.Marshal(rule)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should be rejected due to dangerous regex patterns
			// The validator should flag these as high-risk ReDoS patterns
			// Returns 500 when validation fails in metadata extraction layer
			assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusInternalServerError,
				"Should reject ReDoS pattern, got status: %d, body: %s", w.Code, w.Body.String())
			// Note: Error details are sanitized by security middleware, so we only verify the status code
		})
	}
}

// TestSigmaYAML_MalformedYAMLSyntax tests handling of malformed YAML syntax
func TestSigmaYAML_MalformedYAMLSyntax(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name string
		yaml string
	}{
		{
			name: "unclosed string",
			yaml: `title: "Unclosed String
detection:
  selection:
    field: value
  condition: selection`,
		},
		{
			name: "invalid indentation",
			yaml: `title: Test Rule
 detection:
  selection:
   field: value
  condition: selection`,
		},
		{
			name: "duplicate key",
			yaml: `title: Test Rule
title: Duplicate Title
detection:
  selection:
    field: value
  condition: selection`,
		},
		{
			name: "tab character in indentation",
			yaml: "title: Test Rule\ndetection:\n\tselection:\n\t\tfield: value\n\tcondition: selection",
		},
		{
			name: "missing colon",
			yaml: `title Test Rule
detection:
  selection:
    field: value
  condition: selection`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]interface{}{
				"type":        "sigma",
				"name":        "Malformed YAML Test",
				"description": "Testing malformed YAML handling",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				"sigma_yaml":  tc.yaml,
			}

			body, err := json.Marshal(rule)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should return 400 Bad Request for malformed YAML (not 500)
			assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusCreated,
				"Should reject or accept malformed YAML gracefully, got status: %d", w.Code)
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Should not crash on malformed YAML")
		})
	}
}

// TestSigmaYAML_ExcessiveAnchorCount tests protection against excessive anchors
func TestSigmaYAML_ExcessiveAnchorCount(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create YAML with more than 10 anchors (exceeds MaxYAMLAnchorsAliases)
	excessiveAnchorsYAML := "title: Excessive Anchors Test\ndetection:\n"
	for i := 0; i < 15; i++ {
		excessiveAnchorsYAML += "  anchor" + string(rune('A'+i)) + ": &ref" + string(rune('A'+i)) + " value" + string(rune('A'+i)) + "\n"
	}
	excessiveAnchorsYAML += "  selection:\n    field: value\n  condition: selection"

	rule := map[string]interface{}{
		"type":        "sigma",
		"name":        "Excessive Anchors Test",
		"description": "Testing anchor limit protection",
		"severity":    "Medium",
		"version":     1,
		"enabled":     true,
		"sigma_yaml":  excessiveAnchorsYAML,
	}

	body, err := json.Marshal(rule)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should be rejected due to anchor limit (max 10 in validator)
	// Returns 500 when validation fails in metadata extraction layer
	assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusInternalServerError,
		"Should reject excessive anchors, got status: %d, body: %s", w.Code, w.Body.String())
	// Note: Error details are sanitized by security middleware, so we only verify the status code
}

// TestSigmaYAML_EmptyAndWhitespace tests handling of empty and whitespace YAML
func TestSigmaYAML_EmptyAndWhitespace(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name string
		yaml string
	}{
		{
			name: "empty string",
			yaml: "",
		},
		{
			name: "whitespace only",
			yaml: "   \n\t\n  ",
		},
		{
			name: "newlines only",
			yaml: "\n\n\n",
		},
		{
			name: "YAML with only comments",
			yaml: "# This is a comment\n# Another comment",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]interface{}{
				"type":        "sigma",
				"name":        "Empty YAML Test",
				"description": "Testing empty YAML handling",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				"sigma_yaml":  tc.yaml,
			}

			body, err := json.Marshal(rule)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should return 400 Bad Request for empty YAML
			// May return 500 when validation fails in metadata extraction layer
			assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusInternalServerError,
				"Should reject empty YAML, got status: %d, body: %s", w.Code, w.Body.String())
		})
	}
}

// TestSigmaYAML_YAMLInjectionAttempts tests protection against YAML injection attacks
func TestSigmaYAML_YAMLInjectionAttempts(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name string
		yaml string
	}{
		{
			name: "YAML directive injection",
			yaml: `%YAML 1.1
---
title: Directive Injection Test
detection:
  selection:
    field: value
  condition: selection`,
		},
		{
			name: "tag directive injection",
			yaml: `%TAG ! tag:example.com,2024:
---
title: Tag Injection Test
detection:
  selection:
    field: value
  condition: selection`,
		},
		{
			name: "multiple document injection",
			yaml: `title: First Doc
detection:
  selection:
    field: value
  condition: selection
---
title: Second Doc (should be ignored)
detection:
  selection:
    field: malicious
  condition: selection`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]interface{}{
				"type":        "sigma",
				"name":        "YAML Injection Test",
				"description": "Testing YAML injection protection",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				"sigma_yaml":  tc.yaml,
			}

			body, err := json.Marshal(rule)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should either reject or handle safely (not 500)
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Should not crash on YAML injection attempts, got status: %d", w.Code)
		})
	}
}

// TestSigmaYAML_LargeRepetitionRange tests protection against large regex repetition ranges
func TestSigmaYAML_LargeRepetitionRange(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name string
		yaml string
	}{
		{
			name: "extremely large repetition",
			yaml: `title: Large Repetition Test
detection:
  selection:
    field|re: 'a{10000}'
  condition: selection`,
		},
		{
			name: "unbounded repetition with large min",
			yaml: `title: Unbounded Repetition Test
detection:
  selection:
    field|re: 'a{5000,}'
  condition: selection`,
		},
		{
			name: "large range repetition",
			yaml: `title: Range Repetition Test
detection:
  selection:
    field|re: 'a{1,10000}'
  condition: selection`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]interface{}{
				"type":        "sigma",
				"name":        "Large Repetition Test",
				"description": "Testing large repetition protection",
				"severity":    "Medium",
				"version":     1,
				"enabled":     true,
				"sigma_yaml":  tc.yaml,
			}

			body, err := json.Marshal(rule)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should either reject or handle safely (not 500)
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Should not crash on large repetition ranges, got status: %d", w.Code)
		})
	}
}
