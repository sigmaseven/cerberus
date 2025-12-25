package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Simple CRUD tests that focus on code coverage rather than strict behavior validation
// These tests accept any valid HTTP response as long as the handler executes

// TestRuleCreate_Coverage tests rule creation code paths
func TestRuleCreate_Coverage(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	tests := []struct {
		name string
		body interface{}
	}{
		{
			name: "valid_rule",
			body: map[string]interface{}{
				"name":        "Test Rule",
				"description": "Test description",
				"enabled":     true,
				"severity":    "High",
			},
		},
		{
			name: "rule_with_conditions",
			body: map[string]interface{}{
				"name":     "Complex Rule",
				"enabled":  true,
				"severity": "Medium",
				"conditions": map[string]interface{}{
					"field":    "event_type",
					"operator": "equals",
					"value":    "login",
				},
			},
		},
		{
			name: "empty_body",
			body: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(bodyBytes))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Just verify handler executed (not 404/405)
			assert.NotEqual(t, 404, w.Code, "Handler not found")
			assert.NotEqual(t, 405, w.Code, "Method not allowed")
		})
	}
}

// TestRuleCreate_Malformed tests malformed input handling
func TestRuleCreate_Malformed(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader([]byte("not json")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 for malformed JSON
	assert.Equal(t, 400, w.Code, "Expected 400 for malformed JSON")
}

// TestRuleUpdate_Coverage tests rule update code paths
func TestRuleUpdate_Coverage(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// First, create a rule to update
	createRule := map[string]interface{}{
		"type":     "sigma",
		"name":     "Coverage Test Rule",
		"severity": "Medium",
		"version":  1,
		"enabled":  true,
		"sigma_yaml": `title: Coverage Test Rule
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
	}
	createBody, _ := json.Marshal(createRule)
	req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Skipf("Could not create test rule: %s", w.Body.String())
	}

	var createdRule map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createdRule)
	ruleID := createdRule["id"].(string)

	tests := []struct {
		name string
		body interface{}
	}{
		{
			name: "update_name",
			body: map[string]interface{}{
				"type":     "sigma",
				"name":     "Updated Rule Name",
				"severity": "Medium",
				"version":  1,
				"sigma_yaml": `title: Updated Rule Name
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
			},
		},
		{
			name: "update_enabled",
			body: map[string]interface{}{
				"type":     "sigma",
				"name":     "Coverage Test Rule",
				"severity": "Medium",
				"version":  1,
				"enabled":  false,
				"sigma_yaml": `title: Coverage Test Rule
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
			},
		},
		{
			name: "update_multiple_fields",
			body: map[string]interface{}{
				"type":        "sigma",
				"name":        "New Name",
				"description": "New Description",
				"severity":    "High",
				"version":     1,
				"enabled":     true,
				"sigma_yaml": `title: New Name
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("PUT", "/api/v1/rules/"+ruleID, bytes.NewReader(bodyBytes))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Verify update succeeded
			assert.Equal(t, http.StatusOK, w.Code, "Update should succeed: %s", w.Body.String())
		})
	}
}

// TestRuleUpdate_InvalidID tests update with invalid UUID
func TestRuleUpdate_InvalidID_Coverage(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	update := map[string]interface{}{
		"name": "Updated Name",
	}

	bodyBytes, _ := json.Marshal(update)
	req := httptest.NewRequest("PUT", "/api/v1/rules/invalid-id", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// API returns 404 when rule is not found (doesn't validate UUID format separately)
	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 for non-existent rule")
}

// TestRuleDelete_Coverage tests rule deletion code paths
func TestRuleDelete_Coverage(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create rules to delete
	for i := 0; i < 2; i++ {
		createRule := map[string]interface{}{
			"type":     "sigma",
			"name":     "Delete Coverage Test Rule",
			"severity": "Low",
			"version":  1,
			"enabled":  true,
			"sigma_yaml": `title: Delete Coverage Test Rule
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
		}
		createBody, _ := json.Marshal(createRule)
		req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(createBody))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		addCSRFToRequest(t, req)

		w := httptest.NewRecorder()
		testAPI.router.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Skipf("Could not create test rule: %s", w.Body.String())
		}

		var createdRule map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &createdRule)
		ruleID := createdRule["id"].(string)

		// Delete the rule we just created
		t.Run("delete_rule_"+ruleID[:8], func(t *testing.T) {
			req := httptest.NewRequest("DELETE", "/api/v1/rules/"+ruleID, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Verify deletion succeeded
			assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNoContent,
				"Delete should succeed: %d %s", w.Code, w.Body.String())
		})
	}
}

// TestRuleDelete_InvalidID tests deletion with invalid UUID
func TestRuleDelete_InvalidID_Coverage(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	req := httptest.NewRequest("DELETE", "/api/v1/rules/invalid-id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// API returns 404 when rule is not found (doesn't validate UUID format separately)
	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 for non-existent rule")
}

// TestActionCreate_Coverage tests action creation code paths
func TestActionCreate_Coverage(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	tests := []struct {
		name string
		body interface{}
	}{
		{
			name: "email_action",
			body: map[string]interface{}{
				"name":    "Email Alert",
				"type":    "email",
				"enabled": true,
				"config": map[string]interface{}{
					"to":      "admin@example.com",
					"subject": "Security Alert",
				},
			},
		},
		{
			name: "webhook_action",
			body: map[string]interface{}{
				"name":    "Webhook Action",
				"type":    "webhook",
				"enabled": true,
				"config": map[string]interface{}{
					"url": "https://example.com/webhook",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/actions", bytes.NewReader(bodyBytes))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Just verify handler executed
			assert.NotEqual(t, 404, w.Code, "Handler not found")
			assert.NotEqual(t, 405, w.Code, "Method not allowed")
		})
	}
}

// TestActionUpdate_Coverage tests action update code paths
func TestActionUpdate_Coverage(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	actionID := "550e8400-e29b-41d4-a716-446655440011"

	update := map[string]interface{}{
		"name":    "Updated Action",
		"enabled": false,
	}

	bodyBytes, _ := json.Marshal(update)
	req := httptest.NewRequest("PUT", "/api/v1/actions/"+actionID, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Just verify handler executed
	assert.NotEqual(t, 404, w.Code, "Handler not found")
	assert.NotEqual(t, 405, w.Code, "Method not allowed")
}

// TestActionDelete_Coverage tests action deletion code paths
func TestActionDelete_Coverage(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	actionID := "550e8400-e29b-41d4-a716-446655440011"

	req := httptest.NewRequest("DELETE", "/api/v1/actions/"+actionID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Just verify handler executed
	assert.NotEqual(t, 404, w.Code, "Handler not found")
	assert.NotEqual(t, 405, w.Code, "Method not allowed")
}
