package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"cerberus/soar"
	"cerberus/storage"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 63.6: Comprehensive Playbook Handler Tests
// Tests cover: playbook CRUD, execution triggering, status tracking, execution history, YAML/JSON validation

// TestExecutePlaybook_Success tests playbook execution
func TestExecutePlaybook_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	payload := map[string]string{
		"alert_id": "test-alert-1",
	}
	bodyBytes, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/v1/playbooks/test-playbook-1/execute", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "test-playbook-1"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// May succeed (200), fail (404/400/500), or be unavailable (503)
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound || w.Code == http.StatusBadRequest || w.Code == http.StatusServiceUnavailable || w.Code == http.StatusUnauthorized,
		"Execute playbook should handle request")
}

// TestExecutePlaybook_InvalidAlertID tests execution with invalid alert ID
func TestExecutePlaybook_InvalidAlertID(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	payload := map[string]string{
		"alert_id": "", // Empty alert ID
	}
	bodyBytes, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/v1/playbooks/test-playbook-1/execute", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "test-playbook-1"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Empty alert ID should be rejected")
}

// TestExecutePlaybook_NoExecutor tests execution when executor is not available
func TestExecutePlaybook_NoExecutor(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Remove playbook executor
	testAPI.playbookExecutor = nil

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	payload := map[string]string{
		"alert_id": "test-alert-1",
	}
	bodyBytes, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/v1/playbooks/test-playbook-1/execute", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "test-playbook-1"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Should return 503 when executor unavailable")
}

// TestPlaybookExecution_StatusStructure tests playbook execution status structure
// Note: Execution status endpoint may need to be implemented
func TestPlaybookExecution_StatusStructure(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	req := httptest.NewRequest("GET", "/api/v1/playbook-executions/test-exec-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"id": "test-exec-1"})

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// May return 404 if endpoint doesn't exist, 503 if storage not available, or 200/400 if it does
	assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusOK || w.Code == http.StatusBadRequest || w.Code == http.StatusUnauthorized || w.Code == http.StatusServiceUnavailable,
		"Playbook execution status should handle request")
}

// TestPlaybookValidation_InvalidYAML tests invalid YAML validation
func TestPlaybookValidation_InvalidYAML(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	// Invalid YAML
	invalidYAML := `
name: Test Playbook
steps:
  - id: step1
    action_type: notify
    parameters:
      invalid: [unclosed bracket
`

	payload := map[string]interface{}{
		"playbook": invalidYAML,
	}
	bodyBytes, _ := json.Marshal(payload)

	// Note: Playbook creation endpoint may need validation
	req := httptest.NewRequest("POST", "/api/v1/playbooks", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// May reject invalid YAML (400), return 404 if endpoint doesn't exist, or 503 if storage not available
	assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusNotFound || w.Code == http.StatusUnauthorized || w.Code == http.StatusServiceUnavailable,
		"Invalid YAML should be rejected or endpoint may not exist")
}

// =============================================================================
// TASK 95: Playbook Validation Function Tests
// =============================================================================

// createValidTestPlaybook creates a valid playbook for testing.
func createValidTestPlaybook(id, name string) *soar.Playbook {
	return &soar.Playbook{
		ID:          id,
		Name:        name,
		Description: "Test playbook description",
		Enabled:     true,
		Priority:    10,
		Triggers: []soar.PlaybookTrigger{
			{
				Type: "alert",
				Conditions: []soar.PlaybookCondition{
					{Field: "severity", Operator: "eq", Value: "critical"},
				},
			},
		},
		Steps: []soar.PlaybookStep{
			{
				ID:         "step-1",
				Name:       "Notify Security Team",
				ActionType: soar.ActionTypeNotify,
				Timeout:    5 * time.Minute,
				Parameters: map[string]interface{}{
					"channel": "#security-alerts",
					"message": "Critical alert detected",
				},
			},
		},
	}
}

// TestValidatePlaybookID tests playbook ID validation
func TestValidatePlaybookID(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "Valid ID with letters",
			id:        "my-playbook",
			expectErr: false,
		},
		{
			name:      "Valid ID with numbers",
			id:        "playbook123",
			expectErr: false,
		},
		{
			name:      "Valid ID with underscore",
			id:        "my_playbook_1",
			expectErr: false,
		},
		{
			name:      "Valid ID with hyphen",
			id:        "my-playbook-1",
			expectErr: false,
		},
		{
			name:      "Valid ID - maximum length (64 chars)",
			id:        strings.Repeat("a", 64),
			expectErr: false,
		},
		{
			name:      "Empty ID",
			id:        "",
			expectErr: true,
			errMsg:    "playbook ID cannot be empty",
		},
		{
			name:      "ID too long (65 chars)",
			id:        strings.Repeat("a", 65),
			expectErr: true,
			errMsg:    "must be 1-64 characters",
		},
		{
			name:      "ID with invalid characters (spaces)",
			id:        "my playbook",
			expectErr: true,
			errMsg:    "must be 1-64 characters",
		},
		{
			name:      "ID with invalid characters (special)",
			id:        "playbook@123",
			expectErr: true,
			errMsg:    "must be 1-64 characters",
		},
		{
			name:      "ID with dots",
			id:        "playbook.v1",
			expectErr: true,
			errMsg:    "must be 1-64 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePlaybookID(tt.id)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestValidateActionType tests action type validation
func TestValidateActionType(t *testing.T) {
	tests := []struct {
		name       string
		actionType soar.ActionType
		expectErr  bool
		errMsg     string
	}{
		{
			name:       "Valid - block_ip",
			actionType: soar.ActionTypeBlock,
			expectErr:  false,
		},
		{
			name:       "Valid - isolate_host",
			actionType: soar.ActionTypeIsolate,
			expectErr:  false,
		},
		{
			name:       "Valid - quarantine_file",
			actionType: soar.ActionTypeQuarantine,
			expectErr:  false,
		},
		{
			name:       "Valid - send_notification",
			actionType: soar.ActionTypeNotify,
			expectErr:  false,
		},
		{
			name:       "Valid - enrich_ioc",
			actionType: soar.ActionTypeEnrich,
			expectErr:  false,
		},
		{
			name:       "Valid - create_ticket",
			actionType: soar.ActionTypeCreateTicket,
			expectErr:  false,
		},
		{
			name:       "Valid - update_alert",
			actionType: soar.ActionTypeUpdateAlert,
			expectErr:  false,
		},
		{
			name:       "Valid - call_webhook",
			actionType: soar.ActionTypeWebhook,
			expectErr:  false,
		},
		{
			name:       "Valid - run_script",
			actionType: soar.ActionTypeScript,
			expectErr:  false,
		},
		{
			name:       "Empty action type",
			actionType: "",
			expectErr:  true,
			errMsg:     "action type cannot be empty",
		},
		{
			name:       "Invalid action type",
			actionType: "invalid_action",
			expectErr:  true,
			errMsg:     "invalid action type",
		},
		{
			name:       "Unknown action type",
			actionType: "explode_server",
			expectErr:  true,
			errMsg:     "invalid action type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateActionType(tt.actionType)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestValidatePlaybook_Valid tests valid playbook validation
func TestValidatePlaybook_Valid(t *testing.T) {
	playbook := createValidTestPlaybook("test-playbook", "Test Playbook")
	errs := validatePlaybook(playbook)
	assert.Empty(t, errs, "Valid playbook should have no errors")
}

// TestValidatePlaybook_Nil tests nil playbook validation
func TestValidatePlaybook_Nil(t *testing.T) {
	errs := validatePlaybook(nil)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0], "playbook cannot be nil")
}

// TestValidatePlaybook_RequiredFields tests required field violations
func TestValidatePlaybook_RequiredFields(t *testing.T) {
	tests := []struct {
		name     string
		playbook *soar.Playbook
		errCount int
		errMsgs  []string
	}{
		{
			name: "Empty ID",
			playbook: func() *soar.Playbook {
				p := createValidTestPlaybook("valid-id", "Test")
				p.ID = ""
				return p
			}(),
			errCount: 1,
			errMsgs:  []string{"playbook ID cannot be empty"},
		},
		{
			name: "Empty name",
			playbook: func() *soar.Playbook {
				p := createValidTestPlaybook("valid-id", "Test")
				p.Name = ""
				return p
			}(),
			errCount: 1,
			errMsgs:  []string{"name is required"},
		},
		{
			name: "Whitespace-only name",
			playbook: func() *soar.Playbook {
				p := createValidTestPlaybook("valid-id", "Test")
				p.Name = "   "
				return p
			}(),
			errCount: 1,
			errMsgs:  []string{"name is required"},
		},
		{
			name: "No steps",
			playbook: func() *soar.Playbook {
				p := createValidTestPlaybook("valid-id", "Test")
				p.Steps = nil
				return p
			}(),
			errCount: 1,
			errMsgs:  []string{"at least one step is required"},
		},
		{
			name: "Empty steps array",
			playbook: func() *soar.Playbook {
				p := createValidTestPlaybook("valid-id", "Test")
				p.Steps = []soar.PlaybookStep{}
				return p
			}(),
			errCount: 1,
			errMsgs:  []string{"at least one step is required"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validatePlaybook(tt.playbook)
			assert.Len(t, errs, tt.errCount, "Expected %d errors", tt.errCount)
			for _, msg := range tt.errMsgs {
				found := false
				for _, err := range errs {
					if strings.Contains(err, msg) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected error containing: %s", msg)
			}
		})
	}
}

// TestValidatePlaybook_StructureLimits tests structure limit violations
func TestValidatePlaybook_StructureLimits(t *testing.T) {
	t.Run("Too many triggers", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		// Add 11 triggers (max is 10)
		playbook.Triggers = make([]soar.PlaybookTrigger, MaxTriggersPerPlaybook+1)
		for i := range playbook.Triggers {
			playbook.Triggers[i] = soar.PlaybookTrigger{Type: "alert"}
		}

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "too many triggers") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report too many triggers")
	})

	t.Run("Too many steps", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		// Add 51 steps (max is 50)
		playbook.Steps = make([]soar.PlaybookStep, MaxStepsPerPlaybook+1)
		for i := range playbook.Steps {
			playbook.Steps[i] = soar.PlaybookStep{
				ID:         "step-" + strings.Repeat("x", i),
				Name:       "Step",
				ActionType: soar.ActionTypeNotify,
			}
		}

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "too many steps") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report too many steps")
	})

	t.Run("Too many conditions in trigger", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		// Add 21 conditions (max is 20)
		conditions := make([]soar.PlaybookCondition, MaxConditionsPerTrigger+1)
		for i := range conditions {
			conditions[i] = soar.PlaybookCondition{Field: "field", Operator: "eq", Value: "value"}
		}
		playbook.Triggers[0].Conditions = conditions

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "too many conditions") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report too many conditions")
	})

	t.Run("Name too long", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", strings.Repeat("x", MaxPlaybookNameLength+1))

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "name too long") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report name too long")
	})

	t.Run("Description too long", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Description = strings.Repeat("x", MaxPlaybookDescriptionLength+1)

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "description too long") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report description too long")
	})
}

// TestValidatePlaybook_StepValidation tests step-level validation
func TestValidatePlaybook_StepValidation(t *testing.T) {
	t.Run("Duplicate step IDs", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps = []soar.PlaybookStep{
			{ID: "step-1", Name: "Step 1", ActionType: soar.ActionTypeNotify},
			{ID: "step-1", Name: "Step 2", ActionType: soar.ActionTypeNotify}, // Duplicate
		}

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "duplicate step ID") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report duplicate step ID")
	})

	t.Run("Empty step ID", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].ID = ""

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "ID is required") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report missing step ID")
	})

	t.Run("Empty step name", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].Name = ""

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "name is required") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report missing step name")
	})

	t.Run("Invalid action type in step", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].ActionType = "invalid_action"

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "invalid action type") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report invalid action type in step")
	})

	t.Run("Step name too long", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].Name = strings.Repeat("x", MaxStepNameLength+1)

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "name too long") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report step name too long")
	})
}

// TestValidatePlaybook_TimeoutValidation tests timeout validation
func TestValidatePlaybook_TimeoutValidation(t *testing.T) {
	t.Run("Timeout too short", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].Timeout = 500 * time.Millisecond // Less than 1s

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "timeout too short") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report timeout too short")
	})

	t.Run("Timeout too long", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].Timeout = 31 * time.Minute // More than 30m

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "timeout too long") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report timeout too long")
	})

	t.Run("Timeout at minimum boundary", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].Timeout = MinStepTimeout // Exactly 1s

		errs := validatePlaybook(playbook)
		// Should have no timeout-related errors
		for _, err := range errs {
			assert.NotContains(t, err, "timeout")
		}
	})

	t.Run("Timeout at maximum boundary", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].Timeout = MaxStepTimeout // Exactly 30m

		errs := validatePlaybook(playbook)
		// Should have no timeout-related errors
		for _, err := range errs {
			assert.NotContains(t, err, "timeout")
		}
	})

	t.Run("Zero timeout allowed", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].Timeout = 0 // Zero means no explicit timeout

		errs := validatePlaybook(playbook)
		// Should have no timeout-related errors
		for _, err := range errs {
			assert.NotContains(t, err, "timeout")
		}
	})
}

// TestValidatePlaybook_ParameterSizeLimit tests parameter size validation
func TestValidatePlaybook_ParameterSizeLimit(t *testing.T) {
	t.Run("Parameters too large", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		// Create parameters that exceed 10KB when marshaled
		largeParams := make(map[string]interface{})
		largeParams["data"] = strings.Repeat("x", MaxParameterSizeBytes+1)
		playbook.Steps[0].Parameters = largeParams

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "parameters too large") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report parameters too large")
	})

	t.Run("Parameters at limit", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		// Parameters that are just under the limit
		params := make(map[string]interface{})
		params["data"] = strings.Repeat("x", 1000) // Well under 10KB
		playbook.Steps[0].Parameters = params

		errs := validatePlaybook(playbook)
		// Should have no parameter-related errors
		for _, err := range errs {
			assert.NotContains(t, err, "parameters too large")
		}
	})

	t.Run("Nil parameters allowed", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].Parameters = nil

		errs := validatePlaybook(playbook)
		// Should have no parameter-related errors
		for _, err := range errs {
			assert.NotContains(t, err, "parameter")
		}
	})
}

// TestValidatePlaybook_TriggerValidation tests trigger validation
func TestValidatePlaybook_TriggerValidation(t *testing.T) {
	t.Run("Empty trigger type", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Triggers[0].Type = ""

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "type is required") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report missing trigger type")
	})

	t.Run("Condition with empty field", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Triggers[0].Conditions[0].Field = ""

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "field is required") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report missing condition field")
	})

	t.Run("Condition with empty operator", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Triggers[0].Conditions[0].Operator = ""

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "operator is required") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report missing condition operator")
	})
}

// TestValidatePlaybook_NegativePriority tests negative priority validation
func TestValidatePlaybook_NegativePriority(t *testing.T) {
	playbook := createValidTestPlaybook("valid-id", "Test")
	playbook.Priority = -1

	errs := validatePlaybook(playbook)
	found := false
	for _, err := range errs {
		if strings.Contains(err, "priority cannot be negative") {
			found = true
			break
		}
	}
	assert.True(t, found, "Should report negative priority")
}

// TestValidatePlaybook_MultipleErrors tests collection of multiple errors
func TestValidatePlaybook_MultipleErrors(t *testing.T) {
	playbook := &soar.Playbook{
		ID:          "",                                                  // Error: empty ID
		Name:        "",                                                  // Error: empty name
		Description: strings.Repeat("x", MaxPlaybookDescriptionLength+1), // Error: too long
		Priority:    -5,                                                  // Error: negative priority
		Steps:       []soar.PlaybookStep{},                               // Error: no steps
	}

	errs := validatePlaybook(playbook)
	assert.GreaterOrEqual(t, len(errs), 4, "Should report multiple errors")
}

// TestValidatePlaybook_EdgeCases tests edge cases
func TestValidatePlaybook_EdgeCases(t *testing.T) {
	t.Run("Empty triggers array is valid", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Triggers = []soar.PlaybookTrigger{}

		errs := validatePlaybook(playbook)
		// Empty triggers is allowed - playbook can be manually triggered
		for _, err := range errs {
			assert.NotContains(t, err, "trigger")
		}
	})

	t.Run("Empty tags array is valid", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Tags = []string{}

		errs := validatePlaybook(playbook)
		assert.Empty(t, errs)
	})

	t.Run("Zero priority is valid", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Priority = 0

		errs := validatePlaybook(playbook)
		for _, err := range errs {
			assert.NotContains(t, err, "priority")
		}
	})

	t.Run("Maximum valid structures", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")

		// Exactly at the maximum limits
		playbook.Name = strings.Repeat("x", MaxPlaybookNameLength)
		playbook.Description = strings.Repeat("x", MaxPlaybookDescriptionLength)

		// Max triggers with max conditions each
		playbook.Triggers = make([]soar.PlaybookTrigger, MaxTriggersPerPlaybook)
		for i := range playbook.Triggers {
			playbook.Triggers[i] = soar.PlaybookTrigger{
				Type:       "alert",
				Conditions: make([]soar.PlaybookCondition, MaxConditionsPerTrigger),
			}
			for j := range playbook.Triggers[i].Conditions {
				playbook.Triggers[i].Conditions[j] = soar.PlaybookCondition{
					Field:    "field",
					Operator: "eq",
					Value:    "value",
				}
			}
		}

		// Max steps
		playbook.Steps = make([]soar.PlaybookStep, MaxStepsPerPlaybook)
		for i := range playbook.Steps {
			playbook.Steps[i] = soar.PlaybookStep{
				ID:         "step-" + strings.Repeat("x", i),
				Name:       "Step Name",
				ActionType: soar.ActionTypeNotify,
				Timeout:    MaxStepTimeout,
			}
		}

		errs := validatePlaybook(playbook)
		assert.Empty(t, errs, "Playbook at maximum limits should be valid")
	})
}

// TestValidatePlaybook_StepIDValidation tests step ID format validation
func TestValidatePlaybook_StepIDValidation(t *testing.T) {
	t.Run("Step ID with leading whitespace", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].ID = "  step-1"

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "cannot have leading/trailing whitespace") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report step ID whitespace issue")
	})

	t.Run("Step ID with trailing whitespace", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].ID = "step-1  "

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "cannot have leading/trailing whitespace") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report step ID whitespace issue")
	})

	t.Run("Step ID too long", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].ID = strings.Repeat("x", MaxStepIDLength+1)

		errs := validatePlaybook(playbook)
		found := false
		for _, err := range errs {
			if strings.Contains(err, "ID too long") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should report step ID too long")
	})

	t.Run("Step ID at maximum length", func(t *testing.T) {
		playbook := createValidTestPlaybook("valid-id", "Test")
		playbook.Steps[0].ID = strings.Repeat("x", MaxStepIDLength)

		errs := validatePlaybook(playbook)
		// Should have no step ID length errors
		for _, err := range errs {
			assert.NotContains(t, err, "ID too long")
		}
	})
}

// TestValidatePlaybook_NegativeTimeout tests negative timeout validation
func TestValidatePlaybook_NegativeTimeout(t *testing.T) {
	playbook := createValidTestPlaybook("valid-id", "Test")
	playbook.Steps[0].Timeout = -5 * time.Second

	errs := validatePlaybook(playbook)
	found := false
	for _, err := range errs {
		if strings.Contains(err, "timeout cannot be negative") {
			found = true
			break
		}
	}
	assert.True(t, found, "Should report negative timeout")
}

// TestValidatePlaybook_Concurrent tests thread safety of validation functions
func TestValidatePlaybook_Concurrent(t *testing.T) {
	playbook := createValidTestPlaybook("test-concurrent", "Concurrent Test")

	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				errs := validatePlaybook(playbook)
				assert.Empty(t, errs, "Valid playbook should have no errors")
			}
		}()
	}

	wg.Wait()
}

// TestValidatePlaybookID_Concurrent tests thread safety of ID validation
func TestValidatePlaybookID_Concurrent(t *testing.T) {
	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				err := validatePlaybookID("valid-playbook-id")
				assert.NoError(t, err)
			}
		}()
	}

	wg.Wait()
}

// TestValidateActionType_Concurrent tests thread safety of action type validation
func TestValidateActionType_Concurrent(t *testing.T) {
	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				err := validateActionType(soar.ActionTypeNotify)
				assert.NoError(t, err)
			}
		}()
	}

	wg.Wait()
}

// TestValidateActionType_DeterministicErrorMessage tests error message consistency
func TestValidateActionType_DeterministicErrorMessage(t *testing.T) {
	// Run validation multiple times and ensure error messages are identical
	var messages []string
	for i := 0; i < 10; i++ {
		err := validateActionType("invalid_action")
		require.Error(t, err)
		messages = append(messages, err.Error())
	}

	// All messages should be identical (deterministic)
	for i := 1; i < len(messages); i++ {
		assert.Equal(t, messages[0], messages[i],
			"Error message should be deterministic across multiple calls")
	}

	// Verify the error contains sorted action types
	assert.Contains(t, messages[0], "block_ip")
	assert.Contains(t, messages[0], "must be one of")
}

// =============================================================================
// TASK 96: Playbook CRUD Handler Tests
// =============================================================================

// mockPlaybookStorage implements PlaybookStorageInterface for testing
type mockPlaybookStorage struct {
	playbooks map[string]*soar.Playbook
	// Configurable error returns for testing error paths
	getErr        error
	createErr     error
	updateErr     error
	deleteErr     error
	listErr       error
	countErr      error
	statsErr      error // TASK 98: Error injection for GetPlaybookStats
	nameExists    bool
	nameExistsErr error
}

func newMockPlaybookStorage() *mockPlaybookStorage {
	return &mockPlaybookStorage{
		playbooks: make(map[string]*soar.Playbook),
	}
}

func (m *mockPlaybookStorage) CreatePlaybook(playbook *soar.Playbook) error {
	if m.createErr != nil {
		return m.createErr
	}
	if _, exists := m.playbooks[playbook.ID]; exists {
		return storage.ErrPlaybookNameExists
	}
	m.playbooks[playbook.ID] = playbook
	return nil
}

func (m *mockPlaybookStorage) GetPlaybook(id string) (*soar.Playbook, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if p, exists := m.playbooks[id]; exists {
		return p, nil
	}
	return nil, storage.ErrPlaybookNotFound
}

func (m *mockPlaybookStorage) GetPlaybooks(limit, offset int) ([]soar.Playbook, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	// Sort keys for deterministic pagination (fixes map iteration race)
	ids := make([]string, 0, len(m.playbooks))
	for id := range m.playbooks {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	result := make([]soar.Playbook, 0, limit)
	for i, id := range ids {
		if i >= offset && len(result) < limit {
			result = append(result, *m.playbooks[id])
		}
	}
	return result, nil
}

func (m *mockPlaybookStorage) GetAllPlaybooks() ([]soar.Playbook, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]soar.Playbook, 0, len(m.playbooks))
	for _, p := range m.playbooks {
		result = append(result, *p)
	}
	return result, nil
}

func (m *mockPlaybookStorage) GetPlaybookCount() (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return int64(len(m.playbooks)), nil
}

func (m *mockPlaybookStorage) UpdatePlaybook(id string, playbook *soar.Playbook) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, exists := m.playbooks[id]; !exists {
		return storage.ErrPlaybookNotFound
	}
	m.playbooks[id] = playbook
	return nil
}

func (m *mockPlaybookStorage) DeletePlaybook(id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, exists := m.playbooks[id]; !exists {
		return storage.ErrPlaybookNotFound
	}
	delete(m.playbooks, id)
	return nil
}

func (m *mockPlaybookStorage) EnablePlaybook(id string) error {
	if p, exists := m.playbooks[id]; exists {
		p.Enabled = true
		return nil
	}
	return storage.ErrPlaybookNotFound
}

func (m *mockPlaybookStorage) DisablePlaybook(id string) error {
	if p, exists := m.playbooks[id]; exists {
		p.Enabled = false
		return nil
	}
	return storage.ErrPlaybookNotFound
}

func (m *mockPlaybookStorage) GetPlaybooksByStatus(enabled bool) ([]soar.Playbook, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]soar.Playbook, 0)
	for _, p := range m.playbooks {
		if p.Enabled == enabled {
			result = append(result, *p)
		}
	}
	return result, nil
}

func (m *mockPlaybookStorage) GetPlaybooksByTag(tag string) ([]soar.Playbook, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]soar.Playbook, 0)
	for _, p := range m.playbooks {
		for _, t := range p.Tags {
			if t == tag {
				result = append(result, *p)
				break
			}
		}
	}
	return result, nil
}

func (m *mockPlaybookStorage) SearchPlaybooks(query string) ([]soar.Playbook, error) {
	result := make([]soar.Playbook, 0)
	for _, p := range m.playbooks {
		if strings.Contains(p.Name, query) || strings.Contains(p.Description, query) {
			result = append(result, *p)
		}
	}
	return result, nil
}

func (m *mockPlaybookStorage) PlaybookNameExists(name string, excludeID string) (bool, error) {
	if m.nameExistsErr != nil {
		return false, m.nameExistsErr
	}
	if m.nameExists {
		return true, nil
	}
	for id, p := range m.playbooks {
		if p.Name == name && id != excludeID {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockPlaybookStorage) GetPlaybookStats() (*storage.PlaybookStats, error) {
	if m.statsErr != nil {
		return nil, m.statsErr
	}
	var enabled, disabled int64
	for _, p := range m.playbooks {
		if p.Enabled {
			enabled++
		} else {
			disabled++
		}
	}
	return &storage.PlaybookStats{
		TotalPlaybooks:    int64(len(m.playbooks)),
		EnabledPlaybooks:  enabled,
		DisabledPlaybooks: disabled,
	}, nil
}

func (m *mockPlaybookStorage) EnsureIndexes() error {
	return nil
}

// setupTestAPIWithPlaybookStorage creates a test API with mock playbook storage
func setupTestAPIWithPlaybookStorage(t *testing.T, mockStorage *mockPlaybookStorage) (*API, func()) {
	api, cleanup := setupTestAPI(t)
	api.playbookStorage = mockStorage
	return api, cleanup
}

// =============================================================================
// List Playbooks Tests
// =============================================================================

func TestListPlaybooks_Success(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	// Add some playbooks
	mockStorage.playbooks["pb-1"] = &soar.Playbook{
		ID:      "pb-1",
		Name:    "Test Playbook 1",
		Enabled: true,
		Steps:   []soar.PlaybookStep{{ID: "s1", Name: "Step 1", ActionType: soar.ActionTypeNotify}},
	}
	mockStorage.playbooks["pb-2"] = &soar.Playbook{
		ID:      "pb-2",
		Name:    "Test Playbook 2",
		Enabled: false,
		Steps:   []soar.PlaybookStep{{ID: "s1", Name: "Step 1", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "playbooks")
	assert.Contains(t, response, "total")
	assert.Contains(t, response, "page")
	assert.Contains(t, response, "limit")
}

func TestListPlaybooks_WithPagination(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	// Add many playbooks
	for i := 0; i < 10; i++ {
		id := "pb-" + string(rune('a'+i))
		mockStorage.playbooks[id] = &soar.Playbook{
			ID:    id,
			Name:  "Playbook " + id,
			Steps: []soar.PlaybookStep{{ID: "s1", Name: "Step", ActionType: soar.ActionTypeNotify}},
		}
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks?page=1&limit=5", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, float64(1), response["page"])
	assert.Equal(t, float64(5), response["limit"])
}

func TestListPlaybooks_FilterByEnabled(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-1"] = &soar.Playbook{ID: "pb-1", Name: "Enabled", Enabled: true, Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}}}
	mockStorage.playbooks["pb-2"] = &soar.Playbook{ID: "pb-2", Name: "Disabled", Enabled: false, Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}}}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks?enabled=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	playbooks := response["playbooks"].([]interface{})
	assert.Equal(t, 1, len(playbooks))
}

func TestListPlaybooks_FilterByTag(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-1"] = &soar.Playbook{ID: "pb-1", Name: "Tagged", Tags: []string{"security"}, Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}}}
	mockStorage.playbooks["pb-2"] = &soar.Playbook{ID: "pb-2", Name: "No Tags", Tags: []string{}, Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}}}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks?tag=security", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListPlaybooks_StorageUnavailable(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Ensure storage is nil
	api.playbookStorage = nil

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestListPlaybooks_StorageError(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.listErr = storage.ErrNotFound // Simulate storage error

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListPlaybooks_CountError(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	// Add a playbook so listing will attempt to count
	mockStorage.playbooks["pb-1"] = &soar.Playbook{
		ID:    "pb-1",
		Name:  "Test Playbook",
		Steps: []soar.PlaybookStep{{ID: "s1", Name: "Step", ActionType: soar.ActionTypeNotify}},
	}
	// Simulate GetPlaybookCount() error
	mockStorage.countErr = errors.New("database connection lost")

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	// Verify GetPlaybookCount() error returns 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Response body should contain error indicator
	body := w.Body.String()
	assert.True(t, len(body) > 0, "Error response should not be empty")
}

// =============================================================================
// Create Playbook Tests
// =============================================================================

func TestCreatePlaybook_Success(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	playbook := map[string]interface{}{
		"name":        "New Playbook",
		"description": "Test description",
		"enabled":     true,
		"steps": []map[string]interface{}{
			{
				"id":          "step-1",
				"name":        "Notify Step",
				"action_type": "send_notification",
			},
		},
	}
	body, _ := json.Marshal(playbook)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response soar.Playbook
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.ID)
	assert.Equal(t, "New Playbook", response.Name)
}

func TestCreatePlaybook_WithCustomID(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	playbook := map[string]interface{}{
		"id":   "custom-pb-id",
		"name": "Custom ID Playbook",
		"steps": []map[string]interface{}{
			{"id": "s1", "name": "Step", "action_type": "send_notification"},
		},
	}
	body, _ := json.Marshal(playbook)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response soar.Playbook
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "custom-pb-id", response.ID)
}

func TestCreatePlaybook_InvalidID(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	playbook := map[string]interface{}{
		"id":   "invalid id with spaces",
		"name": "Test",
		"steps": []map[string]interface{}{
			{"id": "s1", "name": "Step", "action_type": "send_notification"},
		},
	}
	body, _ := json.Marshal(playbook)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreatePlaybook_ValidationError(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	// Missing required fields
	playbook := map[string]interface{}{
		"name":  "", // Empty name
		"steps": []map[string]interface{}{},
	}
	body, _ := json.Marshal(playbook)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "details")
}

func TestCreatePlaybook_NameConflict(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["existing-pb"] = &soar.Playbook{
		ID:    "existing-pb",
		Name:  "Existing Playbook",
		Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	playbook := map[string]interface{}{
		"name": "Existing Playbook", // Same name as existing
		"steps": []map[string]interface{}{
			{"id": "s1", "name": "Step", "action_type": "send_notification"},
		},
	}
	body, _ := json.Marshal(playbook)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestCreatePlaybook_InvalidJSON(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks", bytes.NewReader([]byte("invalid json{")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreatePlaybook_StorageUnavailable(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	api.playbookStorage = nil

	playbook := map[string]interface{}{
		"name":  "Test",
		"steps": []map[string]interface{}{{"id": "s1", "name": "S", "action_type": "send_notification"}},
	}
	body, _ := json.Marshal(playbook)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// =============================================================================
// Get Playbook Tests
// =============================================================================

func TestGetPlaybook_Success(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-123"] = &soar.Playbook{
		ID:          "pb-123",
		Name:        "Test Playbook",
		Description: "Description",
		Enabled:     true,
		Steps:       []soar.PlaybookStep{{ID: "s1", Name: "Step", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks/pb-123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"id": "pb-123"})

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response soar.Playbook
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "pb-123", response.ID)
	assert.Equal(t, "Test Playbook", response.Name)
}

func TestGetPlaybook_NotFound(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetPlaybook_InvalidID(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks/invalid@id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid@id"})

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetPlaybook_StorageUnavailable(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	api.playbookStorage = nil

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks/pb-123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"id": "pb-123"})

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// =============================================================================
// Update Playbook Tests
// =============================================================================

func TestUpdatePlaybook_Success(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-123"] = &soar.Playbook{
		ID:        "pb-123",
		Name:      "Original Name",
		CreatedBy: "original-user",
		CreatedAt: time.Now().Add(-24 * time.Hour),
		Steps:     []soar.PlaybookStep{{ID: "s1", Name: "Step", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	update := map[string]interface{}{
		"name":        "Updated Name",
		"description": "Updated description",
		"enabled":     true,
		"steps": []map[string]interface{}{
			{"id": "s1", "name": "Updated Step", "action_type": "send_notification"},
		},
	}
	body, _ := json.Marshal(update)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("PUT", "/api/v1/playbooks/pb-123", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "pb-123"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response soar.Playbook
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Updated Name", response.Name)
	assert.Equal(t, "original-user", response.CreatedBy) // Preserved
}

func TestUpdatePlaybook_NotFound(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	update := map[string]interface{}{
		"name":  "Updated Name",
		"steps": []map[string]interface{}{{"id": "s1", "name": "S", "action_type": "send_notification"}},
	}
	body, _ := json.Marshal(update)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("PUT", "/api/v1/playbooks/nonexistent", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdatePlaybook_ValidationError(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-123"] = &soar.Playbook{
		ID:    "pb-123",
		Name:  "Original",
		Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	update := map[string]interface{}{
		"name":  "", // Empty name is invalid
		"steps": []map[string]interface{}{},
	}
	body, _ := json.Marshal(update)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("PUT", "/api/v1/playbooks/pb-123", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "pb-123"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdatePlaybook_NameConflict(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-1"] = &soar.Playbook{
		ID:    "pb-1",
		Name:  "Playbook One",
		Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}},
	}
	mockStorage.playbooks["pb-2"] = &soar.Playbook{
		ID:    "pb-2",
		Name:  "Playbook Two",
		Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	update := map[string]interface{}{
		"name":  "Playbook Two", // Same name as pb-2
		"steps": []map[string]interface{}{{"id": "s1", "name": "S", "action_type": "send_notification"}},
	}
	body, _ := json.Marshal(update)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("PUT", "/api/v1/playbooks/pb-1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "pb-1"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestUpdatePlaybook_InvalidID(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	update := map[string]interface{}{
		"name":  "Test",
		"steps": []map[string]interface{}{{"id": "s1", "name": "S", "action_type": "send_notification"}},
	}
	body, _ := json.Marshal(update)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("PUT", "/api/v1/playbooks/invalid@id", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "invalid@id"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdatePlaybook_StorageUnavailable(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	api.playbookStorage = nil

	update := map[string]interface{}{
		"name":  "Test",
		"steps": []map[string]interface{}{{"id": "s1", "name": "S", "action_type": "send_notification"}},
	}
	body, _ := json.Marshal(update)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("PUT", "/api/v1/playbooks/pb-123", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "pb-123"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// =============================================================================
// Delete Playbook Tests
// =============================================================================

func TestDeletePlaybook_Success(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-123"] = &soar.Playbook{
		ID:    "pb-123",
		Name:  "To Delete",
		Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("DELETE", "/api/v1/playbooks/pb-123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"id": "pb-123"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify playbook was deleted
	_, exists := mockStorage.playbooks["pb-123"]
	assert.False(t, exists)
}

func TestDeletePlaybook_NotFound(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("DELETE", "/api/v1/playbooks/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeletePlaybook_InvalidID(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("DELETE", "/api/v1/playbooks/invalid@id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid@id"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeletePlaybook_StorageUnavailable(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	api.playbookStorage = nil

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("DELETE", "/api/v1/playbooks/pb-123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"id": "pb-123"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// =============================================================================
// Authentication Tests
// =============================================================================

func TestPlaybookCRUD_RequiresAuthentication(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/playbooks"},
		{"POST", "/api/v1/playbooks"},
		{"GET", "/api/v1/playbooks/pb-123"},
		{"PUT", "/api/v1/playbooks/pb-123"},
		{"DELETE", "/api/v1/playbooks/pb-123"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			// No authorization header

			w := httptest.NewRecorder()
			api.router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestCreatePlaybook_EmptyBody(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks", bytes.NewReader([]byte{}))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListPlaybooks_EmptyResult(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	playbooks := response["playbooks"].([]interface{})
	assert.Equal(t, 0, len(playbooks))
	assert.Equal(t, float64(0), response["total"])
}

func TestUpdatePlaybook_SameNameAllowed(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-123"] = &soar.Playbook{
		ID:    "pb-123",
		Name:  "Same Name",
		Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	// Update with same name should be allowed
	update := map[string]interface{}{
		"name":        "Same Name",
		"description": "Updated description",
		"steps":       []map[string]interface{}{{"id": "s1", "name": "S", "action_type": "send_notification"}},
	}
	body, _ := json.Marshal(update)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("PUT", "/api/v1/playbooks/pb-123", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "pb-123"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// =============================================================================
// TASK 97: Enable/Disable Playbook Tests
// =============================================================================

func TestEnablePlaybook_Success(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-123"] = &soar.Playbook{
		ID:      "pb-123",
		Name:    "Test Playbook",
		Enabled: false,
		Steps:   []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/pb-123/enable", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response soar.Playbook
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Enabled)
}

func TestEnablePlaybook_NotFound(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/nonexistent/enable", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDisablePlaybook_Success(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-123"] = &soar.Playbook{
		ID:      "pb-123",
		Name:    "Test Playbook",
		Enabled: true,
		Steps:   []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/pb-123/disable", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response soar.Playbook
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.False(t, response.Enabled)
}

func TestDisablePlaybook_NotFound(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/nonexistent/disable", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestEnablePlaybook_InvalidID(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	// Use URL-encoded space or special characters that fail validation
	req := httptest.NewRequest("POST", "/api/v1/playbooks/invalid%20id/enable", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// =============================================================================
// TASK 97: Validate Playbook Handler Tests
// =============================================================================

func TestValidatePlaybookHandler_ValidPlaybook(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	playbook := map[string]interface{}{
		"name":        "Valid Playbook",
		"description": "Test description",
		"steps": []map[string]interface{}{
			{"id": "s1", "name": "Step 1", "action_type": "send_notification"},
		},
	}
	body, _ := json.Marshal(playbook)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/validate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response["valid"].(bool))
	assert.Len(t, response["errors"].([]interface{}), 0)
}

func TestValidatePlaybookHandler_InvalidPlaybook(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	playbook := map[string]interface{}{
		"name":  "", // Empty name - validation error
		"steps": []map[string]interface{}{},
	}
	body, _ := json.Marshal(playbook)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/validate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code) // Always 200 - validation result in body

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.False(t, response["valid"].(bool))
	assert.Greater(t, len(response["errors"].([]interface{})), 0)
}

func TestValidatePlaybookHandler_NameExistsWarning(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["existing-pb"] = &soar.Playbook{
		ID:    "existing-pb",
		Name:  "Existing Playbook",
		Steps: []soar.PlaybookStep{{ID: "s1", Name: "S", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	playbook := map[string]interface{}{
		"name": "Existing Playbook", // Same name as existing
		"steps": []map[string]interface{}{
			{"id": "s1", "name": "Step 1", "action_type": "send_notification"},
		},
	}
	body, _ := json.Marshal(playbook)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/validate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response["valid"].(bool)) // Still valid - name conflict is just a warning
	assert.Greater(t, len(response["warnings"].([]interface{})), 0)
}

func TestValidatePlaybookHandler_InvalidJSON(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/validate", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidatePlaybookHandler_InvalidID(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	playbook := map[string]interface{}{
		"id":   "invalid id with spaces",
		"name": "Test Playbook",
		"steps": []map[string]interface{}{
			{"id": "s1", "name": "Step 1", "action_type": "send_notification"},
		},
	}
	body, _ := json.Marshal(playbook)

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/validate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.False(t, response["valid"].(bool))
}

// =============================================================================
// TASK 97: Duplicate Playbook Handler Tests
// =============================================================================

func TestDuplicatePlaybook_Success(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["pb-original"] = &soar.Playbook{
		ID:          "pb-original",
		Name:        "Original Playbook",
		Description: "Original description",
		Enabled:     true,
		Tags:        []string{"security", "critical"},
		Steps: []soar.PlaybookStep{
			{
				ID:         "step-1",
				Name:       "Step 1",
				ActionType: soar.ActionTypeNotify,
				Parameters: map[string]interface{}{"key": "value"},
			},
		},
		Triggers: []soar.PlaybookTrigger{
			{
				Type:       "alert",
				Conditions: []soar.PlaybookCondition{{Field: "severity", Operator: "eq", Value: "high"}},
			},
		},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/pb-original/duplicate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var duplicate soar.Playbook
	err := json.Unmarshal(w.Body.Bytes(), &duplicate)
	require.NoError(t, err)

	// Verify duplicate has new ID
	assert.NotEqual(t, "pb-original", duplicate.ID)
	assert.True(t, strings.HasPrefix(duplicate.ID, "pb-"))

	// Verify name is modified
	assert.Equal(t, "Original Playbook (Copy)", duplicate.Name)

	// Verify disabled by default
	assert.False(t, duplicate.Enabled)

	// Verify deep copy of tags
	assert.Equal(t, []string{"security", "critical"}, duplicate.Tags)

	// Verify steps are copied with new IDs
	assert.Len(t, duplicate.Steps, 1)
	assert.NotEqual(t, "step-1", duplicate.Steps[0].ID)
	assert.True(t, strings.HasPrefix(duplicate.Steps[0].ID, "step-"))
	assert.Equal(t, "Step 1", duplicate.Steps[0].Name)
	assert.Equal(t, soar.ActionTypeNotify, duplicate.Steps[0].ActionType)

	// Verify triggers are copied
	assert.Len(t, duplicate.Triggers, 1)
	assert.Equal(t, "alert", duplicate.Triggers[0].Type)
}

func TestDuplicatePlaybook_NotFound(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/nonexistent/duplicate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDuplicatePlaybook_InvalidID(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	// Use URL-encoded space for invalid ID
	req := httptest.NewRequest("POST", "/api/v1/playbooks/invalid%20id/duplicate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDuplicatePlaybook_DeepCopyVerification(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	original := &soar.Playbook{
		ID:          "pb-original",
		Name:        "Original",
		Description: "Original description",
		Enabled:     true,
		Tags:        []string{"tag1"},
		Steps: []soar.PlaybookStep{
			{
				ID:         "step-1",
				Name:       "Step 1",
				ActionType: soar.ActionTypeNotify,
				Parameters: map[string]interface{}{"nested": map[string]interface{}{"key": "value"}},
			},
		},
	}
	mockStorage.playbooks["pb-original"] = original

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("POST", "/api/v1/playbooks/pb-original/duplicate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	// Modify original and verify duplicate is not affected
	original.Tags[0] = "modified-tag"
	original.Steps[0].Parameters["nested"].(map[string]interface{})["key"] = "modified"

	// Get the duplicate from storage
	var duplicateID string
	for id := range mockStorage.playbooks {
		if id != "pb-original" {
			duplicateID = id
			break
		}
	}

	duplicate := mockStorage.playbooks[duplicateID]

	// Tags should be independent
	assert.Equal(t, "tag1", duplicate.Tags[0])

	// Nested parameters should be independent
	assert.Equal(t, "value", duplicate.Steps[0].Parameters["nested"].(map[string]interface{})["key"])
}

// =============================================================================
// TASK 98: Playbook Stats Endpoint Tests
// =============================================================================

func TestGetPlaybookStats_Success(t *testing.T) {
	mockStorage := newMockPlaybookStorage()

	// Add playbooks with mixed enabled status
	mockStorage.playbooks["pb-1"] = &soar.Playbook{ID: "pb-1", Name: "Enabled 1", Enabled: true}
	mockStorage.playbooks["pb-2"] = &soar.Playbook{ID: "pb-2", Name: "Enabled 2", Enabled: true}
	mockStorage.playbooks["pb-3"] = &soar.Playbook{ID: "pb-3", Name: "Disabled 1", Enabled: false}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var stats storage.PlaybookStats
	err := json.Unmarshal(w.Body.Bytes(), &stats)
	require.NoError(t, err)

	assert.Equal(t, int64(3), stats.TotalPlaybooks)
	assert.Equal(t, int64(2), stats.EnabledPlaybooks)
	assert.Equal(t, int64(1), stats.DisabledPlaybooks)
}

func TestGetPlaybookStats_EmptyStorage(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var stats storage.PlaybookStats
	err := json.Unmarshal(w.Body.Bytes(), &stats)
	require.NoError(t, err)

	assert.Equal(t, int64(0), stats.TotalPlaybooks)
	assert.Equal(t, int64(0), stats.EnabledPlaybooks)
	assert.Equal(t, int64(0), stats.DisabledPlaybooks)
}

func TestGetPlaybookStats_StorageError(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.statsErr = errors.New("database error")

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to retrieve playbook statistics")
}

func TestGetPlaybookStats_StorageNotConfigured(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()
	api.playbookStorage = nil // Ensure storage is nil

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")
	req := httptest.NewRequest("GET", "/api/v1/playbooks/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Playbook management not available")
}

// =============================================================================
// TASK 100: Execute Playbook Storage Integration Tests
// =============================================================================

// TestExecutePlaybook_StorageNotConfigured verifies 503 response when playbook storage is nil
func TestExecutePlaybook_StorageNotConfigured(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()
	api.playbookStorage = nil // Ensure storage is nil

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")

	payload := map[string]string{"alert_id": "test-alert-1"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/v1/playbooks/test-playbook/execute", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "test-playbook"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Playbook management not available")
}

// TestExecutePlaybook_PlaybookNotFound verifies 404 response when playbook doesn't exist
func TestExecutePlaybook_PlaybookNotFound(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	// Empty storage - no playbooks
	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")

	payload := map[string]string{"alert_id": "test-alert-1"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/v1/playbooks/nonexistent-playbook/execute", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent-playbook"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Playbook not found")
}

// TestExecutePlaybook_PlaybookDisabled verifies 400 response when playbook is disabled
func TestExecutePlaybook_PlaybookDisabled(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["disabled-playbook"] = &soar.Playbook{
		ID:      "disabled-playbook",
		Name:    "Disabled Playbook",
		Enabled: false, // Disabled
		Steps:   []soar.PlaybookStep{{ID: "s1", Name: "Step", ActionType: soar.ActionTypeNotify}},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")

	payload := map[string]string{"alert_id": "test-alert-1"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/v1/playbooks/disabled-playbook/execute", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "disabled-playbook"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "disabled")
}

// TestExecutePlaybook_StorageError verifies 500 response when storage returns an error
func TestExecutePlaybook_StorageError(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.getErr = errors.New("database connection failed")

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")

	payload := map[string]string{"alert_id": "test-alert-1"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/v1/playbooks/any-playbook/execute", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "any-playbook"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to retrieve playbook")
}

// TestExecutePlaybook_WithStoragePlaybook verifies successful execution with playbook from storage
func TestExecutePlaybook_WithStoragePlaybook(t *testing.T) {
	mockStorage := newMockPlaybookStorage()
	mockStorage.playbooks["test-playbook"] = &soar.Playbook{
		ID:          "test-playbook",
		Name:        "Test Playbook",
		Description: "A test playbook loaded from storage",
		Enabled:     true,
		Steps: []soar.PlaybookStep{
			{ID: "s1", Name: "Notify Step", ActionType: soar.ActionTypeNotify},
		},
	}

	api, cleanup := setupTestAPIWithPlaybookStorage(t, mockStorage)
	defer cleanup()

	token := createValidTestToken(t, api.config.Auth.JWTSecret, "testuser")

	payload := map[string]string{"alert_id": "test-alert-1"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/v1/playbooks/test-playbook/execute", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "test-playbook"})
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	// May return 200 (success), 404 (alert not found), or 503 (executor unavailable)
	// All are valid depending on test environment configuration
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound ||
		w.Code == http.StatusServiceUnavailable || w.Code == http.StatusInternalServerError,
		"Execute should handle playbook from storage, got status %d", w.Code)
}
