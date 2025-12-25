package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"cerberus/core"
	"cerberus/storage"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateInvestigation_Success tests successful investigation creation
// REQUIREMENT: Test createInvestigation handler (26.9% coverage → target 80%)
// COVERAGE TARGET: All happy path branches
func TestCreateInvestigation_Success(t *testing.T) {
	// Setup test API
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Ensure users exist (required for foreign key constraints)
	ensureTestUser(t, testAPI, "admin")       // For JWT token/created_by
	ensureTestUser(t, testAPI, "analyst-001") // For assignee
	ensureTestUser(t, testAPI, "system")      // For fallback user

	// Create test request
	req := CreateInvestigationRequest{
		Title:       "Suspected Lateral Movement",
		Description: "Multiple failed login attempts followed by successful authentication",
		Priority:    core.InvestigationPriorityCritical,
		AssigneeID:  "analyst-001",
		AlertIDs:    []string{"alert-001", "alert-002"},
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)

	// Create HTTP request with auth
	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	httpReq := httptest.NewRequest("POST", "/api/v1/investigations", bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, httpReq)

	// Execute request
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	// Verify response
	assert.Equal(t, http.StatusCreated, w.Code)

	var response core.Investigation
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.InvestigationID)
	assert.Equal(t, "Suspected Lateral Movement", response.Title)
	assert.Equal(t, "Multiple failed login attempts followed by successful authentication", response.Description)
	assert.Equal(t, core.InvestigationPriorityCritical, response.Priority)
	assert.Equal(t, core.InvestigationStatusOpen, response.Status)
	assert.Equal(t, "analyst-001", response.AssigneeID)
	assert.Equal(t, []string{"alert-001", "alert-002"}, response.AlertIDs)
}

// TestCreateInvestigation_ValidationErrors tests validation error handling
// REQUIREMENT: Test input validation for createInvestigation
// COVERAGE TARGET: Error paths for validation failures
func TestCreateInvestigation_ValidationErrors(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	tests := []struct {
		name           string
		request        CreateInvestigationRequest
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Empty title",
			request: CreateInvestigationRequest{
				Title:       "",
				Description: "Test description",
				Priority:    core.InvestigationPriorityCritical,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Validation failed",
		},
		{
			name: "Title too long",
			request: CreateInvestigationRequest{
				Title:       string(make([]byte, 201)), // 201 chars (max is 200)
				Description: "Test description",
				Priority:    core.InvestigationPriorityCritical,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Validation failed",
		},
		{
			name: "Description too long",
			request: CreateInvestigationRequest{
				Title:       "Test Investigation",
				Description: string(make([]byte, 2001)), // 2001 chars (max is 2000)
				Priority:    core.InvestigationPriorityCritical,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Validation failed",
		},
		{
			name: "Missing priority",
			request: CreateInvestigationRequest{
				Title:       "Test Investigation",
				Description: "Test description",
				// Priority not set
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
			httpReq := httptest.NewRequest("POST", "/api/v1/investigations", bytes.NewReader(body))
			httpReq.Header.Set("Authorization", "Bearer "+token)
			addCSRFToRequest(t, httpReq)
			httpReq.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, httpReq)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// TestCreateInvestigation_InvalidJSON tests JSON parsing error
// REQUIREMENT: Test error handling for malformed requests
func TestCreateInvestigation_InvalidJSON(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	httpReq := httptest.NewRequest("POST", "/api/v1/investigations", bytes.NewReader([]byte("invalid json")))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid request body")
}

// TestCloseInvestigation_Success tests successful investigation closure
// REQUIREMENT: Test closeInvestigation handler (40.9% coverage → target 80%)
// COVERAGE TARGET: All verdict types and ML feedback integration
func TestCloseInvestigation_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create investigation first
	investigation := createTestInvestigation(t, testAPI, "Test Investigation", core.InvestigationPriorityCritical)

	// Close investigation with verdict
	closeReq := CloseInvestigationRequest{
		Verdict:            core.InvestigationVerdictTruePositive,
		ResolutionCategory: "incident_contained",
		Summary:            "Successfully identified and contained lateral movement attack",
		AffectedAssets:     []string{"host-001", "host-002"},
		MLFeedback: &core.MLFeedback{
			UseForTraining:  true,
			MLQualityRating: 5,
			MLHelpfulness:   "very_helpful",
		},
	}

	body, err := json.Marshal(closeReq)
	require.NoError(t, err)

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	url := fmt.Sprintf("/api/v1/investigations/%s/close", investigation.InvestigationID)
	httpReq := httptest.NewRequest("POST", url, bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	// Add mux vars for ID
	httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var response core.Investigation
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, core.InvestigationStatusResolved, response.Status) // Handler sets to "resolved" when closing
	assert.Equal(t, core.InvestigationVerdictTruePositive, response.Verdict)
	assert.Equal(t, "incident_contained", response.ResolutionCategory)
	assert.Equal(t, "Successfully identified and contained lateral movement attack", response.Summary)
	assert.Equal(t, []string{"host-001", "host-002"}, response.AffectedAssets)
	assert.NotNil(t, response.MLFeedback)
	assert.True(t, response.MLFeedback.UseForTraining)
	assert.Equal(t, 5, response.MLFeedback.MLQualityRating)
}

// TestCloseInvestigation_AllVerdictTypes tests all verdict types
// REQUIREMENT: Test complete verdict enum coverage
func TestCloseInvestigation_AllVerdictTypes(t *testing.T) {
	verdicts := []struct {
		verdict  core.InvestigationVerdict
		category string
		summary  string
	}{
		{core.InvestigationVerdictTruePositive, "incident_confirmed", "Confirmed security incident"},
		{core.InvestigationVerdictFalsePositive, "benign_activity", "False positive - normal business activity"},
		{core.InvestigationVerdictInconclusive, "insufficient_data", "Insufficient data to determine"},
	}

	for _, vt := range verdicts {
		t.Run(string(vt.verdict), func(t *testing.T) {
			testAPI, cleanup := setupTestAPI(t)
			defer cleanup()

			investigation := createTestInvestigation(t, testAPI, "Test Investigation", core.InvestigationPriorityMedium)

			closeReq := CloseInvestigationRequest{
				Verdict:            vt.verdict,
				ResolutionCategory: vt.category,
				Summary:            vt.summary,
			}

			body, err := json.Marshal(closeReq)
			require.NoError(t, err)

			token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
			url := fmt.Sprintf("/api/v1/investigations/%s/close", investigation.InvestigationID)
			httpReq := httptest.NewRequest("POST", url, bytes.NewReader(body))
			httpReq.Header.Set("Authorization", "Bearer "+token)
			addCSRFToRequest(t, httpReq)
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, httpReq)

			assert.Equal(t, http.StatusOK, w.Code)

			var response core.Investigation
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Equal(t, vt.verdict, response.Verdict)
			assert.Equal(t, vt.category, response.ResolutionCategory)
		})
	}
}

// TestCloseInvestigation_ValidationErrors tests close validation
// REQUIREMENT: Test validation error handling for closure
func TestCloseInvestigation_ValidationErrors(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	investigation := createTestInvestigation(t, testAPI, "Test Investigation", core.InvestigationPriorityMedium)

	tests := []struct {
		name           string
		request        CloseInvestigationRequest
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Missing verdict",
			request: CloseInvestigationRequest{
				// Verdict missing
				ResolutionCategory: "incident_contained",
				Summary:            "Test summary",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Validation failed",
		},
		{
			name: "Missing resolution category",
			request: CloseInvestigationRequest{
				Verdict: core.InvestigationVerdictTruePositive,
				// ResolutionCategory missing
				Summary: "Test summary",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Validation failed",
		},
		{
			name: "Missing summary",
			request: CloseInvestigationRequest{
				Verdict:            core.InvestigationVerdictTruePositive,
				ResolutionCategory: "incident_contained",
				// Summary missing
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Validation failed",
		},
		{
			name: "Summary too long",
			request: CloseInvestigationRequest{
				Verdict:            core.InvestigationVerdictTruePositive,
				ResolutionCategory: "incident_contained",
				Summary:            string(make([]byte, 5001)), // 5001 chars (max is 5000)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
			url := fmt.Sprintf("/api/v1/investigations/%s/close", investigation.InvestigationID)
			httpReq := httptest.NewRequest("POST", url, bytes.NewReader(body))
			httpReq.Header.Set("Authorization", "Bearer "+token)
			addCSRFToRequest(t, httpReq)
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, httpReq)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// TestGetInvestigationTimeline_Success tests timeline retrieval
// REQUIREMENT: Test getInvestigationTimeline handler (25.9% coverage → target 80%)
// COVERAGE TARGET: Timeline event aggregation and alert integration
func TestGetInvestigationTimeline_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create investigation
	investigation := createTestInvestigation(t, testAPI, "Test Investigation", core.InvestigationPriorityHigh)

	// Add notes
	addInvestigationNote(t, testAPI, investigation.InvestigationID, "First analysis note")
	addInvestigationNote(t, testAPI, investigation.InvestigationID, "Second analysis note")

	// Get timeline
	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	url := fmt.Sprintf("/api/v1/investigations/%s/timeline", investigation.InvestigationID)
	httpReq := httptest.NewRequest("GET", url, nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, investigation.InvestigationID, response["investigation_id"])
	timeline := response["timeline"].([]interface{})
	assert.GreaterOrEqual(t, len(timeline), 2) // At least 2 notes
}

// TestGetInvestigationTimeline_NotFound tests 404 error
// REQUIREMENT: Test error handling for non-existent investigation
func TestGetInvestigationTimeline_NotFound(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	url := "/api/v1/investigations/non-existent-id/timeline"
	httpReq := httptest.NewRequest("GET", url, nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq = mux.SetURLVars(httpReq, map[string]string{"id": "non-existent-id"})

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Investigation not found")
}

// TestAddInvestigationNote_Success tests adding notes
// REQUIREMENT: Test addInvestigationNote handler
func TestAddInvestigationNote_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	investigation := createTestInvestigation(t, testAPI, "Test Investigation", core.InvestigationPriorityMedium)

	noteReq := AddNoteRequest{
		Content: "Investigated source IP - appears to be internal VPN gateway",
	}

	body, err := json.Marshal(noteReq)
	require.NoError(t, err)

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	url := fmt.Sprintf("/api/v1/investigations/%s/notes", investigation.InvestigationID)
	httpReq := httptest.NewRequest("POST", url, bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, httpReq)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var response core.Investigation
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Greater(t, len(response.Notes), 0)
	assert.Equal(t, "Investigated source IP - appears to be internal VPN gateway", response.Notes[len(response.Notes)-1].Content)
}

// TestAddInvestigationNote_ValidationErrors tests note validation
// REQUIREMENT: Test note validation constraints
func TestAddInvestigationNote_ValidationErrors(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	investigation := createTestInvestigation(t, testAPI, "Test Investigation", core.InvestigationPriorityMedium)

	tests := []struct {
		name           string
		content        string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Empty content",
			content:        "",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Validation failed",
		},
		{
			name:           "Content too long",
			content:        string(make([]byte, 5001)), // 5001 chars (max is 5000)
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noteReq := AddNoteRequest{
				Content: tt.content,
			}

			body, err := json.Marshal(noteReq)
			require.NoError(t, err)

			token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
			url := fmt.Sprintf("/api/v1/investigations/%s/notes", investigation.InvestigationID)
			httpReq := httptest.NewRequest("POST", url, bytes.NewReader(body))
			httpReq.Header.Set("Authorization", "Bearer "+token)
			addCSRFToRequest(t, httpReq)
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, httpReq)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// TestAddInvestigationAlert_Success tests linking alerts
// REQUIREMENT: Test addInvestigationAlert handler
func TestAddInvestigationAlert_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	investigation := createTestInvestigation(t, testAPI, "Test Investigation", core.InvestigationPriorityMedium)

	alertReq := AddAlertRequest{
		AlertID: "alert-003",
	}

	body, err := json.Marshal(alertReq)
	require.NoError(t, err)

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	url := fmt.Sprintf("/api/v1/investigations/%s/alerts", investigation.InvestigationID)
	httpReq := httptest.NewRequest("POST", url, bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, httpReq)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var response core.Investigation
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response.AlertIDs, "alert-003")
}

// TestAddInvestigationAlert_ValidationError tests alert validation
// REQUIREMENT: Test alert ID validation
func TestAddInvestigationAlert_ValidationError(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	investigation := createTestInvestigation(t, testAPI, "Test Investigation", core.InvestigationPriorityMedium)

	alertReq := AddAlertRequest{
		AlertID: "", // Empty alert ID
	}

	body, err := json.Marshal(alertReq)
	require.NoError(t, err)

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	url := fmt.Sprintf("/api/v1/investigations/%s/alerts", investigation.InvestigationID)
	httpReq := httptest.NewRequest("POST", url, bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, httpReq)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Validation failed")
}

// TestGetInvestigations_PaginationFull tests pagination
// REQUIREMENT: Test getInvestigations pagination logic
func TestGetInvestigations_PaginationFull(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create 5 test investigations
	for i := 1; i <= 5; i++ {
		createTestInvestigation(t, testAPI, fmt.Sprintf("Investigation %d", i), core.InvestigationPriorityMedium)
	}

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	httpReq := httptest.NewRequest("GET", "/api/v1/investigations?page=1&limit=2", nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check items field exists (pagination uses "items" not "data")
	require.NotNil(t, response["items"], "Response should contain 'items' field")
	items, ok := response["items"].([]interface{})
	require.True(t, ok, "Items field should be an array")

	assert.Equal(t, 2, len(items)) // Limited to 2 per page
	assert.Equal(t, float64(1), response["page"])
	assert.Equal(t, float64(2), response["limit"])
	assert.GreaterOrEqual(t, response["total"], float64(5))
}

// TestGetInvestigations_Filters tests filtering by status and priority
// REQUIREMENT: Test filter query parameter handling
func TestGetInvestigations_Filters(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create investigations with different priorities
	createTestInvestigation(t, testAPI, "Critical Investigation", core.InvestigationPriorityCritical)
	createTestInvestigation(t, testAPI, "High Investigation", core.InvestigationPriorityHigh)
	createTestInvestigation(t, testAPI, "Medium Investigation", core.InvestigationPriorityMedium)

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	httpReq := httptest.NewRequest("GET", "/api/v1/investigations?priority=critical", nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check items field exists and is an array (pagination uses "items" not "data")
	require.NotNil(t, response["items"], "Response should contain 'items' field")
	items, ok := response["items"].([]interface{})
	require.True(t, ok, "Items field should be an array")
	assert.GreaterOrEqual(t, len(items), 1) // At least the critical one
}

// TestGetInvestigation_Success tests single investigation retrieval
// REQUIREMENT: Test getInvestigation handler
func TestGetInvestigation_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	investigation := createTestInvestigation(t, testAPI, "Test Investigation", core.InvestigationPriorityHigh)

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	url := fmt.Sprintf("/api/v1/investigations/%s", investigation.InvestigationID)
	httpReq := httptest.NewRequest("GET", url, nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var response core.Investigation
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, investigation.InvestigationID, response.InvestigationID)
	assert.Equal(t, "Test Investigation", response.Title)
}

// TestUpdateInvestigation_Success tests updating investigation
// REQUIREMENT: Test updateInvestigation handler
func TestUpdateInvestigation_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	investigation := createTestInvestigation(t, testAPI, "Original Title", core.InvestigationPriorityLow)

	// Update investigation
	newTitle := "Updated Title"
	newPriority := core.InvestigationPriorityCritical
	updateReq := UpdateInvestigationRequest{
		Title:    &newTitle,
		Priority: &newPriority,
	}

	body, err := json.Marshal(updateReq)
	require.NoError(t, err)

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	url := fmt.Sprintf("/api/v1/investigations/%s", investigation.InvestigationID)
	httpReq := httptest.NewRequest("PUT", url, bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, httpReq)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var response core.Investigation
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Updated Title", response.Title)
	assert.Equal(t, core.InvestigationPriorityCritical, response.Priority)
}

// TestDeleteInvestigation_Success tests deleting investigation
// REQUIREMENT: Test deleteInvestigation handler
func TestDeleteInvestigation_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	investigation := createTestInvestigation(t, testAPI, "Test Investigation", core.InvestigationPriorityMedium)

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	url := fmt.Sprintf("/api/v1/investigations/%s", investigation.InvestigationID)
	httpReq := httptest.NewRequest("DELETE", url, nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, httpReq)
	httpReq = mux.SetURLVars(httpReq, map[string]string{"id": investigation.InvestigationID})

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify deletion
	httpReq2 := httptest.NewRequest("GET", url, nil)
	httpReq2.Header.Set("Authorization", "Bearer "+token)
	httpReq2 = mux.SetURLVars(httpReq2, map[string]string{"id": investigation.InvestigationID})

	w2 := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w2, httpReq2)

	assert.Equal(t, http.StatusNotFound, w2.Code)
}

// TestGetInvestigationStatistics_Success tests statistics endpoint
// REQUIREMENT: Test getInvestigationStatistics handler
func TestGetInvestigationStatistics_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create some test data
	createTestInvestigation(t, testAPI, "Investigation 1", core.InvestigationPriorityCritical)
	createTestInvestigation(t, testAPI, "Investigation 2", core.InvestigationPriorityHigh)

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	httpReq := httptest.NewRequest("GET", "/api/v1/investigations/statistics", nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Response structure will depend on storage implementation
	assert.NotNil(t, response)
}

// Helper Functions

// createTestInvestigation creates a test investigation
func createTestInvestigation(t *testing.T, api *API, title string, priority core.InvestigationPriority) *core.Investigation {
	// Ensure admin user exists (required for foreign key constraint)
	ensureTestUser(t, api, "admin")

	investigation := core.NewInvestigation(title, "Test description", priority, "admin")
	err := api.investigationStorage.CreateInvestigation(investigation)
	require.NoError(t, err)
	return investigation
}

// ensureTestUser ensures a test user exists in the database
func ensureTestUser(t *testing.T, api *API, username string) {
	// Check if user already exists
	_, err := api.userStorage.GetUserByUsername(context.Background(), username)
	if err == nil {
		// User already exists
		return
	}

	// Create user
	user := &storage.User{
		Username: username,
		Password: "test-password",
		Roles:    []string{"admin"},
		Active:   true,
	}
	err = api.userStorage.CreateUser(context.Background(), user)
	require.NoError(t, err)
}

// addInvestigationNote adds a note to an investigation
func addInvestigationNote(t *testing.T, api *API, investigationID, content string) {
	err := api.investigationStorage.AddNote(investigationID, "test-analyst", content)
	require.NoError(t, err)
}
