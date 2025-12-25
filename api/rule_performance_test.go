package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cerberus/storage"

	"github.com/gorilla/mux"
)

// BLOCKING-5 FIX: Comprehensive API handler tests for rule performance endpoints

// TestHandleGetRulePerformance_Success tests successful retrieval of rule performance stats
func TestHandleGetRulePerformance_Success(t *testing.T) {
	// Setup
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create performance data
	ruleID := "test-rule-123"
	perf := &storage.RulePerformance{
		RuleID:             ruleID,
		AvgEvalTimeMs:      15.5,
		MaxEvalTimeMs:      45.2,
		P99EvalTimeMs:      38.1,
		TotalEvaluations:   1000,
		TotalMatches:       150,
		FalsePositiveCount: 5,
		LastEvaluated:      time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}

	perfStorage := storage.NewSQLiteRulePerformanceStorage(api.sqlite, api.logger)
	if err := perfStorage.UpdatePerformance(perf); err != nil {
		t.Fatalf("Failed to create test performance data: %v", err)
	}

	// Create request
	req := httptest.NewRequest("GET", "/api/v1/rules/"+ruleID+"/performance", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ruleID})
	rr := httptest.NewRecorder()

	// Execute
	api.handleGetRulePerformance(rr, req)

	// Assert
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, status, rr.Body.String())
	}

	var response RulePerformanceResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.RuleID != ruleID {
		t.Errorf("Expected rule_id %s, got %s", ruleID, response.RuleID)
	}
	if response.AvgEvalTimeMs != 15.5 {
		t.Errorf("Expected avg_eval_time_ms 15.5, got %f", response.AvgEvalTimeMs)
	}
	if response.TotalEvaluations != 1000 {
		t.Errorf("Expected total_evaluations 1000, got %d", response.TotalEvaluations)
	}
	if response.TotalMatches != 150 {
		t.Errorf("Expected total_matches 150, got %d", response.TotalMatches)
	}
}

// TestHandleGetRulePerformance_NotFound tests 404 response for non-existent rule
func TestHandleGetRulePerformance_NotFound(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/rules/nonexistent/performance", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	rr := httptest.NewRecorder()

	api.handleGetRulePerformance(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, status)
	}
}

// TestHandleGetRulePerformance_MissingID tests 400 response for missing rule ID
func TestHandleGetRulePerformance_MissingID(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/rules//performance", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	rr := httptest.NewRecorder()

	api.handleGetRulePerformance(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, status)
	}
}

// TestHandleGetSlowRules_ParameterValidation tests query parameter validation
func TestHandleGetSlowRules_ParameterValidation(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	tests := []struct {
		name          string
		threshold     string
		limit         string
		expectStatus  int
		expectRecords bool
	}{
		{
			name:          "valid parameters",
			threshold:     "50.0",
			limit:         "10",
			expectStatus:  http.StatusOK,
			expectRecords: false,
		},
		{
			name:          "default threshold",
			threshold:     "",
			limit:         "10",
			expectStatus:  http.StatusOK,
			expectRecords: false,
		},
		{
			name:          "default limit",
			threshold:     "50.0",
			limit:         "",
			expectStatus:  http.StatusOK,
			expectRecords: false,
		},
		{
			name:          "large limit clamped",
			threshold:     "10.0",
			limit:         "5000",
			expectStatus:  http.StatusOK,
			expectRecords: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/api/v1/rules/performance/slow?"
			if tt.threshold != "" {
				url += "threshold_ms=" + tt.threshold + "&"
			}
			if tt.limit != "" {
				url += "limit=" + tt.limit
			}

			req := httptest.NewRequest("GET", url, nil)
			rr := httptest.NewRecorder()

			api.handleGetSlowRules(rr, req)

			if status := rr.Code; status != tt.expectStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectStatus, status, rr.Body.String())
			}
		})
	}
}

// TestHandleReportFalsePositive_Success tests successful false positive reporting
func TestHandleReportFalsePositive_Success(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	ruleID := "test-rule-456"

	req := httptest.NewRequest("POST", "/api/v1/rules/"+ruleID+"/performance/false-positive", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ruleID})
	rr := httptest.NewRecorder()

	api.handleReportFalsePositive(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, status, rr.Body.String())
	}

	// Verify the false positive was recorded
	perfStorage := storage.NewSQLiteRulePerformanceStorage(api.sqlite, api.logger)
	perf, err := perfStorage.GetPerformance(ruleID)
	if err != nil {
		t.Fatalf("Failed to get performance: %v", err)
	}

	if perf == nil {
		t.Fatal("Performance record should exist after reporting false positive")
	}

	if perf.FalsePositiveCount != 1 {
		t.Errorf("Expected false_positive_count 1, got %d", perf.FalsePositiveCount)
	}
}

// TestHandleReportFalsePositive_MissingID tests 400 response for missing rule ID
func TestHandleReportFalsePositive_MissingID(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/v1/rules//performance/false-positive", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	rr := httptest.NewRecorder()

	api.handleReportFalsePositive(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, status)
	}
}

