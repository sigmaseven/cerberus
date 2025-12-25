package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"cerberus/metrics"
	"cerberus/storage"

	"github.com/gorilla/mux"
)

// RulePerformanceResponse represents the API response for rule performance
type RulePerformanceResponse struct {
	RuleID             string  `json:"rule_id"`
	AvgEvalTimeMs      float64 `json:"avg_eval_time_ms"`
	MaxEvalTimeMs      float64 `json:"max_eval_time_ms"`
	P99EvalTimeMs      float64 `json:"p99_eval_time_ms"`
	TotalEvaluations   int64   `json:"total_evaluations"`
	TotalMatches       int64   `json:"total_matches"`
	FalsePositiveCount int64   `json:"false_positive_count"`
	LastEvaluated      string  `json:"last_evaluated"`
	MatchRate          float64 `json:"match_rate"` // Computed field
}

// handleGetRulePerformance retrieves performance stats for a single rule
// GET /api/v1/rules/{id}/performance
// RBAC: Requires rules:read permission
// OBSERVABILITY: Exposes detailed performance metrics for monitoring
func (s *API) handleGetRulePerformance(w http.ResponseWriter, r *http.Request) {
	// Extract rule ID from path
	vars := mux.Vars(r)
	ruleID := vars["id"]

	if ruleID == "" {
		http.Error(w, "Rule ID is required", http.StatusBadRequest)
		return
	}

	// Get performance stats from storage
	perfStorage := s.getRulePerformanceStorage()
	if perfStorage == nil {
		http.Error(w, "Performance tracking not available", http.StatusServiceUnavailable)
		return
	}

	perf, err := perfStorage.GetPerformance(ruleID)
	if err != nil {
		s.logger.Errorf("Failed to get performance for rule %s: %v", ruleID, err)
		http.Error(w, "Failed to retrieve performance stats", http.StatusInternalServerError)
		return
	}

	// Return 404 if no performance data exists
	if perf == nil {
		http.Error(w, "No performance data available for this rule", http.StatusNotFound)
		return
	}

	// Build response with computed fields
	response := buildPerformanceResponse(perf)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGetSlowRules retrieves rules exceeding performance threshold
// GET /api/v1/rules/performance/slow?threshold_ms=100&limit=20
// RBAC: Requires rules:read permission
// OBSERVABILITY: Identifies performance bottlenecks
func (s *API) handleGetSlowRules(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	thresholdMs := 100.0 // Default threshold
	if thresholdStr := r.URL.Query().Get("threshold_ms"); thresholdStr != "" {
		if parsed, err := strconv.ParseFloat(thresholdStr, 64); err == nil && parsed >= 0 {
			thresholdMs = parsed
		}
	}

	limit := 20 // Default limit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	// Get slow rules from storage
	perfStorage := s.getRulePerformanceStorage()
	if perfStorage == nil {
		http.Error(w, "Performance tracking not available", http.StatusServiceUnavailable)
		return
	}

	slowRules, err := perfStorage.GetSlowRules(thresholdMs, limit)
	if err != nil {
		s.logger.Errorf("Failed to get slow rules: %v", err)
		http.Error(w, "Failed to retrieve slow rules", http.StatusInternalServerError)
		return
	}

	// Build response list
	responses := make([]RulePerformanceResponse, 0, len(slowRules))
	for _, perf := range slowRules {
		responses = append(responses, buildPerformanceResponse(perf))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"threshold_ms": thresholdMs,
		"count":        len(responses),
		"rules":        responses,
	})
}

// handleReportFalsePositive reports a false positive for a rule
// POST /api/v1/rules/{id}/performance/false-positive
// RBAC: Requires rules:write permission
// OBSERVABILITY: Tracks rule accuracy for tuning
func (s *API) handleReportFalsePositive(w http.ResponseWriter, r *http.Request) {
	// Extract rule ID from path
	vars := mux.Vars(r)
	ruleID := vars["id"]

	if ruleID == "" {
		http.Error(w, "Rule ID is required", http.StatusBadRequest)
		return
	}

	// Get performance storage
	perfStorage := s.getRulePerformanceStorage()
	if perfStorage == nil {
		http.Error(w, "Performance tracking not available", http.StatusServiceUnavailable)
		return
	}

	// Report false positive
	if err := perfStorage.ReportFalsePositive(ruleID); err != nil {
		s.logger.Errorf("Failed to report false positive for rule %s: %v", ruleID, err)
		http.Error(w, "Failed to report false positive", http.StatusInternalServerError)
		return
	}

	// Update Prometheus metric
	metrics.RuleFalsePositivesTotal.WithLabelValues(ruleID).Inc()

	// Log the report
	userID := getUserIDFromContext(r.Context())
	s.logger.Infow("False positive reported",
		"rule_id", ruleID,
		"reported_by", userID,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "False positive reported successfully",
	})
}

// buildPerformanceResponse builds API response from storage model
// HELPER: Computes derived fields like match rate
func buildPerformanceResponse(perf *storage.RulePerformance) RulePerformanceResponse {
	// Calculate match rate
	var matchRate float64
	if perf.TotalEvaluations > 0 {
		matchRate = float64(perf.TotalMatches) / float64(perf.TotalEvaluations) * 100.0
	}

	return RulePerformanceResponse{
		RuleID:             perf.RuleID,
		AvgEvalTimeMs:      perf.AvgEvalTimeMs,
		MaxEvalTimeMs:      perf.MaxEvalTimeMs,
		P99EvalTimeMs:      perf.P99EvalTimeMs,
		TotalEvaluations:   perf.TotalEvaluations,
		TotalMatches:       perf.TotalMatches,
		FalsePositiveCount: perf.FalsePositiveCount,
		LastEvaluated:      perf.LastEvaluated.Format("2006-01-02T15:04:05Z"),
		MatchRate:          matchRate,
	}
}

// getRulePerformanceStorage retrieves the performance storage from API
// HELPER: Provides safe access to performance storage
// Returns nil if performance tracking is not configured
func (s *API) getRulePerformanceStorage() storage.RulePerformanceStorage {
	// Check if we have a SQLite instance
	if s.sqlite == nil {
		return nil
	}

	// Create storage instance on demand
	// In a production system, this would be injected via constructor
	return storage.NewSQLiteRulePerformanceStorage(s.sqlite, s.logger)
}
