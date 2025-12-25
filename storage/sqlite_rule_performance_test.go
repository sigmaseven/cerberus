package storage

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestRulePerformanceStorage tests rule performance storage operations
func TestRulePerformanceStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Create rule_performance table directly for testing
	// NOTE: In production, this table is created via migration 1.6.0
	_, err = sqlite.WriteDB.Exec(`
		CREATE TABLE IF NOT EXISTS rule_performance (
			rule_id TEXT PRIMARY KEY,
			avg_eval_time_ms REAL NOT NULL DEFAULT 0,
			max_eval_time_ms REAL NOT NULL DEFAULT 0,
			p99_eval_time_ms REAL NOT NULL DEFAULT 0,
			total_evaluations INTEGER NOT NULL DEFAULT 0,
			total_matches INTEGER NOT NULL DEFAULT 0,
			false_positive_count INTEGER NOT NULL DEFAULT 0,
			last_evaluated DATETIME,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create rule_performance table: %v", err)
	}

	storage := NewSQLiteRulePerformanceStorage(sqlite, logger)

	t.Run("GetPerformance_NotFound", func(t *testing.T) {
		perf, err := storage.GetPerformance("nonexistent")
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if perf != nil {
			t.Errorf("Expected nil for nonexistent rule, got %v", perf)
		}
	})

	t.Run("UpdatePerformance", func(t *testing.T) {
		stats := &RulePerformance{
			RuleID:             "rule1",
			AvgEvalTimeMs:      1.5,
			MaxEvalTimeMs:      5.0,
			P99EvalTimeMs:      4.5,
			TotalEvaluations:   100,
			TotalMatches:       10,
			FalsePositiveCount: 2,
			LastEvaluated:      time.Now().UTC(),
		}

		err := storage.UpdatePerformance(stats)
		if err != nil {
			t.Fatalf("Failed to update performance: %v", err)
		}

		// Retrieve and verify
		retrieved, err := storage.GetPerformance("rule1")
		if err != nil {
			t.Fatalf("Failed to get performance: %v", err)
		}
		if retrieved == nil {
			t.Fatal("Expected performance data, got nil")
		}

		if retrieved.RuleID != "rule1" {
			t.Errorf("Expected rule_id=rule1, got %s", retrieved.RuleID)
		}
		if retrieved.AvgEvalTimeMs != 1.5 {
			t.Errorf("Expected avg_eval_time_ms=1.5, got %f", retrieved.AvgEvalTimeMs)
		}
		if retrieved.TotalEvaluations != 100 {
			t.Errorf("Expected total_evaluations=100, got %d", retrieved.TotalEvaluations)
		}
	})

	t.Run("UpdatePerformance_Upsert", func(t *testing.T) {
		// Update existing record
		stats := &RulePerformance{
			RuleID:           "rule1",
			AvgEvalTimeMs:    2.0,
			MaxEvalTimeMs:    6.0,
			P99EvalTimeMs:    5.5,
			TotalEvaluations: 200,
			TotalMatches:     20,
			LastEvaluated:    time.Now().UTC(),
		}

		err := storage.UpdatePerformance(stats)
		if err != nil {
			t.Fatalf("Failed to upsert performance: %v", err)
		}

		// Retrieve and verify updated values
		retrieved, err := storage.GetPerformance("rule1")
		if err != nil {
			t.Fatalf("Failed to get performance: %v", err)
		}

		if retrieved.AvgEvalTimeMs != 2.0 {
			t.Errorf("Expected avg_eval_time_ms=2.0, got %f", retrieved.AvgEvalTimeMs)
		}
		if retrieved.TotalEvaluations != 200 {
			t.Errorf("Expected total_evaluations=200, got %d", retrieved.TotalEvaluations)
		}
	})

	t.Run("BatchUpdatePerformance", func(t *testing.T) {
		batch := []*RulePerformance{
			{
				RuleID:           "rule2",
				AvgEvalTimeMs:    0.5,
				TotalEvaluations: 50,
				LastEvaluated:    time.Now().UTC(),
			},
			{
				RuleID:           "rule3",
				AvgEvalTimeMs:    3.0,
				TotalEvaluations: 150,
				LastEvaluated:    time.Now().UTC(),
			},
		}

		err := storage.BatchUpdatePerformance(batch)
		if err != nil {
			t.Fatalf("Failed to batch update: %v", err)
		}

		// Verify both records
		perf2, err := storage.GetPerformance("rule2")
		if err != nil || perf2 == nil {
			t.Errorf("Failed to get rule2 performance: %v", err)
		}
		if perf2 != nil && perf2.AvgEvalTimeMs != 0.5 {
			t.Errorf("Expected rule2 avg=0.5, got %f", perf2.AvgEvalTimeMs)
		}

		perf3, err := storage.GetPerformance("rule3")
		if err != nil || perf3 == nil {
			t.Errorf("Failed to get rule3 performance: %v", err)
		}
		if perf3 != nil && perf3.AvgEvalTimeMs != 3.0 {
			t.Errorf("Expected rule3 avg=3.0, got %f", perf3.AvgEvalTimeMs)
		}
	})

	t.Run("GetSlowRules", func(t *testing.T) {
		// Add more rules with varying performance
		rules := []*RulePerformance{
			{RuleID: "slow1", AvgEvalTimeMs: 100.0, TotalEvaluations: 10, LastEvaluated: time.Now().UTC()},
			{RuleID: "slow2", AvgEvalTimeMs: 200.0, TotalEvaluations: 20, LastEvaluated: time.Now().UTC()},
			{RuleID: "fast1", AvgEvalTimeMs: 0.1, TotalEvaluations: 30, LastEvaluated: time.Now().UTC()},
		}
		storage.BatchUpdatePerformance(rules)

		// Get slow rules above 50ms threshold
		slow, err := storage.GetSlowRules(50.0, 10)
		if err != nil {
			t.Fatalf("Failed to get slow rules: %v", err)
		}

		// Should return slow1 and slow2, sorted by avg time DESC
		if len(slow) < 2 {
			t.Fatalf("Expected at least 2 slow rules, got %d", len(slow))
		}

		// Verify sorted by avg time descending
		if slow[0].AvgEvalTimeMs < slow[1].AvgEvalTimeMs {
			t.Errorf("Expected descending sort, got %f before %f",
				slow[0].AvgEvalTimeMs, slow[1].AvgEvalTimeMs)
		}

		// Verify threshold filter
		for _, rule := range slow {
			if rule.AvgEvalTimeMs < 50.0 {
				t.Errorf("Expected all rules > 50ms, got %s with %f",
					rule.RuleID, rule.AvgEvalTimeMs)
			}
		}
	})

	t.Run("ReportFalsePositive", func(t *testing.T) {
		// Report false positive for new rule
		err := storage.ReportFalsePositive("rule_fp")
		if err != nil {
			t.Fatalf("Failed to report false positive: %v", err)
		}

		// Verify count incremented
		perf, err := storage.GetPerformance("rule_fp")
		if err != nil {
			t.Fatalf("Failed to get performance: %v", err)
		}
		if perf.FalsePositiveCount != 1 {
			t.Errorf("Expected false_positive_count=1, got %d", perf.FalsePositiveCount)
		}

		// Report again
		err = storage.ReportFalsePositive("rule_fp")
		if err != nil {
			t.Fatalf("Failed to report second false positive: %v", err)
		}

		// Verify count incremented again
		perf, err = storage.GetPerformance("rule_fp")
		if err != nil {
			t.Fatalf("Failed to get performance: %v", err)
		}
		if perf.FalsePositiveCount != 2 {
			t.Errorf("Expected false_positive_count=2, got %d", perf.FalsePositiveCount)
		}
	})

	t.Run("DeletePerformance", func(t *testing.T) {
		// Create a rule
		stats := &RulePerformance{
			RuleID:           "rule_delete",
			AvgEvalTimeMs:    1.0,
			TotalEvaluations: 100,
			LastEvaluated:    time.Now().UTC(),
		}
		storage.UpdatePerformance(stats)

		// Delete it
		err := storage.DeletePerformance("rule_delete")
		if err != nil {
			t.Fatalf("Failed to delete performance: %v", err)
		}

		// Verify deleted
		perf, err := storage.GetPerformance("rule_delete")
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if perf != nil {
			t.Errorf("Expected nil after delete, got %v", perf)
		}
	})

	t.Run("ValidationErrors", func(t *testing.T) {
		// Test nil stats
		err := storage.UpdatePerformance(nil)
		if err == nil {
			t.Error("Expected error for nil stats")
		}

		// Test empty rule ID
		err = storage.UpdatePerformance(&RulePerformance{RuleID: ""})
		if err == nil {
			t.Error("Expected error for empty rule_id")
		}

		_, err = storage.GetPerformance("")
		if err == nil {
			t.Error("Expected error for empty rule_id")
		}

		err = storage.DeletePerformance("")
		if err == nil {
			t.Error("Expected error for empty rule_id")
		}
	})
}
