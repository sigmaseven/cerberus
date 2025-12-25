package detect

import (
	"testing"
	"time"

	"cerberus/storage"

	"go.uber.org/zap"
)

// TestPerformanceCollector tests the performance collector
func TestPerformanceCollector(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sqlite, err := storage.NewSQLite(":memory:", logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Create rule_performance table for testing
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

	perfStorage := storage.NewSQLiteRulePerformanceStorage(sqlite, logger)
	collector := NewPerformanceCollector(perfStorage, logger)

	t.Run("RecordEvaluation_Single", func(t *testing.T) {
		collector.RecordEvaluation("test_rule", 1.5, true)

		stats := collector.GetStats()
		totalEvals := stats["total_evaluations"].(int64)
		if totalEvals != 1 {
			t.Errorf("Expected 1 evaluation, got %d", totalEvals)
		}

		pendingRules := stats["pending_rules"].(int)
		if pendingRules != 1 {
			t.Errorf("Expected 1 pending rule, got %d", pendingRules)
		}
	})

	t.Run("RecordEvaluation_Multiple", func(t *testing.T) {
		// Record multiple evaluations for same rule
		for i := 0; i < 10; i++ {
			matched := i%3 == 0
			collector.RecordEvaluation("test_rule2", float64(i)*0.5, matched)
		}

		stats := collector.GetStats()
		pendingEvals := stats["pending_evaluations"].(int64)
		if pendingEvals == 0 {
			t.Error("Expected pending evaluations")
		}
	})

	t.Run("AutoFlush_OnBatchSize", func(t *testing.T) {
		// Create new collector with small batch size
		collector2 := NewPerformanceCollector(perfStorage, logger)
		collector2.batchSize = 5

		// Record enough evaluations to trigger flush
		for i := 0; i < 6; i++ {
			collector2.RecordEvaluation("auto_flush_rule", 1.0, i%2 == 0)
		}

		// Give it a moment to flush
		time.Sleep(100 * time.Millisecond)

		// Verify data was written to storage
		perf, err := perfStorage.GetPerformance("auto_flush_rule")
		if err != nil {
			t.Fatalf("Failed to get performance: %v", err)
		}
		if perf == nil {
			t.Error("Expected performance data after auto-flush")
		}
	})

	t.Run("ManualFlush", func(t *testing.T) {
		collector3 := NewPerformanceCollector(perfStorage, logger)

		// Record some evaluations
		for i := 0; i < 5; i++ {
			collector3.RecordEvaluation("manual_flush_rule", float64(i), i%2 == 0)
		}

		// Manually flush
		err := collector3.Flush()
		if err != nil {
			t.Fatalf("Failed to flush: %v", err)
		}

		// Verify data was written
		perf, err := perfStorage.GetPerformance("manual_flush_rule")
		if err != nil {
			t.Fatalf("Failed to get performance: %v", err)
		}
		if perf == nil {
			t.Fatal("Expected performance data after manual flush")
		}
		if perf.TotalEvaluations != 5 {
			t.Errorf("Expected 5 evaluations, got %d", perf.TotalEvaluations)
		}
	})

	t.Run("MatchTracking", func(t *testing.T) {
		collector4 := NewPerformanceCollector(perfStorage, logger)

		// Record 10 evaluations, 3 matches
		for i := 0; i < 10; i++ {
			matched := i < 3
			collector4.RecordEvaluation("match_tracking_rule", 1.0, matched)
		}

		// Flush and verify
		collector4.Flush()

		perf, err := perfStorage.GetPerformance("match_tracking_rule")
		if err != nil {
			t.Fatalf("Failed to get performance: %v", err)
		}
		if perf.TotalMatches != 3 {
			t.Errorf("Expected 3 matches, got %d", perf.TotalMatches)
		}
		if perf.TotalEvaluations != 10 {
			t.Errorf("Expected 10 evaluations, got %d", perf.TotalEvaluations)
		}
	})

	t.Run("MemoryLimit", func(t *testing.T) {
		collector5 := NewPerformanceCollector(perfStorage, logger)

		// Record more than MaxPendingTimes
		for i := 0; i < MaxPendingTimes+100; i++ {
			collector5.RecordEvaluation("memory_limit_rule", 1.0, false)
		}

		stats := collector5.GetStats()
		pendingEvals := stats["pending_evaluations"].(int64)

		// Should be capped at MaxPendingTimes per rule
		if pendingEvals > MaxPendingTimes {
			t.Errorf("Expected pending <= %d, got %d", MaxPendingTimes, pendingEvals)
		}
	})

	t.Run("InvalidInput", func(t *testing.T) {
		collector6 := NewPerformanceCollector(perfStorage, logger)

		// Should ignore empty rule ID
		collector6.RecordEvaluation("", 1.0, true)

		stats := collector6.GetStats()
		pendingRules := stats["pending_rules"].(int)
		if pendingRules != 0 {
			t.Errorf("Expected 0 pending rules for empty ID, got %d", pendingRules)
		}
	})
}

// TestCalculateP99 tests the p99 percentile calculation
func TestCalculateP99(t *testing.T) {
	tests := []struct {
		name     string
		times    []float64
		expected float64
	}{
		{
			name:     "empty",
			times:    []float64{},
			expected: 0,
		},
		{
			name:     "single_value",
			times:    []float64{5.0},
			expected: 5.0,
		},
		{
			name:     "sorted_100_values",
			times:    generateSequence(1.0, 100),
			expected: 100.0, // 99th percentile of 1-100 (99% of 100 = index 99 = value 100)
		},
		{
			name:     "unsorted_values",
			times:    []float64{10.0, 1.0, 5.0, 3.0, 7.0},
			expected: 10.0, // 99th percentile should be highest
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateP99(tt.times)
			if result != tt.expected {
				t.Errorf("Expected p99=%f, got %f", tt.expected, result)
			}
		})
	}
}

// generateSequence generates a sequence of floats from start to start+count-1
func generateSequence(start float64, count int) []float64 {
	result := make([]float64, count)
	for i := 0; i < count; i++ {
		result[i] = start + float64(i)
	}
	return result
}

// TestMergeStats tests the statistics merging logic
func TestMergeStats(t *testing.T) {
	logger := zap.NewNop().Sugar()
	sqlite, err := storage.NewSQLite(":memory:", logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Create rule_performance table for testing
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

	perfStorage := storage.NewSQLiteRulePerformanceStorage(sqlite, logger)
	collector := NewPerformanceCollector(perfStorage, logger)

	t.Run("MergeWithNilExisting", func(t *testing.T) {
		pending := &PendingStats{
			Times:   []float64{1.0, 2.0, 3.0},
			Matches: 2,
		}

		merged := collector.mergeStats("test_rule", nil, pending)

		if merged.TotalEvaluations != 3 {
			t.Errorf("Expected 3 evaluations, got %d", merged.TotalEvaluations)
		}
		if merged.TotalMatches != 2 {
			t.Errorf("Expected 2 matches, got %d", merged.TotalMatches)
		}
		if merged.AvgEvalTimeMs != 2.0 {
			t.Errorf("Expected avg=2.0, got %f", merged.AvgEvalTimeMs)
		}
	})

	t.Run("MergeWithExisting", func(t *testing.T) {
		existing := &storage.RulePerformance{
			RuleID:           "test_rule",
			AvgEvalTimeMs:    5.0,
			TotalEvaluations: 10,
			TotalMatches:     3,
			MaxEvalTimeMs:    10.0,
		}

		pending := &PendingStats{
			Times:   []float64{1.0, 2.0},
			Matches: 1,
		}

		merged := collector.mergeStats("test_rule", existing, pending)

		if merged.TotalEvaluations != 12 {
			t.Errorf("Expected 12 evaluations, got %d", merged.TotalEvaluations)
		}
		if merged.TotalMatches != 4 {
			t.Errorf("Expected 4 matches, got %d", merged.TotalMatches)
		}

		// Rolling average: (5.0*10 + 1.5*2) / 12 = (50 + 3) / 12 = 4.417
		expectedAvg := (5.0*10.0 + 1.5*2.0) / 12.0
		if merged.AvgEvalTimeMs < expectedAvg-0.01 || merged.AvgEvalTimeMs > expectedAvg+0.01 {
			t.Errorf("Expected avg≈%f, got %f", expectedAvg, merged.AvgEvalTimeMs)
		}
	})
}
