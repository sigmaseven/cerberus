package api

import (
	"sync"
	"testing"

	"go.uber.org/zap"
)

// TestNewSigmaRolloutConfig validates configuration creation
func TestNewSigmaRolloutConfig(t *testing.T) {
	tests := []struct {
		name              string
		enabled           bool
		rolloutPercentage int
		enabledRuleIDs    []string
		disabledRuleIDs   []string
		expectError       bool
	}{
		{
			name:              "valid config - fully enabled",
			enabled:           true,
			rolloutPercentage: 100,
			enabledRuleIDs:    []string{},
			disabledRuleIDs:   []string{},
			expectError:       false,
		},
		{
			name:              "valid config - disabled",
			enabled:           false,
			rolloutPercentage: 0,
			enabledRuleIDs:    []string{},
			disabledRuleIDs:   []string{},
			expectError:       false,
		},
		{
			name:              "valid config - partial rollout",
			enabled:           true,
			rolloutPercentage: 50,
			enabledRuleIDs:    []string{"rule-001"},
			disabledRuleIDs:   []string{"rule-002"},
			expectError:       false,
		},
		{
			name:              "invalid - negative percentage",
			enabled:           true,
			rolloutPercentage: -1,
			enabledRuleIDs:    []string{},
			disabledRuleIDs:   []string{},
			expectError:       true,
		},
		{
			name:              "invalid - percentage over 100",
			enabled:           true,
			rolloutPercentage: 101,
			enabledRuleIDs:    []string{},
			disabledRuleIDs:   []string{},
			expectError:       true,
		},
		{
			name:              "valid - empty rule IDs ignored",
			enabled:           true,
			rolloutPercentage: 25,
			enabledRuleIDs:    []string{"", "rule-001", ""},
			disabledRuleIDs:   []string{"", "rule-002"},
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewSigmaRolloutConfig(
				tt.enabled,
				tt.rolloutPercentage,
				tt.enabledRuleIDs,
				tt.disabledRuleIDs,
				nil, // No logger for tests
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if config.Enabled != tt.enabled {
				t.Errorf("Enabled = %v, want %v", config.Enabled, tt.enabled)
			}

			if config.RolloutPercentage != tt.rolloutPercentage {
				t.Errorf("RolloutPercentage = %v, want %v", config.RolloutPercentage, tt.rolloutPercentage)
			}
		})
	}
}

// TestShouldUseSigmaEngine_MasterSwitch validates master switch behavior
func TestShouldUseSigmaEngine_MasterSwitch(t *testing.T) {
	// Master switch disabled - all rules should use legacy engine
	config, err := NewSigmaRolloutConfig(false, 100, []string{"rule-001"}, []string{}, nil)
	if err != nil {
		t.Fatalf("config creation failed: %v", err)
	}

	// Even with 100% rollout and whitelist, should return false
	if config.ShouldUseSigmaEngine("rule-001") {
		t.Error("master switch disabled should return false even for whitelisted rule")
	}

	if config.ShouldUseSigmaEngine("any-rule") {
		t.Error("master switch disabled should return false for any rule")
	}
}

// TestShouldUseSigmaEngine_Blocklist validates blocklist takes precedence
func TestShouldUseSigmaEngine_Blocklist(t *testing.T) {
	// Blocklist should override whitelist and percentage
	config, err := NewSigmaRolloutConfig(
		true,
		100,
		[]string{"rule-001", "rule-002"}, // Whitelist
		[]string{"rule-001", "rule-003"}, // Blocklist
		nil,
	)
	if err != nil {
		t.Fatalf("config creation failed: %v", err)
	}

	// rule-001 is in both whitelist and blocklist - blocklist wins
	if config.ShouldUseSigmaEngine("rule-001") {
		t.Error("blocklist should override whitelist")
	}

	// rule-002 is only in whitelist - should use SIGMA
	if !config.ShouldUseSigmaEngine("rule-002") {
		t.Error("whitelisted rule (not blocked) should use SIGMA")
	}

	// rule-003 is only in blocklist - should use legacy
	if config.ShouldUseSigmaEngine("rule-003") {
		t.Error("blocked rule should use legacy even with 100% rollout")
	}
}

// TestShouldUseSigmaEngine_Whitelist validates whitelist behavior
func TestShouldUseSigmaEngine_Whitelist(t *testing.T) {
	// Whitelist should force SIGMA engine even with 0% rollout
	config, err := NewSigmaRolloutConfig(
		true,
		0, // 0% rollout
		[]string{"rule-important", "rule-critical"},
		[]string{},
		nil,
	)
	if err != nil {
		t.Fatalf("config creation failed: %v", err)
	}

	// Whitelisted rules should use SIGMA despite 0% rollout
	if !config.ShouldUseSigmaEngine("rule-important") {
		t.Error("whitelisted rule should use SIGMA even with 0% rollout")
	}

	if !config.ShouldUseSigmaEngine("rule-critical") {
		t.Error("whitelisted rule should use SIGMA even with 0% rollout")
	}

	// Non-whitelisted rule with 0% rollout should use legacy
	if config.ShouldUseSigmaEngine("rule-normal") {
		t.Error("non-whitelisted rule should use legacy with 0% rollout")
	}
}

// TestShouldUseSigmaEngine_PercentageRouting validates hash-based routing
func TestShouldUseSigmaEngine_PercentageRouting(t *testing.T) {
	tests := []struct {
		name       string
		percentage int
		ruleCount  int
	}{
		{"0% rollout", 0, 100},
		{"25% rollout", 25, 100},
		{"50% rollout", 50, 100},
		{"75% rollout", 75, 100},
		{"100% rollout", 100, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewSigmaRolloutConfig(true, tt.percentage, []string{}, []string{}, nil)
			if err != nil {
				t.Fatalf("config creation failed: %v", err)
			}

			// Generate synthetic rule IDs and count SIGMA usage
			sigmaCount := 0
			for i := 0; i < tt.ruleCount; i++ {
				ruleID := generateTestRuleID(i)
				if config.ShouldUseSigmaEngine(ruleID) {
					sigmaCount++
				}
			}

			// Calculate actual percentage
			actualPercentage := (sigmaCount * 100) / tt.ruleCount

			// Allow ±15% tolerance for hash distribution variance
			// (SHA-256 distribution is good but not perfect for small samples)
			tolerance := 15
			lowerBound := tt.percentage - tolerance
			upperBound := tt.percentage + tolerance

			if actualPercentage < lowerBound || actualPercentage > upperBound {
				t.Errorf("percentage distribution out of range: got %d%%, want %d%% (±%d%%)",
					actualPercentage, tt.percentage, tolerance)
			}

			t.Logf("Rollout %d%%: %d/%d rules use SIGMA (actual: %d%%)",
				tt.percentage, sigmaCount, tt.ruleCount, actualPercentage)
		})
	}
}

// TestShouldUseSigmaEngine_Determinism validates stable routing
func TestShouldUseSigmaEngine_Determinism(t *testing.T) {
	config, err := NewSigmaRolloutConfig(true, 50, []string{}, []string{}, nil)
	if err != nil {
		t.Fatalf("config creation failed: %v", err)
	}

	// Test that same rule ID always returns same result
	testRules := []string{"rule-001", "rule-002", "rule-003", "rule-determinism"}

	for _, ruleID := range testRules {
		// Call multiple times
		firstResult := config.ShouldUseSigmaEngine(ruleID)

		for i := 0; i < 10; i++ {
			result := config.ShouldUseSigmaEngine(ruleID)
			if result != firstResult {
				t.Errorf("non-deterministic result for %s: first=%v, iteration=%d result=%v",
					ruleID, firstResult, i, result)
			}
		}
	}
}

// TestShouldUseSigmaEngine_Concurrency validates thread-safety
func TestShouldUseSigmaEngine_Concurrency(t *testing.T) {
	config, err := NewSigmaRolloutConfig(
		true,
		50,
		[]string{"rule-whitelist"},
		[]string{"rule-blocklist"},
		nil,
	)
	if err != nil {
		t.Fatalf("config creation failed: %v", err)
	}

	// Launch 100 concurrent goroutines
	const goroutines = 100
	const callsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Test concurrent access
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Each goroutine makes multiple calls
			for j := 0; j < callsPerGoroutine; j++ {
				ruleID := generateTestRuleID(id*callsPerGoroutine + j)
				// Just call the method - any data race will be caught by -race flag
				_ = config.ShouldUseSigmaEngine(ruleID)
			}
		}(i)
	}

	wg.Wait()
	// If we reach here without panic or race detector errors, test passes
}

// TestGetStats validates statistics reporting
func TestGetStats(t *testing.T) {
	config, err := NewSigmaRolloutConfig(
		true,
		75,
		[]string{"rule-001", "rule-002", "rule-003"},
		[]string{"rule-bad"},
		nil,
	)
	if err != nil {
		t.Fatalf("config creation failed: %v", err)
	}

	stats := config.GetStats()

	if enabled, ok := stats["enabled"].(bool); !ok || !enabled {
		t.Errorf("stats enabled = %v, want true", stats["enabled"])
	}

	if percentage, ok := stats["rollout_percentage"].(int); !ok || percentage != 75 {
		t.Errorf("stats rollout_percentage = %v, want 75", stats["rollout_percentage"])
	}

	if count, ok := stats["whitelist_count"].(int); !ok || count != 3 {
		t.Errorf("stats whitelist_count = %v, want 3", stats["whitelist_count"])
	}

	if count, ok := stats["blocklist_count"].(int); !ok || count != 1 {
		t.Errorf("stats blocklist_count = %v, want 1", stats["blocklist_count"])
	}
}

// TestHashRuleID validates hash determinism and distribution
func TestHashRuleID(t *testing.T) {
	// Test determinism
	ruleID := "test-rule-001"
	hash1 := hashRuleID(ruleID)
	hash2 := hashRuleID(ruleID)

	if hash1 != hash2 {
		t.Errorf("hash not deterministic: %d != %d", hash1, hash2)
	}

	// Test different inputs produce different hashes
	hash3 := hashRuleID("test-rule-002")
	if hash1 == hash3 {
		t.Error("different rule IDs produced same hash (collision)")
	}

	// Test hash distribution (no clustering)
	const sampleSize = 1000
	hashes := make(map[uint64]bool, sampleSize)

	for i := 0; i < sampleSize; i++ {
		ruleID := generateTestRuleID(i)
		hash := hashRuleID(ruleID)
		hashes[hash] = true
	}

	// We should have nearly 1000 unique hashes (collisions are extremely rare with SHA-256)
	if len(hashes) < sampleSize*95/100 { // Allow 5% tolerance
		t.Errorf("hash distribution poor: %d unique hashes from %d inputs", len(hashes), sampleSize)
	}
}

// TestSigmaRolloutConfig_EdgeCases validates edge case handling
func TestSigmaRolloutConfig_EdgeCases(t *testing.T) {
	t.Run("empty rule ID", func(t *testing.T) {
		config, _ := NewSigmaRolloutConfig(true, 50, []string{}, []string{}, nil)
		// Should handle empty string without panic
		_ = config.ShouldUseSigmaEngine("")
	})

	t.Run("very long rule ID", func(t *testing.T) {
		config, _ := NewSigmaRolloutConfig(true, 50, []string{}, []string{}, nil)
		longRuleID := string(make([]byte, 10000)) // 10KB rule ID
		// Should handle long strings without panic
		_ = config.ShouldUseSigmaEngine(longRuleID)
	})

	t.Run("unicode rule ID", func(t *testing.T) {
		config, _ := NewSigmaRolloutConfig(true, 50, []string{}, []string{}, nil)
		unicodeRuleID := "规则-001-测试-🔥"
		// Should handle unicode without panic
		result1 := config.ShouldUseSigmaEngine(unicodeRuleID)
		result2 := config.ShouldUseSigmaEngine(unicodeRuleID)
		if result1 != result2 {
			t.Error("unicode rule ID not deterministic")
		}
	})

	t.Run("duplicate whitelist entries", func(t *testing.T) {
		config, err := NewSigmaRolloutConfig(
			true,
			0,
			[]string{"rule-001", "rule-001", "rule-001"}, // Duplicates
			[]string{},
			nil,
		)
		if err != nil {
			t.Fatalf("config creation failed: %v", err)
		}

		// Should still work correctly
		if !config.ShouldUseSigmaEngine("rule-001") {
			t.Error("duplicate whitelist entries broke functionality")
		}

		stats := config.GetStats()
		// Map deduplication should result in count of 1
		if count, ok := stats["whitelist_count"].(int); !ok || count != 1 {
			t.Errorf("whitelist_count = %v, want 1 (duplicates should be deduplicated)", count)
		}
	})
}

// TestSigmaRolloutConfig_WithLogger validates logging integration
func TestSigmaRolloutConfig_WithLogger(t *testing.T) {
	// Create test logger
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	config, err := NewSigmaRolloutConfig(
		true,
		50,
		[]string{"rule-whitelist"},
		[]string{"rule-blocklist"},
		sugar,
	)
	if err != nil {
		t.Fatalf("config creation failed: %v", err)
	}

	// Test that logging doesn't cause panics
	config.ShouldUseSigmaEngine("rule-whitelist") // Whitelist case
	config.ShouldUseSigmaEngine("rule-blocklist") // Blocklist case
	config.ShouldUseSigmaEngine("rule-normal")    // Hash routing case

	// If we reach here without panic, logging works
}

// Benchmark tests for performance validation

func BenchmarkShouldUseSigmaEngine_HashRouting(b *testing.B) {
	config, _ := NewSigmaRolloutConfig(true, 50, []string{}, []string{}, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ruleID := generateTestRuleID(i % 1000)
		config.ShouldUseSigmaEngine(ruleID)
	}
}

func BenchmarkShouldUseSigmaEngine_Whitelist(b *testing.B) {
	whitelistedRules := make([]string, 100)
	for i := 0; i < 100; i++ {
		whitelistedRules[i] = generateTestRuleID(i)
	}

	config, _ := NewSigmaRolloutConfig(true, 0, whitelistedRules, []string{}, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ruleID := whitelistedRules[i%100]
		config.ShouldUseSigmaEngine(ruleID)
	}
}

func BenchmarkShouldUseSigmaEngine_Concurrent(b *testing.B) {
	config, _ := NewSigmaRolloutConfig(true, 50, []string{}, []string{}, nil)

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ruleID := generateTestRuleID(i % 1000)
			config.ShouldUseSigmaEngine(ruleID)
			i++
		}
	})
}

func BenchmarkHashRuleID(b *testing.B) {
	ruleIDs := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		ruleIDs[i] = generateTestRuleID(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hashRuleID(ruleIDs[i%1000])
	}
}

// Helper function to generate test rule IDs
func generateTestRuleID(id int) string {
	return "rule-" + string(rune('0'+id%10)) + string(rune('0'+(id/10)%10)) + string(rune('0'+(id/100)%10))
}
