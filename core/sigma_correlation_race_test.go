package core

import (
	"sync"
	"testing"
)

// TestToEnhancedCorrelation_TemporalNoMutation tests that temporal type conversion
// doesn't mutate the original struct, preventing race conditions (Issue #2)
func TestToEnhancedCorrelation_TemporalNoMutation(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_temporal",
		Type:     CorrelationTypeSequence,
		Name:     "Test Temporal",
		Severity: "High",
		Enabled:  true,
	}

	selection := map[string]interface{}{
		"event_type": "test",
	}

	actions := []Action{
		{ID: "action1", Type: "alert"},
	}

	// Create a shared correlation struct
	sc := &SigmaCorrelation{
		Type:     "temporal",
		Timespan: "1h",
		Events:   []string{"event1", "event2"},
	}

	// Store original type
	originalType := sc.Type

	// Call conversion
	_, err := sc.ToEnhancedCorrelation(base, selection, "metric", actions)
	if err != nil {
		t.Fatalf("ToEnhancedCorrelation() error = %v", err)
	}

	// Verify original struct was not mutated
	if sc.Type != originalType {
		t.Errorf("Original struct was mutated: Type = %q, want %q", sc.Type, originalType)
	}
}

// TestToEnhancedCorrelation_TemporalConcurrentAccess tests concurrent access
// to the same correlation struct doesn't cause race conditions
func TestToEnhancedCorrelation_TemporalConcurrentAccess(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_temporal_concurrent",
		Type:     CorrelationTypeSequence,
		Name:     "Test Temporal Concurrent",
		Severity: "High",
		Enabled:  true,
	}

	selection := map[string]interface{}{
		"event_type": "test",
	}

	actions := []Action{
		{ID: "action1", Type: "alert"},
	}

	// Create a shared correlation struct
	sc := &SigmaCorrelation{
		Type:     "temporal",
		Timespan: "1h",
		Events:   []string{"event1", "event2"},
	}

	// Run concurrent conversions
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := sc.ToEnhancedCorrelation(base, selection, "metric", actions)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent conversion error: %v", err)
	}

	// Verify original struct was not mutated
	if sc.Type != "temporal" {
		t.Errorf("Original struct was mutated after concurrent access: Type = %q, want %q", sc.Type, "temporal")
	}
}

// TestToEnhancedCorrelation_TemporalImmutability tests that the conversion
// creates an independent copy
func TestToEnhancedCorrelation_TemporalImmutability(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_temporal_immutable",
		Type:     CorrelationTypeSequence,
		Name:     "Test Temporal Immutable",
		Severity: "High",
		Enabled:  true,
	}

	selection := map[string]interface{}{
		"event_type": "test",
	}

	actions := []Action{
		{ID: "action1", Type: "alert"},
	}

	sc := &SigmaCorrelation{
		Type:     "temporal",
		Timespan: "1h",
		Events:   []string{"event1", "event2", "event3"},
		GroupBy:  []string{"source_ip"},
	}

	// Convert
	result, err := sc.ToEnhancedCorrelation(base, selection, "metric", actions)
	if err != nil {
		t.Fatalf("ToEnhancedCorrelation() error = %v", err)
	}

	// Verify result is correct type
	seqRule, ok := result.(*SequenceCorrelationRule)
	if !ok {
		t.Fatalf("Expected *SequenceCorrelationRule, got %T", result)
	}

	// Verify conversion used the copy's values
	if len(seqRule.Sequence) != len(sc.Events) {
		t.Errorf("Sequence length = %d, want %d", len(seqRule.Sequence), len(sc.Events))
	}

	if len(seqRule.GroupBy) != len(sc.GroupBy) {
		t.Errorf("GroupBy length = %d, want %d", len(seqRule.GroupBy), len(sc.GroupBy))
	}

	// Verify original was not mutated
	if sc.Type != "temporal" {
		t.Errorf("Original Type = %q, want %q", sc.Type, "temporal")
	}
}
