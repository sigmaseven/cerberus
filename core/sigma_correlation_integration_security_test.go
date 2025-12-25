package core

import (
	"sync"
	"testing"
	"time"
)

// TestIntegration_AllSecurityFixes verifies all 6 blocking issues are fixed
// in an integrated end-to-end test scenario.
func TestIntegration_AllSecurityFixes(t *testing.T) {
	t.Run("Issue1_YAMLBombProtection", func(t *testing.T) {
		// Valid YAML should work
		validYAML := `
type: event_count
timespan: 5m
condition:
  operator: ">="
  value: 5
`
		sc, err := ParseYAML([]byte(validYAML))
		if err != nil {
			t.Fatalf("Valid YAML failed: %v", err)
		}
		if sc.Type != "event_count" {
			t.Errorf("Type = %q, want %q", sc.Type, "event_count")
		}
	})

	t.Run("Issue2_NoRaceCondition", func(t *testing.T) {
		base := EnhancedCorrelationRule{
			ID:       "test",
			Type:     CorrelationTypeSequence,
			Name:     "Test",
			Severity: "High",
			Enabled:  true,
		}

		sc := &SigmaCorrelation{
			Type:     "temporal",
			Timespan: "1h",
			Events:   []string{"event1", "event2"},
		}

		// Run 50 concurrent conversions
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := sc.ToEnhancedCorrelation(base, map[string]interface{}{}, "metric", []Action{})
				if err != nil {
					t.Errorf("Concurrent conversion error: %v", err)
				}
			}()
		}
		wg.Wait()

		// Original should not be mutated
		if sc.Type != "temporal" {
			t.Errorf("Type mutated to %q, want %q", sc.Type, "temporal")
		}
	})

	t.Run("Issue3_DSuffixParsing", func(t *testing.T) {
		// Test all d suffix scenarios
		tests := []struct {
			input string
			want  time.Duration
		}{
			{"1d", 24 * time.Hour},
			{"7d", 168 * time.Hour},
			{"30d", 720 * time.Hour},
			{"365d", 365 * 24 * time.Hour},
		}

		for _, tt := range tests {
			got, err := parseDuration(tt.input)
			if err != nil {
				t.Errorf("parseDuration(%q) error = %v", tt.input, err)
				continue
			}
			if got != tt.want {
				t.Errorf("parseDuration(%q) = %v, want %v", tt.input, got, tt.want)
			}
		}

		// Test overflow protection
		_, err := parseDuration("999999999999d")
		if err == nil {
			t.Error("Expected error for huge day value, got nil")
		}
	})

	t.Run("Issue4_ToYAMLValidation", func(t *testing.T) {
		// Invalid correlation should fail
		invalidSc := &SigmaCorrelation{
			Type: "event_count",
			// Missing required fields
		}

		_, err := invalidSc.ToYAML()
		if err == nil {
			t.Error("Expected validation error, got nil")
		}

		// Valid correlation should succeed
		validSc := &SigmaCorrelation{
			Type:     "event_count",
			Timespan: "5m",
			Condition: &CorrelationCondition{
				Operator: ">=",
				Value:    5,
			},
		}

		yaml, err := validSc.ToYAML()
		if err != nil {
			t.Errorf("Valid correlation ToYAML() error = %v", err)
		}
		if len(yaml) == 0 {
			t.Error("ToYAML() returned empty bytes")
		}
	})

	t.Run("Issue5_IntegerOverflowProtection", func(t *testing.T) {
		// Test boundary conditions
		_, err := parseDuration("365d")
		if err != nil {
			t.Errorf("365d should be valid: %v", err)
		}

		_, err = parseDuration("366d")
		if err == nil {
			t.Error("366d should exceed maximum")
		}

		// Test overflow scenarios
		overflowCases := []string{
			"999999999999d",
			"9223372036854775807d", // int64 max
		}

		for _, input := range overflowCases {
			_, err := parseDuration(input)
			if err == nil {
				t.Errorf("Expected error for %q, got nil", input)
			}
		}
	})

	t.Run("Issue6_DocumentationAndUintSupport", func(t *testing.T) {
		// Test all supported numeric types in ToThreshold
		testCases := []struct {
			name  string
			value interface{}
			want  float64
		}{
			{"int", int(5), 5.0},
			{"int64", int64(10), 10.0},
			{"uint", uint(15), 15.0},
			{"uint64", uint64(20), 20.0},
			{"float32", float32(3.5), 3.5},
			{"float64", float64(7.5), 7.5},
		}

		for _, tt := range testCases {
			t.Run(tt.name, func(t *testing.T) {
				cc := &CorrelationCondition{
					Operator: ">=",
					Value:    tt.value,
				}

				threshold, err := cc.ToThreshold()
				if err != nil {
					t.Errorf("ToThreshold() error = %v", err)
					return
				}

				if threshold.Value != tt.want {
					t.Errorf("Value = %v, want %v", threshold.Value, tt.want)
				}
			})
		}
	})

	t.Run("Recommendation_DefaultRareCountField", func(t *testing.T) {
		if DefaultRareCountField != "event_type" {
			t.Errorf("DefaultRareCountField = %q, want %q", DefaultRareCountField, "event_type")
		}

		// Test usage in conversion
		base := EnhancedCorrelationRule{
			ID:       "test_rare",
			Type:     CorrelationTypeRare,
			Name:     "Test",
			Severity: "Medium",
			Enabled:  true,
		}

		sc := &SigmaCorrelation{
			Type:           "rare",
			BaselineWindow: "7d",
			Condition: &CorrelationCondition{
				Operator: "<",
				Value:    3,
			},
		}

		rule, err := sc.ToRareCorrelationRule(base, map[string]interface{}{}, []Action{})
		if err != nil {
			t.Fatalf("ToRareCorrelationRule() error = %v", err)
		}

		if rule.CountField != DefaultRareCountField {
			t.Errorf("CountField = %q, want %q", rule.CountField, DefaultRareCountField)
		}
	})
}

// TestIntegration_CompleteWorkflow tests a complete YAML parse -> validate -> convert -> serialize workflow
func TestIntegration_CompleteWorkflow(t *testing.T) {
	// Step 1: Parse YAML with security checks
	yamlInput := `
type: event_count
timespan: 7d
group_by:
  - source_ip
  - username
condition:
  operator: ">="
  value: 10
`

	sc, err := ParseYAML([]byte(yamlInput))
	if err != nil {
		t.Fatalf("ParseYAML() error = %v", err)
	}

	// Step 2: Validate
	if err := sc.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// Step 3: Parse duration with overflow protection
	duration, err := sc.ParseDuration(sc.Timespan)
	if err != nil {
		t.Fatalf("ParseDuration() error = %v", err)
	}

	expectedDuration := 7 * 24 * time.Hour
	if duration != expectedDuration {
		t.Errorf("Duration = %v, want %v", duration, expectedDuration)
	}

	// Step 4: Convert to enhanced correlation rule
	base := EnhancedCorrelationRule{
		ID:       "test_workflow",
		Type:     CorrelationTypeCount,
		Name:     "Test Workflow",
		Severity: "High",
		Enabled:  true,
	}

	result, err := sc.ToEnhancedCorrelation(base, map[string]interface{}{}, "metric", []Action{})
	if err != nil {
		t.Fatalf("ToEnhancedCorrelation() error = %v", err)
	}

	countRule, ok := result.(*CountCorrelationRule)
	if !ok {
		t.Fatalf("Expected *CountCorrelationRule, got %T", result)
	}

	if countRule.Window != duration {
		t.Errorf("Window = %v, want %v", countRule.Window, duration)
	}

	// Step 5: Serialize back to YAML with validation
	yamlOutput, err := sc.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML() error = %v", err)
	}

	if len(yamlOutput) == 0 {
		t.Error("ToYAML() returned empty bytes")
	}

	// Step 6: Round-trip test
	sc2, err := ParseYAML(yamlOutput)
	if err != nil {
		t.Fatalf("Round-trip ParseYAML() error = %v", err)
	}

	if sc2.Type != sc.Type {
		t.Errorf("Round-trip Type = %q, want %q", sc2.Type, sc.Type)
	}

	if sc2.Timespan != sc.Timespan {
		t.Errorf("Round-trip Timespan = %q, want %q", sc2.Timespan, sc.Timespan)
	}
}

// TestIntegration_SecurityBoundaries tests all security boundaries together
func TestIntegration_SecurityBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		test    func() error
		wantErr bool
	}{
		{
			name: "YAML size limit",
			test: func() error {
				hugeYAML := make([]byte, 1024*1024+1)
				_, err := ParseYAML(hugeYAML)
				return err
			},
			wantErr: true,
		},
		{
			name: "YAML depth limit",
			test: func() error {
				deepYAML := "type: test\n"
				for i := 0; i < 25; i++ {
					deepYAML += "  level:\n"
				}
				_, err := ParseYAML([]byte(deepYAML))
				return err
			},
			wantErr: true,
		},
		{
			name: "Duration maximum",
			test: func() error {
				_, err := parseDuration("9000h")
				return err
			},
			wantErr: true,
		},
		{
			name: "Negative duration",
			test: func() error {
				_, err := parseDuration("-5m")
				return err
			},
			wantErr: true,
		},
		{
			name: "Integer overflow in days",
			test: func() error {
				_, err := parseDuration("999999999999d")
				return err
			},
			wantErr: true,
		},
		{
			name: "Invalid correlation serialization",
			test: func() error {
				sc := &SigmaCorrelation{Type: "event_count"}
				_, err := sc.ToYAML()
				return err
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.test()
			if (err != nil) != tt.wantErr {
				t.Errorf("test() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
