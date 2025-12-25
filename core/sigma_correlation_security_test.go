package core

import (
	"strings"
	"testing"
)

// TestParseYAML_DepthBomb tests YAML depth bomb protection (Issue #1)
func TestParseYAML_DepthBomb(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid shallow YAML",
			yaml: `
type: event_count
timespan: 5m
condition:
  operator: ">="
  value: 5
`,
			wantErr: false,
		},
		{
			name: "deeply nested YAML bomb",
			yaml: func() string {
				// Create deeply nested YAML (25 levels)
				nested := "value: 1\n"
				for i := 0; i < 25; i++ {
					nested = "  level" + strings.Repeat("x", i) + ":\n" + addIndent(nested, 2)
				}
				return "type: event_count\n" + nested
			}(),
			wantErr: true,
			errMsg:  "YAML depth validation failed",
		},
		{
			name: "valid nested YAML at limit",
			yaml: `
type: event_count
timespan: 5m
condition:
  operator: ">="
  value: 5
stages:
  - name: stage1
    detection_ref: ref1
  - name: stage2
    detection_ref: ref2
`,
			wantErr: false,
		},
		{
			name:    "exceeds size limit",
			yaml:    strings.Repeat("a", 1024*1024+1),
			wantErr: true,
			errMsg:  "exceeds maximum size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseYAML([]byte(tt.yaml))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// addIndent adds indentation to each line
func addIndent(s string, spaces int) string {
	lines := strings.Split(s, "\n")
	indent := strings.Repeat(" ", spaces)
	for i, line := range lines {
		if line != "" {
			lines[i] = indent + line
		}
	}
	return strings.Join(lines, "\n")
}

// TestToYAML_Validation tests ToYAML validation (Issue #4)
func TestToYAML_Validation(t *testing.T) {
	tests := []struct {
		name    string
		sc      *SigmaCorrelation
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid correlation",
			sc: &SigmaCorrelation{
				Type:     "event_count",
				Timespan: "5m",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: false,
		},
		{
			name:    "nil correlation",
			sc:      nil,
			wantErr: true,
			errMsg:  "cannot serialize nil correlation",
		},
		{
			name: "invalid correlation - missing timespan",
			sc: &SigmaCorrelation{
				Type: "event_count",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: true,
			errMsg:  "cannot serialize invalid correlation",
		},
		{
			name: "invalid correlation - missing condition",
			sc: &SigmaCorrelation{
				Type:     "event_count",
				Timespan: "5m",
			},
			wantErr: true,
			errMsg:  "cannot serialize invalid correlation",
		},
		{
			name: "invalid correlation - bad timespan",
			sc: &SigmaCorrelation{
				Type:     "event_count",
				Timespan: "invalid",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: true,
			errMsg:  "cannot serialize invalid correlation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.sc.ToYAML()
			if (err != nil) != tt.wantErr {
				t.Errorf("ToYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestParseDuration_IntegerOverflow tests integer overflow protection (Issue #5)
func TestParseDuration_IntegerOverflow(t *testing.T) {
	tests := []struct {
		name     string
		duration string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid 1 day",
			duration: "1d",
			wantErr:  false,
		},
		{
			name:     "valid 365 days",
			duration: "365d",
			wantErr:  false,
		},
		{
			name:     "366 days exceeds limit",
			duration: "366d",
			wantErr:  true,
			errMsg:   "exceeds maximum",
		},
		{
			name:     "huge number causes overflow",
			duration: "999999999999d",
			wantErr:  true,
			errMsg:   "exceeds maximum",
		},
		{
			name:     "int64 max",
			duration: "9223372036854775807d",
			wantErr:  true,
			errMsg:   "exceeds maximum",
		},
		{
			name:     "negative days",
			duration: "-10d",
			wantErr:  true,
			errMsg:   "cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDuration(tt.duration)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestToThreshold_UintTypes tests uint type handling in ToThreshold
func TestToThreshold_UintTypes(t *testing.T) {
	tests := []struct {
		name      string
		condition *CorrelationCondition
		wantValue float64
		wantErr   bool
	}{
		{
			name: "int value",
			condition: &CorrelationCondition{
				Operator: ">=",
				Value:    int(5),
			},
			wantValue: 5.0,
			wantErr:   false,
		},
		{
			name: "int64 value",
			condition: &CorrelationCondition{
				Operator: ">=",
				Value:    int64(10),
			},
			wantValue: 10.0,
			wantErr:   false,
		},
		{
			name: "uint value",
			condition: &CorrelationCondition{
				Operator: ">=",
				Value:    uint(15),
			},
			wantValue: 15.0,
			wantErr:   false,
		},
		{
			name: "uint64 value",
			condition: &CorrelationCondition{
				Operator: ">=",
				Value:    uint64(20),
			},
			wantValue: 20.0,
			wantErr:   false,
		},
		{
			name: "float32 value",
			condition: &CorrelationCondition{
				Operator: ">=",
				Value:    float32(3.5),
			},
			wantValue: 3.5,
			wantErr:   false,
		},
		{
			name: "float64 value",
			condition: &CorrelationCondition{
				Operator: ">=",
				Value:    float64(7.5),
			},
			wantValue: 7.5,
			wantErr:   false,
		},
		{
			name: "unsupported string value",
			condition: &CorrelationCondition{
				Operator: ">=",
				Value:    "not a number",
			},
			wantErr: true,
		},
		{
			name:      "nil condition",
			condition: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threshold, err := tt.condition.ToThreshold()
			if (err != nil) != tt.wantErr {
				t.Errorf("ToThreshold() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if threshold.Value != tt.wantValue {
					t.Errorf("ToThreshold() value = %v, want %v", threshold.Value, tt.wantValue)
				}
				if threshold.Operator != ThresholdOperator(tt.condition.Operator) {
					t.Errorf("ToThreshold() operator = %v, want %v", threshold.Operator, tt.condition.Operator)
				}
			}
		})
	}
}

// TestDefaultRareCountField tests the constant is used correctly
func TestDefaultRareCountField(t *testing.T) {
	if DefaultRareCountField != "event_type" {
		t.Errorf("DefaultRareCountField = %q, want %q", DefaultRareCountField, "event_type")
	}

	// Test it's used in conversion
	base := EnhancedCorrelationRule{
		ID:       "test_rare",
		Type:     CorrelationTypeRare,
		Name:     "Test Rare",
		Severity: "Medium",
		Enabled:  true,
	}

	sc := &SigmaCorrelation{
		Type:           "rare",
		BaselineWindow: "7d",
		// No DistinctField specified - should use default
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
}

// TestValidateYAMLDepth tests the depth validation function
func TestValidateYAMLDepth(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		maxDepth int
		wantErr  bool
	}{
		{
			name: "flat YAML",
			yaml: `
type: event_count
timespan: 5m
`,
			maxDepth: 10,
			wantErr:  false,
		},
		{
			name: "moderately nested",
			yaml: `
type: event_count
condition:
  operator: ">="
  value: 5
`,
			maxDepth: 10,
			wantErr:  false,
		},
		{
			name: "exceeds depth",
			yaml: func() string {
				// Create 15 levels of nesting
				nested := "value: 1\n"
				for i := 0; i < 15; i++ {
					nested = "  level:\n" + addIndent(nested, 2)
				}
				return nested
			}(),
			maxDepth: 5,
			wantErr:  true,
		},
		{
			name: "strings don't count as depth",
			yaml: `
description: "This has a lot of spaces
  but they're in a string
    so they don't count"
value: 1
`,
			maxDepth: 5,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateYAMLDepth([]byte(tt.yaml), tt.maxDepth)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateYAMLDepth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
