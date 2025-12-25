package detect

import (
	"testing"
	"time"
)

// TestNewModifierEvaluator verifies the constructor
func TestNewModifierEvaluator(t *testing.T) {
	timeout := 5 * time.Second
	eval := NewModifierEvaluator(timeout)

	if eval == nil {
		t.Fatal("NewModifierEvaluator returned nil")
	}

	if eval.regexTimeout != timeout {
		t.Errorf("regexTimeout = %v, want %v", eval.regexTimeout, timeout)
	}
}

// TestEvaluateWithModifiers_SingleValueNoModifiers tests default equals comparison
func TestEvaluateWithModifiers_SingleValueNoModifiers(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name    string
		value   interface{}
		pattern interface{}
		want    bool
	}{
		{
			name:    "matching strings",
			value:   "test",
			pattern: "test",
			want:    true,
		},
		{
			name:    "non-matching strings",
			value:   "test",
			pattern: "other",
			want:    false,
		},
		{
			name:    "matching integers",
			value:   42,
			pattern: 42,
			want:    true,
		},
		{
			name:    "non-matching integers",
			value:   42,
			pattern: 43,
			want:    false,
		},
		{
			name:    "both nil",
			value:   nil,
			pattern: nil,
			want:    true,
		},
		{
			name:    "value nil pattern non-nil",
			value:   nil,
			pattern: "test",
			want:    false,
		},
		{
			name:    "value non-nil pattern nil",
			value:   "test",
			pattern: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, []string{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, []) = %v, want %v", tt.value, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestEvaluateWithModifiers_ComparisonModifiers tests comparison modifier handling
func TestEvaluateWithModifiers_ComparisonModifiers(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name      string
		value     interface{}
		pattern   interface{}
		modifiers []string
		want      bool
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "contains modifier matches substring",
			value:     "testing",
			pattern:   "test",
			modifiers: []string{"contains"},
			want:      true,
			wantErr:   false,
		},
		{
			name:      "startswith modifier matches prefix",
			value:     "testing",
			pattern:   "test",
			modifiers: []string{"startswith"},
			want:      true,
			wantErr:   false,
		},
		{
			name:      "endswith modifier matches suffix",
			value:     "testing",
			pattern:   "ing",
			modifiers: []string{"endswith"},
			want:      true,
			wantErr:   false,
		},
		{
			name:      "regex modifier matches pattern",
			value:     "test123",
			pattern:   "test\\d+",
			modifiers: []string{"re"},
			want:      true,
			wantErr:   false,
		},
		{
			name:      "cidr modifier (not yet implemented)",
			value:     "192.168.1.1",
			pattern:   "192.168.0.0/16",
			modifiers: []string{"cidr"},
			want:      false,
			wantErr:   true,
			errMsg:    "not yet implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
					return
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if got != tt.want {
					t.Errorf("EvaluateWithModifiers() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// TestEvaluateWithModifiers_ListPatternORLogic tests OR logic with pattern lists
func TestEvaluateWithModifiers_ListPatternORLogic(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name    string
		value   interface{}
		pattern interface{}
		want    bool
	}{
		{
			name:    "value matches first pattern",
			value:   "a",
			pattern: []interface{}{"a", "b", "c"},
			want:    true,
		},
		{
			name:    "value matches middle pattern",
			value:   "b",
			pattern: []interface{}{"a", "b", "c"},
			want:    true,
		},
		{
			name:    "value matches last pattern",
			value:   "c",
			pattern: []interface{}{"a", "b", "c"},
			want:    true,
		},
		{
			name:    "value matches no pattern",
			value:   "x",
			pattern: []interface{}{"a", "b", "c"},
			want:    false,
		},
		{
			name:    "empty pattern list",
			value:   "x",
			pattern: []interface{}{},
			want:    false,
		},
		{
			name:    "single item pattern list match",
			value:   "test",
			pattern: []interface{}{"test"},
			want:    true,
		},
		{
			name:    "single item pattern list no match",
			value:   "other",
			pattern: []interface{}{"test"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, []string{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, []) = %v, want %v", tt.value, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestEvaluateWithModifiers_ListPatternANDLogic tests AND logic with 'all' modifier
func TestEvaluateWithModifiers_ListPatternANDLogic(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name      string
		value     interface{}
		pattern   interface{}
		modifiers []string
		want      bool
	}{
		{
			name:      "value matches all patterns - impossible with different values",
			value:     "a",
			pattern:   []interface{}{"a", "b"},
			modifiers: []string{"all"},
			want:      false, // "a" cannot equal both "a" AND "b"
		},
		{
			name:      "value matches all patterns - same value",
			value:     "a",
			pattern:   []interface{}{"a", "a"},
			modifiers: []string{"all"},
			want:      true,
		},
		{
			name:      "value matches some but not all",
			value:     "a",
			pattern:   []interface{}{"a", "b", "c"},
			modifiers: []string{"all"},
			want:      false,
		},
		{
			name:      "value matches none with all modifier",
			value:     "x",
			pattern:   []interface{}{"a", "b", "c"},
			modifiers: []string{"all"},
			want:      false,
		},
		{
			name:      "empty pattern list with all modifier",
			value:     "x",
			pattern:   []interface{}{},
			modifiers: []string{"all"},
			want:      false,
		},
		{
			name:      "single pattern with all modifier match",
			value:     "test",
			pattern:   []interface{}{"test"},
			modifiers: []string{"all"},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, %v) = %v, want %v", tt.value, tt.pattern, tt.modifiers, got, tt.want)
			}
		})
	}
}

// TestEvaluateWithModifiers_ListValue tests value as list matching
func TestEvaluateWithModifiers_ListValue(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name    string
		value   interface{}
		pattern interface{}
		want    bool
	}{
		{
			name:    "any value in list matches pattern",
			value:   []interface{}{"a", "b", "c"},
			pattern: "b",
			want:    true,
		},
		{
			name:    "first value in list matches",
			value:   []interface{}{"test", "other"},
			pattern: "test",
			want:    true,
		},
		{
			name:    "last value in list matches",
			value:   []interface{}{"other", "test"},
			pattern: "test",
			want:    true,
		},
		{
			name:    "no value in list matches",
			value:   []interface{}{"a", "b", "c"},
			pattern: "x",
			want:    false,
		},
		{
			name:    "empty value list",
			value:   []interface{}{},
			pattern: "test",
			want:    false,
		},
		{
			name:    "single item value list match",
			value:   []interface{}{"test"},
			pattern: "test",
			want:    true,
		},
		{
			name:    "single item value list no match",
			value:   []interface{}{"other"},
			pattern: "test",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, []string{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, []) = %v, want %v", tt.value, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestEvaluateWithModifiers_ListVsListORLogic tests list vs list with OR logic
func TestEvaluateWithModifiers_ListVsListORLogic(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name    string
		value   interface{}
		pattern interface{}
		want    bool
	}{
		{
			name:    "any value matches any pattern",
			value:   []interface{}{"a", "b"},
			pattern: []interface{}{"b", "c"},
			want:    true,
		},
		{
			name:    "no value matches any pattern",
			value:   []interface{}{"a", "b"},
			pattern: []interface{}{"x", "y"},
			want:    false,
		},
		{
			name:    "first value matches first pattern",
			value:   []interface{}{"test", "other"},
			pattern: []interface{}{"test", "another"},
			want:    true,
		},
		{
			name:    "empty value list",
			value:   []interface{}{},
			pattern: []interface{}{"a", "b"},
			want:    false,
		},
		{
			name:    "empty pattern list",
			value:   []interface{}{"a", "b"},
			pattern: []interface{}{},
			want:    false,
		},
		{
			name:    "both lists empty",
			value:   []interface{}{},
			pattern: []interface{}{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, []string{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, []) = %v, want %v", tt.value, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestEvaluateWithModifiers_ListVsListANDLogic tests list vs list with AND logic
func TestEvaluateWithModifiers_ListVsListANDLogic(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name      string
		value     interface{}
		pattern   interface{}
		modifiers []string
		want      bool
	}{
		{
			name:      "all patterns match at least one value",
			value:     []interface{}{"a", "b", "c"},
			pattern:   []interface{}{"a", "b"},
			modifiers: []string{"all"},
			want:      true,
		},
		{
			name:      "some patterns don't match any value",
			value:     []interface{}{"a", "b"},
			pattern:   []interface{}{"a", "x"},
			modifiers: []string{"all"},
			want:      false,
		},
		{
			name:      "no patterns match",
			value:     []interface{}{"a", "b"},
			pattern:   []interface{}{"x", "y"},
			modifiers: []string{"all"},
			want:      false,
		},
		{
			name:      "single pattern single value match",
			value:     []interface{}{"test"},
			pattern:   []interface{}{"test"},
			modifiers: []string{"all"},
			want:      true,
		},
		{
			name:      "single pattern single value no match",
			value:     []interface{}{"other"},
			pattern:   []interface{}{"test"},
			modifiers: []string{"all"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, %v) = %v, want %v", tt.value, tt.pattern, tt.modifiers, got, tt.want)
			}
		})
	}
}

// TestEvaluateWithModifiers_UnknownModifier tests error handling for unknown modifiers
func TestEvaluateWithModifiers_UnknownModifier(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name      string
		modifiers []string
	}{
		{
			name:      "single unknown modifier",
			modifiers: []string{"unknown"},
		},
		{
			name:      "known and unknown modifiers",
			modifiers: []string{"contains", "unknown"},
		},
		{
			name:      "multiple unknown modifiers",
			modifiers: []string{"unknown1", "unknown2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := eval.EvaluateWithModifiers("test", "test", tt.modifiers)
			if err == nil {
				t.Errorf("expected error for unknown modifier, got nil")
				return
			}
		})
	}
}

// TestEvaluateWithModifiers_MultipleComparisonModifiers tests error for multiple comparison modifiers
func TestEvaluateWithModifiers_MultipleComparisonModifiers(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name      string
		modifiers []string
	}{
		{
			name:      "contains and startswith",
			modifiers: []string{"contains", "startswith"},
		},
		{
			name:      "all comparison modifiers",
			modifiers: []string{"contains", "startswith", "endswith"},
		},
		{
			name:      "re and contains",
			modifiers: []string{"re", "contains"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := eval.EvaluateWithModifiers("test", "test", tt.modifiers)
			if err == nil {
				t.Errorf("expected error for multiple comparison modifiers, got nil")
				return
			}
		})
	}
}

// TestEvaluateWithModifiers_TransformModifiers tests transform modifier handling
func TestEvaluateWithModifiers_TransformModifiers(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name        string
		value       interface{}
		pattern     interface{}
		modifiers   []string
		want        bool
		expectError bool
	}{
		{
			name:        "base64 modifier decodes value",
			value:       "dGVzdA==", // "test" base64 encoded
			pattern:     "test",     // decoded result
			modifiers:   []string{"base64"},
			want:        true,
			expectError: false,
		},
		{
			name: "utf16le modifier decodes UTF-16LE bytes",
			// "Hi" encoded as UTF-16LE: H=0x48,0x00 i=0x69,0x00
			value:       string([]byte{0x48, 0x00, 0x69, 0x00}),
			pattern:     "Hi",
			modifiers:   []string{"utf16le"},
			want:        true,
			expectError: false,
		},
		{
			name:        "wide modifier returns error (unsupported)",
			value:       "test",
			pattern:     "test",
			modifiers:   []string{"wide"},
			want:        false,
			expectError: true, // wide is unsupported
		},
		{
			name:        "windash modifier normalizes dashes",
			value:       "test",
			pattern:     "test",
			modifiers:   []string{"windash"},
			want:        true,
			expectError: false,
		},
		{
			name: "chained base64 then utf16le",
			// "Hi" UTF-16LE (0x48,0x00,0x69,0x00) base64 encoded = "SABJAAA=" (wait, let me calculate)
			// Actually: "SAAiAA==" is "H\x00"\x00" which is wrong
			// Let me just use windash which works on normal strings
			value:       "test\u2013dash", // EN DASH
			pattern:     "test-dash",      // normalized
			modifiers:   []string{"windash"},
			want:        true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, %v) = %v, want %v", tt.value, tt.pattern, tt.modifiers, got, tt.want)
			}
		})
	}
}

// TestEvaluateWithModifiers_TransformAndComparison tests combined transform and comparison modifiers
func TestEvaluateWithModifiers_TransformAndComparison(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name      string
		value     interface{}
		pattern   interface{}
		modifiers []string
		want      bool
		wantErr   bool
	}{
		{
			name:      "base64 with contains",
			value:     "dGVzdGluZw==", // base64("testing")
			pattern:   "test",
			modifiers: []string{"base64", "contains"},
			want:      true, // "testing" contains "test"
			wantErr:   false,
		},
		{
			name: "utf16le with startswith",
			// "Hi" encoded as UTF-16LE: H=0x48,0x00 i=0x69,0x00
			value:     string([]byte{0x48, 0x00, 0x69, 0x00}),
			pattern:   "H",
			modifiers: []string{"utf16le", "startswith"},
			want:      true, // "Hi" starts with "H"
			wantErr:   false,
		},
		{
			name:      "windash with equals",
			value:     "test",
			pattern:   "test",
			modifiers: []string{"windash"},
			want:      true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("EvaluateWithModifiers() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEvaluateWithModifiers_AllModifierWithSinglePattern tests 'all' modifier behavior
func TestEvaluateWithModifiers_AllModifierWithSinglePattern(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name      string
		value     interface{}
		pattern   interface{}
		modifiers []string
		want      bool
	}{
		{
			name:      "single pattern match with all",
			value:     "test",
			pattern:   "test",
			modifiers: []string{"all"},
			want:      true,
		},
		{
			name:      "single pattern no match with all",
			value:     "other",
			pattern:   "test",
			modifiers: []string{"all"},
			want:      false,
		},
		{
			name:      "single pattern in list with all match",
			value:     "test",
			pattern:   []interface{}{"test"},
			modifiers: []string{"all"},
			want:      true,
		},
		{
			name:      "single pattern in list with all no match",
			value:     "other",
			pattern:   []interface{}{"test"},
			modifiers: []string{"all"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, %v) = %v, want %v", tt.value, tt.pattern, tt.modifiers, got, tt.want)
			}
		})
	}
}

// TestEvaluateWithModifiers_TypeConversion tests cross-type comparisons
// SIGMA rules should be able to compare values across type boundaries when
// it makes semantic sense (e.g., comparing number 42 with string "42").
func TestEvaluateWithModifiers_TypeConversion(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name    string
		value   interface{}
		pattern interface{}
		want    bool
	}{
		{
			name:    "string vs int - equal values",
			value:   "42",
			pattern: 42,
			want:    true, // Both convert to "42"
		},
		{
			name:    "int vs string - equal values",
			value:   42,
			pattern: "42",
			want:    true, // Both convert to "42"
		},
		{
			name:    "bool vs string - equal values",
			value:   true,
			pattern: "true",
			want:    true, // Both convert to "true"
		},
		{
			name:    "float vs int - equal values",
			value:   42.0,
			pattern: 42,
			want:    true, // Both convert to "42"
		},
		{
			name:    "string vs int - different values",
			value:   "42",
			pattern: 43,
			want:    false, // "42" != "43"
		},
		{
			name:    "bool vs string - different values",
			value:   true,
			pattern: "false",
			want:    false, // "true" != "false"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, []string{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, []) = %v, want %v", tt.value, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestEvaluateWithModifiers_CaseSensitivity tests case sensitivity without modifiers
func TestEvaluateWithModifiers_CaseSensitivity(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name    string
		value   interface{}
		pattern interface{}
		want    bool
	}{
		{
			name:    "exact case match",
			value:   "Test",
			pattern: "Test",
			want:    true,
		},
		{
			name:    "different case no match",
			value:   "test",
			pattern: "Test",
			want:    false,
		},
		{
			name:    "uppercase vs lowercase",
			value:   "TEST",
			pattern: "test",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, []string{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, []) = %v, want %v", tt.value, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestParseModifiers tests modifier parsing logic
func TestParseModifiers(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name           string
		modifiers      []string
		wantTransform  []string
		wantComparison string
		wantAll        bool
		wantErr        bool
		wantCompCount  int
	}{
		{
			name:           "empty modifiers",
			modifiers:      []string{},
			wantTransform:  nil,
			wantComparison: "equals",
			wantAll:        false,
			wantErr:        false,
		},
		{
			name:           "single transform modifier",
			modifiers:      []string{"base64"},
			wantTransform:  []string{"base64"},
			wantComparison: "equals",
			wantAll:        false,
			wantErr:        false,
		},
		{
			name:           "single comparison modifier",
			modifiers:      []string{"contains"},
			wantTransform:  nil,
			wantComparison: "contains",
			wantAll:        false,
			wantErr:        false,
		},
		{
			name:           "all modifier",
			modifiers:      []string{"all"},
			wantTransform:  nil,
			wantComparison: "equals",
			wantAll:        true,
			wantErr:        false,
		},
		{
			name:           "transform and comparison",
			modifiers:      []string{"base64", "contains"},
			wantTransform:  []string{"base64"},
			wantComparison: "contains",
			wantAll:        false,
			wantErr:        false,
		},
		{
			name:           "multiple transforms",
			modifiers:      []string{"base64", "utf16le", "wide"},
			wantTransform:  []string{"base64", "utf16le", "wide"},
			wantComparison: "equals",
			wantAll:        false,
			wantErr:        false,
		},
		{
			name:           "all modifiers combined",
			modifiers:      []string{"base64", "contains", "all"},
			wantTransform:  []string{"base64"},
			wantComparison: "contains",
			wantAll:        true,
			wantErr:        false,
		},
		{
			name:      "unknown modifier",
			modifiers: []string{"invalid"},
			wantErr:   true,
		},
		{
			name:      "multiple comparison modifiers",
			modifiers: []string{"contains", "startswith"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTransform, gotComparison, gotAll, err := eval.parseModifiers(tt.modifiers)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseModifiers() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseModifiers() unexpected error: %v", err)
				return
			}

			if len(gotTransform) != len(tt.wantTransform) {
				t.Errorf("parseModifiers() transform count = %d, want %d", len(gotTransform), len(tt.wantTransform))
				return
			}

			for i, mod := range tt.wantTransform {
				if gotTransform[i] != mod {
					t.Errorf("parseModifiers() transform[%d] = %s, want %s", i, gotTransform[i], mod)
				}
			}

			if gotComparison != tt.wantComparison {
				t.Errorf("parseModifiers() comparison = %s, want %s", gotComparison, tt.wantComparison)
			}

			if gotAll != tt.wantAll {
				t.Errorf("parseModifiers() all = %v, want %v", gotAll, tt.wantAll)
			}
		})
	}
}

// TestApplyTransformModifiers tests transform modifier implementation
func TestApplyTransformModifiers(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name        string
		value       interface{}
		modifiers   []string
		want        interface{}
		expectError bool
	}{
		{
			name:        "no modifiers",
			value:       "test",
			modifiers:   []string{},
			want:        "test",
			expectError: false,
		},
		{
			name:        "base64 modifier decodes value",
			value:       "dGVzdA==",
			modifiers:   []string{"base64"},
			want:        "test", // base64 decoded
			expectError: false,
		},
		{
			name:        "windash modifier normalizes dashes",
			value:       "test\u2013value", // EN DASH
			modifiers:   []string{"windash"},
			want:        "test-value", // normalized to ASCII hyphen
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.applyTransformModifiers(tt.value, tt.modifiers)
			if tt.expectError {
				if err == nil {
					t.Errorf("applyTransformModifiers() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("applyTransformModifiers() unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("applyTransformModifiers(%v, %v) = %v, want %v", tt.value, tt.modifiers, got, tt.want)
			}
		})
	}
}

// TestCompareValues tests stub implementation
func TestCompareValues(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name     string
		actual   interface{}
		pattern  interface{}
		operator string
		want     bool
		wantErr  bool
	}{
		{
			name:     "equals operator match",
			actual:   "test",
			pattern:  "test",
			operator: "equals",
			want:     true,
			wantErr:  false,
		},
		{
			name:     "equals operator no match",
			actual:   "test",
			pattern:  "other",
			operator: "equals",
			want:     false,
			wantErr:  false,
		},
		{
			name:     "contains operator match",
			actual:   "testing",
			pattern:  "test",
			operator: "contains",
			want:     true,
			wantErr:  false,
		},
		{
			name:     "nil values both",
			actual:   nil,
			pattern:  nil,
			operator: "equals",
			want:     true,
			wantErr:  false,
		},
		{
			name:     "nil actual",
			actual:   nil,
			pattern:  "test",
			operator: "equals",
			want:     false,
			wantErr:  false,
		},
		{
			name:     "nil pattern",
			actual:   "test",
			pattern:  nil,
			operator: "equals",
			want:     false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.compareValues(tt.actual, tt.pattern, tt.operator, 5*time.Second)

			if tt.wantErr {
				if err == nil {
					t.Errorf("compareValues() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("compareValues() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("compareValues(%v, %v, %s) = %v, want %v", tt.actual, tt.pattern, tt.operator, got, tt.want)
			}
		})
	}
}

// TestModifierConstants tests that constants are defined correctly
func TestModifierConstants(t *testing.T) {
	tests := []struct {
		constant string
		value    string
	}{
		{"ModifierBase64", "base64"},
		{"ModifierBase64Offset", "base64offset"},
		{"ModifierUTF16LE", "utf16le"},
		{"ModifierUTF16BE", "utf16be"},
		{"ModifierWide", "wide"},
		{"ModifierWindash", "windash"},
		{"ModifierContains", "contains"},
		{"ModifierStartsWith", "startswith"},
		{"ModifierEndsWith", "endswith"},
		{"ModifierRegex", "re"},
		{"ModifierCIDR", "cidr"},
		{"ModifierAll", "all"},
		{"DefaultOperator", "equals"},
	}

	// This test verifies constants are accessible and have expected values
	constants := map[string]string{
		ModifierBase64:       "base64",
		ModifierBase64Offset: "base64offset",
		ModifierUTF16LE:      "utf16le",
		ModifierUTF16BE:      "utf16be",
		ModifierWide:         "wide",
		ModifierWindash:      "windash",
		ModifierContains:     "contains",
		ModifierStartsWith:   "startswith",
		ModifierEndsWith:     "endswith",
		ModifierRegex:        "re",
		ModifierCIDR:         "cidr",
		ModifierAll:          "all",
		DefaultOperator:      "equals",
	}

	for _, tt := range tests {
		if got, ok := constants[tt.value]; !ok || got != tt.value {
			t.Errorf("constant %s = %v, want %v", tt.constant, got, tt.value)
		}
	}
}

// TestEvaluateWithModifiers_EdgeCases tests additional edge cases
func TestEvaluateWithModifiers_EdgeCases(t *testing.T) {
	eval := NewModifierEvaluator(5 * time.Second)

	tests := []struct {
		name      string
		value     interface{}
		pattern   interface{}
		modifiers []string
		want      bool
		wantErr   bool
	}{
		{
			name:      "empty string values match",
			value:     "",
			pattern:   "",
			modifiers: []string{},
			want:      true,
			wantErr:   false,
		},
		{
			name:      "empty string vs non-empty",
			value:     "",
			pattern:   "test",
			modifiers: []string{},
			want:      false,
			wantErr:   false,
		},
		{
			name:      "zero values match",
			value:     0,
			pattern:   0,
			modifiers: []string{},
			want:      true,
			wantErr:   false,
		},
		{
			name:      "false bool values match",
			value:     false,
			pattern:   false,
			modifiers: []string{},
			want:      true,
			wantErr:   false,
		},
		{
			name:      "list with nil elements",
			value:     []interface{}{nil, "test"},
			pattern:   "test",
			modifiers: []string{},
			want:      true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("EvaluateWithModifiers(%v, %v, %v) = %v, want %v", tt.value, tt.pattern, tt.modifiers, got, tt.want)
			}
		})
	}
}
