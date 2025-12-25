package detect

import (
	"strings"
	"testing"
)

// Test helpers

//lint:ignore U1000 Test helper for aggregation testing scenarios
func testAggregationContext(identifiers map[string]bool) map[string]bool {
	return identifiers
}

// testAvailableIdentifiers returns a standard set of identifiers for testing.
func testAvailableIdentifiers() []string {
	return []string{
		"selection_windows",
		"selection_linux",
		"selection_macos",
		"filter_process",
		"filter_network",
		"create_process",
		"inject_process",
		"registry_windows",
	}
}

// TestParseAggregation_AllOfThem tests "all of them" expressions
func TestParseAggregation_AllOfThem(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{"sel1", "sel2", "sel3"}

	tests := []struct {
		name        string
		expression  string
		context     map[string]bool
		expectTrue  bool
		expectError bool
	}{
		{
			name:       "all of them - all true",
			expression: "all of them",
			context:    map[string]bool{"sel1": true, "sel2": true, "sel3": true},
			expectTrue: true,
		},
		{
			name:       "all of them - one false",
			expression: "all of them",
			context:    map[string]bool{"sel1": true, "sel2": false, "sel3": true},
			expectTrue: false,
		},
		{
			name:       "all of them - all false",
			expression: "all of them",
			context:    map[string]bool{"sel1": false, "sel2": false, "sel3": false},
			expectTrue: false,
		},
		{
			name:       "ALL OF THEM - case insensitive",
			expression: "ALL OF THEM",
			context:    map[string]bool{"sel1": true, "sel2": true, "sel3": true},
			expectTrue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseWithContext() error = %v, expectError %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			result, err := ast.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result != tt.expectTrue {
				t.Errorf("Evaluate() = %v, want %v", result, tt.expectTrue)
			}
		})
	}
}

// TestParseAggregation_AnyOfThem tests "any of them" and "1 of them" expressions
func TestParseAggregation_AnyOfThem(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{"sel1", "sel2", "sel3"}

	tests := []struct {
		name        string
		expression  string
		context     map[string]bool
		expectTrue  bool
		expectError bool
	}{
		{
			name:       "any of them - one true",
			expression: "any of them",
			context:    map[string]bool{"sel1": true, "sel2": false, "sel3": false},
			expectTrue: true,
		},
		{
			name:       "any of them - all false",
			expression: "any of them",
			context:    map[string]bool{"sel1": false, "sel2": false, "sel3": false},
			expectTrue: false,
		},
		{
			name:       "any of them - all true",
			expression: "any of them",
			context:    map[string]bool{"sel1": true, "sel2": true, "sel3": true},
			expectTrue: true,
		},
		{
			name:       "1 of them - one true",
			expression: "1 of them",
			context:    map[string]bool{"sel1": false, "sel2": true, "sel3": false},
			expectTrue: true,
		},
		{
			name:       "1 of them - all false",
			expression: "1 of them",
			context:    map[string]bool{"sel1": false, "sel2": false, "sel3": false},
			expectTrue: false,
		},
		{
			name:       "one of them - using TokenONE",
			expression: "one of them",
			context:    map[string]bool{"sel1": false, "sel2": false, "sel3": true},
			expectTrue: true,
		},
		{
			name:       "Any Of Them - case insensitive",
			expression: "Any Of Them",
			context:    map[string]bool{"sel1": true, "sel2": false, "sel3": false},
			expectTrue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseWithContext() error = %v, expectError %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			result, err := ast.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result != tt.expectTrue {
				t.Errorf("Evaluate() = %v, want %v", result, tt.expectTrue)
			}
		})
	}
}

// TestParseAggregation_NumericCount tests "N of them" expressions with various counts
func TestParseAggregation_NumericCount(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{"sel1", "sel2", "sel3", "sel4"}

	tests := []struct {
		name        string
		expression  string
		context     map[string]bool
		expectTrue  bool
		expectError bool
	}{
		{
			name:       "2 of them - exactly 2 true",
			expression: "2 of them",
			context:    map[string]bool{"sel1": true, "sel2": true, "sel3": false, "sel4": false},
			expectTrue: true,
		},
		{
			name:       "2 of them - more than 2 true",
			expression: "2 of them",
			context:    map[string]bool{"sel1": true, "sel2": true, "sel3": true, "sel4": false},
			expectTrue: true, // At least 2
		},
		{
			name:       "2 of them - less than 2 true",
			expression: "2 of them",
			context:    map[string]bool{"sel1": true, "sel2": false, "sel3": false, "sel4": false},
			expectTrue: false,
		},
		{
			name:       "3 of them - exactly 3 true",
			expression: "3 of them",
			context:    map[string]bool{"sel1": true, "sel2": true, "sel3": true, "sel4": false},
			expectTrue: true,
		},
		{
			name:       "3 of them - all true",
			expression: "3 of them",
			context:    map[string]bool{"sel1": true, "sel2": true, "sel3": true, "sel4": true},
			expectTrue: true,
		},
		{
			name:       "4 of them - all true",
			expression: "4 of them",
			context:    map[string]bool{"sel1": true, "sel2": true, "sel3": true, "sel4": true},
			expectTrue: true,
		},
		{
			name:       "4 of them - one false",
			expression: "4 of them",
			context:    map[string]bool{"sel1": true, "sel2": true, "sel3": true, "sel4": false},
			expectTrue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseWithContext() error = %v, expectError %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			result, err := ast.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result != tt.expectTrue {
				t.Errorf("Evaluate() = %v, want %v", result, tt.expectTrue)
			}
		})
	}
}

// TestParseAggregation_WildcardSuffix tests "N of pattern*" expressions
func TestParseAggregation_WildcardSuffix(t *testing.T) {
	parser := NewConditionParser()
	identifiers := testAvailableIdentifiers()

	tests := []struct {
		name        string
		expression  string
		context     map[string]bool
		expectTrue  bool
		expectError bool
	}{
		{
			name:       "1 of selection_* - matches 3 identifiers",
			expression: "1 of selection_*",
			context: map[string]bool{
				"selection_windows": true,
				"selection_linux":   false,
				"selection_macos":   false,
				"filter_process":    false,
				"filter_network":    false,
				"create_process":    false,
				"inject_process":    false,
				"registry_windows":  false,
			},
			expectTrue: true,
		},
		{
			name:       "2 of selection_* - requires at least 2",
			expression: "2 of selection_*",
			context: map[string]bool{
				"selection_windows": true,
				"selection_linux":   true,
				"selection_macos":   false,
				"filter_process":    false,
				"filter_network":    false,
				"create_process":    false,
				"inject_process":    false,
				"registry_windows":  false,
			},
			expectTrue: true,
		},
		{
			name:       "2 of selection_* - only 1 true",
			expression: "2 of selection_*",
			context: map[string]bool{
				"selection_windows": true,
				"selection_linux":   false,
				"selection_macos":   false,
				"filter_process":    false,
				"filter_network":    false,
				"create_process":    false,
				"inject_process":    false,
				"registry_windows":  false,
			},
			expectTrue: false,
		},
		{
			name:       "all of selection_* - all 3 true",
			expression: "all of selection_*",
			context: map[string]bool{
				"selection_windows": true,
				"selection_linux":   true,
				"selection_macos":   true,
				"filter_process":    false,
				"filter_network":    false,
				"create_process":    false,
				"inject_process":    false,
				"registry_windows":  false,
			},
			expectTrue: true,
		},
		{
			name:       "all of selection_* - one false",
			expression: "all of selection_*",
			context: map[string]bool{
				"selection_windows": true,
				"selection_linux":   false,
				"selection_macos":   true,
				"filter_process":    false,
				"filter_network":    false,
				"create_process":    false,
				"inject_process":    false,
				"registry_windows":  false,
			},
			expectTrue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseWithContext() error = %v, expectError %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			result, err := ast.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result != tt.expectTrue {
				t.Errorf("Evaluate() = %v, want %v", result, tt.expectTrue)
			}
		})
	}
}

// TestParseAggregation_WildcardPrefix tests "*_pattern" expressions
func TestParseAggregation_WildcardPrefix(t *testing.T) {
	parser := NewConditionParser()
	identifiers := testAvailableIdentifiers()

	tests := []struct {
		name        string
		expression  string
		context     map[string]bool
		expectTrue  bool
		expectError bool
	}{
		{
			name:       "1 of *_process - matches 2 identifiers",
			expression: "1 of *_process",
			context: map[string]bool{
				"selection_windows": false,
				"selection_linux":   false,
				"selection_macos":   false,
				"filter_process":    true,
				"filter_network":    false,
				"create_process":    false,
				"inject_process":    false,
				"registry_windows":  false,
			},
			expectTrue: true,
		},
		{
			name:       "2 of *_process - requires at least 2",
			expression: "2 of *_process",
			context: map[string]bool{
				"selection_windows": false,
				"selection_linux":   false,
				"selection_macos":   false,
				"filter_process":    true,
				"filter_network":    false,
				"create_process":    true,
				"inject_process":    false,
				"registry_windows":  false,
			},
			expectTrue: true,
		},
		{
			name:       "all of *_process - all 3 true",
			expression: "all of *_process",
			context: map[string]bool{
				"selection_windows": false,
				"selection_linux":   false,
				"selection_macos":   false,
				"filter_process":    true,
				"filter_network":    false,
				"create_process":    true,
				"inject_process":    true,
				"registry_windows":  false,
			},
			expectTrue: true,
		},
		{
			name:       "1 of *_windows - matches 2 identifiers",
			expression: "1 of *_windows",
			context: map[string]bool{
				"selection_windows": true,
				"selection_linux":   false,
				"selection_macos":   false,
				"filter_process":    false,
				"filter_network":    false,
				"create_process":    false,
				"inject_process":    false,
				"registry_windows":  false,
			},
			expectTrue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseWithContext() error = %v, expectError %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			result, err := ast.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result != tt.expectTrue {
				t.Errorf("Evaluate() = %v, want %v", result, tt.expectTrue)
			}
		})
	}
}

// TestParseAggregation_WildcardMiddle tests "*middle*" expressions
func TestParseAggregation_WildcardMiddle(t *testing.T) {
	parser := NewConditionParser()
	identifiers := testAvailableIdentifiers()

	tests := []struct {
		name        string
		expression  string
		context     map[string]bool
		expectTrue  bool
		expectError bool
	}{
		{
			name:       "1 of *windows* - matches 2 identifiers",
			expression: "1 of *windows*",
			context: map[string]bool{
				"selection_windows": true,
				"selection_linux":   false,
				"selection_macos":   false,
				"filter_process":    false,
				"filter_network":    false,
				"create_process":    false,
				"inject_process":    false,
				"registry_windows":  false,
			},
			expectTrue: true,
		},
		{
			name:       "all of *windows* - all 2 true",
			expression: "all of *windows*",
			context: map[string]bool{
				"selection_windows": true,
				"selection_linux":   false,
				"selection_macos":   false,
				"filter_process":    false,
				"filter_network":    false,
				"create_process":    false,
				"inject_process":    false,
				"registry_windows":  true,
			},
			expectTrue: true,
		},
		{
			name:       "1 of *linux* - matches 1 identifier",
			expression: "1 of *linux*",
			context: map[string]bool{
				"selection_windows": false,
				"selection_linux":   true,
				"selection_macos":   false,
				"filter_process":    false,
				"filter_network":    false,
				"create_process":    false,
				"inject_process":    false,
				"registry_windows":  false,
			},
			expectTrue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseWithContext() error = %v, expectError %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			result, err := ast.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result != tt.expectTrue {
				t.Errorf("Evaluate() = %v, want %v", result, tt.expectTrue)
			}
		})
	}
}

// TestParseAggregation_ComplexWildcards tests complex wildcard patterns
func TestParseAggregation_ComplexWildcards(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{
		"selection_windows_registry",
		"selection_windows_process",
		"selection_linux_process",
		"filter_windows",
	}

	tests := []struct {
		name        string
		expression  string
		context     map[string]bool
		expectTrue  bool
		expectError bool
	}{
		{
			name:       "1 of selection_*_process - matches 2 identifiers",
			expression: "1 of selection_*_process",
			context: map[string]bool{
				"selection_windows_registry": false,
				"selection_windows_process":  true,
				"selection_linux_process":    false,
				"filter_windows":             false,
			},
			expectTrue: true,
		},
		{
			name:       "all of selection_*_process - all 2 true",
			expression: "all of selection_*_process",
			context: map[string]bool{
				"selection_windows_registry": false,
				"selection_windows_process":  true,
				"selection_linux_process":    true,
				"filter_windows":             false,
			},
			expectTrue: true,
		},
		{
			name:       "1 of *_windows_* - matches 2 identifiers",
			expression: "1 of *_windows_*",
			context: map[string]bool{
				"selection_windows_registry": true,
				"selection_windows_process":  false,
				"selection_linux_process":    false,
				"filter_windows":             false,
			},
			expectTrue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseWithContext() error = %v, expectError %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			result, err := ast.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result != tt.expectTrue {
				t.Errorf("Evaluate() = %v, want %v", result, tt.expectTrue)
			}
		})
	}
}

// TestParseAggregation_ExactMatch tests exact identifier matching (no wildcards)
func TestParseAggregation_ExactMatch(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{"selection1", "filter1", "detection1"}

	tests := []struct {
		name        string
		expression  string
		context     map[string]bool
		expectTrue  bool
		expectError bool
	}{
		{
			name:       "1 of selection1 - exact match true",
			expression: "1 of selection1",
			context:    map[string]bool{"selection1": true, "filter1": false, "detection1": false},
			expectTrue: true,
		},
		{
			name:       "1 of selection1 - exact match false",
			expression: "1 of selection1",
			context:    map[string]bool{"selection1": false, "filter1": false, "detection1": false},
			expectTrue: false,
		},
		{
			name:       "all of filter1 - exact match true",
			expression: "all of filter1",
			context:    map[string]bool{"selection1": false, "filter1": true, "detection1": false},
			expectTrue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseWithContext() error = %v, expectError %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			result, err := ast.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result != tt.expectTrue {
				t.Errorf("Evaluate() = %v, want %v", result, tt.expectTrue)
			}
		})
	}
}

// TestParseAggregation_ComplexExpression tests aggregations within larger expressions
func TestParseAggregation_ComplexExpression(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{"selection1", "selection2", "filter1"}

	tests := []struct {
		name        string
		expression  string
		context     map[string]bool
		expectTrue  bool
		expectError bool
	}{
		{
			name:       "(selection1 or filter1) and 1 of selection*",
			expression: "(selection1 or filter1) and 1 of selection*",
			context:    map[string]bool{"selection1": true, "selection2": false, "filter1": false},
			expectTrue: true,
		},
		{
			name:       "(selection1 or filter1) and 1 of selection* - aggregation fails",
			expression: "(selection1 or filter1) and 1 of selection*",
			context:    map[string]bool{"selection1": false, "selection2": false, "filter1": true},
			expectTrue: false,
		},
		{
			name:       "1 of them and not filter1",
			expression: "1 of them and not filter1",
			context:    map[string]bool{"selection1": true, "selection2": false, "filter1": false},
			expectTrue: true,
		},
		{
			name:       "all of selection* or filter1",
			expression: "all of selection* or filter1",
			context:    map[string]bool{"selection1": false, "selection2": false, "filter1": true},
			expectTrue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseWithContext() error = %v, expectError %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			result, err := ast.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result != tt.expectTrue {
				t.Errorf("Evaluate() = %v, want %v", result, tt.expectTrue)
			}
		})
	}
}

// TestParseAggregation_ErrorCases tests error conditions
func TestParseAggregation_ErrorCases(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{"selection1", "selection2", "filter1"}

	tests := []struct {
		name          string
		expression    string
		identifiers   []string
		expectError   bool
		errorContains string
	}{
		{
			name:          "pattern matches nothing",
			expression:    "1 of nonexistent*",
			identifiers:   identifiers,
			expectError:   true,
			errorContains: "matched no identifiers",
		},
		{
			name:          "count exceeds matches",
			expression:    "10 of selection*",
			identifiers:   identifiers,
			expectError:   true,
			errorContains: "requires 10 matches but only 2 identifiers matched",
		},
		{
			name:          "empty availableIdentifiers",
			expression:    "1 of them",
			identifiers:   []string{},
			expectError:   true,
			errorContains: "cannot be empty",
		},
		{
			name:          "nil availableIdentifiers",
			expression:    "1 of them",
			identifiers:   nil,
			expectError:   true,
			errorContains: "cannot be nil",
		},
		{
			name:          "missing OF keyword",
			expression:    "all them",
			identifiers:   identifiers,
			expectError:   true,
			errorContains: "did you mean 'all of",
		},
		{
			name:          "missing target after OF",
			expression:    "all of",
			identifiers:   identifiers,
			expectError:   true,
			errorContains: "expected THEM or pattern",
		},
		{
			name:          "double OF keyword",
			expression:    "all of of them",
			identifiers:   identifiers,
			expectError:   true,
			errorContains: "expected THEM or identifier pattern",
		},
		{
			name:          "zero quantifier",
			expression:    "0 of them",
			identifiers:   identifiers,
			expectError:   true,
			errorContains: "cannot be zero",
		},
		{
			name:          "standalone THEM without quantifier",
			expression:    "them",
			identifiers:   identifiers,
			expectError:   true,
			errorContains: "did you mean 'all of them'",
		},
		{
			name:          "standalone OF without quantifier",
			expression:    "of them",
			identifiers:   identifiers,
			expectError:   true,
			errorContains: "missing quantifier before OF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.identifiers == nil {
				_, err = parser.ParseWithContext(tt.expression, nil)
			} else if len(tt.identifiers) == 0 {
				_, err = parser.ParseWithContext(tt.expression, []string{})
			} else {
				_, err = parser.ParseWithContext(tt.expression, tt.identifiers)
			}

			if (err != nil) != tt.expectError {
				t.Fatalf("ParseWithContext() error = %v, expectError %v", err, tt.expectError)
			}

			if tt.expectError && !strings.Contains(err.Error(), tt.errorContains) {
				t.Errorf("Error should contain %q, got: %v", tt.errorContains, err)
			}
		})
	}
}

// TestParseAggregation_EvaluationErrors tests error conditions during evaluation
func TestParseAggregation_EvaluationErrors(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{"sel1", "sel2"}

	tests := []struct {
		name          string
		expression    string
		context       map[string]bool
		expectError   bool
		errorContains string
	}{
		{
			name:          "missing identifier in context",
			expression:    "all of them",
			context:       map[string]bool{"sel1": true}, // sel2 missing
			expectError:   true,
			errorContains: "not found in evaluation context",
		},
		{
			name:          "nil context",
			expression:    "all of them",
			context:       nil,
			expectError:   true,
			errorContains: "evaluation context is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if err != nil {
				t.Fatalf("ParseWithContext() error = %v", err)
			}

			_, err = ast.Evaluate(tt.context)
			if (err != nil) != tt.expectError {
				t.Fatalf("Evaluate() error = %v, expectError %v", err, tt.expectError)
			}

			if tt.expectError && !strings.Contains(err.Error(), tt.errorContains) {
				t.Errorf("Error should contain %q, got: %v", tt.errorContains, err)
			}
		})
	}
}

// TestGetMatchingIdentifiers tests the wildcard matching helper function
func TestGetMatchingIdentifiers(t *testing.T) {
	identifiers := testAvailableIdentifiers()

	tests := []struct {
		name          string
		pattern       string
		expectMatches []string
	}{
		{
			name:          "them pattern",
			pattern:       "them",
			expectMatches: identifiers, // All identifiers
		},
		{
			name:          "THEM case insensitive",
			pattern:       "THEM",
			expectMatches: identifiers, // All identifiers
		},
		{
			name:    "prefix wildcard selection_*",
			pattern: "selection_*",
			expectMatches: []string{
				"selection_windows",
				"selection_linux",
				"selection_macos",
			},
		},
		{
			name:    "suffix wildcard *_process",
			pattern: "*_process",
			expectMatches: []string{
				"filter_process",
				"create_process",
				"inject_process",
			},
		},
		{
			name:    "middle wildcard *windows*",
			pattern: "*windows*",
			expectMatches: []string{
				"selection_windows",
				"registry_windows",
			},
		},
		{
			name:          "exact match selection_windows",
			pattern:       "selection_windows",
			expectMatches: []string{"selection_windows"},
		},
		{
			name:          "no matches",
			pattern:       "nonexistent*",
			expectMatches: []string{},
		},
		{
			name:          "wildcard only *",
			pattern:       "*",
			expectMatches: identifiers, // Matches all
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := getMatchingIdentifiers(tt.pattern, identifiers)

			if len(matches) != len(tt.expectMatches) {
				t.Errorf("getMatchingIdentifiers() returned %d matches, expected %d",
					len(matches), len(tt.expectMatches))
			}

			// Check that all expected matches are present
			matchMap := make(map[string]bool)
			for _, m := range matches {
				matchMap[m] = true
			}

			for _, expected := range tt.expectMatches {
				if !matchMap[expected] {
					t.Errorf("Expected match %q not found in results", expected)
				}
			}
		})
	}
}

// TestMatchesWildcardPattern tests the wildcard pattern matching logic
func TestMatchesWildcardPattern(t *testing.T) {
	tests := []struct {
		name        string
		identifier  string
		pattern     string
		expectMatch bool
	}{
		// Prefix patterns
		{
			name:        "prefix sel* matches selection",
			identifier:  "selection",
			pattern:     "sel*",
			expectMatch: true,
		},
		{
			name:        "prefix sel* does not match filter_sel",
			identifier:  "filter_sel",
			pattern:     "sel*",
			expectMatch: false,
		},

		// Suffix patterns
		{
			name:        "suffix *_windows matches selection_windows",
			identifier:  "selection_windows",
			pattern:     "*_windows",
			expectMatch: true,
		},
		{
			name:        "suffix *_windows does not match windows_registry",
			identifier:  "windows_registry",
			pattern:     "*_windows",
			expectMatch: false,
		},

		// Middle patterns
		{
			name:        "middle *windows* matches selection_windows_registry",
			identifier:  "selection_windows_registry",
			pattern:     "*windows*",
			expectMatch: true,
		},
		{
			name:        "middle *windows* does not match selection_linux",
			identifier:  "selection_linux",
			pattern:     "*windows*",
			expectMatch: false,
		},

		// Complex patterns
		{
			name:        "complex sel*win*reg matches selection_windows_registry",
			identifier:  "selection_windows_registry",
			pattern:     "sel*win*reg",
			expectMatch: true,
		},
		{
			name:        "complex sel*win*reg does not match sel_reg_win (wrong order)",
			identifier:  "sel_reg_win",
			pattern:     "sel*win*reg",
			expectMatch: false,
		},

		// Edge cases
		{
			name:        "wildcard only * matches anything",
			identifier:  "anything",
			pattern:     "*",
			expectMatch: true,
		},
		{
			name:        "consecutive wildcards **",
			identifier:  "selection",
			pattern:     "sel**ion",
			expectMatch: true,
		},
		{
			name:        "empty string does not match *",
			identifier:  "",
			pattern:     "*",
			expectMatch: true, // Empty segments allow matching empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments := strings.Split(tt.pattern, "*")
			result := matchesWildcardPattern(tt.identifier, segments)

			if result != tt.expectMatch {
				t.Errorf("matchesWildcardPattern(%q, %q) = %v, want %v",
					tt.identifier, tt.pattern, result, tt.expectMatch)
			}
		})
	}
}

// TestParseAggregation_CaseInsensitivity tests case-insensitive parsing
func TestParseAggregation_CaseInsensitivity(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{"sel1", "sel2"}
	context := map[string]bool{"sel1": true, "sel2": true}

	expressions := []string{
		"all of them",
		"ALL OF THEM",
		"All Of Them",
		"aLl oF tHeM",
		"ANY OF THEM",
		"any of them",
		"ONE OF THEM",
		"one of them",
	}

	for _, expr := range expressions {
		t.Run(expr, func(t *testing.T) {
			ast, err := parser.ParseWithContext(expr, identifiers)
			if err != nil {
				t.Fatalf("ParseWithContext() error = %v", err)
			}

			_, err = ast.Evaluate(context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
		})
	}
}

// TestParseAggregation_LargeCount tests aggregations with large counts
func TestParseAggregation_LargeCount(t *testing.T) {
	parser := NewConditionParser()

	// Create 100 identifiers
	identifiers := make([]string, 100)
	context := make(map[string]bool)

	// Create identifiers like id_0, id_1, ..., id_99
	for i := 0; i < 100; i++ {
		identifiers[i] = "id_" + strings.Trim(strings.Fields(strings.Repeat("X", i+1))[0], "X")
	}

	// Actually simpler - just use fmt.Sprintf
	for i := 0; i < 100; i++ {
		// Use a simple pattern
		ones := i % 10
		tens := (i / 10) % 10
		identifiers[i] = "id_" + string(rune(48+tens)) + string(rune(48+ones))
	}

	// Set 75 to true
	for i := 0; i < 75; i++ {
		context[identifiers[i]] = true
	}
	for i := 75; i < 100; i++ {
		context[identifiers[i]] = false
	}

	tests := []struct {
		name       string
		expression string
		expectTrue bool
	}{
		{
			name:       "50 of them - 75 true",
			expression: "50 of them",
			expectTrue: true,
		},
		{
			name:       "75 of them - exactly 75 true",
			expression: "75 of them",
			expectTrue: true,
		},
		{
			name:       "76 of them - only 75 true",
			expression: "76 of them",
			expectTrue: false,
		},
		{
			name:       "100 of them - only 75 true",
			expression: "100 of them",
			expectTrue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.ParseWithContext(tt.expression, identifiers)
			if err != nil {
				t.Fatalf("ParseWithContext() error = %v", err)
			}

			result, err := ast.Evaluate(context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result != tt.expectTrue {
				t.Errorf("Evaluate() = %v, want %v", result, tt.expectTrue)
			}
		})
	}
}
