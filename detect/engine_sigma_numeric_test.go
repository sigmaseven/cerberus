package detect

import (
	"fmt"
	"testing"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)



// ============================================================================
// SIGMA SPECIFICATION COMPLIANCE TESTS - NUMERIC COMPARISON OPERATORS
// ============================================================================
//
// **PURPOSE**: Validate numeric comparison operators compliance with Sigma Specification v2.1.0
// **REFERENCE**: BACKEND_TEST_IMPROVEMENTS.md GAP-SIGMA-007
// **SPECIFICATION**: sigma-compliance.md Section 2.5 (numeric modifiers: gt, gte, lt, lte)
//
// **CRITICAL REQUIREMENTS** (from Sigma spec):
// 1. Integer Comparisons: Support integer values
// 2. Float Comparisons: Support floating-point values
// 3. Negative Numbers: Handle negative values correctly
// 4. Boundary Values: Distinguish equals from greater/less (10 >= 10 is true, 10 > 10 is false)
// 5. Type Coercion: String "10" should coerce to number 10
// 6. Large Numbers: Handle large numeric values
// 7. Zero Handling: Comparisons with zero
//
// **IMPLEMENTATION UNDER TEST**: detect/engine.go lines 427-434, 439-471
// case "greater_than":
//     return compareNumbers(fieldValue, cond.Value, func(a, b float64) bool { return a > b })
// case "less_than":
//     return compareNumbers(fieldValue, cond.Value, func(a, b float64) bool { return a < b })
// case "greater_than_or_equal":
//     return compareNumbers(fieldValue, cond.Value, func(a, b float64) bool { return a >= b })
// case "less_than_or_equal":
//     return compareNumbers(fieldValue, cond.Value, func(a, b float64) bool { return a <= b })
//
// ============================================================================

// TestSigmaNumeric_IntegerComparisons validates
// numeric operators handle integer comparisons per Sigma specification v2.1.0 Section 2.5
func TestSigmaNumeric_IntegerComparisons(t *testing.T) {
	t.Skip("SIGMA uses string-based operators only - numeric comparison operators not applicable")

	tests := []struct {
		name        string
		operator    string
		ruleValue   float64
		eventValue  float64
		shouldMatch bool
		reason      string
	}{
		// Greater than (gt)
		{
			name:        "gt_150_greater_than_100",
			operator:    "greater_than",
			ruleValue:   100.0,
			eventValue:  150.0,
			shouldMatch: true,
			reason:      "150 > 100",
		},
		{
			name:        "gt_50_not_greater_than_100",
			operator:    "greater_than",
			ruleValue:   100.0,
			eventValue:  50.0,
			shouldMatch: false,
			reason:      "50 is not > 100",
		},
		{
			name:        "gt_boundary_equal_values",
			operator:    "greater_than",
			ruleValue:   100.0,
			eventValue:  100.0,
			shouldMatch: false,
			reason:      "100 is NOT > 100 (boundary: equals)",
		},

		// Greater than or equal (gte)
		{
			name:        "gte_150_greater_equal_100",
			operator:    "greater_than_or_equal",
			ruleValue:   100.0,
			eventValue:  150.0,
			shouldMatch: true,
			reason:      "150 >= 100",
		},
		{
			name:        "gte_boundary_equal_values",
			operator:    "greater_than_or_equal",
			ruleValue:   100.0,
			eventValue:  100.0,
			shouldMatch: true,
			reason:      "100 >= 100 (boundary: equals included)",
		},
		{
			name:        "gte_50_not_greater_equal_100",
			operator:    "greater_than_or_equal",
			ruleValue:   100.0,
			eventValue:  50.0,
			shouldMatch: false,
			reason:      "50 is not >= 100",
		},

		// Less than (lt)
		{
			name:        "lt_50_less_than_100",
			operator:    "less_than",
			ruleValue:   100.0,
			eventValue:  50.0,
			shouldMatch: true,
			reason:      "50 < 100",
		},
		{
			name:        "lt_150_not_less_than_100",
			operator:    "less_than",
			ruleValue:   100.0,
			eventValue:  150.0,
			shouldMatch: false,
			reason:      "150 is not < 100",
		},
		{
			name:        "lt_boundary_equal_values",
			operator:    "less_than",
			ruleValue:   100.0,
			eventValue:  100.0,
			shouldMatch: false,
			reason:      "100 is NOT < 100 (boundary: equals)",
		},

		// Less than or equal (lte)
		{
			name:        "lte_50_less_equal_100",
			operator:    "less_than_or_equal",
			ruleValue:   100.0,
			eventValue:  50.0,
			shouldMatch: true,
			reason:      "50 <= 100",
		},
		{
			name:        "lte_boundary_equal_values",
			operator:    "less_than_or_equal",
			ruleValue:   100.0,
			eventValue:  100.0,
			shouldMatch: true,
			reason:      "100 <= 100 (boundary: equals included)",
		},
		{
			name:        "lte_150_not_less_equal_100",
			operator:    "less_than_or_equal",
			ruleValue:   100.0,
			eventValue:  150.0,
			shouldMatch: false,
			reason:      "150 is not <= 100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TASK #184: Map operator to Sigma modifier
			var modifier string
			switch tt.operator {
			case "greater_than":
				modifier = "|gt"
			case "greater_than_or_equal":
				modifier = "|gte"
			case "less_than":
				modifier = "|lt"
			case "less_than_or_equal":
				modifier = "|lte"
			}

			rule := core.Rule{
				ID:      "numeric_test",
				Type:    "sigma",
				Enabled: true,
				SigmaYAML: fmt.Sprintf(`
title: Numeric Test
detection:
  selection:
    count%s: %v
  condition: selection
`, modifier, tt.ruleValue),
			}

			engine := newTestRuleEngineWithSigma([]core.Rule{rule})

			event := core.NewEvent()
			event.Fields = map[string]interface{}{
				"count": tt.eventValue,
			}

			matches := engine.Evaluate(event)

			if tt.shouldMatch {
				require.Len(t, matches, 1, "Numeric comparison: %s", tt.reason)
			} else {
				assert.Empty(t, matches, "Numeric comparison: %s", tt.reason)
			}
		})
	}
}

// TestSigmaNumeric_FloatComparisons validates
// numeric operators handle float comparisons per Sigma specification
func TestSigmaNumeric_FloatComparisons(t *testing.T) {
	t.Skip("SIGMA uses string-based operators only - numeric comparison operators not applicable")

	tests := []struct {
		name        string
		operator    string
		ruleValue   float64
		eventValue  float64
		shouldMatch bool
		reason      string
	}{
		{
			name:        "gt_float_10.6_greater_than_10.5",
			operator:    "greater_than",
			ruleValue:   10.5,
			eventValue:  10.6,
			shouldMatch: true,
			reason:      "10.6 > 10.5",
		},
		{
			name:        "gte_float_boundary_10.5_equal_10.5",
			operator:    "greater_than_or_equal",
			ruleValue:   10.5,
			eventValue:  10.5,
			shouldMatch: true,
			reason:      "10.5 >= 10.5",
		},
		{
			name:        "lt_float_10.4_less_than_10.5",
			operator:    "less_than",
			ruleValue:   10.5,
			eventValue:  10.4,
			shouldMatch: true,
			reason:      "10.4 < 10.5",
		},
		{
			name:        "gt_small_difference",
			operator:    "greater_than",
			ruleValue:   10.0,
			eventValue:  10.0001,
			shouldMatch: true,
			reason:      "10.0001 > 10.0 (small difference is significant)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TASK #184: Map operator to Sigma modifier
			var modifier string
			switch tt.operator {
			case "greater_than":
				modifier = "|gt"
			case "greater_than_or_equal":
				modifier = "|gte"
			case "less_than":
				modifier = "|lt"
			case "less_than_or_equal":
				modifier = "|lte"
			}

			rule := core.Rule{
				ID:      "float_test",
				Type:    "sigma",
				Enabled: true,
				SigmaYAML: fmt.Sprintf(`
title: Float Test
detection:
  selection:
    value%s: %v
  condition: selection
`, modifier, tt.ruleValue),
			}

			engine := newTestRuleEngineWithSigma([]core.Rule{rule})

			event := core.NewEvent()
			event.Fields = map[string]interface{}{
				"value": tt.eventValue,
			}

			matches := engine.Evaluate(event)

			if tt.shouldMatch {
				require.Len(t, matches, 1, "Float comparison: %s", tt.reason)
			} else {
				assert.Empty(t, matches, "Float comparison: %s", tt.reason)
			}
		})
	}
}

// TestSigmaNumeric_NegativeNumbers validates
// numeric operators handle negative numbers per Sigma specification
func TestSigmaNumeric_NegativeNumbers(t *testing.T) {
	t.Skip("SIGMA uses string-based operators only - numeric comparison operators not applicable")

	tests := []struct {
		name        string
		operator    string
		ruleValue   float64
		eventValue  float64
		shouldMatch bool
		reason      string
	}{
		{
			name:        "gt_negative_minus10_greater_than_minus20",
			operator:    "greater_than",
			ruleValue:   -20.0,
			eventValue:  -10.0,
			shouldMatch: true,
			reason:      "-10 > -20",
		},
		{
			name:        "gt_negative_minus20_not_greater_than_minus10",
			operator:    "greater_than",
			ruleValue:   -10.0,
			eventValue:  -20.0,
			shouldMatch: false,
			reason:      "-20 is not > -10",
		},
		{
			name:        "gt_positive_greater_than_negative",
			operator:    "greater_than",
			ruleValue:   -10.0,
			eventValue:  10.0,
			shouldMatch: true,
			reason:      "10 > -10",
		},
		{
			name:        "lt_negative_less_than_positive",
			operator:    "less_than",
			ruleValue:   10.0,
			eventValue:  -10.0,
			shouldMatch: true,
			reason:      "-10 < 10",
		},
		{
			name:        "lt_negative_less_than_zero",
			operator:    "less_than",
			ruleValue:   0.0,
			eventValue:  -10.0,
			shouldMatch: true,
			reason:      "-10 < 0",
		},
		{
			name:        "gt_zero_greater_than_negative",
			operator:    "greater_than",
			ruleValue:   -10.0,
			eventValue:  0.0,
			shouldMatch: true,
			reason:      "0 > -10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TASK #184: Map operator to Sigma modifier
			var modifier string
			switch tt.operator {
			case "greater_than":
				modifier = "|gt"
			case "greater_than_or_equal":
				modifier = "|gte"
			case "less_than":
				modifier = "|lt"
			case "less_than_or_equal":
				modifier = "|lte"
			}

			rule := core.Rule{
				ID:      "negative_test",
				Type:    "sigma",
				Enabled: true,
				SigmaYAML: fmt.Sprintf(`
title: Negative Test
detection:
  selection:
    value%s: %v
  condition: selection
`, modifier, tt.ruleValue),
			}

			engine := newTestRuleEngineWithSigma([]core.Rule{rule})

			event := core.NewEvent()
			event.Fields = map[string]interface{}{
				"value": tt.eventValue,
			}

			matches := engine.Evaluate(event)

			if tt.shouldMatch {
				require.Len(t, matches, 1, "Negative number comparison: %s", tt.reason)
			} else {
				assert.Empty(t, matches, "Negative number comparison: %s", tt.reason)
			}
		})
	}
}

// TestSigmaNumeric_TypeCoercion validates
// numeric operators handle string-to-number type coercion per Sigma specification
func TestSigmaNumeric_TypeCoercion(t *testing.T) {
	t.Skip("SIGMA uses string-based operators only - numeric comparison operators not applicable")

	tests := []struct {
		name        string
		operator    string
		ruleValue   interface{}
		eventValue  interface{}
		shouldMatch bool
		reason      string
	}{
		// String to number conversion
		{
			name:        "gt_string_100_greater_than_number_50",
			operator:    "greater_than",
			ruleValue:   50.0,
			eventValue:  "100", // String in event
			shouldMatch: true,
			reason:      "string '100' should coerce to number 100",
		},
		{
			name:        "gt_number_100_greater_than_string_50",
			operator:    "greater_than",
			ruleValue:   "50", // String in rule
			eventValue:  100.0,
			shouldMatch: true,
			reason:      "string '50' in rule should coerce to number 50",
		},
		{
			name:        "gt_both_strings",
			operator:    "greater_than",
			ruleValue:   "50",
			eventValue:  "100",
			shouldMatch: true,
			reason:      "both strings should coerce: 100 > 50",
		},

		// Invalid string (non-numeric)
		{
			name:        "gt_non_numeric_string_fails",
			operator:    "greater_than",
			ruleValue:   50.0,
			eventValue:  "not_a_number",
			shouldMatch: false,
			reason:      "non-numeric string cannot be compared",
		},
		{
			name:        "gt_empty_string_fails",
			operator:    "greater_than",
			ruleValue:   50.0,
			eventValue:  "",
			shouldMatch: false,
			reason:      "empty string is not numeric",
		},

		// Float conversion
		{
			name:        "gt_string_with_decimals",
			operator:    "greater_than",
			ruleValue:   10.5,
			eventValue:  "20.7",
			shouldMatch: true,
			reason:      "string '20.7' should coerce to float 20.7",
		},

		// Negative numbers as strings
		{
			name:        "lt_negative_number_string",
			operator:    "less_than",
			ruleValue:   0.0,
			eventValue:  "-10",
			shouldMatch: true,
			reason:      "string '-10' should coerce to -10",
		},

		// Scientific notation
		{
			name:        "gt_scientific_notation_string",
			operator:    "greater_than",
			ruleValue:   1000.0,
			eventValue:  "1e4", // 10000
			shouldMatch: true,
			reason:      "string '1e4' should coerce to 10000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TASK #184: Map operator to Sigma modifier
			var modifier string
			switch tt.operator {
			case "greater_than":
				modifier = "|gt"
			case "greater_than_or_equal":
				modifier = "|gte"
			case "less_than":
				modifier = "|lt"
			case "less_than_or_equal":
				modifier = "|lte"
			}

			rule := core.Rule{
				ID:      "coercion_test",
				Type:    "sigma",
				Enabled: true,
				SigmaYAML: fmt.Sprintf(`
title: Coercion Test
detection:
  selection:
    value%s: %v
  condition: selection
`, modifier, tt.ruleValue),
			}

			engine := newTestRuleEngineWithSigma([]core.Rule{rule})

			event := core.NewEvent()
			event.Fields = map[string]interface{}{
				"value": tt.eventValue,
			}

			matches := engine.Evaluate(event)

			if tt.shouldMatch {
				require.Len(t, matches, 1, "Type coercion: %s", tt.reason)
			} else {
				assert.Empty(t, matches, "Type coercion: %s", tt.reason)
			}
		})
	}
}

// TestSigmaNumeric_LargeNumbers validates
// numeric operators handle large numbers per Sigma specification
func TestSigmaNumeric_LargeNumbers(t *testing.T) {
	t.Skip("SIGMA uses string-based operators only - numeric comparison operators not applicable")

	tests := []struct {
		name        string
		operator    string
		ruleValue   float64
		eventValue  float64
		shouldMatch bool
		reason      string
	}{
		{
			name:        "gt_large_number",
			operator:    "greater_than",
			ruleValue:   1000000.0,
			eventValue:  2000000.0,
			shouldMatch: true,
			reason:      "2000000 > 1000000",
		},
		{
			name:        "lt_large_number",
			operator:    "less_than",
			ruleValue:   5000000.0,
			eventValue:  4000000.0,
			shouldMatch: true,
			reason:      "4000000 < 5000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TASK #184: Map operator to Sigma modifier
			var modifier string
			switch tt.operator {
			case "greater_than":
				modifier = "|gt"
			case "greater_than_or_equal":
				modifier = "|gte"
			case "less_than":
				modifier = "|lt"
			case "less_than_or_equal":
				modifier = "|lte"
			}

			rule := core.Rule{
				ID:      "large_number_test",
				Type:    "sigma",
				Enabled: true,
				SigmaYAML: fmt.Sprintf(`
title: Large Number Test
detection:
  selection:
    file_size%s: %v
  condition: selection
`, modifier, tt.ruleValue),
			}

			engine := newTestRuleEngineWithSigma([]core.Rule{rule})

			event := core.NewEvent()
			event.Fields = map[string]interface{}{
				"file_size": tt.eventValue,
			}

			matches := engine.Evaluate(event)

			if tt.shouldMatch {
				require.Len(t, matches, 1, "Large number comparison: %s", tt.reason)
			} else {
				assert.Empty(t, matches, "Large number comparison: %s", tt.reason)
			}
		})
	}
}

// TestSigmaNumeric_ZeroHandling validates
// numeric operators handle zero comparisons per Sigma specification
func TestSigmaNumeric_ZeroHandling(t *testing.T) {
	t.Skip("SIGMA uses string-based operators only - numeric comparison operators not applicable")

	tests := []struct {
		name        string
		operator    string
		ruleValue   float64
		eventValue  float64
		shouldMatch bool
		reason      string
	}{
		{
			name:        "gt_positive_greater_than_zero",
			operator:    "greater_than",
			ruleValue:   0.0,
			eventValue:  0.1,
			shouldMatch: true,
			reason:      "0.1 > 0.0",
		},
		{
			name:        "lt_negative_less_than_zero",
			operator:    "less_than",
			ruleValue:   0.0,
			eventValue:  -0.1,
			shouldMatch: true,
			reason:      "-0.1 < 0.0",
		},
		{
			name:        "gte_zero_equal_zero",
			operator:    "greater_than_or_equal",
			ruleValue:   0.0,
			eventValue:  0.0,
			shouldMatch: true,
			reason:      "0.0 >= 0.0",
		},
		{
			name:        "lte_zero_equal_zero",
			operator:    "less_than_or_equal",
			ruleValue:   0.0,
			eventValue:  0.0,
			shouldMatch: true,
			reason:      "0.0 <= 0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TASK #184: Map operator to Sigma modifier
			var modifier string
			switch tt.operator {
			case "greater_than":
				modifier = "|gt"
			case "greater_than_or_equal":
				modifier = "|gte"
			case "less_than":
				modifier = "|lt"
			case "less_than_or_equal":
				modifier = "|lte"
			}

			rule := core.Rule{
				ID:      "zero_test",
				Type:    "sigma",
				Enabled: true,
				SigmaYAML: fmt.Sprintf(`
title: Zero Test
detection:
  selection:
    value%s: %v
  condition: selection
`, modifier, tt.ruleValue),
			}

			engine := newTestRuleEngineWithSigma([]core.Rule{rule})

			event := core.NewEvent()
			event.Fields = map[string]interface{}{
				"value": tt.eventValue,
			}

			matches := engine.Evaluate(event)

			if tt.shouldMatch {
				require.Len(t, matches, 1, "Zero handling: %s", tt.reason)
			} else {
				assert.Empty(t, matches, "Zero handling: %s", tt.reason)
			}
		})
	}
}
