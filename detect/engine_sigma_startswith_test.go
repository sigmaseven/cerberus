package detect

import (
	"fmt"
	"testing"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// SIGMA SPECIFICATION COMPLIANCE TESTS - STARTS_WITH OPERATOR
// ============================================================================
//
// **PURPOSE**: Validate starts_with operator compliance with Sigma Specification v2.1.0
// **REFERENCE**: BACKEND_TEST_IMPROVEMENTS.md GAP-SIGMA-004
// **SPECIFICATION**: sigma-compliance.md Section 2.3 (starts_with operator)
//
// **CRITICAL REQUIREMENTS** (from Sigma spec):
// 1. Prefix Matching: Value must be prefix of field value
// 2. Case Sensitivity: "Admin" ≠ "admin" (MUST be case-sensitive per current implementation)
// 3. Full String Match: Prefix can equal full string
// 4. Empty Prefix: Empty string is prefix of any string
//
// **NOTE**: Tests use 'test_field' instead of 'username' to avoid field alias
// mappings that would map 'username' to 'User'. This isolates the modifier
// functionality being tested.
//
// ============================================================================

// TestSigmaStartsWith_PrefixMatching validates
// starts_with operator performs prefix matching per Sigma specification v2.1.0 Section 2.3
func TestSigmaStartsWith_PrefixMatching(t *testing.T) {
	tests := []struct {
		name        string
		ruleValue   string
		eventValue  string
		shouldMatch bool
		reason      string
	}{
		{
			name:        "prefix_at_start",
			ruleValue:   "Admin",
			eventValue:  "Administrator",
			shouldMatch: true,
			reason:      "'Admin' is prefix of 'Administrator'",
		},
		{
			name:        "not_prefix",
			ruleValue:   "Admin",
			eventValue:  "SystemAdmin",
			shouldMatch: false,
			reason:      "'Admin' is not prefix of 'SystemAdmin'",
		},
		{
			name:        "prefix_in_middle_fails",
			ruleValue:   "min",
			eventValue:  "Administrator",
			shouldMatch: false,
			reason:      "'min' in middle, not prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := core.Rule{
				ID:      "prefix_test",
				Type:    "sigma",
				Enabled: true,
				SigmaYAML: fmt.Sprintf(`
title: Prefix Test
logsource:
  product: test
detection:
  selection:
    test_field|startswith: %s
  condition: selection
`, tt.ruleValue),
			}

			engine := newTestRuleEngineWithSigma([]core.Rule{rule})

			event := core.NewEvent()
			event.Fields = map[string]interface{}{
				"test_field": tt.eventValue,
			}

			matches := engine.Evaluate(event)

			if tt.shouldMatch {
				require.Len(t, matches, 1, "starts_with prefix matching: %s", tt.reason)
			} else {
				assert.Empty(t, matches, "starts_with prefix matching: %s", tt.reason)
			}
		})
	}
}

// TestSigmaStartsWith_CaseSensitivity validates
// starts_with operator case sensitivity per current implementation
func TestSigmaStartsWith_CaseSensitivity(t *testing.T) {
	tests := []struct {
		name        string
		ruleValue   string
		eventValue  string
		shouldMatch bool
		reason      string
	}{
		{
			name:        "exact_case_match",
			ruleValue:   "Admin",
			eventValue:  "Administrator",
			shouldMatch: true,
			reason:      "exact case prefix match",
		},
		{
			name:        "case_mismatch",
			ruleValue:   "Admin",
			eventValue:  "administrator",
			shouldMatch: false,
			reason:      "case-sensitive: 'Admin' ≠ 'admin'",
		},
		{
			name:        "case_mismatch_uppercase",
			ruleValue:   "admin",
			eventValue:  "ADMINISTRATOR",
			shouldMatch: false,
			reason:      "case-sensitive: 'admin' ≠ 'ADMIN'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := core.Rule{
				ID:      "case_test",
				Type:    "sigma",
				Enabled: true,
				SigmaYAML: fmt.Sprintf(`
title: Case Test
logsource:
  product: test
detection:
  selection:
    test_field|startswith: %s
  condition: selection
`, tt.ruleValue),
			}

			engine := newTestRuleEngineWithSigma([]core.Rule{rule})

			event := core.NewEvent()
			event.Fields = map[string]interface{}{
				"test_field": tt.eventValue,
			}

			matches := engine.Evaluate(event)

			if tt.shouldMatch {
				require.Len(t, matches, 1, "starts_with case sensitivity: %s", tt.reason)
			} else {
				assert.Empty(t, matches, "starts_with case sensitivity: %s", tt.reason)
			}
		})
	}
}

// TestSigmaStartsWith_FullStringMatch validates
// starts_with operator matches when prefix equals full string
func TestSigmaStartsWith_FullStringMatch(t *testing.T) {
	rule := core.Rule{
		ID:      "full_match_test",
		Type:    "sigma",
		Enabled: true,
		SigmaYAML: `
title: Full Match Test
logsource:
  product: test
detection:
  selection:
    test_field|startswith: Admin
  condition: selection
`,
	}

	engine := newTestRuleEngineWithSigma([]core.Rule{rule})

	event := core.NewEvent()
	event.Fields = map[string]interface{}{
		"test_field": "Admin", // Prefix equals full string
	}

	matches := engine.Evaluate(event)

	// MUST match per Sigma spec (prefix can equal full string)
	require.Len(t, matches, 1,
		"starts_with MUST match when prefix equals full string (implicit trailing wildcard)")
}

// TestSigmaStartsWith_EmptyPrefix validates
// starts_with operator empty prefix handling per Sigma specification
func TestSigmaStartsWith_EmptyPrefix(t *testing.T) {
	// Use SIGMA YAML with empty string value
	rule := core.Rule{
		ID:      "empty_prefix_test",
		Type:    "sigma",
		Enabled: true,
		SigmaYAML: `
title: Empty Prefix Test
logsource:
  product: test
detection:
  selection:
    test_field|startswith: ''
  condition: selection
`,
	}

	engine := newTestRuleEngineWithSigma([]core.Rule{rule})

	event := core.NewEvent()
	event.Fields = map[string]interface{}{
		"test_field": "anything",
	}

	matches := engine.Evaluate(event)

	// MUST match per Go strings.HasPrefix behavior (empty string is prefix of any string)
	require.Len(t, matches, 1,
		"starts_with with empty prefix MUST match any string per Go strings.HasPrefix")
}
