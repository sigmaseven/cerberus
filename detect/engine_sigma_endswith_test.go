package detect

import (
	"fmt"
	"testing"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// SIGMA SPECIFICATION COMPLIANCE TESTS - ENDS_WITH OPERATOR
// ============================================================================
//
// **PURPOSE**: Validate ends_with operator compliance with Sigma Specification v2.1.0
// **REFERENCE**: BACKEND_TEST_IMPROVEMENTS.md GAP-SIGMA-005
// **SPECIFICATION**: sigma-compliance.md Section 2.4 (ends_with operator)
//
// **CRITICAL REQUIREMENTS** (from Sigma spec):
// 1. Suffix Matching: Value must be suffix of field value
// 2. Case Sensitivity: ".exe" ≠ ".EXE" (MUST be case-sensitive per current implementation)
// 3. Full String Match: Suffix can equal full string
// 4. Empty Suffix: Empty string is suffix of any string
//
// **IMPLEMENTATION UNDER TEST**: detect/engine.go line 400-406
// case "ends_with":
//     if str, ok := fieldValue.(string); ok {
//         if valStr, ok := cond.Value.(string); ok {
//             return strings.HasSuffix(str, valStr)
//         }
//     }
//     return false
//
// ============================================================================

// TestSigmaEndsWith_SuffixMatching validates
// ends_with operator performs suffix matching per Sigma specification v2.1.0 Section 2.4
func TestSigmaEndsWith_SuffixMatching(t *testing.T) {
	tests := []struct {
		name        string
		ruleValue   string
		eventValue  string
		shouldMatch bool
		reason      string
	}{
		{
			name:        "suffix_at_end",
			ruleValue:   ".exe",
			eventValue:  "cmd.exe",
			shouldMatch: true,
			reason:      "'.exe' is suffix of 'cmd.exe'",
		},
		{
			name:        "not_suffix",
			ruleValue:   ".exe",
			eventValue:  ".exe.backup",
			shouldMatch: false,
			reason:      "'.exe' is not suffix of '.exe.backup'",
		},
		{
			name:        "suffix_in_middle_fails",
			ruleValue:   "min",
			eventValue:  "Administrator",
			shouldMatch: false,
			reason:      "'min' in middle, not suffix",
		},
		{
			name:        "path_suffix",
			ruleValue:   "\\system32\\cmd.exe",
			eventValue:  "C:\\Windows\\system32\\cmd.exe",
			shouldMatch: true,
			reason:      "path suffix match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := core.Rule{
				ID:      "suffix_test",
		Type:    "sigma",
		Enabled: true,
		SigmaYAML: fmt.Sprintf(`
title: Suffix Test
logsource:
  product: syslog
detection:
  selection:
    filename|endswith: %s
  condition: selection
`, tt.ruleValue),
	}

			engine := newTestRuleEngineWithSigma([]core.Rule{rule})

			event := core.NewEvent()
			event.Fields = map[string]interface{}{
				"filename": tt.eventValue,
			}

			matches := engine.Evaluate(event)

			if tt.shouldMatch {
				require.Len(t, matches, 1, "ends_with suffix matching: %s", tt.reason)
			} else {
				assert.Empty(t, matches, "ends_with suffix matching: %s", tt.reason)
			}
		})
	}
}

// TestSigmaEndsWith_CaseSensitivity validates
// ends_with operator case sensitivity per current implementation
func TestSigmaEndsWith_CaseSensitivity(t *testing.T) {
	tests := []struct {
		name        string
		ruleValue   string
		eventValue  string
		shouldMatch bool
		reason      string
	}{
		{
			name:        "exact_case_match",
			ruleValue:   ".exe",
			eventValue:  "cmd.exe",
			shouldMatch: true,
			reason:      "exact case suffix match",
		},
		{
			name:        "case_mismatch_uppercase",
			ruleValue:   ".exe",
			eventValue:  "cmd.EXE",
			shouldMatch: false,
			reason:      "case-sensitive: '.exe' ≠ '.EXE'",
		},
		{
			name:        "case_mismatch_mixed",
			ruleValue:   ".EXE",
			eventValue:  "cmd.exe",
			shouldMatch: false,
			reason:      "case-sensitive: '.EXE' ≠ '.exe'",
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
  product: syslog
detection:
  selection:
    filename|endswith: %s
  condition: selection
`, tt.ruleValue),
	}

			engine := newTestRuleEngineWithSigma([]core.Rule{rule})

			event := core.NewEvent()
			event.Fields = map[string]interface{}{
				"filename": tt.eventValue,
			}

			matches := engine.Evaluate(event)

			if tt.shouldMatch {
				require.Len(t, matches, 1, "ends_with case sensitivity: %s", tt.reason)
			} else {
				assert.Empty(t, matches, "ends_with case sensitivity: %s", tt.reason)
			}
		})
	}
}

// TestSigmaEndsWith_FullStringMatch validates
// ends_with operator matches when suffix equals full string
func TestSigmaEndsWith_FullStringMatch(t *testing.T) {
	rule := core.Rule{
		ID:      "full_match_test",
		Type:    "sigma",
		Enabled: true,
		SigmaYAML: `
title: Full Match Test
logsource:
  product: syslog
detection:
  selection:
    filename|endswith: .exe
  condition: selection
`,
	}

	engine := newTestRuleEngineWithSigma([]core.Rule{rule})

	event := core.NewEvent()
	event.Fields = map[string]interface{}{
		"filename": ".exe", // Suffix equals full string
	}

	matches := engine.Evaluate(event)

	// MUST match per Sigma spec (suffix can equal full string)
	require.Len(t, matches, 1,
		"ends_with MUST match when suffix equals full string (implicit leading wildcard)")
}

// TestSigmaEndsWith_EmptySuffix validates
// ends_with operator empty suffix handling per Sigma specification
func TestSigmaEndsWith_EmptySuffix(t *testing.T) {
	rule := core.Rule{
		ID:      "empty_suffix_test",
		Type:    "sigma",
		Enabled: true,
		SigmaYAML: `
title: Empty Suffix Test
logsource:
  product: test
detection:
  selection:
    filename|endswith: ""
  condition: selection
`,
	}

	engine := newTestRuleEngineWithSigma([]core.Rule{rule})

	event := core.NewEvent()
	event.Fields = map[string]interface{}{
		"filename": "anything.exe",
	}

	matches := engine.Evaluate(event)

	// MUST match per Go strings.HasSuffix behavior (empty string is suffix of any string)
	require.Len(t, matches, 1,
		"ends_with with empty suffix MUST match any string per Go strings.HasSuffix")
}
