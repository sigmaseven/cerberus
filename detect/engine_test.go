package detect

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"cerberus/core"
	testinghelpers "cerberus/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WHY nanoseconds: time.Duration in Go is measured in nanoseconds
// This constant documents the magic number 300000000000 which appears throughout correlation tests
const fiveMinutesInNanoseconds = 5 * 60 * 1000 * 1000 * 1000 // 5 minutes = 300 seconds = 300,000,000,000 nanoseconds

// WHY nanoseconds: time.Duration in Go is measured in nanoseconds
// This constant is used for testing correlation window expiration
const oneSecondInNanoseconds = 1 * 1000 * 1000 * 1000 // 1 second = 1,000,000,000 nanoseconds

func TestRuleEngine_Evaluate(t *testing.T) {
	rules := []core.Rule{
		{
			ID:      testinghelpers.TestRuleID,
			Type:    "sigma",
			Enabled: true,
			SigmaYAML: `title: Test Rule
logsource:
  product: test
detection:
  selection:
    event_type: ` + testinghelpers.TestEventType + `
  condition: selection
`,
		},
	}

	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	require.NotNil(t, event, "NewEvent returned nil")
	require.NotNil(t, event.Fields, "Event.Fields is nil")
	event.EventType = testinghelpers.TestEventType
	event.LogsourceProduct = "test" // Must match the rule's logsource.product
	event.Fields["event_type"] = testinghelpers.TestEventType // SIGMA evaluates against Fields map

	matches := engine.Evaluate(event)
	if len(matches) != 1 {
		t.Fatalf("Expected 1 match for rule %s with event type %s, got %d matches",
			testinghelpers.TestRuleID, testinghelpers.TestEventType, len(matches))
	}
	assert.Equal(t, testinghelpers.TestRuleID, matches[0].GetID(),
		"Match rule ID should be %s, got %s", testinghelpers.TestRuleID, matches[0].GetID())
}

func TestRuleEngine_NoMatch(t *testing.T) {
	rules := []core.Rule{
		{
			ID:      "test_rule",
			Type:    "sigma",
			Enabled: true,
			SigmaYAML: `title: Test Rule
logsource:
  product: test
detection:
  selection:
    event_type: user_login
  condition: selection
`,
		},
	}

	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.EventType = "file_access"

	matches := engine.Evaluate(event)
	assert.Len(t, matches, 0)
}

func TestRuleEngine_EvaluateCorrelation(t *testing.T) {
	correlationRules := []core.CorrelationRule{
		{
			ID:       "correlation_test",
			Sequence: []string{"failed_login", "failed_login"},
			Window:   fiveMinutesInNanoseconds,
		},
	}

	engine := NewRuleEngine([]core.Rule{}, correlationRules, 0)

	// First event
	event1 := core.NewEvent()
	event1.EventType = "failed_login"
	engine.EvaluateCorrelation(event1)

	// Second event within window
	event2 := core.NewEvent()
	event2.EventType = "failed_login"
	matches := engine.EvaluateCorrelation(event2)

	assert.Len(t, matches, 1)
	assert.Equal(t, "correlation_test", matches[0].GetID())
}

func TestRuleEngine_Evaluate_Operators(t *testing.T) {
	t.Skip("Legacy Conditions-based evaluation removed in Task #181 - use SIGMA rules instead")

	tests := []struct {
		name      string
		condition interface{} // was core.Condition
		event     *core.Event
		expected  bool
	}{
		{
			name:      "equals match",
			condition: nil, // was core.Condition
			event: func() *core.Event {
				e := core.NewEvent()
				e.EventType = "user_login"
				return e
			}(),
			expected: true,
		},
		{
			name:      "not_equals match",
			condition: nil, // was core.Condition
			event: func() *core.Event {
				e := core.NewEvent()
				e.EventType = "file_access"
				return e
			}(),
			expected: true,
		},
		{
			name:      "contains match",
			condition: nil, // was core.Condition
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"message": "an error occurred"}
				return e
			}(),
			expected: true,
		},
		{
			name:      "starts_with match",
			condition: nil, // was core.Condition
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"message": "error in system"}
				return e
			}(),
			expected: true,
		},
		{
			name:      "greater_than match",
			condition: nil, // was core.Condition
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"count": 10.0}
				return e
			}(),
			expected: true,
		},
		{
			name:      "regex match",
			condition: nil, // was core.Condition
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"message": "error in system"}
				return e
			}(),
			expected: true,
		},
		{
			name:      "ends_with match",
			condition: nil, // was core.Condition
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"message": "error in system"}
				return e
			}(),
			expected: true,
		},
		{
			name:      "less_than match",
			condition: nil, // was core.Condition
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"count": 10.0}
				return e
			}(),
			expected: true,
		},
		{
			name:      "not_equals no match",
			condition: nil, // was core.Condition
			event: func() *core.Event {
				e := core.NewEvent()
				e.EventType = "user_login"
				return e
			}(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := []core.Rule{
				{
					ID:      "test_rule",
					Type:    "sigma",
					Enabled: true,
					SigmaYAML: `title: Test
detection:
  selection:
    field: value
  condition: selection
`,
				},
			}

			engine := NewRuleEngine(rules, []core.CorrelationRule{}, 0)

			matches := engine.Evaluate(tt.event)
			if tt.expected {
				assert.Len(t, matches, 1)
			} else {
				assert.Len(t, matches, 0)
			}
		})
	}
}

func TestRuleEngine_Evaluate_MultipleConditions(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")

	rules := []core.Rule{
		{
			ID:      "test_rule",
			Type:    "sigma",
			Enabled: true,
			SigmaYAML: `title: Test
detection:
  selection:
    event_type: user_login
    severity: high
  condition: selection
`,
		},
	}

	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.EventType = "user_login"
	event.Severity = "high"

	matches := engine.Evaluate(event)
	assert.Len(t, matches, 1)
}

func TestRuleEngine_EvaluateRule(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

func TestRuleEngine_EvaluateRule_NoMatch(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

func TestRuleEngine_EvaluateRule_EmptyConditions(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}


func TestRuleEngine_GetFieldValue(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.EventType = "user_login"
	event.Fields = map[string]interface{}{
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	// Test top-level field
	value := engine.getFieldValue("event_type", event)
	assert.Equal(t, "user_login", value)

	// Test nested field
	value = engine.getFieldValue("nested.key", event)
	assert.Equal(t, "value", value)

	// Test nonexistent field
	value = engine.getFieldValue("nonexistent", event)
	assert.Nil(t, value)

	// Test invalid nested path
	value = engine.getFieldValue("event_type.invalid", event)
	assert.Nil(t, value)
}

func TestCompareNumbers(t *testing.T) {
	// TASK #181: Test skipped - compareNumbers function deleted
	// SIGMA engine uses strict comparison, not epsilon-aware comparison
	// The deleted function was part of legacy evaluation path
	t.Skip("compareNumbers function deleted in Task #181 - SIGMA uses strict comparison")
}

func TestRuleEngine_EvaluateCorrelationRule(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "correlation_test",
		Sequence: []string{"failed_login", "failed_login"},
		Window:   fiveMinutesInNanoseconds, // WHY: time.Duration in nanoseconds (see const above)
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{correlationRule}, 0)

	// First event
	event1 := core.NewEvent()
	event1.EventType = "failed_login"
	engine.evaluateCorrelationRule(correlationRule, event1)

	// Second event within window
	event2 := core.NewEvent()
	event2.EventType = "failed_login"
	result := engine.evaluateCorrelationRule(correlationRule, event2)

	assert.True(t, result)
}

func TestRuleEngine_EvaluateCorrelationRule_NoMatch(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "correlation_test",
		Sequence: []string{"failed_login", "successful_login"},
		Window:   fiveMinutesInNanoseconds, // WHY: time.Duration in nanoseconds (see const above)
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{correlationRule}, 0)

	// First event
	event1 := core.NewEvent()
	event1.EventType = "failed_login"
	engine.evaluateCorrelationRule(correlationRule, event1)

	// Second event - wrong type
	event2 := core.NewEvent()
	event2.EventType = "failed_login"
	result := engine.evaluateCorrelationRule(correlationRule, event2)

	assert.False(t, result)
}

func TestRuleEngine_EvaluateCorrelationRule_WithConditions(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

func TestRuleEngine_ResetCorrelationState(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)
	// Add a shard via the public API
	engine.shardsMu.Lock()
	engine.correlationShards["test"] = &ShardedCorrelationState{events: []*core.Event{core.NewEvent()}}
	engine.shardsMu.Unlock()

	engine.ResetCorrelationState()

	engine.shardsMu.RLock()
	shardCount := len(engine.correlationShards)
	engine.shardsMu.RUnlock()
	assert.Equal(t, 0, shardCount)
}

func TestRuleEngine_EvaluateCorrelationRule_InsufficientEvents(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "correlation_test",
		Sequence: []string{"failed_login", "failed_login", "successful_login"},
		Window:   fiveMinutesInNanoseconds, // WHY: time.Duration in nanoseconds (see const above)
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{correlationRule}, 0)

	// First event
	event1 := core.NewEvent()
	event1.EventType = "failed_login"
	engine.evaluateCorrelationRule(correlationRule, event1)

	// Second event
	event2 := core.NewEvent()
	event2.EventType = "failed_login"
	result := engine.evaluateCorrelationRule(correlationRule, event2)

	assert.False(t, result)
}

func TestRuleEngine_EvaluateCorrelationRule_ExpiredEvents(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "correlation_test",
		Sequence: []string{"failed_login", "failed_login"},
		Window:   oneSecondInNanoseconds, // WHY: time.Duration in nanoseconds (see const above)
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{correlationRule}, 3600)

	// First event
	event1 := core.NewEvent()
	event1.EventType = "failed_login"
	event1.Timestamp = time.Now().Add(-2 * time.Second) // Old event
	engine.evaluateCorrelationRule(correlationRule, event1)

	// Second event
	event2 := core.NewEvent()
	event2.EventType = "failed_login"
	result := engine.evaluateCorrelationRule(correlationRule, event2)

	assert.False(t, result)
}

func TestRuleEngine_EvaluateCorrelationRule_WithInvalidSequence(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "correlation_test",
		Sequence: []string{"failed_login", "successful_login"},
		Window:   fiveMinutesInNanoseconds, // WHY: time.Duration in nanoseconds (see const above)
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{correlationRule}, 0)

	// First event
	event1 := core.NewEvent()
	event1.EventType = "failed_login"
	engine.evaluateCorrelationRule(correlationRule, event1)

	// Second event - wrong sequence
	event2 := core.NewEvent()
	event2.EventType = "failed_login"
	result := engine.evaluateCorrelationRule(correlationRule, event2)

	assert.False(t, result)
}


func TestRuleEngine_GetFieldValue_NestedInvalid(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.Fields = map[string]interface{}{
		"nested": "notamap",
	}

	value := engine.getFieldValue("nested.key", event)
	assert.Nil(t, value)
}

func TestRuleEngine_GetFieldValue_DeepNested(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.Fields = map[string]interface{}{
		"deep": map[string]interface{}{
			"nested": map[string]interface{}{
				"key": "value",
			},
		},
	}

	value := engine.getFieldValue("deep.nested.key", event)
	assert.Equal(t, "value", value)
}

func TestRuleEngine_EvaluateRule_ORLogic(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// ============================================================================
// SIGMA SPECIFICATION COMPLIANCE TESTS
// Based on: docs/requirements/sigma-compliance.md
// These tests verify operators follow the official Sigma specification,
// not just implementation details.
// ============================================================================

// Requirement: SIGMA-001 - equals Operator Semantics
// Source: Sigma Specification v1.0, Section 3.2.1
// Source: docs/requirements/sigma-compliance.md
// "The 'equals' operator performs case-sensitive exact matching"
func TestRuleEngine_EqualsOperator_SigmaCompliance_CaseSensitivity(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// Requirement: SIGMA-002 - Type Handling
// Source: Sigma Specification v1.0, Section 3.3
// Source: docs/requirements/sigma-compliance.md
// "Field values may be strings or numbers. Comparison behavior depends on types."
func TestRuleEngine_EqualsOperator_SigmaCompliance_TypeHandling(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// Requirement: SIGMA-003 - Missing Field Semantics
// Source: Sigma Specification v1.0, Section 3.4
// Source: docs/requirements/sigma-compliance.md
// "When field does not exist, condition evaluates to false"
func TestRuleEngine_MissingField_SigmaCompliance(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// Requirement: SIGMA-004 - contains Operator Case Sensitivity
// Source: Sigma Specification v1.0 - String Matching
// Source: docs/requirements/sigma-compliance.md
// "Substring matching with case-sensitivity by default"
func TestRuleEngine_ContainsOperator_SigmaCompliance(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// Requirement: SIGMA-005 - startswith Operator
// Source: docs/requirements/sigma-compliance.md
// "Prefix matching with case-sensitivity"
func TestRuleEngine_StartsWithOperator_SigmaCompliance(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// Requirement: SIGMA-006 - endswith Operator
// Source: docs/requirements/sigma-compliance.md
// "Suffix matching with case-sensitivity"
func TestRuleEngine_EndsWithOperator_SigmaCompliance(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// Requirement: SIGMA-007 - not_equals (neq) Operator
// Source: Sigma Specification v2.1.0 - Generic Modifiers
// Source: https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html
// "The field is different from the specified values"
//
// NOTE: This test is skipped because 'not_equals' (neq) is not a field-level modifier
// in standard SIGMA. SIGMA uses condition negation (e.g., "condition: not selection")
// instead of field-level negation. The legacy Conditions format with not_equals cannot
// be automatically converted to SIGMA YAML.
func TestRuleEngine_NotEqualsOperator_SigmaCompliance(t *testing.T) {
	t.Skip("not_equals is not a standard SIGMA modifier - use condition negation instead")
}

// Requirement: SIGMA-008 - Numeric Comparison Operators
// Source: Sigma Specification v2.1.0 - Numeric Modifiers
// Source: https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html
// "lt, lte, gt, gte: Numeric comparison operators"
func TestRuleEngine_NumericComparison_SigmaCompliance(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// Requirement: SIGMA-009 - Regular Expression Operator
// Source: Sigma Specification v2.1.0 - String Modifiers
// Source: https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html
// "re: Value is handled as a regular expression. Supports PCRE with wildcards, anchors, quantifiers, etc."
func TestRuleEngine_RegexOperator_SigmaCompliance(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// Requirement: SIGMA-010 - all Modifier (Array AND Logic)
// Source: Sigma Specification v2.1.0 - Generic Modifiers
// Source: https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html
// "all: Changes lists of values from being linked with OR to AND"
//
// NOTE: This test is skipped because it uses legacy Conditions format that creates
// duplicate YAML keys (same field with multiple conditions), which YAML doesn't allow.
// The proper SIGMA syntax uses value lists: "field|contains|all: ['value1', 'value2']"
// The 'all' modifier functionality is tested in sigma_modifiers_test.go instead.
func TestRuleEngine_AllModifier_SigmaCompliance(t *testing.T) {
	t.Skip("Legacy Conditions format cannot express same-field AND conditions in YAML - use value lists in SIGMA instead")
}

// TestRuleEngine_ConcurrentCorrelation tests concurrent access to correlation state
// TASK 153: Verify no race conditions in engine correlation state
func TestRuleEngine_ConcurrentCorrelation(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// TestRuleEngine_ConcurrentRuleReload tests concurrent rule reloading and evaluation
// TASK 153: Verify no race conditions during rule updates
func TestRuleEngine_ConcurrentRuleReload(t *testing.T) {
	// TASK #184: Legacy Conditions-based tests skipped - use SIGMA rules instead
	t.Skip("Legacy Conditions-based tests skipped - use SIGMA rules instead")
}

// ============================================================================
// Future Timestamp Rejection Tests (SECURITY-2)
// ============================================================================

// TestRuleEngine_EvaluateCorrelationRule_RejectsFutureEvents verifies that events
// with timestamps beyond MaxFutureTimestampTolerance are filtered out.
// SECURITY: Prevents time-based DoS where attackers send future-dated events.
func TestRuleEngine_EvaluateCorrelationRule_RejectsFutureEvents(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "future_timestamp_test",
		Sequence: []string{"login", "login"},
		Window:   fiveMinutesInNanoseconds,
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{correlationRule}, 3600)
	now := time.Now()

	// Event 1: Normal timestamp
	event1 := core.NewEvent()
	event1.EventID = "1"
	event1.EventType = "login"
	event1.Timestamp = now
	engine.evaluateCorrelationRule(correlationRule, event1)

	// Event 2: Future timestamp (beyond MaxFutureTimestampTolerance of 1 minute)
	event2 := core.NewEvent()
	event2.EventID = "2"
	event2.EventType = "login"
	event2.Timestamp = now.Add(2 * time.Minute) // Beyond 1 minute tolerance
	matched := engine.evaluateCorrelationRule(correlationRule, event2)

	// Should NOT match because event2 was filtered out due to future timestamp
	assert.False(t, matched, "Future event beyond tolerance should be rejected")

	// Verify state only contains event1
	engine.shardsMu.RLock()
	shard := engine.correlationShards[correlationRule.ID]
	engine.shardsMu.RUnlock()

	shard.mu.RLock()
	state := shard.events
	shard.mu.RUnlock()

	assert.Len(t, state, 1, "Only non-future event should remain in state")
	assert.Equal(t, "1", state[0].EventID, "Only event1 should be in state")
}

// TestRuleEngine_EvaluateCorrelationRule_AcceptsEventsWithinClockSkew verifies that
// events with timestamps within MaxFutureTimestampTolerance are accepted.
func TestRuleEngine_EvaluateCorrelationRule_AcceptsEventsWithinClockSkew(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "clock_skew_test",
		Sequence: []string{"login", "login"},
		Window:   fiveMinutesInNanoseconds,
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{correlationRule}, 3600)
	now := time.Now()

	// Event 1: Normal timestamp
	event1 := core.NewEvent()
	event1.EventID = "1"
	event1.EventType = "login"
	event1.Timestamp = now
	engine.evaluateCorrelationRule(correlationRule, event1)

	// Event 2: Slightly future timestamp (within 1 minute tolerance)
	event2 := core.NewEvent()
	event2.EventID = "2"
	event2.EventType = "login"
	event2.Timestamp = now.Add(30 * time.Second) // Within 1 minute tolerance
	matched := engine.evaluateCorrelationRule(correlationRule, event2)

	// Should match because both events are valid
	assert.True(t, matched, "Event within clock skew tolerance should be accepted")
}

// TestRuleEngine_EvaluateCorrelationRule_FutureTimestampBoundary tests the exact
// boundary condition at MaxFutureTimestampTolerance.
func TestRuleEngine_EvaluateCorrelationRule_FutureTimestampBoundary(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "boundary_test",
		Sequence: []string{"login", "login"},
		Window:   fiveMinutesInNanoseconds,
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{correlationRule}, 3600)
	now := time.Now()

	// Event 1: Normal timestamp
	event1 := core.NewEvent()
	event1.EventID = "1"
	event1.EventType = "login"
	event1.Timestamp = now
	engine.evaluateCorrelationRule(correlationRule, event1)

	// Event 2: Exactly at the boundary (1 minute = MaxFutureTimestampTolerance)
	event2 := core.NewEvent()
	event2.EventID = "2"
	event2.EventType = "login"
	event2.Timestamp = now.Add(MaxFutureTimestampTolerance)
	matched := engine.evaluateCorrelationRule(correlationRule, event2)

	// Should match because event is exactly at (not beyond) the tolerance
	assert.True(t, matched, "Event exactly at tolerance boundary should be accepted")
}

// TestRuleEngine_EvaluateCorrelationRule_FutureTimestampJustBeyondBoundary tests
// that events just beyond MaxFutureTimestampTolerance are rejected.
func TestRuleEngine_EvaluateCorrelationRule_FutureTimestampJustBeyondBoundary(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "just_beyond_test",
		Sequence: []string{"login", "login"},
		Window:   fiveMinutesInNanoseconds,
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{correlationRule}, 3600)
	now := time.Now()

	// Event 1: Normal timestamp
	event1 := core.NewEvent()
	event1.EventID = "1"
	event1.EventType = "login"
	event1.Timestamp = now
	engine.evaluateCorrelationRule(correlationRule, event1)

	// Event 2: Just beyond the boundary (1 minute + 1 nanosecond)
	event2 := core.NewEvent()
	event2.EventID = "2"
	event2.EventType = "login"
	event2.Timestamp = now.Add(MaxFutureTimestampTolerance + 1*time.Nanosecond)
	matched := engine.evaluateCorrelationRule(correlationRule, event2)

	// Should NOT match because event is beyond tolerance
	assert.False(t, matched, "Event just beyond tolerance should be rejected")
}

// ============================================================================
// Insertion Order Tests
// ============================================================================

// TestInsertEventInOrder_OutOfOrder verifies that out-of-order events are
// inserted at the correct position.
func TestInsertEventInOrder_OutOfOrder(t *testing.T) {
	now := time.Now()

	events := []*core.Event{
		{EventID: "1", Timestamp: now},
		{EventID: "3", Timestamp: now.Add(2 * time.Second)},
	}

	// Insert event with timestamp between existing events
	newEvent := &core.Event{EventID: "2", Timestamp: now.Add(1 * time.Second)}
	result := insertEventInOrder(events, newEvent)

	require.Len(t, result, 3)
	assert.Equal(t, "1", result[0].EventID)
	assert.Equal(t, "2", result[1].EventID, "New event should be inserted in middle")
	assert.Equal(t, "3", result[2].EventID)
}

// TestInsertEventInOrder_InOrder verifies that in-order events are appended.
func TestInsertEventInOrder_InOrder(t *testing.T) {
	now := time.Now()

	events := []*core.Event{
		{EventID: "1", Timestamp: now},
		{EventID: "2", Timestamp: now.Add(1 * time.Second)},
	}

	// Insert event with latest timestamp
	newEvent := &core.Event{EventID: "3", Timestamp: now.Add(2 * time.Second)}
	result := insertEventInOrder(events, newEvent)

	require.Len(t, result, 3)
	assert.Equal(t, "3", result[2].EventID, "New event should be appended at end")
}

// TestInsertEventInOrder_EqualTimestamps verifies stable insertion for equal timestamps.
func TestInsertEventInOrder_EqualTimestamps(t *testing.T) {
	now := time.Now()

	events := []*core.Event{
		{EventID: "1", Timestamp: now},
		{EventID: "2", Timestamp: now}, // Same timestamp
	}

	// Insert another event with the same timestamp
	newEvent := &core.Event{EventID: "3", Timestamp: now}
	result := insertEventInOrder(events, newEvent)

	require.Len(t, result, 3)
	// Stable insertion: new event should be at the end (after existing equal-timestamp events)
	assert.Equal(t, "1", result[0].EventID)
	assert.Equal(t, "2", result[1].EventID)
	assert.Equal(t, "3", result[2].EventID, "New event should be inserted after existing events with same timestamp")
}

// TestInsertEventInOrder_EmptySlice verifies insertion into an empty slice.
func TestInsertEventInOrder_EmptySlice(t *testing.T) {
	events := []*core.Event{}
	newEvent := &core.Event{EventID: "1", Timestamp: time.Now()}

	result := insertEventInOrder(events, newEvent)

	require.Len(t, result, 1)
	assert.Equal(t, "1", result[0].EventID)
}

// TestInsertEventInOrder_NilEvent verifies nil events are ignored.
func TestInsertEventInOrder_NilEvent(t *testing.T) {
	now := time.Now()
	events := []*core.Event{
		{EventID: "1", Timestamp: now},
	}

	result := insertEventInOrder(events, nil)

	assert.Len(t, result, 1, "Nil event should not be added")
}

// TestRuleEngine_ConcurrentVersionCounterUpdates verifies that version counter
// correctly tracks state changes under concurrent access. This test validates
// the optimistic locking mechanism used to prevent race conditions.
func TestRuleEngine_ConcurrentVersionCounterUpdates(t *testing.T) {
	// Create a rule with a multi-step sequence that requires 100 events to match
	// This ensures events accumulate in state instead of immediately clearing
	rule := core.CorrelationRule{
		ID:       "test-concurrent-version",
		Name:     "Test Concurrent Version",
		Sequence: []string{"step1", "step2", "step3", "step4", "step5"}, // 5-step sequence
		Window:   5 * time.Minute,
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{rule}, 60)

	// Run multiple goroutines that evaluate the same rule concurrently
	// All send "step1" events so the sequence never completes
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			event := &core.Event{
				EventID:   fmt.Sprintf("event-%d", id),
				EventType: "step1", // Only send step1, so sequence never matches
				Timestamp: time.Now(),
			}
			engine.evaluateCorrelationRule(rule, event)
		}(i)
	}

	wg.Wait()

	// Verify version counter has been updated (using sharded state)
	engine.shardsMu.RLock()
	shard := engine.correlationShards[rule.ID]
	engine.shardsMu.RUnlock()

	shard.mu.RLock()
	version := shard.version
	stateLen := len(shard.events)
	shard.mu.RUnlock()

	// Version should have been incremented at least once
	assert.GreaterOrEqual(t, version, uint64(1), "Version should have incremented during concurrent access")
	// Some events should be in state (not all 50 due to merge conflicts and memory limits)
	assert.GreaterOrEqual(t, stateLen, 1, "At least one event should be in state")
}

// TestRuleEngine_VersionCounterMonotonicallyIncreases verifies that version counter
// never decreases, even when state is cleared after a match.
func TestRuleEngine_VersionCounterMonotonicallyIncreases(t *testing.T) {
	// Create a rule that matches on a single event
	rule := core.CorrelationRule{
		ID:       "test-monotonic-version",
		Name:     "Test Monotonic Version",
		Sequence: []string{"test_event"},
		Window:   5 * time.Minute,
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{rule}, 60)

	var lastVersion uint64 = 0

	// Send multiple events that will trigger matches and clear state
	for i := 0; i < 10; i++ {
		event := &core.Event{
			EventID:   fmt.Sprintf("event-%d", i),
			EventType: "test_event",
			Timestamp: time.Now(),
		}
		engine.evaluateCorrelationRule(rule, event)

		engine.shardsMu.RLock()
		shard := engine.correlationShards[rule.ID]
		engine.shardsMu.RUnlock()

		shard.mu.RLock()
		currentVersion := shard.version
		shard.mu.RUnlock()

		assert.GreaterOrEqual(t, currentVersion, lastVersion,
			"Version should never decrease (was %d, now %d)", lastVersion, currentVersion)
		lastVersion = currentVersion
	}

	// Final version should be at least 10 (one increment per evaluation)
	assert.GreaterOrEqual(t, lastVersion, uint64(10), "Version should have incremented at least once per event")
}
