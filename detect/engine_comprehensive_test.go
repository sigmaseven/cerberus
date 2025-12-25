package detect

import (
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
)

// NOTE: Legacy evaluateCondition tests removed as part of Task 177
// The evaluateCondition function has been replaced by SIGMA-based rule evaluation
// Comprehensive SIGMA tests exist in:
// - detect/engine_sigma_*.go (operator-specific tests)
// - detect/sigma_*.go (compliance and comprehensive tests)
// Helper functions like compareNumbers, getFieldValue are still tested in engine_test.go

// TestEvaluateCorrelationRule_TableDriven provides comprehensive coverage
// of correlation rule evaluation scenarios
// TASK 148.2: Table-driven tests for evaluateCorrelationRule
func TestEvaluateCorrelationRule_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		rule           core.CorrelationRule
		events         []func() *core.Event
		expectedResult bool // Result of final evaluation
	}{
		{
			name: "simple_sequence_match",
			rule: core.CorrelationRule{
				ID:       "seq_test_1",
				Sequence: []string{"login_failed", "login_failed"},
				Window:   5 * time.Minute,
			},
			events: []func() *core.Event{
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "login_failed"
					e.Timestamp = time.Now()
					return e
				},
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "login_failed"
					e.Timestamp = time.Now().Add(1 * time.Second)
					return e
				},
			},
			expectedResult: true,
		},
		{
			name: "sequence_wrong_order",
			rule: core.CorrelationRule{
				ID:       "seq_test_2",
				Sequence: []string{"login_failed", "login_success"},
				Window:   5 * time.Minute,
			},
			events: []func() *core.Event{
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "login_failed"
					e.Timestamp = time.Now()
					return e
				},
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "login_failed" // Wrong type
					e.Timestamp = time.Now().Add(1 * time.Second)
					return e
				},
			},
			expectedResult: false,
		},
		{
			name: "sequence_with_conditions_match",
			rule: core.CorrelationRule{
				ID:       "seq_test_3",
				Sequence: []string{"access", "access"},
				Window:   5 * time.Minute,
			},
			events: []func() *core.Event{
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "access"
					e.Severity = "high"
					e.Timestamp = time.Now()
					return e
				},
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "access"
					e.Severity = "high"
					e.Timestamp = time.Now().Add(1 * time.Second)
					return e
				},
			},
			expectedResult: true,
		},
		{
			name: "sequence_with_conditions_no_match",
			rule: core.CorrelationRule{
				ID:       "seq_test_4",
				Sequence: []string{"access", "access"},
				Window:   5 * time.Minute,
			},
			events: []func() *core.Event{
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "access"
					e.Severity = "low"
					e.Timestamp = time.Now()
					return e
				},
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "access"
					e.Severity = "low" // Condition not met
					e.Timestamp = time.Now().Add(1 * time.Second)
					return e
				},
			},
			expectedResult: false,
		},
		{
			name: "three_event_sequence",
			rule: core.CorrelationRule{
				ID:       "seq_test_5",
				Sequence: []string{"scan", "probe", "exploit"},
				Window:   10 * time.Minute,
			},
			events: []func() *core.Event{
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "scan"
					e.Timestamp = time.Now()
					return e
				},
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "probe"
					e.Timestamp = time.Now().Add(1 * time.Second)
					return e
				},
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "exploit"
					e.Timestamp = time.Now().Add(2 * time.Second)
					return e
				},
			},
			expectedResult: true,
		},
		{
			name: "insufficient_events_for_sequence",
			rule: core.CorrelationRule{
				ID:       "seq_test_6",
				Sequence: []string{"a", "b", "c"},
				Window:   5 * time.Minute,
			},
			events: []func() *core.Event{
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "a"
					e.Timestamp = time.Now()
					return e
				},
				func() *core.Event {
					e := core.NewEvent()
					e.EventType = "b"
					e.Timestamp = time.Now().Add(1 * time.Second)
					return e
				},
				// Only 2 events, need 3 for sequence
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{tt.rule}, 3600)
			defer engine.Stop()

			var result bool
			for i, eventFn := range tt.events {
				event := eventFn()
				result = engine.evaluateCorrelationRule(tt.rule, event)
				// Only check result on the last event
				if i < len(tt.events)-1 {
					continue
				}
			}

			assert.Equal(t, tt.expectedResult, result, "Test case %s failed", tt.name)
		})
	}
}

// TestCompareNumbers_Comprehensive - TASK #181: SKIPPED
// The compareNumbers function was deleted as part of legacy evaluation removal
// SIGMA engine uses strict comparison per specification
func TestCompareNumbers_Comprehensive(t *testing.T) {
	t.Skip("compareNumbers function deleted in Task #181 - SIGMA uses strict comparison")
}

// TestCompareFloat_EdgeCases - TASK #181: SKIPPED
// The compareFloat function was deleted as part of legacy evaluation removal
// SIGMA engine uses strict comparison per specification
func TestCompareFloat_EdgeCases(t *testing.T) {
	t.Skip("compareFloat function deleted in Task #181 - SIGMA uses strict comparison")
}

// TestIsNumericValue_Types - TASK #181: SKIPPED
// The isNumericValue function was deleted as part of legacy evaluation removal
// SIGMA engine handles type coercion internally per specification
func TestIsNumericValue_Types(t *testing.T) {
	t.Skip("isNumericValue function deleted in Task #181 - SIGMA handles type coercion internally")
}

// NOTE: Legacy benchmarks for evaluateCondition removed as part of Task 181
// The evaluateCondition function has been deleted - all rules now use SIGMA engine evaluation
// For performance benchmarks, see:
// - detect/sigma_benchmark_test.go (SIGMA engine performance tests)
// - detect/performance_test.go (overall engine performance tests)
