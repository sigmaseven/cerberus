package detect

import (
	"regexp"
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
)

func TestRuleEngine_Evaluate(t *testing.T) {
	rules := []core.Rule{
		{
			ID:      "test_rule",
			Enabled: true,
			Conditions: []core.Condition{
				{
					Field:    "event_type",
					Operator: "equals",
					Value:    "user_login",
					Logic:    "AND",
				},
			},
		},
	}

	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.EventType = "user_login"

	matches := engine.Evaluate(event)
	assert.Len(t, matches, 1)
	assert.Equal(t, "test_rule", matches[0].GetID())
}

func TestRuleEngine_NoMatch(t *testing.T) {
	rules := []core.Rule{
		{
			ID:      "test_rule",
			Enabled: true,
			Conditions: []core.Condition{
				{
					Field:    "event_type",
					Operator: "equals",
					Value:    "user_login",
				},
			},
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
			Window:   300000000000, // 5 minutes
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
	tests := []struct {
		name      string
		condition core.Condition
		event     *core.Event
		expected  bool
	}{
		{
			name: "equals match",
			condition: core.Condition{
				Field:    "event_type",
				Operator: "equals",
				Value:    "user_login",
			},
			event: func() *core.Event {
				e := core.NewEvent()
				e.EventType = "user_login"
				return e
			}(),
			expected: true,
		},
		{
			name: "not_equals match",
			condition: core.Condition{
				Field:    "event_type",
				Operator: "not_equals",
				Value:    "user_login",
			},
			event: func() *core.Event {
				e := core.NewEvent()
				e.EventType = "file_access"
				return e
			}(),
			expected: true,
		},
		{
			name: "contains match",
			condition: core.Condition{
				Field:    "message",
				Operator: "contains",
				Value:    "error",
			},
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"message": "an error occurred"}
				return e
			}(),
			expected: true,
		},
		{
			name: "starts_with match",
			condition: core.Condition{
				Field:    "message",
				Operator: "starts_with",
				Value:    "error",
			},
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"message": "error in system"}
				return e
			}(),
			expected: true,
		},
		{
			name: "greater_than match",
			condition: core.Condition{
				Field:    "count",
				Operator: "greater_than",
				Value:    5.0,
			},
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"count": 10.0}
				return e
			}(),
			expected: true,
		},
		{
			name: "regex match",
			condition: core.Condition{
				Field:    "message",
				Operator: "regex",
				Value:    "error.*system",
				Regex:    regexp.MustCompile("error.*system"),
			},
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"message": "error in system"}
				return e
			}(),
			expected: true,
		},
		{
			name: "ends_with match",
			condition: core.Condition{
				Field:    "message",
				Operator: "ends_with",
				Value:    "system",
			},
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"message": "error in system"}
				return e
			}(),
			expected: true,
		},
		{
			name: "less_than match",
			condition: core.Condition{
				Field:    "count",
				Operator: "less_than",
				Value:    20.0,
			},
			event: func() *core.Event {
				e := core.NewEvent()
				e.Fields = map[string]interface{}{"count": 10.0}
				return e
			}(),
			expected: true,
		},
		{
			name: "not_equals no match",
			condition: core.Condition{
				Field:    "event_type",
				Operator: "not_equals",
				Value:    "user_login",
			},
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
					ID:         "test_rule",
					Enabled:    true,
					Conditions: []core.Condition{tt.condition},
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
	rules := []core.Rule{
		{
			ID:      "test_rule",
			Enabled: true,
			Conditions: []core.Condition{
				{
					Field:    "event_type",
					Operator: "equals",
					Value:    "user_login",
					Logic:    "AND",
				},
				{
					Field:    "severity",
					Operator: "equals",
					Value:    "high",
					Logic:    "AND",
				},
			},
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
	rule := core.Rule{
		ID:      "test_rule",
		Enabled: true,
		Conditions: []core.Condition{
			{
				Field:    "event_type",
				Operator: "equals",
				Value:    "user_login",
				Logic:    "AND",
			},
		},
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.EventType = "user_login"

	result := engine.evaluateRule(rule, event)
	assert.True(t, result)
}

func TestRuleEngine_EvaluateRule_NoMatch(t *testing.T) {
	rule := core.Rule{
		ID:      "test_rule",
		Enabled: true,
		Conditions: []core.Condition{
			{
				Field:    "event_type",
				Operator: "equals",
				Value:    "user_login",
				Logic:    "AND",
			},
		},
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.EventType = "file_access"

	result := engine.evaluateRule(rule, event)
	assert.False(t, result)
}

func TestRuleEngine_EvaluateRule_EmptyConditions(t *testing.T) {
	rule := core.Rule{
		ID:         "test_rule",
		Enabled:    true,
		Conditions: []core.Condition{},
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()

	result := engine.evaluateRule(rule, event)
	assert.False(t, result)
}

func TestRuleEngine_EvaluateCondition(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.EventType = "user_login"

	condition := core.Condition{
		Field:    "event_type",
		Operator: "equals",
		Value:    "user_login",
	}

	result := engine.evaluateCondition(condition, event)
	assert.True(t, result)
}

func TestRuleEngine_EvaluateCondition_FieldNotFound(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()

	condition := core.Condition{
		Field:    "nonexistent_field",
		Operator: "equals",
		Value:    "value",
	}

	result := engine.evaluateCondition(condition, event)
	assert.False(t, result)
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
	tests := []struct {
		name     string
		a        interface{}
		b        interface{}
		cmp      func(float64, float64) bool
		expected bool
	}{
		{"greater_than true", 10.0, 5.0, func(a, b float64) bool { return a > b }, true},
		{"greater_than false", 5.0, 10.0, func(a, b float64) bool { return a > b }, false},
		{"string numbers", "10", "5", func(a, b float64) bool { return a > b }, true},
		{"invalid string", "abc", "5", func(a, b float64) bool { return a > b }, false},
		{"non-numeric", "abc", "def", func(a, b float64) bool { return a > b }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareNumbers(tt.a, tt.b, tt.cmp)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRuleEngine_EvaluateCorrelationRule(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "correlation_test",
		Sequence: []string{"failed_login", "failed_login"},
		Window:   300000000000, // 5 minutes
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
		Window:   300000000000, // 5 minutes
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
	correlationRule := core.CorrelationRule{
		ID:       "correlation_test",
		Sequence: []string{"failed_login", "failed_login"},
		Window:   300000000000, // 5 minutes
		Conditions: []core.Condition{
			{
				Field:    "severity",
				Operator: "equals",
				Value:    "high",
			},
		},
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{correlationRule}, 0)

	// First event
	event1 := core.NewEvent()
	event1.EventType = "failed_login"
	engine.evaluateCorrelationRule(correlationRule, event1)

	// Second event - matches sequence but not conditions
	event2 := core.NewEvent()
	event2.EventType = "failed_login"
	event2.Severity = "low"
	result := engine.evaluateCorrelationRule(correlationRule, event2)

	assert.False(t, result)
}

func TestRuleEngine_ResetCorrelationState(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)
	engine.correlationState["test"] = []*core.Event{core.NewEvent()}

	engine.ResetCorrelationState()

	assert.Len(t, engine.correlationState, 0)
}

func TestRuleEngine_EvaluateCorrelationRule_InsufficientEvents(t *testing.T) {
	correlationRule := core.CorrelationRule{
		ID:       "correlation_test",
		Sequence: []string{"failed_login", "failed_login", "successful_login"},
		Window:   300000000000, // 5 minutes
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
		Window:   1000000000, // 1 second
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
		Window:   300000000000, // 5 minutes
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

func TestRuleEngine_EvaluateCondition_GreaterThanOrEqual(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.Fields = map[string]interface{}{"count": 10.0}

	condition := core.Condition{
		Field:    "count",
		Operator: "greater_than_or_equal",
		Value:    10.0,
	}

	result := engine.evaluateCondition(condition, event)
	assert.True(t, result)

	condition.Value = 15.0
	result = engine.evaluateCondition(condition, event)
	assert.False(t, result)
}

func TestRuleEngine_EvaluateCondition_LessThanOrEqual(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.Fields = map[string]interface{}{"count": 10.0}

	condition := core.Condition{
		Field:    "count",
		Operator: "less_than_or_equal",
		Value:    10.0,
	}

	result := engine.evaluateCondition(condition, event)
	assert.True(t, result)

	condition.Value = 5.0
	result = engine.evaluateCondition(condition, event)
	assert.False(t, result)
}

func TestRuleEngine_EvaluateCondition_InvalidOperator(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.Fields = map[string]interface{}{"field": "value"}

	condition := core.Condition{
		Field:    "field",
		Operator: "invalid_operator",
		Value:    "value",
	}

	result := engine.evaluateCondition(condition, event)
	assert.False(t, result)
}

func TestRuleEngine_EvaluateCondition_ContainsNonString(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.Fields = map[string]interface{}{"field": 123}

	condition := core.Condition{
		Field:    "field",
		Operator: "contains",
		Value:    "value",
	}

	result := engine.evaluateCondition(condition, event)
	assert.False(t, result)
}

func TestRuleEngine_EvaluateCondition_RegexInvalidValue(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.Fields = map[string]interface{}{"field": "test"}

	condition := core.Condition{
		Field:    "field",
		Operator: "regex",
		Value:    "[invalid regex",
	}

	result := engine.evaluateCondition(condition, event)
	assert.False(t, result)
}

func TestRuleEngine_EvaluateCondition_RegexNonString(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.Fields = map[string]interface{}{"field": 123}

	condition := core.Condition{
		Field:    "field",
		Operator: "regex",
		Value:    "test",
	}

	result := engine.evaluateCondition(condition, event)
	assert.False(t, result)
}

func TestRuleEngine_EvaluateCondition_StartsWithEndsWithNonString(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.Fields = map[string]interface{}{"field": 123}

	condition := core.Condition{
		Field:    "field",
		Operator: "starts_with",
		Value:    "test",
	}

	result := engine.evaluateCondition(condition, event)
	assert.False(t, result)

	condition.Operator = "ends_with"
	result = engine.evaluateCondition(condition, event)
	assert.False(t, result)
}

func TestRuleEngine_EvaluateCondition_CompareNumbersInvalid(t *testing.T) {
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	event := core.NewEvent()
	event.Fields = map[string]interface{}{"field": "notanumber"}

	condition := core.Condition{
		Field:    "field",
		Operator: "greater_than",
		Value:    10.0,
	}

	result := engine.evaluateCondition(condition, event)
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
	rule := core.Rule{
		ID:      "test_rule",
		Enabled: true,
		Conditions: []core.Condition{
			{
				Field:    "event_type",
				Operator: "equals",
				Value:    "user_login",
				Logic:    "OR",
			},
			{
				Field:    "severity",
				Operator: "equals",
				Value:    "high",
				Logic:    "AND",
			},
		},
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 0)

	// Test OR logic - first condition true
	event := core.NewEvent()
	event.EventType = "user_login"
	event.Severity = "low"

	result := engine.evaluateRule(rule, event)
	assert.True(t, result)

	// Test OR logic - second condition true
	event2 := core.NewEvent()
	event2.EventType = "file_access"
	event2.Severity = "high"

	result = engine.evaluateRule(rule, event2)
	assert.True(t, result)

	// Test OR logic - both false
	event3 := core.NewEvent()
	event3.EventType = "file_access"
	event3.Severity = "low"

	result = engine.evaluateRule(rule, event3)
	assert.False(t, result)
}
