package core

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 64.2: Comprehensive CQL Rule Tests
// Tests cover: CQL rule validation, structure, serialization, CorrelationConfig,
// CQLRuleMatch conversion, and error handling
//
// NOTE: CQL query parsing and execution is tested in search/parser_test.go and search/evaluator_test.go
// This file focuses on testing the CQLRule type itself

// TestCQLRule_Validate_ValidRule tests validation of valid CQL rule
func TestCQLRule_Validate_ValidRule(t *testing.T) {
	rule := CQLRule{
		ID:          "cql-test-1",
		Name:        "Test CQL Rule",
		Description: "Test description",
		Query:       `event_type == "failed_login" AND source_ip == "192.168.1.100"`,
		Severity:    "high",
		Enabled:     true,
	}

	err := rule.Validate()
	assert.NoError(t, err, "Valid CQL rule should pass validation")
}

// TestCQLRule_Validate_MissingName tests validation error for missing name
func TestCQLRule_Validate_MissingName(t *testing.T) {
	rule := CQLRule{
		ID:       "cql-test-2",
		Query:    `event_type == "failed_login"`,
		Severity: "medium",
		Enabled:  true,
	}

	err := rule.Validate()
	require.Error(t, err, "Rule without name should fail validation")
	assert.Contains(t, err.Error(), "name is required")
}

// TestCQLRule_Validate_MissingQuery tests validation error for missing query
func TestCQLRule_Validate_MissingQuery(t *testing.T) {
	rule := CQLRule{
		ID:       "cql-test-3",
		Name:     "Test Rule",
		Severity: "high",
		Enabled:  true,
	}

	err := rule.Validate()
	require.Error(t, err, "Rule without query should fail validation")
	assert.Contains(t, err.Error(), "query is required")
}

// TestCQLRule_Validate_InvalidSeverity tests validation error for invalid severity
func TestCQLRule_Validate_InvalidSeverity(t *testing.T) {
	rule := CQLRule{
		ID:       "cql-test-4",
		Name:     "Test Rule",
		Query:    `event_type == "failed_login"`,
		Severity: "invalid", // Invalid severity
		Enabled:  true,
	}

	err := rule.Validate()
	require.Error(t, err, "Rule with invalid severity should fail validation")
	assert.Contains(t, err.Error(), "invalid severity")
}

// TestCQLRule_Validate_SeverityValues tests all valid severity values
func TestCQLRule_Validate_SeverityValues(t *testing.T) {
	validSeverities := []string{"low", "medium", "high", "critical"}

	for _, severity := range validSeverities {
		t.Run(severity, func(t *testing.T) {
			rule := CQLRule{
				ID:       "cql-test-" + severity,
				Name:     "Test Rule",
				Query:    `event_type == "failed_login"`,
				Severity: severity,
				Enabled:  true,
			}

			err := rule.Validate()
			assert.NoError(t, err, "Severity %s should be valid", severity)
		})
	}
}

// TestCQLRule_Structure tests CQLRule structure and fields
func TestCQLRule_Structure(t *testing.T) {
	now := time.Now()
	rule := CQLRule{
		ID:          "cql-structure-test",
		Name:        "Structure Test Rule",
		Description: "Test rule structure",
		Query:       `event_type == "test" AND severity == "high"`,
		Severity:    "high",
		Enabled:     true,
		Tags:        []string{"test", "cql"},
		MITRE:       []string{"T1078", "T1084"},
		Actions:     []string{"action1", "action2"},
		Metadata: map[string]string{
			"author": "test-author",
			"source": "test-source",
		},
		CreatedAt:      now,
		UpdatedAt:      now,
		Author:         "Test Author",
		References:     []string{"ref1", "ref2"},
		FalsePositives: "Known false positive scenario",
	}

	assert.Equal(t, "cql-structure-test", rule.ID)
	assert.Equal(t, "Structure Test Rule", rule.Name)
	assert.Equal(t, `event_type == "test" AND severity == "high"`, rule.Query)
	assert.Equal(t, "high", rule.Severity)
	assert.True(t, rule.Enabled)
	assert.Len(t, rule.Tags, 2)
	assert.Len(t, rule.MITRE, 2)
	assert.Len(t, rule.Actions, 2)
	assert.NotNil(t, rule.Metadata)
	assert.Equal(t, now.Unix(), rule.CreatedAt.Unix())
	assert.Equal(t, now.Unix(), rule.UpdatedAt.Unix())
	assert.Equal(t, "Test Author", rule.Author)
	assert.Len(t, rule.References, 2)
	assert.Equal(t, "Known false positive scenario", rule.FalsePositives)
}

// TestCQLRule_CorrelationConfig tests CorrelationConfig structure
func TestCQLRule_CorrelationConfig(t *testing.T) {
	rule := CQLRule{
		ID:       "cql-correlation-test",
		Name:     "Correlation Test",
		Query:    `event_type == "login"`,
		Severity: "medium",
		Enabled:  true,
		Correlation: &CorrelationConfig{
			Timeframe:   300, // 5 minutes
			GroupBy:     []string{"source_ip", "username"},
			Aggregation: "count",
			Threshold:   10,
			Operator:    ">=",
		},
	}

	require.NotNil(t, rule.Correlation)
	assert.Equal(t, 300, rule.Correlation.Timeframe)
	assert.Equal(t, []string{"source_ip", "username"}, rule.Correlation.GroupBy)
	assert.Equal(t, "count", rule.Correlation.Aggregation)
	assert.Equal(t, 10, rule.Correlation.Threshold)
	assert.Equal(t, ">=", rule.Correlation.Operator)
}

// TestCQLRule_CorrelationConfig_AllAggregations tests all aggregation types
func TestCQLRule_CorrelationConfig_AllAggregations(t *testing.T) {
	aggregations := []string{"count", "sum", "avg", "min", "max", "distinct"}

	for _, agg := range aggregations {
		t.Run(agg, func(t *testing.T) {
			rule := CQLRule{
				ID:       "cql-agg-test-" + agg,
				Name:     "Aggregation Test",
				Query:    `event_type == "test"`,
				Severity: "medium",
				Enabled:  true,
				Correlation: &CorrelationConfig{
					Timeframe:   60,
					Aggregation: agg,
					Threshold:   5,
					Operator:    ">",
				},
			}

			assert.Equal(t, agg, rule.Correlation.Aggregation)
		})
	}
}

// TestCQLRule_Serialization tests JSON serialization/deserialization
func TestCQLRule_Serialization(t *testing.T) {
	now := time.Now()
	rule := CQLRule{
		ID:          "cql-serialization-test",
		Name:        "Serialization Test",
		Description: "Test JSON serialization",
		Query:       `event_type == "test" AND severity >= "high"`,
		Severity:    "high",
		Enabled:     true,
		Tags:        []string{"test"},
		MITRE:       []string{"T1078"},
		Actions:     []string{"action1"},
		Metadata: map[string]string{
			"key": "value",
		},
		CreatedAt:      now,
		UpdatedAt:      now,
		Author:         "Test Author",
		References:     []string{"ref1"},
		FalsePositives: "Test FP",
		Correlation: &CorrelationConfig{
			Timeframe:   300,
			GroupBy:     []string{"source_ip"},
			Aggregation: "count",
			Field:       "event_count",
			Threshold:   10,
			Operator:    ">=",
		},
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(rule)
	require.NoError(t, err, "Should serialize CQLRule to JSON")
	assert.NotEmpty(t, jsonData)

	// Deserialize from JSON
	var deserializedRule CQLRule
	err = json.Unmarshal(jsonData, &deserializedRule)
	require.NoError(t, err, "Should deserialize CQLRule from JSON")

	assert.Equal(t, rule.ID, deserializedRule.ID)
	assert.Equal(t, rule.Name, deserializedRule.Name)
	assert.Equal(t, rule.Query, deserializedRule.Query)
	assert.Equal(t, rule.Severity, deserializedRule.Severity)
	assert.Equal(t, rule.Enabled, deserializedRule.Enabled)
	assert.Equal(t, rule.Tags, deserializedRule.Tags)
	assert.Equal(t, rule.MITRE, deserializedRule.MITRE)
	assert.Equal(t, rule.Actions, deserializedRule.Actions)
	assert.NotNil(t, deserializedRule.Correlation)
	assert.Equal(t, rule.Correlation.Timeframe, deserializedRule.Correlation.Timeframe)
	assert.Equal(t, rule.Correlation.Aggregation, deserializedRule.Correlation.Aggregation)
	// JSON unmarshals numbers as float64, so we need to compare properly
	// REQUIREMENT: Threshold should be preserved through serialization
	assert.EqualValues(t, rule.Correlation.Threshold, deserializedRule.Correlation.Threshold, "Threshold should be preserved through JSON serialization")
	assert.Equal(t, rule.Correlation.Operator, deserializedRule.Correlation.Operator)
}

// TestCQLRule_Serialization_WithoutCorrelation tests serialization without correlation config
func TestCQLRule_Serialization_WithoutCorrelation(t *testing.T) {
	rule := CQLRule{
		ID:       "cql-no-correlation-test",
		Name:     "No Correlation Test",
		Query:    `event_type == "test"`,
		Severity: "medium",
		Enabled:  true,
		// No Correlation field
	}

	jsonData, err := json.Marshal(rule)
	require.NoError(t, err, "Should serialize rule without correlation")

	var deserializedRule CQLRule
	err = json.Unmarshal(jsonData, &deserializedRule)
	require.NoError(t, err, "Should deserialize rule without correlation")
	assert.Nil(t, deserializedRule.Correlation, "Correlation should be nil when not set")
}

// TestCQLRuleMatch_ToAlert tests CQLRuleMatch to Alert conversion
func TestCQLRuleMatch_ToAlert(t *testing.T) {
	rule := CQLRule{
		ID:       "cql-match-test",
		Name:     "Match Test Rule",
		Query:    `event_type == "failed_login"`,
		Severity: "high",
		MITRE:    []string{"T1078", "T1084"},
	}

	event := &Event{
		EventID:   "event-123",
		EventType: "failed_login",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"source_ip": "192.168.1.100",
			"username":  "testuser",
		},
	}

	match := &CQLRuleMatch{
		Rule:          &rule,
		Event:         event,
		Timestamp:     time.Now(),
		MatchedFields: map[string]interface{}{"event_type": "failed_login"},
	}

	alert, err := match.ToAlert()
	require.NoError(t, err, "ToAlert should not return error")
	require.NotNil(t, alert, "ToAlert should return non-nil alert")
	assert.Equal(t, rule.ID, alert.RuleID)
	assert.Equal(t, event.EventID, alert.EventID)
	assert.Equal(t, rule.Severity, alert.Severity)
	assert.Equal(t, rule.Name, alert.RuleName)
	assert.Equal(t, "cql", alert.RuleType)
	assert.Equal(t, rule.MITRE, alert.MitreTechniques)
	assert.Equal(t, event, alert.Event, "Alert should contain the matched event")
}

// TestCQLRuleMatch_ToAlert_NilEvent tests ToAlert error handling for nil event
func TestCQLRuleMatch_ToAlert_NilEvent(t *testing.T) {
	rule := &CQLRule{
		ID:       "test-rule",
		Name:     "Test Rule",
		Severity: "high",
	}

	match := &CQLRuleMatch{
		Rule:      rule,
		Event:     nil, // This should trigger error
		Timestamp: time.Now(),
	}

	alert, err := match.ToAlert()
	require.Error(t, err, "ToAlert should return error for nil event")
	assert.Nil(t, alert)
	assert.Contains(t, err.Error(), "failed to convert CQL match to alert")
}
// TestCQLRuleMatch_Structure tests CQLRuleMatch structure
func TestCQLRuleMatch_Structure(t *testing.T) {
	rule := CQLRule{
		ID:       "cql-match-structure-test",
		Name:     "Structure Test",
		Query:    `event_type == "test"`,
		Severity: "medium",
	}

	event := &Event{
		EventID:   "event-456",
		EventType: "test",
		Timestamp: time.Now(),
	}

	now := time.Now()
	matchedFields := map[string]interface{}{
		"event_type": "test",
		"severity":   "high",
	}

	match := &CQLRuleMatch{
		Rule:          &rule,
		Event:         event,
		Timestamp:     now,
		MatchedFields: matchedFields,
	}

	assert.Equal(t, &rule, match.Rule)
	assert.Equal(t, event, match.Event)
	assert.Equal(t, now.Unix(), match.Timestamp.Unix())
	assert.Equal(t, matchedFields, match.MatchedFields)
}

// TestCorrelationConfig_Structure tests CorrelationConfig structure
func TestCorrelationConfig_Structure(t *testing.T) {
	config := CorrelationConfig{
		Timeframe:   600, // 10 minutes
		GroupBy:     []string{"source_ip", "username"},
		Aggregation: "count",
		Field:       "event_count",
		Threshold:   15,
		Operator:    ">=",
	}

	assert.Equal(t, 600, config.Timeframe)
	assert.Equal(t, []string{"source_ip", "username"}, config.GroupBy)
	assert.Equal(t, "count", config.Aggregation)
	assert.Equal(t, "event_count", config.Field)
	assert.Equal(t, 15, config.Threshold)
	assert.Equal(t, ">=", config.Operator)
}

// TestCorrelationConfig_Serialization tests CorrelationConfig serialization
func TestCorrelationConfig_Serialization(t *testing.T) {
	config := CorrelationConfig{
		Timeframe:   300,
		GroupBy:     []string{"source_ip"},
		Aggregation: "distinct",
		Field:       "username",
		Threshold:   5,
		Operator:    ">",
	}

	jsonData, err := json.Marshal(config)
	require.NoError(t, err, "Should serialize CorrelationConfig to JSON")

	var deserializedConfig CorrelationConfig
	err = json.Unmarshal(jsonData, &deserializedConfig)
	require.NoError(t, err, "Should deserialize CorrelationConfig from JSON")

	assert.Equal(t, config.Timeframe, deserializedConfig.Timeframe)
	assert.Equal(t, config.GroupBy, deserializedConfig.GroupBy)
	assert.Equal(t, config.Aggregation, deserializedConfig.Aggregation)
	assert.Equal(t, config.Field, deserializedConfig.Field)
	// JSON unmarshals numbers as float64, so we need to compare properly
	// REQUIREMENT: Threshold should be preserved through serialization
	assert.EqualValues(t, config.Threshold, deserializedConfig.Threshold, "Threshold should be preserved through JSON serialization")
	assert.Equal(t, config.Operator, deserializedConfig.Operator)
}

// TestCQLRule_ComplexQuery tests CQL rule with complex query syntax
func TestCQLRule_ComplexQuery(t *testing.T) {
	complexQueries := []string{
		`event_type == "failed_login" AND (source_ip == "192.168.1.100" OR source_ip == "10.0.0.1")`,
		`event_type == "file_access" AND file_path CONTAINS "/etc/passwd" AND NOT user == "root"`,
		`severity >= "high" AND (event_type == "exploit" OR event_type == "malware")`,
		`timestamp >= "2024-01-01T00:00:00Z" AND event_type == "login"`,
		`source_ip MATCHES "^192\\.168\\." AND event_count > 10`,
	}

	for i, query := range complexQueries {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			rule := CQLRule{
				ID:       "cql-complex-" + string(rune('A'+i)),
				Name:     "Complex Query Test",
				Query:    query,
				Severity: "high",
				Enabled:  true,
			}

			err := rule.Validate()
			assert.NoError(t, err, "Complex query should pass validation: %s", query)
			assert.Equal(t, query, rule.Query)
		})
	}
}

// TestCQLRule_EmptyFields tests CQL rule with empty optional fields
func TestCQLRule_EmptyFields(t *testing.T) {
	rule := CQLRule{
		ID:       "cql-empty-fields-test",
		Name:     "Empty Fields Test",
		Query:    `event_type == "test"`,
		Severity: "low",
		Enabled:  false,
		// All other fields are empty/default
	}

	err := rule.Validate()
	assert.NoError(t, err, "Rule with empty optional fields should still be valid")
	assert.Nil(t, rule.Correlation)
	assert.Empty(t, rule.Tags)
	assert.Empty(t, rule.MITRE)
	assert.Empty(t, rule.Actions)
	assert.Nil(t, rule.Metadata)
	assert.Empty(t, rule.Author)
	assert.Empty(t, rule.References)
	assert.Empty(t, rule.FalsePositives)
}

// TestCQLRule_AllFields tests CQL rule with all fields populated
func TestCQLRule_AllFields(t *testing.T) {
	now := time.Now()
	rule := CQLRule{
		ID:          "cql-all-fields-test",
		Name:        "All Fields Test",
		Description: "Test with all fields",
		Query:       `event_type == "test" AND severity == "high"`,
		Severity:    "critical",
		Enabled:     true,
		Tags:        []string{"tag1", "tag2", "tag3"},
		MITRE:       []string{"T1078", "T1084", "T1055"},
		Actions:     []string{"action1", "action2", "action3"},
		Metadata: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
		CreatedAt:      now,
		UpdatedAt:      now,
		Author:         "Test Author",
		References:     []string{"ref1", "ref2"},
		FalsePositives: "Known false positive",
		Correlation: &CorrelationConfig{
			Timeframe:   300,
			GroupBy:     []string{"source_ip", "username"},
			Aggregation: "count",
			Field:       "event_count",
			Threshold:   10,
			Operator:    ">=",
		},
	}

	err := rule.Validate()
	assert.NoError(t, err, "Rule with all fields should be valid")

	// Verify all fields are set
	assert.NotEmpty(t, rule.ID)
	assert.NotEmpty(t, rule.Name)
	assert.NotEmpty(t, rule.Description)
	assert.NotEmpty(t, rule.Query)
	assert.NotEmpty(t, rule.Severity)
	assert.True(t, rule.Enabled)
	assert.Len(t, rule.Tags, 3)
	assert.Len(t, rule.MITRE, 3)
	assert.Len(t, rule.Actions, 3)
	assert.NotNil(t, rule.Metadata)
	assert.Len(t, rule.Metadata, 2)
	assert.NotZero(t, rule.CreatedAt)
	assert.NotZero(t, rule.UpdatedAt)
	assert.NotEmpty(t, rule.Author)
	assert.Len(t, rule.References, 2)
	assert.NotEmpty(t, rule.FalsePositives)
	assert.NotNil(t, rule.Correlation)
}
