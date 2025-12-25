package core

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 64.1: Comprehensive Correlation Rule Evaluation Tests
// Tests cover: correlation rule structure, validation, serialization, threshold evaluation,
// AlertableRule interface methods, and rule type definitions
//
// NOTE: Actual correlation evaluation logic is tested in detect/correlation_evaluators_test.go
// This file focuses on testing the core correlation rule types themselves

// TestCountCorrelationRule_Structure tests CountCorrelationRule structure and fields
func TestCountCorrelationRule_Structure(t *testing.T) {
	rule := CountCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:          "count-test-1",
			Type:        CorrelationTypeCount,
			Name:        "Failed Login Threshold",
			Description: "Detects multiple failed login attempts",
			Severity:    "high",
			Enabled:     true,
			Tags:        []string{"authentication", "brute_force"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		Window:  5 * time.Minute,
		GroupBy: []string{"source_ip", "username"},
		Threshold: Threshold{
			Operator: ThresholdOpGreaterEqual,
			Value:    5.0,
		},
		Selection: map[string]interface{}{
			"event_type": "failed_login",
		},
		Actions: []Action{
			{ID: "action1", Type: "webhook"},
		},
	}

	assert.Equal(t, "count-test-1", rule.ID)
	assert.Equal(t, CorrelationTypeCount, rule.Type)
	assert.Equal(t, "Failed Login Threshold", rule.Name)
	assert.Equal(t, 5*time.Minute, rule.Window)
	assert.Equal(t, []string{"source_ip", "username"}, rule.GroupBy)
	assert.Equal(t, ThresholdOpGreaterEqual, rule.Threshold.Operator)
	assert.Equal(t, 5.0, rule.Threshold.Value)
	assert.NotNil(t, rule.Selection)
	assert.Len(t, rule.Actions, 1)
}

// TestValueCountCorrelationRule_Structure tests ValueCountCorrelationRule structure
func TestValueCountCorrelationRule_Structure(t *testing.T) {
	rule := ValueCountCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "valuecount-test-1",
			Type:     CorrelationTypeValueCount,
			Name:     "Multiple User Login",
			Severity: "medium",
			Enabled:  true,
		},
		Window:     10 * time.Minute,
		CountField: "username",
		GroupBy:    []string{"source_ip"},
		Threshold: Threshold{
			Operator: ThresholdOpGreaterEqual,
			Value:    3.0,
		},
		Selection: map[string]interface{}{
			"event_type": "successful_login",
		},
	}

	assert.Equal(t, "valuecount-test-1", rule.ID)
	assert.Equal(t, CorrelationTypeValueCount, rule.Type)
	assert.Equal(t, "username", rule.CountField)
	assert.Equal(t, 10*time.Minute, rule.Window)
}

// TestSequenceCorrelationRule_Structure tests SequenceCorrelationRule structure
func TestSequenceCorrelationRule_Structure(t *testing.T) {
	rule := SequenceCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "sequence-test-1",
			Type:     CorrelationTypeSequence,
			Name:     "Attack Sequence",
			Severity: "high",
			Enabled:  true,
		},
		Window:  1 * time.Hour,
		Ordered: true,
		Sequence: []SequenceStage{
			{
				Name:      "reconnaissance",
				Selection: map[string]interface{}{"event_type": "port_scan"},
				Required:  true,
			},
			{
				Name:      "exploitation",
				Selection: map[string]interface{}{"event_type": "exploit_attempt"},
				Required:  true,
			},
		},
		GroupBy: []string{"source_ip"},
		MaxSpan: 2 * time.Hour,
	}

	assert.Equal(t, "sequence-test-1", rule.ID)
	assert.Equal(t, CorrelationTypeSequence, rule.Type)
	assert.True(t, rule.Ordered)
	assert.Len(t, rule.Sequence, 2)
	assert.Equal(t, "reconnaissance", rule.Sequence[0].Name)
	assert.True(t, rule.Sequence[0].Required)
	assert.Equal(t, 2*time.Hour, rule.MaxSpan)
}

// TestRareCorrelationRule_Structure tests RareCorrelationRule structure
func TestRareCorrelationRule_Structure(t *testing.T) {
	rule := RareCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "rare-test-1",
			Type:     CorrelationTypeRare,
			Name:     "Rare Process Execution",
			Severity: "medium",
			Enabled:  true,
		},
		Window:     24 * time.Hour,
		CountField: "process_name",
		Threshold: Threshold{
			Operator: ThresholdOpLessEqual,
			Value:    1.0,
		},
		Selection: map[string]interface{}{
			"event_type": "process_execution",
		},
	}

	assert.Equal(t, "rare-test-1", rule.ID)
	assert.Equal(t, CorrelationTypeRare, rule.Type)
	assert.Equal(t, "process_name", rule.CountField)
	assert.Equal(t, 24*time.Hour, rule.Window)
}

// TestStatisticalCorrelationRule_Structure tests StatisticalCorrelationRule structure
func TestStatisticalCorrelationRule_Structure(t *testing.T) {
	rule := StatisticalCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "statistical-test-1",
			Type:     CorrelationTypeStatistical,
			Name:     "Anomaly Detection",
			Severity: "high",
			Enabled:  true,
		},
		Window:         1 * time.Hour,
		BaselineWindow: 7 * 24 * time.Hour, // 7 days
		MetricField:    "bytes_sent",
		GroupBy:        []string{"source_ip"},
		Threshold: Threshold{
			Operator: ThresholdOpStdDev,
			Value:    3.0, // 3 standard deviations
		},
		Selection: map[string]interface{}{
			"event_type": "network_traffic",
		},
	}

	assert.Equal(t, "statistical-test-1", rule.ID)
	assert.Equal(t, CorrelationTypeStatistical, rule.Type)
	assert.Equal(t, "bytes_sent", rule.MetricField)
	assert.Equal(t, 7*24*time.Hour, rule.BaselineWindow)
	assert.Equal(t, ThresholdOpStdDev, rule.Threshold.Operator)
}

// TestCrossEntityCorrelationRule_Structure tests CrossEntityCorrelationRule structure
func TestCrossEntityCorrelationRule_Structure(t *testing.T) {
	rule := CrossEntityCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "crossentity-test-1",
			Type:     CorrelationTypeCrossEntity,
			Name:     "Lateral Movement",
			Severity: "high",
			Enabled:  true,
		},
		Window:        15 * time.Minute,
		TrackField:    "username",
		CountDistinct: "dest_host",
		Threshold: Threshold{
			Operator: ThresholdOpGreaterEqual,
			Value:    3.0,
		},
		Selection: map[string]interface{}{
			"event_type": "authentication",
		},
	}

	assert.Equal(t, "crossentity-test-1", rule.ID)
	assert.Equal(t, CorrelationTypeCrossEntity, rule.Type)
	assert.Equal(t, "username", rule.TrackField)
	assert.Equal(t, "dest_host", rule.CountDistinct)
}

// TestChainCorrelationRule_Structure tests ChainCorrelationRule structure
func TestChainCorrelationRule_Structure(t *testing.T) {
	rule := ChainCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "chain-test-1",
			Type:     CorrelationTypeChain,
			Name:     "Multi-Stage Attack",
			Severity: "critical",
			Enabled:  true,
		},
		MaxDuration: 24 * time.Hour,
		MinStages:   3,
		Stages: []ChainStage{
			{
				Name:      "stage1",
				Selection: map[string]interface{}{"event_type": "recon"},
				Required:  true,
			},
			{
				Name:      "stage2",
				Selection: map[string]interface{}{"event_type": "exploit"},
				Required:  true,
			},
		},
		GroupBy: []string{"source_ip", "dest_ip"},
	}

	assert.Equal(t, "chain-test-1", rule.ID)
	assert.Equal(t, CorrelationTypeChain, rule.Type)
	assert.Equal(t, 24*time.Hour, rule.MaxDuration)
	assert.Equal(t, 3, rule.MinStages)
	assert.Len(t, rule.Stages, 2)
}

// TestThresholdOperators tests threshold operator constants
func TestThresholdOperators(t *testing.T) {
	assert.Equal(t, ThresholdOperator(">"), ThresholdOpGreater)
	assert.Equal(t, ThresholdOperator("<"), ThresholdOpLess)
	assert.Equal(t, ThresholdOperator(">="), ThresholdOpGreaterEqual)
	assert.Equal(t, ThresholdOperator("<="), ThresholdOpLessEqual)
	assert.Equal(t, ThresholdOperator("=="), ThresholdOpEqual)
	assert.Equal(t, ThresholdOperator("!="), ThresholdOpNotEqual)
	assert.Equal(t, ThresholdOperator("std_dev"), ThresholdOpStdDev)
}

// TestCorrelationTypes tests correlation type constants
func TestCorrelationTypes(t *testing.T) {
	assert.Equal(t, CorrelationType("count"), CorrelationTypeCount)
	assert.Equal(t, CorrelationType("value_count"), CorrelationTypeValueCount)
	assert.Equal(t, CorrelationType("sequence"), CorrelationTypeSequence)
	assert.Equal(t, CorrelationType("rare"), CorrelationTypeRare)
	assert.Equal(t, CorrelationType("statistical"), CorrelationTypeStatistical)
	assert.Equal(t, CorrelationType("cross_entity"), CorrelationTypeCrossEntity)
	assert.Equal(t, CorrelationType("chain"), CorrelationTypeChain)
}

// TestCorrelationRule_GetID_GetSeverity_GetActions tests AlertableRule interface methods
func TestCorrelationRule_GetID_GetSeverity_GetActions(t *testing.T) {
	actions := []Action{
		{ID: "action1", Type: "webhook"},
		{ID: "action2", Type: "email"},
	}

	// Test CountCorrelationRule
	countRule := CountCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "test-rule-count",
			Severity: "high",
		},
		Actions: actions,
	}
	assert.Equal(t, "test-rule-count", countRule.GetID())
	assert.Equal(t, "high", countRule.GetSeverity())
	assert.Equal(t, actions, countRule.GetActions())

	// Test ValueCountCorrelationRule
	valueCountRule := ValueCountCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "test-rule-valuecount",
			Severity: "medium",
		},
		Actions: actions,
	}
	assert.Equal(t, "test-rule-valuecount", valueCountRule.GetID())
	assert.Equal(t, "medium", valueCountRule.GetSeverity())
	assert.Equal(t, actions, valueCountRule.GetActions())

	// Test SequenceCorrelationRule
	sequenceRule := SequenceCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "test-rule-sequence",
			Severity: "high",
		},
		Actions: actions,
	}
	assert.Equal(t, "test-rule-sequence", sequenceRule.GetID())
	assert.Equal(t, "high", sequenceRule.GetSeverity())
	assert.Equal(t, actions, sequenceRule.GetActions())

	// Test RareCorrelationRule
	rareRule := RareCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "test-rule-rare",
			Severity: "medium",
		},
		Actions: actions,
	}
	assert.Equal(t, "test-rule-rare", rareRule.GetID())
	assert.Equal(t, "medium", rareRule.GetSeverity())
	assert.Equal(t, actions, rareRule.GetActions())

	// Test StatisticalCorrelationRule
	statisticalRule := StatisticalCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "test-rule-statistical",
			Severity: "high",
		},
		Actions: actions,
	}
	assert.Equal(t, "test-rule-statistical", statisticalRule.GetID())
	assert.Equal(t, "high", statisticalRule.GetSeverity())
	assert.Equal(t, actions, statisticalRule.GetActions())

	// Test CrossEntityCorrelationRule
	crossEntityRule := CrossEntityCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "test-rule-crossentity",
			Severity: "high",
		},
		Actions: actions,
	}
	assert.Equal(t, "test-rule-crossentity", crossEntityRule.GetID())
	assert.Equal(t, "high", crossEntityRule.GetSeverity())
	assert.Equal(t, actions, crossEntityRule.GetActions())

	// Test ChainCorrelationRule
	chainRule := ChainCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "test-rule-chain",
			Severity: "critical",
		},
		Actions: actions,
	}
	assert.Equal(t, "test-rule-chain", chainRule.GetID())
	assert.Equal(t, "critical", chainRule.GetSeverity())
	assert.Equal(t, actions, chainRule.GetActions())
}

// TestCorrelationRule_Serialization tests JSON serialization/deserialization
func TestCorrelationRule_Serialization(t *testing.T) {
	// Test CountCorrelationRule serialization
	countRule := CountCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "serialization-test",
			Type:     CorrelationTypeCount,
			Name:     "Test Rule",
			Severity: "high",
			Enabled:  true,
		},
		Window:  5 * time.Minute,
		GroupBy: []string{"source_ip"},
		Threshold: Threshold{
			Operator: ThresholdOpGreaterEqual,
			Value:    5.0,
		},
		Selection: map[string]interface{}{
			"event_type": "failed_login",
		},
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(countRule)
	require.NoError(t, err, "Should serialize CountCorrelationRule to JSON")
	assert.NotEmpty(t, jsonData)

	// Deserialize from JSON
	var deserializedRule CountCorrelationRule
	err = json.Unmarshal(jsonData, &deserializedRule)
	require.NoError(t, err, "Should deserialize CountCorrelationRule from JSON")
	assert.Equal(t, countRule.ID, deserializedRule.ID)
	assert.Equal(t, countRule.Type, deserializedRule.Type)
	assert.Equal(t, countRule.Name, deserializedRule.Name)
	assert.Equal(t, countRule.Window, deserializedRule.Window)
	assert.Equal(t, countRule.Threshold.Operator, deserializedRule.Threshold.Operator)
	assert.Equal(t, countRule.Threshold.Value, deserializedRule.Threshold.Value)

	// Test SequenceCorrelationRule serialization
	sequenceRule := SequenceCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "sequence-serialization-test",
			Type:     CorrelationTypeSequence,
			Name:     "Test Sequence",
			Severity: "high",
			Enabled:  true,
		},
		Window:  1 * time.Hour,
		Ordered: true,
		Sequence: []SequenceStage{
			{
				Name:      "stage1",
				Selection: map[string]interface{}{"event_type": "event_a"},
				Required:  true,
			},
		},
		GroupBy: []string{"source_ip"},
	}

	jsonData, err = json.Marshal(sequenceRule)
	require.NoError(t, err, "Should serialize SequenceCorrelationRule to JSON")

	var deserializedSequence SequenceCorrelationRule
	err = json.Unmarshal(jsonData, &deserializedSequence)
	require.NoError(t, err, "Should deserialize SequenceCorrelationRule from JSON")
	assert.Equal(t, sequenceRule.ID, deserializedSequence.ID)
	assert.Equal(t, sequenceRule.Ordered, deserializedSequence.Ordered)
	assert.Len(t, deserializedSequence.Sequence, 1)
	assert.Equal(t, sequenceRule.Sequence[0].Name, deserializedSequence.Sequence[0].Name)
}

// TestThreshold_Structure tests Threshold structure
func TestThreshold_Structure(t *testing.T) {
	threshold := Threshold{
		Operator: ThresholdOpGreaterEqual,
		Value:    10.5,
	}

	assert.Equal(t, ThresholdOpGreaterEqual, threshold.Operator)
	assert.Equal(t, 10.5, threshold.Value)
}

// TestSequenceStage_Structure tests SequenceStage structure
func TestSequenceStage_Structure(t *testing.T) {
	stage := SequenceStage{
		Name:      "login_attempt",
		Selection: map[string]interface{}{"event_type": "failed_login"},
		Required:  true,
	}

	assert.Equal(t, "login_attempt", stage.Name)
	assert.NotNil(t, stage.Selection)
	assert.True(t, stage.Required)
}

// TestChainStage_Structure tests ChainStage structure
func TestChainStage_Structure(t *testing.T) {
	stage := ChainStage{
		Name:      "reconnaissance",
		Selection: map[string]interface{}{"event_type": "port_scan"},
		Required:  true,
	}

	assert.Equal(t, "reconnaissance", stage.Name)
	assert.NotNil(t, stage.Selection)
	assert.True(t, stage.Required)
}

// TestEnhancedCorrelationRule_BaseStructure tests base EnhancedCorrelationRule structure
func TestEnhancedCorrelationRule_BaseStructure(t *testing.T) {
	now := time.Now()
	baseRule := EnhancedCorrelationRule{
		ID:          "base-rule-1",
		Type:        CorrelationTypeCount,
		Name:        "Base Rule",
		Description: "Test description",
		Severity:    "high",
		Enabled:     true,
		Tags:        []string{"test", "tag"},
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	assert.Equal(t, "base-rule-1", baseRule.ID)
	assert.Equal(t, CorrelationTypeCount, baseRule.Type)
	assert.Equal(t, "Base Rule", baseRule.Name)
	assert.Equal(t, "high", baseRule.Severity)
	assert.True(t, baseRule.Enabled)
	assert.Len(t, baseRule.Tags, 2)
	assert.Equal(t, now.Unix(), baseRule.CreatedAt.Unix())
	assert.Equal(t, now.Unix(), baseRule.UpdatedAt.Unix())
}
