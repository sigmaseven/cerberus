package detect

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"cerberus/core"
)

// EnhancedCorrelationEvaluator provides methods to evaluate all correlation rule types
type EnhancedCorrelationEvaluator struct {
	stateStore CorrelationStateStore
}

// NewEnhancedCorrelationEvaluator creates a new enhanced correlation evaluator
func NewEnhancedCorrelationEvaluator(stateStore CorrelationStateStore) *EnhancedCorrelationEvaluator {
	return &EnhancedCorrelationEvaluator{
		stateStore: stateStore,
	}
}

// MatchesSelection checks if an event matches the selection criteria
func (e *EnhancedCorrelationEvaluator) MatchesSelection(event *core.Event, selection map[string]interface{}) bool {
	if len(selection) == 0 {
		return true
	}

	for fieldPath, expectedValue := range selection {
		eventValue := getEventFieldByPath(event, fieldPath)

		if !matchesValue(eventValue, expectedValue) {
			return false
		}
	}

	return true
}

// EvaluateThreshold evaluates a value against a threshold
func (e *EnhancedCorrelationEvaluator) EvaluateThreshold(value float64, threshold core.Threshold) bool {
	switch threshold.Operator {
	case core.ThresholdOpGreater:
		return value > threshold.Value
	case core.ThresholdOpLess:
		return value < threshold.Value
	case core.ThresholdOpGreaterEqual:
		return value >= threshold.Value
	case core.ThresholdOpLessEqual:
		return value <= threshold.Value
	case core.ThresholdOpEqual:
		return value == threshold.Value
	case core.ThresholdOpNotEqual:
		return value != threshold.Value
	default:
		return false
	}
}

// EvaluateStatisticalThreshold evaluates a value against statistical threshold
func (e *EnhancedCorrelationEvaluator) EvaluateStatisticalThreshold(value float64, stats Statistics, threshold core.Threshold) bool {
	if threshold.Operator == core.ThresholdOpStdDev {
		// Check if value is beyond N standard deviations from mean
		deviation := math.Abs(value - stats.Mean)
		threshold_deviation := threshold.Value * stats.StdDev
		return deviation > threshold_deviation
	}
	return e.EvaluateThreshold(value, threshold)
}

// GenerateCorrelationAlert creates an alert from correlation detection
func (e *EnhancedCorrelationEvaluator) GenerateCorrelationAlert(
	rule core.AlertableRule,
	triggerEvent *core.Event,
	correlatedEvents []*core.Event,
	context map[string]interface{},
) *core.Alert {
	alert := &core.Alert{
		AlertID:         generateAlertID(),
		RuleID:          rule.GetID(),
		RuleName:        rule.GetName(),
		RuleDescription: rule.GetDescription(),
		Severity:        rule.GetSeverity(),
		Timestamp:       time.Now(),
		Status:          core.AlertStatusPending,
		Event:           triggerEvent,
		RuleType:        core.RuleTypeCorrelation,
		Category:        "correlation",
		ConfidenceScore: 85, // Correlation rules have higher confidence
		RiskScore:       core.CalculateRiskScore(rule.GetSeverity(), 0),
		OccurrenceCount: 1,
	}

	// Derive source from trigger event if available
	if triggerEvent != nil {
		if triggerEvent.Source != "" {
			alert.Source = triggerEvent.Source
		} else if triggerEvent.ListenerName != "" {
			alert.Source = triggerEvent.ListenerName
		}
	}

	// Store correlation context in event IDs for now
	if len(correlatedEvents) > 0 {
		eventIDs := make([]string, len(correlatedEvents))
		for i, evt := range correlatedEvents {
			eventIDs[i] = evt.EventID
		}
		alert.EventIDs = eventIDs
	}

	return alert
}

// Helper Functions

// getEventFieldByPath extracts a field value from an event using dot notation path
func getEventFieldByPath(event *core.Event, fieldPath string) interface{} {
	if event == nil {
		return nil
	}

	// Handle direct event struct fields
	switch fieldPath {
	case "timestamp":
		return event.Timestamp
	case "type", "event_type":
		return event.EventType
	case "source":
		return event.Source
	case "severity":
		return event.Severity
	case "source_ip":
		return event.SourceIP
	}

	// Handle nested fields in event.Fields using dot notation
	return getNestedField(event.Fields, fieldPath)
}

// getNestedField retrieves nested field from map using dot notation
func getNestedField(data map[string]interface{}, path string) interface{} {
	if data == nil {
		return nil
	}

	parts := strings.Split(path, ".")
	current := interface{}(data)

	for _, part := range parts {
		if currentMap, ok := current.(map[string]interface{}); ok {
			current = currentMap[part]
		} else {
			return nil
		}
	}

	return current
}

// matchesValue checks if an actual value matches the expected value
func matchesValue(actual interface{}, expected interface{}) bool {
	if actual == nil {
		return expected == nil
	}

	// Handle slice/array expected values (OR logic)
	if expectedSlice, ok := expected.([]interface{}); ok {
		for _, expectedItem := range expectedSlice {
			if matchesValue(actual, expectedItem) {
				return true
			}
		}
		return false
	}

	// Handle string slice expected values
	if expectedSlice, ok := expected.([]string); ok {
		for _, expectedItem := range expectedSlice {
			if matchesValue(actual, expectedItem) {
				return true
			}
		}
		return false
	}

	// Handle wildcard patterns for strings
	if expectedStr, ok := expected.(string); ok {
		if actualStr, ok := actual.(string); ok {
			return matchesPattern(actualStr, expectedStr)
		}
	}

	// Handle numeric comparisons with type conversion
	actualFloat, actualIsNum := toFloat64(actual)
	expectedFloat, expectedIsNum := toFloat64(expected)
	if actualIsNum && expectedIsNum {
		return actualFloat == expectedFloat
	}

	// Direct equality comparison
	return reflect.DeepEqual(actual, expected)
}

// matchesPattern checks if a string matches a pattern (supports wildcards)
func matchesPattern(str, pattern string) bool {
	// Exact match
	if str == pattern {
		return true
	}

	// Wildcard support
	if strings.Contains(pattern, "*") {
		// Simple wildcard matching
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			return strings.Contains(str, pattern[1:len(pattern)-1])
		}
		if strings.HasPrefix(pattern, "*") {
			return strings.HasSuffix(str, pattern[1:])
		}
		if strings.HasSuffix(pattern, "*") {
			return strings.HasPrefix(str, pattern[:len(pattern)-1])
		}
	}

	return false
}

// toFloat64 converts various numeric types to float64
func toFloat64(val interface{}) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
	}
}

// generateAlertID generates a unique alert ID
func generateAlertID() string {
	// Use UUID or timestamp-based ID generation
	return fmt.Sprintf("alert_%d", time.Now().UnixNano())
}

// ExtractNumericValue extracts a numeric value from an event field
func (e *EnhancedCorrelationEvaluator) ExtractNumericValue(event *core.Event, fieldPath string) (float64, error) {
	value := getEventFieldByPath(event, fieldPath)

	if floatVal, ok := toFloat64(value); ok {
		return floatVal, nil
	}

	return 0, fmt.Errorf("field %s is not numeric: %v", fieldPath, value)
}

// GetDistinctValues extracts distinct values for a field from a list of events
func (e *EnhancedCorrelationEvaluator) GetDistinctValues(events []*core.Event, fieldPath string) []interface{} {
	seen := make(map[string]bool)
	distinct := make([]interface{}, 0)

	for _, event := range events {
		value := getEventFieldByPath(event, fieldPath)
		valueStr := fmt.Sprintf("%v", value)

		if !seen[valueStr] {
			seen[valueStr] = true
			distinct = append(distinct, value)
		}
	}

	return distinct
}

// ComputeStatistics calculates statistics for numeric values
func (e *EnhancedCorrelationEvaluator) ComputeStatistics(values []float64) Statistics {
	if len(values) == 0 {
		return Statistics{}
	}

	stats := Statistics{
		Count: len(values),
		Min:   values[0],
		Max:   values[0],
	}

	// Calculate sum, min, max
	sum := 0.0
	for _, v := range values {
		sum += v
		if v < stats.Min {
			stats.Min = v
		}
		if v > stats.Max {
			stats.Max = v
		}
	}

	stats.Sum = sum
	stats.Mean = sum / float64(len(values))

	// Calculate standard deviation
	variance := 0.0
	for _, v := range values {
		diff := v - stats.Mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	stats.StdDev = math.Sqrt(variance)

	return stats
}
