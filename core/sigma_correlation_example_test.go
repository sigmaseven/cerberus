package core

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// ExampleSigmaCorrelation_eventCount demonstrates an event_count correlation rule.
// This detects when events exceed a threshold within a time window.
func ExampleSigmaCorrelation_eventCount() {
	yamlStr := `
type: event_count
group_by:
  - source_ip
  - username
timespan: 5m
condition:
  operator: ">="
  value: 5
`

	var sc SigmaCorrelation
	if err := yaml.Unmarshal([]byte(yamlStr), &sc); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if err := sc.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Type: %s\n", sc.Type)
	fmt.Printf("GroupBy: %v\n", sc.GroupBy)
	fmt.Printf("Operator: %s\n", sc.Condition.Operator)
	// Output:
	// Type: event_count
	// GroupBy: [source_ip username]
	// Operator: >=
}

// ExampleSigmaCorrelation_valueCount demonstrates a value_count correlation rule.
// This counts distinct values of a field within a time window.
func ExampleSigmaCorrelation_valueCount() {
	yamlStr := `
type: value_count
distinct_field: username
group_by:
  - source_ip
timespan: 10m
condition:
  operator: ">="
  value: 10
`

	var sc SigmaCorrelation
	if err := yaml.Unmarshal([]byte(yamlStr), &sc); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if err := sc.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Type: %s\n", sc.Type)
	fmt.Printf("DistinctField: %s\n", sc.DistinctField)
	// Output:
	// Type: value_count
	// DistinctField: username
}

// ExampleSigmaCorrelation_sequence demonstrates a sequence correlation rule.
// This detects ordered or unordered sequences of events.
func ExampleSigmaCorrelation_sequence() {
	yamlStr := `
type: sequence
timespan: 1h
ordered: true
events:
  - login_attempt
  - privilege_escalation
  - lateral_movement
group_by:
  - username
`

	var sc SigmaCorrelation
	if err := yaml.Unmarshal([]byte(yamlStr), &sc); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if err := sc.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Type: %s\n", sc.Type)
	fmt.Printf("Ordered: %t\n", sc.Ordered)
	fmt.Printf("Events: %v\n", sc.Events)
	// Output:
	// Type: sequence
	// Ordered: true
	// Events: [login_attempt privilege_escalation lateral_movement]
}

// ExampleSigmaCorrelation_chain demonstrates a chain correlation rule.
// This detects multi-stage attack chains across time.
func ExampleSigmaCorrelation_chain() {
	yamlStr := `
type: chain
max_duration: 24h
min_stages: 2
group_by:
  - source_ip
stages:
  - name: reconnaissance
    detection_ref: sigma_rule_recon_001
    timeout: 1h
  - name: exploitation
    detection_ref: sigma_rule_exploit_001
    timeout: 30m
`

	var sc SigmaCorrelation
	if err := yaml.Unmarshal([]byte(yamlStr), &sc); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if err := sc.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Type: %s\n", sc.Type)
	fmt.Printf("MinStages: %d\n", sc.MinStages)
	fmt.Printf("Stages: %d\n", len(sc.Stages))
	// Output:
	// Type: chain
	// MinStages: 2
	// Stages: 2
}

// ExampleSigmaCorrelation_statistical demonstrates a statistical correlation rule.
// This detects statistical anomalies using standard deviation.
func ExampleSigmaCorrelation_statistical() {
	yamlStr := `
type: statistical
baseline_window: 30d
timespan: 1h
std_dev_threshold: 3.0
group_by:
  - source_ip
`

	var sc SigmaCorrelation
	if err := yaml.Unmarshal([]byte(yamlStr), &sc); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if err := sc.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Type: %s\n", sc.Type)
	fmt.Printf("StdDevThreshold: %.1f\n", sc.StdDevThreshold)
	// Output:
	// Type: statistical
	// StdDevThreshold: 3.0
}

// ExampleSigmaCorrelation_ToEnhancedCorrelation demonstrates converting
// a SIGMA correlation to an enhanced correlation rule.
func ExampleSigmaCorrelation_ToEnhancedCorrelation() {
	sc := &SigmaCorrelation{
		Type:     "event_count",
		Timespan: "5m",
		GroupBy:  []string{"source_ip"},
		Condition: &CorrelationCondition{
			Operator: ">=",
			Value:    5,
		},
	}

	base := EnhancedCorrelationRule{
		ID:       "brute_force_001",
		Type:     CorrelationTypeCount,
		Name:     "Brute Force Detection",
		Severity: "High",
		Enabled:  true,
	}

	selection := map[string]interface{}{
		"event_type": "login_failed",
		"service":    "ssh",
	}

	actions := []Action{
		{
			ID:   "action_webhook_001",
			Type: "webhook",
			Config: map[string]interface{}{
				"url": "https://soc.example.com/alerts",
			},
		},
	}

	rule, err := sc.ToEnhancedCorrelation(base, selection, "", actions)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	countRule, ok := rule.(*CountCorrelationRule)
	if !ok {
		fmt.Println("Failed to convert to CountCorrelationRule")
		return
	}

	fmt.Printf("Rule ID: %s\n", countRule.ID)
	fmt.Printf("Window: %v\n", countRule.Window)
	fmt.Printf("GroupBy: %v\n", countRule.GroupBy)
	// Output:
	// Rule ID: brute_force_001
	// Window: 5m0s
	// GroupBy: [source_ip]
}

// ExampleRule_ParsedCorrelation demonstrates parsing a correlation from a Rule.
func ExampleRule_ParsedCorrelation() {
	rule := &Rule{
		ID:   "test_rule_001",
		Type: "sigma",
		Name: "Test Correlation Rule",
		Correlation: map[string]interface{}{
			"type":     "event_count",
			"timespan": "5m",
			"group_by": []string{"source_ip"},
			"condition": map[string]interface{}{
				"operator": ">=",
				"value":    5,
			},
		},
	}

	corr, err := rule.ParsedCorrelation()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	window, _ := corr.ParseDuration(corr.Timespan)
	fmt.Printf("Type: %s\n", corr.Type)
	fmt.Printf("Window: %v\n", window)
	// Output:
	// Type: event_count
	// Window: 5m0s
}

// ExampleParseDuration demonstrates parsing duration strings with days support.
func ExampleParseDuration() {
	durations := []string{"5m", "1h", "24h", "7d", "30d"}

	for _, d := range durations {
		duration, err := parseDuration(d)
		if err != nil {
			fmt.Printf("%s: Error - %v\n", d, err)
			continue
		}
		fmt.Printf("%s = %v\n", d, duration)
	}
	// Output:
	// 5m = 5m0s
	// 1h = 1h0m0s
	// 24h = 24h0m0s
	// 7d = 168h0m0s
	// 30d = 720h0m0s
}

// ExampleSigmaCorrelation_ToYAML demonstrates serializing a correlation to YAML.
func ExampleSigmaCorrelation_ToYAML() {
	sc := &SigmaCorrelation{
		Type:     "value_count",
		Timespan: "10m",
		GroupBy:  []string{"source_ip"},
		Condition: &CorrelationCondition{
			Operator: ">=",
			Value:    10,
		},
		DistinctField: "username",
	}

	yamlBytes, err := sc.ToYAML()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("%s", yamlBytes)
	// Output:
	// type: value_count
	// group_by:
	//     - source_ip
	// timespan: 10m
	// condition:
	//     operator: '>='
	//     value: 10
	// distinct_field: username
}

// ExampleCorrelationCondition_ToThreshold demonstrates converting
// a condition to a threshold.
func ExampleCorrelationCondition_ToThreshold() {
	cond := &CorrelationCondition{
		Operator: ">=",
		Value:    5,
	}

	threshold, err := cond.ToThreshold()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Operator: %s\n", threshold.Operator)
	fmt.Printf("Value: %.0f\n", threshold.Value)
	// Output:
	// Operator: >=
	// Value: 5
}

// ExampleSigmaCorrelation_ParseDuration demonstrates safe duration parsing.
func ExampleSigmaCorrelation_ParseDuration() {
	sc := &SigmaCorrelation{}

	testCases := []string{"5m", "1h", "7d", "invalid"}

	for _, tc := range testCases {
		duration, err := sc.ParseDuration(tc)
		if err != nil {
			fmt.Printf("%s: Error\n", tc)
			continue
		}
		fmt.Printf("%s: %v\n", tc, duration)
	}
	// Output:
	// 5m: 5m0s
	// 1h: 1h0m0s
	// 7d: 168h0m0s
	// invalid: Error
}

// ExampleSigmaCorrelation_crossEntity demonstrates a cross_entity correlation.
// This tracks activity across multiple entities.
func ExampleSigmaCorrelation_crossEntity() {
	yamlStr := `
type: cross_entity
track_field: username
count_distinct: dest_host
timespan: 15m
condition:
  operator: ">="
  value: 5
`

	var sc SigmaCorrelation
	if err := yaml.Unmarshal([]byte(yamlStr), &sc); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if err := sc.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Type: %s\n", sc.Type)
	fmt.Printf("TrackField: %s\n", sc.TrackField)
	fmt.Printf("CountDistinct: %s\n", sc.CountDistinct)
	// Output:
	// Type: cross_entity
	// TrackField: username
	// CountDistinct: dest_host
}

// ExampleSigmaCorrelation_rare demonstrates a rare event correlation.
// This detects events that occur infrequently compared to a baseline.
func ExampleSigmaCorrelation_rare() {
	yamlStr := `
type: rare
baseline_window: 7d
distinct_field: process_name
condition:
  operator: "<"
  value: 3
`

	var sc SigmaCorrelation
	if err := yaml.Unmarshal([]byte(yamlStr), &sc); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if err := sc.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	baseline, _ := sc.ParseDuration(sc.BaselineWindow)
	fmt.Printf("Type: %s\n", sc.Type)
	fmt.Printf("Baseline: %v\n", baseline)
	// Output:
	// Type: rare
	// Baseline: 168h0m0s
}

// ExampleSigmaCorrelation_completeWorkflow demonstrates a complete workflow
// from YAML to enhanced correlation rule.
func ExampleSigmaCorrelation_completeWorkflow() {
	// 1. Define correlation in YAML
	yamlStr := `
type: event_count
group_by:
  - source_ip
timespan: 5m
condition:
  operator: ">="
  value: 5
`

	// 2. Parse YAML
	var sc SigmaCorrelation
	if err := yaml.Unmarshal([]byte(yamlStr), &sc); err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	// 3. Validate
	if err := sc.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	// 4. Create base metadata
	base := EnhancedCorrelationRule{
		ID:          "rule_001",
		Type:        CorrelationTypeCount,
		Name:        "Failed Login Detection",
		Description: "Detects multiple failed login attempts",
		Severity:    "High",
		Enabled:     true,
		CreatedAt:   time.Now(),
	}

	// 5. Define selection criteria
	selection := map[string]interface{}{
		"event_type": "login_failed",
	}

	// 6. Define actions
	actions := []Action{
		{
			ID:   "action_001",
			Type: "alert",
		},
	}

	// 7. Convert to enhanced correlation
	rule, err := sc.ToEnhancedCorrelation(base, selection, "", actions)
	if err != nil {
		fmt.Printf("Conversion error: %v\n", err)
		return
	}

	// 8. Use the rule
	countRule := rule.(*CountCorrelationRule)
	fmt.Printf("Created rule: %s\n", countRule.Name)
	fmt.Printf("Window: %v\n", countRule.Window)
	fmt.Printf("Threshold: %s %.0f\n", countRule.Threshold.Operator, countRule.Threshold.Value)
	// Output:
	// Created rule: Failed Login Detection
	// Window: 5m0s
	// Threshold: >= 5
}
