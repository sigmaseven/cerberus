package detect

import (
	"testing"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

// TestSigmaEngineIntegration tests the integration of SIGMA engine with RuleEngine
// TASK #131.2: Integration test for SIGMA engine in main detection engine
func TestSigmaEngineIntegration(t *testing.T) {
	// Create a simple SIGMA rule
	sigmaYAML := `
title: Test SIGMA Rule
description: Test rule for SIGMA engine integration
detection:
  selection:
    EventID: 4624
    LogonType: 10
  condition: selection
`

	rule := core.Rule{
		ID:        "sigma-test-1",
		Name:      "Test SIGMA Rule",
		Type:      "sigma",
		Enabled:   true,
		SigmaYAML: sigmaYAML,
	}

	// Create logger
	logger := zap.NewNop().Sugar()

	// Create engine config with SIGMA enabled
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaFieldMappingConfig:    "", // Use empty to test default mappings
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        30 * time.Minute,
		SigmaEngineCleanupInterval: 5 * time.Minute,
		Logger:                     logger,
	}

	// Create engine with SIGMA support
	engine := NewRuleEngineWithConfig([]core.Rule{rule}, nil, 3600, config)
	defer engine.Stop()

	// Test event that should match
	matchingEvent := &core.Event{
		EventID: "test-event-1",
		Fields: map[string]interface{}{
			"EventID":   "4624",
			"LogonType": 10,
		},
	}

	// Evaluate using the integrated engine
	matches := engine.Evaluate(matchingEvent)

	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}

	if len(matches) > 0 && matches[0].GetID() != "sigma-test-1" {
		t.Errorf("Expected rule ID 'sigma-test-1', got '%s'", matches[0].GetID())
	}

	// Test event that should NOT match
	nonMatchingEvent := &core.Event{
		EventID: "test-event-2",
		Fields: map[string]interface{}{
			"EventID":   "4625",
			"LogonType": 3,
		},
	}

	matches = engine.Evaluate(nonMatchingEvent)

	if len(matches) != 0 {
		t.Errorf("Expected 0 matches for non-matching event, got %d", len(matches))
	}
}

// TestSigmaEngineDisabled tests that legacy rules are skipped when they don't have SIGMA YAML
// TASK #181: Legacy condition evaluation removed - rules without SIGMA YAML are skipped
func TestSigmaEngineDisabled(t *testing.T) {
	// Create a traditional rule without SIGMA YAML (will be skipped)
	rule := core.Rule{
		ID:      "legacy-1",
		Name:    "Legacy Rule",
		Type:    "traditional",
		Enabled: true,
		// No SigmaYAML - this rule will be skipped
	}

	// Create engine WITHOUT SIGMA support (nil config)
	engine := NewRuleEngine([]core.Rule{rule}, nil, 3600)
	defer engine.Stop()

	// Test event
	event := &core.Event{
		EventID:   "test-1",
		EventType: "login",
	}

	matches := engine.Evaluate(event)

	// TASK #181: Legacy rules without SIGMA YAML are now skipped (logs warning)
	if len(matches) != 0 {
		t.Errorf("Expected 0 matches (legacy rules without SIGMA YAML are skipped), got %d", len(matches))
	}
}

// TestSigmaEngineMixedRules tests evaluation with SIGMA rules only
// TASK #181: Legacy condition evaluation removed - only SIGMA rules are evaluated
func TestSigmaEngineMixedRules(t *testing.T) {
	// SIGMA rule
	sigmaYAML := `
title: SIGMA Rule
detection:
  selection:
    EventID: 4624
  condition: selection
`

	sigmaRule := core.Rule{
		ID:        "sigma-1",
		Name:      "SIGMA Rule",
		Type:      "sigma",
		Enabled:   true,
		SigmaYAML: sigmaYAML,
	}

	// Legacy rule (without SIGMA YAML - will be skipped)
	legacyRule := core.Rule{
		ID:      "legacy-1",
		Name:    "Legacy Rule",
		Type:    "traditional",
		Enabled: true,
		// No SigmaYAML - this rule will be skipped
	}

	// Create engine with SIGMA support
	logger := zap.NewNop().Sugar()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaFieldMappingConfig:    "",
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        30 * time.Minute,
		SigmaEngineCleanupInterval: 5 * time.Minute,
		Logger:                     logger,
	}

	engine := NewRuleEngineWithConfig([]core.Rule{sigmaRule, legacyRule}, nil, 3600, config)
	defer engine.Stop()

	// Event that matches SIGMA rule (legacy rule without SIGMA YAML is skipped)
	event := &core.Event{
		EventID:  "test-1",
		Severity: "high",
		Fields: map[string]interface{}{
			"EventID": "4624",
		},
	}

	matches := engine.Evaluate(event)

	// TASK #181: Only SIGMA rules are evaluated - legacy rules without sigma_yaml are skipped
	if len(matches) != 1 {
		t.Errorf("Expected 1 match (only SIGMA rule, legacy skipped), got %d", len(matches))
	}

	// Verify the match is from SIGMA rule
	if len(matches) > 0 && matches[0].GetID() != "sigma-1" {
		t.Errorf("Expected match from sigma-1, got %s", matches[0].GetID())
	}
}

// TestReloadSigmaEngine tests cache invalidation
// TASK #131.2: Test cache reload functionality
func TestReloadSigmaEngine(t *testing.T) {
	sigmaYAML := `
title: Test Rule
detection:
  selection:
    field1: value1
  condition: selection
`

	rule := core.Rule{
		ID:        "sigma-reload-1",
		Name:      "Reload Test",
		Type:      "sigma",
		Enabled:   true,
		SigmaYAML: sigmaYAML,
	}

	logger := zap.NewNop().Sugar()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaFieldMappingConfig:    "",
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        30 * time.Minute,
		SigmaEngineCleanupInterval: 5 * time.Minute,
		Logger:                     logger,
	}

	engine := NewRuleEngineWithConfig([]core.Rule{rule}, nil, 3600, config)
	defer engine.Stop()

	// First evaluation - should cache the rule
	event := &core.Event{
		EventID: "test-1",
		Fields: map[string]interface{}{
			"field1": "value1",
		},
	}

	matches := engine.Evaluate(event)
	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}

	// Get initial stats
	stats := engine.GetSigmaEngineStats()
	initialEvals := stats["evaluations"].(int64)

	// Reload cache (invalidate all)
	engine.ReloadSigmaEngine()

	// Evaluate again - should re-parse
	matches = engine.Evaluate(event)
	if len(matches) != 1 {
		t.Errorf("Expected 1 match after reload, got %d", len(matches))
	}

	// Check that evaluations increased
	stats = engine.GetSigmaEngineStats()
	newEvals := stats["evaluations"].(int64)

	if newEvals <= initialEvals {
		t.Errorf("Expected evaluations to increase after reload, got %d (was %d)", newEvals, initialEvals)
	}
}

// TestGetSigmaEngineStats tests metrics collection
// TASK #131.2: Test metrics/observability
func TestGetSigmaEngineStats(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaFieldMappingConfig:    "",
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        30 * time.Minute,
		SigmaEngineCleanupInterval: 5 * time.Minute,
		Logger:                     logger,
	}

	engine := NewRuleEngineWithConfig(nil, nil, 3600, config)
	defer engine.Stop()

	stats := engine.GetSigmaEngineStats()

	// Check that stats contain expected fields
	expectedFields := []string{
		"enabled",
		"evaluations",
		"cache_hits",
		"cache_misses",
		"matches",
		"errors",
		"parse_errors",
		"avg_eval_time_ns",
		"cache_hit_rate",
		"cache_size",
		"cache_evictions",
	}

	for _, field := range expectedFields {
		if _, exists := stats[field]; !exists {
			t.Errorf("Expected stats to contain field '%s'", field)
		}
	}

	// Verify enabled is true
	if enabled, ok := stats["enabled"].(bool); !ok || !enabled {
		t.Errorf("Expected 'enabled' to be true")
	}
}

// TestSigmaEngineStatsDisabled tests that stats show disabled when SIGMA engine is off
// TASK #131.2: Test disabled state
func TestSigmaEngineStatsDisabled(t *testing.T) {
	// Create engine without SIGMA support
	engine := NewRuleEngine(nil, nil, 3600)
	defer engine.Stop()

	stats := engine.GetSigmaEngineStats()

	if enabled, ok := stats["enabled"].(bool); !ok || enabled {
		t.Errorf("Expected 'enabled' to be false when SIGMA engine is disabled")
	}

	// Should only have one field when disabled
	if len(stats) != 1 {
		t.Errorf("Expected only 'enabled' field when SIGMA engine is disabled, got %d fields", len(stats))
	}
}

// TestSigmaEngineInvalidRule tests error handling for invalid SIGMA rules
// TASK #131.2: Test error handling
func TestSigmaEngineInvalidRule(t *testing.T) {
	// Invalid SIGMA YAML (missing detection section)
	invalidYAML := `
title: Invalid Rule
description: This rule is missing detection section
`

	rule := core.Rule{
		ID:        "invalid-1",
		Name:      "Invalid Rule",
		Type:      "sigma",
		Enabled:   true,
		SigmaYAML: invalidYAML,
	}

	logger := zap.NewNop().Sugar()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaFieldMappingConfig:    "",
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        30 * time.Minute,
		SigmaEngineCleanupInterval: 5 * time.Minute,
		Logger:                     logger,
	}

	engine := NewRuleEngineWithConfig([]core.Rule{rule}, nil, 3600, config)
	defer engine.Stop()

	event := &core.Event{
		EventID: "test-1",
		Fields:  map[string]interface{}{},
	}

	// Should not match (graceful degradation)
	matches := engine.Evaluate(event)

	if len(matches) != 0 {
		t.Errorf("Expected 0 matches for invalid SIGMA rule, got %d", len(matches))
	}

	// Check that parse error was recorded
	stats := engine.GetSigmaEngineStats()
	parseErrors := stats["parse_errors"].(int64)

	if parseErrors == 0 {
		t.Errorf("Expected parse_errors > 0 for invalid SIGMA rule")
	}
}

// TestReloadSigmaEngineRule tests single-rule cache invalidation
// TASK #131.2: Test targeted cache invalidation
func TestReloadSigmaEngineRule(t *testing.T) {
	rule1YAML := `
title: Rule 1
detection:
  selection:
    field: value1
  condition: selection
`

	rule2YAML := `
title: Rule 2
detection:
  selection:
    field: value2
  condition: selection
`

	rule1 := core.Rule{
		ID:        "sigma-1",
		Name:      "Rule 1",
		Type:      "sigma",
		Enabled:   true,
		SigmaYAML: rule1YAML,
	}

	rule2 := core.Rule{
		ID:        "sigma-2",
		Name:      "Rule 2",
		Type:      "sigma",
		Enabled:   true,
		SigmaYAML: rule2YAML,
	}

	logger := zap.NewNop().Sugar()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaFieldMappingConfig:    "",
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        30 * time.Minute,
		SigmaEngineCleanupInterval: 5 * time.Minute,
		Logger:                     logger,
	}

	engine := NewRuleEngineWithConfig([]core.Rule{rule1, rule2}, nil, 3600, config)
	defer engine.Stop()

	// Evaluate both rules to cache them
	event1 := &core.Event{
		EventID: "test-1",
		Fields:  map[string]interface{}{"field": "value1"},
	}
	event2 := &core.Event{
		EventID: "test-2",
		Fields:  map[string]interface{}{"field": "value2"},
	}

	engine.Evaluate(event1)
	engine.Evaluate(event2)

	// Reload only rule1
	engine.ReloadSigmaEngineRule("sigma-1")

	// Both rules should still work
	matches := engine.Evaluate(event1)
	if len(matches) != 1 {
		t.Errorf("Expected 1 match for rule1 after targeted reload, got %d", len(matches))
	}

	matches = engine.Evaluate(event2)
	if len(matches) != 1 {
		t.Errorf("Expected 1 match for rule2 after targeted reload, got %d", len(matches))
	}
}
