package detect

import (
	"context"
	"strings"
	"testing"

	"cerberus/core"

	"go.uber.org/zap"
)

// TestExtractDetectionSection tests the extractDetectionSection helper function
func TestExtractDetectionSection(t *testing.T) {
	tests := []struct {
		name      string
		parsed    map[string]interface{}
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid detection section",
			parsed: map[string]interface{}{
				"detection": map[string]interface{}{
					"condition": "selection",
					"selection": map[string]interface{}{
						"EventID": 4624,
					},
				},
			},
			wantErr: false,
		},
		{
			name:      "missing detection section",
			parsed:    map[string]interface{}{},
			wantErr:   true,
			errSubstr: "missing required 'detection' section",
		},
		{
			name: "detection section not a map",
			parsed: map[string]interface{}{
				"detection": "not a map",
			},
			wantErr:   true,
			errSubstr: "detection' section is not a map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detection, err := extractDetectionSection(tt.parsed)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Expected error containing '%s', got '%v'", tt.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if detection == nil {
					t.Error("Expected non-nil detection map")
				}
			}
		})
	}
}

// TestExtractCondition tests the extractCondition helper function
func TestExtractCondition(t *testing.T) {
	tests := []struct {
		name      string
		detection map[string]interface{}
		want      string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid condition",
			detection: map[string]interface{}{
				"condition": "selection and not filter",
			},
			want:    "selection and not filter",
			wantErr: false,
		},
		{
			name: "condition with whitespace",
			detection: map[string]interface{}{
				"condition": "  selection  ",
			},
			want:    "selection",
			wantErr: false,
		},
		{
			name:      "missing condition",
			detection: map[string]interface{}{},
			wantErr:   true,
			errSubstr: "missing 'condition'",
		},
		{
			name: "condition not a string",
			detection: map[string]interface{}{
				"condition": 123,
			},
			wantErr:   true,
			errSubstr: "condition' must be a string",
		},
		{
			name: "empty condition",
			detection: map[string]interface{}{
				"condition": "   ",
			},
			wantErr:   true,
			errSubstr: "condition' cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition, err := extractCondition(tt.detection)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Expected error containing '%s', got '%v'", tt.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if condition != tt.want {
					t.Errorf("Expected condition '%s', got '%s'", tt.want, condition)
				}
			}
		})
	}
}

// TestBuildDetectionBlocks tests the buildDetectionBlocks helper function
func TestBuildDetectionBlocks(t *testing.T) {
	logger := zap.NewNop().Sugar()

	tests := []struct {
		name           string
		detection      map[string]interface{}
		wantBlockCount int
		wantErr        bool
		errSubstr      string
	}{
		{
			name: "valid detection blocks",
			detection: map[string]interface{}{
				"condition": "selection",
				"selection": map[string]interface{}{
					"EventID": 4624,
				},
			},
			wantBlockCount: 1,
			wantErr:        false,
		},
		{
			name: "multiple detection blocks",
			detection: map[string]interface{}{
				"condition": "selection and not filter",
				"selection": map[string]interface{}{
					"EventID": 4624,
				},
				"filter": map[string]interface{}{
					"User": "SYSTEM",
				},
			},
			wantBlockCount: 2,
			wantErr:        false,
		},
		{
			name: "list-type detection block",
			detection: map[string]interface{}{
				"condition": "selection",
				"selection": []interface{}{
					map[string]interface{}{"EventID": 4624},
					map[string]interface{}{"EventID": 4625},
				},
			},
			wantBlockCount: 1,
			wantErr:        false,
		},
		{
			name: "only condition, no blocks",
			detection: map[string]interface{}{
				"condition": "all",
			},
			wantErr:   true,
			errSubstr: "no detection blocks",
		},
		{
			name: "block name too long",
			detection: map[string]interface{}{
				"condition":                                                                                                       "selection",
				"this_is_a_very_long_block_name_that_exceeds_the_maximum_allowed_length_of_100_characters_and_should_be_rejected": map[string]interface{}{
					"EventID": 4624,
				},
			},
			wantErr:   true,
			errSubstr: "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks, names, err := buildDetectionBlocks(tt.detection, logger)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Expected error containing '%s', got '%v'", tt.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(blocks) != tt.wantBlockCount {
					t.Errorf("Expected %d blocks, got %d", tt.wantBlockCount, len(blocks))
				}
				if len(names) != tt.wantBlockCount {
					t.Errorf("Expected %d block names, got %d", tt.wantBlockCount, len(names))
				}
			}
		})
	}
}

// TestExtractLogsource tests the extractLogsource helper function
func TestExtractLogsource(t *testing.T) {
	tests := []struct {
		name       string
		parsed     map[string]interface{}
		wantFields int
	}{
		{
			name: "valid logsource",
			parsed: map[string]interface{}{
				"logsource": map[string]interface{}{
					"product": "windows",
					"service": "security",
				},
			},
			wantFields: 2,
		},
		{
			name:       "missing logsource",
			parsed:     map[string]interface{}{},
			wantFields: 0,
		},
		{
			name: "logsource not a map",
			parsed: map[string]interface{}{
				"logsource": "not a map",
			},
			wantFields: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logsource := extractLogsource(tt.parsed)

			if logsource == nil {
				t.Error("Expected non-nil logsource map")
			}
			if len(logsource) != tt.wantFields {
				t.Errorf("Expected %d fields, got %d", tt.wantFields, len(logsource))
			}
		})
	}
}

// TestParseCorrelationBlockStatic tests the parseCorrelationBlockStatic helper function
func TestParseCorrelationBlockStatic(t *testing.T) {
	tests := []struct {
		name      string
		parsed    map[string]interface{}
		wantNil   bool
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid correlation block",
			parsed: map[string]interface{}{
				"correlation": map[string]interface{}{
					"type":      "event_count",
					"group-by":  []interface{}{"SourceIP"},
					"timespan":  "5m",
					"condition": map[string]interface{}{"operator": ">=", "value": float64(10)},
				},
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name:    "no correlation block",
			parsed:  map[string]interface{}{},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "correlation block too large",
			parsed: map[string]interface{}{
				"correlation": map[string]interface{}{
					"type": "event_count",
					// Create a large payload that exceeds 1MB
					"large_field": strings.Repeat("x", 1024*1024+1),
				},
			},
			wantErr:   true,
			errSubstr: "exceeds maximum allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			correlation, err := parseCorrelationBlockStatic(tt.parsed)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Expected error containing '%s', got '%v'", tt.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.wantNil && correlation != nil {
					t.Error("Expected nil correlation, got non-nil")
				}
				if !tt.wantNil && correlation == nil {
					t.Error("Expected non-nil correlation, got nil")
				}
			}
		})
	}
}

// TestParseSigmaYAML_WithHelpers tests the refactored ParseSigmaYAML function
func TestParseSigmaYAML_WithHelpers(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantTitle string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid SIGMA YAML",
			yaml: `
title: Test Rule
detection:
  selection:
    EventID: 4624
  condition: selection
`,
			wantTitle: "Test Rule",
			wantErr:   false,
		},
		{
			name: "YAML with correlation",
			yaml: `
title: Test Correlation Rule
detection:
  selection:
    EventID: 4625
  condition: selection
correlation:
  type: event_count
  group-by:
    - SourceIP
  timespan: 5m
  condition:
    operator: ">="
    value: 10
`,
			wantTitle: "Test Correlation Rule",
			wantErr:   false,
		},
		{
			name:      "empty YAML",
			yaml:      "",
			wantErr:   true,
			errSubstr: "SIGMA YAML is empty",
		},
		{
			name: "missing detection",
			yaml: `
title: Test Rule
`,
			wantErr:   true,
			errSubstr: "missing required 'detection' section",
		},
		{
			name: "missing condition",
			yaml: `
title: Test Rule
detection:
  selection:
    EventID: 4624
`,
			wantErr:   true,
			errSubstr: "missing 'condition'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			title, detection, correlation, err := ParseSigmaYAML(tt.yaml)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Expected error containing '%s', got '%v'", tt.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if title != tt.wantTitle {
					t.Errorf("Expected title '%s', got '%s'", tt.wantTitle, title)
				}
				if detection == nil {
					t.Error("Expected non-nil detection")
				}
				// correlation can be nil for rules without correlation blocks
				if strings.Contains(tt.yaml, "correlation:") && correlation == nil {
					t.Error("Expected non-nil correlation for YAML with correlation block")
				}
			}
		})
	}
}

// TestInvalidateCorrelationRules_WithEncapsulation tests the refactored InvalidateCorrelationRules
func TestInvalidateCorrelationRules_WithEncapsulation(t *testing.T) {
	logger := zap.NewNop().Sugar()
	engine := NewSigmaEngine(context.Background(), nil, logger)
	engine.Start()
	defer engine.Stop()

	// Create test rules with and without correlation
	rule1 := &core.Rule{
		ID:   "rule-1",
		Type: "sigma",
		SigmaYAML: `
title: Rule 1
detection:
  selection:
    EventID: 4624
  condition: selection
`,
	}

	rule2 := &core.Rule{
		ID:   "rule-2",
		Type: "sigma",
		SigmaYAML: `
title: Rule 2
detection:
  selection:
    EventID: 4625
  condition: selection
correlation:
  type: event_count
  group-by:
    - SourceIP
  timespan: 5m
  condition:
    operator: ">="
    value: 10
`,
	}

	rule3 := &core.Rule{
		ID:   "rule-3",
		Type: "sigma",
		SigmaYAML: `
title: Rule 3
detection:
  selection:
    EventID: 4626
  condition: selection
`,
	}

	// Populate cache by evaluating rules
	event := &core.Event{
		EventID: "test-event",
		Fields:  map[string]interface{}{"EventID": 4624},
	}

	engine.Evaluate(rule1, event)
	engine.Evaluate(rule2, event)
	engine.Evaluate(rule3, event)

	// Verify cache has all rules
	stats := engine.GetCacheStats()
	if stats.Size != 3 {
		t.Errorf("Expected cache size 3, got %d", stats.Size)
	}

	// Invalidate correlation rules (should only invalidate rule-2)
	count := engine.InvalidateCorrelationRules()

	if count != 1 {
		t.Errorf("Expected to invalidate 1 correlation rule, got %d", count)
	}

	// Verify cache now has 2 rules (rule-1 and rule-3)
	stats = engine.GetCacheStats()
	if stats.Size != 2 {
		t.Errorf("Expected cache size 2 after invalidation, got %d", stats.Size)
	}

	// Verify rule-2 is no longer cached
	if engine.cache.Contains("rule-2") {
		t.Error("rule-2 should not be in cache after invalidation")
	}

	// Verify rule-1 and rule-3 are still cached
	if !engine.cache.Contains("rule-1") {
		t.Error("rule-1 should still be in cache")
	}
	if !engine.cache.Contains("rule-3") {
		t.Error("rule-3 should still be in cache")
	}
}

// TestGetCachedRule_Refactored tests that the refactored getCachedRule maintains functionality
func TestGetCachedRule_Refactored(t *testing.T) {
	logger := zap.NewNop().Sugar()
	engine := NewSigmaEngine(context.Background(), nil, logger)
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-rule",
		Type: "sigma",
		SigmaYAML: `
title: Test Rule
detection:
  selection:
    EventID: 4624
  filter:
    User: SYSTEM
  condition: selection and not filter
logsource:
  product: windows
  service: security
`,
	}

	// First call should cache the rule
	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("getCachedRule failed: %v", err)
	}

	if cached == nil {
		t.Fatal("Expected non-nil cached rule")
	}

	if cached.RuleID != "test-rule" {
		t.Errorf("Expected RuleID 'test-rule', got '%s'", cached.RuleID)
	}

	if len(cached.DetectionBlocks) != 2 {
		t.Errorf("Expected 2 detection blocks, got %d", len(cached.DetectionBlocks))
	}

	if len(cached.Logsource) != 2 {
		t.Errorf("Expected 2 logsource fields, got %d", len(cached.Logsource))
	}

	// Second call should hit cache
	cached2, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("getCachedRule failed on second call: %v", err)
	}

	if cached2 == nil {
		t.Fatal("Expected non-nil cached rule on second call")
	}

	// Verify cache hit was recorded
	metrics := engine.GetMetrics()
	if metrics.CacheHits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", metrics.CacheHits)
	}
}
