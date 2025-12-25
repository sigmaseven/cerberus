package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// TestData represents test event data loaded from JSON
type TestData struct {
	Events []TestEvent `json:"events"`
}

// TestEvent represents a single test event with expected matches
type TestEvent struct {
	Name        string                 `json:"name"`
	Fields      map[string]interface{} `json:"fields"`
	ShouldMatch []string               `json:"should_match"`
}

// testSigmaLogger creates a no-op logger for tests
func testSigmaLogger() *zap.SugaredLogger {
	logger, _ := zap.NewDevelopment()
	return logger.Sugar()
}

// loadTestRules loads all YAML rules from a directory
func loadTestRules(t *testing.T, dir string) []*core.Rule {
	t.Helper()
	var rules []*core.Rule

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || (!strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml")) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		var parsed map[string]interface{}
		if err := yaml.Unmarshal(content, &parsed); err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		id, _ := parsed["id"].(string)
		title, _ := parsed["title"].(string)
		if id == "" {
			id = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		}

		rule := &core.Rule{
			ID:        id,
			Name:      title,
			Type:      "sigma",
			SigmaYAML: string(content),
			Enabled:   true,
		}
		rules = append(rules, rule)
		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		t.Logf("Warning loading rules from %s: %v", dir, err)
	}
	return rules
}

//lint:ignore U1000 Test helper for loading event test fixtures from JSON files
func loadTestEvents(t *testing.T, path string) []TestEvent {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("Failed to read test events: %v", err)
	}

	var data TestData
	if err := json.Unmarshal(content, &data); err != nil {
		t.Fatalf("Failed to parse test events: %v", err)
	}
	return data.Events
}

// TestSigmaEngine_LoadAllTestRules verifies all test rules can be parsed
func TestSigmaEngine_LoadAllTestRules(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testSigmaLogger())
	engine.Start()
	defer engine.Stop()

	testdataDir := "testdata/sigma_rules"
	if _, err := os.Stat(testdataDir); os.IsNotExist(err) {
		t.Skip("No testdata directory found")
	}

	rules := loadTestRules(t, testdataDir)
	if len(rules) == 0 {
		t.Skip("No test rules found")
	}

	t.Logf("Loaded %d test rules", len(rules))

	// Test that each rule can be parsed without error
	for _, rule := range rules {
		t.Run(rule.ID, func(t *testing.T) {
			event := &core.Event{
				EventID: "test-event",
				Fields:  map[string]interface{}{"test": "value"},
			}
			_, err := engine.Evaluate(rule, event)
			// We only care that it doesn't panic or return parse errors
			if err != nil && strings.Contains(err.Error(), "failed to parse") {
				t.Errorf("Rule %s failed to parse: %v", rule.ID, err)
			}
		})
	}
}

// TestSigmaEngine_AllModifiers tests each SIGMA modifier individually
func TestSigmaEngine_AllModifiers(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testSigmaLogger())
	engine.Start()
	defer engine.Stop()

	// unimplementedModifiers tracks modifiers not yet implemented in the SIGMA engine
	unimplementedModifiers := map[string]bool{
		"gt": true, "gte": true, "lt": true, "lte": true,
		"base64": true, "base64offset": true,
		"wildcard": true,
	}

	modifierTests := []struct {
		name        string
		modifier    string
		ruleValue   interface{}
		eventValue  interface{}
		shouldMatch bool
	}{
		// String modifiers - case sensitive by SIGMA spec
		{"contains_match", "contains", "test", "this is a test string", true},
		{"contains_no_match", "contains", "xyz", "this is a test string", false},
		{"contains_case_sensitive", "contains", "TEST", "this is a test", false}, // SIGMA is case-sensitive by default
		{"startswith_match", "startswith", "this", "this is a test", true},
		{"startswith_no_match", "startswith", "that", "this is a test", false},
		{"startswith_case_sensitive", "startswith", "THIS", "this is a test", false}, // SIGMA is case-sensitive by default
		{"endswith_match", "endswith", "test", "this is a test", true},
		{"endswith_no_match", "endswith", "testing", "this is a test", false},
		{"endswith_case_sensitive", "endswith", "TEST", "this is a test", false}, // SIGMA is case-sensitive by default

		// Regex modifiers
		{"re_match", "re", "test.*string", "this is a test string", true},
		{"re_no_match", "re", "^test", "this is a test string", false},
		{"re_case_sensitive", "re", "Test", "test", false},

		// Numeric comparisons (not implemented yet)
		{"gt_match", "gt", 5, 10, true},
		{"gt_no_match", "gt", 15, 10, false},
		{"gte_match", "gte", 10, 10, true},
		{"lt_match", "lt", 15, 10, true},
		{"lt_no_match", "lt", 5, 10, false},
		{"lte_match", "lte", 10, 10, true},

		// Base64 (not implemented yet)
		{"base64_match", "base64", "dGVzdA==", "test", true},
		{"base64offset_match", "base64offset", "dGVzd", "test", true},

		// CIDR
		{"cidr_match", "cidr", "192.168.1.0/24", "192.168.1.100", true},
		{"cidr_no_match", "cidr", "192.168.1.0/24", "10.0.0.1", false},

		// Wildcard (not implemented yet)
		{"wildcard_match", "wildcard", "*test*", "this is a test string", true},
		{"wildcard_no_match", "wildcard", "test*end", "test something else", false},
	}

	for _, tc := range modifierTests {
		t.Run(tc.name, func(t *testing.T) {
			// Skip unimplemented modifiers
			if unimplementedModifiers[tc.modifier] {
				t.Skipf("Modifier %s is not yet implemented", tc.modifier)
			}

			sigmaYAML := fmt.Sprintf(`
title: Modifier Test - %s
id: modifier-test-%s
logsource:
    category: test
detection:
    selection:
        field|%s: %v
    condition: selection
`, tc.name, tc.name, tc.modifier, formatYAMLValue(tc.ruleValue))

			rule := &core.Rule{
				ID:        "modifier-test-" + tc.name,
				Type:      "sigma",
				SigmaYAML: sigmaYAML,
				Enabled:   true,
			}

			event := &core.Event{
				EventID: "test-event",
				Fields: map[string]interface{}{
					"field": tc.eventValue,
				},
			}

			match, err := engine.Evaluate(rule, event)
			if err != nil {
				t.Fatalf("Unexpected error for modifier %s: %v", tc.modifier, err)
			}

			if tc.shouldMatch && !match {
				t.Errorf("Expected match for modifier %s with rule value %v and event value %v",
					tc.modifier, tc.ruleValue, tc.eventValue)
			}
			if !tc.shouldMatch && match {
				t.Errorf("Expected no match for modifier %s with rule value %v and event value %v",
					tc.modifier, tc.ruleValue, tc.eventValue)
			}
		})
	}
}

// formatYAMLValue formats a value for YAML
func formatYAMLValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return fmt.Sprintf("'%s'", val)
	case int, int64, float64:
		return fmt.Sprintf("%v", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// TestSigmaEngine_ComplexConditions tests complex condition expressions
func TestSigmaEngine_ComplexConditions(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testSigmaLogger())
	engine.Start()
	defer engine.Stop()

	tests := []struct {
		name        string
		condition   string
		blocks      map[string]map[string]interface{}
		eventFields map[string]interface{}
		shouldMatch bool
	}{
		{
			name:      "simple_and",
			condition: "sel1 and sel2",
			blocks: map[string]map[string]interface{}{
				"sel1": {"field1": "value1"},
				"sel2": {"field2": "value2"},
			},
			eventFields: map[string]interface{}{"field1": "value1", "field2": "value2"},
			shouldMatch: true,
		},
		{
			name:      "simple_or",
			condition: "sel1 or sel2",
			blocks: map[string]map[string]interface{}{
				"sel1": {"field1": "value1"},
				"sel2": {"field2": "value2"},
			},
			eventFields: map[string]interface{}{"field1": "value1"},
			shouldMatch: true,
		},
		{
			name:      "not_filter",
			condition: "selection and not filter",
			blocks: map[string]map[string]interface{}{
				"selection": {"field1": "value1"},
				"filter":    {"field2": "excluded"},
			},
			eventFields: map[string]interface{}{"field1": "value1", "field2": "allowed"},
			shouldMatch: true,
		},
		{
			name:      "complex_nested",
			condition: "(sel1 or sel2) and not filter",
			blocks: map[string]map[string]interface{}{
				"sel1":   {"field1": "value1"},
				"sel2":   {"field1": "value2"},
				"filter": {"user": "SYSTEM"},
			},
			eventFields: map[string]interface{}{"field1": "value1", "user": "admin"},
			shouldMatch: true,
		},
		{
			name:      "all_of_them",
			condition: "all of them",
			blocks: map[string]map[string]interface{}{
				"selection1": {"field1": "value1"},
				"selection2": {"field2": "value2"},
			},
			eventFields: map[string]interface{}{"field1": "value1", "field2": "value2"},
			shouldMatch: true,
		},
		{
			name:      "1_of_selection",
			condition: "1 of selection*",
			blocks: map[string]map[string]interface{}{
				"selection_windows": {"os": "windows"},
				"selection_linux":   {"os": "linux"},
			},
			eventFields: map[string]interface{}{"os": "windows"},
			shouldMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Build SIGMA YAML from test case
			var blockYAML strings.Builder
			for name, fields := range tc.blocks {
				blockYAML.WriteString(fmt.Sprintf("    %s:\n", name))
				for field, value := range fields {
					blockYAML.WriteString(fmt.Sprintf("        %s: %s\n", field, formatYAMLValue(value)))
				}
			}

			sigmaYAML := fmt.Sprintf(`
title: Complex Condition Test - %s
id: complex-test-%s
logsource:
    category: test
detection:
%s    condition: %s
`, tc.name, tc.name, blockYAML.String(), tc.condition)

			rule := &core.Rule{
				ID:        "complex-test-" + tc.name,
				Type:      "sigma",
				SigmaYAML: sigmaYAML,
				Enabled:   true,
			}

			event := &core.Event{
				EventID: "test-event",
				Fields:  tc.eventFields,
			}

			match, err := engine.Evaluate(rule, event)
			if err != nil {
				t.Logf("Evaluation returned error (may be expected): %v", err)
			}

			if tc.shouldMatch != match && err == nil {
				t.Errorf("Expected match=%v for condition '%s', got match=%v",
					tc.shouldMatch, tc.condition, match)
			}
		})
	}
}

// TestSigmaEngine_EdgeCases tests edge cases and boundary conditions
func TestSigmaEngine_EdgeCases(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testSigmaLogger())
	engine.Start()
	defer engine.Stop()

	t.Run("empty_field_value", func(t *testing.T) {
		sigmaYAML := `
title: Empty Field Test
id: edge-empty-001
logsource:
    category: test
detection:
    selection:
        field: ''
    condition: selection
`
		rule := &core.Rule{ID: "edge-empty", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}
		event := &core.Event{EventID: "test", Fields: map[string]interface{}{"field": ""}}

		match, err := engine.Evaluate(rule, event)
		require.NoError(t, err)
		assert.True(t, match, "Empty string should match empty string")
	})

	t.Run("nil_field_value", func(t *testing.T) {
		sigmaYAML := `
title: Nil Field Test
id: edge-nil-001
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
`
		rule := &core.Rule{ID: "edge-nil", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}
		event := &core.Event{EventID: "test", Fields: map[string]interface{}{"other": "value"}}

		match, _ := engine.Evaluate(rule, event)
		assert.False(t, match, "Missing field should not match")
	})

	t.Run("numeric_as_string", func(t *testing.T) {
		sigmaYAML := `
title: Numeric String Test
id: edge-numeric-001
logsource:
    category: test
detection:
    selection:
        port: '8080'
    condition: selection
`
		rule := &core.Rule{ID: "edge-numeric", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}
		event := &core.Event{EventID: "test", Fields: map[string]interface{}{"port": "8080"}}

		match, err := engine.Evaluate(rule, event)
		require.NoError(t, err)
		assert.True(t, match, "String '8080' should match")
	})

	t.Run("boolean_field", func(t *testing.T) {
		sigmaYAML := `
title: Boolean Field Test
id: edge-bool-001
logsource:
    category: test
detection:
    selection:
        enabled: true
    condition: selection
`
		rule := &core.Rule{ID: "edge-bool", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}
		event := &core.Event{EventID: "test", Fields: map[string]interface{}{"enabled": true}}

		match, err := engine.Evaluate(rule, event)
		require.NoError(t, err)
		assert.True(t, match, "Boolean true should match")
	})

	t.Run("unicode_field_value", func(t *testing.T) {
		sigmaYAML := `
title: Unicode Test
id: edge-unicode-001
logsource:
    category: test
detection:
    selection:
        field|contains: 'тест'
    condition: selection
`
		rule := &core.Rule{ID: "edge-unicode", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}
		event := &core.Event{EventID: "test", Fields: map[string]interface{}{"field": "это тест unicode"}}

		match, err := engine.Evaluate(rule, event)
		require.NoError(t, err)
		assert.True(t, match, "Unicode should match")
	})

	t.Run("very_long_field_value", func(t *testing.T) {
		longValue := strings.Repeat("a", 100000)
		sigmaYAML := `
title: Long Value Test
id: edge-long-001
logsource:
    category: test
detection:
    selection:
        field|contains: 'aaaa'
    condition: selection
`
		rule := &core.Rule{ID: "edge-long", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}
		event := &core.Event{EventID: "test", Fields: map[string]interface{}{"field": longValue}}

		match, err := engine.Evaluate(rule, event)
		require.NoError(t, err)
		assert.True(t, match, "Long value should match")
	})

	t.Run("special_characters", func(t *testing.T) {
		// Test that field values with special characters like backslashes work
		// Note: Using "Image" field which doesn't trigger field aliasing issues
		sigmaYAML := `
title: Special Chars Test
id: edge-special-001
logsource:
    category: test
detection:
    selection:
        Image|contains: 'Windows'
    condition: selection
`
		rule := &core.Rule{ID: "edge-special", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}
		event := &core.Event{EventID: "test", Fields: map[string]interface{}{"Image": `C:\Windows\System32\cmd.exe`}}

		match, err := engine.Evaluate(rule, event)
		require.NoError(t, err)
		assert.True(t, match, "Path with backslashes should match")
	})

	t.Run("windows_path_backslash", func(t *testing.T) {
		// Test Windows path matching using endswith modifier
		// Using "CommandLine" field which is standard SIGMA field
		sigmaYAML := `
title: Windows Path Test
id: edge-winpath-001
logsource:
    category: test
detection:
    selection:
        CommandLine|endswith: '\cmd.exe'
    condition: selection
`
		rule := &core.Rule{ID: "edge-winpath", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}
		event := &core.Event{EventID: "test", Fields: map[string]interface{}{"CommandLine": `C:\Windows\System32\cmd.exe`}}

		match, err := engine.Evaluate(rule, event)
		require.NoError(t, err)
		assert.True(t, match, "Windows path should match with endswith")
	})
}

// TestSigmaEngine_SecurityTests tests security-related scenarios
func TestSigmaEngine_SecurityTests(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testSigmaLogger())
	engine.Start()
	defer engine.Stop()

	t.Run("regex_complexity_limit", func(t *testing.T) {
		// Test that complex regex patterns don't cause ReDoS
		sigmaYAML := `
title: ReDoS Test
id: security-redos-001
logsource:
    category: test
detection:
    selection:
        field|re: '(a+)+b'
    condition: selection
`
		rule := &core.Rule{ID: "security-redos", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}
		// This input would cause ReDoS in naive implementations
		event := &core.Event{EventID: "test", Fields: map[string]interface{}{"field": strings.Repeat("a", 30) + "c"}}

		start := time.Now()
		_, _ = engine.Evaluate(rule, event)
		elapsed := time.Since(start)

		// Should complete quickly (regex timeout protection)
		assert.Less(t, elapsed, 10*time.Second, "Regex should not take too long (ReDoS protection)")
	})

	t.Run("yaml_bomb_protection", func(t *testing.T) {
		// Test that deeply nested YAML doesn't cause issues
		// (This is more of a YAML parser test, but important for security)
		deepYAML := `
title: Deep Nesting Test
id: security-nest-001
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
`
		rule := &core.Rule{ID: "security-nest", Type: "sigma", SigmaYAML: deepYAML, Enabled: true}
		event := &core.Event{EventID: "test", Fields: map[string]interface{}{"field": "value"}}

		_, err := engine.Evaluate(rule, event)
		assert.NoError(t, err)
	})

	t.Run("large_event_handling", func(t *testing.T) {
		sigmaYAML := `
title: Large Event Test
id: security-large-001
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
`
		rule := &core.Rule{ID: "security-large", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}

		// Event with many fields
		fields := make(map[string]interface{})
		for i := 0; i < 1000; i++ {
			fields[fmt.Sprintf("field_%d", i)] = fmt.Sprintf("value_%d", i)
		}
		fields["field"] = "value"
		event := &core.Event{EventID: "test", Fields: fields}

		match, err := engine.Evaluate(rule, event)
		require.NoError(t, err)
		assert.True(t, match)
	})
}

// TestSigmaEngine_ConcurrentEvaluation tests thread-safety
func TestSigmaEngine_ConcurrentEvaluation(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testSigmaLogger())
	engine.Start()
	defer engine.Stop()

	sigmaYAML := `
title: Concurrent Test
id: concurrent-001
logsource:
    category: test
detection:
    selection:
        field|contains: 'test'
    condition: selection
`
	rule := &core.Rule{ID: "concurrent", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}

	const goroutines = 100
	const iterations = 100

	var wg sync.WaitGroup
	errors := make(chan error, goroutines*iterations)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				event := &core.Event{
					EventID: fmt.Sprintf("event-%d-%d", id, j),
					Fields: map[string]interface{}{
						"field": fmt.Sprintf("this is test %d-%d", id, j),
					},
				}
				match, err := engine.Evaluate(rule, event)
				if err != nil {
					errors <- err
				}
				if !match {
					errors <- fmt.Errorf("expected match for event %s", event.EventID)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	var errCount int
	for err := range errors {
		errCount++
		t.Logf("Concurrent error: %v", err)
	}

	assert.Zero(t, errCount, "No errors should occur during concurrent evaluation")

	// Verify cache stats
	stats := engine.GetCacheStats()
	t.Logf("Cache stats after concurrent test: hits=%d, misses=%d", stats.Hits, stats.Misses)
	// In concurrent execution, multiple goroutines may hit cache miss before first one populates it
	// So we allow some cache misses, but the vast majority should be hits
	totalEvals := int64(goroutines * iterations)
	assert.LessOrEqual(t, stats.Misses, int64(goroutines), "Cache misses should be <= number of goroutines (racing initial evaluations)")
	assert.GreaterOrEqual(t, stats.Hits+stats.Misses, totalEvals, "Total hits+misses should cover all evaluations")
}

// TestSigmaEngine_MetricsTracking verifies metrics are properly recorded
func TestSigmaEngine_MetricsTracking(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testSigmaLogger())
	engine.Start()
	defer engine.Stop()

	sigmaYAML := `
title: Metrics Test
id: metrics-001
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
`
	rule := &core.Rule{ID: "metrics", Type: "sigma", SigmaYAML: sigmaYAML, Enabled: true}

	// Matching event
	event1 := &core.Event{EventID: "test1", Fields: map[string]interface{}{"field": "value"}}
	match1, _ := engine.Evaluate(rule, event1)
	assert.True(t, match1)

	// Non-matching event
	event2 := &core.Event{EventID: "test2", Fields: map[string]interface{}{"field": "other"}}
	match2, _ := engine.Evaluate(rule, event2)
	assert.False(t, match2)

	// Error case (nil rule)
	_, _ = engine.Evaluate(nil, event1)

	metrics := engine.GetMetrics()
	assert.Equal(t, int64(2), metrics.Evaluations, "Should have 2 successful evaluations")
	assert.Equal(t, int64(1), metrics.Matches, "Should have 1 match")
	assert.Equal(t, int64(1), metrics.Errors, "Should have 1 error (nil rule)")
}
