package detect

import (
	"context"
	"strings"
	"testing"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

// testLogger creates a no-op logger for tests
func testLogger() *zap.SugaredLogger {
	logger, _ := zap.NewDevelopment()
	return logger.Sugar()
}

func TestNewSigmaEngine(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())

	if engine == nil {
		t.Fatal("NewSigmaEngine returned nil")
	}

	if engine.fieldMapper == nil {
		t.Error("fieldMapper not initialized")
	}

	if engine.modifierEval == nil {
		t.Error("modifierEval not initialized")
	}

	if engine.cache == nil {
		t.Error("cache not initialized")
	}

	if engine.conditionParser == nil {
		t.Error("conditionParser not initialized")
	}
}

func TestSigmaEngine_StartAndStop(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())

	engine.Start()

	// Should not panic
	done := make(chan struct{})
	go func() {
		engine.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good
	case <-time.After(1 * time.Second):
		t.Error("Stop() timed out")
	}
}

func TestSigmaEngine_Evaluate_NilRule(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	event := &core.Event{EventID: "test-1"}

	match, err := engine.Evaluate(nil, event)
	if err == nil {
		t.Error("Expected error for nil rule")
	}
	if match {
		t.Error("Expected no match for nil rule")
	}
}

func TestSigmaEngine_Evaluate_NilEvent(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-rule",
		Type:      "sigma",
		SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
	}

	match, err := engine.Evaluate(rule, nil)
	if err == nil {
		t.Error("Expected error for nil event")
	}
	if match {
		t.Error("Expected no match for nil event")
	}
}

func TestSigmaEngine_Evaluate_NonSigmaRule(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-rule",
		Type: "cql", // Not a SIGMA rule
	}
	event := &core.Event{EventID: "test-1"}

	match, err := engine.Evaluate(rule, event)
	if err == nil {
		t.Error("Expected error for non-SIGMA rule")
	}
	if match {
		t.Error("Expected no match for non-SIGMA rule")
	}
}

func TestSigmaEngine_Evaluate_SimpleRule_Match(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-rule-1",
		Type: "sigma",
		SigmaYAML: `
title: Test Rule
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    CommandLine|contains: "powershell"
  condition: selection
`,
	}

	event := &core.Event{
		EventID:   "event-1",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"CommandLine": "C:\\Windows\\System32\\powershell.exe -ep bypass",
		},
	}

	match, err := engine.Evaluate(rule, event)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if !match {
		t.Error("Expected rule to match")
	}
}

func TestSigmaEngine_Evaluate_SimpleRule_NoMatch(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-rule-2",
		Type: "sigma",
		SigmaYAML: `
title: Test Rule
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    CommandLine|contains: "powershell"
  condition: selection
`,
	}

	event := &core.Event{
		EventID:   "event-1",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"CommandLine": "C:\\Windows\\System32\\cmd.exe /c dir",
		},
	}

	match, err := engine.Evaluate(rule, event)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if match {
		t.Error("Expected rule NOT to match")
	}
}

func TestSigmaEngine_Evaluate_MultipleConditions_AND(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-rule-and",
		Type: "sigma",
		SigmaYAML: `
title: Test AND Condition
detection:
  selection1:
    CommandLine|contains: "powershell"
  selection2:
    User: "admin"
  condition: selection1 and selection2
`,
	}

	tests := []struct {
		name        string
		fields      map[string]interface{}
		expectMatch bool
	}{
		{
			name: "both match",
			fields: map[string]interface{}{
				"CommandLine": "powershell.exe",
				"User":        "admin",
			},
			expectMatch: true,
		},
		{
			name: "only selection1 matches",
			fields: map[string]interface{}{
				"CommandLine": "powershell.exe",
				"User":        "guest",
			},
			expectMatch: false,
		},
		{
			name: "only selection2 matches",
			fields: map[string]interface{}{
				"CommandLine": "cmd.exe",
				"User":        "admin",
			},
			expectMatch: false,
		},
		{
			name: "neither matches",
			fields: map[string]interface{}{
				"CommandLine": "cmd.exe",
				"User":        "guest",
			},
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &core.Event{
				EventID: "test-event",
				Fields:  tt.fields,
			}

			match, err := engine.Evaluate(rule, event)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if match != tt.expectMatch {
				t.Errorf("Expected match=%v, got %v", tt.expectMatch, match)
			}
		})
	}
}

func TestSigmaEngine_Evaluate_MultipleConditions_OR(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-rule-or",
		Type: "sigma",
		SigmaYAML: `
title: Test OR Condition
detection:
  selection1:
    CommandLine|contains: "powershell"
  selection2:
    CommandLine|contains: "cmd"
  condition: selection1 or selection2
`,
	}

	tests := []struct {
		name        string
		commandLine string
		expectMatch bool
	}{
		{"powershell", "powershell.exe", true},
		{"cmd", "cmd.exe /c dir", true},
		{"both", "powershell.exe & cmd.exe", true},
		{"neither", "notepad.exe", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &core.Event{
				EventID: "test-event",
				Fields: map[string]interface{}{
					"CommandLine": tt.commandLine,
				},
			}

			match, err := engine.Evaluate(rule, event)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if match != tt.expectMatch {
				t.Errorf("Expected match=%v, got %v", tt.expectMatch, match)
			}
		})
	}
}

func TestSigmaEngine_Evaluate_NOT(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-rule-not",
		Type: "sigma",
		SigmaYAML: `
title: Test NOT Condition
detection:
  selection:
    CommandLine|contains: "powershell"
  filter:
    User: "SYSTEM"
  condition: selection and not filter
`,
	}

	tests := []struct {
		name        string
		commandLine string
		user        string
		expectMatch bool
	}{
		{"powershell by user", "powershell.exe", "admin", true},
		{"powershell by SYSTEM", "powershell.exe", "SYSTEM", false},
		{"cmd by user", "cmd.exe", "admin", false},
		{"cmd by SYSTEM", "cmd.exe", "SYSTEM", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &core.Event{
				EventID: "test-event",
				Fields: map[string]interface{}{
					"CommandLine": tt.commandLine,
					"User":        tt.user,
				},
			}

			match, err := engine.Evaluate(rule, event)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if match != tt.expectMatch {
				t.Errorf("Expected match=%v, got %v", tt.expectMatch, match)
			}
		})
	}
}

func TestSigmaEngine_Evaluate_ValueList(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-rule-list",
		Type: "sigma",
		SigmaYAML: `
title: Test Value List
detection:
  selection:
    Image|endswith:
      - "\\powershell.exe"
      - "\\cmd.exe"
      - "\\wscript.exe"
  condition: selection
`,
	}

	tests := []struct {
		name        string
		image       string
		expectMatch bool
	}{
		{"powershell", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", true},
		{"cmd", "C:\\Windows\\System32\\cmd.exe", true},
		{"wscript", "C:\\Windows\\System32\\wscript.exe", true},
		{"notepad", "C:\\Windows\\System32\\notepad.exe", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &core.Event{
				EventID: "test-event",
				Fields: map[string]interface{}{
					"Image": tt.image,
				},
			}

			match, err := engine.Evaluate(rule, event)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if match != tt.expectMatch {
				t.Errorf("Expected match=%v, got %v", tt.expectMatch, match)
			}
		})
	}
}

func TestSigmaEngine_Evaluate_Modifiers(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	tests := []struct {
		name        string
		sigmaYAML   string
		fields      map[string]interface{}
		expectMatch bool
	}{
		{
			name: "startswith",
			sigmaYAML: `
title: Test startswith
detection:
  selection:
    CommandLine|startswith: "powershell"
  condition: selection
`,
			fields:      map[string]interface{}{"CommandLine": "powershell.exe -ep bypass"},
			expectMatch: true,
		},
		{
			name: "endswith",
			sigmaYAML: `
title: Test endswith
detection:
  selection:
    Image|endswith: ".exe"
  condition: selection
`,
			fields:      map[string]interface{}{"Image": "C:\\Windows\\System32\\cmd.exe"},
			expectMatch: true,
		},
		{
			name: "contains",
			sigmaYAML: `
title: Test contains
detection:
  selection:
    CommandLine|contains: "bypass"
  condition: selection
`,
			fields:      map[string]interface{}{"CommandLine": "powershell.exe -ep bypass -c"},
			expectMatch: true,
		},
		{
			name: "equals (no modifier)",
			sigmaYAML: `
title: Test equals
detection:
  selection:
    User: "admin"
  condition: selection
`,
			fields:      map[string]interface{}{"User": "admin"},
			expectMatch: true,
		},
		{
			name: "equals (no match)",
			sigmaYAML: `
title: Test equals no match
detection:
  selection:
    User: "admin"
  condition: selection
`,
			fields:      map[string]interface{}{"User": "ADMIN"},
			expectMatch: false, // Case-sensitive by default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &core.Rule{
				ID:        "test-" + strings.ReplaceAll(tt.name, " ", "-"),
				Type:      "sigma",
				SigmaYAML: tt.sigmaYAML,
			}

			event := &core.Event{
				EventID: "test-event",
				Fields:  tt.fields,
			}

			match, err := engine.Evaluate(rule, event)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if match != tt.expectMatch {
				t.Errorf("Expected match=%v, got %v", tt.expectMatch, match)
			}
		})
	}
}

func TestSigmaEngine_Evaluate_CacheHit(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-cache",
		Type: "sigma",
		SigmaYAML: `
title: Cache Test
detection:
  selection:
    field: "value"
  condition: selection
`,
	}

	event := &core.Event{
		EventID: "test-event",
		Fields:  map[string]interface{}{"field": "value"},
	}

	// First evaluation - cache miss
	_, err := engine.Evaluate(rule, event)
	if err != nil {
		t.Fatalf("First evaluation failed: %v", err)
	}

	metrics := engine.GetMetrics()
	if metrics.CacheMisses != 1 {
		t.Errorf("Expected 1 cache miss, got %d", metrics.CacheMisses)
	}

	// Second evaluation - should be cache hit
	_, err = engine.Evaluate(rule, event)
	if err != nil {
		t.Fatalf("Second evaluation failed: %v", err)
	}

	metrics = engine.GetMetrics()
	if metrics.CacheHits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", metrics.CacheHits)
	}
}

func TestSigmaEngine_InvalidateCache(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-invalidate",
		Type: "sigma",
		SigmaYAML: `
title: Test
detection:
  selection:
    field: "value"
  condition: selection
`,
	}

	event := &core.Event{
		EventID: "test-event",
		Fields:  map[string]interface{}{"field": "value"},
	}

	// First evaluation
	engine.Evaluate(rule, event)

	// Invalidate
	engine.InvalidateCache(rule.ID)

	// Next evaluation should be a cache miss
	engine.Evaluate(rule, event)

	metrics := engine.GetMetrics()
	if metrics.CacheMisses != 2 {
		t.Errorf("Expected 2 cache misses, got %d", metrics.CacheMisses)
	}
}

func TestSigmaEngine_Evaluate_MissingDetection(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-missing",
		Type: "sigma",
		SigmaYAML: `
title: Missing Detection
logsource:
  product: windows
`,
	}

	event := &core.Event{EventID: "test-event"}

	_, err := engine.Evaluate(rule, event)
	if err == nil {
		t.Error("Expected error for missing detection")
	}
}

func TestSigmaEngine_Evaluate_MissingCondition(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-no-condition",
		Type: "sigma",
		SigmaYAML: `
title: Missing Condition
detection:
  selection:
    field: value
`,
	}

	event := &core.Event{EventID: "test-event"}

	_, err := engine.Evaluate(rule, event)
	if err == nil {
		t.Error("Expected error for missing condition")
	}
}

func TestSigmaEngine_Evaluate_FieldNotFound(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-field-missing",
		Type: "sigma",
		SigmaYAML: `
title: Test Field Missing
detection:
  selection:
    NonExistentField: "value"
  condition: selection
`,
	}

	event := &core.Event{
		EventID: "test-event",
		Fields: map[string]interface{}{
			"OtherField": "other value",
		},
	}

	match, err := engine.Evaluate(rule, event)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Should not match because field doesn't exist
	if match {
		t.Error("Expected no match when required field is missing")
	}
}

func TestParseSigmaYAML(t *testing.T) {
	tests := []struct {
		name      string
		sigmaYAML string
		wantTitle string
		wantError bool
	}{
		{
			name: "valid rule",
			sigmaYAML: `
title: Test Rule
detection:
  selection:
    field: value
  condition: selection
`,
			wantTitle: "Test Rule",
			wantError: false,
		},
		{
			name:      "empty yaml",
			sigmaYAML: "",
			wantError: true,
		},
		{
			name: "missing detection",
			sigmaYAML: `
title: No Detection
logsource:
  product: windows
`,
			wantError: true,
		},
		{
			name: "missing condition",
			sigmaYAML: `
title: No Condition
detection:
  selection:
    field: value
`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			title, detection, _, err := ParseSigmaYAML(tt.sigmaYAML)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if title != tt.wantTitle {
					t.Errorf("Expected title=%q, got %q", tt.wantTitle, title)
				}
				if detection == nil {
					t.Error("Expected detection to be non-nil")
				}
			}
		})
	}
}

func TestSigmaEngine_Evaluate_AggregationAllOfThem(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-all-of-them",
		Type: "sigma",
		SigmaYAML: `
title: Test All Of Them
detection:
  selection1:
    CommandLine|contains: "powershell"
  selection2:
    User: "admin"
  condition: all of them
`,
	}

	tests := []struct {
		name        string
		fields      map[string]interface{}
		expectMatch bool
	}{
		{
			name: "both match",
			fields: map[string]interface{}{
				"CommandLine": "powershell.exe",
				"User":        "admin",
			},
			expectMatch: true,
		},
		{
			name: "only one matches",
			fields: map[string]interface{}{
				"CommandLine": "powershell.exe",
				"User":        "guest",
			},
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &core.Event{
				EventID: "test-event",
				Fields:  tt.fields,
			}

			match, err := engine.Evaluate(rule, event)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if match != tt.expectMatch {
				t.Errorf("Expected match=%v, got %v", tt.expectMatch, match)
			}
		})
	}
}

func TestSigmaEngine_Evaluate_AggregationOneOfSelection(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "test-one-of-selection",
		Type: "sigma",
		SigmaYAML: `
title: Test 1 of selection_*
detection:
  selection_windows:
    Image|endswith: "\\powershell.exe"
  selection_linux:
    Image|endswith: "/bash"
  condition: 1 of selection_*
`,
	}

	tests := []struct {
		name        string
		image       string
		expectMatch bool
	}{
		{"windows match", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", true},
		{"linux match", "/usr/bin/bash", true},
		{"no match", "/usr/bin/python", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &core.Event{
				EventID: "test-event",
				Fields: map[string]interface{}{
					"Image": tt.image,
				},
			}

			match, err := engine.Evaluate(rule, event)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if match != tt.expectMatch {
				t.Errorf("Expected match=%v, got %v", tt.expectMatch, match)
			}
		})
	}
}

func BenchmarkSigmaEngine_Evaluate_Simple(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-simple",
		Type: "sigma",
		SigmaYAML: `
title: Benchmark Simple
detection:
  selection:
    CommandLine|contains: "powershell"
  condition: selection
`,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"CommandLine": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
		},
	}

	// Warm up cache
	engine.Evaluate(rule, event)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}

func BenchmarkSigmaEngine_Evaluate_Complex(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-complex",
		Type: "sigma",
		SigmaYAML: `
title: Benchmark Complex
detection:
  selection:
    CommandLine|contains:
      - "powershell"
      - "cmd"
      - "wscript"
    User:
      - "admin"
      - "SYSTEM"
  filter:
    ParentImage|endswith: "\\svchost.exe"
  condition: selection and not filter
`,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"CommandLine": "powershell.exe -ep bypass",
			"User":        "admin",
			"ParentImage": "C:\\Windows\\explorer.exe",
		},
	}

	// Warm up cache
	engine.Evaluate(rule, event)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}
