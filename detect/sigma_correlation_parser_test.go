package detect

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"cerberus/core"
)

// TestParseCorrelationBlock_EventCount tests parsing event_count correlation type.
func TestParseCorrelationBlock_EventCount(t *testing.T) {
	sigmaYAML := `
title: Brute Force Detection
detection:
  selection:
    event_id: 4625
  condition: selection
correlation:
  type: event_count
  group_by:
    - source_ip
    - username
  timespan: 5m
  condition:
    operator: ">="
    value: 5
`

	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-event-count",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule with event_count correlation: %v", err)
	}

	if cached.Correlation == nil {
		t.Fatal("Expected correlation to be parsed, got nil")
	}

	if cached.Correlation.Type != "event_count" {
		t.Errorf("Expected type 'event_count', got '%s'", cached.Correlation.Type)
	}

	if len(cached.Correlation.GroupBy) != 2 {
		t.Errorf("Expected 2 group_by fields, got %d", len(cached.Correlation.GroupBy))
	}

	if cached.Correlation.Timespan != "5m" {
		t.Errorf("Expected timespan '5m', got '%s'", cached.Correlation.Timespan)
	}

	if cached.Correlation.Condition == nil {
		t.Fatal("Expected condition to be set")
	}

	if cached.Correlation.Condition.Operator != ">=" {
		t.Errorf("Expected operator '>=', got '%s'", cached.Correlation.Condition.Operator)
	}
}

// TestParseCorrelationBlock_ValueCount tests parsing value_count correlation type.
func TestParseCorrelationBlock_ValueCount(t *testing.T) {
	sigmaYAML := `
title: Password Spray Detection
detection:
  selection:
    event_id: 4625
  condition: selection
correlation:
  type: value_count
  group_by:
    - source_ip
  distinct_field: username
  timespan: 10m
  condition:
    operator: ">"
    value: 10
`

	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-value-count",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule with value_count correlation: %v", err)
	}

	if cached.Correlation == nil {
		t.Fatal("Expected correlation to be parsed, got nil")
	}

	if cached.Correlation.Type != "value_count" {
		t.Errorf("Expected type 'value_count', got '%s'", cached.Correlation.Type)
	}

	if cached.Correlation.DistinctField != "username" {
		t.Errorf("Expected distinct_field 'username', got '%s'", cached.Correlation.DistinctField)
	}

	if cached.Correlation.Condition.Operator != ">" {
		t.Errorf("Expected operator '>', got '%s'", cached.Correlation.Condition.Operator)
	}
}

// TestParseCorrelationBlock_Sequence tests parsing sequence correlation type.
func TestParseCorrelationBlock_Sequence(t *testing.T) {
	sigmaYAML := `
title: Lateral Movement Detection
detection:
  selection:
    event_id: 4624
  condition: selection
correlation:
  type: sequence
  events:
    - recon
    - access
    - exfil
  ordered: true
  timespan: 1h
`

	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-sequence",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule with sequence correlation: %v", err)
	}

	if cached.Correlation == nil {
		t.Fatal("Expected correlation to be parsed, got nil")
	}

	if cached.Correlation.Type != "sequence" {
		t.Errorf("Expected type 'sequence', got '%s'", cached.Correlation.Type)
	}

	if len(cached.Correlation.Events) != 3 {
		t.Errorf("Expected 3 events, got %d", len(cached.Correlation.Events))
	}

	if !cached.Correlation.Ordered {
		t.Error("Expected ordered to be true")
	}
}

// TestParseCorrelationBlock_Temporal tests parsing temporal correlation type.
func TestParseCorrelationBlock_Temporal(t *testing.T) {
	sigmaYAML := `
title: Time-based Anomaly Detection
detection:
  selection:
    event_type: login
  condition: selection
correlation:
  type: temporal
  timespan: 30m
  group_by:
    - user_id
`

	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-temporal",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule with temporal correlation: %v", err)
	}

	if cached.Correlation == nil {
		t.Fatal("Expected correlation to be parsed, got nil")
	}

	if cached.Correlation.Type != "temporal" {
		t.Errorf("Expected type 'temporal', got '%s'", cached.Correlation.Type)
	}

	if cached.Correlation.Timespan != "30m" {
		t.Errorf("Expected timespan '30m', got '%s'", cached.Correlation.Timespan)
	}
}

// TestParseCorrelationBlock_Rare tests parsing rare correlation type.
func TestParseCorrelationBlock_Rare(t *testing.T) {
	sigmaYAML := `
title: Rare Process Execution
detection:
  selection:
    event_id: 1
  condition: selection
correlation:
  type: rare
  baseline_window: 7d
  condition:
    operator: "<"
    value: 3
`

	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-rare",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule with rare correlation: %v", err)
	}

	if cached.Correlation == nil {
		t.Fatal("Expected correlation to be parsed, got nil")
	}

	if cached.Correlation.Type != "rare" {
		t.Errorf("Expected type 'rare', got '%s'", cached.Correlation.Type)
	}

	if cached.Correlation.BaselineWindow != "7d" {
		t.Errorf("Expected baseline_window '7d', got '%s'", cached.Correlation.BaselineWindow)
	}

	if cached.Correlation.Condition.Operator != "<" {
		t.Errorf("Expected operator '<', got '%s'", cached.Correlation.Condition.Operator)
	}
}

// TestParseCorrelationBlock_Statistical tests parsing statistical correlation type.
func TestParseCorrelationBlock_Statistical(t *testing.T) {
	sigmaYAML := `
title: Statistical Anomaly Detection
detection:
  selection:
    event_type: network_connection
  condition: selection
correlation:
  type: statistical
  baseline_window: 30d
  std_dev_threshold: 3.0
`

	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-statistical",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule with statistical correlation: %v", err)
	}

	if cached.Correlation == nil {
		t.Fatal("Expected correlation to be parsed, got nil")
	}

	if cached.Correlation.Type != "statistical" {
		t.Errorf("Expected type 'statistical', got '%s'", cached.Correlation.Type)
	}

	if cached.Correlation.BaselineWindow != "30d" {
		t.Errorf("Expected baseline_window '30d', got '%s'", cached.Correlation.BaselineWindow)
	}

	if cached.Correlation.StdDevThreshold != 3.0 {
		t.Errorf("Expected std_dev_threshold 3.0, got %f", cached.Correlation.StdDevThreshold)
	}
}

// TestParseCorrelationBlock_Chain tests parsing chain correlation type.
func TestParseCorrelationBlock_Chain(t *testing.T) {
	sigmaYAML := `
title: Multi-stage Attack Chain
detection:
  selection:
    event_type: security
  condition: selection
correlation:
  type: chain
  stages:
    - name: reconnaissance
      detection_ref: rule_recon_001
      timeout: 1h
    - name: exploitation
      detection_ref: rule_exploit_001
      timeout: 30m
    - name: exfiltration
      detection_ref: rule_exfil_001
      timeout: 15m
  min_stages: 2
  max_duration: 24h
`

	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-chain",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule with chain correlation: %v", err)
	}

	if cached.Correlation == nil {
		t.Fatal("Expected correlation to be parsed, got nil")
	}

	if cached.Correlation.Type != "chain" {
		t.Errorf("Expected type 'chain', got '%s'", cached.Correlation.Type)
	}

	if len(cached.Correlation.Stages) != 3 {
		t.Errorf("Expected 3 stages, got %d", len(cached.Correlation.Stages))
	}

	if cached.Correlation.MinStages != 2 {
		t.Errorf("Expected min_stages 2, got %d", cached.Correlation.MinStages)
	}

	if cached.Correlation.MaxDuration != "24h" {
		t.Errorf("Expected max_duration '24h', got '%s'", cached.Correlation.MaxDuration)
	}

	// Verify first stage
	if cached.Correlation.Stages[0].Name != "reconnaissance" {
		t.Errorf("Expected stage name 'reconnaissance', got '%s'", cached.Correlation.Stages[0].Name)
	}

	if cached.Correlation.Stages[0].DetectionRef != "rule_recon_001" {
		t.Errorf("Expected detection_ref 'rule_recon_001', got '%s'", cached.Correlation.Stages[0].DetectionRef)
	}
}

// TestParseCorrelationBlock_CrossEntity tests parsing cross_entity correlation type.
func TestParseCorrelationBlock_CrossEntity(t *testing.T) {
	sigmaYAML := `
title: Cross-entity Activity Detection
detection:
  selection:
    event_type: access
  condition: selection
correlation:
  type: cross_entity
  track_field: username
  count_distinct: dest_host
  timespan: 15m
  condition:
    operator: ">="
    value: 5
`

	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-cross-entity",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule with cross_entity correlation: %v", err)
	}

	if cached.Correlation == nil {
		t.Fatal("Expected correlation to be parsed, got nil")
	}

	if cached.Correlation.Type != "cross_entity" {
		t.Errorf("Expected type 'cross_entity', got '%s'", cached.Correlation.Type)
	}

	if cached.Correlation.TrackField != "username" {
		t.Errorf("Expected track_field 'username', got '%s'", cached.Correlation.TrackField)
	}

	if cached.Correlation.CountDistinct != "dest_host" {
		t.Errorf("Expected count_distinct 'dest_host', got '%s'", cached.Correlation.CountDistinct)
	}
}

// TestParseCorrelationBlock_NoCorrelation tests rules without correlation blocks.
func TestParseCorrelationBlock_NoCorrelation(t *testing.T) {
	sigmaYAML := `
title: Simple Detection Rule
detection:
  selection:
    event_id: 4624
  condition: selection
`

	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-no-correlation",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule without correlation: %v", err)
	}

	if cached.Correlation != nil {
		t.Error("Expected correlation to be nil for rule without correlation block")
	}
}

// TestParseCorrelationBlock_MalformedYAML tests error handling for malformed YAML.
func TestParseCorrelationBlock_MalformedYAML(t *testing.T) {
	sigmaYAML := `
title: Malformed Correlation
detection:
  selection:
    event_id: 4624
  condition: selection
correlation:
  type: event_count
  timespan: "invalid_duration"
  condition:
    operator: ">="
    value: 5
`

	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:        "test-malformed",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	// Should parse successfully but log a warning about correlation failure
	cached, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	// Correlation should be nil due to validation failure
	if cached.Correlation != nil {
		t.Error("Expected correlation to be nil for malformed correlation block")
	}
}

// TestParseCorrelationBlock_MissingRequiredFields tests validation errors.
func TestParseCorrelationBlock_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name      string
		sigmaYAML string
		wantNil   bool
	}{
		{
			name: "event_count missing timespan",
			sigmaYAML: `
title: Missing Timespan
detection:
  selection:
    event_id: 4624
  condition: selection
correlation:
  type: event_count
  condition:
    operator: ">="
    value: 5
`,
			wantNil: true,
		},
		{
			name: "value_count missing distinct_field",
			sigmaYAML: `
title: Missing Distinct Field
detection:
  selection:
    event_id: 4625
  condition: selection
correlation:
  type: value_count
  timespan: 10m
  condition:
    operator: ">"
    value: 10
`,
			wantNil: true,
		},
		{
			name: "sequence missing events",
			sigmaYAML: `
title: Missing Events
detection:
  selection:
    event_id: 4624
  condition: selection
correlation:
  type: sequence
  timespan: 1h
`,
			wantNil: true,
		},
		{
			name: "chain missing stages",
			sigmaYAML: `
title: Missing Stages
detection:
  selection:
    event_id: 4624
  condition: selection
correlation:
  type: chain
  max_duration: 24h
`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewSigmaEngine(context.Background(), nil, testLogger())
			engine.Start()
			defer engine.Stop()

			rule := &core.Rule{
				ID:        "test-validation-" + tt.name,
				Type:      "sigma",
				SigmaYAML: tt.sigmaYAML,
			}

			cached, err := engine.getCachedRule(rule)
			if err != nil {
				t.Fatalf("Failed to parse rule: %v", err)
			}

			if tt.wantNil && cached.Correlation != nil {
				t.Error("Expected correlation to be nil due to validation failure")
			}
		})
	}
}

// TestInvalidateCorrelationRules tests correlation-aware cache invalidation.
func TestInvalidateCorrelationRules(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	// Add rule with correlation
	ruleWithCorr := &core.Rule{
		ID:   "rule-with-corr",
		Type: "sigma",
		SigmaYAML: `
title: Rule With Correlation
detection:
  selection:
    event_id: 4625
  condition: selection
correlation:
  type: event_count
  timespan: 5m
  condition:
    operator: ">="
    value: 5
`,
	}

	// Add rule without correlation
	ruleWithoutCorr := &core.Rule{
		ID:   "rule-without-corr",
		Type: "sigma",
		SigmaYAML: `
title: Rule Without Correlation
detection:
  selection:
    event_id: 4624
  condition: selection
`,
	}

	// Cache both rules
	_, err := engine.getCachedRule(ruleWithCorr)
	if err != nil {
		t.Fatalf("Failed to cache rule with correlation: %v", err)
	}

	_, err = engine.getCachedRule(ruleWithoutCorr)
	if err != nil {
		t.Fatalf("Failed to cache rule without correlation: %v", err)
	}

	// Verify both are cached
	if !engine.cache.Contains(ruleWithCorr.ID) {
		t.Error("Rule with correlation not cached")
	}
	if !engine.cache.Contains(ruleWithoutCorr.ID) {
		t.Error("Rule without correlation not cached")
	}

	// Invalidate correlation rules only
	count := engine.InvalidateCorrelationRules()

	// Should invalidate 1 rule
	if count != 1 {
		t.Errorf("Expected 1 rule to be invalidated, got %d", count)
	}

	// Verify rule with correlation is invalidated
	if engine.cache.Contains(ruleWithCorr.ID) {
		t.Error("Rule with correlation should be invalidated")
	}

	// Verify rule without correlation is still cached
	if !engine.cache.Contains(ruleWithoutCorr.ID) {
		t.Error("Rule without correlation should still be cached")
	}
}

// TestParseSigmaYAML_WithCorrelation tests the utility function with correlation.
func TestParseSigmaYAML_WithCorrelation(t *testing.T) {
	sigmaYAML := `
title: Test Rule With Correlation
detection:
  selection:
    event_id: 4625
  condition: selection
correlation:
  type: event_count
  timespan: 5m
  condition:
    operator: ">="
    value: 5
`

	title, detection, correlation, err := ParseSigmaYAML(sigmaYAML)
	if err != nil {
		t.Fatalf("Failed to parse SIGMA YAML: %v", err)
	}

	if title != "Test Rule With Correlation" {
		t.Errorf("Expected title 'Test Rule With Correlation', got '%s'", title)
	}

	if detection == nil {
		t.Fatal("Expected detection section to be parsed")
	}

	if correlation == nil {
		t.Fatal("Expected correlation section to be parsed")
	}

	if correlation.Type != "event_count" {
		t.Errorf("Expected correlation type 'event_count', got '%s'", correlation.Type)
	}
}

// TestParseSigmaYAML_WithoutCorrelation tests the utility function without correlation.
func TestParseSigmaYAML_WithoutCorrelation(t *testing.T) {
	sigmaYAML := `
title: Test Rule Without Correlation
detection:
  selection:
    event_id: 4624
  condition: selection
`

	title, detection, correlation, err := ParseSigmaYAML(sigmaYAML)
	if err != nil {
		t.Fatalf("Failed to parse SIGMA YAML: %v", err)
	}

	if title != "Test Rule Without Correlation" {
		t.Errorf("Expected title 'Test Rule Without Correlation', got '%s'", title)
	}

	if detection == nil {
		t.Fatal("Expected detection section to be parsed")
	}

	if correlation != nil {
		t.Error("Expected correlation to be nil for rule without correlation block")
	}
}

// TestParseSigmaYAML_InvalidCorrelation tests error handling for invalid correlation.
func TestParseSigmaYAML_InvalidCorrelation(t *testing.T) {
	sigmaYAML := `
title: Test Rule With Invalid Correlation
detection:
  selection:
    event_id: 4625
  condition: selection
correlation:
  type: invalid_type
  timespan: 5m
`

	_, _, _, err := ParseSigmaYAML(sigmaYAML)
	if err == nil {
		t.Fatal("Expected error for invalid correlation type")
	}

	if !strings.Contains(err.Error(), "unsupported correlation type") {
		t.Errorf("Expected error about unsupported type, got: %v", err)
	}
}

// TestCorrelationCacheRoundtrip tests caching and retrieval of correlation rules.
func TestCorrelationCacheRoundtrip(t *testing.T) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	sigmaYAML := `
title: Cache Roundtrip Test
detection:
  selection:
    event_id: 4625
  condition: selection
correlation:
  type: value_count
  group_by:
    - source_ip
  distinct_field: username
  timespan: 10m
  condition:
    operator: ">"
    value: 10
`

	rule := &core.Rule{
		ID:        "test-cache-roundtrip",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	// First access - cache miss
	cached1, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	// Second access - cache hit
	cached2, err := engine.getCachedRule(rule)
	if err != nil {
		t.Fatalf("Failed to retrieve cached rule: %v", err)
	}

	// Verify correlation is preserved across cache operations
	if cached1.Correlation == nil || cached2.Correlation == nil {
		t.Fatal("Expected correlation to be present in both cached entries")
	}

	if cached1.Correlation.Type != cached2.Correlation.Type {
		t.Error("Correlation type mismatch between cache entries")
	}

	if cached1.Correlation.DistinctField != cached2.Correlation.DistinctField {
		t.Error("Correlation distinct_field mismatch between cache entries")
	}

	// Verify cache hit metrics
	stats := engine.cache.GetStats()
	if stats.Hits < 1 {
		t.Error("Expected at least one cache hit")
	}
}

// BenchmarkCorrelationParsing benchmarks correlation parsing overhead.
func BenchmarkCorrelationParsing(b *testing.B) {
	benchmarks := []struct {
		name      string
		sigmaYAML string
	}{
		{
			name: "DetectionOnly",
			sigmaYAML: `
title: Detection Only Rule
detection:
  selection:
    event_id: 4625
  condition: selection
`,
		},
		{
			name: "WithEventCount",
			sigmaYAML: `
title: Rule With Event Count
detection:
  selection:
    event_id: 4625
  condition: selection
correlation:
  type: event_count
  group_by:
    - source_ip
    - username
  timespan: 5m
  condition:
    operator: ">="
    value: 5
`,
		},
		{
			name: "WithChain",
			sigmaYAML: `
title: Rule With Chain
detection:
  selection:
    event_type: security
  condition: selection
correlation:
  type: chain
  stages:
    - name: reconnaissance
      detection_ref: rule_recon_001
      timeout: 1h
    - name: exploitation
      detection_ref: rule_exploit_001
      timeout: 30m
    - name: exfiltration
      detection_ref: rule_exfil_001
      timeout: 15m
  min_stages: 2
  max_duration: 24h
`,
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			engine := NewSigmaEngine(context.Background(), nil, testLogger())
			engine.Start()
			defer engine.Stop()

			rule := &core.Rule{
				ID:        "bench-rule-" + bm.name,
				Type:      "sigma",
				SigmaYAML: bm.sigmaYAML,
			}

			// Clear cache before benchmark
			engine.InvalidateAllCache()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Invalidate cache each iteration to measure parsing overhead
				engine.InvalidateCache(rule.ID)

				_, err := engine.getCachedRule(rule)
				if err != nil {
					b.Fatalf("Failed to parse rule: %v", err)
				}
			}
		})
	}
}

// BenchmarkCorrelationCacheHit benchmarks cache hit performance for correlation rules.
func BenchmarkCorrelationCacheHit(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	sigmaYAML := `
title: Cached Correlation Rule
detection:
  selection:
    event_id: 4625
  condition: selection
correlation:
  type: value_count
  group_by:
    - source_ip
  distinct_field: username
  timespan: 10m
  condition:
    operator: ">"
    value: 10
`

	rule := &core.Rule{
		ID:        "bench-cached-rule",
		Type:      "sigma",
		SigmaYAML: sigmaYAML,
	}

	// Prime the cache
	_, err := engine.getCachedRule(rule)
	if err != nil {
		b.Fatalf("Failed to prime cache: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.getCachedRule(rule)
		if err != nil {
			b.Fatalf("Failed to get cached rule: %v", err)
		}
	}
}

// BenchmarkInvalidateCorrelationRules benchmarks correlation-aware invalidation.
func BenchmarkInvalidateCorrelationRules(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, testLogger())
	engine.Start()
	defer engine.Stop()

	// Populate cache with mix of rules
	for i := 0; i < 50; i++ {
		hasCorrelation := i%2 == 0 // 50% with correlation

		sigmaYAML := `
title: Test Rule
detection:
  selection:
    event_id: 4625
  condition: selection
`
		if hasCorrelation {
			sigmaYAML += `
correlation:
  type: event_count
  timespan: 5m
  condition:
    operator: ">="
    value: 5
`
		}

		rule := &core.Rule{
			ID:        fmt.Sprintf("bench-rule-%d", i),
			Type:      "sigma",
			SigmaYAML: sigmaYAML,
		}

		_, err := engine.getCachedRule(rule)
		if err != nil {
			b.Fatalf("Failed to cache rule: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.InvalidateCorrelationRules()

		// Repopulate for next iteration
		b.StopTimer()
		for j := 0; j < 25; j++ {
			rule := &core.Rule{
				ID:   fmt.Sprintf("bench-rule-%d", j*2),
				Type: "sigma",
				SigmaYAML: `
title: Test Rule
detection:
  selection:
    event_id: 4625
  condition: selection
correlation:
  type: event_count
  timespan: 5m
  condition:
    operator: ">="
    value: 5
`,
			}
			engine.getCachedRule(rule)
		}
		b.StartTimer()
	}
}
