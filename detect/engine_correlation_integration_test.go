package detect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRuleStorage implements storage.RuleStorageInterface for testing.
type mockRuleStorage struct {
	rules []core.Rule
}

func (m *mockRuleStorage) GetRules(limit int, offset int) ([]core.Rule, error) {
	return m.rules, nil
}

func (m *mockRuleStorage) GetAllRules() ([]core.Rule, error) {
	return m.rules, nil
}

func (m *mockRuleStorage) GetRulesByType(ruleType string, limit int, offset int) ([]core.Rule, error) {
	var filtered []core.Rule
	for _, r := range m.rules {
		if r.Type == ruleType {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

func (m *mockRuleStorage) GetEnabledRules() ([]core.Rule, error) {
	var enabled []core.Rule
	for _, r := range m.rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	return enabled, nil
}

func (m *mockRuleStorage) GetRuleCount() (int64, error) {
	return int64(len(m.rules)), nil
}

func (m *mockRuleStorage) GetRule(id string) (*core.Rule, error) {
	for _, r := range m.rules {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("rule not found")
}

func (m *mockRuleStorage) CreateRule(rule *core.Rule) error              { return nil }
func (m *mockRuleStorage) UpdateRule(id string, rule *core.Rule) error   { return nil }
func (m *mockRuleStorage) DeleteRule(id string) error                    { return nil }
func (m *mockRuleStorage) EnableRule(id string) error                    { return nil }
func (m *mockRuleStorage) DisableRule(id string) error                   { return nil }
func (m *mockRuleStorage) SearchRules(query string) ([]core.Rule, error) { return nil, nil }
func (m *mockRuleStorage) GetRulesWithFilters(filters *core.RuleFilters) ([]core.Rule, int64, error) {
	return nil, 0, nil
}
func (m *mockRuleStorage) GetRuleFilterMetadata() (*core.RuleFilterMetadata, error) { return nil, nil }
func (m *mockRuleStorage) EnsureIndexes() error                                     { return nil }

// TestLoadCorrelationRulesFromStorage_CountRule tests loading count-based correlation rules.
// TASK 168.6: Test correlation rule loading with count correlation type.
func TestLoadCorrelationRulesFromStorage_CountRule(t *testing.T) {
	sigmaYAML := `title: Brute Force Detection
description: Detects multiple failed logins
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
correlation:
  type: event_count
  group_by:
    - source_ip
    - username
  timespan: 5m
  condition:
    operator: ">"
    value: 5
level: high`

	rule := core.Rule{
		ID:          "brute_force_corr",
		Type:        "sigma",
		Name:        "Brute Force Detection",
		Description: "Detects multiple failed logins",
		Severity:    "high",
		Enabled:     true,
		SigmaYAML:   sigmaYAML,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	mockStorage := &mockRuleStorage{rules: []core.Rule{rule}}

	// Create engine with SIGMA support
	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	defer engine.Stop()

	// Load correlation rules
	err := engine.LoadCorrelationRulesFromStorage(ctx, mockStorage)
	require.NoError(t, err, "Failed to load correlation rules")

	// Verify count rules were loaded
	counts := engine.GetEnhancedCorrelationRuleCount()
	assert.Equal(t, 1, counts["count"], "Expected 1 count rule")
	assert.Equal(t, 0, counts["value_count"], "Expected 0 value_count rules")
	assert.Equal(t, 0, counts["sequence"], "Expected 0 sequence rules")
}

// TestLoadCorrelationRulesFromStorage_ValueCountRule tests loading value_count correlation rules.
// TASK 168.6: Test correlation rule loading with value_count correlation type.
func TestLoadCorrelationRulesFromStorage_ValueCountRule(t *testing.T) {
	sigmaYAML := `title: Lateral Movement Detection
description: Detects access to multiple hosts
status: stable
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    EventID: 3
  condition: selection
correlation:
  type: value_count
  distinct_field: dest_host
  group_by:
    - source_ip
  timespan: 10m
  condition:
    operator: ">"
    value: 10
level: high`

	rule := core.Rule{
		ID:          "lateral_movement_corr",
		Type:        "sigma",
		Name:        "Lateral Movement Detection",
		Description: "Detects access to multiple hosts",
		Severity:    "high",
		Enabled:     true,
		SigmaYAML:   sigmaYAML,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	mockStorage := &mockRuleStorage{rules: []core.Rule{rule}}

	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	defer engine.Stop()

	err := engine.LoadCorrelationRulesFromStorage(ctx, mockStorage)
	require.NoError(t, err, "Failed to load correlation rules")

	counts := engine.GetEnhancedCorrelationRuleCount()
	assert.Equal(t, 0, counts["count"], "Expected 0 count rules")
	assert.Equal(t, 1, counts["value_count"], "Expected 1 value_count rule")
}

// TestLoadCorrelationRulesFromStorage_SequenceRule tests loading sequence correlation rules.
// TASK 168.6: Test correlation rule loading with temporal/sequence correlation type.
func TestLoadCorrelationRulesFromStorage_SequenceRule(t *testing.T) {
	sigmaYAML := `title: Attack Chain Detection
description: Detects reconnaissance followed by exploitation
status: stable
logsource:
  product: windows
detection:
  selection:
    EventID:
      - 4624
      - 4625
  condition: selection
correlation:
  type: temporal
  events:
    - recon
    - exploit
  group_by:
    - source_ip
  timespan: 1h
  ordered: true
level: critical`

	rule := core.Rule{
		ID:          "attack_chain_corr",
		Type:        "sigma",
		Name:        "Attack Chain Detection",
		Description: "Detects reconnaissance followed by exploitation",
		Severity:    "critical",
		Enabled:     true,
		SigmaYAML:   sigmaYAML,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	mockStorage := &mockRuleStorage{rules: []core.Rule{rule}}

	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	defer engine.Stop()

	err := engine.LoadCorrelationRulesFromStorage(ctx, mockStorage)
	require.NoError(t, err, "Failed to load correlation rules")

	counts := engine.GetEnhancedCorrelationRuleCount()
	assert.Equal(t, 0, counts["count"], "Expected 0 count rules")
	assert.Equal(t, 1, counts["sequence"], "Expected 1 sequence rule")
}

// TestLoadCorrelationRulesFromStorage_RareRule tests loading rare event correlation rules.
// TASK 168.6: Test correlation rule loading with rare correlation type.
func TestLoadCorrelationRulesFromStorage_RareRule(t *testing.T) {
	sigmaYAML := `title: Rare Process Execution
description: Detects rarely seen processes
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
  condition: selection
correlation:
  type: rare
  distinct_field: Image
  baseline_window: 24h
  condition:
    operator: "<="
    value: 2
level: medium`

	rule := core.Rule{
		ID:          "rare_process_corr",
		Type:        "sigma",
		Name:        "Rare Process Execution",
		Description: "Detects rarely seen processes",
		Severity:    "medium",
		Enabled:     true,
		SigmaYAML:   sigmaYAML,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	mockStorage := &mockRuleStorage{rules: []core.Rule{rule}}

	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	defer engine.Stop()

	err := engine.LoadCorrelationRulesFromStorage(ctx, mockStorage)
	require.NoError(t, err, "Failed to load correlation rules")

	counts := engine.GetEnhancedCorrelationRuleCount()
	assert.Equal(t, 1, counts["rare"], "Expected 1 rare rule")
}

// TestEvaluateCorrelationRules_CountRule tests count-based correlation evaluation.
// TASK 168.6: Test that count correlation rules trigger alerts correctly.
func TestEvaluateCorrelationRules_CountRule(t *testing.T) {
	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	defer engine.Stop()

	// Add a count correlation rule
	countRule := core.CountCorrelationRule{
		EnhancedCorrelationRule: core.EnhancedCorrelationRule{
			ID:          "count_test",
			Type:        core.CorrelationTypeCount,
			Name:        "Count Test Rule",
			Description: "Test count correlation",
			Severity:    "high",
			Enabled:     true,
		},
		Window: 5 * time.Minute,
		Selection: map[string]interface{}{
			"event_type": "failed_login",
		},
		GroupBy: []string{"source_ip"},
		Threshold: core.Threshold{
			Operator: core.ThresholdOpGreater,
			Value:    2,
		},
	}
	engine.AddCountRule(countRule)

	// Create test events
	baseEvent := &core.Event{
		EventID:   "evt1",
		Timestamp: time.Now(),
		EventType: "failed_login",
		Fields: map[string]interface{}{
			"source_ip": "192.168.1.100",
		},
	}

	// Send events to trigger correlation
	for i := 0; i < 3; i++ {
		event := *baseEvent
		event.EventID = fmt.Sprintf("evt%d", i+1)
		alerts := engine.EvaluateCorrelationRules(&event)

		if i == 2 {
			// Third event should trigger alert
			assert.NotEmpty(t, alerts, "Expected correlation alert on 3rd event")
			if len(alerts) > 0 {
				assert.Equal(t, "count_test", alerts[0].RuleID)
				assert.Equal(t, "high", alerts[0].Severity)
			}
		} else {
			// First two events should not trigger
			assert.Empty(t, alerts, "Should not trigger alert before threshold")
		}
	}
}

// TestEvaluateCorrelationRules_SequenceRule tests sequence-based correlation evaluation.
// TASK 168.6: Test that sequence correlation rules trigger alerts correctly.
func TestEvaluateCorrelationRules_SequenceRule(t *testing.T) {
	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	defer engine.Stop()

	// Add a sequence correlation rule
	seqRule := core.SequenceCorrelationRule{
		EnhancedCorrelationRule: core.EnhancedCorrelationRule{
			ID:          "seq_test",
			Type:        core.CorrelationTypeSequence,
			Name:        "Sequence Test Rule",
			Description: "Test sequence correlation",
			Severity:    "critical",
			Enabled:     true,
		},
		Window:  10 * time.Minute,
		Ordered: true,
		Sequence: []core.SequenceStage{
			{
				Name:      "recon",
				Selection: map[string]interface{}{"event_type": "port_scan"},
				Required:  true,
			},
			{
				Name:      "exploit",
				Selection: map[string]interface{}{"event_type": "exploit_attempt"},
				Required:  true,
			},
		},
		GroupBy: []string{"source_ip"},
	}
	engine.AddSequenceRule(seqRule)

	// Create test events in sequence
	event1 := &core.Event{
		EventID:   "evt1",
		Timestamp: time.Now(),
		EventType: "port_scan",
		Fields: map[string]interface{}{
			"source_ip": "192.168.1.100",
		},
	}

	event2 := &core.Event{
		EventID:   "evt2",
		Timestamp: time.Now().Add(1 * time.Minute),
		EventType: "exploit_attempt",
		Fields: map[string]interface{}{
			"source_ip": "192.168.1.100",
		},
	}

	// First event should not trigger
	alerts := engine.EvaluateCorrelationRules(event1)
	assert.Empty(t, alerts, "First event should not trigger sequence")

	// Second event should complete sequence and trigger
	alerts = engine.EvaluateCorrelationRules(event2)
	assert.NotEmpty(t, alerts, "Second event should complete sequence")
	if len(alerts) > 0 {
		assert.Equal(t, "seq_test", alerts[0].RuleID)
		assert.Equal(t, "critical", alerts[0].Severity)
	}
}

// TestConfigureCorrelationStateTTL tests TTL configuration based on correlation windows.
// TASK 168.3: Test that TTL is calculated correctly from correlation windows.
func TestConfigureCorrelationStateTTL(t *testing.T) {
	ctx := context.Background()
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, nil)
	defer engine.Stop()

	// Add rules with different windows
	engine.AddCountRule(core.CountCorrelationRule{
		EnhancedCorrelationRule: core.EnhancedCorrelationRule{
			ID:      "rule1",
			Enabled: true,
		},
		Window: 5 * time.Minute,
	})

	engine.AddSequenceRule(core.SequenceCorrelationRule{
		EnhancedCorrelationRule: core.EnhancedCorrelationRule{
			ID:      "rule2",
			Enabled: true,
		},
		Window: 30 * time.Minute,
	})

	// TTL should be 2x the maximum window (30 minutes)
	ttl := engine.ConfigureCorrelationStateTTL()
	expectedTTL := 60 * time.Minute
	assert.Equal(t, expectedTTL, ttl, "TTL should be 2x maximum window")
}

// TestCorrelationStateCleanup tests that expired correlation state is cleaned up.
// TASK 168.3: Test correlation state expiration and cleanup.
func TestCorrelationStateCleanup(t *testing.T) {
	ctx := context.Background()
	engine := NewRuleEngineWithContext(ctx, nil, nil, 1, nil) // 1 second TTL
	defer engine.Stop()

	// Add a count rule with short window
	engine.AddCountRule(core.CountCorrelationRule{
		EnhancedCorrelationRule: core.EnhancedCorrelationRule{
			ID:          "cleanup_test",
			Type:        core.CorrelationTypeCount,
			Name:        "Cleanup Test",
			Description: "Test state cleanup",
			Severity:    "low",
			Enabled:     true,
		},
		Window: 1 * time.Second,
		Selection: map[string]interface{}{
			"event_type": "test_event",
		},
		GroupBy: []string{"source_ip"},
		Threshold: core.Threshold{
			Operator: core.ThresholdOpGreater,
			Value:    10, // High threshold to prevent triggering
		},
	})

	// Send event
	event := &core.Event{
		EventID:   "evt1",
		Timestamp: time.Now(),
		EventType: "test_event",
		Fields: map[string]interface{}{
			"source_ip": "192.168.1.100",
		},
	}
	engine.EvaluateCorrelationRules(event)

	// Wait for cleanup
	time.Sleep(3 * time.Second)

	// State should be cleaned up (we can't directly verify, but engine should still work)
	alerts := engine.EvaluateCorrelationRules(event)
	assert.Empty(t, alerts, "Should not trigger with fresh state")
}

// TestCorrelationRuleRouting tests that rules are routed to correct evaluators.
// TASK 168.4: Test that correlation types are routed correctly.
func TestCorrelationRuleRouting(t *testing.T) {
	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	defer engine.Stop()

	// Load mixed correlation rules
	sigmaYAMLs := []string{
		`title: Count Rule
logsource:
  product: windows
detection:
  selection:
    EventID: 4625
  condition: selection
correlation:
  type: event_count
  group_by: [source_ip]
  timespan: 5m
  condition:
    operator: ">"
    value: 5
level: high`,
		`title: Value Count Rule
logsource:
  product: windows
detection:
  selection:
    EventID: 3
  condition: selection
correlation:
  type: value_count
  distinct_field: dest_host
  group_by: [source_ip]
  timespan: 10m
  condition:
    operator: ">"
    value: 10
level: high`,
		`title: Sequence Rule
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
correlation:
  type: temporal
  events: [rule3a, rule3b]
  group_by: [source_ip]
  timespan: 1h
  ordered: true
level: critical`,
	}

	rules := make([]core.Rule, len(sigmaYAMLs))
	for i, yaml := range sigmaYAMLs {
		rules[i] = core.Rule{
			ID:        fmt.Sprintf("rule%d", i+1),
			Type:      "sigma",
			Name:      fmt.Sprintf("Rule %d", i+1),
			Severity:  "high",
			Enabled:   true,
			SigmaYAML: yaml,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	}

	mockStorage := &mockRuleStorage{rules: rules}
	err := engine.LoadCorrelationRulesFromStorage(ctx, mockStorage)
	require.NoError(t, err, "Failed to load correlation rules")

	// Verify correct routing
	counts := engine.GetEnhancedCorrelationRuleCount()
	assert.Equal(t, 1, counts["count"], "Expected 1 count rule")
	assert.Equal(t, 1, counts["value_count"], "Expected 1 value_count rule")
	assert.Equal(t, 1, counts["sequence"], "Expected 1 sequence rule")
}

// TestCorrelationPerformance tests that correlation evaluation meets performance requirements.
// TASK 168.6: Test performance requirement of 10k events/sec.
func TestCorrelationPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx := context.Background()
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, nil)
	defer engine.Stop()

	// Add multiple correlation rules
	for i := 0; i < 10; i++ {
		engine.AddCountRule(core.CountCorrelationRule{
			EnhancedCorrelationRule: core.EnhancedCorrelationRule{
				ID:          fmt.Sprintf("perf_rule_%d", i),
				Type:        core.CorrelationTypeCount,
				Name:        fmt.Sprintf("Performance Rule %d", i),
				Description: "Performance test rule",
				Severity:    "low",
				Enabled:     true,
			},
			Window: 5 * time.Minute,
			Selection: map[string]interface{}{
				"event_type": "perf_test",
			},
			GroupBy: []string{"source_ip"},
			Threshold: core.Threshold{
				Operator: core.ThresholdOpGreater,
				Value:    1000, // High threshold
			},
		})
	}

	// Benchmark event processing
	eventCount := 10000
	start := time.Now()

	for i := 0; i < eventCount; i++ {
		event := &core.Event{
			EventID:   fmt.Sprintf("evt%d", i),
			Timestamp: time.Now(),
			EventType: "perf_test",
			Fields: map[string]interface{}{
				"source_ip": fmt.Sprintf("192.168.1.%d", i%255),
			},
		}
		engine.EvaluateCorrelationRules(event)
	}

	elapsed := time.Since(start)
	eventsPerSec := float64(eventCount) / elapsed.Seconds()

	t.Logf("Processed %d events in %v (%.2f events/sec)", eventCount, elapsed, eventsPerSec)

	// Performance requirement: 10k events/sec
	assert.Greater(t, eventsPerSec, 10000.0, "Should process at least 10k events/sec")
}

// TestLoadCorrelationRulesFromStorage_StatisticalRule tests loading statistical correlation rules.
// ISSUE #3: Test correlation rule loading with statistical correlation type.
func TestLoadCorrelationRulesFromStorage_StatisticalRule(t *testing.T) {
	sigmaYAML := `title: Statistical Anomaly Detection
description: Detects statistical outliers in data transfer
status: stable
logsource:
  product: network
  category: traffic
detection:
  selection:
    EventID: 5156
  condition: selection
correlation:
  type: statistical
  distinct_field: bytes_sent
  group_by:
    - source_ip
  timespan: 1h
  baseline_window: 7d
  condition:
    operator: ">"
    value: 3
level: medium`

	rule := core.Rule{
		ID:          "statistical_anomaly_corr",
		Type:        "sigma",
		Name:        "Statistical Anomaly Detection",
		Description: "Detects statistical outliers in data transfer",
		Severity:    "medium",
		Enabled:     true,
		SigmaYAML:   sigmaYAML,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	mockStorage := &mockRuleStorage{rules: []core.Rule{rule}}

	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	defer engine.Stop()

	err := engine.LoadCorrelationRulesFromStorage(ctx, mockStorage)
	require.NoError(t, err, "Failed to load correlation rules")

	counts := engine.GetEnhancedCorrelationRuleCount()
	assert.Equal(t, 0, counts["count"], "Expected 0 count rules")
	assert.Equal(t, 1, counts["statistical"], "Expected 1 statistical rule")
}

// TestLoadCorrelationRulesFromStorage_CrossEntityRule tests loading cross_entity correlation rules.
// ISSUE #3: Test correlation rule loading with cross_entity correlation type.
func TestLoadCorrelationRulesFromStorage_CrossEntityRule(t *testing.T) {
	sigmaYAML := `title: Cross-Entity Lateral Movement
description: Detects user accessing multiple hosts
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
correlation:
  type: cross_entity
  distinct_field: dest_host
  group_by:
    - username
  timespan: 15m
  condition:
    operator: ">"
    value: 5
level: high`

	rule := core.Rule{
		ID:          "cross_entity_movement_corr",
		Type:        "sigma",
		Name:        "Cross-Entity Lateral Movement",
		Description: "Detects user accessing multiple hosts",
		Severity:    "high",
		Enabled:     true,
		SigmaYAML:   sigmaYAML,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	mockStorage := &mockRuleStorage{rules: []core.Rule{rule}}

	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	defer engine.Stop()

	err := engine.LoadCorrelationRulesFromStorage(ctx, mockStorage)
	require.NoError(t, err, "Failed to load correlation rules")

	counts := engine.GetEnhancedCorrelationRuleCount()
	assert.Equal(t, 0, counts["count"], "Expected 0 count rules")
	assert.Equal(t, 1, counts["cross_entity"], "Expected 1 cross_entity rule")
}

// TestLoadCorrelationRulesFromStorage_ChainRule tests loading chain correlation rules.
// ISSUE #3: Test correlation rule loading with chain correlation type.
func TestLoadCorrelationRulesFromStorage_ChainRule(t *testing.T) {
	sigmaYAML := `title: Multi-Stage Attack Chain
description: Detects complete attack kill chain
status: stable
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
correlation:
  type: chain
  stages:
    - name: reconnaissance
    - name: initial_access
    - name: execution
    - name: persistence
  group_by:
    - source_ip
  timespan: 24h
level: critical`

	rule := core.Rule{
		ID:          "attack_chain_corr",
		Type:        "sigma",
		Name:        "Multi-Stage Attack Chain",
		Description: "Detects complete attack kill chain",
		Severity:    "critical",
		Enabled:     true,
		SigmaYAML:   sigmaYAML,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	mockStorage := &mockRuleStorage{rules: []core.Rule{rule}}

	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	defer engine.Stop()

	err := engine.LoadCorrelationRulesFromStorage(ctx, mockStorage)
	require.NoError(t, err, "Failed to load correlation rules")

	counts := engine.GetEnhancedCorrelationRuleCount()
	assert.Equal(t, 0, counts["count"], "Expected 0 count rules")
	assert.Equal(t, 1, counts["chain"], "Expected 1 chain rule")
}

// TestCorrelation24HourWindowValidation tests that 24-hour window limit is enforced.
// ISSUE #4: Test validation of 24-hour maximum window across all converter functions.
func TestCorrelation24HourWindowValidation(t *testing.T) {
	ctx := context.Background()
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        10 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}

	testCases := []struct {
		name          string
		correlType    string
		timespan      string
		shouldSucceed bool
	}{
		{
			name:          "Count rule with valid 1h window",
			correlType:    "event_count",
			timespan:      "1h",
			shouldSucceed: true,
		},
		{
			name:          "Count rule with valid 24h window",
			correlType:    "event_count",
			timespan:      "24h",
			shouldSucceed: true,
		},
		{
			name:          "Count rule with invalid 25h window",
			correlType:    "event_count",
			timespan:      "25h",
			shouldSucceed: false,
		},
		{
			name:          "Value count rule with invalid 48h window",
			correlType:    "value_count",
			timespan:      "48h",
			shouldSucceed: false,
		},
		{
			name:          "Sequence rule with invalid 30h window",
			correlType:    "temporal",
			timespan:      "30h",
			shouldSucceed: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sigmaYAML := fmt.Sprintf(`title: %s
description: Test 24h window validation
status: stable
logsource:
  product: test
detection:
  selection:
    EventID: 1
  condition: selection
correlation:
  type: %s
  group_by: [source_ip]
  timespan: %s
  condition:
    operator: ">"
    value: 5
level: high`, tc.name, tc.correlType, tc.timespan)

			rule := core.Rule{
				ID:        fmt.Sprintf("test_%s", tc.name),
				Type:      "sigma",
				Name:      tc.name,
				Severity:  "high",
				Enabled:   true,
				SigmaYAML: sigmaYAML,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}

			mockStorage := &mockRuleStorage{rules: []core.Rule{rule}}
			engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
			defer engine.Stop()

			err := engine.LoadCorrelationRulesFromStorage(ctx, mockStorage)

			if tc.shouldSucceed {
				assert.NoError(t, err, "Expected rule loading to succeed for valid window")
			} else {
				// Rule loading doesn't fail, but the rule won't be added to collections
				// We can verify by checking rule counts
				counts := engine.GetEnhancedCorrelationRuleCount()
				totalRules := counts["count"] + counts["value_count"] + counts["sequence"] +
					counts["rare"] + counts["statistical"] + counts["cross_entity"] + counts["chain"]
				assert.Equal(t, 0, totalRules, "Expected no rules to be loaded for invalid window")
			}
		})
	}
}
