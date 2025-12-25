package detect

import (
	"testing"
	"time"

	"cerberus/core"
)

func TestMatchesLogsource(t *testing.T) {
	engine := NewSigmaEngine(nil, nil, nil)

	tests := []struct {
		name      string
		logsource map[string]interface{}
		event     *core.Event
		expected  bool
	}{
		{
			name:      "empty logsource matches all events",
			logsource: nil,
			event: &core.Event{
				EventType: "process_creation",
			},
			expected: true,
		},
		{
			name:      "empty logsource map matches all events",
			logsource: map[string]interface{}{},
			event: &core.Event{
				EventType: "process_creation",
			},
			expected: true,
		},
		{
			name: "category matches event type",
			logsource: map[string]interface{}{
				"category": "process_creation",
			},
			event: &core.Event{
				EventType: "process_creation",
			},
			expected: true,
		},
		{
			name: "category mismatch - zeek rdp rule vs process_creation event",
			logsource: map[string]interface{}{
				"product": "zeek",
				"service": "rdp",
			},
			event: &core.Event{
				EventType:    "process_creation",
				SourceFormat: "json",
				Fields: map[string]interface{}{
					"Image": "cmd.exe",
				},
			},
			expected: false, // Event has no zeek product or rdp service
		},
		{
			name: "product and service match",
			logsource: map[string]interface{}{
				"product": "zeek",
				"service": "rdp",
			},
			event: &core.Event{
				EventType:    "network_connection",
				SourceFormat: "json",
				Fields: map[string]interface{}{
					"product": "zeek",
					"service": "rdp",
				},
			},
			expected: true,
		},
		{
			name: "product matches but service doesn't",
			logsource: map[string]interface{}{
				"product": "zeek",
				"service": "rdp",
			},
			event: &core.Event{
				EventType:    "network_connection",
				SourceFormat: "json",
				Fields: map[string]interface{}{
					"product": "zeek",
					"service": "dns",
				},
			},
			expected: false,
		},
		{
			name: "windows sysmon process creation",
			logsource: map[string]interface{}{
				"product":  "windows",
				"category": "process_creation",
				"service":  "sysmon",
			},
			event: &core.Event{
				EventType:    "process_creation",
				SourceFormat: "json",
				Fields: map[string]interface{}{
					"product": "windows",
					"service": "sysmon",
				},
			},
			expected: true,
		},
		{
			name: "windows process creation - different service",
			logsource: map[string]interface{}{
				"product":  "windows",
				"category": "process_creation",
				"service":  "sysmon",
			},
			event: &core.Event{
				EventType:    "process_creation",
				SourceFormat: "json",
				Fields: map[string]interface{}{
					"product": "windows",
					// No service field
				},
			},
			expected: false, // service doesn't match
		},
		{
			name: "authentication event matches auth category alias",
			logsource: map[string]interface{}{
				"category": "authentication",
			},
			event: &core.Event{
				EventType: "auth",
			},
			expected: true, // "auth" is an alias for "authentication"
		},
		{
			name: "linux authentication event",
			logsource: map[string]interface{}{
				"product":  "linux",
				"category": "authentication",
			},
			event: &core.Event{
				EventType:    "authentication",
				SourceFormat: "json",
				Fields: map[string]interface{}{
					"product": "linux",
				},
			},
			expected: true,
		},
		{
			name: "case insensitive matching",
			logsource: map[string]interface{}{
				"product": "WINDOWS",
			},
			event: &core.Event{
				Fields: map[string]interface{}{
					"product": "windows",
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.matchesLogsource(tt.logsource, tt.event)
			if result != tt.expected {
				t.Errorf("matchesLogsource() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestLogsourceFilteringIntegration tests the full evaluation flow with logsource filtering
func TestLogsourceFilteringIntegration(t *testing.T) {
	engine := NewSigmaEngine(nil, nil, nil)
	engine.Start()
	defer engine.Stop()

	// Create a rule that should only match Zeek RDP events
	zeekRDPRule := &core.Rule{
		ID:      "zeek-rdp-test",
		Name:    "Test Zeek RDP Rule",
		Type:    "sigma",
		Enabled: true,
		SigmaYAML: `
title: Test Zeek RDP Detection
logsource:
    product: zeek
    service: rdp
detection:
    selection:
        id.resp_p: 3389
    condition: selection
`,
	}

	// Event 1: Should NOT match - wrong product/service
	processEvent := &core.Event{
		EventID:      "evt-1",
		Timestamp:    time.Now(),
		EventType:    "process_creation",
		SourceFormat: "json",
		Fields: map[string]interface{}{
			"Image":       "cmd.exe",
			"CommandLine": "whoami",
		},
	}

	// Event 2: Should match - correct product/service
	zeekRDPEvent := &core.Event{
		EventID:      "evt-2",
		Timestamp:    time.Now(),
		EventType:    "network_connection",
		SourceFormat: "json",
		Fields: map[string]interface{}{
			"product":   "zeek",
			"service":   "rdp",
			"id.resp_p": 3389,
		},
	}

	// Test: Process event should NOT match zeek RDP rule
	match1, err := engine.Evaluate(zeekRDPRule, processEvent)
	if err != nil {
		t.Errorf("Evaluate() error = %v", err)
	}
	if match1 {
		t.Errorf("Process event should NOT match Zeek RDP rule (logsource mismatch)")
	}

	// Test: Zeek RDP event SHOULD match zeek RDP rule
	match2, err := engine.Evaluate(zeekRDPRule, zeekRDPEvent)
	if err != nil {
		t.Errorf("Evaluate() error = %v", err)
	}
	if !match2 {
		t.Errorf("Zeek RDP event should match Zeek RDP rule")
	}
}

// TestLogsourceFilteringWithWindowsSysmon tests Windows Sysmon rule matching
func TestLogsourceFilteringWithWindowsSysmon(t *testing.T) {
	engine := NewSigmaEngine(nil, nil, nil)
	engine.Start()
	defer engine.Stop()

	// Create a Windows Sysmon process creation rule
	sysmonRule := &core.Rule{
		ID:      "sysmon-test",
		Name:    "Test Sysmon Rule",
		Type:    "sigma",
		Enabled: true,
		SigmaYAML: `
title: Suspicious Command Execution
logsource:
    product: windows
    category: process_creation
    service: sysmon
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
`,
	}

	// Event 1: Windows Sysmon event with cmd.exe - should match
	sysmonEvent := &core.Event{
		EventID:      "evt-1",
		Timestamp:    time.Now(),
		EventType:    "process_creation",
		SourceFormat: "json",
		Fields: map[string]interface{}{
			"product": "windows",
			"service": "sysmon",
			"Image":   `C:\Windows\System32\cmd.exe`,
		},
	}

	// Event 2: Linux event - should NOT match (wrong product)
	linuxEvent := &core.Event{
		EventID:      "evt-2",
		Timestamp:    time.Now(),
		EventType:    "process_creation",
		SourceFormat: "json",
		Fields: map[string]interface{}{
			"product": "linux",
			"Image":   "/bin/bash",
		},
	}

	// Event 3: Authentication event - should NOT match (wrong category)
	authEvent := &core.Event{
		EventID:      "evt-3",
		Timestamp:    time.Now(),
		EventType:    "authentication",
		SourceFormat: "json",
		Fields: map[string]interface{}{
			"product": "windows",
			"service": "sysmon",
			"user":    "admin",
		},
	}

	// Test: Sysmon event should match
	match1, err := engine.Evaluate(sysmonRule, sysmonEvent)
	if err != nil {
		t.Errorf("Evaluate() error = %v", err)
	}
	if !match1 {
		t.Errorf("Sysmon event should match Sysmon rule")
	}

	// Test: Linux event should NOT match
	match2, err := engine.Evaluate(sysmonRule, linuxEvent)
	if err != nil {
		t.Errorf("Evaluate() error = %v", err)
	}
	if match2 {
		t.Errorf("Linux event should NOT match Sysmon rule (product mismatch)")
	}

	// Test: Auth event should NOT match
	match3, err := engine.Evaluate(sysmonRule, authEvent)
	if err != nil {
		t.Errorf("Evaluate() error = %v", err)
	}
	if match3 {
		t.Errorf("Auth event should NOT match process_creation rule (category mismatch)")
	}
}
