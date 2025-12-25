package core

import (
	"strings"
	"testing"
)

// TestParsedSigmaRule_ValidYAML tests parsing of valid SIGMA YAML
func TestParsedSigmaRule_ValidYAML(t *testing.T) {
	rule := &Rule{
		ID:   "test-rule-1",
		Type: "sigma",
		SigmaYAML: `
title: Test SIGMA Rule
id: test-rule-1
description: A test rule
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4688
    CommandLine|contains: 'powershell'
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059.001
`,
	}

	parsed, err := rule.ParsedSigmaRule()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if parsed == nil {
		t.Fatal("expected parsed result, got nil")
	}

	// Verify title field
	title, ok := parsed["title"].(string)
	if !ok {
		t.Fatal("expected title to be string")
	}
	if title != "Test SIGMA Rule" {
		t.Errorf("expected title 'Test SIGMA Rule', got '%s'", title)
	}

	// Verify level field
	level, ok := parsed["level"].(string)
	if !ok {
		t.Fatal("expected level to be string")
	}
	if level != "medium" {
		t.Errorf("expected level 'medium', got '%s'", level)
	}

	// Verify detection exists
	_, ok = parsed["detection"]
	if !ok {
		t.Error("expected detection field to exist")
	}

	// Verify logsource exists
	_, ok = parsed["logsource"]
	if !ok {
		t.Error("expected logsource field to exist")
	}

	// Verify tags exists
	_, ok = parsed["tags"]
	if !ok {
		t.Error("expected tags field to exist")
	}
}

// TestParsedSigmaRule_EmptySigmaYAML tests error handling for empty sigma_yaml field
func TestParsedSigmaRule_EmptySigmaYAML(t *testing.T) {
	rule := &Rule{
		ID:        "test-rule-2",
		Type:      "sigma",
		SigmaYAML: "",
	}

	parsed, err := rule.ParsedSigmaRule()
	if err == nil {
		t.Fatal("expected error for empty sigma_yaml, got nil")
	}

	if parsed != nil {
		t.Errorf("expected nil parsed result, got %v", parsed)
	}

	expectedErrMsg := "sigma_yaml field is empty"
	if !strings.Contains(err.Error(), expectedErrMsg) {
		t.Errorf("expected error message to contain '%s', got '%s'", expectedErrMsg, err.Error())
	}
}

// TestParsedSigmaRule_InvalidYAMLSyntax tests error handling for invalid YAML syntax
func TestParsedSigmaRule_InvalidYAMLSyntax(t *testing.T) {
	testCases := []struct {
		name      string
		yamlInput string
	}{
		{
			name: "malformed YAML with tabs",
			yamlInput: `title: Test Rule
	invalid_tabs:
		nested: value`,
		},
		{
			name: "unclosed quotes",
			yamlInput: `title: "Test Rule
description: missing quote`,
		},
		{
			name: "invalid structure",
			yamlInput: `title: Test
[invalid bracket syntax
description: missing close`,
		},
		{
			name: "invalid indentation",
			yamlInput: `title: Test
  description: Bad indent
 level: medium`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := &Rule{
				ID:        "test-rule-invalid",
				Type:      "sigma",
				SigmaYAML: tc.yamlInput,
			}

			parsed, err := rule.ParsedSigmaRule()
			if err == nil {
				t.Fatal("expected error for invalid YAML syntax, got nil")
			}

			if parsed != nil {
				t.Errorf("expected nil parsed result, got %v", parsed)
			}

			expectedErrMsg := "failed to parse sigma_yaml"
			if !strings.Contains(err.Error(), expectedErrMsg) {
				t.Errorf("expected error message to contain '%s', got '%s'", expectedErrMsg, err.Error())
			}
		})
	}
}

// TestParsedSigmaRule_ComplexNestedDetection tests parsing of complex YAML with nested detection blocks
func TestParsedSigmaRule_ComplexNestedDetection(t *testing.T) {
	rule := &Rule{
		ID:   "test-rule-complex",
		Type: "sigma",
		SigmaYAML: `
title: Complex Detection Rule
id: complex-rule-1
status: test
logsource:
  category: network_connection
  product: windows
detection:
  selection1:
    EventID: 3
    DestinationPort:
      - 80
      - 443
      - 8080
  selection2:
    DestinationIp|startswith:
      - '10.'
      - '192.168.'
  filter:
    Image|endswith: '\chrome.exe'
  condition: (selection1 and selection2) and not filter
level: high
tags:
  - attack.command_and_control
  - attack.t1071.001
falsepositives:
  - Legitimate internal traffic
  - VPN connections
references:
  - https://example.com/reference1
  - https://example.com/reference2
`,
	}

	parsed, err := rule.ParsedSigmaRule()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify detection structure exists and is a map
	detection, ok := parsed["detection"].(map[string]interface{})
	if !ok {
		t.Fatal("expected detection to be a map")
	}

	// Verify nested selection1
	selection1, ok := detection["selection1"].(map[string]interface{})
	if !ok {
		t.Fatal("expected selection1 to be a map")
	}

	// Verify DestinationPort is a slice
	destPort, ok := selection1["DestinationPort"]
	if !ok {
		t.Fatal("expected DestinationPort to exist in selection1")
	}

	destPortSlice, ok := destPort.([]interface{})
	if !ok {
		t.Fatal("expected DestinationPort to be a slice")
	}

	if len(destPortSlice) != 3 {
		t.Errorf("expected 3 destination ports, got %d", len(destPortSlice))
	}

	// Verify condition exists
	condition, ok := detection["condition"].(string)
	if !ok {
		t.Fatal("expected condition to be a string")
	}

	if !strings.Contains(condition, "selection1") {
		t.Error("expected condition to reference selection1")
	}

	// Verify falsepositives array
	falsepositives, ok := parsed["falsepositives"].([]interface{})
	if !ok {
		t.Fatal("expected falsepositives to be a slice")
	}

	if len(falsepositives) != 2 {
		t.Errorf("expected 2 false positives, got %d", len(falsepositives))
	}

	// Verify references array
	references, ok := parsed["references"].([]interface{})
	if !ok {
		t.Fatal("expected references to be a slice")
	}

	if len(references) != 2 {
		t.Errorf("expected 2 references, got %d", len(references))
	}
}

// TestParsedSigmaRule_AllStandardFields tests parsing of YAML with all standard SIGMA fields
func TestParsedSigmaRule_AllStandardFields(t *testing.T) {
	rule := &Rule{
		ID:   "test-rule-standard",
		Type: "sigma",
		SigmaYAML: `
title: Complete SIGMA Rule Example
id: rule-standard-123
status: stable
description: A comprehensive SIGMA rule with all standard fields
author: Security Team
date: 2024-01-01
modified: 2024-01-15
logsource:
  category: process_creation
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: '\cmd.exe'
  condition: selection
level: critical
tags:
  - attack.execution
  - attack.t1059.003
falsepositives:
  - Administrative scripts
  - Legitimate batch processing
references:
  - https://attack.mitre.org/techniques/T1059/003/
fields:
  - CommandLine
  - ParentImage
  - User
`,
	}

	parsed, err := rule.ParsedSigmaRule()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify all standard fields exist
	requiredFields := []string{"title", "id", "status", "description", "author", "date", "modified", "logsource", "detection", "level", "tags"}
	for _, field := range requiredFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("expected field '%s' to exist", field)
		}
	}

	// Verify title
	title, ok := parsed["title"].(string)
	if !ok || title != "Complete SIGMA Rule Example" {
		t.Errorf("expected title 'Complete SIGMA Rule Example', got '%v'", parsed["title"])
	}

	// Verify logsource structure
	logsource, ok := parsed["logsource"].(map[string]interface{})
	if !ok {
		t.Fatal("expected logsource to be a map")
	}

	if logsource["category"] != "process_creation" {
		t.Errorf("expected logsource category 'process_creation', got '%v'", logsource["category"])
	}

	if logsource["product"] != "windows" {
		t.Errorf("expected logsource product 'windows', got '%v'", logsource["product"])
	}

	if logsource["service"] != "sysmon" {
		t.Errorf("expected logsource service 'sysmon', got '%v'", logsource["service"])
	}

	// Verify detection structure
	detection, ok := parsed["detection"].(map[string]interface{})
	if !ok {
		t.Fatal("expected detection to be a map")
	}

	if _, ok := detection["selection"]; !ok {
		t.Error("expected detection to have selection")
	}

	if _, ok := detection["condition"]; !ok {
		t.Error("expected detection to have condition")
	}

	// Verify level
	level, ok := parsed["level"].(string)
	if !ok || level != "critical" {
		t.Errorf("expected level 'critical', got '%v'", parsed["level"])
	}

	// Verify tags array
	tags, ok := parsed["tags"].([]interface{})
	if !ok {
		t.Fatal("expected tags to be a slice")
	}

	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}

	// Verify fields array
	fields, ok := parsed["fields"].([]interface{})
	if !ok {
		t.Fatal("expected fields to be a slice")
	}

	if len(fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(fields))
	}
}

// TestParsedSigmaRule_NilReceiver tests graceful handling of nil receiver
func TestParsedSigmaRule_NilReceiver(t *testing.T) {
	var rule *Rule // nil pointer

	parsed, err := rule.ParsedSigmaRule()
	if err == nil {
		t.Fatal("expected error for nil receiver, got nil")
	}

	if parsed != nil {
		t.Errorf("expected nil parsed result, got %v", parsed)
	}

	expectedErrMsg := "cannot parse SIGMA YAML from nil rule"
	if !strings.Contains(err.Error(), expectedErrMsg) {
		t.Errorf("expected error message to contain '%s', got '%s'", expectedErrMsg, err.Error())
	}
}

// TestParsedSigmaRule_WhitespaceOnly tests handling of whitespace-only sigma_yaml
func TestParsedSigmaRule_WhitespaceOnly(t *testing.T) {
	testCases := []struct {
		name      string
		yamlInput string
	}{
		{
			name:      "spaces only",
			yamlInput: "     ",
		},
		{
			name:      "tabs only",
			yamlInput: "\t\t\t",
		},
		{
			name:      "newlines only",
			yamlInput: "\n\n\n",
		},
		{
			name:      "mixed whitespace",
			yamlInput: "  \t\n  \t\n  ",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := &Rule{
				ID:        "test-rule-whitespace",
				Type:      "sigma",
				SigmaYAML: tc.yamlInput,
			}

			parsed, err := rule.ParsedSigmaRule()
			if err == nil {
				t.Fatal("expected error for whitespace-only sigma_yaml, got nil")
			}

			if parsed != nil {
				t.Errorf("expected nil parsed result, got %v", parsed)
			}

			expectedErrMsg := "sigma_yaml field is empty"
			if !strings.Contains(err.Error(), expectedErrMsg) {
				t.Errorf("expected error message to contain '%s', got '%s'", expectedErrMsg, err.Error())
			}
		})
	}
}

// TestParsedSigmaRule_RoundTrip tests parsing and then accessing specific fields
func TestParsedSigmaRule_RoundTrip(t *testing.T) {
	originalYAML := `
title: Round Trip Test
id: roundtrip-123
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection:
    action: create
    path|startswith: '/tmp/'
  condition: selection
level: low
tags:
  - attack.persistence
  - attack.t1547
`

	rule := &Rule{
		ID:        "roundtrip-test",
		Type:      "sigma",
		SigmaYAML: originalYAML,
	}

	// First parse
	parsed1, err := rule.ParsedSigmaRule()
	if err != nil {
		t.Fatalf("first parse failed: %v", err)
	}

	// Second parse (on-demand, no caching)
	parsed2, err := rule.ParsedSigmaRule()
	if err != nil {
		t.Fatalf("second parse failed: %v", err)
	}

	// Verify both parses return same data
	title1, ok1 := parsed1["title"].(string)
	title2, ok2 := parsed2["title"].(string)

	if !ok1 || !ok2 {
		t.Fatal("expected title to be string in both parses")
	}

	if title1 != title2 {
		t.Errorf("expected same title, got '%s' and '%s'", title1, title2)
	}

	if title1 != "Round Trip Test" {
		t.Errorf("expected title 'Round Trip Test', got '%s'", title1)
	}

	// Access nested fields
	logsource, ok := parsed1["logsource"].(map[string]interface{})
	if !ok {
		t.Fatal("expected logsource to be a map")
	}

	category, ok := logsource["category"].(string)
	if !ok || category != "file_event" {
		t.Errorf("expected category 'file_event', got '%v'", logsource["category"])
	}

	// Access detection fields
	detection, ok := parsed1["detection"].(map[string]interface{})
	if !ok {
		t.Fatal("expected detection to be a map")
	}

	selection, ok := detection["selection"].(map[string]interface{})
	if !ok {
		t.Fatal("expected selection to be a map")
	}

	action, ok := selection["action"].(string)
	if !ok || action != "create" {
		t.Errorf("expected action 'create', got '%v'", selection["action"])
	}

	// Verify tags are accessible
	tags, ok := parsed1["tags"].([]interface{})
	if !ok {
		t.Fatal("expected tags to be a slice")
	}

	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}

	tag1, ok := tags[0].(string)
	if !ok || tag1 != "attack.persistence" {
		t.Errorf("expected first tag 'attack.persistence', got '%v'", tags[0])
	}
}

// TestParsedSigmaRule_UnicodeAndSpecialChars tests handling of unicode and special characters
func TestParsedSigmaRule_UnicodeAndSpecialChars(t *testing.T) {
	rule := &Rule{
		ID:   "test-rule-unicode",
		Type: "sigma",
		SigmaYAML: `
title: "Unicode Test Rule 中文测试 🔒"
id: unicode-rule-1
description: "Testing unicode characters: ñ, é, ü, 日本語, 한글, العربية"
author: "Test Author <test@example.com>"
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - "C:\\Program Files\\App"
      - 'Special "quotes" test'
      - "Backslash \\ test"
      - "Tab\ttest"
      - "Newline\ntest"
  condition: selection
level: medium
tags:
  - test.unicode
  - test.special-chars
`,
	}

	parsed, err := rule.ParsedSigmaRule()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify unicode in title
	title, ok := parsed["title"].(string)
	if !ok {
		t.Fatal("expected title to be string")
	}

	if !strings.Contains(title, "中文测试") {
		t.Error("expected title to contain Chinese characters")
	}

	if !strings.Contains(title, "🔒") {
		t.Error("expected title to contain emoji")
	}

	// Verify unicode in description
	description, ok := parsed["description"].(string)
	if !ok {
		t.Fatal("expected description to be string")
	}

	unicodeChars := []string{"ñ", "é", "ü", "日本語", "한글", "العربية"}
	for _, char := range unicodeChars {
		if !strings.Contains(description, char) {
			t.Errorf("expected description to contain '%s'", char)
		}
	}

	// Verify special characters in author (email)
	author, ok := parsed["author"].(string)
	if !ok {
		t.Fatal("expected author to be string")
	}

	if !strings.Contains(author, "<test@example.com>") {
		t.Error("expected author to contain email address")
	}

	// Verify special characters in CommandLine
	detection, ok := parsed["detection"].(map[string]interface{})
	if !ok {
		t.Fatal("expected detection to be a map")
	}

	selection, ok := detection["selection"].(map[string]interface{})
	if !ok {
		t.Fatal("expected selection to be a map")
	}

	cmdLine, ok := selection["CommandLine|contains"].([]interface{})
	if !ok {
		t.Fatal("expected CommandLine|contains to be a slice")
	}

	if len(cmdLine) != 5 {
		t.Errorf("expected 5 CommandLine patterns, got %d", len(cmdLine))
	}

	// Verify backslash is preserved
	found := false
	for _, item := range cmdLine {
		if str, ok := item.(string); ok && strings.Contains(str, "C:\\Program Files") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find backslash in CommandLine patterns")
	}
}

// TestParsedSigmaRule_YAMLBombProtection tests protection against YAML bombs
func TestParsedSigmaRule_YAMLBombProtection(t *testing.T) {
	// Create a large YAML string exceeding 1MB limit
	largeYAML := "title: Large Rule\n"
	largeYAML += "description: " + strings.Repeat("A", 1024*1024) // 1MB+ of 'A' characters

	rule := &Rule{
		ID:        "test-rule-bomb",
		Type:      "sigma",
		SigmaYAML: largeYAML,
	}

	parsed, err := rule.ParsedSigmaRule()
	if err == nil {
		t.Fatal("expected error for YAML exceeding size limit, got nil")
	}

	if parsed != nil {
		t.Errorf("expected nil parsed result, got %v", parsed)
	}

	expectedErrMsg := "exceeds maximum size"
	if !strings.Contains(err.Error(), expectedErrMsg) {
		t.Errorf("expected error message to contain '%s', got '%s'", expectedErrMsg, err.Error())
	}
}

// BenchmarkParsedSigmaRule benchmarks the parsing performance
func BenchmarkParsedSigmaRule(b *testing.B) {
	rule := &Rule{
		ID:   "benchmark-rule",
		Type: "sigma",
		SigmaYAML: `
title: Benchmark SIGMA Rule
id: benchmark-123
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    EventID: 1
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
  selection2:
    CommandLine|contains:
      - 'Invoke-Expression'
      - 'IEX'
      - 'DownloadString'
  condition: selection1 and selection2
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1059.003
falsepositives:
  - Administrative scripts
  - Legitimate automation
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/003/
fields:
  - CommandLine
  - ParentImage
  - User
  - IntegrityLevel
`,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsed, err := rule.ParsedSigmaRule()
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if parsed == nil {
			b.Fatal("expected parsed result")
		}
	}
}

// BenchmarkParsedSigmaRule_Complex benchmarks parsing of complex YAML
func BenchmarkParsedSigmaRule_Complex(b *testing.B) {
	// Build a complex YAML with many selections and conditions
	complexYAML := `
title: Complex Benchmark Rule
id: complex-benchmark
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    EventID: 1
    Image|endswith:
      - '\process1.exe'
      - '\process2.exe'
      - '\process3.exe'
  selection2:
    CommandLine|contains:
      - 'arg1'
      - 'arg2'
      - 'arg3'
  selection3:
    User|startswith:
      - 'DOMAIN\'
      - 'NT AUTHORITY\'
  filter1:
    ParentImage|endswith: '\explorer.exe'
  filter2:
    IntegrityLevel: 'High'
  condition: (selection1 and selection2 and selection3) and not (filter1 or filter2)
level: critical
tags:
`
	// Add many tags
	for i := 0; i < 20; i++ {
		complexYAML += "  - attack.technique_" + string(rune('a'+i)) + "\n"
	}

	rule := &Rule{
		ID:        "complex-benchmark",
		Type:      "sigma",
		SigmaYAML: complexYAML,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsed, err := rule.ParsedSigmaRule()
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if parsed == nil {
			b.Fatal("expected parsed result")
		}
	}
}
