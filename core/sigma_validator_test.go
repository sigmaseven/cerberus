package core

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestValidateSigmaYAML_ValidRules tests valid SIGMA YAML that should pass validation
func TestValidateSigmaYAML_ValidRules(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		description string
	}{
		{
			name: "minimal_valid_rule",
			yaml: `title: Minimal Valid Rule
detection:
  selection:
    EventID: 1
  condition: selection`,
			description: "Minimal rule with only required fields",
		},
		{
			name: "complete_valid_rule",
			yaml: `title: Complete Valid Rule
id: test-123
status: experimental
description: Test SIGMA rule with all fields
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    CommandLine: whoami
  condition: selection
references:
  - https://example.com
author: Test Author
tags:
  - attack.t1059`,
			description: "Complete rule with all optional fields",
		},
		{
			name: "rule_with_safe_regex",
			yaml: `title: Rule with Safe Regex
detection:
  selection:
    CommandLine|re: '^whoami\.exe$'
  condition: selection`,
			description: "Rule with safe regex pattern",
		},
		{
			name: "rule_with_multiple_safe_regexes",
			yaml: `title: Rule with Multiple Safe Regexes
detection:
  selection:
    CommandLine|re:
      - '^cmd\.exe$'
      - '^powershell\.exe$'
  condition: selection`,
			description: "Rule with array of safe regex patterns",
		},
		{
			name: "nested_detection_structure",
			yaml: `title: Nested Detection Structure
detection:
  selection1:
    EventID: 1
  selection2:
    EventID: 2
  filter:
    User: SYSTEM
  condition: (selection1 or selection2) and not filter`,
			description: "Rule with complex nested detection structure",
		},
		{
			name: "all_valid_levels",
			yaml: `title: Informational Level
detection:
  selection:
    EventID: 1
  condition: selection
level: informational`,
			description: "Rule with informational level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ValidateSigmaYAML(tt.yaml)
			require.NoError(t, err, "Validation should pass for: %s", tt.description)
			require.NotNil(t, parsed, "Parsed result should not be nil")

			// Verify required fields are present
			assert.Contains(t, parsed, "title", "Parsed result should contain title")
			assert.Contains(t, parsed, "detection", "Parsed result should contain detection")
		})
	}
}

// TestValidateSigmaYAML_EmptyInput tests validation of empty or whitespace-only input
func TestValidateSigmaYAML_EmptyInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty_string", ""},
		{"whitespace_only", "   \t\n  "},
		{"newlines_only", "\n\n\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ValidateSigmaYAML(tt.input)
			assert.Error(t, err, "Empty input should fail validation")
			assert.Nil(t, parsed, "Parsed result should be nil for invalid input")

			// Verify error type and message
			var sigmaErr *SigmaValidationError
			require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
			assert.Equal(t, "yaml", sigmaErr.Field, "Error should be for yaml field")
			assert.Contains(t, sigmaErr.Message, "empty", "Error message should mention empty")
		})
	}
}

// TestValidateSigmaYAML_SizeLimit tests the 1MB size limit protection
func TestValidateSigmaYAML_SizeLimit(t *testing.T) {
	// Create a YAML that exceeds 1MB
	largeTitleBuilder := strings.Builder{}
	largeTitleBuilder.WriteString("title: ")
	// Write more than 1MB of 'A' characters
	for i := 0; i < MaxSigmaYAMLSize+1000; i++ {
		largeTitleBuilder.WriteString("A")
	}
	largeTitleBuilder.WriteString("\ndetection:\n  selection:\n    EventID: 1\n  condition: selection")

	largeYAML := largeTitleBuilder.String()

	parsed, err := ValidateSigmaYAML(largeYAML)
	assert.Error(t, err, "Oversized YAML should fail validation")
	assert.Nil(t, parsed, "Parsed result should be nil for oversized input")

	// Verify error details
	var sigmaErr *SigmaValidationError
	require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
	assert.Equal(t, "yaml", sigmaErr.Field, "Error should be for yaml field")
	assert.Contains(t, sigmaErr.Message, "exceeds maximum allowed size", "Error should mention size limit")
}

// TestValidateSigmaYAML_YAMLDepth tests the depth limit protection
func TestValidateSigmaYAML_YAMLDepth(t *testing.T) {
	// Create deeply nested YAML (exceeds MaxYAMLDepth)
	depthBuilder := strings.Builder{}
	depthBuilder.WriteString("title: Deep Nesting Test\ndetection:\n  condition: selection\n  selection:\n")

	// Create nesting deeper than MaxYAMLDepth (50)
	for i := 0; i < MaxYAMLDepth+5; i++ {
		depthBuilder.WriteString(strings.Repeat("  ", i))
		depthBuilder.WriteString(fmt.Sprintf("level%d:\n", i))
	}
	depthBuilder.WriteString(strings.Repeat("  ", MaxYAMLDepth+5))
	depthBuilder.WriteString("value: deep")

	deepYAML := depthBuilder.String()

	parsed, err := ValidateSigmaYAML(deepYAML)
	assert.Error(t, err, "Deeply nested YAML should fail validation")
	assert.Nil(t, parsed, "Parsed result should be nil for deeply nested input")

	// Verify error details
	var sigmaErr *SigmaValidationError
	require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
	assert.Equal(t, "yaml", sigmaErr.Field, "Error should be for yaml field")
	assert.Contains(t, sigmaErr.Message, "nesting depth", "Error should mention depth")
}

// TestValidateSigmaYAML_AnchorAliasLimit tests billion laughs attack protection
func TestValidateSigmaYAML_AnchorAliasLimit(t *testing.T) {
	// Create YAML with too many anchors/aliases
	anchorBuilder := strings.Builder{}
	anchorBuilder.WriteString("title: Anchor Test\ndetection:\n  condition: selection\n  selection:\n")

	// Create more than MaxYAMLAnchorsAliases (10) anchors
	for i := 0; i < MaxYAMLAnchorsAliases+5; i++ {
		anchorBuilder.WriteString(fmt.Sprintf("    anchor%d: &anchor%d value\n", i, i))
	}

	anchorYAML := anchorBuilder.String()

	parsed, err := ValidateSigmaYAML(anchorYAML)
	assert.Error(t, err, "YAML with too many anchors should fail validation")
	assert.Nil(t, parsed, "Parsed result should be nil for anchor-heavy input")

	// Verify error details
	var sigmaErr *SigmaValidationError
	require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
	assert.Equal(t, "yaml", sigmaErr.Field, "Error should be for yaml field")
	assert.Contains(t, sigmaErr.Message, "anchors/aliases", "Error should mention anchors")
}

// TestValidateSigmaYAML_MalformedYAML tests handling of malformed YAML
func TestValidateSigmaYAML_MalformedYAML(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "invalid_yaml_syntax",
			yaml: `title: Test
detection: [unclosed bracket
condition: selection`,
		},
		{
			name: "invalid_indentation",
			yaml: `title: Test
detection:
selection:
  EventID: 1
  condition: selection`,
		},
		{
			name: "duplicate_keys",
			yaml: `title: Test
title: Duplicate
detection:
  selection:
    EventID: 1
  condition: selection`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ValidateSigmaYAML(tt.yaml)
			assert.Error(t, err, "Malformed YAML should fail validation")
			assert.Nil(t, parsed, "Parsed result should be nil for malformed YAML")

			// Verify error type
			var sigmaErr *SigmaValidationError
			require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
		})
	}
}

// TestValidateSigmaYAML_MissingRequiredFields tests validation of missing required fields
func TestValidateSigmaYAML_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		expectedField string
	}{
		{
			name: "missing_title",
			yaml: `detection:
  selection:
    EventID: 1
  condition: selection`,
			expectedField: "title",
		},
		{
			name:          "missing_detection",
			yaml:          `title: Missing Detection`,
			expectedField: "detection",
		},
		{
			name: "missing_condition",
			yaml: `title: Missing Condition
detection:
  selection:
    EventID: 1`,
			expectedField: "detection.condition",
		},
		{
			name: "empty_title",
			yaml: `title: ""
detection:
  selection:
    EventID: 1
  condition: selection`,
			expectedField: "title",
		},
		{
			name: "empty_condition",
			yaml: `title: Empty Condition
detection:
  selection:
    EventID: 1
  condition: ""`,
			expectedField: "detection.condition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ValidateSigmaYAML(tt.yaml)
			assert.Error(t, err, "YAML with missing required field should fail validation")
			assert.Nil(t, parsed, "Parsed result should be nil when required fields are missing")

			// Verify error references the correct field
			var sigmaErr *SigmaValidationError
			require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
			assert.Contains(t, sigmaErr.Field, tt.expectedField, "Error should reference the missing field")
		})
	}
}

// TestValidateSigmaYAML_InvalidDetectionType tests validation when detection is not a map
func TestValidateSigmaYAML_InvalidDetectionType(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "detection_as_string",
			yaml: `title: Invalid Detection Type
detection: "not a map"`,
		},
		{
			name: "detection_as_array",
			yaml: `title: Invalid Detection Type
detection:
  - item1
  - item2`,
		},
		{
			name: "detection_as_number",
			yaml: `title: Invalid Detection Type
detection: 123`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ValidateSigmaYAML(tt.yaml)
			assert.Error(t, err, "YAML with invalid detection type should fail validation")
			assert.Nil(t, parsed, "Parsed result should be nil for invalid detection type")

			var sigmaErr *SigmaValidationError
			require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
			assert.Equal(t, "detection", sigmaErr.Field, "Error should be for detection field")
			assert.Contains(t, sigmaErr.Message, "must be a map", "Error should mention type requirement")
		})
	}
}

// TestValidateSigmaYAML_InvalidLevel tests validation of invalid severity levels
func TestValidateSigmaYAML_InvalidLevel(t *testing.T) {
	tests := []struct {
		name              string
		level             string
		expectedInMessage string
	}{
		{"invalid_level_string", "super-critical", "invalid level"},
		{"invalid_level_typo", "hgih", "invalid level"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := fmt.Sprintf(`title: Invalid Level Test
detection:
  selection:
    EventID: 1
  condition: selection
level: %s`, tt.level)

			parsed, err := ValidateSigmaYAML(yaml)
			assert.Error(t, err, "YAML with invalid level should fail validation")
			assert.Nil(t, parsed, "Parsed result should be nil for invalid level")

			var sigmaErr *SigmaValidationError
			require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
			assert.Equal(t, "level", sigmaErr.Field, "Error should be for level field")
			assert.Contains(t, sigmaErr.Message, tt.expectedInMessage, "Error should contain expected message")
		})
	}
}

// TestValidateSigmaYAML_InvalidLevelType tests when level is not a string
func TestValidateSigmaYAML_InvalidLevelType(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "level_as_number",
			yaml: `title: Invalid Level Type
detection:
  selection:
    EventID: 1
  condition: selection
level: 3`,
		},
		{
			name: "level_as_null",
			yaml: `title: Invalid Level Type
detection:
  selection:
    EventID: 1
  condition: selection
level: null`,
		},
		{
			name: "level_as_empty_string_literal",
			yaml: `title: Invalid Level Type
detection:
  selection:
    EventID: 1
  condition: selection
level: ""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ValidateSigmaYAML(tt.yaml)
			assert.Error(t, err, "YAML with non-string level should fail validation")
			assert.Nil(t, parsed, "Parsed result should be nil for non-string level")

			var sigmaErr *SigmaValidationError
			require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
			assert.Equal(t, "level", sigmaErr.Field, "Error should be for level field")
		})
	}
}

// TestValidateSigmaYAML_AllValidLevels tests all valid SIGMA severity levels
func TestValidateSigmaYAML_AllValidLevels(t *testing.T) {
	levels := []string{"informational", "low", "medium", "high", "critical"}

	for _, level := range levels {
		t.Run("level_"+level, func(t *testing.T) {
			yaml := fmt.Sprintf(`title: Valid Level Test
detection:
  selection:
    EventID: 1
  condition: selection
level: %s`, level)

			parsed, err := ValidateSigmaYAML(yaml)
			require.NoError(t, err, "Valid level '%s' should pass validation", level)
			require.NotNil(t, parsed, "Parsed result should not be nil")

			// Verify level was parsed correctly
			assert.Equal(t, level, parsed["level"], "Level should match")
		})
	}
}

// TestValidateSigmaYAML_LevelCaseInsensitive tests that level validation is case-insensitive
func TestValidateSigmaYAML_LevelCaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		level string
	}{
		{"uppercase", "HIGH"},
		{"mixed_case", "MeDiUm"},
		{"lowercase", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := fmt.Sprintf(`title: Case Insensitive Level
detection:
  selection:
    EventID: 1
  condition: selection
level: %s`, tt.level)

			parsed, err := ValidateSigmaYAML(yaml)
			require.NoError(t, err, "Level should be case-insensitive")
			require.NotNil(t, parsed, "Parsed result should not be nil")
		})
	}
}

// TestValidateSigmaYAML_DangerousRegex tests rejection of dangerous regex patterns
func TestValidateSigmaYAML_DangerousRegex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		reason  string
	}{
		{
			name:    "nested_quantifiers",
			pattern: "(a+)+",
			reason:  "nested quantifiers cause catastrophic backtracking",
		},
		{
			name:    "overlapping_alternation",
			pattern: "(a|a)+",
			reason:  "overlapping alternation with quantifier",
		},
		{
			name:    "exponential_repetition",
			pattern: "(.*)*b",
			reason:  "exponential repetition pattern",
		},
		{
			name:    "very_long_pattern",
			pattern: strings.Repeat("a", 1001),
			reason:  "pattern exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := fmt.Sprintf(`title: Dangerous Regex Test
detection:
  selection:
    CommandLine|re: '%s'
  condition: selection`, tt.pattern)

			parsed, err := ValidateSigmaYAML(yaml)
			assert.Error(t, err, "Dangerous regex should fail validation: %s", tt.reason)
			assert.Nil(t, parsed, "Parsed result should be nil for dangerous regex")

			var sigmaErr *SigmaValidationError
			require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
			assert.Contains(t, sigmaErr.Field, "|re", "Error should reference regex field")
			assert.Contains(t, strings.ToLower(sigmaErr.Message), "risk", "Error should mention risk level")
		})
	}
}

// TestValidateSigmaYAML_DangerousRegexArray tests rejection of dangerous regex in arrays
func TestValidateSigmaYAML_DangerousRegexArray(t *testing.T) {
	yaml := `title: Dangerous Regex Array Test
detection:
  selection:
    CommandLine|re:
      - '^cmd\.exe$'
      - '(a+)+'
      - '^powershell\.exe$'
  condition: selection`

	parsed, err := ValidateSigmaYAML(yaml)
	assert.Error(t, err, "Array with dangerous regex should fail validation")
	assert.Nil(t, parsed, "Parsed result should be nil when array contains dangerous regex")

	var sigmaErr *SigmaValidationError
	require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
	assert.Contains(t, sigmaErr.Field, "|re", "Error should reference regex field")
	assert.Contains(t, sigmaErr.Field, "[1]", "Error should reference array index")
}

// TestValidateSigmaYAML_NestedRegexValidation tests regex validation in nested structures
func TestValidateSigmaYAML_NestedRegexValidation(t *testing.T) {
	yaml := `title: Nested Regex Test
detection:
  selection1:
    field1|re: '^safe$'
  selection2:
    nested:
      field2|re: '(a+)+'
  condition: selection1 or selection2`

	parsed, err := ValidateSigmaYAML(yaml)
	assert.Error(t, err, "Nested dangerous regex should fail validation")
	assert.Nil(t, parsed, "Parsed result should be nil for nested dangerous regex")

	var sigmaErr *SigmaValidationError
	require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
	assert.Contains(t, sigmaErr.Field, "|re", "Error should reference regex field")
}

// TestValidateSigmaYAML_RegexInvalidType tests handling of non-string regex values
func TestValidateSigmaYAML_RegexInvalidType(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "regex_as_number",
			yaml: `title: Regex Type Test
detection:
  selection:
    field|re: 123
  condition: selection`,
		},
		{
			name: "regex_array_with_number",
			yaml: `title: Regex Array Type Test
detection:
  selection:
    field|re:
      - '^safe$'
      - 456
  condition: selection`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ValidateSigmaYAML(tt.yaml)
			assert.Error(t, err, "Non-string regex value should fail validation")
			assert.Nil(t, parsed, "Parsed result should be nil for non-string regex")

			var sigmaErr *SigmaValidationError
			require.ErrorAs(t, err, &sigmaErr, "Error should be SigmaValidationError")
			assert.Contains(t, sigmaErr.Message, "must be a string", "Error should mention type requirement")
		})
	}
}

// TestCheckYAMLDepth tests the depth checking function
func TestCheckYAMLDepth(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		expectedDepth int
	}{
		{
			name:          "flat_structure",
			yaml:          `key: value`,
			expectedDepth: 2, // root + key/value
		},
		{
			name: "nested_structure",
			yaml: `level1:
  level2:
    level3: value`,
			expectedDepth: 6, // root + levels
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var node yaml.Node
			err := yaml.Unmarshal([]byte(tt.yaml), &node)
			require.NoError(t, err, "YAML should parse successfully")

			depth := checkYAMLDepth(&node, 0)
			assert.GreaterOrEqual(t, depth, 1, "Depth should be at least 1")
		})
	}
}

// TestCheckYAMLDepth_NilNode tests handling of nil nodes
func TestCheckYAMLDepth_NilNode(t *testing.T) {
	depth := checkYAMLDepth(nil, 5)
	assert.Equal(t, 5, depth, "Nil node should return current depth")
}

// TestCountAnchorsAliases tests the anchor/alias counting function
func TestCountAnchorsAliases(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		expectedCount int
	}{
		{
			name:          "no_anchors",
			yaml:          `key: value`,
			expectedCount: 0,
		},
		{
			name:          "one_anchor",
			yaml:          `anchor: &anchor_name value`,
			expectedCount: 1,
		},
		{
			name:          "one_alias",
			yaml:          `alias: *anchor_name`,
			expectedCount: 1,
		},
		{
			name: "multiple_anchors_aliases",
			yaml: `anchor1: &a1 value
alias1: *a1
anchor2: &a2 value
alias2: *a2`,
			expectedCount: 4,
		},
		{
			name:          "anchor_in_string_ignored",
			yaml:          `key: "this is an & in a string"`,
			expectedCount: 0,
		},
		{
			name:          "alias_in_string_ignored",
			yaml:          `key: 'this is a * in a string'`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := countAnchorsAliases(tt.yaml)
			assert.Equal(t, tt.expectedCount, count, "Anchor/alias count should match")
		})
	}
}

// TestSigmaValidationError_Error tests the error message formatting
func TestSigmaValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *SigmaValidationError
		expected string
	}{
		{
			name: "error_without_underlying",
			err: &SigmaValidationError{
				Field:   "test_field",
				Message: "test message",
			},
			expected: "SIGMA validation failed for field 'test_field': test message",
		},
		{
			name: "error_with_underlying",
			err: &SigmaValidationError{
				Field:   "test_field",
				Message: "test message",
				Err:     fmt.Errorf("underlying error"),
			},
			expected: "SIGMA validation failed for field 'test_field': test message: underlying error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error(), "Error message should match expected format")
		})
	}
}

// TestSigmaValidationError_Unwrap tests error unwrapping
func TestSigmaValidationError_Unwrap(t *testing.T) {
	underlyingErr := fmt.Errorf("underlying error")
	sigmaErr := &SigmaValidationError{
		Field:   "test",
		Message: "message",
		Err:     underlyingErr,
	}

	unwrapped := sigmaErr.Unwrap()
	assert.Equal(t, underlyingErr, unwrapped, "Unwrap should return underlying error")
}

// TestValidateSigmaYAML_ComplexRealWorld tests validation of complex real-world SIGMA rules
func TestValidateSigmaYAML_ComplexRealWorld(t *testing.T) {
	complexYAML := `title: Suspicious PowerShell Execution
id: a8b8e5e0-1234-5678-90ab-cdef12345678
status: experimental
description: Detects suspicious PowerShell command line patterns
author: Security Team
date: 2024/01/01
modified: 2024/01/15
level: high
logsource:
  category: process_creation
  product: windows
  service: sysmon
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_cli:
    CommandLine|contains:
      - 'Invoke-Expression'
      - 'IEX'
      - 'downloadstring'
  filter_legitimate:
    User|contains: 'NT AUTHORITY\SYSTEM'
  condition: selection_img and selection_cli and not filter_legitimate
falsepositives:
  - Legitimate administrative scripts
  - System maintenance tasks
tags:
  - attack.execution
  - attack.t1059.001
references:
  - https://attack.mitre.org/techniques/T1059/001/`

	parsed, err := ValidateSigmaYAML(complexYAML)
	require.NoError(t, err, "Complex real-world SIGMA rule should pass validation")
	require.NotNil(t, parsed, "Parsed result should not be nil")

	// Verify structure
	assert.Equal(t, "Suspicious PowerShell Execution", parsed["title"])
	assert.Equal(t, "high", parsed["level"])
	assert.Contains(t, parsed, "detection")
	assert.Contains(t, parsed, "logsource")
}

// TestValidateSigmaYAML_EdgeCases tests edge cases and boundary conditions
func TestValidateSigmaYAML_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		shouldErr bool
	}{
		{
			name: "detection_with_empty_map",
			yaml: `title: Empty Detection Map
detection:
  selection: {}
  condition: selection`,
			shouldErr: false,
		},
		{
			name: "unicode_in_title",
			yaml: `title: Test Rule with Unicode ℃ 日本語
detection:
  selection:
    EventID: 1
  condition: selection`,
			shouldErr: false,
		},
		{
			name: "very_long_field_name",
			yaml: fmt.Sprintf(`title: Long Field Name
detection:
  selection:
    %s: value
  condition: selection`, strings.Repeat("a", 500)),
			shouldErr: false,
		},
		{
			name: "null_title",
			yaml: `title: null
detection:
  selection:
    EventID: 1
  condition: selection`,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ValidateSigmaYAML(tt.yaml)
			if tt.shouldErr {
				assert.Error(t, err, "Edge case should fail validation")
				assert.Nil(t, parsed, "Parsed result should be nil for invalid edge case")
			} else {
				assert.NoError(t, err, "Edge case should pass validation")
				assert.NotNil(t, parsed, "Parsed result should not be nil for valid edge case")
			}
		})
	}
}

// TestValidateSigmaYAML_ConcurrentAccess tests thread safety of validation function
func TestValidateSigmaYAML_ConcurrentAccess(t *testing.T) {
	validYAML := `title: Concurrent Test
detection:
  selection:
    EventID: 1
  condition: selection`

	// Run multiple validations concurrently
	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			_, err := ValidateSigmaYAML(validYAML)
			assert.NoError(t, err, "Concurrent validation should succeed")
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestValidateSigmaYAML_RegexComplexityBranchCoverage tests additional regex complexity branches
func TestValidateSigmaYAML_RegexComplexityBranchCoverage(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		shouldErr bool
		reason    string
	}{
		{
			name: "regex_with_moderate_nesting",
			yaml: `title: Moderate Nesting
detection:
  selection:
    field|re: '((a))'
  condition: selection`,
			shouldErr: false,
			reason:    "Moderate nesting should be allowed",
		},
		{
			name: "regex_with_large_repetition_exact",
			yaml: `title: Large Repetition Exact
detection:
  selection:
    field|re: 'a{1500}'
  condition: selection`,
			shouldErr: false, // Large repetition alone doesn't trigger high/critical risk
			reason:    "Exact repetition is detected but may be medium risk",
		},
		{
			name: "regex_with_large_repetition_range",
			yaml: `title: Large Repetition Range
detection:
  selection:
    field|re: 'a{1,1500}'
  condition: selection`,
			shouldErr: false, // Large repetition alone doesn't trigger high/critical risk
			reason:    "Range repetition is detected but may be medium risk",
		},
		{
			name: "regex_with_alternations_moderate",
			yaml: `title: Moderate Alternations
detection:
  selection:
    field|re: 'a|b|c|d|e'
  condition: selection`,
			shouldErr: false,
			reason:    "Moderate alternations should be allowed",
		},
		{
			name: "regex_with_combined_risk_factors",
			yaml: `title: Combined Risk Factors
detection:
  selection:
    field|re: '((a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|1|2|3|4|5|6)+)'
  condition: selection`, // Deep nesting (4) + many alternations = high complexity score
			shouldErr: true,
			reason:    "Combined risk factors should trigger high risk",
		},
		{
			name: "regex_with_escaped_chars",
			yaml: `title: Escaped Characters
detection:
  selection:
    field|re: '\(\)\+\*\?'
  condition: selection`,
			shouldErr: false,
			reason:    "Escaped special characters should be safe",
		},
		{
			name: "regex_deep_nesting_safe",
			yaml: `title: Deep Nesting Safe
detection:
  selection:
    field|re: '(((a)))'
  condition: selection`,
			shouldErr: false,
			reason:    "Deep nesting without quantifiers should be safe",
		},
		{
			name: "regex_deep_nesting_with_quantifier",
			yaml: `title: Deep Nesting with Quantifier
detection:
  selection:
    field|re: '((((a))))++'
  condition: selection`,
			shouldErr: true,
			reason:    "Deep nesting with stacked quantifiers should fail",
		},
		{
			name: "regex_empty_pattern",
			yaml: `title: Empty Regex Pattern
detection:
  selection:
    field|re: ''
  condition: selection`,
			shouldErr: false,
			reason:    "Empty pattern should be safe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ValidateSigmaYAML(tt.yaml)
			if tt.shouldErr {
				assert.Error(t, err, "Should fail: %s", tt.reason)
				assert.Nil(t, parsed)
			} else {
				assert.NoError(t, err, "Should pass: %s", tt.reason)
				assert.NotNil(t, parsed)
			}
		})
	}
}

// TestDetectNestedQuantifiers_EdgeCases tests edge cases in nested quantifier detection
func TestDetectNestedQuantifiers_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		pattern        string
		expectNested   bool
		expectMinDepth int
	}{
		{
			name:           "empty_pattern",
			pattern:        "",
			expectNested:   false,
			expectMinDepth: 0,
		},
		{
			name:           "simple_pattern",
			pattern:        "abc",
			expectNested:   false,
			expectMinDepth: 0,
		},
		{
			name:           "escaped_parens",
			pattern:        `\(\)`,
			expectNested:   false,
			expectMinDepth: 0,
		},
		{
			name:           "nested_groups_no_quantifiers",
			pattern:        "((a))",
			expectNested:   false,
			expectMinDepth: 2,
		},
		{
			name:           "nested_with_quantifier_closing_paren",
			pattern:        "((a)+)",
			expectNested:   true,
			expectMinDepth: 2,
		},
		{
			name:           "stacked_quantifiers",
			pattern:        "a++",
			expectNested:   true,
			expectMinDepth: 0,
		},
		{
			name:           "quantifier_after_brace_close_nested",
			pattern:        "((a){2,3})+",
			expectNested:   true,
			expectMinDepth: 2,
		},
		{
			name:           "escaped_plus_not_nested",
			pattern:        `\+\+`,
			expectNested:   false,
			expectMinDepth: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasNested, depth := detectNestedQuantifiers(tt.pattern)
			assert.Equal(t, tt.expectNested, hasNested, "Nested quantifier detection mismatch")
			assert.GreaterOrEqual(t, depth, tt.expectMinDepth, "Depth should be at least minimum expected")
		})
	}
}

// TestHasLargeRepetitionRange_EdgeCases tests edge cases in large repetition detection
func TestHasLargeRepetitionRange_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectLarge bool
	}{
		{
			name:        "no_braces",
			pattern:     "abc",
			expectLarge: false,
		},
		{
			name:        "small_exact_repetition",
			pattern:     "a{10}",
			expectLarge: false,
		},
		{
			name:        "large_exact_repetition",
			pattern:     "a{1001}",
			expectLarge: true,
		},
		{
			name:        "small_range",
			pattern:     "a{5,10}",
			expectLarge: false,
		},
		{
			name:        "large_end_range",
			pattern:     "a{1,1001}",
			expectLarge: true,
		},
		{
			name:        "large_span_range",
			pattern:     "a{1,1002}",
			expectLarge: true,
		},
		{
			name:        "unbounded_small_start",
			pattern:     "a{5,}",
			expectLarge: false,
		},
		{
			name:        "unbounded_large_start",
			pattern:     "a{1001,}",
			expectLarge: true,
		},
		{
			name:        "multiple_braces_one_large",
			pattern:     "a{10}b{2000}",
			expectLarge: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasLargeRepetitionRange(tt.pattern)
			assert.Equal(t, tt.expectLarge, result, "Large repetition detection mismatch")
		})
	}
}
