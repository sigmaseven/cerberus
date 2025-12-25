package core

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

// TestIntegration_RuleWithAllNewFields is an integration test verifying all new fields work together
func TestIntegration_RuleWithAllNewFields(t *testing.T) {
	// Create a complete rule with all new fields
	rule := Rule{
		ID:              "integration-complete",
		Type:            "sigma",
		Name:            "Complete Integration Test",
		Description:     "Tests all new SigmaYAML and logsource fields",
		Severity:        "critical",
		Version:         1,
		Tags:            []string{"integration", "sigma", "test"},
		MitreTactics:    []string{"TA0001", "TA0002"},
		MitreTechniques: []string{"T1059", "T1003"},
		Author:          "Integration Test Suite",
		Enabled:         true,
		SigmaYAML: `title: Complete SIGMA Rule
id: integration-123
status: stable
description: |
  This is a complete SIGMA rule for integration testing
  with multiple lines and special characters: "quotes", 'apostrophes'
author: Test Suite
date: 2024/01/01
modified: 2024/01/15
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
    CommandLine|contains|all:
      - '-enc'
      - 'bypass'
  filter:
    User|contains: 'SYSTEM'
  condition: selection and not filter
falsepositives:
  - Legitimate admin scripts
  - Automated deployment tools
level: high
references:
  - https://example.com/threat-intel
  - https://attack.mitre.org/techniques/T1059`,
		LogsourceCategory: "process_creation",
		LogsourceProduct:  "windows",
		LogsourceService:  "sysmon",
		References:        []string{"https://example.com/ref1", "https://example.com/ref2"},
		FalsePositives:    []string{"Automated scripts", "CI/CD pipelines"},
		CreatedAt:         time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2024, 1, 15, 14, 30, 0, 0, time.UTC),
	}

	// Test 1: JSON Marshaling
	t.Run("JSON marshaling preserves all fields", func(t *testing.T) {
		jsonData, err := json.MarshalIndent(rule, "", "  ")
		require.NoError(t, err, "JSON marshal should succeed")

		jsonStr := string(jsonData)

		// Verify new fields are present
		assert.Contains(t, jsonStr, `"sigma_yaml"`, "JSON should contain sigma_yaml")
		assert.Contains(t, jsonStr, `"logsource_category": "process_creation"`, "JSON should contain logsource_category")
		assert.Contains(t, jsonStr, `"logsource_product": "windows"`, "JSON should contain logsource_product")
		assert.Contains(t, jsonStr, `"logsource_service": "sysmon"`, "JSON should contain logsource_service")

		// Verify YAML content is preserved
		assert.Contains(t, jsonStr, `title: Complete SIGMA Rule`, "YAML content should be present")
		assert.Contains(t, jsonStr, `process_creation`, "YAML logsource category should be present")

		t.Logf("JSON output verified successfully (length: %d bytes)", len(jsonData))
	})

	// Test 2: JSON Round-trip
	t.Run("JSON round-trip preserves data integrity", func(t *testing.T) {
		jsonData, err := json.Marshal(rule)
		require.NoError(t, err)

		var decoded Rule
		err = json.Unmarshal(jsonData, &decoded)
		require.NoError(t, err)

		assert.Equal(t, rule.SigmaYAML, decoded.SigmaYAML, "SigmaYAML should match")
		assert.Equal(t, rule.LogsourceCategory, decoded.LogsourceCategory, "LogsourceCategory should match")
		assert.Equal(t, rule.LogsourceProduct, decoded.LogsourceProduct, "LogsourceProduct should match")
		assert.Equal(t, rule.LogsourceService, decoded.LogsourceService, "LogsourceService should match")
		assert.Equal(t, rule.ID, decoded.ID, "ID should match")
		assert.Equal(t, rule.Type, decoded.Type, "Type should match")
		assert.Equal(t, rule.Severity, decoded.Severity, "Severity should match")
	})

	// Test 3: BSON Marshaling
	t.Run("BSON marshaling preserves all fields", func(t *testing.T) {
		bsonData, err := bson.Marshal(rule)
		require.NoError(t, err, "BSON marshal should succeed")

		var result map[string]interface{}
		err = bson.Unmarshal(bsonData, &result)
		require.NoError(t, err)

		assert.Contains(t, result, "sigma_yaml", "BSON should have sigma_yaml")
		assert.Contains(t, result, "logsource_category", "BSON should have logsource_category")
		assert.Contains(t, result, "logsource_product", "BSON should have logsource_product")
		assert.Contains(t, result, "logsource_service", "BSON should have logsource_service")

		t.Logf("BSON output verified successfully (length: %d bytes)", len(bsonData))
	})

	// Test 4: BSON Round-trip
	t.Run("BSON round-trip preserves data integrity", func(t *testing.T) {
		bsonData, err := bson.Marshal(rule)
		require.NoError(t, err)

		var decoded Rule
		err = bson.Unmarshal(bsonData, &decoded)
		require.NoError(t, err)

		assert.Equal(t, rule.SigmaYAML, decoded.SigmaYAML, "SigmaYAML should match")
		assert.Equal(t, rule.LogsourceCategory, decoded.LogsourceCategory, "LogsourceCategory should match")
		assert.Equal(t, rule.LogsourceProduct, decoded.LogsourceProduct, "LogsourceProduct should match")
		assert.Equal(t, rule.LogsourceService, decoded.LogsourceService, "LogsourceService should match")
	})

	// Test 5: Interface implementation still works
	t.Run("AlertableRule interface implementation", func(t *testing.T) {
		var alertable AlertableRule = rule
		assert.Equal(t, rule.ID, alertable.GetID(), "GetID should work")
		assert.Equal(t, rule.Name, alertable.GetName(), "GetName should work")
		assert.Equal(t, rule.Description, alertable.GetDescription(), "GetDescription should work")
		assert.Equal(t, rule.Severity, alertable.GetSeverity(), "GetSeverity should work")
		assert.Equal(t, rule.Actions, alertable.GetActions(), "GetActions should work")
	})
}

// TestIntegration_BackwardCompatibility verifies old code without new fields still works
func TestIntegration_BackwardCompatibility(t *testing.T) {
	// Create a CQL rule (without SIGMA fields)
	// TASK #184: Detection and Logsource fields removed - CQL rules use Query field
	oldStyleRule := Rule{
		ID:          "backward-compat",
		Type:        "cql",
		Name:        "Old Style Rule",
		Description: "Rule created without new fields",
		Severity:    "medium",
		Enabled:     true,
		Query:       "event_type = 'test'",
		// Deliberately omit: SigmaYAML, LogsourceCategory, LogsourceProduct, LogsourceService
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Test JSON marshaling/unmarshaling
	t.Run("old style JSON round-trip", func(t *testing.T) {
		jsonData, err := json.Marshal(oldStyleRule)
		require.NoError(t, err)

		var decoded Rule
		err = json.Unmarshal(jsonData, &decoded)
		require.NoError(t, err)

		assert.Equal(t, oldStyleRule.ID, decoded.ID)
		assert.Equal(t, oldStyleRule.Type, decoded.Type)
		assert.Equal(t, oldStyleRule.Name, decoded.Name)
		assert.Equal(t, "", decoded.SigmaYAML, "SigmaYAML should be empty for old-style rules")
		assert.Equal(t, "", decoded.LogsourceCategory, "LogsourceCategory should be empty")
		assert.Equal(t, "", decoded.LogsourceProduct, "LogsourceProduct should be empty")
		assert.Equal(t, "", decoded.LogsourceService, "LogsourceService should be empty")
	})

	// Test BSON marshaling/unmarshaling
	t.Run("old style BSON round-trip", func(t *testing.T) {
		bsonData, err := bson.Marshal(oldStyleRule)
		require.NoError(t, err)

		var decoded Rule
		err = bson.Unmarshal(bsonData, &decoded)
		require.NoError(t, err)

		assert.Equal(t, oldStyleRule.ID, decoded.ID)
		assert.Equal(t, oldStyleRule.Type, decoded.Type)
		assert.Equal(t, "", decoded.SigmaYAML, "SigmaYAML should be empty")
	})
}

// TestIntegration_MixedUsage tests scenarios where some fields are populated and others aren't
func TestIntegration_MixedUsage(t *testing.T) {
	testCases := []struct {
		name       string
		rule       Rule
		expectJSON map[string]bool // field name -> should be in JSON
		expectBSON map[string]bool // field name -> should be in BSON
	}{
		{
			name: "only SigmaYAML populated",
			rule: Rule{
				ID:        "mixed-1",
				Name:      "Only YAML",
				Severity:  "low",
				SigmaYAML: "title: Test",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			expectJSON: map[string]bool{
				"sigma_yaml":         true,
				"logsource_category": false,
				"logsource_product":  false,
				"logsource_service":  false,
			},
			expectBSON: map[string]bool{
				"sigma_yaml":         true,
				"logsource_category": false,
				"logsource_product":  false,
				"logsource_service":  false,
			},
		},
		{
			name: "only logsource fields populated",
			rule: Rule{
				ID:                "mixed-2",
				Name:              "Only Logsource",
				Severity:          "medium",
				LogsourceCategory: "network",
				LogsourceProduct:  "cisco",
				LogsourceService:  "asa",
				CreatedAt:         time.Now(),
				UpdatedAt:         time.Now(),
			},
			expectJSON: map[string]bool{
				"sigma_yaml":         false,
				"logsource_category": true,
				"logsource_product":  true,
				"logsource_service":  true,
			},
			expectBSON: map[string]bool{
				"sigma_yaml":         false,
				"logsource_category": true,
				"logsource_product":  true,
				"logsource_service":  true,
			},
		},
		{
			name: "partial logsource fields",
			rule: Rule{
				ID:                "mixed-3",
				Name:              "Partial Logsource",
				Severity:          "high",
				SigmaYAML:         "title: Partial",
				LogsourceCategory: "process",
				// Product and Service omitted
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			expectJSON: map[string]bool{
				"sigma_yaml":         true,
				"logsource_category": true,
				"logsource_product":  false,
				"logsource_service":  false,
			},
			expectBSON: map[string]bool{
				"sigma_yaml":         true,
				"logsource_category": true,
				"logsource_product":  false,
				"logsource_service":  false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test JSON
			jsonData, err := json.Marshal(tc.rule)
			require.NoError(t, err)
			jsonStr := string(jsonData)

			for field, shouldExist := range tc.expectJSON {
				if shouldExist {
					assert.Contains(t, jsonStr, field, "JSON should contain %s", field)
				} else {
					// Check that field is not present with a value
					assert.NotContains(t, jsonStr, `"`+field+`":"`, "JSON should not contain %s with value", field)
				}
			}

			// Test BSON
			bsonData, err := bson.Marshal(tc.rule)
			require.NoError(t, err)

			var result map[string]interface{}
			err = bson.Unmarshal(bsonData, &result)
			require.NoError(t, err)

			for field, shouldExist := range tc.expectBSON {
				if shouldExist {
					assert.Contains(t, result, field, "BSON should contain %s", field)
				} else {
					assert.NotContains(t, result, field, "BSON should not contain %s", field)
				}
			}
		})
	}
}
