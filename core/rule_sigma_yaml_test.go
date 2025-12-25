package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

// TestRule_SigmaYAML_JSONMarshal verifies that SigmaYAML field marshals correctly to JSON
func TestRule_SigmaYAML_JSONMarshal(t *testing.T) {
	sigmaYAML := `title: Test Rule
id: test-123
status: experimental
description: Test SIGMA rule
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection`

	rule := Rule{
		ID:                "test-rule",
		Name:              "Test Rule",
		Type:              "sigma",
		Severity:          "high",
		SigmaYAML:         sigmaYAML,
		LogsourceCategory: "process_creation",
		LogsourceProduct:  "windows",
		LogsourceService:  "sysmon",
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	data, err := json.Marshal(rule)
	require.NoError(t, err, "JSON marshal should succeed")
	require.NotEmpty(t, data, "Marshaled data should not be empty")

	// Verify the marshaled JSON contains our fields
	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"sigma_yaml"`, "JSON should contain sigma_yaml field")
	assert.Contains(t, jsonStr, `"logsource_category":"process_creation"`, "JSON should contain logsource_category")
	assert.Contains(t, jsonStr, `"logsource_product":"windows"`, "JSON should contain logsource_product")
	assert.Contains(t, jsonStr, `"logsource_service":"sysmon"`, "JSON should contain logsource_service")
	assert.Contains(t, jsonStr, `title: Test Rule`, "JSON should contain YAML content")
}

// TestRule_SigmaYAML_JSONUnmarshal verifies that SigmaYAML field unmarshals correctly from JSON
func TestRule_SigmaYAML_JSONUnmarshal(t *testing.T) {
	sigmaYAML := `title: Test Rule
id: test-123
status: experimental
description: Test SIGMA rule
logsource:
  category: network_connection
  product: linux
  service: auditd
detection:
  selection:
    EventID: 3
  condition: selection`

	jsonData := `{
		"id": "test-rule-unmarshal",
		"type": "sigma",
		"name": "Test Unmarshal",
		"severity": "medium",
		"sigma_yaml": "` + strings.ReplaceAll(sigmaYAML, "\n", "\\n") + `",
		"logsource_category": "network_connection",
		"logsource_product": "linux",
		"logsource_service": "auditd",
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z"
	}`

	var rule Rule
	err := json.Unmarshal([]byte(jsonData), &rule)
	require.NoError(t, err, "JSON unmarshal should succeed")

	assert.Equal(t, "test-rule-unmarshal", rule.ID, "ID should match")
	assert.Equal(t, "sigma", rule.Type, "Type should match")
	assert.Equal(t, sigmaYAML, rule.SigmaYAML, "SigmaYAML should match")
	assert.Equal(t, "network_connection", rule.LogsourceCategory, "LogsourceCategory should match")
	assert.Equal(t, "linux", rule.LogsourceProduct, "LogsourceProduct should match")
	assert.Equal(t, "auditd", rule.LogsourceService, "LogsourceService should match")
}

// TestRule_SigmaYAML_JSONRoundTrip verifies full round-trip JSON marshaling/unmarshaling
func TestRule_SigmaYAML_JSONRoundTrip(t *testing.T) {
	originalRule := Rule{
		ID:                "roundtrip-test",
		Type:              "sigma",
		Name:              "Round Trip Test",
		Description:       "Tests round-trip serialization",
		Severity:          "critical",
		Version:           1,
		Tags:              []string{"test", "roundtrip"},
		MitreTactics:      []string{"TA0001"},
		MitreTechniques:   []string{"T1059"},
		Author:            "Test Author",
		SigmaYAML:         "title: Round Trip\nid: rt-123\ndetection:\n  selection:\n    field: value\n  condition: selection",
		LogsourceCategory: "process_creation",
		LogsourceProduct:  "windows",
		LogsourceService:  "security",
		Enabled:           true,
		CreatedAt:         time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC),
	}

	// Marshal to JSON
	data, err := json.Marshal(originalRule)
	require.NoError(t, err, "Marshal should succeed")

	// Unmarshal back to struct
	var decodedRule Rule
	err = json.Unmarshal(data, &decodedRule)
	require.NoError(t, err, "Unmarshal should succeed")

	// Verify all new fields match
	assert.Equal(t, originalRule.SigmaYAML, decodedRule.SigmaYAML, "SigmaYAML should match after round-trip")
	assert.Equal(t, originalRule.LogsourceCategory, decodedRule.LogsourceCategory, "LogsourceCategory should match")
	assert.Equal(t, originalRule.LogsourceProduct, decodedRule.LogsourceProduct, "LogsourceProduct should match")
	assert.Equal(t, originalRule.LogsourceService, decodedRule.LogsourceService, "LogsourceService should match")

	// Verify other important fields
	assert.Equal(t, originalRule.ID, decodedRule.ID, "ID should match")
	assert.Equal(t, originalRule.Type, decodedRule.Type, "Type should match")
	assert.Equal(t, originalRule.Severity, decodedRule.Severity, "Severity should match")
}

// TestRule_SigmaYAML_BSONMarshal verifies that SigmaYAML field marshals correctly to BSON
func TestRule_SigmaYAML_BSONMarshal(t *testing.T) {
	sigmaYAML := `title: BSON Test
id: bson-123
status: stable
description: BSON marshaling test
logsource:
  category: file_event
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 11
  condition: selection`

	rule := Rule{
		ID:                "bson-test-rule",
		Type:              "sigma",
		Name:              "BSON Test",
		Severity:          "low",
		SigmaYAML:         sigmaYAML,
		LogsourceCategory: "file_event",
		LogsourceProduct:  "windows",
		LogsourceService:  "sysmon",
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	data, err := bson.Marshal(rule)
	require.NoError(t, err, "BSON marshal should succeed")
	require.NotEmpty(t, data, "Marshaled BSON data should not be empty")

	// Unmarshal to verify structure
	var result map[string]interface{}
	err = bson.Unmarshal(data, &result)
	require.NoError(t, err, "BSON unmarshal to map should succeed")

	// Verify fields exist in BSON
	assert.Contains(t, result, "sigma_yaml", "BSON should contain sigma_yaml field")
	assert.Contains(t, result, "logsource_category", "BSON should contain logsource_category")
	assert.Contains(t, result, "logsource_product", "BSON should contain logsource_product")
	assert.Contains(t, result, "logsource_service", "BSON should contain logsource_service")

	// Verify values
	assert.Equal(t, sigmaYAML, result["sigma_yaml"], "SigmaYAML value should match")
	assert.Equal(t, "file_event", result["logsource_category"], "LogsourceCategory value should match")
	assert.Equal(t, "windows", result["logsource_product"], "LogsourceProduct value should match")
	assert.Equal(t, "sysmon", result["logsource_service"], "LogsourceService value should match")
}

// TestRule_SigmaYAML_BSONUnmarshal verifies that SigmaYAML field unmarshals correctly from BSON
func TestRule_SigmaYAML_BSONUnmarshal(t *testing.T) {
	sigmaYAML := `title: BSON Unmarshal Test
id: bson-unmarshal-123
status: test
description: Testing BSON unmarshaling
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject: 'HKLM\Software\Test'
  condition: selection`

	// Create a BSON document with our new fields
	bsonDoc := bson.M{
		"_id":                "bson-unmarshal-test",
		"type":               "sigma",
		"name":               "BSON Unmarshal Test",
		"severity":           "high",
		"sigma_yaml":         sigmaYAML,
		"logsource_category": "registry_event",
		"logsource_product":  "windows",
		"logsource_service":  "sysmon",
		"enabled":            true,
		"created_at":         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		"updated_at":         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	data, err := bson.Marshal(bsonDoc)
	require.NoError(t, err, "BSON marshal should succeed")

	var rule Rule
	err = bson.Unmarshal(data, &rule)
	require.NoError(t, err, "BSON unmarshal should succeed")

	assert.Equal(t, "bson-unmarshal-test", rule.ID, "ID should match")
	assert.Equal(t, "sigma", rule.Type, "Type should match")
	assert.Equal(t, sigmaYAML, rule.SigmaYAML, "SigmaYAML should match")
	assert.Equal(t, "registry_event", rule.LogsourceCategory, "LogsourceCategory should match")
	assert.Equal(t, "windows", rule.LogsourceProduct, "LogsourceProduct should match")
	assert.Equal(t, "sysmon", rule.LogsourceService, "LogsourceService should match")
}

// TestRule_SigmaYAML_BSONRoundTrip verifies full round-trip BSON marshaling/unmarshaling
func TestRule_SigmaYAML_BSONRoundTrip(t *testing.T) {
	originalRule := Rule{
		ID:                "bson-roundtrip",
		Type:              "sigma",
		Name:              "BSON Round Trip",
		Description:       "Tests BSON round-trip",
		Severity:          "medium",
		Version:           2,
		SigmaYAML:         "title: BSON RT\nid: brt-456\ndetection:\n  sel:\n    key: val\n  condition: sel",
		LogsourceCategory: "dns_query",
		LogsourceProduct:  "windows",
		LogsourceService:  "dns-client",
		Enabled:           false,
		CreatedAt:         time.Date(2024, 2, 1, 12, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2024, 2, 2, 12, 0, 0, 0, time.UTC),
	}

	// Marshal to BSON
	data, err := bson.Marshal(originalRule)
	require.NoError(t, err, "BSON marshal should succeed")

	// Unmarshal back
	var decodedRule Rule
	err = bson.Unmarshal(data, &decodedRule)
	require.NoError(t, err, "BSON unmarshal should succeed")

	// Verify new fields
	assert.Equal(t, originalRule.SigmaYAML, decodedRule.SigmaYAML, "SigmaYAML should match")
	assert.Equal(t, originalRule.LogsourceCategory, decodedRule.LogsourceCategory, "LogsourceCategory should match")
	assert.Equal(t, originalRule.LogsourceProduct, decodedRule.LogsourceProduct, "LogsourceProduct should match")
	assert.Equal(t, originalRule.LogsourceService, decodedRule.LogsourceService, "LogsourceService should match")
	assert.Equal(t, originalRule.ID, decodedRule.ID, "ID should match")
	assert.Equal(t, originalRule.Enabled, decodedRule.Enabled, "Enabled should match")
}

// TestRule_SigmaYAML_Omitempty_JSON verifies omitempty behavior for empty fields in JSON
func TestRule_SigmaYAML_Omitempty_JSON(t *testing.T) {
	tests := []struct {
		name             string
		rule             Rule
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			name: "all fields populated",
			rule: Rule{
				ID:                "test-1",
				Type:              "sigma",
				Name:              "Test",
				Severity:          "high",
				SigmaYAML:         "title: Test",
				LogsourceCategory: "process_creation",
				LogsourceProduct:  "windows",
				LogsourceService:  "sysmon",
				CreatedAt:         time.Now().UTC(),
				UpdatedAt:         time.Now().UTC(),
			},
			shouldContain:    []string{"sigma_yaml", "logsource_category", "logsource_product", "logsource_service"},
			shouldNotContain: []string{},
		},
		{
			name: "empty sigma_yaml",
			rule: Rule{
				ID:                "test-2",
				Type:              "cql",
				Name:              "Test CQL",
				Severity:          "low",
				LogsourceCategory: "network",
				CreatedAt:         time.Now().UTC(),
				UpdatedAt:         time.Now().UTC(),
			},
			shouldContain:    []string{"logsource_category"},
			shouldNotContain: []string{`"sigma_yaml":""`},
		},
		{
			name: "all logsource fields empty",
			rule: Rule{
				ID:        "test-3",
				Type:      "cql",
				Name:      "No Logsource",
				Severity:  "info",
				SigmaYAML: "title: Test",
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			},
			shouldContain:    []string{"sigma_yaml"},
			shouldNotContain: []string{`"logsource_category":""`, `"logsource_product":""`, `"logsource_service":""`},
		},
		{
			name: "all new fields empty",
			rule: Rule{
				ID:        "test-4",
				Type:      "cql",
				Name:      "All Empty",
				Severity:  "info",
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			},
			shouldContain:    []string{},
			shouldNotContain: []string{`"sigma_yaml":""`, `"logsource_category":""`, `"logsource_product":""`, `"logsource_service":""`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.rule)
			require.NoError(t, err, "Marshal should succeed")

			jsonStr := string(data)
			for _, shouldContain := range tt.shouldContain {
				assert.Contains(t, jsonStr, shouldContain, "JSON should contain %s", shouldContain)
			}
			for _, shouldNotContain := range tt.shouldNotContain {
				assert.NotContains(t, jsonStr, shouldNotContain, "JSON should not contain %s", shouldNotContain)
			}
		})
	}
}

// TestRule_SigmaYAML_Omitempty_BSON verifies omitempty behavior for empty fields in BSON
func TestRule_SigmaYAML_Omitempty_BSON(t *testing.T) {
	tests := []struct {
		name              string
		rule              Rule
		shouldHaveKeys    []string
		shouldNotHaveKeys []string
	}{
		{
			name: "all fields populated",
			rule: Rule{
				ID:                "test-1",
				Type:              "sigma",
				Name:              "Test",
				Severity:          "high",
				SigmaYAML:         "title: Test",
				LogsourceCategory: "process_creation",
				LogsourceProduct:  "windows",
				LogsourceService:  "sysmon",
				CreatedAt:         time.Now().UTC(),
				UpdatedAt:         time.Now().UTC(),
			},
			shouldHaveKeys:    []string{"sigma_yaml", "logsource_category", "logsource_product", "logsource_service"},
			shouldNotHaveKeys: []string{},
		},
		{
			name: "empty sigma_yaml",
			rule: Rule{
				ID:                "test-2",
				Type:              "cql",
				Name:              "Test CQL",
				Severity:          "low",
				LogsourceCategory: "network",
				CreatedAt:         time.Now().UTC(),
				UpdatedAt:         time.Now().UTC(),
			},
			shouldHaveKeys:    []string{"logsource_category"},
			shouldNotHaveKeys: []string{"sigma_yaml"},
		},
		{
			name: "all new fields empty",
			rule: Rule{
				ID:        "test-3",
				Type:      "cql",
				Name:      "All Empty",
				Severity:  "info",
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			},
			shouldHaveKeys:    []string{},
			shouldNotHaveKeys: []string{"sigma_yaml", "logsource_category", "logsource_product", "logsource_service"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := bson.Marshal(tt.rule)
			require.NoError(t, err, "BSON marshal should succeed")

			var result map[string]interface{}
			err = bson.Unmarshal(data, &result)
			require.NoError(t, err, "BSON unmarshal should succeed")

			for _, key := range tt.shouldHaveKeys {
				assert.Contains(t, result, key, "BSON should have key %s", key)
			}
			for _, key := range tt.shouldNotHaveKeys {
				assert.NotContains(t, result, key, "BSON should not have key %s", key)
			}
		})
	}
}

// TestRule_SigmaYAML_SpecialCharacters tests handling of special characters in YAML
func TestRule_SigmaYAML_SpecialCharacters(t *testing.T) {
	specialYAML := `title: Special Characters Test
id: special-123
description: |
  Tests special characters: "quotes", 'apostrophes', \backslashes\
  Unicode: 日本語 emoji: 🔥
  Newlines and tabs:	indented
logsource:
  category: test
  product: "product with spaces"
  service: 'service-with-dashes'
detection:
  selection:
    CommandLine|contains:
      - 'cmd.exe /c "test"'
      - "powershell -enc $(base64)"
      - 'path\to\file.exe'
  condition: selection`

	rule := Rule{
		ID:                "special-char-test",
		Type:              "sigma",
		Name:              "Special Chars",
		Severity:          "test",
		SigmaYAML:         specialYAML,
		LogsourceCategory: "test",
		LogsourceProduct:  "product with spaces",
		LogsourceService:  "service-with-dashes",
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	// Test JSON round-trip
	jsonData, err := json.Marshal(rule)
	require.NoError(t, err, "JSON marshal should handle special characters")

	var jsonRule Rule
	err = json.Unmarshal(jsonData, &jsonRule)
	require.NoError(t, err, "JSON unmarshal should handle special characters")
	assert.Equal(t, specialYAML, jsonRule.SigmaYAML, "Special characters should survive JSON round-trip")

	// Test BSON round-trip
	bsonData, err := bson.Marshal(rule)
	require.NoError(t, err, "BSON marshal should handle special characters")

	var bsonRule Rule
	err = bson.Unmarshal(bsonData, &bsonRule)
	require.NoError(t, err, "BSON unmarshal should handle special characters")
	assert.Equal(t, specialYAML, bsonRule.SigmaYAML, "Special characters should survive BSON round-trip")
}

// TestRule_SigmaYAML_LargeYAML tests handling of large YAML content
func TestRule_SigmaYAML_LargeYAML(t *testing.T) {
	// Generate a large YAML with many detection conditions
	var yamlBuilder strings.Builder
	yamlBuilder.WriteString("title: Large YAML Test\nid: large-123\ndetection:\n")

	for i := 0; i < 100; i++ {
		yamlBuilder.WriteString("  selection_")
		yamlBuilder.WriteString(strings.Repeat("x", i%10))
		yamlBuilder.WriteString(":\n    field")
		yamlBuilder.WriteString(strings.Repeat("_", i%5))
		yamlBuilder.WriteString(": value")
		yamlBuilder.WriteString(strings.Repeat("y", i%8))
		yamlBuilder.WriteString("\n")
	}
	yamlBuilder.WriteString("  condition: 1 of selection_*")

	largeYAML := yamlBuilder.String()

	rule := Rule{
		ID:                "large-yaml-test",
		Type:              "sigma",
		Name:              "Large YAML",
		Severity:          "test",
		SigmaYAML:         largeYAML,
		LogsourceCategory: "test",
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	// Test JSON round-trip
	jsonData, err := json.Marshal(rule)
	require.NoError(t, err, "JSON marshal should handle large YAML")
	require.True(t, len(jsonData) > 1000, "Large YAML should produce substantial JSON")

	var jsonRule Rule
	err = json.Unmarshal(jsonData, &jsonRule)
	require.NoError(t, err, "JSON unmarshal should handle large YAML")
	assert.Equal(t, largeYAML, jsonRule.SigmaYAML, "Large YAML should survive JSON round-trip")

	// Test BSON round-trip
	bsonData, err := bson.Marshal(rule)
	require.NoError(t, err, "BSON marshal should handle large YAML")

	var bsonRule Rule
	err = bson.Unmarshal(bsonData, &bsonRule)
	require.NoError(t, err, "BSON unmarshal should handle large YAML")
	assert.Equal(t, largeYAML, bsonRule.SigmaYAML, "Large YAML should survive BSON round-trip")
}

// TestRule_SigmaYAML_NilValues tests handling of nil/zero values
func TestRule_SigmaYAML_NilValues(t *testing.T) {
	rule := Rule{
		ID:                "nil-test",
		Type:              "sigma",
		Name:              "Nil Test",
		Severity:          "test",
		SigmaYAML:         "",          // Empty string
		LogsourceCategory: "",          // Empty string
		LogsourceProduct:  "",          // Empty string
		LogsourceService:  "",          // Empty string
		CreatedAt:         time.Time{}, // Zero time
		UpdatedAt:         time.Time{}, // Zero time
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(rule)
	require.NoError(t, err, "JSON marshal should handle empty values")

	var jsonRule Rule
	err = json.Unmarshal(jsonData, &jsonRule)
	require.NoError(t, err, "JSON unmarshal should handle empty values")

	// Empty strings should be preserved as empty, not nil
	assert.Equal(t, "", jsonRule.SigmaYAML, "Empty SigmaYAML should remain empty")
	assert.Equal(t, "", jsonRule.LogsourceCategory, "Empty LogsourceCategory should remain empty")
	assert.Equal(t, "", jsonRule.LogsourceProduct, "Empty LogsourceProduct should remain empty")
	assert.Equal(t, "", jsonRule.LogsourceService, "Empty LogsourceService should remain empty")

	// Test BSON marshaling
	bsonData, err := bson.Marshal(rule)
	require.NoError(t, err, "BSON marshal should handle empty values")

	var bsonRule Rule
	err = bson.Unmarshal(bsonData, &bsonRule)
	require.NoError(t, err, "BSON unmarshal should handle empty values")

	assert.Equal(t, "", bsonRule.SigmaYAML, "Empty SigmaYAML should remain empty in BSON")
	assert.Equal(t, "", bsonRule.LogsourceCategory, "Empty LogsourceCategory should remain empty in BSON")
	assert.Equal(t, "", bsonRule.LogsourceProduct, "Empty LogsourceProduct should remain empty in BSON")
	assert.Equal(t, "", bsonRule.LogsourceService, "Empty LogsourceService should remain empty in BSON")
}

// TestRule_SigmaYAML_StructInstantiation verifies struct can be instantiated with new fields
func TestRule_SigmaYAML_StructInstantiation(t *testing.T) {
	// Test various ways of instantiating the struct
	t.Run("struct literal with all fields", func(t *testing.T) {
		rule := Rule{
			ID:                "test-1",
			Type:              "sigma",
			Name:              "Test Rule",
			Severity:          "high",
			SigmaYAML:         "title: Test",
			LogsourceCategory: "process_creation",
			LogsourceProduct:  "windows",
			LogsourceService:  "sysmon",
		}
		assert.Equal(t, "title: Test", rule.SigmaYAML)
		assert.Equal(t, "process_creation", rule.LogsourceCategory)
		assert.Equal(t, "windows", rule.LogsourceProduct)
		assert.Equal(t, "sysmon", rule.LogsourceService)
	})

	t.Run("zero value struct", func(t *testing.T) {
		var rule Rule
		assert.Equal(t, "", rule.SigmaYAML)
		assert.Equal(t, "", rule.LogsourceCategory)
		assert.Equal(t, "", rule.LogsourceProduct)
		assert.Equal(t, "", rule.LogsourceService)
	})

	t.Run("pointer to struct", func(t *testing.T) {
		rule := &Rule{
			ID:                "test-2",
			SigmaYAML:         "title: Pointer Test",
			LogsourceCategory: "network_connection",
		}
		assert.NotNil(t, rule)
		assert.Equal(t, "title: Pointer Test", rule.SigmaYAML)
		assert.Equal(t, "network_connection", rule.LogsourceCategory)
	})

	t.Run("partial initialization", func(t *testing.T) {
		rule := Rule{
			ID:        "test-3",
			SigmaYAML: "title: Partial",
			// Omit logsource fields - they should default to empty strings
		}
		assert.Equal(t, "title: Partial", rule.SigmaYAML)
		assert.Equal(t, "", rule.LogsourceCategory)
		assert.Equal(t, "", rule.LogsourceProduct)
		assert.Equal(t, "", rule.LogsourceService)
	})
}

// TestRule_SigmaYAML_ConcurrentAccess tests thread-safe access to new fields
func TestRule_SigmaYAML_ConcurrentAccess(t *testing.T) {
	rule := Rule{
		ID:                "concurrent-test",
		Type:              "sigma",
		Name:              "Concurrent Test",
		Severity:          "high",
		SigmaYAML:         "title: Original",
		LogsourceCategory: "original_category",
		LogsourceProduct:  "original_product",
		LogsourceService:  "original_service",
	}

	// Test concurrent reads (should be safe)
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			yaml := rule.SigmaYAML
			category := rule.LogsourceCategory
			product := rule.LogsourceProduct
			service := rule.LogsourceService

			assert.NotEmpty(t, yaml, "SigmaYAML should be readable")
			assert.NotEmpty(t, category, "LogsourceCategory should be readable")
			assert.NotEmpty(t, product, "LogsourceProduct should be readable")
			assert.NotEmpty(t, service, "LogsourceService should be readable")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestRule_SigmaYAML_MultipleYAMLFormats tests various valid YAML formats
func TestRule_SigmaYAML_MultipleYAMLFormats(t *testing.T) {
	testCases := []struct {
		name     string
		yaml     string
		category string
		product  string
		service  string
	}{
		{
			name:     "flow style",
			yaml:     "title: Flow\ndetection: {selection: {field: value}, condition: selection}",
			category: "test",
			product:  "test",
			service:  "test",
		},
		{
			name: "block style",
			yaml: `title: Block
detection:
  selection:
    field: value
  condition: selection`,
			category: "process_creation",
			product:  "windows",
			service:  "sysmon",
		},
		{
			name: "multiline strings",
			yaml: `title: Multiline
description: |
  This is a multiline
  description that spans
  multiple lines
detection:
  selection:
    field: value
  condition: selection`,
			category: "network",
			product:  "linux",
			service:  "auditd",
		},
		{
			name: "arrays",
			yaml: `title: Arrays
tags: [tag1, tag2, tag3]
logsource:
  category: test
  product: [product1, product2]
detection:
  selection:
    field:
      - value1
      - value2
  condition: selection`,
			category: "test",
			product:  "test",
			service:  "test",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := Rule{
				ID:                "yaml-format-test",
				Type:              "sigma",
				Name:              tc.name,
				Severity:          "test",
				SigmaYAML:         tc.yaml,
				LogsourceCategory: tc.category,
				LogsourceProduct:  tc.product,
				LogsourceService:  tc.service,
				CreatedAt:         time.Now().UTC(),
				UpdatedAt:         time.Now().UTC(),
			}

			// Test JSON round-trip
			jsonData, err := json.Marshal(rule)
			require.NoError(t, err, "JSON marshal should succeed for %s", tc.name)

			var jsonRule Rule
			err = json.Unmarshal(jsonData, &jsonRule)
			require.NoError(t, err, "JSON unmarshal should succeed for %s", tc.name)
			assert.Equal(t, tc.yaml, jsonRule.SigmaYAML, "YAML should survive JSON round-trip for %s", tc.name)

			// Test BSON round-trip
			bsonData, err := bson.Marshal(rule)
			require.NoError(t, err, "BSON marshal should succeed for %s", tc.name)

			var bsonRule Rule
			err = bson.Unmarshal(bsonData, &bsonRule)
			require.NoError(t, err, "BSON unmarshal should succeed for %s", tc.name)
			assert.Equal(t, tc.yaml, bsonRule.SigmaYAML, "YAML should survive BSON round-trip for %s", tc.name)
		})
	}
}
