package detect

import (
	"os"
	"testing"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestLoadRules_JSON(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	rules, err := LoadRules("../rules.json", sugar)
	assert.NoError(t, err)
	assert.Len(t, rules, 2)
	assert.Equal(t, "failed_login", rules[0].ID)
	assert.Equal(t, "admin_access", rules[1].ID)
}

func TestLoadRules_FileNotFound(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	_, err := LoadRules("nonexistent.json", sugar)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read rules file")
}

func TestLoadRules_InvalidJSON(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Create a temporary invalid JSON file
	tempFile := "/tmp/invalid_rules.json"
	defer os.Remove(tempFile)

	err := os.WriteFile(tempFile, []byte("invalid json"), 0644)
	assert.NoError(t, err)

	_, err = LoadRules(tempFile, sugar)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal rules")
}

func TestLoadCorrelationRules_JSON(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	rules, err := LoadCorrelationRules("../correlation_rules.json", sugar)
	assert.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.Equal(t, "brute_force", rules[0].ID)
}

func TestLoadCorrelationRules_FileNotFound(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	_, err := LoadCorrelationRules("nonexistent.json", sugar)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read correlation rules file")
}

func TestLoadCorrelationRules_InvalidJSON(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Create a temporary invalid JSON file
	tempFile := "/tmp/invalid_correlation_rules.json"
	defer os.Remove(tempFile)

	err := os.WriteFile(tempFile, []byte("invalid json"), 0644)
	assert.NoError(t, err)

	_, err = LoadCorrelationRules(tempFile, sugar)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal correlation rules")
}

func TestCompileRegexInRules_InvalidRegex(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	rules := []core.Rule{
		{
			ID: "test",
			Conditions: []core.Condition{
				{
					Field:    "field",
					Operator: "regex",
					Value:    "[invalid regex",
				},
			},
		},
	}

	validRules, err := compileRegexInRules(rules, "rule", sugar)
	assert.NoError(t, err)
	assert.Len(t, validRules, 0)
}

func TestCompileRegexInCorrelationRules_InvalidRegex(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	rules := []core.CorrelationRule{
		{
			ID: "test",
			Conditions: []core.Condition{
				{
					Field:    "field",
					Operator: "regex",
					Value:    "[invalid regex",
				},
			},
		},
	}

	validRules, err := compileRegexInCorrelationRules(rules, "correlation rule", sugar)
	assert.NoError(t, err)
	assert.Len(t, validRules, 0)
}

func TestLoadRulesFromFile_EmptyRules(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Create a temporary file with empty rules
	tempFile := "/tmp/empty_rules.json"
	defer os.Remove(tempFile)

	emptyRules := `{"rules": []}`
	err := os.WriteFile(tempFile, []byte(emptyRules), 0644)
	assert.NoError(t, err)

	rules, err := loadRulesFromFile(tempFile, sugar)
	assert.NoError(t, err)
	assert.Len(t, rules, 0)
}

func TestLoadRulesFromFile_MissingID(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Create a temporary file with rule missing ID
	tempFile := "/tmp/missing_id_rules.json"
	defer os.Remove(tempFile)

	invalidRules := `{"rules": [{"conditions": []}]}`
	err := os.WriteFile(tempFile, []byte(invalidRules), 0644)
	assert.NoError(t, err)

	_, err = loadRulesFromFile(tempFile, sugar)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rule missing ID")
}

func TestLoadCorrelationRulesFromFile_MissingID(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Create a temporary file with correlation rule missing ID
	tempFile := "/tmp/missing_id_correlation.json"
	defer os.Remove(tempFile)

	invalidRules := `{"rules": [{"sequence": ["event1", "event2"]}]}`
	err := os.WriteFile(tempFile, []byte(invalidRules), 0644)
	assert.NoError(t, err)

	_, err = loadCorrelationRulesFromFile(tempFile, sugar)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "correlation rule missing ID")
}

func TestLoadCorrelationRulesFromFile_EmptySequence(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Create a temporary file with correlation rule with empty sequence
	tempFile := "/tmp/empty_sequence_correlation.json"
	defer os.Remove(tempFile)

	invalidRules := `{"rules": [{"id": "test", "sequence": []}]}`
	err := os.WriteFile(tempFile, []byte(invalidRules), 0644)
	assert.NoError(t, err)

	rules, err := loadCorrelationRulesFromFile(tempFile, sugar)
	assert.NoError(t, err)
	assert.Len(t, rules, 1) // Should load but warn
}
