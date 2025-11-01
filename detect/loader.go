package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cerberus/core"
	"cerberus/storage"
	"github.com/xeipuuv/gojsonschema"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// compileRegexInRules compiles regex patterns in rules and returns only valid ones
func compileRegexInRules(rules []core.Rule, ruleType string, logger *zap.SugaredLogger) ([]core.Rule, error) {
	var validRules []core.Rule
	for _, rule := range rules {
		valid := true
		for j := range rule.Conditions {
			cond := &rule.Conditions[j]
			if cond.Operator == "regex" {
				if valStr, ok := cond.Value.(string); ok {
					regex, err := regexp.Compile(valStr)
					if err != nil {
						logger.Errorf("Invalid regex pattern in %s %s condition %d: %v, skipping rule", ruleType, rule.ID, j, err)
						valid = false
						break
					}
					cond.Regex = regex
				}
			}
		}
		if valid {
			validRules = append(validRules, rule)
		}
	}
	return validRules, nil
}

// compileRegexInCorrelationRules compiles regex patterns in correlation rules and returns only valid ones
func compileRegexInCorrelationRules(rules []core.CorrelationRule, ruleType string, logger *zap.SugaredLogger) ([]core.CorrelationRule, error) {
	var validRules []core.CorrelationRule
	for _, rule := range rules {
		valid := true
		for j := range rule.Conditions {
			cond := &rule.Conditions[j]
			if cond.Operator == "regex" {
				if valStr, ok := cond.Value.(string); ok {
					regex, err := regexp.Compile(valStr)
					if err != nil {
						logger.Errorf("Invalid regex pattern in %s %s condition %d: %v, skipping rule", ruleType, rule.ID, j, err)
						valid = false
						break
					}
					cond.Regex = regex
				}
			}
		}
		if valid {
			validRules = append(validRules, rule)
		}
	}
	return validRules, nil
}

// LoadRules loads rules from a JSON file
func LoadRules(filename string, logger *zap.SugaredLogger) ([]core.Rule, error) {
	return loadRulesFromFile(filename, logger)
}

// LoadCorrelationRules loads correlation rules from a JSON file
func LoadCorrelationRules(filename string, logger *zap.SugaredLogger) ([]core.CorrelationRule, error) {
	return loadCorrelationRulesFromFile(filename, logger)
}

// LoadRulesFromDB loads rules from MongoDB
func LoadRulesFromDB(ruleStorage *storage.RuleStorage) ([]core.Rule, error) {
	return ruleStorage.GetRules()
}

// loadRulesFromFile loads rules from a JSON file (internal)
func loadRulesFromFile(filename string, logger *zap.SugaredLogger) ([]core.Rule, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	// Validate against JSON schema (optional)
	// Assume schema is in the same directory as the rules file
	schemaFilename := filepath.Join(filepath.Dir(filename), "rules_schema.json")
	schemaData, err := os.ReadFile(schemaFilename)
	if err != nil {
		logger.Warnf("Schema file not found, skipping validation: %v", err)
	} else {
		schemaLoader := gojsonschema.NewBytesLoader(schemaData)
		documentLoader := gojsonschema.NewBytesLoader(data)

		result, err := gojsonschema.Validate(schemaLoader, documentLoader)
		if err != nil {
			return nil, fmt.Errorf("failed to validate rules against schema: %w", err)
		}
		if !result.Valid() {
			return nil, fmt.Errorf("rules validation failed: %v", result.Errors())
		}
	}

	var rules core.Rules
	if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
		err = yaml.Unmarshal(data, &rules)
	} else {
		err = json.Unmarshal(data, &rules)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	// Compile regex patterns
	rules.Rules, err = compileRegexInRules(rules.Rules, "rule", logger)
	if err != nil {
		return nil, err
	}

	// Validate rules
	for _, rule := range rules.Rules {
		if rule.ID == "" {
			return nil, fmt.Errorf("rule missing ID")
		}
		if len(rule.Conditions) == 0 {
			logger.Warnf("Warning: rule %s has no conditions", rule.ID)
		}
	}

	logger.Infof("Loaded %d rules from %s", len(rules.Rules), filename)
	return rules.Rules, nil
}

// loadCorrelationRulesFromFile loads correlation rules from a JSON file (internal)
func loadCorrelationRulesFromFile(filename string, logger *zap.SugaredLogger) ([]core.CorrelationRule, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read correlation rules file: %w", err)
	}

	// Validate against JSON schema (optional)
	if !strings.HasSuffix(filename, ".yaml") && !strings.HasSuffix(filename, ".yml") {
		schemaFilename := filepath.Join(filepath.Dir(filename), "correlation_rules_schema.json")
		schemaData, err := os.ReadFile(schemaFilename)
		if err != nil {
			logger.Warnf("Schema file not found, skipping validation: %v", err)
		} else {
			schemaLoader := gojsonschema.NewBytesLoader(schemaData)
			documentLoader := gojsonschema.NewBytesLoader(data)

			result, err := gojsonschema.Validate(schemaLoader, documentLoader)
			if err != nil {
				return nil, fmt.Errorf("failed to validate correlation rules against schema: %w", err)
			}
			if !result.Valid() {
				var errors []string
				for _, desc := range result.Errors() {
					errors = append(errors, desc.String())
				}
				return nil, fmt.Errorf("correlation rules validation failed: %s", strings.Join(errors, "; "))
			}
		}
	} else {
		logger.Warnf("Schema validation skipped for YAML file: %s", filename)
	}

	var rules core.CorrelationRules
	if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
		err = yaml.Unmarshal(data, &rules)
	} else {
		err = json.Unmarshal(data, &rules)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal correlation rules: %w", err)
	}

	// Compile regex patterns
	rules.Rules, err = compileRegexInCorrelationRules(rules.Rules, "correlation rule", logger)
	if err != nil {
		return nil, err
	}

	// Validate rules
	for _, rule := range rules.Rules {
		if rule.ID == "" {
			return nil, fmt.Errorf("correlation rule missing ID")
		}
		if len(rule.Sequence) == 0 {
			logger.Warnf("Warning: correlation rule %s has no sequence", rule.ID)
		}
	}

	logger.Infof("Loaded %d correlation rules from %s", len(rules.Rules), filename)
	return rules.Rules, nil
}
