package api

import (
	"testing"

	"cerberus/core"
)

// Standalone unit tests for Task 179 validation logic
// These tests don't require full API setup

// TASK #184: Skipped - Conditions field removed from core.Rule
func TestTask179_ValidateRuleForCreation_SigmaWithConditions(t *testing.T) {
	t.Skip("Conditions field removed in TASK #184 - rules now use SIGMA YAML")
}

func TestTask179_ValidateRuleForCreation_ValidSigma(t *testing.T) {
	rule := &core.Rule{
		Type:      "sigma",
		Name:      "Test Rule",
		SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
	}

	err := ValidateRuleForCreation(rule)
	if err != nil {
		t.Errorf("Unexpected error for valid SIGMA rule: %v", err)
	}
}

// TASK #184: Skipped - Conditions field removed from core.Rule
func TestTask179_ValidateRuleForCreation_DefaultTypeWithConditions(t *testing.T) {
	t.Skip("Conditions field removed in TASK #184 - rules now use SIGMA YAML")
}

func TestTask179_ValidateRuleForCreation_ValidCql(t *testing.T) {
	rule := &core.Rule{
		Type:  "cql",
		Name:  "Test CQL Rule",
		Query: "SELECT * FROM events WHERE action = 'failed_login'",
	}

	err := ValidateRuleForCreation(rule)
	if err != nil {
		t.Errorf("Unexpected error for valid CQL rule: %v", err)
	}
}

func TestTask179_ValidateRuleForCreation_CqlWithSigmaYaml(t *testing.T) {
	rule := &core.Rule{
		Type:      "cql",
		Name:      "Test CQL Rule",
		Query:     "SELECT * FROM events",
		SigmaYAML: "title: Test",
	}

	err := ValidateRuleForCreation(rule)
	if err == nil {
		t.Fatal("Expected error for CQL rule with sigma_yaml, got nil")
	}

	// Error message includes rule name prefix
	expectedMsg := "rule 'Test CQL Rule': CQL rules cannot have sigma_yaml field (use query)"
	if err.Error() != expectedMsg {
		t.Errorf("Got error %q, want %q", err.Error(), expectedMsg)
	}
}

func TestTask179_ValidateRuleForCreation_SigmaMissingSigmaYaml(t *testing.T) {
	rule := &core.Rule{
		Type: "sigma",
		Name: "Test Rule",
	}

	err := ValidateRuleForCreation(rule)
	if err == nil {
		t.Fatal("Expected error for SIGMA rule without sigma_yaml, got nil")
	}

	// Error message includes rule name prefix
	expectedMsg := "rule 'Test Rule': SIGMA rules must have sigma_yaml field populated"
	if err.Error() != expectedMsg {
		t.Errorf("Got error %q, want %q", err.Error(), expectedMsg)
	}
}

func TestTask179_ValidateRuleForCreation_CqlMissingQuery(t *testing.T) {
	rule := &core.Rule{
		Type: "cql",
		Name: "Test CQL Rule",
	}

	err := ValidateRuleForCreation(rule)
	if err == nil {
		t.Fatal("Expected error for CQL rule without query, got nil")
	}

	// Error message includes rule name prefix
	expectedMsg := "rule 'Test CQL Rule': CQL rules must have query field populated"
	if err.Error() != expectedMsg {
		t.Errorf("Got error %q, want %q", err.Error(), expectedMsg)
	}
}

func TestTask179_ValidateRuleForCreation_NilRule(t *testing.T) {
	err := ValidateRuleForCreation(nil)
	if err == nil {
		t.Fatal("Expected error for nil rule, got nil")
	}

	expectedMsg := "cannot validate nil rule"
	if err.Error() != expectedMsg {
		t.Errorf("Got error %q, want %q", err.Error(), expectedMsg)
	}
}

func TestTask179_ValidateRuleForCreation_CorrelationRule(t *testing.T) {
	rule := &core.Rule{
		Type: "correlation",
		Name: "Test Correlation Rule",
	}

	// Correlation rules should pass through (they use separate validation)
	err := ValidateRuleForCreation(rule)
	if err != nil {
		t.Errorf("Unexpected error for correlation rule: %v", err)
	}
}

func TestTask179_ValidateRuleForCreation_InvalidType(t *testing.T) {
	rule := &core.Rule{
		Type: "invalid_type",
		Name: "Test Rule",
	}

	err := ValidateRuleForCreation(rule)
	if err == nil {
		t.Fatal("Expected error for invalid rule type, got nil")
	}

	// Error message includes rule name prefix and uppercase type
	expected := "rule 'Test Rule': invalid rule type: INVALID_TYPE (must be SIGMA, CQL, or CORRELATION)"
	if err.Error() != expected {
		t.Errorf("Got unexpected error: %v", err)
	}
}
