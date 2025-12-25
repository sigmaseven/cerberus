package core

import (
	"strings"
	"testing"
)

// TestRuleValidate_ValidSIGMA tests valid SIGMA rule scenarios
func TestRuleValidate_ValidSIGMA(t *testing.T) {
	tests := []struct {
		name      string
		rule      *Rule
		wantError bool
	}{
		{
			name: "valid SIGMA rule with sigma_yaml",
			rule: &Rule{
				Type:      "SIGMA",
				SigmaYAML: "title: Test Rule\ndetection:\n  selection:\n    field: value",
				Query:     "",
			},
			wantError: false,
		},
		{
			name: "valid SIGMA rule lowercase type",
			rule: &Rule{
				Type:      "sigma",
				SigmaYAML: "title: Test Rule",
				Query:     "",
			},
			wantError: false,
		},
		{
			name: "valid SIGMA rule mixed case type",
			rule: &Rule{
				Type:      "SiGmA",
				SigmaYAML: "title: Test Rule",
				Query:     "",
			},
			wantError: false,
		},
		{
			name: "valid SIGMA rule with whitespace in type",
			rule: &Rule{
				Type:      "  SIGMA  ",
				SigmaYAML: "title: Test Rule",
				Query:     "",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Rule.Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestRuleValidate_ValidCQL tests valid CQL rule scenarios
func TestRuleValidate_ValidCQL(t *testing.T) {
	tests := []struct {
		name      string
		rule      *Rule
		wantError bool
	}{
		{
			name: "valid CQL rule with query",
			rule: &Rule{
				Type:      "CQL",
				Query:     "event_type = 'login' AND status = 'failed'",
				SigmaYAML: "",
			},
			wantError: false,
		},
		{
			name: "valid CQL rule lowercase type",
			rule: &Rule{
				Type:      "cql",
				Query:     "event_type = 'login'",
				SigmaYAML: "",
			},
			wantError: false,
		},
		{
			name: "valid CQL rule mixed case type",
			rule: &Rule{
				Type:      "CqL",
				Query:     "SELECT * FROM events",
				SigmaYAML: "",
			},
			wantError: false,
		},
		{
			name: "valid CQL rule with whitespace in type",
			rule: &Rule{
				Type:      "  CQL  ",
				Query:     "event_type = 'test'",
				SigmaYAML: "",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Rule.Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestRuleValidate_SIGMAWithQuery tests SIGMA rules with query field (should fail)
func TestRuleValidate_SIGMAWithQuery(t *testing.T) {
	tests := []struct {
		name          string
		rule          *Rule
		wantError     bool
		errorContains string
	}{
		{
			name: "SIGMA rule with non-empty query",
			rule: &Rule{
				Type:      "SIGMA",
				SigmaYAML: "title: Test Rule",
				Query:     "event_type = 'test'",
			},
			wantError:     true,
			errorContains: "SIGMA rules must have sigma_yaml field and cannot have query field",
		},
		{
			name: "SIGMA rule with whitespace-only sigma_yaml",
			rule: &Rule{
				Type:      "SIGMA",
				SigmaYAML: "   ",
				Query:     "",
			},
			wantError:     true,
			errorContains: "SIGMA rules must have sigma_yaml field and cannot have query field",
		},
		{
			name: "SIGMA rule with non-empty query after trimming",
			rule: &Rule{
				Type:      "SIGMA",
				SigmaYAML: "title: Test",
				Query:     " query_content ",
			},
			wantError:     true,
			errorContains: "SIGMA rules must have sigma_yaml field and cannot have query field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Rule.Validate() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Rule.Validate() error = %v, want error containing %q", err, tt.errorContains)
				}
			}
		})
	}
}

// TestRuleValidate_SIGMAWithoutSigmaYAML tests SIGMA rules without sigma_yaml (should fail)
func TestRuleValidate_SIGMAWithoutSigmaYAML(t *testing.T) {
	tests := []struct {
		name          string
		rule          *Rule
		wantError     bool
		errorContains string
	}{
		{
			name: "SIGMA rule with empty sigma_yaml",
			rule: &Rule{
				Type:      "SIGMA",
				SigmaYAML: "",
				Query:     "",
			},
			wantError:     true,
			errorContains: "SIGMA rules must have sigma_yaml field and cannot have query field",
		},
		{
			name: "SIGMA rule with whitespace-only sigma_yaml",
			rule: &Rule{
				Type:      "SIGMA",
				SigmaYAML: "   \n\t  ",
				Query:     "",
			},
			wantError:     true,
			errorContains: "SIGMA rules must have sigma_yaml field and cannot have query field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Rule.Validate() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Rule.Validate() error = %v, want error containing %q", err, tt.errorContains)
				}
			}
		})
	}
}

// TestRuleValidate_CQLWithSigmaYAML tests CQL rules with sigma_yaml field (should fail)
func TestRuleValidate_CQLWithSigmaYAML(t *testing.T) {
	tests := []struct {
		name          string
		rule          *Rule
		wantError     bool
		errorContains string
	}{
		{
			name: "CQL rule with non-empty sigma_yaml",
			rule: &Rule{
				Type:      "CQL",
				Query:     "event_type = 'test'",
				SigmaYAML: "title: Test Rule",
			},
			wantError:     true,
			errorContains: "CQL rules must have query field and cannot have sigma_yaml field",
		},
		{
			name: "CQL rule with whitespace-only query",
			rule: &Rule{
				Type:      "CQL",
				Query:     "   ",
				SigmaYAML: "",
			},
			wantError:     true,
			errorContains: "CQL rules must have query field and cannot have sigma_yaml field",
		},
		{
			name: "CQL rule with sigma_yaml containing non-whitespace content",
			rule: &Rule{
				Type:      "CQL",
				Query:     "SELECT * FROM events",
				SigmaYAML: "  content  ",
			},
			wantError:     true,
			errorContains: "CQL rules must have query field and cannot have sigma_yaml field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Rule.Validate() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Rule.Validate() error = %v, want error containing %q", err, tt.errorContains)
				}
			}
		})
	}
}

// TestRuleValidate_CQLWithoutQuery tests CQL rules without query (should fail)
func TestRuleValidate_CQLWithoutQuery(t *testing.T) {
	tests := []struct {
		name          string
		rule          *Rule
		wantError     bool
		errorContains string
	}{
		{
			name: "CQL rule with empty query",
			rule: &Rule{
				Type:      "CQL",
				Query:     "",
				SigmaYAML: "",
			},
			wantError:     true,
			errorContains: "CQL rules must have query field and cannot have sigma_yaml field",
		},
		{
			name: "CQL rule with whitespace-only query",
			rule: &Rule{
				Type:      "CQL",
				Query:     "   \n\t  ",
				SigmaYAML: "",
			},
			wantError:     true,
			errorContains: "CQL rules must have query field and cannot have sigma_yaml field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Rule.Validate() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Rule.Validate() error = %v, want error containing %q", err, tt.errorContains)
				}
			}
		})
	}
}

// TestRuleValidate_CorrelationType tests correlation rule type (should skip validation)
func TestRuleValidate_CorrelationType(t *testing.T) {
	tests := []struct {
		name      string
		rule      *Rule
		wantError bool
	}{
		{
			name: "CORRELATION rule with no fields",
			rule: &Rule{
				Type:      "CORRELATION",
				Query:     "",
				SigmaYAML: "",
			},
			wantError: false,
		},
		{
			name: "CORRELATION rule with query",
			rule: &Rule{
				Type:      "CORRELATION",
				Query:     "some query",
				SigmaYAML: "",
			},
			wantError: false,
		},
		{
			name: "CORRELATION rule with sigma_yaml",
			rule: &Rule{
				Type:      "CORRELATION",
				Query:     "",
				SigmaYAML: "some yaml",
			},
			wantError: false,
		},
		{
			name: "CORRELATION rule with both fields",
			rule: &Rule{
				Type:      "CORRELATION",
				Query:     "some query",
				SigmaYAML: "some yaml",
			},
			wantError: false,
		},
		{
			name: "correlation rule lowercase",
			rule: &Rule{
				Type:      "correlation",
				Query:     "",
				SigmaYAML: "",
			},
			wantError: false,
		},
		{
			name: "correlation rule mixed case",
			rule: &Rule{
				Type:      "CoRrElAtIoN",
				Query:     "",
				SigmaYAML: "",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Rule.Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestRuleValidate_UnknownType tests unknown rule types (should fail)
func TestRuleValidate_UnknownType(t *testing.T) {
	tests := []struct {
		name          string
		rule          *Rule
		wantError     bool
		errorContains string
	}{
		{
			name: "unknown rule type",
			rule: &Rule{
				Type:      "UNKNOWN",
				Query:     "",
				SigmaYAML: "",
			},
			wantError:     true,
			errorContains: "unknown rule type: UNKNOWN",
		},
		{
			name: "invalid rule type",
			rule: &Rule{
				Type:      "INVALID_TYPE",
				Query:     "",
				SigmaYAML: "",
			},
			wantError:     true,
			errorContains: "unknown rule type: INVALID_TYPE",
		},
		{
			name: "numeric rule type",
			rule: &Rule{
				Type:      "12345",
				Query:     "",
				SigmaYAML: "",
			},
			wantError:     true,
			errorContains: "unknown rule type: 12345",
		},
		{
			name: "special characters in rule type",
			rule: &Rule{
				Type:      "SIGMA@CQL",
				Query:     "",
				SigmaYAML: "",
			},
			wantError:     true,
			errorContains: "unknown rule type: SIGMA@CQL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Rule.Validate() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Rule.Validate() error = %v, want error containing %q", err, tt.errorContains)
				}
			}
		})
	}
}

// TestRuleValidate_EmptyType tests empty rule type (should fail)
func TestRuleValidate_EmptyType(t *testing.T) {
	tests := []struct {
		name          string
		rule          *Rule
		wantError     bool
		errorContains string
	}{
		{
			name: "empty rule type",
			rule: &Rule{
				Type:      "",
				Query:     "",
				SigmaYAML: "",
			},
			wantError:     true,
			errorContains: "rule type cannot be empty",
		},
		{
			name: "whitespace-only rule type",
			rule: &Rule{
				Type:      "   \n\t  ",
				Query:     "",
				SigmaYAML: "",
			},
			wantError:     true,
			errorContains: "rule type cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Rule.Validate() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Rule.Validate() error = %v, want error containing %q", err, tt.errorContains)
				}
			}
		})
	}
}

// TestRuleValidate_NilRule tests nil rule pointer (should fail gracefully)
func TestRuleValidate_NilRule(t *testing.T) {
	var rule *Rule
	err := rule.Validate()
	if err == nil {
		t.Error("Rule.Validate() expected error for nil rule, got nil")
	}
	if !strings.Contains(err.Error(), "cannot validate nil rule") {
		t.Errorf("Rule.Validate() error = %v, want error containing 'cannot validate nil rule'", err)
	}
}

// TestRuleValidate_EdgeCases tests various edge cases
func TestRuleValidate_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		rule          *Rule
		wantError     bool
		errorContains string
	}{
		{
			name: "SIGMA rule with newlines in sigma_yaml",
			rule: &Rule{
				Type:      "SIGMA",
				SigmaYAML: "title: Test\ndetection:\n  selection:\n    field: value",
				Query:     "",
			},
			wantError: false,
		},
		{
			name: "CQL rule with complex query",
			rule: &Rule{
				Type:      "CQL",
				Query:     "event_type = 'login' AND (status = 'failed' OR status = 'denied') AND timestamp > NOW() - INTERVAL '1 hour'",
				SigmaYAML: "",
			},
			wantError: false,
		},
		{
			name: "SIGMA rule with tabs and spaces",
			rule: &Rule{
				Type:      "\t SIGMA \t",
				SigmaYAML: "\ttitle: Test\t",
				Query:     "",
			},
			wantError: false,
		},
		{
			name: "CQL rule with tabs and spaces",
			rule: &Rule{
				Type:      "\t CQL \t",
				Query:     "\tSELECT * FROM events\t",
				SigmaYAML: "",
			},
			wantError: false,
		},
		{
			name: "SIGMA with only newlines in sigma_yaml",
			rule: &Rule{
				Type:      "SIGMA",
				SigmaYAML: "\n\n\n",
				Query:     "",
			},
			wantError:     true,
			errorContains: "SIGMA rules must have sigma_yaml field and cannot have query field",
		},
		{
			name: "CQL with only newlines in query",
			rule: &Rule{
				Type:      "CQL",
				Query:     "\n\n\n",
				SigmaYAML: "",
			},
			wantError:     true,
			errorContains: "CQL rules must have query field and cannot have sigma_yaml field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Rule.Validate() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Rule.Validate() error = %v, want error containing %q", err, tt.errorContains)
				}
			}
		})
	}
}

// TestRuleValidate_ComprehensiveCoverage ensures all branches are tested
func TestRuleValidate_ComprehensiveCoverage(t *testing.T) {
	t.Run("comprehensive matrix test", func(t *testing.T) {
		// This test ensures all combinations are covered
		types := []string{"SIGMA", "CQL", "CORRELATION", "INVALID", ""}
		sigmaYAMLs := []string{"valid yaml", "", "   "}
		queries := []string{"valid query", "", "   "}

		for _, typ := range types {
			for _, yaml := range sigmaYAMLs {
				for _, query := range queries {
					rule := &Rule{
						Type:      typ,
						SigmaYAML: yaml,
						Query:     query,
					}
					// Just ensure it doesn't panic
					_ = rule.Validate()
				}
			}
		}
	})
}

// BenchmarkRuleValidate benchmarks the Validate method
func BenchmarkRuleValidate(b *testing.B) {
	tests := []struct {
		name string
		rule *Rule
	}{
		{
			name: "valid SIGMA rule",
			rule: &Rule{
				Type:      "SIGMA",
				SigmaYAML: "title: Test Rule\ndetection:\n  selection:\n    field: value",
			},
		},
		{
			name: "valid CQL rule",
			rule: &Rule{
				Type:  "CQL",
				Query: "event_type = 'login' AND status = 'failed'",
			},
		},
		{
			name: "invalid SIGMA rule",
			rule: &Rule{
				Type:      "SIGMA",
				SigmaYAML: "title: Test",
				Query:     "invalid",
			},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = tt.rule.Validate()
			}
		})
	}
}
