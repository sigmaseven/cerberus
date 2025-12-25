package api

import (
	"strings"
	"testing"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateBaseRule_SecurityVectors tests validation against security attack vectors
// Requirement: FR-SEC-007 (Input Validation), OWASP Input Validation
func TestValidateBaseRule_SecurityVectors(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		ruleName    string
		description string
		severity    string
		version     int
		expectError bool
		errorMsg    string
		requirement string
	}{
		// Valid cases
		{
			name:        "Valid rule with all fields",
			id:          "rule-1",
			ruleName:    "Valid Rule Name",
			description: "Valid description",
			severity:    "High",
			version:     1,
			expectError: false,
			requirement: "FR-SEC-007",
		},
		{
			name:        "Valid rule with minimal name",
			id:          "rule-2",
			ruleName:    "A",
			description: "",
			severity:    "Low",
			version:     1,
			expectError: false,
			requirement: "FR-SEC-007",
		},
		{
			name:        "Valid rule with max length name (100 chars)",
			id:          "rule-3",
			ruleName:    strings.Repeat("a", 100),
			description: "",
			severity:    "Medium",
			version:     1,
			expectError: false,
			requirement: "FR-SEC-007",
		},
		{
			name:        "Valid rule with max length description (500 chars)",
			id:          "rule-4",
			ruleName:    "Valid Name",
			description: strings.Repeat("d", 500),
			severity:    "Critical",
			version:     1,
			expectError: false,
			requirement: "FR-SEC-007",
		},

		// SQL Injection attack vectors
		{
			name:        "SQL injection - DROP TABLE",
			id:          "rule-sql-1",
			ruleName:    "'; DROP TABLE rules; --",
			description: "Test",
			severity:    "High",
			version:     1,
			expectError: false, // Input validation doesn't prevent SQL injection - that's handled by parameterized queries
			requirement: "FR-SEC-004",
		},
		{
			name:        "SQL injection - UNION SELECT",
			id:          "rule-sql-2",
			ruleName:    "' UNION SELECT * FROM users --",
			description: "Test",
			severity:    "High",
			version:     1,
			expectError: false,
			requirement: "FR-SEC-004",
		},

		// XSS attack vectors
		{
			name:        "XSS - script tag in name",
			id:          "rule-xss-1",
			ruleName:    "<script>alert('xss')</script>",
			description: "Test",
			severity:    "High",
			version:     1,
			expectError: false, // XSS prevention is handled by output encoding, not input validation
			requirement: "FR-SEC-006",
		},
		{
			name:        "XSS - event handler in description",
			id:          "rule-xss-2",
			ruleName:    "Valid",
			description: "<img src=x onerror=alert('xss')>",
			severity:    "High",
			version:     1,
			expectError: false,
			requirement: "FR-SEC-006",
		},

		// Length-based DoS attack vectors
		{
			name:        "DoS - name too long (101 chars)",
			id:          "rule-dos-1",
			ruleName:    strings.Repeat("a", 101),
			description: "Test",
			severity:    "High",
			version:     1,
			expectError: true,
			errorMsg:    "name is required and must be 1-100 characters",
			requirement: "FR-SEC-007",
		},
		{
			name:        "DoS - description too long (501 chars)",
			id:          "rule-dos-2",
			ruleName:    "Valid Name",
			description: strings.Repeat("d", 501),
			severity:    "High",
			version:     1,
			expectError: true,
			errorMsg:    "description must be at most 500 characters",
			requirement: "FR-SEC-007",
		},
		{
			name:        "DoS - extremely long name (10000 chars)",
			id:          "rule-dos-3",
			ruleName:    strings.Repeat("a", 10000),
			description: "Test",
			severity:    "High",
			version:     1,
			expectError: true,
			errorMsg:    "name is required and must be 1-100 characters",
			requirement: "FR-SEC-007",
		},

		// Empty/null validation
		{
			name:        "Invalid - empty name",
			id:          "rule-empty-1",
			ruleName:    "",
			description: "Test",
			severity:    "High",
			version:     1,
			expectError: true,
			errorMsg:    "name is required and must be 1-100 characters",
			requirement: "FR-SEC-007",
		},
		{
			name:        "Invalid - whitespace-only name",
			id:          "rule-empty-2",
			ruleName:    "   ",
			description: "Test",
			severity:    "High",
			version:     1,
			expectError: true,
			errorMsg:    "name is required and must be 1-100 characters",
			requirement: "FR-SEC-007",
		},

		// Invalid severity values
		{
			name:        "Invalid - invalid severity",
			id:          "rule-sev-1",
			ruleName:    "Valid Name",
			description: "Test",
			severity:    "Invalid",
			version:     1,
			expectError: true,
			errorMsg:    "severity must be Low, Medium, High, or Critical",
			requirement: "FR-SEC-007",
		},
		{
			name:        "Invalid - empty severity",
			id:          "rule-sev-2",
			ruleName:    "Valid Name",
			description: "Test",
			severity:    "",
			version:     1,
			expectError: true,
			errorMsg:    "severity must be Low, Medium, High, or Critical",
			requirement: "FR-SEC-007",
		},
		{
			name:        "Invalid - case-sensitive severity (lowercase)",
			id:          "rule-sev-3",
			ruleName:    "Valid Name",
			description: "Test",
			severity:    "high",
			version:     1,
			expectError: true,
			errorMsg:    "severity must be Low, Medium, High, or Critical",
			requirement: "FR-SEC-007",
		},

		// Invalid version values
		{
			name:        "Invalid - zero version",
			id:          "rule-ver-1",
			ruleName:    "Valid Name",
			description: "Test",
			severity:    "High",
			version:     0,
			expectError: true,
			errorMsg:    "version must be positive",
			requirement: "FR-SEC-007",
		},
		{
			name:        "Invalid - negative version",
			id:          "rule-ver-2",
			ruleName:    "Valid Name",
			description: "Test",
			severity:    "High",
			version:     -1,
			expectError: true,
			errorMsg:    "version must be positive",
			requirement: "FR-SEC-007",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBaseRule(tt.id, tt.ruleName, tt.description, tt.severity, tt.version)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateConditions_SecurityVectors tests condition validation against security attack vectors
// Requirement: FR-SEC-007 (Input Validation), OWASP Input Validation
// TASK #184: Skipped - validateConditions function removed along with core.Condition struct
func TestValidateConditions_SecurityVectors(t *testing.T) {
	t.Skip("validateConditions function removed in TASK #184 - rules now use SIGMA YAML for detection logic")
	return

	// Dead code below - kept for reference
	tests := []struct {
		name        string
		conditions  []interface{}
		expectError bool
		errorMsg    string
		requirement string
	}{
		// Valid cases
		{
			name: "Valid single condition",
			conditions: []interface{}{
				map[string]interface{}{"field": "source_ip", "operator": "equals", "value": "192.168.1.1", "logic": ""},
			},
			expectError: false,
			requirement: "FR-SEC-007",
		},
		{
			name: "Valid multiple conditions with AND logic",
			conditions: []interface{}{
				map[string]interface{}{"field": "source_ip", "operator": "equals", "value": "192.168.1.1", "logic": "AND"},
				map[string]interface{}{"field": "destination_port", "operator": "equals", "value": "443", "logic": ""},
			},
			expectError: false,
			requirement: "FR-SEC-007",
		},
		{
			name: "Valid multiple conditions with OR logic",
			conditions: []interface{}{
				map[string]interface{}{"field": "severity", "operator": "equals", "value": "high", "logic": "OR"},
				map[string]interface{}{"field": "severity", "operator": "equals", "value": "critical", "logic": ""},
			},
			expectError: false,
			requirement: "FR-SEC-007",
		},
		{
			name: "Valid condition with array value",
			conditions: []interface{}{
				map[string]interface{}{"field": "event_type", "operator": "equals", "value": []interface{}{"login", "logout", "access"}, "logic": ""},
			},
			expectError: false,
			requirement: "FR-SEC-007",
		},
		{
			name: "Valid condition at max field length (256 chars)",
			conditions: []interface{}{
				map[string]interface{}{"field": strings.Repeat("a", 256), "operator": "equals", "value": "test", "logic": ""},
			},
			expectError: false,
			requirement: "FR-SEC-007",
		},
		{
			name: "Valid condition at max value length (10000 chars)",
			conditions: []interface{}{
				map[string]interface{}{"field": "data", "operator": "equals", "value": strings.Repeat("x", 10000), "logic": ""},
			},
			expectError: false,
			requirement: "FR-SEC-007",
		},

		// DoS attack vectors - too many conditions
		{
			name:        "DoS - too many conditions (101)",
			conditions:  generateConditions(101),
			expectError: true,
			errorMsg:    "too many conditions",
			requirement: "FR-SEC-007",
		},
		{
			name:        "DoS - exactly at limit (100 conditions)",
			conditions:  generateConditions(100),
			expectError: false,
			requirement: "FR-SEC-007",
		},

		// DoS attack vectors - field name length
		{
			name: "DoS - field name too long (257 chars)",
			conditions: []interface{}{
				map[string]interface{}{"field": strings.Repeat("a", 257), "operator": "equals", "value": "test", "logic": ""},
			},
			expectError: true,
			errorMsg:    "field name too long",
			requirement: "FR-SEC-007",
		},
		{
			name: "DoS - extremely long field name (100000 chars)",
			conditions: []interface{}{
				map[string]interface{}{"field": strings.Repeat("a", 100000), "operator": "equals", "value": "test", "logic": ""},
			},
			expectError: true,
			errorMsg:    "field name too long",
			requirement: "FR-SEC-007",
		},

		// DoS attack vectors - value length
		{
			name: "DoS - value too long (10001 chars)",
			conditions: []interface{}{
				map[string]interface{}{"field": "data", "operator": "equals", "value": strings.Repeat("x", 10001), "logic": ""},
			},
			expectError: true,
			errorMsg:    "value too long",
			requirement: "FR-SEC-007",
		},
		{
			name: "DoS - extremely long value (1000000 chars)",
			conditions: []interface{}{
				map[string]interface{}{"field": "data", "operator": "equals", "value": strings.Repeat("x", 1000000), "logic": ""},
			},
			expectError: true,
			errorMsg:    "value too long",
			requirement: "FR-SEC-007",
		},

		// DoS attack vectors - array values
		{
			name: "DoS - too many array elements (1001)",
			conditions: []interface{}{
				map[string]interface{}{"field": "event_type", "operator": "equals", "value": generateArrayValues(1001), "logic": ""},
			},
			expectError: true,
			errorMsg:    "too many array elements",
			requirement: "FR-SEC-007",
		},
		{
			name: "DoS - array element too long",
			conditions: []interface{}{
				map[string]interface{}{"field": "event_type", "operator": "equals", "value": []interface{}{strings.Repeat("x", 10001)}, "logic": ""},
			},
			expectError: true,
			errorMsg:    "array element",
			requirement: "FR-SEC-007",
		},

		// Invalid field
		{
			name: "Invalid - empty field",
			conditions: []interface{}{
				map[string]interface{}{"field": "", "operator": "equals", "value": "test", "logic": ""},
			},
			expectError: true,
			errorMsg:    "field is required",
			requirement: "FR-SEC-007",
		},
		{
			name: "Invalid - whitespace-only field",
			conditions: []interface{}{
				map[string]interface{}{"field": "   ", "operator": "equals", "value": "test", "logic": ""},
			},
			expectError: true,
			errorMsg:    "field is required",
			requirement: "FR-SEC-007",
		},

		// Invalid operator
		{
			name: "Invalid - invalid operator",
			conditions: []interface{}{
				map[string]interface{}{"field": "source_ip", "operator": "invalid_op", "value": "test", "logic": ""},
			},
			expectError: true,
			errorMsg:    "invalid operator",
			requirement: "FR-SEC-007",
		},
		{
			name: "Invalid - empty operator",
			conditions: []interface{}{
				map[string]interface{}{"field": "source_ip", "operator": "", "value": "test", "logic": ""},
			},
			expectError: true,
			errorMsg:    "invalid operator",
			requirement: "FR-SEC-007",
		},

		// Invalid value
		{
			name: "Invalid - nil value",
			conditions: []interface{}{
				map[string]interface{}{"field": "source_ip", "operator": "equals", "value": nil, "logic": ""},
			},
			expectError: true,
			errorMsg:    "value is required",
			requirement: "FR-SEC-007",
		},

		// Invalid logic
		{
			name: "Invalid - invalid logic",
			conditions: []interface{}{
				map[string]interface{}{"field": "source_ip", "operator": "equals", "value": "test", "logic": "XOR"},
			},
			expectError: true,
			errorMsg:    "logic must be AND or OR",
			requirement: "FR-SEC-007",
		},
		{
			name: "Invalid - case-sensitive logic (lowercase)",
			conditions: []interface{}{
				map[string]interface{}{"field": "source_ip", "operator": "equals", "value": "test", "logic": "and"},
			},
			expectError: true,
			errorMsg:    "logic must be AND or OR",
			requirement: "FR-SEC-007",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// err := validateConditions(tt.conditions)  // TASK #184: Commented out - function removed
			var err error

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateRule_ComprehensiveCoverage tests the complete validateRule function
// Requirement: FR-SEC-007 (Input Validation)
// Note: Conditions field removed - rules now use SigmaYAML
func TestValidateRule_ComprehensiveCoverage(t *testing.T) {
	tests := []struct {
		name        string
		rule        *core.Rule
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid complete rule",
			rule: &core.Rule{
				ID:          "rule-1",
				Type:        "sigma",
				Name:        "Valid Rule",
				Description: "Test description",
				Severity:    "High",
				Version:     1,
				SigmaYAML:   "title: Test\ndetection:\n  selection:\n    source_ip: 192.168.1.1\n  condition: selection\n",
				Actions:     []core.Action{},
			},
			expectError: false,
		},
		{
			name: "Invalid - fails base validation",
			rule: &core.Rule{
				ID:          "rule-2",
				Type:        "sigma",
				Name:        "", // Empty name
				Description: "Test",
				Severity:    "High",
				Version:     1,
				SigmaYAML:   "title: Test\ndetection:\n  selection:\n    source_ip: 192.168.1.1\n  condition: selection\n",
			},
			expectError: true,
			errorMsg:    "name is required",
		},
		{
			name: "Invalid - no detection logic (empty SigmaYAML)",
			rule: &core.Rule{
				ID:          "rule-3",
				Type:        "sigma",
				Name:        "Valid Name",
				Description: "Test",
				Severity:    "High",
				Version:     1,
				SigmaYAML:   "",
			},
			expectError: true,
			errorMsg:    "",
		},
		{
			name: "Invalid - invalid SigmaYAML",
			rule: &core.Rule{
				ID:          "rule-4",
				Type:        "sigma",
				Name:        "Valid Name",
				Description: "Test",
				Severity:    "High",
				Version:     1,
				SigmaYAML:   "invalid yaml content [[[",
			},
			expectError: true,
			errorMsg:    "invalid sigma_yaml",
		},
		{
			name: "Valid - rule with actions",
			rule: &core.Rule{
				ID:          "rule-5",
				Type:        "sigma",
				Name:        "Rule with Actions",
				Description: "Test",
				Severity:    "High",
				Version:     1,
				SigmaYAML:   "title: Test\ndetection:\n  selection:\n    source_ip: 192.168.1.1\n  condition: selection\n",
				Actions: []core.Action{
					{Type: "webhook", Config: map[string]interface{}{"url": "https://example.com/webhook"}},
				},
			},
			expectError: false,
		},
		{
			name: "Invalid - invalid action",
			rule: &core.Rule{
				ID:          "rule-6",
				Type:        "sigma",
				Name:        "Rule with Invalid Action",
				Description: "Test",
				Severity:    "High",
				Version:     1,
				SigmaYAML: "title: Test\ndetection:\n  selection:\n    source_ip: 192.168.1.1\n  condition: selection\n",
				Actions: []core.Action{
					{Type: "webhook", Config: map[string]interface{}{"url": ""}}, // Empty URL
				},
			},
			expectError: true,
			errorMsg:    "webhook action requires a valid url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRule(tt.rule)

			if tt.expectError {
				assert.Error(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateWebhookAction_ComprehensiveCoverage tests webhook action validation
// Requirement: FR-SEC-007 (Input Validation)
func TestValidateWebhookAction_ComprehensiveCoverage(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid webhook with HTTPS URL",
			config:      map[string]interface{}{"url": "https://example.com/webhook"},
			expectError: false,
		},
		{
			name:        "Valid webhook with HTTP URL",
			config:      map[string]interface{}{"url": "http://example.com/webhook"},
			expectError: false,
		},
		{
			name:        "Valid webhook with complex URL",
			config:      map[string]interface{}{"url": "https://api.example.com:8443/v1/webhooks/alerts?auth=token123"},
			expectError: false,
		},
		{
			name:        "Invalid - missing url",
			config:      map[string]interface{}{},
			expectError: true,
			errorMsg:    "webhook action requires a valid url",
		},
		{
			name:        "Invalid - empty url",
			config:      map[string]interface{}{"url": ""},
			expectError: true,
			errorMsg:    "webhook action requires a valid url",
		},
		{
			name:        "Invalid - whitespace-only url",
			config:      map[string]interface{}{"url": "   "},
			expectError: true,
			errorMsg:    "webhook action requires a valid url",
		},
		{
			name:        "Invalid - url is not a string",
			config:      map[string]interface{}{"url": 12345},
			expectError: true,
			errorMsg:    "webhook action requires a valid url",
		},
		{
			name:        "Invalid - malformed URL",
			config:      map[string]interface{}{"url": "not a valid url"},
			expectError: true,
			errorMsg:    "webhook action requires a valid URL",
		},
		{
			name:        "Invalid - URL without scheme",
			config:      map[string]interface{}{"url": "example.com/webhook"},
			expectError: true,
			errorMsg:    "webhook action requires a valid URL",
		},
		{
			name:        "Invalid - URL with invalid scheme (ftp)",
			config:      map[string]interface{}{"url": "ftp://example.com/webhook"},
			expectError: true,
			errorMsg:    "webhook URL must use http or https scheme",
		},
		{
			name:        "Invalid - URL with invalid scheme (file) - missing host",
			config:      map[string]interface{}{"url": "file:///etc/passwd"},
			expectError: true,
			errorMsg:    "webhook action requires a valid URL", // file:// URLs don't have hosts
		},
		{
			name:        "Invalid - URL with invalid scheme (javascript)",
			config:      map[string]interface{}{"url": "javascript:alert(1)"},
			expectError: true,
			errorMsg:    "webhook action requires a valid URL", // javascript: URLs don't have hosts
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookAction(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateSlackAction_ComprehensiveCoverage tests Slack action validation
// Requirement: FR-SEC-007 (Input Validation)
func TestValidateSlackAction_ComprehensiveCoverage(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid Slack webhook",
			config:      map[string]interface{}{"webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"},
			expectError: false,
		},
		{
			name:        "Invalid - missing webhook_url",
			config:      map[string]interface{}{},
			expectError: true,
			errorMsg:    "slack action requires a valid webhook_url",
		},
		{
			name:        "Invalid - empty webhook_url",
			config:      map[string]interface{}{"webhook_url": ""},
			expectError: true,
			errorMsg:    "slack action requires a valid webhook_url",
		},
		{
			name:        "Invalid - whitespace-only webhook_url",
			config:      map[string]interface{}{"webhook_url": "   "},
			expectError: true,
			errorMsg:    "slack action requires a valid webhook_url",
		},
		{
			name:        "Invalid - webhook_url is not a string",
			config:      map[string]interface{}{"webhook_url": 12345},
			expectError: true,
			errorMsg:    "slack action requires a valid webhook_url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSlackAction(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateJiraAction_ComprehensiveCoverage tests Jira action validation
// Requirement: FR-SEC-007 (Input Validation)
func TestValidateJiraAction_ComprehensiveCoverage(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid Jira config",
			config: map[string]interface{}{
				"base_url": "https://jira.example.com",
				"project":  "SEC",
			},
			expectError: false,
		},
		{
			name:        "Invalid - missing base_url",
			config:      map[string]interface{}{"project": "SEC"},
			expectError: true,
			errorMsg:    "jira action requires a valid base_url",
		},
		{
			name:        "Invalid - empty base_url",
			config:      map[string]interface{}{"base_url": "", "project": "SEC"},
			expectError: true,
			errorMsg:    "jira action requires a valid base_url",
		},
		{
			name:        "Invalid - whitespace-only base_url",
			config:      map[string]interface{}{"base_url": "   ", "project": "SEC"},
			expectError: true,
			errorMsg:    "jira action requires a valid base_url",
		},
		{
			name:        "Invalid - base_url is not a string",
			config:      map[string]interface{}{"base_url": 12345, "project": "SEC"},
			expectError: true,
			errorMsg:    "jira action requires a valid base_url",
		},
		{
			name:        "Invalid - missing project",
			config:      map[string]interface{}{"base_url": "https://jira.example.com"},
			expectError: true,
			errorMsg:    "jira action requires a valid project",
		},
		{
			name:        "Invalid - empty project",
			config:      map[string]interface{}{"base_url": "https://jira.example.com", "project": ""},
			expectError: true,
			errorMsg:    "jira action requires a valid project",
		},
		{
			name:        "Invalid - whitespace-only project",
			config:      map[string]interface{}{"base_url": "https://jira.example.com", "project": "   "},
			expectError: true,
			errorMsg:    "jira action requires a valid project",
		},
		{
			name:        "Invalid - project is not a string",
			config:      map[string]interface{}{"base_url": "https://jira.example.com", "project": 12345},
			expectError: true,
			errorMsg:    "jira action requires a valid project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJiraAction(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateEmailAction_ComprehensiveCoverage tests email action validation
// Requirement: FR-SEC-007 (Input Validation)
func TestValidateEmailAction_ComprehensiveCoverage(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid email config with integer port",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        587,
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: false,
		},
		{
			name: "Valid email config with float64 port",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        float64(587),
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: false,
		},
		{
			name: "Valid email config with port 25",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        25,
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: false,
		},
		{
			name: "Valid email config with port 465",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        465,
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: false,
		},
		{
			name: "Valid email config with port 65535",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        65535,
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: false,
		},
		{
			name: "Invalid - missing smtp_server",
			config: map[string]interface{}{
				"port": 587,
				"from": "alerts@example.com",
				"to":   "security@example.com",
			},
			expectError: true,
			errorMsg:    "email action requires a valid smtp_server",
		},
		{
			name: "Invalid - empty smtp_server",
			config: map[string]interface{}{
				"smtp_server": "",
				"port":        587,
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: true,
			errorMsg:    "email action requires a valid smtp_server",
		},
		{
			name: "Invalid - missing port",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: true,
			errorMsg:    "email action requires a valid port",
		},
		{
			name: "Invalid - port is 0",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        0,
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: true,
			errorMsg:    "email action requires a valid port (1-65535)",
		},
		{
			name: "Invalid - port is negative",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        -1,
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: true,
			errorMsg:    "email action requires a valid port (1-65535)",
		},
		{
			name: "Invalid - port is too large (65536)",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        65536,
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: true,
			errorMsg:    "email action requires a valid port (1-65535)",
		},
		{
			name: "Invalid - port is not an integer (float with decimal)",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        587.5,
				"from":        "alerts@example.com",
				"to":          "security@example.com",
			},
			expectError: true,
			errorMsg:    "email action requires a valid port (1-65535)",
		},
		{
			name: "Invalid - missing from",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        587,
				"to":          "security@example.com",
			},
			expectError: true,
			errorMsg:    "email action requires a valid from",
		},
		{
			name: "Invalid - empty from",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        587,
				"from":        "",
				"to":          "security@example.com",
			},
			expectError: true,
			errorMsg:    "email action requires a valid from",
		},
		{
			name: "Invalid - missing to",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        587,
				"from":        "alerts@example.com",
			},
			expectError: true,
			errorMsg:    "email action requires a valid to",
		},
		{
			name: "Invalid - empty to",
			config: map[string]interface{}{
				"smtp_server": "smtp.example.com",
				"port":        587,
				"from":        "alerts@example.com",
				"to":          "",
			},
			expectError: true,
			errorMsg:    "email action requires a valid to",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEmailAction(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateAction_ComprehensiveCoverage tests the validateAction function
// Requirement: FR-SEC-007 (Input Validation)
func TestValidateAction_ComprehensiveCoverage(t *testing.T) {
	tests := []struct {
		name        string
		action      *core.Action
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid webhook action",
			action: &core.Action{
				Type:   "webhook",
				Config: map[string]interface{}{"url": "https://example.com/webhook"},
			},
			expectError: false,
		},
		{
			name: "Valid slack action",
			action: &core.Action{
				Type:   "slack",
				Config: map[string]interface{}{"webhook_url": "https://hooks.slack.com/services/XXX"},
			},
			expectError: false,
		},
		{
			name: "Valid jira action",
			action: &core.Action{
				Type:   "jira",
				Config: map[string]interface{}{"base_url": "https://jira.example.com", "project": "SEC"},
			},
			expectError: false,
		},
		{
			name: "Valid email action",
			action: &core.Action{
				Type: "email",
				Config: map[string]interface{}{
					"smtp_server": "smtp.example.com",
					"port":        587,
					"from":        "alerts@example.com",
					"to":          "security@example.com",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid - empty type",
			action: &core.Action{
				Type:   "",
				Config: map[string]interface{}{"url": "https://example.com/webhook"},
			},
			expectError: true,
			errorMsg:    "action type is required",
		},
		{
			name: "Invalid - whitespace-only type",
			action: &core.Action{
				Type:   "   ",
				Config: map[string]interface{}{"url": "https://example.com/webhook"},
			},
			expectError: true,
			errorMsg:    "action type is required",
		},
		{
			name: "Invalid - invalid type",
			action: &core.Action{
				Type:   "invalid_type",
				Config: map[string]interface{}{"url": "https://example.com/webhook"},
			},
			expectError: true,
			errorMsg:    "action type must be webhook, jira, email, or slack",
		},
		{
			name: "Invalid - webhook with invalid config",
			action: &core.Action{
				Type:   "webhook",
				Config: map[string]interface{}{"url": ""},
			},
			expectError: true,
			errorMsg:    "webhook action requires a valid url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAction(tt.action)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateCorrelationRule_ComprehensiveCoverage tests correlation rule validation
// Requirement: FR-SEC-007 (Input Validation)
func TestValidateCorrelationRule_ComprehensiveCoverage(t *testing.T) {
	tests := []struct {
		name        string
		rule        *core.CorrelationRule
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid correlation rule",
			rule: &core.CorrelationRule{
				ID:          "corr-1",
				Name:        "Valid Correlation",
				Description: "Test",
				Severity:    "High",
				Version:     1,
				Window:      300,
				Sequence: []string{"event1", "event2"},
			},
			expectError: false,
		},
		{
			name: "Invalid - fails base validation",
			rule: &core.CorrelationRule{
				ID:          "corr-2",
				Name:        "", // Empty name
				Description: "Test",
				Severity:    "High",
				Version:     1,
				Window:      300,
				Sequence: []string{"event1", "event2"},
			},
			expectError: true,
			errorMsg:    "correlation rule",
		},
		{
			name: "Invalid - zero window",
			rule: &core.CorrelationRule{
				ID:          "corr-3",
				Name:        "Valid Name",
				Description: "Test",
				Severity:    "High",
				Version:     1,
				Window:      0,
				Sequence: []string{"event1", "event2"},
			},
			expectError: true,
			errorMsg:    "correlation rule window must be positive",
		},
		{
			name: "Invalid - negative window",
			rule: &core.CorrelationRule{
				ID:          "corr-4",
				Name:        "Valid Name",
				Description: "Test",
				Severity:    "High",
				Version:     1,
				Window:      -300,
				Sequence: []string{"event1", "event2"},
			},
			expectError: true,
			errorMsg:    "correlation rule window must be positive",
		},
		// TASK #184: "Invalid - no conditions" test removed
		// Conditions field has been removed from CorrelationRule
		// Correlation rules now use sequence-based matching only
		{
			name: "Invalid - no sequence",
			rule: &core.CorrelationRule{
				ID:          "corr-6",
				Name:        "Valid Name",
				Description: "Test",
				Severity:    "High",
				Version:     1,
				Window:      300,
				Sequence: []string{},
			},
			expectError: true,
			errorMsg:    "sequence is required",
		},
		// TASK #184: "Invalid - invalid condition" test removed
		// Conditions field has been removed from CorrelationRule
		// No longer validating condition field requirements
		{
			name: "Valid - correlation rule with actions",
			rule: &core.CorrelationRule{
				ID:          "corr-8",
				Name:        "Correlation with Actions",
				Description: "Test",
				Severity:    "High",
				Version:     1,
				Window:      300,
				Sequence: []string{"event1", "event2"},
				Actions: []core.Action{
					{Type: "webhook", Config: map[string]interface{}{"url": "https://example.com/webhook"}},
				},
			},
			expectError: false,
		},
		{
			name: "Invalid - invalid action",
			rule: &core.CorrelationRule{
				ID:          "corr-9",
				Name:        "Correlation with Invalid Action",
				Description: "Test",
				Severity:    "High",
				Version:     1,
				Window:      300,
				Sequence: []string{"event1", "event2"},
				Actions: []core.Action{
					{Type: "webhook", Config: map[string]interface{}{"url": ""}}, // Empty URL
				},
			},
			expectError: true,
			errorMsg:    "webhook action requires a valid url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCorrelationRule(tt.rule)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper functions for test data generation

// generateConditions creates n conditions for testing DoS scenarios
// Note: core.Condition has been removed. This function is kept for backward compatibility
// but may need to be updated based on new detection logic structure.
func generateConditions(n int) []interface{} {
	conditions := make([]interface{}, n)
	for i := 0; i < n; i++ {
		conditions[i] = map[string]interface{}{
			"field":    "field" + string(rune(i)),
			"operator": "equals",
			"value":    "value",
			"logic":    "",
		}
	}
	return conditions
}

// generateArrayValues creates an array of n values for testing DoS scenarios
func generateArrayValues(n int) []interface{} {
	values := make([]interface{}, n)
	for i := 0; i < n; i++ {
		values[i] = "value" + string(rune(i))
	}
	return values
}

// TestValidationConstants_Coverage ensures constants are properly defined
// TASK #184: MaxConditions, MaxFieldNameLength, and MaxValueLength removed with core.Condition struct
func TestValidationConstants_Coverage(t *testing.T) {
	// Only MaxDescLength remains - other constants removed with core.Condition
	require.Equal(t, 2000, MaxDescLength, "MaxDescLength should be 2000")
}

// TestValidSeverities_Coverage ensures severity validation map is properly defined
func TestValidSeverities_Coverage(t *testing.T) {
	require.True(t, validSeverities["Low"], "Low should be a valid severity")
	require.True(t, validSeverities["Medium"], "Medium should be a valid severity")
	require.True(t, validSeverities["High"], "High should be a valid severity")
	require.True(t, validSeverities["Critical"], "Critical should be a valid severity")
	require.False(t, validSeverities["Invalid"], "Invalid should not be a valid severity")
}

// TestValidOperators_Coverage ensures operator validation map is properly defined
func TestValidOperators_Coverage(t *testing.T) {
	require.True(t, validOperators["equals"], "equals should be a valid operator")
	require.True(t, validOperators["not_equals"], "not_equals should be a valid operator")
	require.True(t, validOperators["contains"], "contains should be a valid operator")
	require.True(t, validOperators["starts_with"], "starts_with should be a valid operator")
	require.True(t, validOperators["ends_with"], "ends_with should be a valid operator")
	require.True(t, validOperators["regex"], "regex should be a valid operator")
	require.True(t, validOperators["greater_than"], "greater_than should be a valid operator")
	require.True(t, validOperators["less_than"], "less_than should be a valid operator")
	require.True(t, validOperators["greater_than_or_equal"], "greater_than_or_equal should be a valid operator")
	require.True(t, validOperators["less_than_or_equal"], "less_than_or_equal should be a valid operator")
	require.False(t, validOperators["invalid"], "invalid should not be a valid operator")
}

// TestValidLogics_Coverage ensures logic validation map is properly defined
func TestValidLogics_Coverage(t *testing.T) {
	require.True(t, validLogics["AND"], "AND should be a valid logic")
	require.True(t, validLogics["OR"], "OR should be a valid logic")
	require.False(t, validLogics["XOR"], "XOR should not be a valid logic")
	require.False(t, validLogics["and"], "and (lowercase) should not be a valid logic")
}
