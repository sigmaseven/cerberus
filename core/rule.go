package core

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TASK #184: regexp import removed - Condition struct deleted

// AlertableRule interface for rules that can generate alerts
type AlertableRule interface {
	GetID() string
	GetName() string
	GetDescription() string
	GetSeverity() string
	GetActions() []Action
}

// Rule represents a detection rule
type Rule struct {
	ID              string                 `json:"id" bson:"_id" example:"failed_login"`
	Type            string                 `json:"type" bson:"type" example:"sigma"` // 'sigma' or 'cql'
	Name            string                 `json:"name" bson:"name" example:"Failed User Login"`
	Description     string                 `json:"description" bson:"description" example:"Detects multiple failed login attempts"`
	Severity        string                 `json:"severity" bson:"severity" example:"Warning"`
	Version         int                    `json:"version" bson:"version" example:"1"`
	Tags            []string               `json:"tags,omitempty" bson:"tags,omitempty"`
	MitreTactics    []string               `json:"mitre_tactics,omitempty" bson:"mitre_tactics,omitempty"`
	MitreTechniques []string               `json:"mitre_techniques,omitempty" bson:"mitre_techniques,omitempty"`
	Author          string                 `json:"author,omitempty" bson:"author,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	// TASK #184: Conditions field removed - SIGMA rules use SigmaYAML for detection
	Actions []Action `json:"actions" bson:"actions"`
	Enabled         bool                   `json:"enabled" bson:"enabled" example:"true"`
	Query           string                 `json:"query,omitempty" bson:"query,omitempty"`             // CQL query string
	Correlation     map[string]interface{} `json:"correlation,omitempty" bson:"correlation,omitempty"` // Correlation config
	References     []string `json:"references,omitempty" bson:"references,omitempty"`
	FalsePositives []string `json:"false_positives,omitempty" bson:"false_positives,omitempty"`

	// TASK #184: Detection and Logsource fields removed - use SigmaYAML instead
	// SigmaYAML contains the complete SIGMA rule in YAML format for SIGMA-type rules
	SigmaYAML string `json:"sigma_yaml,omitempty" bson:"sigma_yaml,omitempty"`

	// Denormalized logsource fields for efficient querying and filtering of SIGMA rules
	// LogsourceCategory represents the general category of logs (e.g., "process_creation", "network_connection")
	LogsourceCategory string `json:"logsource_category,omitempty" bson:"logsource_category,omitempty"`
	// LogsourceProduct represents the product generating the logs (e.g., "windows", "linux", "azure")
	LogsourceProduct string `json:"logsource_product,omitempty" bson:"logsource_product,omitempty"`
	// LogsourceService represents the specific service within the product (e.g., "sysmon", "security", "application")
	LogsourceService string `json:"logsource_service,omitempty" bson:"logsource_service,omitempty"`

	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// GetID returns the rule ID
func (r Rule) GetID() string {
	return r.ID
}

// GetName returns the rule name
func (r Rule) GetName() string {
	return r.Name
}

// GetDescription returns the rule description
func (r Rule) GetDescription() string {
	return r.Description
}

// GetSeverity returns the rule severity
func (r Rule) GetSeverity() string {
	return r.Severity
}

// GetActions returns the rule actions
func (r Rule) GetActions() []Action {
	return r.Actions
}

// ParsedSigmaRule parses the SigmaYAML field and returns the structured YAML data.
// This method performs on-demand parsing without caching the result.
//
// Security considerations:
//   - Protects against YAML bombs by limiting input size
//   - Returns detailed errors for malformed YAML
//   - Handles nil receivers gracefully
//
// Returns:
//   - map[string]interface{}: The parsed SIGMA rule structure
//   - error: Any parsing errors or validation failures
//
// Example usage:
//
//	parsed, err := rule.ParsedSigmaRule()
//	if err != nil {
//	    return fmt.Errorf("failed to parse SIGMA YAML: %w", err)
//	}
//	title := parsed["title"].(string)
func (r *Rule) ParsedSigmaRule() (map[string]interface{}, error) {
	// Handle nil receiver gracefully
	if r == nil {
		return nil, fmt.Errorf("cannot parse SIGMA YAML from nil rule")
	}

	// Check if SigmaYAML field is empty
	trimmedYAML := strings.TrimSpace(r.SigmaYAML)
	if trimmedYAML == "" {
		return nil, fmt.Errorf("sigma_yaml field is empty")
	}

	// Security: Protect against YAML bombs (extremely large payloads)
	// Reasonable limit for SIGMA rules is 1MB
	const maxYAMLSize = 1024 * 1024 // 1MB
	if len(r.SigmaYAML) > maxYAMLSize {
		return nil, fmt.Errorf("sigma_yaml exceeds maximum size of %d bytes", maxYAMLSize)
	}

	// Parse YAML into map structure
	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(r.SigmaYAML), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse sigma_yaml: %w", err)
	}

	return parsed, nil
}

// ParsedCorrelation parses the Correlation field and returns a SigmaCorrelation struct.
// This method performs on-demand parsing and validation.
//
// Security considerations:
//   - Validates correlation type before parsing
//   - Performs type-specific field validation
//   - Handles nil receivers gracefully
//
// Returns:
//   - *SigmaCorrelation: The parsed correlation configuration
//   - error: Any parsing or validation errors
//
// Example usage:
//
//	corr, err := rule.ParsedCorrelation()
//	if err != nil {
//	    return fmt.Errorf("failed to parse correlation: %w", err)
//	}
//	window, _ := corr.ParseDuration(corr.Timespan)
func (r *Rule) ParsedCorrelation() (*SigmaCorrelation, error) {
	// Handle nil receiver gracefully
	if r == nil {
		return nil, fmt.Errorf("cannot parse correlation from nil rule")
	}

	// Check if Correlation field is present
	if r.Correlation == nil || len(r.Correlation) == 0 {
		return nil, fmt.Errorf("correlation field is empty or nil")
	}

	// Convert map to YAML bytes for unmarshaling
	yamlBytes, err := yaml.Marshal(r.Correlation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal correlation to YAML: %w", err)
	}

	// Parse YAML into SigmaCorrelation
	var sc SigmaCorrelation
	if err := yaml.Unmarshal(yamlBytes, &sc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal correlation: %w", err)
	}

	// Validate parsed correlation
	if err := sc.Validate(); err != nil {
		return nil, fmt.Errorf("correlation validation failed: %w", err)
	}

	return &sc, nil
}

// Validate validates the Rule based on its type and ensures mutual exclusion
// between SIGMA and CQL fields. Returns an error if validation fails.
//
// Validation rules:
//   - SIGMA rules must have sigma_yaml field populated and query field empty
//   - CQL rules must have query field populated and sigma_yaml field empty
//   - CORRELATION rules skip validation (use separate storage)
//   - Unknown rule types are rejected
func (r *Rule) Validate() error {
	if r == nil {
		return fmt.Errorf("cannot validate nil rule")
	}

	// Normalize type to uppercase for comparison
	ruleType := strings.ToUpper(strings.TrimSpace(r.Type))

	switch ruleType {
	case "SIGMA":
		// SIGMA rules must have sigma_yaml and cannot have query
		if strings.TrimSpace(r.SigmaYAML) == "" {
			return fmt.Errorf("SIGMA rules must have sigma_yaml field and cannot have query field")
		}
		if strings.TrimSpace(r.Query) != "" {
			return fmt.Errorf("SIGMA rules must have sigma_yaml field and cannot have query field")
		}
		return nil

	case "CQL":
		// CQL rules must have query and cannot have sigma_yaml
		if strings.TrimSpace(r.Query) == "" {
			return fmt.Errorf("CQL rules must have query field and cannot have sigma_yaml field")
		}
		if strings.TrimSpace(r.SigmaYAML) != "" {
			return fmt.Errorf("CQL rules must have query field and cannot have sigma_yaml field")
		}
		return nil

	case "CORRELATION":
		// Correlation rules use separate table/validation - skip validation here
		return nil

	default:
		// Unknown or empty rule type
		if ruleType == "" {
			return fmt.Errorf("rule type cannot be empty")
		}
		return fmt.Errorf("unknown rule type: %s (must be SIGMA, CQL, or CORRELATION)", ruleType)
	}
}

// TASK #184: Condition struct removed - SIGMA rules use SigmaYAML for detection
// Legacy Condition struct was:
//   type Condition struct {
//       Field    string         `json:"field"`
//       Operator string         `json:"operator"` // equals, not_equals, contains, etc.
//       Value    interface{}    `json:"value"`
//       Logic    string         `json:"logic"` // AND, OR
//       Regex    *regexp.Regexp `json:"-"`
//   }
// Detection rules now use SigmaYAML field exclusively.
// Correlation rules use core.CorrelationCondition from sigma_correlation.go.

// Action represents an action to take on match (for Phase 3, but include)
type Action struct {
	ID        string                 `json:"id" bson:"_id" example:"action-123"`
	Type      string                 `json:"type" bson:"type" example:"webhook"` // webhook, jira, etc.
	Config    map[string]interface{} `json:"config" bson:"config" swaggertype:"object"`
	CreatedAt time.Time              `json:"created_at" bson:"created_at" swaggertype:"string"`
	UpdatedAt time.Time              `json:"updated_at" bson:"updated_at" swaggertype:"string"`
}

// Rules is a collection of rules
type Rules struct {
	Rules []Rule `json:"rules" bson:"rules"`
}

// CorrelationRules is a collection of correlation rules
type CorrelationRules struct {
	Rules []CorrelationRule `json:"rules" bson:"rules"`
}

// CorrelationRule for multi-event rules
type CorrelationRule struct {
	ID          string        `json:"id" bson:"_id" example:"correlation_rule_1"`
	Name        string        `json:"name" bson:"name" example:"Brute Force Detection"`
	Description string        `json:"description" bson:"description" example:"Detects multiple failed logins"`
	Severity    string        `json:"severity" bson:"severity" example:"High"`
	Version     int           `json:"version" bson:"version" example:"1"`
	Window      time.Duration `json:"window" bson:"window" swaggertype:"integer" example:"300000000000"` // time window for correlation in nanoseconds
	// TASK #184: Conditions field removed - use SIGMA correlation syntax instead
	Sequence  []string  `json:"sequence" bson:"sequence" example:"user_login,user_login,user_login"` // sequence of event types
	Actions   []Action  `json:"actions" bson:"actions"`
	CreatedAt time.Time `json:"created_at" bson:"created_at" swaggertype:"string"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at" swaggertype:"string"`
}

// GetID returns the correlation rule ID
func (cr CorrelationRule) GetID() string {
	return cr.ID
}

// GetName returns the correlation rule name
func (cr CorrelationRule) GetName() string {
	return cr.Name
}

// GetDescription returns the correlation rule description
func (cr CorrelationRule) GetDescription() string {
	return cr.Description
}

// GetSeverity returns the correlation rule severity
func (cr CorrelationRule) GetSeverity() string {
	return cr.Severity
}

// GetActions returns the correlation rule actions
func (cr CorrelationRule) GetActions() []Action {
	return cr.Actions
}
