package api

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"cerberus/core"
)

var validSeverities = map[string]bool{"Low": true, "Medium": true, "High": true, "Critical": true}

var validOperators = map[string]bool{
	"equals": true, "not_equals": true, "contains": true, "starts_with": true, "ends_with": true,
	"regex": true, "greater_than": true, "less_than": true, "greater_than_or_equal": true, "less_than_or_equal": true,
}

var validLogics = map[string]bool{"AND": true, "OR": true}

// validateRule validates a rule
func validateBaseRule(id, name, description, severity string, version int) error {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	severity = strings.TrimSpace(severity)

	if len(name) == 0 || len(name) > 100 {
		return errors.New("name is required and must be 1-100 characters")
	}
	if len(description) > 500 {
		return errors.New("description must be at most 500 characters")
	}
	if !validSeverities[severity] {
		return errors.New("severity must be Low, Medium, High, or Critical")
	}
	if version <= 0 {
		return errors.New("version must be positive")
	}
	return nil
}

const (
	// SECURITY: Input length limits to prevent DoS attacks
	MaxDescLength = 2000 // Maximum length for description fields
)

// TASK #184: validateConditions function deleted - core.Condition struct removed
// All rules now use SIGMA YAML for detection logic

func validateRule(rule *core.Rule) error {
	// First validate the rule type and SIGMA/CQL field requirements
	// This calls core.Rule.Validate() which checks:
	// - SIGMA rules must have sigma_yaml and cannot have query
	// - CQL rules must have query and cannot have sigma_yaml
	if err := rule.Validate(); err != nil {
		return err
	}

	// Additional validation for base rule fields
	if err := validateBaseRule(rule.ID, rule.Name, rule.Description, rule.Severity, rule.Version); err != nil {
		return err
	}

	// TASK #184: Conditions validation removed - SIGMA rules use SigmaYAML, CQL rules use Query

	// Validate YAML syntax for SIGMA rules
	ruleType := strings.ToUpper(strings.TrimSpace(rule.Type))
	if ruleType == "SIGMA" && strings.TrimSpace(rule.SigmaYAML) != "" {
		if _, err := rule.ParsedSigmaRule(); err != nil {
			return fmt.Errorf("invalid sigma_yaml: %w", err)
		}
	}

	// Validate actions for all rule types
	for _, action := range rule.Actions {
		if err := validateAction(&action); err != nil {
			return err
		}
	}

	return nil
}

func validateWebhookAction(config map[string]interface{}) error {
	urlStr, ok := config["url"].(string)
	if !ok || strings.TrimSpace(urlStr) == "" {
		return errors.New("webhook action requires a valid url in config")
	}
	parsedURL, err := url.Parse(urlStr)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return errors.New("webhook action requires a valid URL")
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return errors.New("webhook URL must use http or https scheme")
	}
	return nil
}

func validateSlackAction(config map[string]interface{}) error {
	if webhookURL, ok := config["webhook_url"].(string); !ok || strings.TrimSpace(webhookURL) == "" {
		return errors.New("slack action requires a valid webhook_url in config")
	}
	return nil
}

func validateJiraAction(config map[string]interface{}) error {
	if baseURL, ok := config["base_url"].(string); !ok || strings.TrimSpace(baseURL) == "" {
		return errors.New("jira action requires a valid base_url in config")
	}
	if project, ok := config["project"].(string); !ok || strings.TrimSpace(project) == "" {
		return errors.New("jira action requires a valid project in config")
	}
	return nil
}

func validateEmailAction(config map[string]interface{}) error {
	if smtpServer, ok := config["smtp_server"].(string); !ok || strings.TrimSpace(smtpServer) == "" {
		return errors.New("email action requires a valid smtp_server in config")
	}
	var portVal float64
	if p, ok := config["port"].(float64); ok {
		portVal = p
	} else if p, ok := config["port"].(int); ok {
		portVal = float64(p)
	} else {
		return errors.New("email action requires a valid port (1-65535) in config")
	}
	if portVal < 1 || portVal > 65535 || portVal != float64(int(portVal)) {
		return errors.New("email action requires a valid port (1-65535) in config")
	}
	if from, ok := config["from"].(string); !ok || strings.TrimSpace(from) == "" {
		return errors.New("email action requires a valid from in config")
	}
	if to, ok := config["to"].(string); !ok || strings.TrimSpace(to) == "" {
		return errors.New("email action requires a valid to in config")
	}
	return nil
}

func validateAction(action *core.Action) error {
	atype := strings.TrimSpace(action.Type)
	validTypes := map[string]bool{"webhook": true, "jira": true, "email": true, "slack": true}
	if atype == "" {
		return errors.New("action type is required")
	}
	if !validTypes[atype] {
		return errors.New("action type must be webhook, jira, email, or slack")
	}
	switch atype {
	case "webhook":
		return validateWebhookAction(action.Config)
	case "jira":
		return validateJiraAction(action.Config)
	case "email":
		return validateEmailAction(action.Config)
	case "slack":
		return validateSlackAction(action.Config)
	}
	return nil
}

// validateCorrelationRule validates a correlation rule
func validateCorrelationRule(rule *core.CorrelationRule) error {
	if err := validateBaseRule(rule.ID, rule.Name, rule.Description, rule.Severity, rule.Version); err != nil {
		return fmt.Errorf("correlation rule: %w", err)
	}
	if rule.Window <= 0 {
		return errors.New("correlation rule window must be positive")
	}
	// TASK #184: Conditions validation removed - correlation rules use sequence-based matching
	if len(rule.Sequence) == 0 {
		return errors.New("sequence is required")
	}
	for _, action := range rule.Actions {
		if err := validateAction(&action); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRuleForCreation validates rule format before creation/update.
// TASK #184: Conditions field removed - SIGMA rules use sigma_yaml exclusively
//
// Security Considerations:
// - Enforces type-specific field requirements (SIGMA vs CQL)
// - Validates required fields are populated before persistence
//
// Validation Rules:
// - SIGMA rules (or unspecified type defaulting to SIGMA):
//   * Must have sigma_yaml field populated
//   * Cannot have query field (CQL-specific)
// - CQL rules:
//   * Must have query field populated
//   * Cannot have sigma_yaml field (SIGMA-specific)
//
// Returns:
//   - nil if validation passes
//   - error describing the validation failure
func ValidateRuleForCreation(rule *core.Rule) error {
	if rule == nil {
		return fmt.Errorf("cannot validate nil rule")
	}

	// Normalize type for comparison (default to SIGMA if not specified)
	// IMPORTANT: We normalize and PERSIST the type to ensure consistent storage
	ruleType := strings.ToUpper(strings.TrimSpace(rule.Type))
	if ruleType == "" {
		ruleType = "SIGMA"
	}
	// Persist normalized type back to the rule struct for consistent storage
	rule.Type = ruleType

	// Get rule identifier for error messages
	ruleID := rule.ID
	if ruleID == "" {
		ruleID = rule.Name
	}
	if ruleID == "" {
		ruleID = "(unnamed)"
	}

	switch ruleType {
	case "SIGMA":
		// SIGMA rules must have sigma_yaml populated
		if strings.TrimSpace(rule.SigmaYAML) == "" {
			return fmt.Errorf("rule '%s': SIGMA rules must have sigma_yaml field populated", ruleID)
		}

		// SIGMA rules cannot have CQL query field
		if strings.TrimSpace(rule.Query) != "" {
			return fmt.Errorf("rule '%s': SIGMA rules cannot have query field (use sigma_yaml)", ruleID)
		}

		// Validate YAML syntax by parsing it
		if _, err := rule.ParsedSigmaRule(); err != nil {
			return fmt.Errorf("rule '%s': invalid sigma_yaml: %w", ruleID, err)
		}

	case "CQL":
		// CQL rules must have query populated
		if strings.TrimSpace(rule.Query) == "" {
			return fmt.Errorf("rule '%s': CQL rules must have query field populated", ruleID)
		}

		// CQL rules cannot have SIGMA fields
		if strings.TrimSpace(rule.SigmaYAML) != "" {
			return fmt.Errorf("rule '%s': CQL rules cannot have sigma_yaml field (use query)", ruleID)
		}

	case "CORRELATION":
		// Correlation rules use separate validation path
		// They are not subject to this validation
		return nil

	default:
		return fmt.Errorf("rule '%s': invalid rule type: %s (must be SIGMA, CQL, or CORRELATION)", ruleID, rule.Type)
	}

	return nil
}
