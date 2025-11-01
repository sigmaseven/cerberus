package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
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

func validateConditions(conditions []core.Condition) error {
	for i, cond := range conditions {
		field := strings.TrimSpace(cond.Field)
		operator := strings.TrimSpace(cond.Operator)
		logic := strings.TrimSpace(cond.Logic)
		if field == "" {
			return fmt.Errorf("condition %d: field is required", i)
		}
		if !validOperators[operator] {
			return fmt.Errorf("condition %d: invalid operator", i)
		}
		if cond.Value == nil {
			return fmt.Errorf("condition %d: value is required", i)
		}
		if logic != "" && !validLogics[logic] {
			return fmt.Errorf("condition %d: logic must be AND or OR", i)
		}
	}
	return nil
}

func validateRule(rule *core.Rule) error {
	if err := validateBaseRule(rule.ID, rule.Name, rule.Description, rule.Severity, rule.Version); err != nil {
		return err
	}
	if len(rule.Conditions) == 0 {
		return errors.New("at least one condition is required")
	}
	if err := validateConditions(rule.Conditions); err != nil {
		return err
	}
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

// getRealIP extracts the real client IP, considering proxy headers if trusted
func getRealIP(r *http.Request, trustProxy bool) string {
	// Check X-Forwarded-For header if proxy headers are trusted
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP in case of multiple
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				ip := strings.TrimSpace(ips[0])
				if ip != "" && net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
		// Check X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" && net.ParseIP(xri) != nil {
			return xri
		}
	}
	// Fallback to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
	if len(rule.Conditions) == 0 {
		return errors.New("at least one condition is required")
	}
	if len(rule.Sequence) == 0 {
		return errors.New("sequence is required")
	}
	if err := validateConditions(rule.Conditions); err != nil {
		return err
	}
	for _, action := range rule.Actions {
		if err := validateAction(&action); err != nil {
			return err
		}
	}
	return nil
}
