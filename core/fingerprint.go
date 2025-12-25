package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"text/template"
	"time"

	"go.uber.org/zap"
)

// FingerprintConfig defines how alert fingerprints are generated
type FingerprintConfig struct {
	Enabled    bool          `json:"enabled" bson:"enabled"`
	Fields     []string      `json:"fields,omitempty" bson:"fields,omitempty"`             // Fields to include in fingerprint
	Template   string        `json:"template,omitempty" bson:"template,omitempty"`         // Custom template: "{{.RuleID}}-{{.SourceIP}}-{{.DestIP}}"
	TimeWindow time.Duration `json:"time_window" bson:"time_window" swaggertype:"integer"` // Window for deduplication (e.g., 1 hour)
}

// AlertFingerprinter generates fingerprints for alerts
type AlertFingerprinter struct {
	config FingerprintConfig
	logger *zap.SugaredLogger
}

// NewAlertFingerprinter creates a new AlertFingerprinter with the given configuration
func NewAlertFingerprinter(config FingerprintConfig) *AlertFingerprinter {
	return &AlertFingerprinter{config: config, logger: zap.NewNop().Sugar()} // Default no-op logger
}

// NewAlertFingerprinterWithLogger creates a new AlertFingerprinter with logger
func NewAlertFingerprinterWithLogger(config FingerprintConfig, logger *zap.SugaredLogger) *AlertFingerprinter {
	return &AlertFingerprinter{config: config, logger: logger}
}

// GenerateFingerprint generates a unique fingerprint for an alert based on configuration
func (af *AlertFingerprinter) GenerateFingerprint(alert *Alert) string {
	if !af.config.Enabled {
		// If fingerprinting is disabled, return empty string
		return ""
	}

	var parts []string

	if af.config.Template != "" {
		// Validate template for security before parsing
		if err := af.validateTemplate(af.config.Template); err != nil {
			af.logger.Warnw("Template fingerprint validation failed, falling back to field-based fingerprint",
				"error", err,
				"template", af.config.Template)
			return af.fallbackFingerprint(alert)
		}

		// Use template-based fingerprint with safe execution
		tmpl, err := template.New("fingerprint").Parse(af.config.Template)
		if err != nil {
			// Template parsing failed, fall back to field-based fingerprint
			return af.fallbackFingerprint(alert)
		}

		// Create template data from alert
		templateData := af.createTemplateData(alert)

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, templateData); err != nil {
			// Log template execution error for debugging
			af.logger.Warnw("Template fingerprint execution failed, falling back to field-based fingerprint",
				"error", err,
				"template", af.config.Template,
				"alert_id", alert.AlertID)
			return af.fallbackFingerprint(alert)
		}

		return af.hash(buf.String())
	}

	// Use field-based fingerprint
	for _, field := range af.config.Fields {
		value := af.extractField(alert, field)
		if value != "" {
			parts = append(parts, fmt.Sprintf("%s=%s", field, value))
		}
	}

	if len(parts) == 0 {
		// No fields configured, use fallback
		return af.fallbackFingerprint(alert)
	}

	return af.hash(joinParts(parts))
}

// createTemplateData creates a map of data for template execution
func (af *AlertFingerprinter) createTemplateData(alert *Alert) map[string]interface{} {
	data := map[string]interface{}{
		"RuleID":   alert.RuleID,
		"Severity": alert.Severity,
		"EventID":  alert.EventID,
	}

	// Add event fields if available
	if alert.Event != nil {
		// Extract common metadata fields
		if alert.Event.Fields != nil {
			data["SourceIP"] = getFieldString(alert.Event.Fields, "source_ip")
			data["DestIP"] = getFieldString(alert.Event.Fields, "dest_ip")
			data["User"] = getFieldString(alert.Event.Fields, "user")
			data["Process"] = getFieldString(alert.Event.Fields, "process")
			data["File"] = getFieldString(alert.Event.Fields, "file")
			data["Command"] = getFieldString(alert.Event.Fields, "command")
		}
	}

	return data
}

// validateTemplate validates template for security to prevent template injection
func (af *AlertFingerprinter) validateTemplate(templateStr string) error {
	// Check for dangerous template directives
	dangerousPatterns := []string{
		`\{\{\s*\.\s*\}\}`,      // Access to root context
		`\{\{\s*call\s+`,        // Function calls
		`\{\{\s*define\s+`,      // Template definitions
		`\{\{\s*template\s+`,    // Template inclusion
		`\{\{\s*block\s+`,       // Block definitions
		`\{\{\s*with\s+\$\w+`,   // Variable assignments
		`\{\{\s*\$[a-zA-Z_]\w*`, // Variable access
		`\{\{\s*pipeline\s+`,    // Pipeline operations
		`\{\{\s*index\s+`,       // Index operations
		`\{\{\s*len\s+`,         // Length operations
		`\{\{\s*print\s+`,       // Print functions
		`\{\{\s*printf\s+`,      // Printf functions
		`\{\{\s*sprintf\s+`,     // Sprintf functions
	}

	for _, pattern := range dangerousPatterns {
		if matched, _ := regexp.MatchString(pattern, templateStr); matched {
			return fmt.Errorf("template contains potentially dangerous directive: %s", pattern)
		}
	}

	// Ensure template only uses safe field access
	safePattern := `^\s*\{\{\s*\.[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\}\}\s*$`
	if matched, _ := regexp.MatchString(safePattern, templateStr); !matched {
		return fmt.Errorf("template must use only safe field access (e.g., {{.FieldName}})")
	}

	return nil
}

// extractField extracts a field value from an alert
func (af *AlertFingerprinter) extractField(alert *Alert, field string) string {
	switch field {
	case "rule_id":
		return alert.RuleID
	case "severity":
		return alert.Severity
	case "event_id":
		return alert.EventID
	}

	// Try to extract from event fields
	if alert.Event != nil && alert.Event.Fields != nil {
		switch field {
		case "source_ip":
			return getFieldString(alert.Event.Fields, "source_ip")
		case "dest_ip":
			return getFieldString(alert.Event.Fields, "dest_ip")
		case "user":
			return getFieldString(alert.Event.Fields, "user")
		case "process":
			return getFieldString(alert.Event.Fields, "process")
		case "file":
			return getFieldString(alert.Event.Fields, "file")
		case "command":
			return getFieldString(alert.Event.Fields, "command")
		}
	}

	return ""
}

// getFieldString safely extracts a string value from a map
func getFieldString(fields map[string]interface{}, key string) string {
	if val, ok := fields[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
		// Try to convert to string
		return fmt.Sprintf("%v", val)
	}
	return ""
}

// hash generates a SHA-256 hash of the input string
func (af *AlertFingerprinter) hash(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// fallbackFingerprint generates a default fingerprint when configuration is incomplete
func (af *AlertFingerprinter) fallbackFingerprint(alert *Alert) string {
	// Default fingerprint: rule_id + event_id
	return af.hash(fmt.Sprintf("%s|%s", alert.RuleID, alert.EventID))
}

// joinParts joins fingerprint parts with a separator
func joinParts(parts []string) string {
	result := ""
	for i, part := range parts {
		if i > 0 {
			result += "|"
		}
		result += part
	}
	return result
}

// DefaultFingerprintConfig returns a default fingerprint configuration
func DefaultFingerprintConfig() FingerprintConfig {
	return FingerprintConfig{
		Enabled:    true,
		Fields:     []string{"rule_id", "source_ip", "dest_ip", "user"},
		TimeWindow: 1 * time.Hour,
	}
}
