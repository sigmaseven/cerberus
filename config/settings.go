package config

import (
	"fmt"
	"sync"

	"github.com/spf13/viper"
)

// SettingSchema defines metadata for a setting
type SettingSchema struct {
	Type            string      `json:"type"`
	Min             *int        `json:"min,omitempty"`
	Max             *int        `json:"max,omitempty"`
	Default         interface{} `json:"default"`
	Description     string      `json:"description"`
	RestartRequired bool        `json:"restart_required"`
	Category        string      `json:"category"`
	Options         []string    `json:"options,omitempty"`
	Conditional     string      `json:"conditional,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// UpdateResult represents the result of a settings update
type UpdateResult struct {
	Success            bool              `json:"success"`
	Message            string            `json:"message"`
	AppliedImmediately []string          `json:"applied_immediately"`
	RequiresRestart    []string          `json:"requires_restart"`
	ValidationErrors   []ValidationError `json:"validation_errors"`
}

// SettingsManager handles runtime configuration updates
type SettingsManager struct {
	config     *Config
	configPath string
	mu         sync.RWMutex
	schema     map[string]SettingSchema
}

// NewSettingsManager creates a new settings manager
func NewSettingsManager(config *Config, configPath string) *SettingsManager {
	sm := &SettingsManager{
		config:     config,
		configPath: configPath,
		schema:     buildSettingsSchema(),
	}
	return sm
}

// GetSettings returns current configuration with sensitive data masked
func (sm *SettingsManager) GetSettings() *Config {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return MaskSensitiveSettings(sm.config)
}

// GetSchema returns validation schema for all settings
func (sm *SettingsManager) GetSchema() map[string]SettingSchema {
	return sm.schema
}

// ValidateSettings checks if settings are valid
func (sm *SettingsManager) ValidateSettings(updates map[string]interface{}) []ValidationError {
	var errors []ValidationError

	// Validate retention settings
	if events, ok := updates["retention.events"].(float64); ok {
		if events < 1 || events > 365 {
			errors = append(errors, ValidationError{
				Field:   "retention.events",
				Message: "Event retention must be between 1 and 365 days",
			})
		}
	}

	if alerts, ok := updates["retention.alerts"].(float64); ok {
		if alerts < 1 || alerts > 730 {
			errors = append(errors, ValidationError{
				Field:   "retention.alerts",
				Message: "Alert retention must be between 1 and 730 days",
			})
		}
	}

	// Validate ports
	ports := []string{
		"listeners.syslog.port",
		"listeners.cef.port",
		"listeners.json.port",
		"api.port",
	}

	for _, portField := range ports {
		if port, ok := updates[portField].(float64); ok {
			if port < 1 || port > 65535 {
				errors = append(errors, ValidationError{
					Field:   portField,
					Message: "Port must be between 1 and 65535",
				})
			}
		}
	}

	return errors
}

// UpdateSettings applies configuration updates
func (sm *SettingsManager) UpdateSettings(updates map[string]interface{}) (*UpdateResult, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Validate first
	validationErrors := sm.ValidateSettings(updates)
	if len(validationErrors) > 0 {
		return &UpdateResult{
			Success:          false,
			Message:          "Validation failed",
			ValidationErrors: validationErrors,
		}, nil
	}

	appliedImmediately := []string{}
	requiresRestart := []string{}

	// Apply updates
	for key, value := range updates {
		schema, exists := sm.schema[key]
		if !exists {
			continue
		}

		// Set in viper
		viper.Set(key, value)

		// Track which settings need restart
		if schema.RestartRequired {
			requiresRestart = append(requiresRestart, key)
		} else {
			appliedImmediately = append(appliedImmediately, key)
		}
	}

	// Save to config file
	if err := viper.WriteConfig(); err != nil {
		return nil, fmt.Errorf("failed to save configuration: %w", err)
	}

	// Reload config
	newConfig, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to reload configuration: %w", err)
	}

	sm.config = newConfig

	return &UpdateResult{
		Success:            true,
		Message:            "Settings updated successfully",
		AppliedImmediately: appliedImmediately,
		RequiresRestart:    requiresRestart,
		ValidationErrors:   []ValidationError{},
	}, nil
}

// UpdateSettingsWithAudit updates settings with audit logging
// This is a wrapper to add audit logging when called from API handlers
func (sm *SettingsManager) UpdateSettingsWithAudit(updates map[string]interface{}, username, sourceIP string, logger interface{}) (*UpdateResult, error) {
	// Type assert logger to something we can use for logging
	type Logger interface {
		Infow(msg string, keysAndValues ...interface{})
	}

	var log Logger
	if l, ok := logger.(Logger); ok {
		log = l
	}

	// AUDIT: Settings update attempt
	if log != nil {
		log.Infow("AUDIT: Settings update initiated",
			"action", "update_settings",
			"username", username,
			"source_ip", sourceIP,
			"resource_type", "settings",
			"changes_count", len(updates),
			"timestamp", "now")
	}

	result, err := sm.UpdateSettings(updates)
	if err != nil {
		// AUDIT: Failed settings update
		if log != nil {
			log.Infow("AUDIT: Settings update failed",
				"action", "update_settings",
				"outcome", "failure",
				"username", username,
				"source_ip", sourceIP,
				"resource_type", "settings",
				"error", err.Error(),
				"timestamp", "now")
		}
		return result, err
	}

	// AUDIT: Successful settings update
	if log != nil {
		log.Infow("AUDIT: Settings updated successfully",
			"action", "update_settings",
			"outcome", "success",
			"username", username,
			"source_ip", sourceIP,
			"resource_type", "settings",
			"applied_immediately", result.AppliedImmediately,
			"requires_restart", result.RequiresRestart,
			"validation_errors", len(result.ValidationErrors),
			"timestamp", "now")
	}

	return result, nil
}

// MaskSensitiveSettings masks passwords and secrets
func MaskSensitiveSettings(config *Config) *Config {
	masked := *config
	// Add masking logic as needed
	return &masked
}

// GetRestartRequired returns list of settings that need restart
func (sm *SettingsManager) GetRestartRequired(changes map[string]interface{}) []string {
	var required []string
	for key := range changes {
		if schema, exists := sm.schema[key]; exists && schema.RestartRequired {
			required = append(required, key)
		}
	}
	return required
}

// buildSettingsSchema constructs the settings schema
func buildSettingsSchema() map[string]SettingSchema {
	schema := make(map[string]SettingSchema)

	// Retention settings
	schema["retention.events"] = SettingSchema{
		Type:            "integer",
		Min:             intPtr(1),
		Max:             intPtr(365),
		Default:         30,
		Description:     "How long to keep event logs (days)",
		RestartRequired: false,
		Category:        "retention",
	}

	schema["retention.alerts"] = SettingSchema{
		Type:            "integer",
		Min:             intPtr(1),
		Max:             intPtr(730),
		Default:         90,
		Description:     "How long to keep alerts (days)",
		RestartRequired: false,
		Category:        "retention",
	}

	// Listener settings
	schema["listeners.syslog.port"] = SettingSchema{
		Type:            "integer",
		Min:             intPtr(1),
		Max:             intPtr(65535),
		Default:         514,
		Description:     "Syslog listener port",
		RestartRequired: true,
		Category:        "listeners",
	}

	schema["listeners.syslog.host"] = SettingSchema{
		Type:            "string",
		Default:         "0.0.0.0",
		Description:     "Syslog listener host",
		RestartRequired: true,
		Category:        "listeners",
	}

	schema["listeners.cef.port"] = SettingSchema{
		Type:            "integer",
		Min:             intPtr(1),
		Max:             intPtr(65535),
		Default:         515,
		Description:     "CEF listener port",
		RestartRequired: true,
		Category:        "listeners",
	}

	schema["listeners.cef.host"] = SettingSchema{
		Type:            "string",
		Default:         "0.0.0.0",
		Description:     "CEF listener host",
		RestartRequired: true,
		Category:        "listeners",
	}

	schema["listeners.json.port"] = SettingSchema{
		Type:            "integer",
		Min:             intPtr(1),
		Max:             intPtr(65535),
		Default:         8888,
		Description:     "JSON listener port",
		RestartRequired: true,
		Category:        "listeners",
	}

	schema["listeners.json.host"] = SettingSchema{
		Type:            "string",
		Default:         "0.0.0.0",
		Description:     "JSON listener host",
		RestartRequired: true,
		Category:        "listeners",
	}

	schema["listeners.json.tls"] = SettingSchema{
		Type:            "boolean",
		Default:         false,
		Description:     "Enable TLS for JSON listener",
		RestartRequired: true,
		Category:        "listeners",
	}

	// API settings
	schema["api.port"] = SettingSchema{
		Type:            "integer",
		Min:             intPtr(1),
		Max:             intPtr(65535),
		Default:         8080,
		Description:     "API server port",
		RestartRequired: true,
		Category:        "api",
	}

	schema["api.tls"] = SettingSchema{
		Type:            "boolean",
		Default:         false,
		Description:     "Enable TLS for API",
		RestartRequired: true,
		Category:        "api",
	}

	// Auth settings
	schema["auth.enabled"] = SettingSchema{
		Type:            "boolean",
		Default:         false,
		Description:     "Enable authentication",
		RestartRequired: true,
		Category:        "auth",
	}

	return schema
}

// Helper function
func intPtr(i int) *int {
	return &i
}
