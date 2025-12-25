package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSigmaEngineConfigDefaults verifies that SIGMA engine configuration defaults are set correctly.
// REQUIREMENT: Task #131.1 - SIGMA Engine Configuration
func TestSigmaEngineConfigDefaults(t *testing.T) {
	viper.Reset()
	setDefaults()

	assert.False(t, viper.GetBool("engine.enable_native_sigma_engine"), "SIGMA engine should be disabled by default")
	assert.Equal(t, "config/sigma_field_mappings.yaml", viper.GetString("engine.sigma_field_mapping_config"))
	assert.Equal(t, 1000, viper.GetInt("engine.sigma_engine_cache_size"))
	assert.Equal(t, 30*time.Minute, viper.GetDuration("engine.sigma_engine_cache_ttl"))
	assert.Equal(t, 5*time.Minute, viper.GetDuration("engine.sigma_engine_cleanup_interval"))
}

// TestSigmaEngineConfigValidation verifies that SIGMA engine configuration validation works.
// REQUIREMENT: Task #131.1 - SIGMA Engine Configuration Validation
func TestSigmaEngineConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func(*Config)
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_sigma_engine_config",
			setupConfig: func(c *Config) {
				c.Engine.EnableNativeSigmaEngine = true
				c.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
				c.Engine.SigmaEngineCacheSize = 1000
				c.Engine.SigmaEngineCacheTTL = 30 * time.Minute
				c.Engine.SigmaEngineCleanupInterval = 5 * time.Minute
			},
			expectError: false,
		},
		{
			name: "sigma_disabled_no_validation",
			setupConfig: func(c *Config) {
				c.Engine.EnableNativeSigmaEngine = false
				c.Engine.SigmaFieldMappingConfig = "" // Empty is OK when disabled
				c.Engine.SigmaEngineCacheSize = 0     // Zero is OK when disabled
			},
			expectError: false,
		},
		{
			name: "empty_field_mapping_config",
			setupConfig: func(c *Config) {
				c.Engine.EnableNativeSigmaEngine = true
				c.Engine.SigmaFieldMappingConfig = ""
				c.Engine.SigmaEngineCacheSize = 1000
				c.Engine.SigmaEngineCacheTTL = 30 * time.Minute
				c.Engine.SigmaEngineCleanupInterval = 5 * time.Minute
			},
			expectError: true,
			errorMsg:    "engine.sigma_field_mapping_config cannot be empty",
		},
		{
			name: "cache_size_too_small",
			setupConfig: func(c *Config) {
				c.Engine.EnableNativeSigmaEngine = true
				c.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
				c.Engine.SigmaEngineCacheSize = 0 // Invalid
				c.Engine.SigmaEngineCacheTTL = 30 * time.Minute
				c.Engine.SigmaEngineCleanupInterval = 5 * time.Minute
			},
			expectError: true,
			errorMsg:    "engine.sigma_engine_cache_size must be between 1 and 100000",
		},
		{
			name: "cache_size_too_large",
			setupConfig: func(c *Config) {
				c.Engine.EnableNativeSigmaEngine = true
				c.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
				c.Engine.SigmaEngineCacheSize = 200000 // Too large
				c.Engine.SigmaEngineCacheTTL = 30 * time.Minute
				c.Engine.SigmaEngineCleanupInterval = 5 * time.Minute
			},
			expectError: true,
			errorMsg:    "engine.sigma_engine_cache_size must be between 1 and 100000",
		},
		{
			name: "cache_ttl_too_small",
			setupConfig: func(c *Config) {
				c.Engine.EnableNativeSigmaEngine = true
				c.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
				c.Engine.SigmaEngineCacheSize = 1000
				c.Engine.SigmaEngineCacheTTL = 30 * time.Second // Too small
				c.Engine.SigmaEngineCleanupInterval = 5 * time.Minute
			},
			expectError: true,
			errorMsg:    "engine.sigma_engine_cache_ttl must be at least 1 minute",
		},
		{
			name: "cache_ttl_too_large",
			setupConfig: func(c *Config) {
				c.Engine.EnableNativeSigmaEngine = true
				c.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
				c.Engine.SigmaEngineCacheSize = 1000
				c.Engine.SigmaEngineCacheTTL = 48 * time.Hour // Too large
				c.Engine.SigmaEngineCleanupInterval = 5 * time.Minute
			},
			expectError: true,
			errorMsg:    "engine.sigma_engine_cache_ttl must be at most 24 hours",
		},
		{
			name: "cleanup_interval_too_small",
			setupConfig: func(c *Config) {
				c.Engine.EnableNativeSigmaEngine = true
				c.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
				c.Engine.SigmaEngineCacheSize = 1000
				c.Engine.SigmaEngineCacheTTL = 30 * time.Minute
				c.Engine.SigmaEngineCleanupInterval = 30 * time.Second // Too small
			},
			expectError: true,
			errorMsg:    "engine.sigma_engine_cleanup_interval must be at least 1 minute",
		},
		{
			name: "cleanup_interval_too_large",
			setupConfig: func(c *Config) {
				c.Engine.EnableNativeSigmaEngine = true
				c.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
				c.Engine.SigmaEngineCacheSize = 1000
				c.Engine.SigmaEngineCacheTTL = 30 * time.Minute
				c.Engine.SigmaEngineCleanupInterval = 2 * time.Hour // Too large
			},
			expectError: true,
			errorMsg:    "engine.sigma_engine_cleanup_interval must be at most 1 hour",
		},
		{
			name: "cleanup_interval_exceeds_ttl_allowed",
			setupConfig: func(c *Config) {
				c.Engine.EnableNativeSigmaEngine = true
				c.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
				c.Engine.SigmaEngineCacheSize = 1000
				c.Engine.SigmaEngineCacheTTL = 10 * time.Minute
				c.Engine.SigmaEngineCleanupInterval = 15 * time.Minute // Exceeds TTL but within valid range
			},
			expectError: false, // This is allowed, just inefficient
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal valid config
			config := &Config{}
			config.MongoDB.URI = "mongodb://localhost:27017"
			config.MongoDB.Database = "test"
			config.MongoDB.Enabled = true
			config.Listeners.Syslog.Port = 514
			config.Listeners.Syslog.Host = "0.0.0.0"
			config.Listeners.CEF.Port = 515
			config.Listeners.CEF.Host = "0.0.0.0"
			config.Listeners.JSON.Port = 8080
			config.Listeners.JSON.Host = "0.0.0.0"
			config.API.Port = 8081
			config.Retention.Events = 30
			config.Retention.Alerts = 30
			config.Engine.RegexTimeoutMs = 500
			config.Engine.RegexMaxLength = 1000
			config.Engine.CircuitBreaker.MaxFailures = 5
			config.Engine.CircuitBreaker.TimeoutSeconds = 60
			config.Engine.CircuitBreaker.MaxHalfOpenRequests = 3
			config.Security.Webhooks.Timeout = 10
			config.Security.RegexTimeout = 100 * time.Millisecond

			// Apply test-specific configuration
			tt.setupConfig(config)

			// Validate
			err := validateConfig(config)

			if tt.expectError {
				require.Error(t, err, "expected validation error")
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err, "expected no validation error")
			}
		})
	}
}

// TestSigmaEngineConfigLoadFromViper verifies configuration can be loaded via viper.
// REQUIREMENT: Task #131.1 - SIGMA Engine Configuration Loading
func TestSigmaEngineConfigLoadFromViper(t *testing.T) {
	viper.Reset()
	setDefaults()

	// Override some defaults
	viper.Set("engine.enable_native_sigma_engine", true)
	viper.Set("engine.sigma_field_mapping_config", "custom/path/mappings.yaml")
	viper.Set("engine.sigma_engine_cache_size", 2000)
	viper.Set("engine.sigma_engine_cache_ttl", 45*time.Minute)
	viper.Set("engine.sigma_engine_cleanup_interval", 10*time.Minute)

	var config Config
	err := viper.Unmarshal(&config)
	require.NoError(t, err)

	assert.True(t, config.Engine.EnableNativeSigmaEngine)
	assert.Equal(t, "custom/path/mappings.yaml", config.Engine.SigmaFieldMappingConfig)
	assert.Equal(t, 2000, config.Engine.SigmaEngineCacheSize)
	assert.Equal(t, 45*time.Minute, config.Engine.SigmaEngineCacheTTL)
	assert.Equal(t, 10*time.Minute, config.Engine.SigmaEngineCleanupInterval)
}

// TestSigmaEngineConfigYAMLSerialization verifies the mapstructure tags work correctly.
// REQUIREMENT: Task #131.1 - SIGMA Engine Configuration Serialization
func TestSigmaEngineConfigYAMLSerialization(t *testing.T) {
	viper.Reset()
	setDefaults()

	// Set SIGMA config via mapstructure-style keys
	viper.Set("engine.enable_native_sigma_engine", true)
	viper.Set("engine.sigma_field_mapping_config", "test/mappings.yaml")
	viper.Set("engine.sigma_engine_cache_size", 5000)
	viper.Set("engine.sigma_engine_cache_ttl", "1h")
	viper.Set("engine.sigma_engine_cleanup_interval", "15m")

	var config Config
	err := viper.Unmarshal(&config)
	require.NoError(t, err)

	// Verify unmarshaling worked
	assert.True(t, config.Engine.EnableNativeSigmaEngine)
	assert.Equal(t, "test/mappings.yaml", config.Engine.SigmaFieldMappingConfig)
	assert.Equal(t, 5000, config.Engine.SigmaEngineCacheSize)
	assert.Equal(t, 1*time.Hour, config.Engine.SigmaEngineCacheTTL)
	assert.Equal(t, 15*time.Minute, config.Engine.SigmaEngineCleanupInterval)
}

// TestSigmaEngineConfigMinMaxValues verifies boundary conditions.
// REQUIREMENT: Task #131.1 - SIGMA Engine Configuration Bounds
func TestSigmaEngineConfigMinMaxValues(t *testing.T) {
	tests := []struct {
		name       string
		cacheSize  int
		ttl        time.Duration
		cleanup    time.Duration
		shouldFail bool
	}{
		{"min_valid_cache_size", 1, 30 * time.Minute, 5 * time.Minute, false},
		{"max_valid_cache_size", 100000, 30 * time.Minute, 5 * time.Minute, false},
		{"min_valid_ttl", 1000, 1 * time.Minute, 1 * time.Minute, false},
		{"max_valid_ttl", 1000, 24 * time.Hour, 5 * time.Minute, false},
		{"min_valid_cleanup", 1000, 30 * time.Minute, 1 * time.Minute, false},
		{"max_valid_cleanup", 1000, 30 * time.Minute, 1 * time.Hour, false},
		{"zero_cache_size", 0, 30 * time.Minute, 5 * time.Minute, true},
		{"exceeds_max_cache_size", 100001, 30 * time.Minute, 5 * time.Minute, true},
		{"ttl_too_small", 1000, 59 * time.Second, 5 * time.Minute, true},
		{"ttl_too_large", 1000, 25 * time.Hour, 5 * time.Minute, true},
		{"cleanup_too_small", 1000, 30 * time.Minute, 59 * time.Second, true},
		{"cleanup_too_large", 1000, 30 * time.Minute, 61 * time.Minute, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{}
			config.MongoDB.URI = "mongodb://localhost:27017"
			config.MongoDB.Database = "test"
			config.MongoDB.Enabled = true
			config.Listeners.Syslog.Port = 514
			config.Listeners.Syslog.Host = "0.0.0.0"
			config.Listeners.CEF.Port = 515
			config.Listeners.CEF.Host = "0.0.0.0"
			config.Listeners.JSON.Port = 8080
			config.Listeners.JSON.Host = "0.0.0.0"
			config.API.Port = 8081
			config.Retention.Events = 30
			config.Retention.Alerts = 30
			config.Engine.RegexTimeoutMs = 500
			config.Engine.RegexMaxLength = 1000
			config.Engine.CircuitBreaker.MaxFailures = 5
			config.Engine.CircuitBreaker.TimeoutSeconds = 60
			config.Engine.CircuitBreaker.MaxHalfOpenRequests = 3
			config.Security.Webhooks.Timeout = 10
			config.Security.RegexTimeout = 100 * time.Millisecond

			config.Engine.EnableNativeSigmaEngine = true
			config.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
			config.Engine.SigmaEngineCacheSize = tt.cacheSize
			config.Engine.SigmaEngineCacheTTL = tt.ttl
			config.Engine.SigmaEngineCleanupInterval = tt.cleanup

			err := validateConfig(config)

			if tt.shouldFail {
				assert.Error(t, err, "expected validation to fail for %s", tt.name)
			} else {
				assert.NoError(t, err, "expected validation to pass for %s", tt.name)
			}
		})
	}
}
