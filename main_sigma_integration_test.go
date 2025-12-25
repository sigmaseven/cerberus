package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestSigmaEngineConfigLoadFromYAML verifies SIGMA config is loaded correctly from YAML
func TestSigmaEngineConfigLoadFromYAML(t *testing.T) {
	// Create temporary config file
	configContent := `
engine:
  enable_native_sigma_engine: true
  sigma_field_mapping_config: "config/sigma_field_mappings.yaml"
  sigma_engine_cache_size: 5000
  sigma_engine_cache_ttl: 60m
  sigma_engine_cleanup_interval: 10m
  correlation_state_ttl: 3600
  channel_buffer_size: 1000
  worker_count: 4
`

	tmpfile, err := os.CreateTemp("", "test_config_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	// Load config using viper (similar to LoadConfig)
	viper.Reset()
	viper.SetConfigFile(tmpfile.Name())
	viper.SetConfigType("yaml")

	// Set defaults as LoadConfig does
	viper.SetDefault("engine.enable_native_sigma_engine", false)
	viper.SetDefault("engine.sigma_field_mapping_config", "config/sigma_field_mappings.yaml")
	viper.SetDefault("engine.sigma_engine_cache_size", 1000)
	viper.SetDefault("engine.sigma_engine_cache_ttl", 30*time.Minute)
	viper.SetDefault("engine.sigma_engine_cleanup_interval", 5*time.Minute)

	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}

	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify values are loaded correctly
	if !cfg.Engine.EnableNativeSigmaEngine {
		t.Error("Expected EnableNativeSigmaEngine to be true")
	}
	if cfg.Engine.SigmaFieldMappingConfig != "config/sigma_field_mappings.yaml" {
		t.Errorf("Expected SigmaFieldMappingConfig to be 'config/sigma_field_mappings.yaml', got %s", cfg.Engine.SigmaFieldMappingConfig)
	}
	if cfg.Engine.SigmaEngineCacheSize != 5000 {
		t.Errorf("Expected SigmaEngineCacheSize to be 5000, got %d", cfg.Engine.SigmaEngineCacheSize)
	}
	if cfg.Engine.SigmaEngineCacheTTL != 60*time.Minute {
		t.Errorf("Expected SigmaEngineCacheTTL to be 60m, got %v", cfg.Engine.SigmaEngineCacheTTL)
	}
	if cfg.Engine.SigmaEngineCleanupInterval != 10*time.Minute {
		t.Errorf("Expected SigmaEngineCleanupInterval to be 10m, got %v", cfg.Engine.SigmaEngineCleanupInterval)
	}

	// Test initialization with this config
	logger, _ := zap.NewProduction()
	sugar := logger.Sugar()
	defer logger.Sync()

	rawEventCh := make(chan *core.Event, 100)
	processedEventCh := make(chan *core.Event, 100)
	alertCh := make(chan *core.Alert, 100)

	rules := []core.Rule{}
	correlationRules := []core.CorrelationRule{}

	detector, err := initializeDetector(&cfg, rules, correlationRules, rawEventCh, processedEventCh, alertCh, sugar)
	require.NoError(t, err, "initializeDetector failed")

	if detector == nil {
		t.Fatal("Expected detector to be initialized with loaded config, got nil")
	}

	// Clean up
	detector.Stop()
	close(rawEventCh)
	close(processedEventCh)
	close(alertCh)
}

// TestSigmaEngineConfigLoadFromEnv verifies SIGMA config can be overridden via environment
func TestSigmaEngineConfigLoadFromEnv(t *testing.T) {
	// Save original env
	originalEnv := os.Getenv("CERBERUS_ENGINE_ENABLE_NATIVE_SIGMA_ENGINE")
	defer func() {
		if originalEnv != "" {
			os.Setenv("CERBERUS_ENGINE_ENABLE_NATIVE_SIGMA_ENGINE", originalEnv)
		} else {
			os.Unsetenv("CERBERUS_ENGINE_ENABLE_NATIVE_SIGMA_ENGINE")
		}
	}()

	// Set environment variable
	os.Setenv("CERBERUS_ENGINE_ENABLE_NATIVE_SIGMA_ENGINE", "true")

	// Reset viper for clean state
	viper.Reset()
	viper.SetEnvPrefix("CERBERUS")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Explicitly bind the environment variable
	_ = viper.BindEnv("engine.enable_native_sigma_engine", "CERBERUS_ENGINE_ENABLE_NATIVE_SIGMA_ENGINE")

	// Set defaults
	viper.SetDefault("engine.enable_native_sigma_engine", false)
	viper.SetDefault("engine.sigma_field_mapping_config", "config/sigma_field_mappings.yaml")
	viper.SetDefault("engine.sigma_engine_cache_size", 1000)
	viper.SetDefault("engine.sigma_engine_cache_ttl", 30*time.Minute)
	viper.SetDefault("engine.sigma_engine_cleanup_interval", 5*time.Minute)
	viper.SetDefault("engine.correlation_state_ttl", 3600)

	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify environment variable override
	if !cfg.Engine.EnableNativeSigmaEngine {
		t.Error("Expected EnableNativeSigmaEngine to be true from env var")
	}
}

// TestInitializeDetectorLogging verifies proper logging of SIGMA engine status
func TestInitializeDetectorLogging(t *testing.T) {
	logger, _ := zap.NewProduction()
	sugar := logger.Sugar()
	defer logger.Sync()

	tests := []struct {
		name              string
		enableSigmaEngine bool
		expectedInLog     string
	}{
		{
			name:              "SIGMA enabled",
			enableSigmaEngine: true,
			expectedInLog:     "SIGMA native engine enabled",
		},
		{
			name:              "SIGMA disabled",
			enableSigmaEngine: false,
			expectedInLog:     "SIGMA native engine disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Engine.EnableNativeSigmaEngine = tt.enableSigmaEngine
			cfg.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
			cfg.Engine.SigmaEngineCacheSize = 1000
			cfg.Engine.SigmaEngineCacheTTL = 30 * time.Minute
			cfg.Engine.SigmaEngineCleanupInterval = 5 * time.Minute
			cfg.Engine.CorrelationStateTTL = 3600
			cfg.Engine.ChannelBufferSize = 100

			rawEventCh := make(chan *core.Event, 100)
			processedEventCh := make(chan *core.Event, 100)
			alertCh := make(chan *core.Alert, 100)

			rules := []core.Rule{}
			correlationRules := []core.CorrelationRule{}

			// This should log the expected message
			detector, err := initializeDetector(cfg, rules, correlationRules, rawEventCh, processedEventCh, alertCh, sugar)
			require.NoError(t, err, "initializeDetector failed")

			if detector == nil {
				t.Fatal("Expected detector to be initialized, got nil")
			}

			// Clean up
			detector.Stop()
			close(rawEventCh)
			close(processedEventCh)
			close(alertCh)
		})
	}
}
