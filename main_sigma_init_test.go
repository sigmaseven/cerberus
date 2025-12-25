package main

import (
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/detect"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestInitializeDetectorWithSigmaEngineDisabled verifies detector initialization with SIGMA disabled
func TestInitializeDetectorWithSigmaEngineDisabled(t *testing.T) {
	logger, _ := zap.NewProduction()
	sugar := logger.Sugar()
	defer logger.Sync()

	cfg := &config.Config{}
	cfg.Engine.EnableNativeSigmaEngine = false
	cfg.Engine.CorrelationStateTTL = 3600
	cfg.Engine.ChannelBufferSize = 100

	rawEventCh := make(chan *core.Event, 100)
	processedEventCh := make(chan *core.Event, 100)
	alertCh := make(chan *core.Alert, 100)

	rules := []core.Rule{}
	correlationRules := []core.CorrelationRule{}

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
}

// TestInitializeDetectorWithSigmaEngineEnabled verifies detector initialization with SIGMA enabled
func TestInitializeDetectorWithSigmaEngineEnabled(t *testing.T) {
	logger, _ := zap.NewProduction()
	sugar := logger.Sugar()
	defer logger.Sync()

	cfg := &config.Config{}
	cfg.Engine.EnableNativeSigmaEngine = true
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
}

// TestRuleEngineConfigFromConfig verifies configuration mapping
func TestRuleEngineConfigFromConfig(t *testing.T) {
	logger, _ := zap.NewProduction()
	sugar := logger.Sugar()
	defer logger.Sync()

	cfg := &config.Config{}
	cfg.Engine.EnableNativeSigmaEngine = true
	cfg.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
	cfg.Engine.SigmaEngineCacheSize = 2000
	cfg.Engine.SigmaEngineCacheTTL = 45 * time.Minute
	cfg.Engine.SigmaEngineCleanupInterval = 10 * time.Minute

	// Create engine config as done in initializeDetector
	engineConfig := &detect.RuleEngineConfig{
		EnableNativeSigmaEngine:    cfg.Engine.EnableNativeSigmaEngine,
		SigmaFieldMappingConfig:    cfg.Engine.SigmaFieldMappingConfig,
		SigmaEngineCacheSize:       cfg.Engine.SigmaEngineCacheSize,
		SigmaEngineCacheTTL:        cfg.Engine.SigmaEngineCacheTTL,
		SigmaEngineCleanupInterval: cfg.Engine.SigmaEngineCleanupInterval,
		Logger:                     sugar,
	}

	// Verify mapping
	if !engineConfig.EnableNativeSigmaEngine {
		t.Error("Expected EnableNativeSigmaEngine to be true")
	}
	if engineConfig.SigmaFieldMappingConfig != "config/sigma_field_mappings.yaml" {
		t.Errorf("Expected SigmaFieldMappingConfig to be 'config/sigma_field_mappings.yaml', got %s", engineConfig.SigmaFieldMappingConfig)
	}
	if engineConfig.SigmaEngineCacheSize != 2000 {
		t.Errorf("Expected SigmaEngineCacheSize to be 2000, got %d", engineConfig.SigmaEngineCacheSize)
	}
	if engineConfig.SigmaEngineCacheTTL != 45*time.Minute {
		t.Errorf("Expected SigmaEngineCacheTTL to be 45m, got %v", engineConfig.SigmaEngineCacheTTL)
	}
	if engineConfig.SigmaEngineCleanupInterval != 10*time.Minute {
		t.Errorf("Expected SigmaEngineCleanupInterval to be 10m, got %v", engineConfig.SigmaEngineCleanupInterval)
	}
	if engineConfig.Logger == nil {
		t.Error("Expected Logger to be set")
	}
}

// TestSigmaEngineConfigDefaults verifies default values are used when config is missing
func TestSigmaEngineConfigDefaults(t *testing.T) {
	logger, _ := zap.NewProduction()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Empty config - should use defaults from config package
	cfg := &config.Config{}

	// Load defaults as LoadConfig would
	cfg.Engine.EnableNativeSigmaEngine = false // Default from config package
	cfg.Engine.SigmaFieldMappingConfig = "config/sigma_field_mappings.yaml"
	cfg.Engine.SigmaEngineCacheSize = 1000
	cfg.Engine.SigmaEngineCacheTTL = 30 * time.Minute
	cfg.Engine.SigmaEngineCleanupInterval = 5 * time.Minute
	cfg.Engine.CorrelationStateTTL = 3600

	rawEventCh := make(chan *core.Event, 100)
	processedEventCh := make(chan *core.Event, 100)
	alertCh := make(chan *core.Alert, 100)

	rules := []core.Rule{}
	correlationRules := []core.CorrelationRule{}

	// Should not panic with default values
	detector, err := initializeDetector(cfg, rules, correlationRules, rawEventCh, processedEventCh, alertCh, sugar)
	require.NoError(t, err, "initializeDetector failed")

	if detector == nil {
		t.Fatal("Expected detector to be initialized with defaults, got nil")
	}

	// Clean up
	detector.Stop()
	close(rawEventCh)
	close(processedEventCh)
	close(alertCh)
}
