package api

import (
	"encoding/json"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SimpleMLConfigManager provides a simple in-memory ML configuration manager
type SimpleMLConfigManager struct {
	mu     sync.RWMutex
	config *MLAPIConfig
	logger *zap.SugaredLogger
}

// NewSimpleMLConfigManager creates a new simple ML config manager
func NewSimpleMLConfigManager(logger *zap.SugaredLogger) *SimpleMLConfigManager {
	return &SimpleMLConfigManager{
		config: &MLAPIConfig{
			Enabled:          true,
			BatchSize:        1000,
			TrainingInterval: "1h",
			RetrainThreshold: 5000,
			ValidationRatio:  0.2,
			EnableContinuous: true,
			DriftDetection:   true,
			MinConfidence:    0.6,
			Algorithms:       []string{"zscore", "iqr", "isolation_forest"},
			VotingStrategy:   "weighted",
			Weights: map[string]float64{
				"zscore":           1.0,
				"iqr":              1.0,
				"isolation_forest": 1.0,
			},
		},
		logger: logger,
	}
}

// GetMLConfig returns the current ML configuration
func (m *SimpleMLConfigManager) GetMLConfig() (*MLAPIConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent external modification
	configCopy := *m.config
	return &configCopy, nil
}

// UpdateMLConfig updates the ML configuration
func (m *SimpleMLConfigManager) UpdateMLConfig(config *MLAPIConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate configuration
	if config.BatchSize <= 0 {
		config.BatchSize = 1000
	}
	if config.TrainingInterval == "" {
		config.TrainingInterval = "1h"
	}
	if config.RetrainThreshold <= 0 {
		config.RetrainThreshold = 5000
	}
	if config.ValidationRatio <= 0 || config.ValidationRatio >= 1 {
		config.ValidationRatio = 0.2
	}
	if config.MinConfidence <= 0 || config.MinConfidence > 1 {
		config.MinConfidence = 0.6
	}
	if len(config.Algorithms) == 0 {
		config.Algorithms = []string{"zscore", "iqr", "isolation_forest"}
	}
	if config.VotingStrategy == "" {
		config.VotingStrategy = "weighted"
	}
	if config.Weights == nil {
		config.Weights = map[string]float64{
			"zscore":           1.0,
			"iqr":              1.0,
			"isolation_forest": 1.0,
		}
	}

	// Ensure all algorithms have weights
	for _, algo := range config.Algorithms {
		if _, exists := config.Weights[algo]; !exists {
			config.Weights[algo] = 1.0
		}
	}

	m.config = config

	// Log configuration update (existing non-audit log)
	configJSON, _ := json.Marshal(config)
	m.logger.Infow("ML configuration updated", "config", string(configJSON))

	return nil
}

// UpdateMLConfigWithAudit updates ML configuration with audit logging
// This is a wrapper to add audit logging when called from API handlers
func (m *SimpleMLConfigManager) UpdateMLConfigWithAudit(config *MLAPIConfig, username, sourceIP string) error {
	// AUDIT: ML configuration update attempt
	m.logger.Infow("AUDIT: ML configuration update initiated",
		"action", "update_ml_config",
		"username", username,
		"source_ip", sourceIP,
		"resource_type", "ml_config",
		"timestamp", time.Now().UTC())

	err := m.UpdateMLConfig(config)
	if err != nil {
		// AUDIT: Failed ML configuration update
		m.logger.Infow("AUDIT: ML configuration update failed",
			"action", "update_ml_config",
			"outcome", "failure",
			"username", username,
			"source_ip", sourceIP,
			"resource_type", "ml_config",
			"error", err.Error(),
			"timestamp", time.Now().UTC())
		return err
	}

	// AUDIT: Successful ML configuration update
	m.logger.Infow("AUDIT: ML configuration updated successfully",
		"action", "update_ml_config",
		"outcome", "success",
		"username", username,
		"source_ip", sourceIP,
		"resource_type", "ml_config",
		"enabled", config.Enabled,
		"batch_size", config.BatchSize,
		"training_interval", config.TrainingInterval,
		"drift_detection", config.DriftDetection,
		"algorithms", config.Algorithms,
		"voting_strategy", config.VotingStrategy,
		"timestamp", time.Now().UTC())

	return nil
}
