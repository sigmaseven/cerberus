package api

import (
	"go.uber.org/zap"
)

// MLManager coordinates all ML components
type MLManager struct {
	detector      MLAnomalyDetector
	configManager MLConfigManager
	metrics       *MLMetricsCollector
	logger        *zap.SugaredLogger
}

// NewMLManager creates a new ML manager
func NewMLManager(detector MLAnomalyDetector, logger *zap.SugaredLogger) *MLManager {
	return &MLManager{
		detector:      detector,
		configManager: NewSimpleMLConfigManager(logger),
		metrics:       NewMLMetricsCollector(),
		logger:        logger,
	}
}
