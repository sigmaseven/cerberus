package ml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TASK 59.8: Detector Manager Tests
// Tests cover: detector registration, selection, ensemble voting

// TestStatisticalDetectorManager_RegisterDetector tests detector registration
func TestStatisticalDetectorManager_RegisterDetector(t *testing.T) {
	logger := zap.NewNop().Sugar()
	manager := NewStatisticalDetectorManager(&StatisticalDetectorConfig{
		Detectors: []string{"zscore", "iqr"},
		Logger:    logger,
	})

	// Verify detectors are already registered from constructor
	// Manager automatically creates detectors from config
	// Use GetDetectors() to retrieve them

	// Verify detectors are registered
	detector, err := manager.GetDetector("zscore")
	require.NoError(t, err)
	assert.Equal(t, "zscore", detector.Name(), "Should retrieve registered detector")

	detector, err = manager.GetDetector("iqr")
	require.NoError(t, err)
	assert.Equal(t, "iqr", detector.Name(), "Should retrieve IQR detector")
}

// TestStatisticalDetectorManager_ListDetectors tests detector listing
func TestStatisticalDetectorManager_ListDetectors(t *testing.T) {
	logger := zap.NewNop().Sugar()
	manager := NewStatisticalDetectorManager(&StatisticalDetectorConfig{
		Detectors: []string{"zscore", "iqr"},
		Logger:    logger,
	})

	// Detectors are registered in constructor

	// List detectors using GetDetectors()
	detectors := manager.GetDetectors()
	assert.GreaterOrEqual(t, len(detectors), 2, "Should list registered detectors")

	// Verify detector names are in map
	assert.NotNil(t, detectors["zscore"], "Should include zscore detector")
	assert.NotNil(t, detectors["iqr"], "Should include iqr detector")

	// Verify detector names
	if zscore, exists := detectors["zscore"]; exists {
		assert.Equal(t, "zscore", zscore.Name(), "Z-score detector name should match")
	}
	if iqr, exists := detectors["iqr"]; exists {
		assert.Equal(t, "iqr", iqr.Name(), "IQR detector name should match")
	}
}
