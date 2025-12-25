package ml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TASK 59.4: Feature Normalization Tests
// Tests cover: min-max scaling, z-score normalization, outlier handling

// TestZScoreNormalizer_UpdateStats tests statistics update
func TestZScoreNormalizer_UpdateStats(t *testing.T) {
	logger := zap.NewNop().Sugar()
	normalizer := NewZScoreNormalizer(logger)

	// Update with values
	values := []float64{10.0, 20.0, 30.0, 40.0, 50.0}
	for _, val := range values {
		normalizer.UpdateStats("test_feature", val)
	}

	// Get statistics
	mean, stddev, min, max, count := normalizer.GetStats("test_feature")
	assert.Equal(t, int64(5), count, "Should have 5 samples")
	assert.Equal(t, 10.0, min, "Minimum should be 10")
	assert.Equal(t, 50.0, max, "Maximum should be 50")
	assert.Equal(t, 30.0, mean, "Mean should be 30")
	assert.Greater(t, stddev, 0.0, "Standard deviation should be positive")
}

// TestZScoreNormalizer_Normalize tests z-score normalization
func TestZScoreNormalizer_Normalize(t *testing.T) {
	logger := zap.NewNop().Sugar()
	normalizer := NewZScoreNormalizer(logger)

	// Train with values (mean=30, stddev≈15.81)
	values := []float64{10.0, 20.0, 30.0, 40.0, 50.0}
	for _, val := range values {
		normalizer.UpdateStats("test_feature", val)
	}

	// Normalize mean value (should be close to 0)
	normalized := normalizer.Normalize("test_feature", 30.0)
	assert.InDelta(t, 0.0, normalized, 0.1, "Mean value should normalize to ~0")

	// Normalize value one stddev above mean (should be ~1)
	mean, stddev, _, _, _ := normalizer.GetStats("test_feature")
	valueOneStdDevAbove := mean + stddev
	normalized = normalizer.Normalize("test_feature", valueOneStdDevAbove)
	assert.InDelta(t, 1.0, normalized, 0.1, "Value one stddev above mean should normalize to ~1")
}

// TestZScoreNormalizer_InsufficientData tests normalization with insufficient data
func TestZScoreNormalizer_InsufficientData(t *testing.T) {
	logger := zap.NewNop().Sugar()
	normalizer := NewZScoreNormalizer(logger)

	// Single value (not enough for stddev calculation)
	normalizer.UpdateStats("test_feature", 10.0)

	// Normalize should return original value (not enough data)
	normalized := normalizer.Normalize("test_feature", 20.0)
	assert.Equal(t, 20.0, normalized, "Should return original value with insufficient data")
}

// TestMinMaxNormalizer_Normalize tests min-max normalization
func TestMinMaxNormalizer_Normalize(t *testing.T) {
	logger := zap.NewNop().Sugar()
	normalizer := NewMinMaxNormalizer(logger)

	// Train with values (min=10, max=50)
	values := []float64{10.0, 20.0, 30.0, 40.0, 50.0}
	for _, val := range values {
		normalizer.UpdateStats("test_feature", val)
	}

	// Normalize minimum (should be 0)
	normalized := normalizer.Normalize("test_feature", 10.0)
	assert.Equal(t, 0.0, normalized, "Minimum should normalize to 0")

	// Normalize maximum (should be 1)
	normalized = normalizer.Normalize("test_feature", 50.0)
	assert.Equal(t, 1.0, normalized, "Maximum should normalize to 1")

	// Normalize middle value (should be 0.5)
	normalized = normalizer.Normalize("test_feature", 30.0)
	assert.InDelta(t, 0.5, normalized, 0.01, "Middle value should normalize to ~0.5")
}

// TestMinMaxNormalizer_OutOfRange tests out-of-range values
func TestMinMaxNormalizer_OutOfRange(t *testing.T) {
	logger := zap.NewNop().Sugar()
	normalizer := NewMinMaxNormalizer(logger)

	// Train with values (min=10, max=50)
	values := []float64{10.0, 20.0, 30.0, 40.0, 50.0}
	for _, val := range values {
		normalizer.UpdateStats("test_feature", val)
	}

	// Normalize value below minimum
	// MinMaxNormalizer clamps values to [0, 1] range
	normalized := normalizer.Normalize("test_feature", 5.0)
	// Value below minimum is clamped to 0.0
	assert.Equal(t, 0.0, normalized, "Value below minimum should be clamped to 0")

	// Normalize value above maximum
	normalized = normalizer.Normalize("test_feature", 60.0)
	// Value above maximum is clamped to 1.0
	assert.Equal(t, 1.0, normalized, "Value above maximum should be clamped to 1")
}

// TestFeatureNormalizerManager_SelectNormalizer tests normalizer selection
func TestFeatureNormalizerManager_SelectNormalizer(t *testing.T) {
	logger := zap.NewNop().Sugar()
	manager := NewFeatureNormalizerManager(logger)

	// Test z-score normalization
	normalized := manager.NormalizeFeature("zscore", "test_feature", 10.0)
	assert.NotNil(t, normalized, "Should normalize using z-score")

	// Test min-max normalization
	normalized = manager.NormalizeFeature("minmax", "test_feature", 10.0)
	assert.NotNil(t, normalized, "Should normalize using min-max")

	// Test unknown method (should return original value)
	normalized = manager.NormalizeFeature("unknown", "test_feature", 10.0)
	assert.Equal(t, 10.0, normalized, "Unknown method should return original value")
}
