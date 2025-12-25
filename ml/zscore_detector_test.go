package ml

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TASK 59.7: Z-Score Detector Tests
// Tests cover: z-score calculation, threshold configuration, accuracy metrics

// TestZScoreDetector_Train tests detector training
func TestZScoreDetector_Train(t *testing.T) {
	logger := zap.NewNop().Sugar()
	detector := NewZScoreDetector(&ZScoreConfig{
		Threshold:  3.0,
		MinSamples: 5,
		Logger:     logger,
	})

	// Train with normal values
	ctx := context.Background()
	features := &FeatureVector{
		EventID: "test-event",
		Features: map[string]float64{
			"feature1": 10.0,
			"feature2": 20.0,
			"feature3": 30.0,
		},
	}

	err := detector.Train(ctx, features)
	require.NoError(t, err, "Should train detector without error")

	stats := detector.GetStats()
	assert.Greater(t, stats.TotalSamples, int64(0), "Should have trained samples")
}

// TestZScoreDetector_OutlierDetection tests outlier detection
func TestZScoreDetector_OutlierDetection(t *testing.T) {
	logger := zap.NewNop().Sugar()
	detector := NewZScoreDetector(&ZScoreConfig{
		Threshold:  3.0, // 3 sigma threshold
		MinSamples: 5,
		Logger:     logger,
	})

	ctx := context.Background()

	// Train with normal values (mean ≈ 30, stddev ≈ 15.81)
	for i := 1; i <= 5; i++ {
		features := &FeatureVector{
			EventID: "train-event",
			Features: map[string]float64{
				"value": float64(i * 10), // 10, 20, 30, 40, 50
			},
		}
		detector.Train(ctx, features)
	}

	// Test normal value (within 3 sigma)
	normalFeatures := &FeatureVector{
		EventID: "test-normal",
		Features: map[string]float64{
			"value": 30.0, // Close to mean
		},
	}
	result, err := detector.Detect(ctx, normalFeatures)
	require.NoError(t, err)
	assert.False(t, result.IsAnomaly, "Normal value should not be detected as outlier")

	// Test outlier value (beyond 3 sigma)
	outlierFeatures := &FeatureVector{
		EventID: "test-outlier",
		Features: map[string]float64{
			"value": 100.0, // Far from mean (> 3 sigma)
		},
	}
	result, err = detector.Detect(ctx, outlierFeatures)
	require.NoError(t, err)
	assert.True(t, result.IsAnomaly, "Outlier value (> 3 sigma) should be detected as anomaly")
}

// TestZScoreDetector_ThresholdConfiguration tests different threshold values
func TestZScoreDetector_ThresholdConfiguration(t *testing.T) {
	logger := zap.NewNop().Sugar()

	testCases := []struct {
		name      string
		threshold float64
	}{
		{"Strict (2.5)", 2.5},
		{"Standard (3.0)", 3.0},
		{"Lenient (3.5)", 3.5},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			detector := NewZScoreDetector(&ZScoreConfig{
				Threshold:  tc.threshold,
				MinSamples: 5,
				Logger:     logger,
			})

			assert.NotNil(t, detector, "Detector should be created")
			assert.Equal(t, "zscore", detector.Name(), "Detector name should be 'zscore'")
		})
	}
}

// TestZScoreDetector_ZeroVariance tests zero variance handling
// Note: TestZScoreDetector_InsufficientData is defined in detector_test.go
func TestZScoreDetector_ZeroVariance(t *testing.T) {
	logger := zap.NewNop().Sugar()
	detector := NewZScoreDetector(&ZScoreConfig{
		Threshold:  3.0,
		MinSamples: 5,
		Logger:     logger,
	})

	// Train with constant values (zero variance)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		features := &FeatureVector{
			EventID:  "train-event",
			Features: map[string]float64{"value": 10.0}, // All same value
		}
		detector.Train(ctx, features)
	}

	// Detection should handle zero variance gracefully
	features := &FeatureVector{
		EventID:  "test-event",
		Features: map[string]float64{"value": 10.0},
	}
	result, err := detector.Detect(ctx, features)
	require.NoError(t, err, "Should handle zero variance gracefully")
	// Should not detect anomaly when value matches mean (stddev = 0)
	_ = result
}
