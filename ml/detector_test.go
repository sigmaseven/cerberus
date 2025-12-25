package ml

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestZScoreDetector_Detect(t *testing.T) {
	logger := zap.NewNop().Sugar()
	detector := NewZScoreDetector(&ZScoreConfig{
		Threshold:  2.0,
		MinSamples: 10,
		Logger:     logger,
	})

	ctx := context.Background()

	// Create normal training data (mean=10, stddev=2)
	features := &FeatureVector{
		EventID:   "train-1",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	// Train with normal data
	for i := 0; i < 20; i++ {
		features.Features["test_feature"] = 10.0 + float64(i%5-2) // Values: 8,9,10,11,12
		features.EventID = "train-" + string(rune(i))
		err := detector.Train(ctx, features)
		require.NoError(t, err)
	}

	// Test normal detection
	normalFeatures := &FeatureVector{
		EventID:   "normal-test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	result, err := detector.Detect(ctx, normalFeatures)
	require.NoError(t, err)
	assert.False(t, result.IsAnomaly)
	assert.InDelta(t, 0.0, result.Score, 1.0) // Should be close to 0

	// Test anomalous detection
	anomalousFeatures := &FeatureVector{
		EventID:   "anomaly-test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 20.0, // 5+ stddev away
		},
	}

	result, err = detector.Detect(ctx, anomalousFeatures)
	require.NoError(t, err)
	assert.True(t, result.IsAnomaly)
	assert.Greater(t, result.Score, 2.0)
	assert.Equal(t, "zscore", result.Algorithm)
}

func TestIQRDetector_Detect(t *testing.T) {
	logger := zap.NewNop().Sugar()
	detector := NewIQRDetector(&IQRConfig{
		MaxSamples: 100,
		Multiplier: 1.5,
		Logger:     logger,
	})

	ctx := context.Background()

	// Create normal training data
	features := &FeatureVector{
		EventID:   "train-1",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	// Train with normal data (values 5-15)
	for i := 0; i < 20; i++ {
		features.Features["test_feature"] = 5.0 + float64(i%11) // Values: 5,6,7,8,9,10,11,12,13,14,15
		features.EventID = "train-" + string(rune(i))
		err := detector.Train(ctx, features)
		require.NoError(t, err)
	}

	// Test normal detection
	normalFeatures := &FeatureVector{
		EventID:   "normal-test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	result, err := detector.Detect(ctx, normalFeatures)
	require.NoError(t, err)
	assert.False(t, result.IsAnomaly)
	assert.Equal(t, 0.0, result.Score)

	// Test anomalous detection (outlier)
	anomalousFeatures := &FeatureVector{
		EventID:   "anomaly-test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 30.0, // Way outside IQR
		},
	}

	result, err = detector.Detect(ctx, anomalousFeatures)
	require.NoError(t, err)
	assert.True(t, result.IsAnomaly)
	assert.Greater(t, result.Score, 0.0)
	assert.Equal(t, "iqr", result.Algorithm)
}

func TestStatisticalDetectorManager_DetectMajorityVote(t *testing.T) {
	logger := zap.NewNop().Sugar()
	manager := NewStatisticalDetectorManager(&StatisticalDetectorConfig{
		Detectors: []string{"zscore", "iqr"},
		Logger:    logger,
	})

	ctx := context.Background()

	// Train with normal data
	features := &FeatureVector{
		EventID:   "train-1",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	for i := 0; i < 50; i++ {
		features.Features["test_feature"] = 10.0 + float64(i%5-2)
		features.EventID = "train-" + string(rune(i))
		err := manager.Train(ctx, features)
		require.NoError(t, err)
	}

	// Test normal detection
	normalFeatures := &FeatureVector{
		EventID:   "normal-test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	result, err := manager.DetectMajorityVote(ctx, normalFeatures)
	require.NoError(t, err)
	assert.False(t, result.IsAnomaly)

	// Test anomalous detection
	anomalousFeatures := &FeatureVector{
		EventID:   "anomaly-test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 25.0, // Should be anomalous for both detectors
		},
	}

	result, err = manager.DetectMajorityVote(ctx, anomalousFeatures)
	require.NoError(t, err)
	assert.True(t, result.IsAnomaly)
	assert.Contains(t, result.Algorithm, "majority_vote")
}

func TestZScoreDetector_InsufficientData(t *testing.T) {
	logger := zap.NewNop().Sugar()
	detector := NewZScoreDetector(&ZScoreConfig{
		MinSamples: 100, // Require lots of samples
		Logger:     logger,
	})

	ctx := context.Background()

	// Train with insufficient data
	features := &FeatureVector{
		EventID:   "train-1",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	for i := 0; i < 10; i++ { // Less than MinSamples
		err := detector.Train(ctx, features)
		require.NoError(t, err)
	}

	// Detection should not flag as anomaly due to insufficient training
	testFeatures := &FeatureVector{
		EventID:   "test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 100.0, // Very different value
		},
	}

	result, err := detector.Detect(ctx, testFeatures)
	require.NoError(t, err)
	assert.False(t, result.IsAnomaly) // Should not detect due to insufficient training
}

func TestIQRDetector_QuantileCalculation(t *testing.T) {
	logger := zap.NewNop().Sugar()
	detector := NewIQRDetector(&IQRConfig{
		Logger: logger,
	})

	// Test quantile calculation directly
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	q25 := detector.calculateQuantile(values, 0.25)
	q50 := detector.calculateQuantile(values, 0.5)
	q75 := detector.calculateQuantile(values, 0.75)

	assert.InDelta(t, 3.25, q25, 0.01) // (2+3)/2 * 0.25 adjustment
	assert.Equal(t, 5.5, q50)          // (5+6)/2
	assert.InDelta(t, 7.75, q75, 0.01) // (7+8)/2 * 0.75 adjustment
}

func TestStatisticalDetectorManager_GetDetector(t *testing.T) {
	logger := zap.NewNop().Sugar()
	manager := NewStatisticalDetectorManager(&StatisticalDetectorConfig{
		Detectors: []string{"zscore"},
		Logger:    logger,
	})

	// Test getting existing detector
	detector, err := manager.GetDetector("zscore")
	require.NoError(t, err)
	assert.NotNil(t, detector)
	assert.Equal(t, "zscore", detector.Name())

	// Test getting non-existent detector
	_, err = manager.GetDetector("nonexistent")
	assert.Error(t, err)
}

func TestStatisticalDetectorManager_AddRemoveDetector(t *testing.T) {
	logger := zap.NewNop().Sugar()
	manager := NewStatisticalDetectorManager(&StatisticalDetectorConfig{
		Detectors: []string{"iqr"}, // Start with just IQR detector
		Logger:    logger,
	})

	// Add detector
	zscoreDetector := NewZScoreDetector(&ZScoreConfig{Logger: logger})
	err := manager.AddDetector("zscore", zscoreDetector)
	require.NoError(t, err)

	// Verify it was added
	detector, err := manager.GetDetector("zscore")
	require.NoError(t, err)
	assert.Equal(t, zscoreDetector, detector)

	// Try to add duplicate
	err = manager.AddDetector("zscore", zscoreDetector)
	assert.Error(t, err)

	// Remove detector
	err = manager.RemoveDetector("zscore")
	require.NoError(t, err)

	// Verify it was removed
	_, err = manager.GetDetector("zscore")
	assert.Error(t, err)

	// Try to remove non-existent
	err = manager.RemoveDetector("nonexistent")
	assert.Error(t, err)
}

func BenchmarkZScoreDetector_Detect(b *testing.B) {
	logger := zap.NewNop().Sugar()
	detector := NewZScoreDetector(&ZScoreConfig{
		Logger: logger,
	})

	ctx := context.Background()

	// Pre-train detector
	features := &FeatureVector{
		EventID:   "train",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	for i := 0; i < 100; i++ {
		features.Features["test_feature"] = 10.0 + float64(i%10-5)
		err := detector.Train(ctx, features)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Benchmark detection
	testFeatures := &FeatureVector{
		EventID:   "test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := detector.Detect(ctx, testFeatures)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIQRDetector_Detect(b *testing.B) {
	logger := zap.NewNop().Sugar()
	detector := NewIQRDetector(&IQRConfig{
		Logger: logger,
	})

	ctx := context.Background()

	// Pre-train detector
	features := &FeatureVector{
		EventID:   "train",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	for i := 0; i < 100; i++ {
		features.Features["test_feature"] = 5.0 + float64(i%11)
		err := detector.Train(ctx, features)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Benchmark detection
	testFeatures := &FeatureVector{
		EventID:   "test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := detector.Detect(ctx, testFeatures)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStatisticalDetectorManager_DetectMajorityVote(b *testing.B) {
	logger := zap.NewNop().Sugar()
	manager := NewStatisticalDetectorManager(&StatisticalDetectorConfig{
		Detectors: []string{"zscore", "iqr"},
		Logger:    logger,
	})

	ctx := context.Background()

	// Pre-train manager
	features := &FeatureVector{
		EventID:   "train",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	for i := 0; i < 50; i++ {
		features.Features["test_feature"] = 10.0 + float64(i%5-2)
		err := manager.Train(ctx, features)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Benchmark detection
	testFeatures := &FeatureVector{
		EventID:   "test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 10.0,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.DetectMajorityVote(ctx, testFeatures)
		if err != nil {
			b.Fatal(err)
		}
	}
}
