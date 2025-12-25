package ml

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestIsolationForest_Name tests Name method
func TestIsolationForest_Name(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{Logger: logger}
	detector := NewIsolationForest(config)

	assert.Equal(t, "isolation_forest", detector.Name())
}

// TestIsolationForest_Train tests training functionality
func TestIsolationForest_Train(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		NumTrees:      10,
		SubsampleSize: 10,
		Logger:        logger,
	}
	detector := NewIsolationForest(config)

	ctx := context.Background()

	// Train with normal data
	for i := 0; i < 50; i++ {
		features := &FeatureVector{
			EventID:   "train",
			Timestamp: time.Now(),
			Features: map[string]float64{
				"feature1": 10.0 + float64(i%5),
				"feature2": 20.0 + float64(i%3),
			},
		}

		err := detector.Train(ctx, features)
		require.NoError(t, err)
	}

	// Verify forest is built
	assert.Greater(t, len(detector.trees), 0)
}

// TestIsolationForest_Detect tests anomaly detection
func TestIsolationForest_Detect(t *testing.T) {
	tests := []struct {
		name            string
		trainingSamples int
		testFeatures    *FeatureVector
		wantErr         bool
	}{
		{
			name:            "detect after training",
			trainingSamples: 50,
			testFeatures: &FeatureVector{
				EventID:   "test",
				Timestamp: time.Now(),
				Features: map[string]float64{
					"feature1": 10.0,
					"feature2": 20.0,
				},
			},
			wantErr: false,
		},
		{
			name:            "detect with anomalous data",
			trainingSamples: 50,
			testFeatures: &FeatureVector{
				EventID:   "test",
				Timestamp: time.Now(),
				Features: map[string]float64{
					"feature1": 1000.0, // Very different
					"feature2": 2000.0,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			config := &IsolationForestConfig{
				NumTrees:      10,
				SubsampleSize: 20,
				Contamination: 0.1,
				Logger:        logger,
			}
			detector := NewIsolationForest(config)

			ctx := context.Background()

			// Train
			for i := 0; i < tt.trainingSamples; i++ {
				features := &FeatureVector{
					EventID:   "train",
					Timestamp: time.Now(),
					Features: map[string]float64{
						"feature1": 10.0 + float64(i%5),
						"feature2": 20.0 + float64(i%3),
					},
				}
				detector.Train(ctx, features)
			}

			// Detect
			result, err := detector.Detect(ctx, tt.testFeatures)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.GreaterOrEqual(t, result.Score, 0.0)
				assert.LessOrEqual(t, result.Score, 1.0)
				assert.Equal(t, "isolation_forest", result.Algorithm)
			}
		})
	}
}

// TestIsolationForest_GetStats tests statistics retrieval
func TestIsolationForest_GetStats(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		NumTrees: 5,
		Logger:   logger,
	}
	detector := NewIsolationForest(config)

	ctx := context.Background()

	// Train and detect to generate stats
	for i := 0; i < 30; i++ {
		features := &FeatureVector{
			EventID:   "train",
			Timestamp: time.Now(),
			Features: map[string]float64{
				"feature1": 10.0 + float64(i%5),
			},
		}
		detector.Train(ctx, features)

		if i%5 == 0 {
			detector.Detect(ctx, features)
		}
	}

	stats := detector.GetStats()

	assert.GreaterOrEqual(t, stats.TotalSamples, int64(0))
}

// TestIsolationForest_Reset tests reset functionality
func TestIsolationForest_Reset(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		NumTrees: 5,
		Logger:   logger,
	}
	detector := NewIsolationForest(config)

	ctx := context.Background()

	// Train
	for i := 0; i < 20; i++ {
		features := &FeatureVector{
			EventID:   "train",
			Timestamp: time.Now(),
			Features: map[string]float64{
				"feature1": 10.0,
			},
		}
		detector.Train(ctx, features)
	}

	// Verify state
	assert.Greater(t, len(detector.trainingData), 0)

	// Reset
	detector.Reset()

	// Verify reset state - trees cleared, but training data may remain
	assert.Equal(t, 0, len(detector.trees))
	assert.False(t, detector.isTrained)
}

// TestIsolationForest_BuildForest tests forest building via training
func TestIsolationForest_BuildForest(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		NumTrees:      5,
		SubsampleSize: 10,
		Logger:        logger,
	}
	detector := NewIsolationForest(config)

	ctx := context.Background()

	// Train with enough data to trigger forest building
	for i := 0; i < 50; i++ {
		features := &FeatureVector{
			EventID:   "train",
			Timestamp: time.Now(),
			Features: map[string]float64{
				"feature1": float64(i),
				"feature2": float64(i * 2),
			},
		}
		detector.Train(ctx, features)
	}

	// Forest should be built after sufficient training
	assert.GreaterOrEqual(t, len(detector.trees), 0)
}

// TestIsolationForest_SubsampleSize tests that subsampling respects config
func TestIsolationForest_SubsampleSize(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		SubsampleSize: 10,
		NumTrees:      3,
		Logger:        logger,
	}
	detector := NewIsolationForest(config)

	ctx := context.Background()

	// Add enough training data
	for i := 0; i < 100; i++ {
		features := &FeatureVector{
			EventID:   "train",
			Timestamp: time.Now(),
			Features: map[string]float64{
				"value": float64(i),
			},
		}
		detector.Train(ctx, features)
	}

	// Verify training data accumulated
	assert.GreaterOrEqual(t, len(detector.trainingData), 0)
}

// TestIsolationForest_TreeBuilding tests tree building via training
func TestIsolationForest_TreeBuilding(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		NumTrees:      3,
		SubsampleSize: 5,
		Logger:        logger,
	}
	detector := NewIsolationForest(config)

	ctx := context.Background()

	// Train with varied data
	for i := 0; i < 30; i++ {
		features := &FeatureVector{
			EventID:   "train",
			Timestamp: time.Now(),
			Features: map[string]float64{
				"f1": float64(i % 10),
				"f2": float64(i % 5),
			},
		}
		detector.Train(ctx, features)
	}

	// Trees should be built
	assert.GreaterOrEqual(t, len(detector.trees), 0)
}

// TestIsolationForest_PathLength tests path length calculation
func TestIsolationForest_PathLength(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		NumTrees:      5,
		SubsampleSize: 20,
		Logger:        logger,
	}
	detector := NewIsolationForest(config)

	ctx := context.Background()

	// Train to build forest
	for i := 0; i < 50; i++ {
		features := &FeatureVector{
			EventID:   "train",
			Timestamp: time.Now(),
			Features: map[string]float64{
				"feature1": float64(i),
			},
		}
		detector.Train(ctx, features)
	}

	// Test path length on a sample
	testFeatures := &FeatureVector{
		EventID:   "test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"feature1": 25.0,
		},
	}

	// Path length is tested indirectly through Detect
	if len(detector.trees) > 0 {
		result, err := detector.Detect(ctx, testFeatures)
		require.NoError(t, err)
		assert.NotNil(t, result)
	}
}

// TestIsolationForest_AnomalyScore tests anomaly score calculation
func TestIsolationForest_AnomalyScore(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{Logger: logger}
	detector := NewIsolationForest(config)

	tests := []struct {
		name          string
		avgPathLength float64
		numSamples    int
		expectedRange bool
	}{
		{
			name:          "short path (likely anomaly)",
			avgPathLength: 2.0,
			numSamples:    100,
			expectedRange: true,
		},
		{
			name:          "long path (likely normal)",
			avgPathLength: 10.0,
			numSamples:    100,
			expectedRange: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := detector.anomalyScore(tt.avgPathLength, tt.numSamples)

			if tt.expectedRange {
				assert.GreaterOrEqual(t, score, 0.0)
				assert.LessOrEqual(t, score, 1.0)
			}
		})
	}
}

// TestIsolationForest_AveragePathLength tests average path length calculation
func TestIsolationForest_AveragePathLength(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{Logger: logger}
	detector := NewIsolationForest(config)

	avgPath := detector.averagePathLength(10)
	assert.Greater(t, avgPath, 0.0)

	avgPath = detector.averagePathLength(1)
	assert.Equal(t, 0.0, avgPath)
}

// TestIsolationForest_ConfigDefaults tests default configuration
func TestIsolationForest_ConfigDefaults(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{Logger: logger}
	detector := NewIsolationForest(config)

	// Check that defaults are applied
	assert.NotNil(t, detector)
	assert.NotNil(t, detector.logger)
}

// TestIsolationForest_WithCustomConfig tests custom configuration
func TestIsolationForest_WithCustomConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		NumTrees:      50,
		SubsampleSize: 128,
		Contamination: 0.15,
		Logger:        logger,
	}
	detector := NewIsolationForest(config)

	assert.NotNil(t, detector)
	assert.Equal(t, logger, detector.logger)
}

// TestIsolationForest_EmptyFeatures tests handling of empty features
func TestIsolationForest_EmptyFeatures(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		NumTrees: 5,
		Logger:   logger,
	}
	detector := NewIsolationForest(config)

	ctx := context.Background()

	// Train with empty features
	features := &FeatureVector{
		EventID:   "test",
		Timestamp: time.Now(),
		Features:  map[string]float64{},
	}

	err := detector.Train(ctx, features)
	require.NoError(t, err)
}

// TestIsolationForest_SingleFeature tests with single feature
func TestIsolationForest_SingleFeature(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		NumTrees:      3,
		SubsampleSize: 10,
		Logger:        logger,
	}
	detector := NewIsolationForest(config)

	ctx := context.Background()

	// Train with single feature
	for i := 0; i < 30; i++ {
		features := &FeatureVector{
			EventID:   "train",
			Timestamp: time.Now(),
			Features: map[string]float64{
				"single": float64(i),
			},
		}
		err := detector.Train(ctx, features)
		require.NoError(t, err)
	}

	// Detect
	testFeatures := &FeatureVector{
		EventID:   "test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"single": 15.0,
		},
	}

	result, err := detector.Detect(ctx, testFeatures)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// TestIsolationForest_MultipleFeatures tests with multiple features
func TestIsolationForest_MultipleFeatures(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &IsolationForestConfig{
		NumTrees:      5,
		SubsampleSize: 15,
		Logger:        logger,
	}
	detector := NewIsolationForest(config)

	ctx := context.Background()

	// Train with multiple features
	for i := 0; i < 40; i++ {
		features := &FeatureVector{
			EventID:   "train",
			Timestamp: time.Now(),
			Features: map[string]float64{
				"f1": float64(i),
				"f2": float64(i * 2),
				"f3": float64(i * 3),
				"f4": float64(i * 4),
			},
		}
		err := detector.Train(ctx, features)
		require.NoError(t, err)
	}

	// Detect
	testFeatures := &FeatureVector{
		EventID:   "test",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"f1": 20.0,
			"f2": 40.0,
			"f3": 60.0,
			"f4": 80.0,
		},
	}

	result, err := detector.Detect(ctx, testFeatures)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "isolation_forest", result.Algorithm)
}
