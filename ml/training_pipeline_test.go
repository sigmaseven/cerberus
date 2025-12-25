package ml

import (
	"context"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestNewTrainingPipeline tests training pipeline constructor
func TestNewTrainingPipeline(t *testing.T) {
	tests := []struct {
		name           string
		config         *TrainingPipelineConfig
		wantBatchSize  int
		wantInterval   time.Duration
		wantThreshold  int
		wantValidation float64
	}{
		{
			name:           "nil config uses defaults",
			config:         nil,
			wantBatchSize:  1000,
			wantInterval:   1 * time.Hour,
			wantThreshold:  5000,
			wantValidation: 0.2,
		},
		{
			name: "zero values use defaults",
			config: &TrainingPipelineConfig{
				BatchSize:        0,
				TrainingInterval: 0,
				RetrainThreshold: 0,
				ValidationRatio:  0,
			},
			wantBatchSize:  1000,
			wantInterval:   1 * time.Hour,
			wantThreshold:  5000,
			wantValidation: 0.2,
		},
		{
			name: "custom config values",
			config: &TrainingPipelineConfig{
				BatchSize:        500,
				TrainingInterval: 30 * time.Minute,
				RetrainThreshold: 1000,
				ValidationRatio:  0.3,
			},
			wantBatchSize:  500,
			wantInterval:   30 * time.Minute,
			wantThreshold:  1000,
			wantValidation: 0.3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
				Algorithms: []string{"zscore"},
				Logger:     logger,
			})
			extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{
				Logger: logger,
			})
			normalizer := NewFeatureNormalizerManager(logger)
			cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

			pipeline := NewTrainingPipeline(tt.config, ensemble, extractor, normalizer, cache)

			require.NotNil(t, pipeline)
			assert.Equal(t, tt.wantBatchSize, pipeline.config.BatchSize)
			assert.Equal(t, tt.wantInterval, pipeline.config.TrainingInterval)
			assert.Equal(t, tt.wantThreshold, pipeline.config.RetrainThreshold)
			assert.Equal(t, tt.wantValidation, pipeline.config.ValidationRatio)
			assert.NotNil(t, pipeline.ensemble)
			assert.NotNil(t, pipeline.extractor)
			assert.NotNil(t, pipeline.normalizer)
			assert.NotNil(t, pipeline.cache)
			assert.False(t, pipeline.isRunning)
		})
	}
}

// TestTrainingPipeline_Start tests starting the pipeline
func TestTrainingPipeline_Start(t *testing.T) {
	tests := []struct {
		name               string
		enableContinuous   bool
		wantContinuousLoop bool
	}{
		{
			name:               "start with continuous learning",
			enableContinuous:   true,
			wantContinuousLoop: true,
		},
		{
			name:               "start without continuous learning",
			enableContinuous:   false,
			wantContinuousLoop: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			config := &TrainingPipelineConfig{
				BatchSize:        100,
				TrainingInterval: 100 * time.Millisecond,
				EnableContinuous: tt.enableContinuous,
				Logger:           logger,
			}

			ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
				Algorithms: []string{"zscore"},
				Logger:     logger,
			})
			extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
			normalizer := NewFeatureNormalizerManager(logger)
			cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

			pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()

			err := pipeline.Start(ctx)
			require.NoError(t, err)
			assert.True(t, pipeline.isRunning)

			// Wait a bit to let continuous loop start if enabled
			time.Sleep(200 * time.Millisecond)

			// Stop the pipeline
			err = pipeline.Stop()
			require.NoError(t, err)
			assert.False(t, pipeline.isRunning)
		})
	}
}

// TestTrainingPipeline_StartAlreadyRunning tests starting an already running pipeline
func TestTrainingPipeline_StartAlreadyRunning(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &TrainingPipelineConfig{
		EnableContinuous: false,
		Logger:           logger,
	}

	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	ctx := context.Background()
	err := pipeline.Start(ctx)
	require.NoError(t, err)

	// Try to start again
	err = pipeline.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	pipeline.Stop()
}

// TestTrainingPipeline_Stop tests stopping the pipeline
func TestTrainingPipeline_Stop(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &TrainingPipelineConfig{
		EnableContinuous: true,
		TrainingInterval: 1 * time.Hour,
		Logger:           logger,
	}

	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	ctx := context.Background()
	err := pipeline.Start(ctx)
	require.NoError(t, err)

	err = pipeline.Stop()
	require.NoError(t, err)
	assert.False(t, pipeline.isRunning)

	// Stopping again should be safe
	err = pipeline.Stop()
	require.NoError(t, err)
}

// TestTrainingPipeline_ProcessEvent tests event processing
func TestTrainingPipeline_ProcessEvent(t *testing.T) {
	tests := []struct {
		name    string
		event   *core.Event
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid event",
			event: &core.Event{
				EventID:   "test-1",
				Timestamp: time.Now(),
				EventType: "test",
				SourceIP:  "192.168.1.1",
				Fields: map[string]interface{}{
					"source_ip":   "192.168.1.1",
					"source_port": float64(12345),
				},
			},
			wantErr: false,
		},
		{
			name:    "nil event",
			event:   nil,
			wantErr: true,
			errMsg:  "event cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
				Algorithms: []string{"zscore"},
				Logger:     logger,
			})
			extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
			normalizer := NewFeatureNormalizerManager(logger)
			cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

			config := &TrainingPipelineConfig{
				BatchSize:        100,
				EnableContinuous: false,
				Logger:           logger,
			}
			pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

			// Train ensemble first
			ctx := context.Background()
			for i := 0; i < 30; i++ {
				trainEvent := createTestEvent("train", time.Now())
				features, _ := extractor.ExtractFeatures(ctx, trainEvent)
				ensemble.Train(ctx, features)
			}

			result, err := pipeline.ProcessEvent(ctx, tt.event)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.GreaterOrEqual(t, result.Score, 0.0)
			}
		})
	}
}

// TestTrainingPipeline_AddToTrainingBuffer tests adding features to buffer
func TestTrainingPipeline_AddToTrainingBuffer(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	config := &TrainingPipelineConfig{
		BatchSize:        10, // Small batch for testing
		EnableContinuous: false,
		Logger:           logger,
	}
	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	ctx := context.Background()

	// Add features below batch size
	for i := 0; i < 5; i++ {
		event := createTestEvent("test", time.Now())
		features, err := extractor.ExtractFeatures(ctx, event)
		require.NoError(t, err)

		pipeline.addToTrainingBuffer(features)
	}

	assert.Equal(t, int64(5), pipeline.sampleCount)
	assert.Equal(t, 5, len(pipeline.trainingBuffer))
}

// TestTrainingPipeline_TriggerTraining tests manual training trigger
func TestTrainingPipeline_TriggerTraining(t *testing.T) {
	tests := []struct {
		name        string
		bufferSize  int
		wantTrainig bool
	}{
		{
			name:        "train with data in buffer",
			bufferSize:  50,
			wantTrainig: true,
		},
		{
			name:        "train with empty buffer",
			bufferSize:  0,
			wantTrainig: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
				Algorithms: []string{"zscore"},
				Logger:     logger,
			})
			extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
			normalizer := NewFeatureNormalizerManager(logger)
			cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

			config := &TrainingPipelineConfig{
				BatchSize:        100,
				ValidationRatio:  0.2,
				EnableContinuous: false,
				Logger:           logger,
			}
			pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

			ctx := context.Background()

			// Add features to buffer
			for i := 0; i < tt.bufferSize; i++ {
				event := createTestEvent("train", time.Now())
				features, _ := extractor.ExtractFeatures(ctx, event)
				pipeline.trainingBuffer = append(pipeline.trainingBuffer, features)
			}

			beforeLastTraining := pipeline.lastTraining

			err := pipeline.triggerTraining(ctx)
			require.NoError(t, err)

			if tt.wantTrainig {
				assert.True(t, pipeline.lastTraining.After(beforeLastTraining))
				assert.Equal(t, 0, len(pipeline.trainingBuffer)) // Buffer cleared
			} else {
				assert.Equal(t, beforeLastTraining, pipeline.lastTraining)
			}
		})
	}
}

// TestTrainingPipeline_TriggerTrainingWithValidation tests training with validation split
func TestTrainingPipeline_TriggerTrainingWithValidation(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	config := &TrainingPipelineConfig{
		BatchSize:        100,
		ValidationRatio:  0.2, // 20% for validation
		EnableContinuous: false,
		Logger:           logger,
	}
	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	ctx := context.Background()

	// Add 100 features to buffer
	for i := 0; i < 100; i++ {
		event := createTestEvent("train", time.Now())
		features, _ := extractor.ExtractFeatures(ctx, event)
		pipeline.trainingBuffer = append(pipeline.trainingBuffer, features)
	}

	err := pipeline.triggerTraining(ctx)
	require.NoError(t, err)

	// Validation data should be set (20 samples)
	assert.Equal(t, 20, len(pipeline.validationData))
	assert.Equal(t, 0, len(pipeline.trainingBuffer)) // Buffer cleared
	assert.Greater(t, len(pipeline.performanceHistory), 0)
}

// TestTrainingPipeline_ContextCancellation tests context cancellation during training
func TestTrainingPipeline_ContextCancellation(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	config := &TrainingPipelineConfig{
		BatchSize:        100,
		EnableContinuous: false,
		Logger:           logger,
	}
	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	ctx, cancel := context.WithCancel(context.Background())

	// Add many features to buffer
	for i := 0; i < 1000; i++ {
		event := createTestEvent("train", time.Now())
		features, _ := extractor.ExtractFeatures(context.Background(), event)
		pipeline.trainingBuffer = append(pipeline.trainingBuffer, features)
	}

	// Cancel immediately
	cancel()

	err := pipeline.triggerTraining(ctx)

	// Should return context.Canceled error
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestTrainingPipeline_ValidateModel tests model validation
func TestTrainingPipeline_ValidateModel(t *testing.T) {
	tests := []struct {
		name               string
		validationDataSize int
		wantScore          bool
		expectedScoreRange bool
	}{
		{
			name:               "validate with data",
			validationDataSize: 20,
			wantScore:          true,
			expectedScoreRange: true,
		},
		{
			name:               "validate with no data",
			validationDataSize: 0,
			wantScore:          false,
			expectedScoreRange: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
				Algorithms: []string{"zscore"},
				Logger:     logger,
			})
			extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
			normalizer := NewFeatureNormalizerManager(logger)
			cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

			config := &TrainingPipelineConfig{
				BatchSize: 100,
				Logger:    logger,
			}
			pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

			ctx := context.Background()

			// Train ensemble first
			for i := 0; i < 50; i++ {
				event := createTestEvent("train", time.Now())
				features, _ := extractor.ExtractFeatures(ctx, event)
				ensemble.Train(ctx, features)
			}

			// Add validation data
			for i := 0; i < tt.validationDataSize; i++ {
				event := createTestEvent("validate", time.Now())
				features, _ := extractor.ExtractFeatures(ctx, event)
				pipeline.validationData = append(pipeline.validationData, features)
			}

			score := pipeline.validateModel(ctx)

			if tt.wantScore {
				assert.GreaterOrEqual(t, score, 0.0)
				if tt.expectedScoreRange {
					assert.LessOrEqual(t, score, 1.0)
				}
			} else {
				assert.Equal(t, 0.0, score)
			}
		})
	}
}

// TestTrainingPipeline_DetectConceptDrift tests drift detection
func TestTrainingPipeline_DetectConceptDrift(t *testing.T) {
	tests := []struct {
		name               string
		enableDrift        bool
		performanceHistory []TrainingPerformance
		wantDrift          bool
	}{
		{
			name:               "drift detection disabled",
			enableDrift:        false,
			performanceHistory: []TrainingPerformance{},
			wantDrift:          false,
		},
		{
			name:               "insufficient history",
			enableDrift:        true,
			performanceHistory: []TrainingPerformance{{ValidationScore: 0.8}},
			wantDrift:          false,
		},
		{
			name:        "significant score drop detected",
			enableDrift: true,
			performanceHistory: []TrainingPerformance{
				{ValidationScore: 0.8, Timestamp: time.Now().Add(-2 * time.Hour)},
				{ValidationScore: 0.5, Timestamp: time.Now().Add(-1 * time.Hour)}, // 30% drop
			},
			wantDrift: true,
		},
		{
			name:        "no significant score drop",
			enableDrift: true,
			performanceHistory: []TrainingPerformance{
				{ValidationScore: 0.8, Timestamp: time.Now().Add(-2 * time.Hour)},
				{ValidationScore: 0.75, Timestamp: time.Now().Add(-1 * time.Hour)}, // Only 5% drop
			},
			wantDrift: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
				Algorithms: []string{"zscore"},
				Logger:     logger,
			})
			extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
			normalizer := NewFeatureNormalizerManager(logger)
			cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

			config := &TrainingPipelineConfig{
				DriftDetection: tt.enableDrift,
				Logger:         logger,
			}
			pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)
			pipeline.performanceHistory = tt.performanceHistory

			driftDetected := pipeline.detectConceptDrift()

			assert.Equal(t, tt.wantDrift, driftDetected)
		})
	}
}

// TestTrainingPipeline_GetAlgorithmMetrics tests algorithm metrics retrieval
func TestTrainingPipeline_GetAlgorithmMetrics(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore", "iqr"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	config := &TrainingPipelineConfig{Logger: logger}
	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	ctx := context.Background()

	// Train and detect to generate stats
	for i := 0; i < 50; i++ {
		event := createTestEvent("test", time.Now())
		features, _ := extractor.ExtractFeatures(ctx, event)
		ensemble.Train(ctx, features)

		if i%5 == 0 {
			ensemble.Detect(ctx, features)
		}
	}

	metrics := pipeline.getAlgorithmMetrics()

	assert.NotNil(t, metrics)
	assert.Greater(t, len(metrics), 0)

	// Check that metrics contain expected keys
	for key := range metrics {
		assert.Contains(t, key, "_anomaly_rate")
	}
}

// TestTrainingPipeline_GetStatus tests status retrieval
func TestTrainingPipeline_GetStatus(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	config := &TrainingPipelineConfig{
		BatchSize: 100,
		Logger:    logger,
	}
	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	// Set some state
	pipeline.isRunning = true
	pipeline.sampleCount = 150
	pipeline.lastTraining = time.Now()

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		event := createTestEvent("test", time.Now())
		features, _ := extractor.ExtractFeatures(ctx, event)
		pipeline.trainingBuffer = append(pipeline.trainingBuffer, features)
	}

	status := pipeline.GetStatus()

	assert.True(t, status.IsRunning)
	assert.Equal(t, int64(150), status.SampleCount)
	assert.Equal(t, 10, status.BufferSize)
	assert.True(t, status.LastTraining.After(time.Time{}))
}

// TestTrainingPipeline_ForceTraining tests manual training trigger
func TestTrainingPipeline_ForceTraining(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	config := &TrainingPipelineConfig{
		BatchSize: 100,
		Logger:    logger,
	}
	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	ctx := context.Background()

	// Add some features to buffer
	for i := 0; i < 50; i++ {
		event := createTestEvent("test", time.Now())
		features, _ := extractor.ExtractFeatures(ctx, event)
		pipeline.trainingBuffer = append(pipeline.trainingBuffer, features)
	}

	beforeTraining := pipeline.lastTraining

	err := pipeline.ForceTraining(ctx)
	require.NoError(t, err)

	assert.True(t, pipeline.lastTraining.After(beforeTraining))
}

// TestTrainingPipeline_Reset tests pipeline reset
func TestTrainingPipeline_Reset(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	config := &TrainingPipelineConfig{
		BatchSize: 100,
		Logger:    logger,
	}
	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	ctx := context.Background()

	// Add state to pipeline
	for i := 0; i < 50; i++ {
		event := createTestEvent("test", time.Now())
		features, _ := extractor.ExtractFeatures(ctx, event)
		pipeline.trainingBuffer = append(pipeline.trainingBuffer, features)
		pipeline.validationData = append(pipeline.validationData, features)
	}
	pipeline.sampleCount = 100
	pipeline.lastTraining = time.Now()
	pipeline.performanceHistory = append(pipeline.performanceHistory, TrainingPerformance{
		Timestamp: time.Now(),
	})

	// Reset
	pipeline.Reset()

	// Verify reset state
	assert.Equal(t, 0, len(pipeline.trainingBuffer))
	assert.Equal(t, 0, len(pipeline.validationData))
	assert.Equal(t, 0, len(pipeline.performanceHistory))
	assert.Equal(t, int64(0), pipeline.sampleCount)
	assert.Equal(t, time.Time{}, pipeline.lastTraining)
}

// TestTrainingPipeline_GetPerformanceHistory tests performance history retrieval
func TestTrainingPipeline_GetPerformanceHistory(t *testing.T) {
	tests := []struct {
		name         string
		historySize  int
		limit        int
		wantReturned int
	}{
		{
			name:         "get all history when limit is larger",
			historySize:  5,
			limit:        10,
			wantReturned: 5,
		},
		{
			name:         "get limited history when limit is smaller",
			historySize:  20,
			limit:        10,
			wantReturned: 10,
		},
		{
			name:         "get exact limit",
			historySize:  10,
			limit:        10,
			wantReturned: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
				Algorithms: []string{"zscore"},
				Logger:     logger,
			})
			extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
			normalizer := NewFeatureNormalizerManager(logger)
			cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

			config := &TrainingPipelineConfig{Logger: logger}
			pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

			// Add performance history
			for i := 0; i < tt.historySize; i++ {
				pipeline.performanceHistory = append(pipeline.performanceHistory, TrainingPerformance{
					Timestamp:   time.Now().Add(-time.Duration(i) * time.Hour),
					SampleCount: int64(100 + i),
				})
			}

			history := pipeline.GetPerformanceHistory(tt.limit)

			assert.Equal(t, tt.wantReturned, len(history))

			// If limited, should return the most recent ones
			if tt.historySize > tt.limit {
				// Verify we got the most recent (last) entries
				assert.Equal(t, int64(100+tt.historySize-tt.limit), history[0].SampleCount)
			}
		})
	}
}

// TestTrainingPipeline_ContinuousTrainingLoop tests continuous training loop
func TestTrainingPipeline_ContinuousTrainingLoop(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	config := &TrainingPipelineConfig{
		BatchSize:        100,
		TrainingInterval: 200 * time.Millisecond, // Short interval for testing
		EnableContinuous: true,
		Logger:           logger,
	}
	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start continuous loop
	err := pipeline.Start(ctx)
	require.NoError(t, err)

	// Add some data to buffer
	bgCtx := context.Background()
	for i := 0; i < 50; i++ {
		event := createTestEvent("test", time.Now())
		features, _ := extractor.ExtractFeatures(bgCtx, event)
		pipeline.addToTrainingBuffer(features)
	}

	// Wait for at least one training cycle
	time.Sleep(600 * time.Millisecond)

	// Stop pipeline
	err = pipeline.Stop()
	require.NoError(t, err)

	// Should have performed at least one training
	// (buffer might be cleared if training triggered)
}

// TestTrainingPipeline_PerformanceHistoryLimit tests that performance history is capped
func TestTrainingPipeline_PerformanceHistoryLimit(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ensemble := NewEnsembleEngine(&EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	})
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger})
	normalizer := NewFeatureNormalizerManager(logger)
	cache := NewMemoryFeatureCacheWithLimit(logger, 1000)

	config := &TrainingPipelineConfig{
		BatchSize: 10,
		Logger:    logger,
	}
	pipeline := NewTrainingPipeline(config, ensemble, extractor, normalizer, cache)

	ctx := context.Background()

	// Trigger training many times to exceed history limit
	for i := 0; i < 150; i++ {
		// Add features to buffer
		for j := 0; j < 20; j++ {
			event := createTestEvent("test", time.Now())
			features, _ := extractor.ExtractFeatures(ctx, event)
			pipeline.trainingBuffer = append(pipeline.trainingBuffer, features)
		}

		// Trigger training
		pipeline.triggerTraining(ctx)
	}

	// Performance history should be capped at 100
	assert.LessOrEqual(t, len(pipeline.performanceHistory), 100)
}
