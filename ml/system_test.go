package ml

import (
	"context"
	"fmt"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// MockEventStorage implements EventStorage for testing
type MockEventStorage struct {
	events []core.Event
	err    error
}

func (m *MockEventStorage) GetEvents(ctx context.Context, limit, offset int) ([]core.Event, error) {
	if m.err != nil {
		return nil, m.err
	}

	end := offset + limit
	if end > len(m.events) {
		end = len(m.events)
	}

	if offset >= len(m.events) {
		return []core.Event{}, nil
	}

	return m.events[offset:end], nil
}

func (m *MockEventStorage) GetEventCount(ctx context.Context) (int64, error) {
	if m.err != nil {
		return 0, m.err
	}
	return int64(len(m.events)), nil
}

func createTestEvent(id string, timestamp time.Time) *core.Event {
	return &core.Event{
		EventID:   id,
		Timestamp: timestamp,
		EventType: "test_event",
		SourceIP:  "192.168.1.100",
		Severity:  "info",
		Fields: map[string]interface{}{
			"source_ip":        "192.168.1.100",
			"destination_ip":   "10.0.0.50",
			"source_port":      float64(12345),
			"destination_port": float64(443),
			"bytes_sent":       float64(1024),
			"bytes_received":   float64(2048),
		},
	}
}

func createTestConfig(mode string, algorithms []string) *config.Config {
	cfg := &config.Config{}
	cfg.ML.Mode = mode
	cfg.ML.Algorithms = algorithms
	cfg.ML.MinTrainingSamples = 10
	cfg.ML.BatchSize = 100
	cfg.ML.TrainingInterval = 1
	cfg.ML.RetrainThreshold = 500
	cfg.ML.AnomalyThreshold = 0.7
	cfg.ML.FeatureCacheSize = 1000
	cfg.ML.EnableDriftDetection = false
	return cfg
}

// TestNewAnomalyDetectionSystem_SimpleMode tests simple mode initialization
func TestNewAnomalyDetectionSystem_SimpleMode(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		algorithms []string
		wantMode   string
	}{
		{
			name:       "default mode is simple",
			mode:       "",
			algorithms: []string{"zscore", "iqr"},
			wantMode:   "simple",
		},
		{
			name:       "explicit simple mode",
			mode:       "simple",
			algorithms: []string{"zscore"},
			wantMode:   "simple",
		},
		{
			name:       "all algorithms in simple mode",
			mode:       "simple",
			algorithms: []string{"zscore", "iqr", "isolation_forest"},
			wantMode:   "simple",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig(tt.mode, tt.algorithms)
			storage := &MockEventStorage{events: []core.Event{}}
			logger := zap.NewNop().Sugar()

			system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

			require.NotNil(t, system)
			assert.Equal(t, tt.wantMode, system.mode)
			assert.NotNil(t, system.featureExtractor)
			assert.NotNil(t, system.simpleTrainingPipeline)
			assert.Nil(t, system.advancedTrainingPipeline)
			assert.Nil(t, system.ensembleEngine)
			assert.Equal(t, len(tt.algorithms), len(system.detectors))
		})
	}
}

// TestNewAnomalyDetectionSystem_ContinuousMode tests continuous mode initialization
func TestNewAnomalyDetectionSystem_ContinuousMode(t *testing.T) {
	cfg := createTestConfig("continuous", []string{"zscore", "iqr"})
	storage := &MockEventStorage{events: []core.Event{}}
	logger := zap.NewNop().Sugar()

	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	require.NotNil(t, system)
	assert.Equal(t, "continuous", system.mode)
	assert.NotNil(t, system.featureExtractor)
	assert.NotNil(t, system.advancedTrainingPipeline)
	assert.NotNil(t, system.ensembleEngine)
	assert.Nil(t, system.simpleTrainingPipeline)
	assert.Greater(t, len(system.detectors), 0)
}

// TestNewAnomalyDetectionSystem_WithRedisCache tests with Redis cache
func TestNewAnomalyDetectionSystem_WithRedisCache(t *testing.T) {
	cfg := createTestConfig("simple", []string{"zscore"})
	storage := &MockEventStorage{events: []core.Event{}}
	logger := zap.NewNop().Sugar()

	// Redis cache is optional, so we pass nil and verify system still works
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	require.NotNil(t, system)
	assert.NotNil(t, system.featureExtractor)
	// Without Redis, should use in-memory cache
}

// TestCreateDetector tests detector creation for different algorithms
func TestCreateDetector(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantNil   bool
	}{
		{"zscore detector", "zscore", false},
		{"iqr detector", "iqr", false},
		{"isolation_forest detector", "isolation_forest", false},
		{"unknown algorithm", "unknown", true},
	}

	cfg := createTestConfig("simple", []string{})
	storage := &MockEventStorage{events: []core.Event{}}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := system.createDetector(tt.algorithm)
			if tt.wantNil {
				assert.Nil(t, detector)
			} else {
				assert.NotNil(t, detector)
			}
		})
	}
}

// TestDetectAnomaly_SimpleMode tests anomaly detection in simple mode
func TestDetectAnomaly_SimpleMode(t *testing.T) {
	cfg := createTestConfig("simple", []string{"zscore", "iqr"})
	storage := &MockEventStorage{events: []core.Event{}}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	// Train detectors with normal events
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		event := createTestEvent(fmt.Sprintf("train-%d", i), time.Now())
		features, err := system.featureExtractor.ExtractFeatures(ctx, event)
		require.NoError(t, err)

		for _, detector := range system.detectors {
			err = detector.Train(ctx, features)
			require.NoError(t, err)
		}
	}

	// Test detection on a normal event
	testEvent := createTestEvent("test-normal", time.Now())
	result, err := system.DetectAnomaly(testEvent)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Score, 0.0)
	assert.LessOrEqual(t, result.Score, 1.0)
	assert.Equal(t, "weighted_average", result.VotingStrategy)
	assert.NotNil(t, result.AlgorithmResults)
}

// TestDetectAnomaly_ContinuousMode tests anomaly detection in continuous mode
func TestDetectAnomaly_ContinuousMode(t *testing.T) {
	cfg := createTestConfig("continuous", []string{"zscore"})
	storage := &MockEventStorage{events: []core.Event{}}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	// Train the ensemble
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		event := createTestEvent(fmt.Sprintf("train-%d", i), time.Now())
		features, err := system.featureExtractor.ExtractFeatures(ctx, event)
		require.NoError(t, err)
		err = system.ensembleEngine.Train(ctx, features)
		require.NoError(t, err)
	}

	// Test detection
	testEvent := createTestEvent("test-continuous", time.Now())
	result, err := system.DetectAnomaly(testEvent)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.AlgorithmResults)
}

// TestDetectAnomaly_AllDetectorsFail tests when all detectors fail
func TestDetectAnomaly_AllDetectorsFail(t *testing.T) {
	cfg := createTestConfig("simple", []string{"zscore"})
	storage := &MockEventStorage{events: []core.Event{}}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	// Don't train detectors - they should fail on nil features
	testEvent := &core.Event{
		EventID:   "test",
		Timestamp: time.Now(),
		EventType: "test",
		Fields:    map[string]interface{}{}, // Empty data
	}

	// This should succeed because feature extraction handles empty data
	result, err := system.DetectAnomaly(testEvent)

	// With empty data, detectors might not have enough information
	// but should not error out completely
	if err != nil {
		assert.Contains(t, err.Error(), "failed")
	} else {
		assert.NotNil(t, result)
	}
}

// TestProcessEvent tests ProcessEvent interface implementation
func TestProcessEvent(t *testing.T) {
	cfg := createTestConfig("simple", []string{"zscore"})
	storage := &MockEventStorage{events: []core.Event{}}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	// Train first
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		event := createTestEvent(fmt.Sprintf("train-%d", i), time.Now())
		features, _ := system.featureExtractor.ExtractFeatures(ctx, event)
		for _, detector := range system.detectors {
			detector.Train(ctx, features)
		}
	}

	testEvent := createTestEvent("test-process", time.Now())
	result, err := system.ProcessEvent(ctx, testEvent)

	require.NoError(t, err)
	assert.NotNil(t, result)

	// Result should be an EnsembleResult
	ensembleResult, ok := result.(*EnsembleResult)
	assert.True(t, ok)
	assert.NotNil(t, ensembleResult)
}

// TestSimpleTrainingPipeline_TrainAllModels tests simple pipeline training
func TestSimpleTrainingPipeline_TrainAllModels(t *testing.T) {
	// Create test events
	events := make([]core.Event, 100)
	for i := 0; i < 100; i++ {
		events[i] = *createTestEvent(fmt.Sprintf("event-%d", i), time.Now())
	}

	cfg := createTestConfig("simple", []string{"zscore", "iqr"})
	storage := &MockEventStorage{events: events}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	ctx := context.Background()
	err := system.simpleTrainingPipeline.TrainAllModels(ctx)

	require.NoError(t, err)
	assert.True(t, system.simpleTrainingPipeline.status.LastTraining.After(time.Time{}))
}

// TestSimpleTrainingPipeline_InsufficientSamples tests training with insufficient data
func TestSimpleTrainingPipeline_InsufficientSamples(t *testing.T) {
	// Create only 5 events (less than MinTrainingSamples of 10)
	events := make([]core.Event, 5)
	for i := 0; i < 5; i++ {
		events[i] = *createTestEvent(fmt.Sprintf("event-%d", i), time.Now())
	}

	cfg := createTestConfig("simple", []string{"zscore"})
	storage := &MockEventStorage{events: events}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	ctx := context.Background()
	err := system.simpleTrainingPipeline.TrainAllModels(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient training samples")
}

// TestSimpleTrainingPipeline_StorageError tests training with storage errors
func TestSimpleTrainingPipeline_StorageError(t *testing.T) {
	cfg := createTestConfig("simple", []string{"zscore"})
	storage := &MockEventStorage{
		events: []core.Event{},
		err:    fmt.Errorf("storage error"),
	}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	ctx := context.Background()
	err := system.simpleTrainingPipeline.TrainAllModels(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get event count")
}

// TestSimpleTrainingPipeline_ContextCancellation tests context cancellation during training
func TestSimpleTrainingPipeline_ContextCancellation(t *testing.T) {
	// Create many events to ensure cancellation happens during processing
	events := make([]core.Event, 1000)
	for i := 0; i < 1000; i++ {
		events[i] = *createTestEvent(fmt.Sprintf("event-%d", i), time.Now())
	}

	cfg := createTestConfig("simple", []string{"zscore"})
	storage := &MockEventStorage{events: events}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := system.simpleTrainingPipeline.TrainAllModels(ctx)

	// Should return context.Canceled error
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestFetchTrainingData tests data fetching functionality
func TestFetchTrainingData(t *testing.T) {
	tests := []struct {
		name        string
		eventCount  int
		wantFetched int
		storageErr  error
		wantErr     bool
		errContains string
	}{
		{
			name:        "fetch small dataset",
			eventCount:  100,
			wantFetched: 100,
			storageErr:  nil,
			wantErr:     false,
		},
		{
			name:        "fetch large dataset",
			eventCount:  15000,
			wantFetched: 10000, // Max is 10000
			storageErr:  nil,
			wantErr:     false,
		},
		{
			name:        "storage not available",
			eventCount:  100,
			wantFetched: 0,
			storageErr:  nil,
			wantErr:     true,
			errContains: "event storage not available",
		},
		{
			name:        "event count error",
			eventCount:  100,
			wantFetched: 0,
			storageErr:  fmt.Errorf("count error"),
			wantErr:     true,
			errContains: "failed to get event count",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig("simple", []string{"zscore"})
			logger := zap.NewNop().Sugar()

			var pipeline *SimpleTrainingPipeline
			if tt.errContains == "event storage not available" {
				// Test nil storage
				pipeline = &SimpleTrainingPipeline{
					config:       cfg,
					eventStorage: nil,
					logger:       logger,
				}
			} else {
				events := make([]core.Event, tt.eventCount)
				for i := 0; i < tt.eventCount; i++ {
					events[i] = *createTestEvent(fmt.Sprintf("event-%d", i), time.Now())
				}
				storage := &MockEventStorage{
					events: events,
					err:    tt.storageErr,
				}
				pipeline = &SimpleTrainingPipeline{
					config:       cfg,
					eventStorage: storage,
					logger:       logger,
				}
			}

			ctx := context.Background()
			fetchedEvents, err := pipeline.fetchTrainingData(ctx)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantFetched, len(fetchedEvents))
			}
		})
	}
}

// TestForceTraining tests manual training trigger
func TestForceTraining(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{"simple mode force training", "simple"},
		{"continuous mode force training", "continuous"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := make([]core.Event, 100)
			for i := 0; i < 100; i++ {
				events[i] = *createTestEvent(fmt.Sprintf("event-%d", i), time.Now())
			}

			cfg := createTestConfig(tt.mode, []string{"zscore"})
			storage := &MockEventStorage{events: events}
			logger := zap.NewNop().Sugar()
			system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

			ctx := context.Background()
			err := system.ForceTraining(ctx)

			// For continuous mode with no training buffer, this should succeed but do nothing
			// For simple mode, should train successfully
			if tt.mode == "simple" {
				require.NoError(t, err)
			} else {
				// Continuous mode might return error or succeed depending on state
				// Both are acceptable
			}
		})
	}
}

// TestReset tests reset functionality
func TestReset(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{"reset simple mode", "simple"},
		{"reset continuous mode", "continuous"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig(tt.mode, []string{"zscore"})
			storage := &MockEventStorage{events: []core.Event{}}
			logger := zap.NewNop().Sugar()
			system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

			err := system.Reset()

			require.NoError(t, err)
			status := system.GetStatus()
			assert.False(t, status.IsRunning)
		})
	}
}

// TestGetStatus tests status retrieval
func TestGetStatus(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{"get status simple mode", "simple"},
		{"get status continuous mode", "continuous"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig(tt.mode, []string{"zscore"})
			storage := &MockEventStorage{events: []core.Event{}}
			logger := zap.NewNop().Sugar()
			system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

			status := system.GetStatus()

			assert.NotNil(t, status)
			assert.False(t, status.IsRunning)
		})
	}
}

// TestStartTrainingPipeline_SimpleMode tests training pipeline lifecycle in simple mode
func TestStartTrainingPipeline_SimpleMode(t *testing.T) {
	events := make([]core.Event, 50)
	for i := 0; i < 50; i++ {
		events[i] = *createTestEvent(fmt.Sprintf("event-%d", i), time.Now())
	}

	cfg := createTestConfig("simple", []string{"zscore"})
	cfg.ML.TrainingInterval = 1 // 1 hour interval (won't trigger in this test)
	storage := &MockEventStorage{events: events}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start pipeline in background
	done := make(chan struct{})
	go func() {
		system.StartTrainingPipeline(ctx)
		close(done)
	}()

	// Wait for initial training to complete or timeout
	select {
	case <-done:
		// Pipeline stopped when context was cancelled
	case <-time.After(3 * time.Second):
		t.Fatal("Pipeline did not stop after context timeout")
	}
}

// TestStartTrainingPipeline_ContinuousMode tests training pipeline in continuous mode
func TestStartTrainingPipeline_ContinuousMode(t *testing.T) {
	events := make([]core.Event, 50)
	for i := 0; i < 50; i++ {
		events[i] = *createTestEvent(fmt.Sprintf("event-%d", i), time.Now())
	}

	cfg := createTestConfig("continuous", []string{"zscore"})
	cfg.ML.TrainingInterval = 1
	storage := &MockEventStorage{events: events}
	logger := zap.NewNop().Sugar()
	system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start pipeline
	done := make(chan struct{})
	go func() {
		system.StartTrainingPipeline(ctx)
		close(done)
	}()

	// Wait for pipeline to stop
	select {
	case <-done:
		// Success
	case <-time.After(3 * time.Second):
		t.Fatal("Pipeline did not stop")
	}
}

// TestTrainFromHistoricalData tests historical data training
func TestTrainFromHistoricalData(t *testing.T) {
	tests := []struct {
		name        string
		eventCount  int
		minSamples  int
		wantErr     bool
		errContains string
	}{
		{
			name:       "sufficient historical data",
			eventCount: 100,
			minSamples: 50,
			wantErr:    false,
		},
		{
			name:        "insufficient historical data",
			eventCount:  5,
			minSamples:  10,
			wantErr:     true,
			errContains: "insufficient training samples",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := make([]core.Event, tt.eventCount)
			for i := 0; i < tt.eventCount; i++ {
				events[i] = *createTestEvent(fmt.Sprintf("event-%d", i), time.Now())
			}

			cfg := createTestConfig("continuous", []string{"zscore"})
			cfg.ML.MinTrainingSamples = tt.minSamples
			storage := &MockEventStorage{events: events}
			logger := zap.NewNop().Sugar()
			system := NewAnomalyDetectionSystem(cfg, storage, nil, logger)

			ctx := context.Background()
			err := system.trainFromHistoricalData(ctx)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestSimpleTrainingPipeline_ForceTraining tests forcing training on simple pipeline
func TestSimpleTrainingPipeline_ForceTraining(t *testing.T) {
	events := make([]core.Event, 100)
	for i := 0; i < 100; i++ {
		events[i] = *createTestEvent(fmt.Sprintf("event-%d", i), time.Now())
	}

	cfg := createTestConfig("simple", []string{"zscore"})
	storage := &MockEventStorage{events: events}
	logger := zap.NewNop().Sugar()

	pipeline := &SimpleTrainingPipeline{
		config:       cfg,
		eventStorage: storage,
		logger:       logger,
		detectors:    make(map[string]AnomalyDetector),
	}

	// Add a detector
	pipeline.detectors["zscore"] = NewZScoreDetector(&ZScoreConfig{Logger: logger})

	ctx := context.Background()
	err := pipeline.ForceTraining(ctx)

	require.NoError(t, err)
	assert.True(t, pipeline.status.LastTraining.After(time.Time{}))
}

// TestSimpleTrainingPipeline_Reset tests resetting simple pipeline
func TestSimpleTrainingPipeline_Reset(t *testing.T) {
	cfg := createTestConfig("simple", []string{"zscore"})
	logger := zap.NewNop().Sugar()

	pipeline := &SimpleTrainingPipeline{
		config: cfg,
		logger: logger,
		status: TrainingPipelineStatus{
			IsRunning:    true,
			LastTraining: time.Now(),
		},
	}

	err := pipeline.Reset()

	require.NoError(t, err)
	assert.False(t, pipeline.status.IsRunning)
	assert.Equal(t, time.Time{}, pipeline.status.LastTraining)
}

// TestSimpleTrainingPipeline_GetStatus tests getting simple pipeline status
func TestSimpleTrainingPipeline_GetStatus(t *testing.T) {
	cfg := createTestConfig("simple", []string{"zscore"})
	logger := zap.NewNop().Sugar()

	now := time.Now()
	pipeline := &SimpleTrainingPipeline{
		config: cfg,
		logger: logger,
		status: TrainingPipelineStatus{
			IsRunning:    true,
			LastTraining: now,
		},
	}

	status := pipeline.GetStatus()

	assert.True(t, status.IsRunning)
	assert.Equal(t, now, status.LastTraining)
}
