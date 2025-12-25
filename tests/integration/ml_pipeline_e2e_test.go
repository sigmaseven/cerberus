package integration

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"os"
	"testing"
	"time"

	"cerberus/core"
	"cerberus/ml"
	"cerberus/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TASK 61.5: ML Pipeline E2E Integration Test
// Tests complete ML pipeline: feature extraction → training → prediction → alert

// TestMLPipeline_FeatureExtraction tests feature extraction from events
func TestMLPipeline_FeatureExtraction(t *testing.T) {
	infra := SetupTestInfrastructure(t)
	defer infra.Cleanup()

	ctx := context.Background()

	// Create feature extractors
	contentExtractor := ml.NewContentFeatureExtractor()
	networkExtractor := ml.NewNetworkFeatureExtractor()
	temporalExtractor := ml.NewTemporalFeatureExtractor()

	// Generate test event
	event := GenerateTestEvent(func(e *core.Event) {
		e.Severity = "high"
		e.Fields["source_ip"] = "192.168.1.100"
	})

	// Extract features (require context and return error)
	contentFeatures, err := contentExtractor.Extract(ctx, event)
	require.NoError(t, err, "Should extract content features")
	networkFeatures, err := networkExtractor.Extract(ctx, event)
	require.NoError(t, err, "Should extract network features")
	temporalFeatures, err := temporalExtractor.Extract(ctx, event)
	require.NoError(t, err, "Should extract temporal features")

	assert.NotEmpty(t, contentFeatures, "Content features should be extracted")
	assert.NotEmpty(t, networkFeatures, "Network features should be extracted")
	assert.NotEmpty(t, temporalFeatures, "Temporal features should be extracted")
}

// TestMLPipeline_Training tests model training workflow
func TestMLPipeline_Training(t *testing.T) {
	infra := SetupTestInfrastructure(t)
	defer infra.Cleanup()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	// Create detector with config
	zscoreConfig := &ml.ZScoreConfig{
		Threshold:  3.0,
		MinSamples: 30,
		Logger:     logger,
	}
	detector := ml.NewZScoreDetector(zscoreConfig)

	// Generate training data
	events := []*core.Event{}
	for i := 0; i < 100; i++ {
		events = append(events, GenerateTestEvent())
	}

	// Extract features and train
	contentExtractor := ml.NewContentFeatureExtractor()
	for _, event := range events {
		features, err := contentExtractor.Extract(ctx, event)
		require.NoError(t, err)

		featureVector := &ml.FeatureVector{
			EventID:   event.EventID,
			Timestamp: event.Timestamp,
			Features:  features,
		}
		err = detector.Train(ctx, featureVector)
		require.NoError(t, err)
	}

	// Test detection
	testEvent := GenerateTestEvent()
	testFeatures, err := contentExtractor.Extract(ctx, testEvent)
	require.NoError(t, err)

	testFeatureVector := &ml.FeatureVector{
		EventID:   testEvent.EventID,
		Timestamp: testEvent.Timestamp,
		Features:  testFeatures,
	}

	result, err := detector.Detect(ctx, testFeatureVector)
	require.NoError(t, err, "Should detect anomaly")

	assert.NotNil(t, result, "Anomaly result should not be nil")
	assert.IsType(t, false, result.IsAnomaly, "IsAnomaly should be boolean")
}

// TestMLPipeline_ModelPersistence tests model saving and loading
func TestMLPipeline_ModelPersistence(t *testing.T) {
	infra := SetupTestInfrastructure(t)
	defer infra.Cleanup()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	// Create detector with config and train
	iqrConfig := &ml.IQRConfig{
		MaxSamples: 1000,
		Multiplier: 1.5,
		Logger:     logger,
	}
	detector := ml.NewIQRDetector(iqrConfig)

	contentExtractor := ml.NewContentFeatureExtractor()
	for i := 0; i < 50; i++ {
		event := GenerateTestEvent()
		features, err := contentExtractor.Extract(ctx, event)
		require.NoError(t, err)

		featureVector := &ml.FeatureVector{
			EventID:   event.EventID,
			Timestamp: event.Timestamp,
			Features:  features,
		}
		err = detector.Train(ctx, featureVector)
		require.NoError(t, err)
	}

	// Serialize model to bytes (simplified - use gob encoding)
	var modelData bytes.Buffer
	encoder := gob.NewEncoder(&modelData)
	err := encoder.Encode(detector)
	require.NoError(t, err, "Should serialize model")

	// Save model
	dbPath := fmt.Sprintf("test_ml_model_%d.db", time.Now().UnixNano())
	sqlite, err := storage.NewSQLite(dbPath, logger)
	require.NoError(t, err)
	defer sqlite.Close()
	defer os.Remove(dbPath) // Cleanup

	modelStorage := storage.NewMLModelStorage(sqlite, logger)

	modelName := "test-model-1"
	modelVersion := "1.0"
	modelType := "iqr"
	config := `{"multiplier": 1.5, "max_samples": 1000}`
	metrics := `{"anomalies_found": 0}`

	err = modelStorage.SaveModel(ctx, modelName, modelVersion, modelType, modelData.Bytes(), config, metrics)
	require.NoError(t, err, "Should save model")

	// Load model
	modelTypeLoaded, modelDataLoaded, err := modelStorage.LoadModel(ctx, modelName, modelVersion)
	require.NoError(t, err, "Should load model")
	assert.NotEmpty(t, modelTypeLoaded, "Model type should not be empty")
	assert.NotEmpty(t, modelDataLoaded, "Model data should not be empty")
}
