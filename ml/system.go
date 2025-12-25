package ml

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cerberus/config"
	"cerberus/core"

	"go.uber.org/zap"
)

// EventStorage defines interface for fetching events for ML training
type EventStorage interface {
	GetEvents(ctx context.Context, limit, offset int) ([]core.Event, error)
	GetEventCount(ctx context.Context) (int64, error)
}

// AnomalyDetectionSystem coordinates all ML components
type AnomalyDetectionSystem struct {
	config       *config.Config
	eventStorage EventStorage
	redisCache   *core.RedisCache
	logger       *zap.SugaredLogger

	detectors        map[string]AnomalyDetector
	featureExtractor *FeatureExtractorManager

	// Pipeline mode selection
	mode                     string // "simple" or "continuous"
	simpleTrainingPipeline   *SimpleTrainingPipeline
	advancedTrainingPipeline *TrainingPipeline
	ensembleEngine           *EnsembleEngine

	// TASK 37.4: Model persistence and loading
	modelLoader *ModelLoader
}

// NewAnomalyDetectionSystem creates a new ML system
func NewAnomalyDetectionSystem(cfg *config.Config, eventStorage EventStorage, redis *core.RedisCache, logger *zap.SugaredLogger) *AnomalyDetectionSystem {
	// Default to simple mode if not specified
	mode := cfg.ML.Mode
	if mode == "" {
		mode = "simple"
	}

	system := &AnomalyDetectionSystem{
		config:       cfg,
		eventStorage: eventStorage,
		redisCache:   redis,
		logger:       logger,
		detectors:    make(map[string]AnomalyDetector),
		mode:         mode,
	}

	// Initialize feature extractor with Redis cache
	var cache FeatureCache
	if redis != nil {
		cache = NewRedisFeatureCache(redis, logger)
	} else {
		// Use in-memory cache if Redis not available
		cache = NewMemoryFeatureCacheWithLimit(logger, cfg.ML.FeatureCacheSize)
	}

	feConfig := &FeatureExtractorConfig{
		Logger: logger,
		Cache:  cache,
	}
	system.featureExtractor = NewFeatureExtractorManager(feConfig)

	// TASK 37.4: Load persisted models if loader is available
	// This will be called after modelLoader is set (see LoadPersistedModels)
	if system.modelLoader != nil {
		logger.Info("Loading persisted models from storage...")
		loadedModels, err := system.modelLoader.LoadActiveModels(context.Background())
		if err != nil {
			logger.Warnf("Failed to load persisted models: %v. Starting with fresh detectors.", err)
		} else if len(loadedModels) > 0 {
			logger.Infof("Loaded %d persisted models from storage", len(loadedModels))
			// Register loaded models
			for algorithm, detector := range loadedModels {
				system.detectors[algorithm] = detector
				logger.Infof("Registered loaded detector: %s", algorithm)
			}
		}
	}

	// Initialize based on mode
	if mode == "continuous" {
		logger.Info("Initializing ML system in continuous learning mode")
		system.initializeContinuousMode(cache)
	} else {
		logger.Info("Initializing ML system in simple mode")
		system.initializeSimpleMode()
	}

	return system
}

// SetModelLoader sets the model loader for automatic loading (TASK 37.4)
func (ads *AnomalyDetectionSystem) SetModelLoader(loader *ModelLoader) {
	ads.modelLoader = loader
}

// LoadPersistedModels loads active models from storage (TASK 37.4)
// Can be called after system initialization to load models
func (ads *AnomalyDetectionSystem) LoadPersistedModels(ctx context.Context) error {
	if ads.modelLoader == nil {
		return fmt.Errorf("model loader not configured")
	}

	loadedModels, err := ads.modelLoader.LoadActiveModels(ctx)
	if err != nil {
		return fmt.Errorf("failed to load persisted models: %w", err)
	}

	// Register loaded models, replacing any existing detectors
	for algorithm, detector := range loadedModels {
		ads.detectors[algorithm] = detector
		ads.logger.Infof("Registered persisted detector: %s", algorithm)
	}

	return nil
}

// initializeSimpleMode sets up the simple periodic training pipeline
// TASK 37.4: Enhanced to use persisted models if available
func (ads *AnomalyDetectionSystem) initializeSimpleMode() {
	// Initialize detectors (only create new ones if not already loaded from storage)
	for _, algorithm := range ads.config.ML.Algorithms {
		// TASK 37.4: Check if model was loaded from storage
		if _, exists := ads.detectors[algorithm]; exists {
			ads.logger.Debugf("Using persisted model for algorithm: %s", algorithm)
			continue // Skip creating new detector, use persisted one
		}

		// Create new detector if no persisted model available
		detector := ads.createDetector(algorithm)
		if detector != nil {
			ads.detectors[algorithm] = detector
		}
	}

	// Initialize simple training pipeline
	ads.simpleTrainingPipeline = &SimpleTrainingPipeline{
		config:       ads.config,
		eventStorage: ads.eventStorage,
		logger:       ads.logger,
		detectors:    ads.detectors,
	}
}

// initializeContinuousMode sets up the advanced continuous learning pipeline
func (ads *AnomalyDetectionSystem) initializeContinuousMode(cache FeatureCache) {
	// Create ensemble engine
	ensembleConfig := &EnsembleEngineConfig{
		Algorithms:     ads.config.ML.Algorithms,
		Weights:        make(map[string]float64),
		VotingStrategy: "weighted",
		MinConfidence:  0.6,
		Logger:         ads.logger,
	}
	ads.ensembleEngine = NewEnsembleEngine(ensembleConfig)

	// Get detectors from ensemble
	ads.detectors = ads.ensembleEngine.GetDetectors()

	// Create normalizer
	normalizer := NewFeatureNormalizerManager(ads.logger)

	// Create advanced training pipeline
	pipelineConfig := &TrainingPipelineConfig{
		BatchSize:        ads.config.ML.BatchSize,
		TrainingInterval: time.Duration(ads.config.ML.TrainingInterval) * time.Hour,
		RetrainThreshold: ads.config.ML.RetrainThreshold,
		ValidationRatio:  0.2,
		EnableContinuous: true,
		DriftDetection:   ads.config.ML.EnableDriftDetection,
		Logger:           ads.logger,
	}
	ads.advancedTrainingPipeline = NewTrainingPipeline(pipelineConfig, ads.ensembleEngine, ads.featureExtractor, normalizer, cache)
}

// createDetector creates a detector instance for the given algorithm
func (ads *AnomalyDetectionSystem) createDetector(algorithm string) AnomalyDetector {
	switch algorithm {
	case "zscore":
		config := &ZScoreConfig{Threshold: 3.0}
		return NewZScoreDetector(config)
	case "iqr":
		config := &IQRConfig{Multiplier: 1.5}
		return NewIQRDetector(config)
	case "isolation_forest":
		config := &IsolationForestConfig{
			NumTrees:      100,
			SubsampleSize: 256,
			Contamination: 0.1,
			Logger:        ads.logger,
		}
		return NewIsolationForest(config)
	default:
		ads.logger.Warnf("Unknown ML algorithm: %s", algorithm)
		return nil
	}
}

// DetectAnomaly performs real-time anomaly detection
func (ads *AnomalyDetectionSystem) DetectAnomaly(event *core.Event) (*EnsembleResult, error) {
	ctx := context.Background()

	// Use continuous mode pipeline if enabled
	if ads.mode == "continuous" && ads.advancedTrainingPipeline != nil {
		return ads.advancedTrainingPipeline.ProcessEvent(ctx, event)
	}

	// Simple mode: manual feature extraction and detection
	features, err := ads.featureExtractor.ExtractFeatures(ctx, event)
	if err != nil {
		return nil, err
	}

	// Run all detectors
	results := make(map[string]*AnomalyResult)
	var ensembleScore float64
	var totalWeight float64

	for name, detector := range ads.detectors {
		result, err := detector.Detect(ctx, features)
		if err != nil {
			ads.logger.Errorf("Detector %s failed: %v", name, err)
			continue
		}

		results[name] = result

		// Simple ensemble: average of all detector scores
		ensembleScore += result.Score
		totalWeight++
	}

	if totalWeight == 0 {
		return nil, fmt.Errorf("all anomaly detectors failed, cannot perform anomaly detection")
	}

	ensembleScore /= totalWeight

	return &EnsembleResult{
		IsAnomaly:        ensembleScore > ads.config.ML.AnomalyThreshold,
		Score:            ensembleScore,
		Confidence:       1.0 - ensembleScore/ads.config.ML.AnomalyThreshold, // Simple confidence calculation
		AlgorithmResults: results,
		VotingStrategy:   "weighted_average",
		ConsensusLevel:   0.8, // Placeholder
		DetectedAt:       time.Now(),
	}, nil
}

// StartTrainingPipeline starts the automated training process
func (ads *AnomalyDetectionSystem) StartTrainingPipeline(ctx context.Context) {
	if ads.mode == "continuous" {
		// Start continuous learning pipeline
		ads.logger.Info("Starting continuous learning pipeline")
		if err := ads.advancedTrainingPipeline.Start(ctx); err != nil {
			ads.logger.Errorf("Failed to start continuous learning pipeline: %v", err)
			return
		}

		// Initial training with historical data
		if err := ads.trainFromHistoricalData(ctx); err != nil {
			if strings.Contains(err.Error(), "insufficient training samples") {
				ads.logger.Warnf("Initial training skipped due to insufficient data: %v", err)
			} else {
				ads.logger.Errorf("Initial training failed: %v", err)
			}
		}

		// Keep running until context is done
		<-ctx.Done()
		ads.advancedTrainingPipeline.Stop()
	} else {
		// Simple mode: periodic training
		ticker := time.NewTicker(time.Duration(ads.config.ML.TrainingInterval) * time.Hour)
		defer ticker.Stop()

		// Initial training
		if err := ads.simpleTrainingPipeline.TrainAllModels(ctx); err != nil {
			if strings.Contains(err.Error(), "insufficient training samples") {
				ads.logger.Warnf("Initial training skipped due to insufficient data: %v", err)
			} else {
				ads.logger.Errorf("Initial training failed: %v", err)
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ads.logger.Info("Starting scheduled ML training")
				if err := ads.simpleTrainingPipeline.TrainAllModels(ctx); err != nil {
					ads.logger.Errorf("Scheduled training failed: %v", err)
				}
			}
		}
	}
}

// trainFromHistoricalData trains the continuous pipeline with historical data
func (ads *AnomalyDetectionSystem) trainFromHistoricalData(ctx context.Context) error {
	// Need to create a temporary simple pipeline to fetch historical data
	tempPipeline := &SimpleTrainingPipeline{
		config:       ads.config,
		eventStorage: ads.eventStorage,
		logger:       ads.logger,
	}

	events, err := tempPipeline.fetchTrainingData(ctx)
	if err != nil {
		return err
	}

	if len(events) < ads.config.ML.MinTrainingSamples {
		return fmt.Errorf("insufficient training samples: %d < %d", len(events), ads.config.ML.MinTrainingSamples)
	}

	ads.logger.Infof("Training continuous pipeline with %d historical events", len(events))

	// Extract features from historical events and train ensemble directly
	// We cannot use ProcessEvent here because it requires a trained model
	for i, event := range events {
		// Check context cancellation periodically
		if i%100 == 0 {
			select {
			case <-ctx.Done():
				ads.logger.Debugw("Context cancelled during historical training",
					"processed_events", i,
					"total_events", len(events))
				return ctx.Err()
			default:
			}
		}

		// Extract features
		features, err := ads.featureExtractor.ExtractFeatures(ctx, event)
		if err != nil {
			ads.logger.Warnf("Failed to extract features from event %d: %v", i, err)
			continue
		}

		// Train the ensemble (which trains all detectors and sets isTrained flag)
		if err := ads.ensembleEngine.Train(ctx, features); err != nil {
			ads.logger.Warnf("Failed to train ensemble with event %d: %v", i, err)
		}
	}

	ads.logger.Info("Initial training of ensemble completed with historical data")

	ads.logger.Info("Continuous pipeline initial training completed")
	return nil
}

// ProcessEvent implements the MLAnomalyDetector interface
func (ads *AnomalyDetectionSystem) ProcessEvent(ctx context.Context, event *core.Event) (interface{}, error) {
	result, err := ads.DetectAnomaly(event)
	return result, err
}

// ForceTraining forces a training cycle
func (stp *SimpleTrainingPipeline) ForceTraining(ctx context.Context) error {
	return stp.TrainAllModels(ctx)
}

// Reset resets the training pipeline
func (stp *SimpleTrainingPipeline) Reset() error {
	stp.status = TrainingPipelineStatus{}
	return nil
}

// ForceTraining forces a training cycle
func (ads *AnomalyDetectionSystem) ForceTraining(ctx context.Context) error {
	if ads.mode == "continuous" {
		return ads.advancedTrainingPipeline.ForceTraining(ctx)
	}
	return ads.simpleTrainingPipeline.ForceTraining(ctx)
}

// Reset resets the ML system
func (ads *AnomalyDetectionSystem) Reset() error {
	if ads.mode == "continuous" {
		ads.advancedTrainingPipeline.Reset()
		return nil
	}
	return ads.simpleTrainingPipeline.Reset()
}

// GetStatus returns the training pipeline status
func (ads *AnomalyDetectionSystem) GetStatus() TrainingPipelineStatus {
	if ads.mode == "continuous" {
		return ads.advancedTrainingPipeline.GetStatus()
	}
	return ads.simpleTrainingPipeline.GetStatus()
}

// SimpleTrainingPipeline provides basic training functionality
type SimpleTrainingPipeline struct {
	config       *config.Config
	eventStorage EventStorage
	logger       *zap.SugaredLogger
	detectors    map[string]AnomalyDetector
	status       TrainingPipelineStatus
}

// TrainAllModels trains all configured ML models
func (stp *SimpleTrainingPipeline) TrainAllModels(ctx context.Context) error {
	stp.status.IsRunning = true
	defer func() { stp.status.IsRunning = false }()

	stp.logger.Info("Starting ML model training")

	// Fetch historical events
	events, err := stp.fetchTrainingData(ctx)
	if err != nil {
		return err
	}

	if len(events) < stp.config.ML.MinTrainingSamples {
		return fmt.Errorf("insufficient training samples: %d < %d", len(events), stp.config.ML.MinTrainingSamples)
	}

	// Extract features
	features := make([]*FeatureVector, len(events))
	extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{
		Logger: stp.logger,
		Cache:  nil,
	})

	for i, event := range events {
		// Check context cancellation periodically
		if i%100 == 0 {
			select {
			case <-ctx.Done():
				stp.logger.Debugw("Context cancelled during feature extraction",
					"processed_events", i,
					"total_events", len(events))
				return ctx.Err()
			default:
			}
		}

		fv, err := extractor.ExtractFeatures(ctx, event)
		if err != nil {
			stp.logger.Warnf("Failed to extract features: %v", err)
			continue
		}
		features[i] = fv
	}

	// Train each detector
	for name, detector := range stp.detectors {
		stp.logger.Infof("Training %s detector", name)
		for i, fv := range features {
			// Check context cancellation periodically during training
			if i%100 == 0 {
				select {
				case <-ctx.Done():
					stp.logger.Debugw("Context cancelled during detector training",
						"detector", name,
						"processed_samples", i)
					return ctx.Err()
				default:
				}
			}

			if err := detector.Train(ctx, fv); err != nil {
				stp.logger.Errorf("Failed to train %s: %v", name, err)
			}
		}
	}

	stp.status.LastTraining = time.Now()

	stp.logger.Info("ML training completed")
	return nil
}

func (stp *SimpleTrainingPipeline) fetchTrainingData(ctx context.Context) ([]*core.Event, error) {
	if stp.eventStorage == nil {
		return nil, fmt.Errorf("event storage not available")
	}

	// Get total event count
	totalCount, err := stp.eventStorage.GetEventCount(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get event count: %w", err)
	}

	// Calculate how many events to fetch based on historical days config
	// For simplicity, fetch the most recent N events (where N is configurable)
	// In a production system, we'd want to filter by timestamp, but for now
	// we'll use a simple limit approach
	maxEventsToFetch := 10000 // Fetch up to 10k events for training
	if totalCount < int64(maxEventsToFetch) {
		maxEventsToFetch = int(totalCount)
	}

	stp.logger.Infof("[ML] Fetching %d events for training (total: %d)", maxEventsToFetch, totalCount)

	// Fetch events in batches to avoid memory exhaustion
	const batchSize = 1000
	var allEvents []*core.Event

	for offset := 0; offset < maxEventsToFetch; offset += batchSize {
		// Check context cancellation
		select {
		case <-ctx.Done():
			stp.logger.Debugw("Context cancelled during training data fetch",
				"fetched_events", len(allEvents),
				"offset", offset)
			return allEvents, ctx.Err()
		default:
		}

		limit := batchSize
		if offset+limit > maxEventsToFetch {
			limit = maxEventsToFetch - offset
		}

		events, err := stp.eventStorage.GetEvents(ctx, limit, offset)
		if err != nil {
			stp.logger.Warnf("[ML] Failed to fetch events batch (offset=%d): %v", offset, err)
			break
		}

		// Convert []Event to []*Event
		for i := range events {
			allEvents = append(allEvents, &events[i])
		}

		if len(events) < batchSize {
			break // No more events
		}
	}

	stp.logger.Infof("[ML] Fetched %d events for ML training", len(allEvents))
	return allEvents, nil
}

// GetStatus returns the current training pipeline status
func (stp *SimpleTrainingPipeline) GetStatus() TrainingPipelineStatus {
	return stp.status
}
