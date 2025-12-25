package ml

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cerberus/core"
	"go.uber.org/zap"
)

// TrainingPipelineConfig holds configuration for the training pipeline
type TrainingPipelineConfig struct {
	BatchSize        int           // Number of samples to collect before training
	TrainingInterval time.Duration // How often to trigger training
	RetrainThreshold int           // Retrain after this many new samples
	ValidationRatio  float64       // Ratio of data to use for validation
	EnableContinuous bool          // Enable continuous learning
	DriftDetection   bool          // Enable concept drift detection
	Logger           *zap.SugaredLogger
}

// TrainingPipeline manages model training and updates
type TrainingPipeline struct {
	mu         sync.RWMutex
	config     *TrainingPipelineConfig
	ensemble   *EnsembleEngine
	extractor  *FeatureExtractorManager
	normalizer *FeatureNormalizerManager
	cache      FeatureCache

	// Training data
	trainingBuffer []*FeatureVector
	validationData []*FeatureVector
	lastTraining   time.Time
	sampleCount    int64

	// Performance tracking
	performanceHistory []TrainingPerformance
	logger             *zap.SugaredLogger
	isRunning          bool
	stopChan           chan struct{}
	ctx                context.Context // Lifecycle context for cancellation
}

// TrainingPerformance tracks training performance over time
type TrainingPerformance struct {
	Timestamp        time.Time
	TrainingDuration time.Duration
	SampleCount      int64
	ValidationScore  float64
	DriftDetected    bool
	AlgorithmMetrics map[string]float64
}

// NewTrainingPipeline creates a new training pipeline
func NewTrainingPipeline(config *TrainingPipelineConfig, ensemble *EnsembleEngine, extractor *FeatureExtractorManager, normalizer *FeatureNormalizerManager, cache FeatureCache) *TrainingPipeline {
	if config == nil {
		config = &TrainingPipelineConfig{}
	}

	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}
	if config.TrainingInterval == 0 {
		config.TrainingInterval = 1 * time.Hour
	}
	if config.RetrainThreshold == 0 {
		config.RetrainThreshold = 5000
	}
	if config.ValidationRatio == 0 {
		config.ValidationRatio = 0.2
	}
	if config.Logger == nil {
		config.Logger = zap.NewNop().Sugar()
	}

	return &TrainingPipeline{
		config:             config,
		ensemble:           ensemble,
		extractor:          extractor,
		normalizer:         normalizer,
		cache:              cache,
		trainingBuffer:     make([]*FeatureVector, 0, config.BatchSize),
		validationData:     make([]*FeatureVector, 0),
		performanceHistory: make([]TrainingPerformance, 0),
		logger:             config.Logger,
		stopChan:           make(chan struct{}),
	}
}

// Start begins the training pipeline
func (p *TrainingPipeline) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.isRunning {
		p.mu.Unlock()
		return fmt.Errorf("training pipeline already running")
	}
	p.isRunning = true
	p.ctx = ctx // Store context for background goroutines
	p.mu.Unlock()

	p.logger.Infow("Starting training pipeline",
		"batch_size", p.config.BatchSize,
		"training_interval", p.config.TrainingInterval,
		"continuous_learning", p.config.EnableContinuous)

	// Start continuous training if enabled
	if p.config.EnableContinuous {
		go p.continuousTrainingLoop(ctx)
	}

	return nil
}

// Stop stops the training pipeline
func (p *TrainingPipeline) Stop() error {
	p.mu.Lock()
	if !p.isRunning {
		p.mu.Unlock()
		return nil
	}
	p.isRunning = false
	p.mu.Unlock()

	close(p.stopChan)
	p.logger.Info("Training pipeline stopped")
	return nil
}

// ProcessEvent processes an event through the ML pipeline
func (p *TrainingPipeline) ProcessEvent(ctx context.Context, event *core.Event) (*EnsembleResult, error) {
	if event == nil {
		return nil, fmt.Errorf("event cannot be nil")
	}

	// Extract features
	features, err := p.extractor.ExtractFeatures(ctx, event)
	if err != nil {
		return nil, fmt.Errorf("feature extraction failed: %w", err)
	}

	// Normalize features
	for featureName, value := range features.Features {
		normalized := p.normalizer.NormalizeFeature("zscore", featureName, value)
		features.Features[featureName] = normalized
	}

	// Cache features
	if p.cache != nil {
		if err := p.cache.Set(ctx, features, 1*time.Hour); err != nil {
			p.logger.Warnw("Failed to cache features", "event_id", event.EventID, "error", err)
		}
	}

	// Detect anomalies
	result, err := p.ensemble.Detect(ctx, features)
	if err != nil {
		return nil, fmt.Errorf("anomaly detection failed: %w", err)
	}

	// Add to training buffer for continuous learning
	p.addToTrainingBuffer(features)

	// Update normalizer statistics
	for featureName, value := range features.Features {
		p.normalizer.UpdateNormalizerStats(featureName, value)
	}

	return result, nil
}

// addToTrainingBuffer adds features to the training buffer
func (p *TrainingPipeline) addToTrainingBuffer(features *FeatureVector) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.trainingBuffer = append(p.trainingBuffer, features)
	p.sampleCount++

	// Check if we should trigger training
	shouldTrain := len(p.trainingBuffer) >= p.config.BatchSize ||
		(p.config.EnableContinuous && p.sampleCount%int64(p.config.RetrainThreshold) == 0)

	if shouldTrain {
		// Use stored context for background training (with timeout for safety)
		trainingCtx := p.ctx
		if trainingCtx == nil {
			trainingCtx = context.Background()
		}

		go func() {
			// Create a timeout context to ensure training doesn't run indefinitely
			ctx, cancel := context.WithTimeout(trainingCtx, 10*time.Minute)
			defer cancel()

			if err := p.triggerTraining(ctx); err != nil {
				p.logger.Errorw("Background training failed", "error", err)
			}
		}()
	}
}

// triggerTraining performs model training
func (p *TrainingPipeline) triggerTraining(ctx context.Context) error {
	p.mu.Lock()
	if len(p.trainingBuffer) == 0 {
		p.mu.Unlock()
		return nil
	}

	// Prepare training data
	trainingData := make([]*FeatureVector, len(p.trainingBuffer))
	copy(trainingData, p.trainingBuffer)

	// Split for validation
	validationSize := int(float64(len(trainingData)) * p.config.ValidationRatio)
	if validationSize > 0 {
		p.validationData = trainingData[:validationSize]
		trainingData = trainingData[validationSize:]
	}

	// Clear buffer
	p.trainingBuffer = make([]*FeatureVector, 0, p.config.BatchSize)
	p.mu.Unlock()

	p.logger.Infow("Starting model training",
		"training_samples", len(trainingData),
		"validation_samples", len(p.validationData))

	start := time.Now()

	// Train ensemble
	trainingErrors := 0
	for i, features := range trainingData {
		// Check context cancellation periodically
		if i%100 == 0 {
			select {
			case <-ctx.Done():
				p.logger.Debugw("Context cancelled during ensemble training",
					"processed_samples", i,
					"total_samples", len(trainingData))
				return ctx.Err()
			default:
			}
		}

		if err := p.ensemble.Train(ctx, features); err != nil {
			trainingErrors++
			p.logger.Debugw("Training error", "event_id", features.EventID, "error", err)
		}
	}

	trainingDuration := time.Since(start)

	// Validate performance
	validationScore := p.validateModel(ctx)

	// Check for concept drift
	driftDetected := p.detectConceptDrift()

	// Record performance
	performance := TrainingPerformance{
		Timestamp:        time.Now(),
		TrainingDuration: trainingDuration,
		SampleCount:      int64(len(trainingData)),
		ValidationScore:  validationScore,
		DriftDetected:    driftDetected,
		AlgorithmMetrics: p.getAlgorithmMetrics(),
	}

	p.mu.Lock()
	p.performanceHistory = append(p.performanceHistory, performance)
	p.lastTraining = time.Now()

	// Keep only recent history
	if len(p.performanceHistory) > 100 {
		p.performanceHistory = p.performanceHistory[len(p.performanceHistory)-100:]
	}
	p.mu.Unlock()

	p.logger.Infow("Training completed",
		"duration", trainingDuration,
		"training_errors", trainingErrors,
		"validation_score", validationScore,
		"drift_detected", driftDetected)

	return nil
}

// continuousTrainingLoop runs periodic training
func (p *TrainingPipeline) continuousTrainingLoop(ctx context.Context) {
	ticker := time.NewTicker(p.config.TrainingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			if err := p.triggerTraining(ctx); err != nil {
				p.logger.Errorw("Continuous training failed", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// validateModel evaluates model performance on validation data
func (p *TrainingPipeline) validateModel(ctx context.Context) float64 {
	if len(p.validationData) == 0 {
		return 0.0
	}

	totalScore := 0.0
	validDetections := 0

	for i, features := range p.validationData {
		// Check context cancellation periodically
		if i%100 == 0 {
			select {
			case <-ctx.Done():
				p.logger.Debugw("Context cancelled during model validation",
					"processed_samples", i,
					"total_samples", len(p.validationData))
				return 0.0
			default:
			}
		}

		result, err := p.ensemble.Detect(ctx, features)
		if err != nil {
			continue
		}

		// For validation, we assume validation data is normal
		// Score represents confidence in normal behavior
		score := 1.0 - result.Score // Invert score (higher = more normal)
		totalScore += score
		validDetections++
	}

	if validDetections == 0 {
		return 0.0
	}

	return totalScore / float64(validDetections)
}

// detectConceptDrift detects if the data distribution has changed
func (p *TrainingPipeline) detectConceptDrift() bool {
	if !p.config.DriftDetection || len(p.performanceHistory) < 2 {
		return false
	}

	// Simple drift detection: check if validation score dropped significantly
	recent := p.performanceHistory[len(p.performanceHistory)-1]
	previous := p.performanceHistory[len(p.performanceHistory)-2]

	scoreDrop := previous.ValidationScore - recent.ValidationScore
	driftThreshold := 0.2 // 20% drop indicates potential drift

	return scoreDrop > driftThreshold
}

// getAlgorithmMetrics returns performance metrics for each algorithm
func (p *TrainingPipeline) getAlgorithmMetrics() map[string]float64 {
	stats := p.ensemble.GetStats()
	metrics := make(map[string]float64)

	for name, stat := range stats.AlgorithmStats {
		if stat.TotalSamples > 0 {
			// Calculate anomaly detection rate
			metrics[name+"_anomaly_rate"] = float64(stat.AnomaliesFound) / float64(stat.TotalSamples)
		}
	}

	return metrics
}

// GetStatus returns the current status of the training pipeline
func (p *TrainingPipeline) GetStatus() TrainingPipelineStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return TrainingPipelineStatus{
		IsRunning:          p.isRunning,
		SampleCount:        p.sampleCount,
		BufferSize:         len(p.trainingBuffer),
		LastTraining:       p.lastTraining,
		PerformanceHistory: p.performanceHistory,
	}
}

// TrainingPipelineStatus represents the current state of the training pipeline
type TrainingPipelineStatus struct {
	IsRunning          bool                  `json:"is_running"`
	SampleCount        int64                 `json:"sample_count"`
	BufferSize         int                   `json:"buffer_size"`
	LastTraining       time.Time             `json:"last_training"`
	PerformanceHistory []TrainingPerformance `json:"performance_history"`
}

// ForceTraining manually triggers model training
func (p *TrainingPipeline) ForceTraining(ctx context.Context) error {
	p.logger.Info("Forcing model training")
	return p.triggerTraining(ctx)
}

// Reset resets the training pipeline
func (p *TrainingPipeline) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.trainingBuffer = make([]*FeatureVector, 0, p.config.BatchSize)
	p.validationData = make([]*FeatureVector, 0)
	p.performanceHistory = make([]TrainingPerformance, 0)
	p.sampleCount = 0
	p.lastTraining = time.Time{}

	// Reset ensemble
	p.ensemble.Reset()

	p.logger.Info("Training pipeline reset")
}

// GetPerformanceHistory returns recent training performance
func (p *TrainingPipeline) GetPerformanceHistory(limit int) []TrainingPerformance {
	p.mu.RLock()
	defer p.mu.RUnlock()

	history := p.performanceHistory
	if len(history) <= limit {
		return history
	}

	return history[len(history)-limit:]
}
