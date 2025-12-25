package ml

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"go.uber.org/zap"
)

// EnsembleEngineConfig holds configuration for the ensemble engine
type EnsembleEngineConfig struct {
	Algorithms     []string           // List of algorithms to use (zscore, iqr, isolation_forest)
	Weights        map[string]float64 // Weights for each algorithm (optional)
	VotingStrategy string             // "majority", "weighted", "average", "minimum"
	MinConfidence  float64            // Minimum confidence threshold
	Logger         *zap.SugaredLogger
}

// EnsembleEngine combines multiple anomaly detection algorithms
type EnsembleEngine struct {
	mu        sync.RWMutex
	detectors map[string]AnomalyDetector
	config    *EnsembleEngineConfig
	logger    *zap.SugaredLogger
	stats     EnsembleStats
	isTrained bool
}

// EnsembleStats holds ensemble-level statistics
type EnsembleStats struct {
	TotalDetections   int64
	AnomaliesDetected int64
	AlgorithmStats    map[string]DetectorStats
	EnsembleAccuracy  float64
	LastUpdated       time.Time
}

// EnsembleResult contains the combined result from all algorithms
type EnsembleResult struct {
	IsAnomaly        bool                      `json:"is_anomaly"`
	Score            float64                   `json:"score"`
	Confidence       float64                   `json:"confidence"`
	AlgorithmResults map[string]*AnomalyResult `json:"algorithm_results"`
	VotingStrategy   string                    `json:"voting_strategy"`
	ConsensusLevel   float64                   `json:"consensus_level"` // 0-1, how much agreement
	DetectedAt       time.Time                 `json:"detected_at"`
}

// NewEnsembleEngine creates a new ensemble engine
func NewEnsembleEngine(config *EnsembleEngineConfig) *EnsembleEngine {
	if config == nil {
		config = &EnsembleEngineConfig{}
	}

	if len(config.Algorithms) == 0 {
		config.Algorithms = []string{"zscore", "iqr", "isolation_forest"}
	}

	if config.Weights == nil {
		config.Weights = make(map[string]float64)
	}

	if config.VotingStrategy == "" {
		config.VotingStrategy = "weighted"
	}

	if config.MinConfidence == 0 {
		config.MinConfidence = 0.6
	}

	if config.Logger == nil {
		config.Logger = zap.NewNop().Sugar()
	}

	engine := &EnsembleEngine{
		detectors: make(map[string]AnomalyDetector),
		config:    config,
		logger:    config.Logger,
		stats: EnsembleStats{
			AlgorithmStats: make(map[string]DetectorStats),
		},
	}

	// Initialize detectors
	engine.initializeDetectors()

	return engine
}

// initializeDetectors creates and configures all requested detectors
func (e *EnsembleEngine) initializeDetectors() {
	e.initializeDetectorsWithLoader(nil)
}

// initializeDetectorsWithLoader initializes detectors with optional model loader
// TASK 26.4: Load persisted models on startup, fallback to new detectors
func (e *EnsembleEngine) initializeDetectorsWithLoader(loader *ModelLoader) {
	for _, algorithm := range e.config.Algorithms {
		var detector AnomalyDetector
		var err error

		// TASK 26.4: Attempt to load persisted model if loader available
		if loader != nil {
			detector, err = loader.LoadOrTrainDetector(context.Background(), algorithm)
			if err != nil {
				e.logger.Warnf("Failed to load model for %s, creating new detector: %v", algorithm, err)
			}
		}

		// Fallback to new detector if loader not available or load failed
		if detector == nil {
			switch algorithm {
			case "zscore":
				detector = NewZScoreDetector(&ZScoreConfig{
					Logger: e.logger,
				})
			case "iqr":
				detector = NewIQRDetector(&IQRConfig{
					Logger: e.logger,
				})
			case "isolation_forest":
				detector = NewIsolationForest(&IsolationForestConfig{
					Logger: e.logger,
				})
			default:
				e.logger.Warnw("Unknown algorithm requested", "algorithm", algorithm)
				continue
			}
		}

		e.detectors[algorithm] = detector

		// Set default weight if not specified
		if _, exists := e.config.Weights[algorithm]; !exists {
			e.config.Weights[algorithm] = 1.0
		}
	}
}

// Train trains all detectors with the provided features
// Uses a separate write lock to prevent concurrent training and reading
func (e *EnsembleEngine) Train(ctx context.Context, features *FeatureVector) error {
	if features == nil {
		return fmt.Errorf("features cannot be nil")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var lastErr error
	trainedCount := 0

	// Create a copy of the detectors map to avoid race conditions during training
	detectorsCopy := make(map[string]AnomalyDetector)
	for name, detector := range e.detectors {
		detectorsCopy[name] = detector
	}

	// Train on the copied map while holding the write lock
	for name, detector := range detectorsCopy {
		if err := detector.Train(ctx, features); err != nil {
			e.logger.Errorw("Failed to train detector",
				"detector", name,
				"event_id", features.EventID,
				"error", err)
			lastErr = err
		} else {
			trainedCount++
		}
	}

	if trainedCount > 0 {
		e.isTrained = true
		e.stats.TotalDetections++
	}

	return lastErr
}

// Detect analyzes features using all algorithms and combines results
// Uses read lock for detection to allow concurrent reads while preventing writes
func (e *EnsembleEngine) Detect(ctx context.Context, features *FeatureVector) (*EnsembleResult, error) {
	if features == nil {
		return nil, fmt.Errorf("features cannot be nil")
	}

	// Check training status with read lock
	e.mu.RLock()
	isTrained := e.isTrained
	e.mu.RUnlock()

	if !isTrained {
		return nil, fmt.Errorf("ensemble not trained yet")
	}

	// Acquire read lock for detection - allows concurrent detections
	e.mu.RLock()

	// Create a snapshot of detectors and config to avoid holding lock during inference
	detectorsCopy := make(map[string]AnomalyDetector)
	weightsCopy := make(map[string]float64)
	for name, detector := range e.detectors {
		detectorsCopy[name] = detector
		weightsCopy[name] = e.config.Weights[name]
	}
	votingStrategy := e.config.VotingStrategy
	e.mu.RUnlock()

	// Get results from all detectors (no lock held during inference)
	algorithmResults := make(map[string]*AnomalyResult)
	anomalyVotes := 0
	totalWeight := 0.0
	weightedScore := 0.0

	for name, detector := range detectorsCopy {
		result, err := detector.Detect(ctx, features)
		if err != nil {
			e.logger.Warnw("Detector failed during detection",
				"detector", name,
				"event_id", features.EventID,
				"error", err)
			continue
		}

		algorithmResults[name] = result

		weight := weightsCopy[name]
		totalWeight += weight

		if result.IsAnomaly {
			anomalyVotes++
			weightedScore += result.Score * weight
		} else {
			weightedScore += (1.0 - result.Score) * weight // Invert score for normal
		}
	}

	if len(algorithmResults) == 0 {
		return nil, fmt.Errorf("no detectors produced results")
	}

	// Apply voting strategy (using snapshot data)
	e.mu.RLock()
	isAnomaly, score, confidence := e.applyVotingStrategy(algorithmResults, anomalyVotes, weightedScore, totalWeight)
	e.mu.RUnlock()

	// Calculate consensus level (agreement among algorithms)
	consensusLevel := e.calculateConsensus(algorithmResults)

	result := &EnsembleResult{
		IsAnomaly:        isAnomaly,
		Score:            score,
		Confidence:       confidence,
		AlgorithmResults: algorithmResults,
		VotingStrategy:   votingStrategy,
		ConsensusLevel:   consensusLevel,
		DetectedAt:       time.Now(),
	}

	// Update statistics with write lock (brief critical section)
	// Use atomic operations with overflow protection
	e.mu.Lock()
	// Prevent integer overflow - if we're near max int64, reset counters
	if e.stats.TotalDetections < 9223372036854775000 {
		e.stats.TotalDetections++
	} else {
		e.logger.Warn("TotalDetections counter near overflow, resetting statistics")
		e.stats.TotalDetections = 1
		e.stats.AnomaliesDetected = 0
	}
	if isAnomaly {
		if e.stats.AnomaliesDetected < 9223372036854775000 {
			e.stats.AnomaliesDetected++
		}
	}
	e.stats.LastUpdated = time.Now()
	e.mu.Unlock()

	return result, nil
}

// applyVotingStrategy applies the configured voting strategy
func (e *EnsembleEngine) applyVotingStrategy(results map[string]*AnomalyResult, anomalyVotes int, weightedScore, totalWeight float64) (bool, float64, float64) {
	switch e.config.VotingStrategy {
	case "majority":
		return e.majorityVote(results, anomalyVotes)
	case "weighted":
		return e.weightedVote(results, weightedScore, totalWeight)
	case "average":
		return e.averageVote(results)
	case "minimum":
		return e.minimumVote(results)
	default:
		e.logger.Warnw("Unknown voting strategy, using weighted", "strategy", e.config.VotingStrategy)
		return e.weightedVote(results, weightedScore, totalWeight)
	}
}

// majorityVote uses simple majority voting
func (e *EnsembleEngine) majorityVote(results map[string]*AnomalyResult, anomalyVotes int) (bool, float64, float64) {
	totalDetectors := len(results)
	isAnomaly := anomalyVotes > totalDetectors/2

	// Calculate average score and confidence
	totalScore := 0.0
	totalConfidence := 0.0

	for _, result := range results {
		totalScore += result.Score
		totalConfidence += result.Confidence
	}

	avgScore := totalScore / float64(totalDetectors)
	avgConfidence := totalConfidence / float64(totalDetectors)

	return isAnomaly, avgScore, avgConfidence
}

// weightedVote uses weighted voting based on algorithm weights
func (e *EnsembleEngine) weightedVote(results map[string]*AnomalyResult, weightedScore, totalWeight float64) (bool, float64, float64) {
	if totalWeight == 0 {
		return e.majorityVote(results, 0)
	}

	// Normalize weighted score to 0-1 range
	score := weightedScore / totalWeight

	// Decision based on score threshold
	isAnomaly := score > 0.5

	// Calculate weighted confidence
	totalConfidence := 0.0
	totalWeightForConfidence := 0.0

	for name, result := range results {
		weight := e.config.Weights[name]
		totalConfidence += result.Confidence * weight
		totalWeightForConfidence += weight
	}

	confidence := totalConfidence / totalWeightForConfidence

	return isAnomaly, score, confidence
}

// averageVote uses average of all algorithm scores
func (e *EnsembleEngine) averageVote(results map[string]*AnomalyResult) (bool, float64, float64) {
	totalScore := 0.0
	totalConfidence := 0.0
	anomalyCount := 0

	for _, result := range results {
		totalScore += result.Score
		totalConfidence += result.Confidence
		if result.IsAnomaly {
			anomalyCount++
		}
	}

	avgScore := totalScore / float64(len(results))
	avgConfidence := totalConfidence / float64(len(results))

	// Decision based on average score
	isAnomaly := avgScore > 0.5

	return isAnomaly, avgScore, avgConfidence
}

// minimumVote uses the most conservative approach (requires all algorithms to agree)
func (e *EnsembleEngine) minimumVote(results map[string]*AnomalyResult) (bool, float64, float64) {
	allAgree := true
	maxScore := 0.0
	minConfidence := 1.0

	for _, result := range results {
		if !result.IsAnomaly {
			allAgree = false
		}
		if result.Score > maxScore {
			maxScore = result.Score
		}
		if result.Confidence < minConfidence {
			minConfidence = result.Confidence
		}
	}

	return allAgree, maxScore, minConfidence
}

// calculateConsensus measures agreement among algorithms
func (e *EnsembleEngine) calculateConsensus(results map[string]*AnomalyResult) float64 {
	if len(results) <= 1 {
		return 1.0
	}

	anomalyCount := 0
	for _, result := range results {
		if result.IsAnomaly {
			anomalyCount++
		}
	}

	// Consensus is the proportion of agreement
	// If all agree on anomaly: consensus = 1.0
	// If half agree: consensus = 0.5
	// If all disagree: consensus = 0.0

	proportionAnomaly := float64(anomalyCount) / float64(len(results))

	// Consensus = 1 - 2 * |proportion - 0.5|
	// This gives 1.0 when all agree, 0.0 when exactly half agree
	consensus := 1.0 - 2.0*math.Abs(proportionAnomaly-0.5)

	return math.Max(0.0, math.Min(1.0, consensus))
}

// GetStats returns ensemble statistics
func (e *EnsembleEngine) GetStats() EnsembleStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := e.stats

	// Update algorithm stats
	stats.AlgorithmStats = make(map[string]DetectorStats)
	for name, detector := range e.detectors {
		stats.AlgorithmStats[name] = detector.GetStats()
	}

	// Calculate ensemble accuracy (if we had ground truth)
	if stats.TotalDetections > 0 {
		// For now, just use detection rate as a proxy
		stats.EnsembleAccuracy = float64(stats.AnomaliesDetected) / float64(stats.TotalDetections)
	}

	return stats
}

// Reset resets all detectors
func (e *EnsembleEngine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, detector := range e.detectors {
		detector.Reset()
	}

	e.stats = EnsembleStats{
		AlgorithmStats: make(map[string]DetectorStats),
	}
	e.isTrained = false
}

// GetDetectors returns all configured detectors
func (e *EnsembleEngine) GetDetectors() map[string]AnomalyDetector {
	e.mu.RLock()
	defer e.mu.RUnlock()

	detectors := make(map[string]AnomalyDetector)
	for name, detector := range e.detectors {
		detectors[name] = detector
	}

	return detectors
}

// AddDetector adds a new detector to the ensemble
func (e *EnsembleEngine) AddDetector(name string, detector AnomalyDetector, weight float64) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.detectors[name]; exists {
		return fmt.Errorf("detector already exists: %s", name)
	}

	e.detectors[name] = detector
	e.config.Weights[name] = weight

	return nil
}

// RemoveDetector removes a detector from the ensemble
func (e *EnsembleEngine) RemoveDetector(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.detectors[name]; !exists {
		return fmt.Errorf("detector not found: %s", name)
	}

	delete(e.detectors, name)
	delete(e.config.Weights, name)

	return nil
}

// GetTopAnomalies returns the most anomalous features across all algorithms
func (e *EnsembleEngine) GetTopAnomalies(results map[string]*AnomalyResult, limit int) []string {
	// For now, return empty slice since individual algorithms don't specify feature names
	// This could be enhanced in the future to track feature-level anomalies
	return []string{}
}

// GetScore returns the anomaly score
func (r *EnsembleResult) GetScore() float64 {
	return r.Score
}

// GetIsAnomaly returns whether this is classified as an anomaly
func (r *EnsembleResult) GetIsAnomaly() bool {
	return r.IsAnomaly
}
