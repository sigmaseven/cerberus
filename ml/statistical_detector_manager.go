package ml

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// StatisticalDetectorManager manages multiple statistical anomaly detectors
type StatisticalDetectorManager struct {
	mu        sync.RWMutex
	detectors map[string]AnomalyDetector
	logger    *zap.SugaredLogger
}

// StatisticalDetectorConfig holds configuration for the detector manager
type StatisticalDetectorConfig struct {
	Detectors []string // List of detector types to enable (zscore, iqr)
	Logger    *zap.SugaredLogger
}

// NewStatisticalDetectorManager creates a new statistical detector manager
func NewStatisticalDetectorManager(config *StatisticalDetectorConfig) *StatisticalDetectorManager {
	if config == nil {
		config = &StatisticalDetectorConfig{}
	}

	if len(config.Detectors) == 0 {
		// Default to both detectors
		config.Detectors = []string{"zscore", "iqr"}
	}

	if config.Logger == nil {
		config.Logger = zap.NewNop().Sugar()
	}

	manager := &StatisticalDetectorManager{
		detectors: make(map[string]AnomalyDetector),
		logger:    config.Logger,
	}

	// Initialize requested detectors
	for _, detectorType := range config.Detectors {
		switch detectorType {
		case "zscore":
			manager.detectors["zscore"] = NewZScoreDetector(&ZScoreConfig{
				Logger: config.Logger,
			})
		case "iqr":
			manager.detectors["iqr"] = NewIQRDetector(&IQRConfig{
				Logger: config.Logger,
			})
		default:
			config.Logger.Warnw("Unknown detector type, skipping", "type", detectorType)
		}
	}

	return manager
}

// Train updates all detectors with normal training data
func (m *StatisticalDetectorManager) Train(ctx context.Context, features *FeatureVector) error {
	if features == nil {
		return fmt.Errorf("features cannot be nil")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	for name, detector := range m.detectors {
		if err := detector.Train(ctx, features); err != nil {
			m.logger.Errorw("Failed to train detector",
				"detector", name,
				"event_id", features.EventID,
				"error", err)
			lastErr = err
		}
	}

	return lastErr
}

// Detect analyzes features using all detectors and returns combined results
func (m *StatisticalDetectorManager) Detect(ctx context.Context, features *FeatureVector) ([]*AnomalyResult, error) {
	if features == nil {
		return nil, fmt.Errorf("features cannot be nil")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []*AnomalyResult

	for name, detector := range m.detectors {
		result, err := detector.Detect(ctx, features)
		if err != nil {
			m.logger.Errorw("Failed to detect with detector",
				"detector", name,
				"event_id", features.EventID,
				"error", err)
			continue
		}

		results = append(results, result)
	}

	return results, nil
}

// DetectMajorityVote performs detection and returns majority vote result
func (m *StatisticalDetectorManager) DetectMajorityVote(ctx context.Context, features *FeatureVector) (*AnomalyResult, error) {
	results, err := m.Detect(ctx, features)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no detectors available")
	}

	// Count votes
	anomalyVotes := 0
	totalScore := 0.0
	maxConfidence := 0.0
	var bestAlgorithm string
	var anomalousFeature string

	for _, result := range results {
		if result.IsAnomaly {
			anomalyVotes++
		}
		totalScore += result.Score
		if result.Confidence > maxConfidence {
			maxConfidence = result.Confidence
			bestAlgorithm = result.Algorithm
			anomalousFeature = result.FeatureName
		}
	}

	// Majority vote (more than half)
	isAnomaly := anomalyVotes > len(results)/2
	avgScore := totalScore / float64(len(results))

	// Confidence based on agreement level
	agreementRatio := float64(anomalyVotes) / float64(len(results))
	confidence := agreementRatio * maxConfidence

	return &AnomalyResult{
		IsAnomaly:   isAnomaly,
		Score:       avgScore,
		Confidence:  confidence,
		Threshold:   0.5, // Majority threshold
		Algorithm:   fmt.Sprintf("majority_vote(%s)", bestAlgorithm),
		DetectedAt:  time.Now(),
		FeatureName: anomalousFeature,
	}, nil
}

// GetDetector returns a specific detector by name
func (m *StatisticalDetectorManager) GetDetector(name string) (AnomalyDetector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	detector, exists := m.detectors[name]
	if !exists {
		return nil, fmt.Errorf("detector not found: %s", name)
	}

	return detector, nil
}

// GetDetectors returns all available detectors
func (m *StatisticalDetectorManager) GetDetectors() map[string]AnomalyDetector {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent external modification
	detectors := make(map[string]AnomalyDetector)
	for name, detector := range m.detectors {
		detectors[name] = detector
	}

	return detectors
}

// GetStats returns combined statistics from all detectors
func (m *StatisticalDetectorManager) GetStats() map[string]DetectorStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]DetectorStats)
	for name, detector := range m.detectors {
		stats[name] = detector.GetStats()
	}

	return stats
}

// Reset resets all detectors
func (m *StatisticalDetectorManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, detector := range m.detectors {
		detector.Reset()
	}
}

// AddDetector adds a new detector to the manager
func (m *StatisticalDetectorManager) AddDetector(name string, detector AnomalyDetector) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.detectors[name]; exists {
		return fmt.Errorf("detector already exists: %s", name)
	}

	m.detectors[name] = detector
	return nil
}

// RemoveDetector removes a detector from the manager
func (m *StatisticalDetectorManager) RemoveDetector(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.detectors[name]; !exists {
		return fmt.Errorf("detector not found: %s", name)
	}

	delete(m.detectors, name)
	return nil
}
