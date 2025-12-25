package ml

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// IQRDetector implements IQR (Interquartile Range) based anomaly detection
type IQRDetector struct {
	mu            sync.RWMutex
	featureValues map[string][]float64
	maxSamples    int
	multiplier    float64 // IQR multiplier (default: 1.5)
	logger        *zap.SugaredLogger
	stats         DetectorStats
}

// IQRConfig holds configuration for IQR detector
type IQRConfig struct {
	MaxSamples int     // Maximum samples to keep per feature (default: 1000)
	Multiplier float64 // IQR multiplier for outlier detection (default: 1.5)
	Logger     *zap.SugaredLogger
}

// NewIQRDetector creates a new IQR anomaly detector
func NewIQRDetector(config *IQRConfig) *IQRDetector {
	if config == nil {
		config = &IQRConfig{}
	}

	if config.MaxSamples == 0 {
		config.MaxSamples = 1000
	}
	if config.Multiplier == 0 {
		config.Multiplier = 1.5 // Standard Tukey fence
	}
	if config.Logger == nil {
		config.Logger = zap.NewNop().Sugar()
	}

	return &IQRDetector{
		featureValues: make(map[string][]float64),
		maxSamples:    config.MaxSamples,
		multiplier:    config.Multiplier,
		logger:        config.Logger,
		stats:         DetectorStats{},
	}
}

// Name returns the detector name
func (d *IQRDetector) Name() string {
	return "iqr"
}

// Train updates the detector with normal training data
func (d *IQRDetector) Train(ctx context.Context, features *FeatureVector) error {
	if features == nil || features.Features == nil {
		return fmt.Errorf("features cannot be nil")
	}

	start := time.Now()
	defer func() {
		d.stats.TrainingTime += time.Since(start)
		d.stats.LastUpdated = time.Now()
	}()

	d.mu.Lock()
	defer d.mu.Unlock()

	// Update samples for each feature
	for featureName, value := range features.Features {
		d.updateFeatureSamples(featureName, value)
	}

	d.stats.TotalSamples++
	return nil
}

// Detect analyzes features and returns anomaly result
func (d *IQRDetector) Detect(ctx context.Context, features *FeatureVector) (*AnomalyResult, error) {
	if features == nil || features.Features == nil {
		return nil, fmt.Errorf("features cannot be nil")
	}

	start := time.Now()
	defer func() {
		detectionTime := time.Since(start)
		// Update rolling average
		if d.stats.DetectionTimeAvg == 0 {
			d.stats.DetectionTimeAvg = detectionTime
		} else {
			d.stats.DetectionTimeAvg = (d.stats.DetectionTimeAvg + detectionTime) / 2
		}
	}()

	d.mu.RLock()
	defer d.mu.RUnlock()

	maxScore := 0.0
	anomalousFeature := ""
	confidence := 0.0

	// Check each feature for anomalies
	for featureName, value := range features.Features {
		values, exists := d.featureValues[featureName]
		if !exists || len(values) < 10 { // Need minimum samples for robust statistics
			continue
		}

		// Calculate IQR-based anomaly score
		score, isAnomaly := d.calculateIQRAnomaly(values, value)

		if score > maxScore {
			maxScore = score
			anomalousFeature = featureName
		}

		if isAnomaly {
			// Confidence based on how far the value is from the IQR bounds
			featureConfidence := math.Min(score/5.0, 1.0) // Normalize to 0-1
			if featureConfidence > confidence {
				confidence = featureConfidence
			}
		}
	}

	isAnomaly := maxScore > 0

	result := &AnomalyResult{
		IsAnomaly:   isAnomaly,
		Score:       maxScore,
		Confidence:  confidence,
		Threshold:   d.multiplier, // Using multiplier as threshold representation
		Algorithm:   d.Name(),
		DetectedAt:  time.Now(),
		FeatureName: anomalousFeature,
	}

	if isAnomaly {
		d.stats.AnomaliesFound++
	}

	return result, nil
}

// GetStats returns detector statistics
func (d *IQRDetector) GetStats() DetectorStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.stats
}

// Reset clears all learned patterns
func (d *IQRDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.featureValues = make(map[string][]float64)
	d.stats = DetectorStats{}
}

// updateFeatureSamples adds a new value to the sample set for a feature
func (d *IQRDetector) updateFeatureSamples(featureName string, value float64) {
	values, exists := d.featureValues[featureName]
	if !exists {
		values = make([]float64, 0, d.maxSamples)
	}

	// Add new value
	values = append(values, value)

	// Keep only the most recent samples
	if len(values) > d.maxSamples {
		values = values[len(values)-d.maxSamples:]
	}

	d.featureValues[featureName] = values
}

// calculateIQRAnomaly calculates if a value is anomalous using IQR method
// Returns (score, isAnomaly) where score is the deviation from IQR bounds
func (d *IQRDetector) calculateIQRAnomaly(values []float64, testValue float64) (float64, bool) {
	if len(values) < 4 {
		return 0, false
	}

	// Create a copy and sort
	sortedValues := make([]float64, len(values))
	copy(sortedValues, values)
	sort.Float64s(sortedValues)

	// Calculate quartiles
	q1 := d.calculateQuantile(sortedValues, 0.25)
	q3 := d.calculateQuantile(sortedValues, 0.75)
	iqr := q3 - q1

	if iqr == 0 {
		// No spread in data, check if value differs from median
		median := d.calculateQuantile(sortedValues, 0.5)
		if testValue != median {
			return 1.0, true // Any difference is anomalous
		}
		return 0, false
	}

	// Calculate Tukey fences
	lowerFence := q1 - d.multiplier*iqr
	upperFence := q3 + d.multiplier*iqr

	// Check if value is outside fences
	if testValue < lowerFence {
		deviation := math.Abs(testValue-lowerFence) / iqr
		return deviation, true
	}

	if testValue > upperFence {
		deviation := math.Abs(testValue-upperFence) / iqr
		return deviation, true
	}

	return 0, false
}

// calculateQuantile calculates the quantile of a sorted slice
func (d *IQRDetector) calculateQuantile(sortedValues []float64, quantile float64) float64 {
	n := len(sortedValues)
	if n == 0 {
		return 0
	}

	// Use linear interpolation for quantiles
	index := quantile * float64(n-1)
	lowerIndex := int(math.Floor(index))
	upperIndex := int(math.Ceil(index))

	if lowerIndex == upperIndex {
		return sortedValues[lowerIndex]
	}

	if upperIndex >= n {
		return sortedValues[n-1]
	}

	// Linear interpolation
	weight := index - float64(lowerIndex)
	return sortedValues[lowerIndex]*(1-weight) + sortedValues[upperIndex]*weight
}
