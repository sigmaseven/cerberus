package ml

import (
	"fmt"
	"math"
	"sync"

	"go.uber.org/zap"
)

// FeatureNormalizer normalizes feature values using various techniques
type FeatureNormalizer interface {
	// Normalize normalizes a single feature value
	Normalize(featureName string, value float64) float64

	// UpdateStats updates normalization statistics with new feature values
	UpdateStats(featureName string, value float64)

	// GetStats returns current normalization statistics for a feature
	GetStats(featureName string) (mean, stddev, min, max float64, count int64)
}

// ZScoreNormalizer normalizes features using Z-score standardization
type ZScoreNormalizer struct {
	mu     sync.RWMutex
	stats  map[string]*FeatureStats
	logger *zap.SugaredLogger
}

// FeatureStats holds statistical information for feature normalization
type FeatureStats struct {
	Count  int64
	Sum    float64
	SumSq  float64
	Min    float64
	Max    float64
	Mean   float64
	StdDev float64
}

// NewZScoreNormalizer creates a new Z-score normalizer
func NewZScoreNormalizer(logger *zap.SugaredLogger) *ZScoreNormalizer {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	return &ZScoreNormalizer{
		stats:  make(map[string]*FeatureStats),
		logger: logger,
	}
}

// UpdateStats updates the running statistics for a feature
func (n *ZScoreNormalizer) UpdateStats(featureName string, value float64) {
	n.mu.Lock()
	defer n.mu.Unlock()

	stats, exists := n.stats[featureName]
	if !exists {
		stats = &FeatureStats{
			Min: value,
			Max: value,
		}
		n.stats[featureName] = stats
	}

	// Update count and sums
	stats.Count++
	stats.Sum += value
	stats.SumSq += value * value

	// Update min/max
	if value < stats.Min {
		stats.Min = value
	}
	if value > stats.Max {
		stats.Max = value
	}

	// Update mean and stddev
	if stats.Count > 1 {
		stats.Mean = stats.Sum / float64(stats.Count)
		// Use sample variance (divide by n-1) for better statistical properties
		variance := (stats.SumSq - float64(stats.Count)*stats.Mean*stats.Mean) / float64(stats.Count-1)
		if variance > 0 {
			stats.StdDev = math.Sqrt(variance)
		} else {
			stats.StdDev = 0
		}
	}
}

// Normalize normalizes a feature value using Z-score
func (n *ZScoreNormalizer) Normalize(featureName string, value float64) float64 {
	n.mu.RLock()
	stats, exists := n.stats[featureName]
	n.mu.RUnlock()

	if !exists || stats.Count < 2 || stats.StdDev == 0 {
		// Not enough data or no variance, return original value
		return value
	}

	// Z-score = (value - mean) / stddev
	zscore := (value - stats.Mean) / stats.StdDev

	// Clamp extreme outliers to prevent numerical issues
	if zscore > 10 {
		zscore = 10
	} else if zscore < -10 {
		zscore = -10
	}

	return zscore
}

// GetStats returns current statistics for a feature
func (n *ZScoreNormalizer) GetStats(featureName string) (mean, stddev, min, max float64, count int64) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	stats, exists := n.stats[featureName]
	if !exists {
		return 0, 0, 0, 0, 0
	}

	return stats.Mean, stats.StdDev, stats.Min, stats.Max, stats.Count
}

// MinMaxNormalizer normalizes features to [0, 1] range
type MinMaxNormalizer struct {
	mu     sync.RWMutex
	stats  map[string]*FeatureStats
	logger *zap.SugaredLogger
}

// NewMinMaxNormalizer creates a new min-max normalizer
func NewMinMaxNormalizer(logger *zap.SugaredLogger) *MinMaxNormalizer {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	return &MinMaxNormalizer{
		stats:  make(map[string]*FeatureStats),
		logger: logger,
	}
}

// UpdateStats updates the running statistics for a feature
func (n *MinMaxNormalizer) UpdateStats(featureName string, value float64) {
	n.mu.Lock()
	defer n.mu.Unlock()

	stats, exists := n.stats[featureName]
	if !exists {
		stats = &FeatureStats{
			Min: value,
			Max: value,
		}
		n.stats[featureName] = stats
	}

	stats.Count++

	// Update min/max
	if value < stats.Min {
		stats.Min = value
	}
	if value > stats.Max {
		stats.Max = value
	}
}

// Normalize normalizes a feature value to [0, 1] range
func (n *MinMaxNormalizer) Normalize(featureName string, value float64) float64 {
	n.mu.RLock()
	stats, exists := n.stats[featureName]
	n.mu.RUnlock()

	if !exists || stats.Max == stats.Min {
		// No range or not enough data, return 0.5 as neutral value
		return 0.5
	}

	// Min-max normalization = (value - min) / (max - min)
	normalized := (value - stats.Min) / (stats.Max - stats.Min)

	// Clamp to [0, 1] range
	if normalized < 0 {
		normalized = 0
	} else if normalized > 1 {
		normalized = 1
	}

	return normalized
}

// GetStats returns current statistics for a feature
func (n *MinMaxNormalizer) GetStats(featureName string) (mean, stddev, min, max float64, count int64) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	stats, exists := n.stats[featureName]
	if !exists {
		return 0, 0, 0, 0, 0
	}

	return 0, 0, stats.Min, stats.Max, stats.Count // MinMax doesn't track mean/stddev
}

// RobustNormalizer normalizes features using robust statistics (median, IQR)
type RobustNormalizer struct {
	mu         sync.RWMutex
	values     map[string][]float64
	logger     *zap.SugaredLogger
	maxSamples int // Maximum number of samples to keep for each feature
}

// NewRobustNormalizer creates a new robust normalizer
func NewRobustNormalizer(logger *zap.SugaredLogger) *RobustNormalizer {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	return &RobustNormalizer{
		values:     make(map[string][]float64),
		logger:     logger,
		maxSamples: 10000, // Keep last 10k samples per feature
	}
}

// UpdateStats adds a new value to the sample set for a feature
func (n *RobustNormalizer) UpdateStats(featureName string, value float64) {
	n.mu.Lock()
	defer n.mu.Unlock()

	values, exists := n.values[featureName]
	if !exists {
		values = make([]float64, 0, n.maxSamples)
	}

	// Add new value
	values = append(values, value)

	// Keep only the most recent samples
	if len(values) > n.maxSamples {
		values = values[len(values)-n.maxSamples:]
	}

	n.values[featureName] = values
}

// Normalize normalizes using median and IQR (robust to outliers)
func (n *RobustNormalizer) Normalize(featureName string, value float64) float64 {
	n.mu.RLock()
	values, exists := n.values[featureName]
	n.mu.RUnlock()

	if !exists || len(values) < 10 {
		// Not enough data for robust statistics
		return value
	}

	// Calculate median and IQR
	sortedValues := make([]float64, len(values))
	copy(sortedValues, values)

	// Simple sort (could be optimized)
	for i := 0; i < len(sortedValues)-1; i++ {
		for j := i + 1; j < len(sortedValues); j++ {
			if sortedValues[i] > sortedValues[j] {
				sortedValues[i], sortedValues[j] = sortedValues[j], sortedValues[i]
			}
		}
	}

	median := calculateMedian(sortedValues)
	iqr := calculateIQR(sortedValues)

	if iqr == 0 {
		// No spread, return median-based normalization
		if value > median {
			return 1.0
		}
		return 0.0
	}

	// Robust Z-score using median and IQR
	robustZ := (value - median) / iqr

	// Clamp extreme values
	if robustZ > 5 {
		robustZ = 5
	} else if robustZ < -5 {
		robustZ = -5
	}

	return robustZ
}

// GetStats returns median and IQR as statistics
func (n *RobustNormalizer) GetStats(featureName string) (median, iqr, min, max float64, count int64) {
	n.mu.RLock()
	values, exists := n.values[featureName]
	n.mu.RUnlock()

	if !exists {
		return 0, 0, 0, 0, 0
	}

	if len(values) == 0 {
		return 0, 0, 0, 0, 0
	}

	sortedValues := make([]float64, len(values))
	copy(sortedValues, values)

	// Simple sort
	for i := 0; i < len(sortedValues)-1; i++ {
		for j := i + 1; j < len(sortedValues); j++ {
			if sortedValues[i] > sortedValues[j] {
				sortedValues[i], sortedValues[j] = sortedValues[j], sortedValues[i]
			}
		}
	}

	med := calculateMedian(sortedValues)
	iqrVal := calculateIQR(sortedValues)
	minVal := sortedValues[0]
	maxVal := sortedValues[len(sortedValues)-1]

	return med, iqrVal, minVal, maxVal, int64(len(values))
}

// Helper functions for robust statistics
func calculateMedian(sortedValues []float64) float64 {
	n := len(sortedValues)
	if n%2 == 1 {
		return sortedValues[n/2]
	}
	return (sortedValues[n/2-1] + sortedValues[n/2]) / 2.0
}

func calculateIQR(sortedValues []float64) float64 {
	n := len(sortedValues)
	q1Index := n / 4
	q3Index := 3 * n / 4

	q1 := sortedValues[q1Index]
	q3 := sortedValues[q3Index]

	return q3 - q1
}

// FeatureNormalizerManager manages multiple normalizers
type FeatureNormalizerManager struct {
	normalizers map[string]FeatureNormalizer
	logger      *zap.SugaredLogger
}

// NewFeatureNormalizerManager creates a new normalizer manager
func NewFeatureNormalizerManager(logger *zap.SugaredLogger) *FeatureNormalizerManager {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	manager := &FeatureNormalizerManager{
		normalizers: make(map[string]FeatureNormalizer),
		logger:      logger,
	}

	// Register different normalizers
	manager.normalizers["zscore"] = NewZScoreNormalizer(logger)
	manager.normalizers["minmax"] = NewMinMaxNormalizer(logger)
	manager.normalizers["robust"] = NewRobustNormalizer(logger)

	return manager
}

// NormalizeFeature normalizes a feature using the specified normalizer
func (m *FeatureNormalizerManager) NormalizeFeature(normalizerType, featureName string, value float64) float64 {
	normalizer, exists := m.normalizers[normalizerType]
	if !exists {
		m.logger.Warnw("Unknown normalizer type", "type", normalizerType)
		return value
	}

	return normalizer.Normalize(featureName, value)
}

// UpdateNormalizerStats updates statistics for all normalizers
func (m *FeatureNormalizerManager) UpdateNormalizerStats(featureName string, value float64) {
	for _, normalizer := range m.normalizers {
		normalizer.UpdateStats(featureName, value)
	}
}

// GetNormalizerStats returns statistics for a specific normalizer and feature
func (m *FeatureNormalizerManager) GetNormalizerStats(normalizerType, featureName string) (mean, stddev, min, max float64, count int64, err error) {
	normalizer, exists := m.normalizers[normalizerType]
	if !exists {
		return 0, 0, 0, 0, 0, fmt.Errorf("unknown normalizer type: %s", normalizerType)
	}

	mean, stddev, min, max, count = normalizer.GetStats(featureName)
	return mean, stddev, min, max, count, nil
}
