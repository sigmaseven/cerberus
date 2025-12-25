package ml

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AnomalyDetector defines the interface for anomaly detection algorithms
type AnomalyDetector interface {
	// Name returns the name of the detector
	Name() string

	// Train updates the detector with normal training data
	Train(ctx context.Context, features *FeatureVector) error

	// Detect analyzes features and returns anomaly score and decision
	Detect(ctx context.Context, features *FeatureVector) (*AnomalyResult, error)

	// GetStats returns detector statistics
	GetStats() DetectorStats

	// Reset clears all learned patterns
	Reset()
}

// AnomalyResult contains the result of anomaly detection
type AnomalyResult struct {
	IsAnomaly   bool      `json:"is_anomaly"`
	Score       float64   `json:"score"`      // Anomaly score (higher = more anomalous)
	Confidence  float64   `json:"confidence"` // Confidence in the decision (0-1)
	Threshold   float64   `json:"threshold"`  // Threshold used for decision
	Algorithm   string    `json:"algorithm"`  // Detection algorithm used
	DetectedAt  time.Time `json:"detected_at"`
	FeatureName string    `json:"feature_name,omitempty"` // Specific feature that triggered anomaly
}

// DetectorStats contains statistics about detector performance
type DetectorStats struct {
	TotalSamples     int64         `json:"total_samples"`
	AnomaliesFound   int64         `json:"anomalies_found"`
	TrainingTime     time.Duration `json:"training_time"`
	DetectionTimeAvg time.Duration `json:"detection_time_avg"`
	LastUpdated      time.Time     `json:"last_updated"`
}

// ZScoreDetector implements Z-Score based anomaly detection
type ZScoreDetector struct {
	mu           sync.RWMutex
	featureStats map[string]*FeatureStats
	threshold    float64
	minSamples   int
	logger       *zap.SugaredLogger
	stats        DetectorStats
}

// ZScoreConfig holds configuration for Z-Score detector
type ZScoreConfig struct {
	Threshold  float64 // Z-score threshold (default: 3.0)
	MinSamples int     // Minimum samples before detection (default: 30)
	Logger     *zap.SugaredLogger
}

// NewZScoreDetector creates a new Z-Score anomaly detector
func NewZScoreDetector(config *ZScoreConfig) *ZScoreDetector {
	if config == nil {
		config = &ZScoreConfig{}
	}

	if config.Threshold == 0 {
		config.Threshold = 3.0 // Standard 3-sigma rule
	}
	if config.MinSamples == 0 {
		config.MinSamples = 30
	}
	if config.Logger == nil {
		config.Logger = zap.NewNop().Sugar()
	}

	return &ZScoreDetector{
		featureStats: make(map[string]*FeatureStats),
		threshold:    config.Threshold,
		minSamples:   config.MinSamples,
		logger:       config.Logger,
		stats:        DetectorStats{},
	}
}

// Name returns the detector name
func (d *ZScoreDetector) Name() string {
	return "zscore"
}

// Train updates the detector with normal training data
func (d *ZScoreDetector) Train(ctx context.Context, features *FeatureVector) error {
	if features == nil || features.Features == nil {
		return fmt.Errorf("features cannot be nil")
	}

	start := time.Now()

	// SECURITY FIX: Acquire mutex before accessing shared state
	d.mu.Lock()
	defer d.mu.Unlock()

	// Update statistics for each feature
	for featureName, value := range features.Features {
		d.updateFeatureStats(featureName, value)
	}

	d.stats.TotalSamples++

	// Update timing stats with mutex held to prevent race
	d.stats.TrainingTime += time.Since(start)
	d.stats.LastUpdated = time.Now()

	return nil
}

// Detect analyzes features and returns anomaly result
func (d *ZScoreDetector) Detect(ctx context.Context, features *FeatureVector) (*AnomalyResult, error) {
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
		stats, exists := d.featureStats[featureName]
		if !exists || stats.Count < int64(d.minSamples) {
			// Not enough training data for this feature
			continue
		}

		// Calculate Z-score
		zscore := d.calculateZScore(stats, value)
		score := math.Abs(zscore)

		if score > maxScore {
			maxScore = score
			anomalousFeature = featureName
		}

		// Calculate confidence based on how far from threshold
		if score > d.threshold {
			featureConfidence := math.Min(score/d.threshold, 2.0) / 2.0 // Normalize to 0-1
			if featureConfidence > confidence {
				confidence = featureConfidence
			}
		}
	}

	isAnomaly := maxScore > d.threshold

	result := &AnomalyResult{
		IsAnomaly:   isAnomaly,
		Score:       maxScore,
		Confidence:  confidence,
		Threshold:   d.threshold,
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
func (d *ZScoreDetector) GetStats() DetectorStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.stats
}

// Reset clears all learned patterns
func (d *ZScoreDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.featureStats = make(map[string]*FeatureStats)
	d.stats = DetectorStats{}
}

// updateFeatureStats updates running statistics for a feature
func (d *ZScoreDetector) updateFeatureStats(featureName string, value float64) {
	stats, exists := d.featureStats[featureName]
	if !exists {
		stats = &FeatureStats{
			Min: value,
			Max: value,
		}
		d.featureStats[featureName] = stats
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
		// Use sample variance (divide by n-1)
		variance := (stats.SumSq - float64(stats.Count)*stats.Mean*stats.Mean) / float64(stats.Count-1)
		if variance > 0 {
			stats.StdDev = math.Sqrt(variance)
		} else {
			stats.StdDev = 0
		}
	}
}

// calculateZScore calculates the Z-score for a value given feature statistics
func (d *ZScoreDetector) calculateZScore(stats *FeatureStats, value float64) float64 {
	if stats.StdDev == 0 {
		// No variance, can't calculate Z-score
		if value == stats.Mean {
			return 0.0
		}
		// Return large score if different from mean
		return 10.0
	}

	return (value - stats.Mean) / stats.StdDev
}
