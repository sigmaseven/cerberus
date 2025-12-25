package ml

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cerberus/core"
	"go.uber.org/zap"
)

// FeatureExtractor defines the interface for feature extraction
type FeatureExtractor interface {
	// Extract extracts features from an event and returns them as a map
	Extract(ctx context.Context, event *core.Event) (map[string]float64, error)

	// Name returns the name of the feature extractor
	Name() string
}

// FeatureVector represents a collection of extracted features
type FeatureVector struct {
	EventID   string             `json:"event_id"`
	Timestamp time.Time          `json:"timestamp"`
	Features  map[string]float64 `json:"features"`
}

// FeatureExtractorConfig holds configuration for feature extraction
type FeatureExtractorConfig struct {
	Logger *zap.SugaredLogger
	Cache  FeatureCache
}

// FeatureExtractorManager manages multiple feature extractors
type FeatureExtractorManager struct {
	extractors []FeatureExtractor
	cache      FeatureCache
	logger     *zap.SugaredLogger
}

// NewFeatureExtractorManager creates a new feature extractor manager
func NewFeatureExtractorManager(cfg *FeatureExtractorConfig) *FeatureExtractorManager {
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop().Sugar()
	}

	manager := &FeatureExtractorManager{
		cache:  cfg.Cache,
		logger: cfg.Logger,
	}

	// Register all feature extractors
	manager.extractors = []FeatureExtractor{
		NewTemporalFeatureExtractor(),
		NewNetworkFeatureExtractor(),
		NewContentFeatureExtractor(),
		NewFrequencyFeatureExtractor(),
		NewVolumeFeatureExtractor(),
		NewGeographicFeatureExtractor(),
	}

	return manager
}

// ExtractFeatures extracts all features from an event using all registered extractors
func (m *FeatureExtractorManager) ExtractFeatures(ctx context.Context, event *core.Event) (*FeatureVector, error) {
	if event == nil {
		return nil, fmt.Errorf("event cannot be nil")
	}

	// Check cache first
	if m.cache != nil {
		if cached, err := m.cache.Get(ctx, event.EventID); err == nil && cached != nil {
			m.logger.Debugw("Feature cache hit", "event_id", event.EventID)
			return cached, nil
		}
	}

	features := make(map[string]float64)
	totalStart := time.Now()

	// Extract features concurrently using worker pool pattern
	type extractionResult struct {
		features map[string]float64
		err      error
		name     string
		duration time.Duration
	}

	results := make(chan extractionResult, len(m.extractors))
	var wg sync.WaitGroup

	// Limit concurrent goroutines to prevent resource exhaustion
	// Allow max 5 concurrent extractions
	semaphore := make(chan struct{}, 5)

	// Start concurrent extraction
	for _, extractor := range m.extractors {
		wg.Add(1)
		go func(ext FeatureExtractor) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }() // Release semaphore

			start := time.Now()

			extractorFeatures, err := ext.Extract(ctx, event)
			duration := time.Since(start)

			results <- extractionResult{
				features: extractorFeatures,
				err:      err,
				name:     ext.Name(),
				duration: duration,
			}
		}(extractor)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for result := range results {
		if result.err != nil {
			m.logger.Errorw("Feature extraction failed",
				"extractor", result.name,
				"event_id", event.EventID,
				"error", result.err)
			continue // Continue with other extractors
		}

		// Merge features (later extractors can override earlier ones if needed)
		for key, value := range result.features {
			features[key] = value
		}

		if result.duration > 5*time.Millisecond {
			m.logger.Warnw("Feature extraction slow",
				"extractor", result.name,
				"duration_ms", result.duration.Milliseconds(),
				"event_id", event.EventID)
		}
	}

	totalDuration := time.Since(totalStart)
	if totalDuration > 50*time.Millisecond {
		m.logger.Warnw("Total feature extraction slow",
			"duration_ms", totalDuration.Milliseconds(),
			"event_id", event.EventID,
			"feature_count", len(features))
	}

	fv := &FeatureVector{
		EventID:   event.EventID,
		Timestamp: event.Timestamp,
		Features:  features,
	}

	// Cache the extracted features
	if m.cache != nil {
		if err := m.cache.Set(ctx, fv, time.Hour); err != nil {
			m.logger.Warnw("Failed to cache features", "event_id", event.EventID, "error", err)
		}
	}

	return fv, nil
}

// GetFeatureNames returns all feature names that can be extracted
func (m *FeatureExtractorManager) GetFeatureNames() []string {
	var names []string
	for _, extractor := range m.extractors {
		// This is a simplified approach - in practice, we'd need each extractor
		// to provide its feature names
		names = append(names, extractor.Name())
	}
	return names
}
