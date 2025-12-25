package ml

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TASK 59.5: Feature Cache Tests
// Tests cover: cache operations, TTL expiration, eviction, hit/miss metrics

// TestMemoryFeatureCache_GetSet tests cache get/set operations
func TestMemoryFeatureCache_GetSet(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cache := NewMemoryFeatureCacheWithLimit(logger, 100)

	features := &FeatureVector{
		EventID: "test-event-1",
		Features: map[string]float64{
			"feature1": 10.0,
			"feature2": 20.0,
		},
	}

	ctx := context.Background()

	// Set features
	err := cache.Set(ctx, features, 1*time.Hour)
	require.NoError(t, err, "Should set features in cache")

	// Get features
	retrieved, err := cache.Get(ctx, "test-event-1")
	require.NoError(t, err, "Should retrieve features from cache")
	assert.NotNil(t, retrieved, "Retrieved features should not be nil")
	assert.Equal(t, features.EventID, retrieved.EventID, "Event ID should match")
	assert.Equal(t, features.Features["feature1"], retrieved.Features["feature1"], "Feature1 should match")
	assert.Equal(t, features.Features["feature2"], retrieved.Features["feature2"], "Feature2 should match")
}

// TestMemoryFeatureCache_Miss tests cache miss handling
func TestMemoryFeatureCache_Miss(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cache := NewMemoryFeatureCacheWithLimit(logger, 100)

	ctx := context.Background()

	// Try to get non-existent features
	_, err := cache.Get(ctx, "non-existent-event")
	assert.Error(t, err, "Should return error for cache miss")
	assert.Contains(t, err.Error(), "not found", "Error should indicate not found")
}

// TestMemoryFeatureCache_TTLExpiration tests TTL expiration
func TestMemoryFeatureCache_TTLExpiration(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cache := NewMemoryFeatureCacheWithLimit(logger, 100)

	features := &FeatureVector{
		EventID: "test-event-1",
		Features: map[string]float64{
			"feature1": 10.0,
		},
	}

	ctx := context.Background()

	// Set features with short TTL
	err := cache.Set(ctx, features, 100*time.Millisecond)
	require.NoError(t, err, "Should set features")

	// Verify features are cached
	_, err = cache.Get(ctx, "test-event-1")
	require.NoError(t, err, "Features should be in cache")

	// Wait for TTL expiration
	time.Sleep(150 * time.Millisecond)

	// Features should be expired
	_, err = cache.Get(ctx, "test-event-1")
	assert.Error(t, err, "Features should be expired after TTL")
}

// TestMemoryFeatureCache_Stats tests cache statistics
func TestMemoryFeatureCache_Stats(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cache := NewMemoryFeatureCacheWithLimit(logger, 100)

	ctx := context.Background()

	// Set features
	features := &FeatureVector{
		EventID:  "test-event-1",
		Features: map[string]float64{"feature1": 10.0},
	}
	cache.Set(ctx, features, 1*time.Hour)

	// Get features (hit)
	_, err := cache.Get(ctx, "test-event-1")
	require.NoError(t, err)

	// Try to get non-existent (miss)
	_, err = cache.Get(ctx, "non-existent")
	assert.Error(t, err)

	// Get stats
	stats := cache.GetStats()
	assert.Greater(t, stats.Hits, int64(0), "Should have cache hits")
	assert.Greater(t, stats.Misses, int64(0), "Should have cache misses")
	assert.Greater(t, stats.HitRate, 0.0, "Hit rate should be positive")
	assert.LessOrEqual(t, stats.HitRate, 1.0, "Hit rate should be <= 1.0")
}

// TestMemoryFeatureCache_Eviction tests cache eviction
func TestMemoryFeatureCache_Eviction(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cache := NewMemoryFeatureCacheWithLimit(logger, 2) // Small limit for testing

	ctx := context.Background()

	// Add features up to limit
	for i := 0; i < 3; i++ {
		features := &FeatureVector{
			EventID:  "test-event-" + string(rune('1'+i)),
			Features: map[string]float64{"feature1": float64(i)},
		}
		err := cache.Set(ctx, features, 1*time.Hour)
		require.NoError(t, err)
	}

	// First event should be evicted (LRU)
	_, err := cache.Get(ctx, "test-event-1")
	assert.Error(t, err, "First event should be evicted")

	// Later events should still be in cache
	_, err = cache.Get(ctx, "test-event-3")
	assert.NoError(t, err, "Latest event should be in cache")
}
