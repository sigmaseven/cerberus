package ml

import (
	"context"
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestFeatureExtractorManager_ExtractFeatures(t *testing.T) {
	logger := zap.NewNop().Sugar()
	manager := NewFeatureExtractorManager(&FeatureExtractorConfig{
		Logger: logger,
	})

	// Create a test event (Monday during business hours)
	event := &core.Event{
		EventID:   "test-event-123",
		Timestamp: time.Date(2023, 11, 6, 14, 30, 45, 0, time.UTC), // Monday 2:30 PM
		SourceIP:  "192.168.1.100",
		EventType: "user_login",
		Severity:  "info",
		Fields: map[string]interface{}{
			"destination_port": "443",
			"protocol":         "tcp",
			"connection_state": "established",
			"user_agent":       "Mozilla/5.0",
		},
	}

	ctx := context.Background()
	features, err := manager.ExtractFeatures(ctx, event)

	require.NoError(t, err)
	assert.NotNil(t, features)
	assert.Equal(t, "test-event-123", features.EventID)
	assert.Equal(t, event.Timestamp, features.Timestamp)
	assert.NotEmpty(t, features.Features)

	// Check that we have features from multiple extractors
	assert.Contains(t, features.Features, "hour_of_day")       // temporal
	assert.Contains(t, features.Features, "ip_is_private")     // network
	assert.Contains(t, features.Features, "message_length")    // content
	assert.Contains(t, features.Features, "event_data_fields") // volume

	// Verify temporal features
	assert.Equal(t, float64(14), features.Features["hour_of_day"])      // 2 PM
	assert.Equal(t, float64(1), features.Features["day_of_week"])       // Monday = 1
	assert.Equal(t, float64(1), features.Features["is_business_hours"]) // 14:30 is business hours (Mon-Fri 9-17)

	// Verify network features
	assert.Equal(t, float64(1), features.Features["ip_is_private"]) // 192.168.1.100 is private
	assert.Equal(t, float64(4), features.Features["ip_version"])    // IPv4
	assert.Equal(t, float64(443), features.Features["destination_port"])
}

func TestFeatureExtractorManager_ExtractFeatures_NilEvent(t *testing.T) {
	logger := zap.NewNop().Sugar()
	manager := NewFeatureExtractorManager(&FeatureExtractorConfig{
		Logger: logger,
	})

	ctx := context.Background()
	features, err := manager.ExtractFeatures(ctx, nil)

	assert.Error(t, err)
	assert.Nil(t, features)
	assert.Contains(t, err.Error(), "event cannot be nil")
}

func TestFeatureExtractorManager_GetFeatureNames(t *testing.T) {
	logger := zap.NewNop().Sugar()
	manager := NewFeatureExtractorManager(&FeatureExtractorConfig{
		Logger: logger,
	})

	names := manager.GetFeatureNames()
	assert.NotEmpty(t, names)
	assert.Contains(t, names, "temporal")
	assert.Contains(t, names, "network")
}

func TestTemporalFeatureExtractor_Extract(t *testing.T) {
	extractor := NewTemporalFeatureExtractor()

	// Test with Monday 9 AM
	event := &core.Event{
		Timestamp: time.Date(2023, 11, 6, 9, 15, 30, 0, time.UTC), // Monday
	}

	ctx := context.Background()
	features, err := extractor.Extract(ctx, event)

	require.NoError(t, err)
	assert.NotEmpty(t, features)

	// Verify temporal features
	assert.Equal(t, float64(9), features["hour_of_day"])
	assert.Equal(t, float64(1), features["day_of_week"]) // Monday = 1
	assert.Equal(t, float64(1), features["is_business_hours"])
	assert.Equal(t, float64(0), features["is_weekend"])
	assert.Equal(t, float64(11), features["month"])
	assert.Equal(t, float64(4), features["quarter"]) // Q4
	assert.Equal(t, float64(1), features["is_holiday_season"])
	assert.Equal(t, float64(15), features["minute_of_hour"])
	assert.Equal(t, float64(30), features["second_of_minute"])
	assert.Equal(t, float64(0), features["time_of_day_category"]) // morning
	assert.Equal(t, float64(6), features["day_of_month"])
	assert.Equal(t, float64(45), features["week_of_year"])
}

func TestNetworkFeatureExtractor_Extract(t *testing.T) {
	extractor := NewNetworkFeatureExtractor()

	tests := []struct {
		name     string
		sourceIP string
		fields   map[string]interface{}
		expected map[string]float64
	}{
		{
			name:     "private IPv4 with port",
			sourceIP: "192.168.1.100",
			fields: map[string]interface{}{
				"destination_port": "443",
				"protocol":         "tcp",
				"connection_state": "established",
			},
			expected: map[string]float64{
				"ip_is_private":      1.0,
				"ip_is_loopback":     0.0,
				"ip_version":         4.0,
				"ip_octet_1":         192.0,
				"ip_octet_2":         168.0,
				"ip_octet_3":         1.0,
				"ip_octet_4":         100.0,
				"destination_port":   443.0,
				"port_is_well_known": 1.0,
				"protocol_tcp":       1.0,
				"conn_established":   1.0,
			},
		},
		{
			name:     "public IPv4",
			sourceIP: "8.8.8.8",
			fields:   map[string]interface{}{},
			expected: map[string]float64{
				"ip_is_private":  0.0,
				"ip_is_loopback": 0.0,
				"ip_version":     4.0,
				"ip_octet_1":     8.0,
				"ip_octet_2":     8.0,
				"ip_octet_3":     8.0,
				"ip_octet_4":     8.0,
			},
		},
		{
			name:     "invalid IP",
			sourceIP: "invalid.ip",
			fields:   map[string]interface{}{},
			expected: map[string]float64{
				"ip_is_private":  0.0,
				"ip_is_loopback": 0.0,
				"ip_version":     0.0,
				"ip_octet_1":     0.0,
				"ip_octet_2":     0.0,
				"ip_octet_3":     0.0,
				"ip_octet_4":     0.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &core.Event{
				SourceIP: tt.sourceIP,
				Fields:   tt.fields,
			}

			ctx := context.Background()
			features, err := extractor.Extract(ctx, event)

			require.NoError(t, err)
			for key, expectedValue := range tt.expected {
				assert.Equal(t, expectedValue, features[key], "feature %s", key)
			}
		})
	}
}

func TestZScoreNormalizer(t *testing.T) {
	logger := zap.NewNop().Sugar()
	normalizer := NewZScoreNormalizer(logger)

	// Test with insufficient data
	normalized := normalizer.Normalize("test_feature", 5.0)
	assert.Equal(t, 5.0, normalized) // Should return original value

	// Add some training data
	normalizer.UpdateStats("test_feature", 10.0)
	normalizer.UpdateStats("test_feature", 20.0)
	normalizer.UpdateStats("test_feature", 30.0)

	// Test normalization
	normalized = normalizer.Normalize("test_feature", 20.0) // mean = 20
	assert.InDelta(t, 0.0, normalized, 0.01)                // Should be 0 (mean)

	normalized = normalizer.Normalize("test_feature", 30.0) // +1 stddev
	assert.InDelta(t, 1.0, normalized, 0.01)

	normalized = normalizer.Normalize("test_feature", 10.0) // -1 stddev
	assert.InDelta(t, -1.0, normalized, 0.01)

	// Test outlier clamping
	normalized = normalizer.Normalize("test_feature", 120.0) // Way above
	assert.InDelta(t, 10.0, normalized, 0.01)                // Should be clamped to 10

	// Test stats
	mean, stddev, min, max, count := normalizer.GetStats("test_feature")
	assert.Equal(t, 20.0, mean)
	assert.InDelta(t, 10.0, stddev, 0.01)
	assert.Equal(t, 10.0, min)
	assert.Equal(t, 30.0, max)
	assert.Equal(t, int64(3), count)
}

func TestMinMaxNormalizer(t *testing.T) {
	logger := zap.NewNop().Sugar()
	normalizer := NewMinMaxNormalizer(logger)

	// Add training data
	normalizer.UpdateStats("test_feature", 10.0)
	normalizer.UpdateStats("test_feature", 20.0)
	normalizer.UpdateStats("test_feature", 30.0)

	// Test normalization
	normalized := normalizer.Normalize("test_feature", 10.0) // min
	assert.Equal(t, 0.0, normalized)

	normalized = normalizer.Normalize("test_feature", 20.0) // midpoint
	assert.Equal(t, 0.5, normalized)

	normalized = normalizer.Normalize("test_feature", 30.0) // max
	assert.Equal(t, 1.0, normalized)

	normalized = normalizer.Normalize("test_feature", 40.0) // above max
	assert.Equal(t, 1.0, normalized)                        // clamped

	normalized = normalizer.Normalize("test_feature", 5.0) // below min
	assert.Equal(t, 0.0, normalized)                       // clamped

	// Test stats
	_, _, min, max, count := normalizer.GetStats("test_feature")
	assert.Equal(t, 10.0, min)
	assert.Equal(t, 30.0, max)
	assert.Equal(t, int64(3), count)
}

func TestRobustNormalizer(t *testing.T) {
	logger := zap.NewNop().Sugar()
	normalizer := NewRobustNormalizer(logger)

	// Add training data with outliers
	values := []float64{1, 2, 3, 4, 5, 100} // 100 is outlier
	for _, v := range values {
		normalizer.UpdateStats("test_feature", v)
	}

	// Test normalization (should be robust to outlier)
	normalized := normalizer.Normalize("test_feature", 3.0) // median-ish
	assert.NotEqual(t, 0.0, normalized)                     // Should be normalized

	// Test with insufficient data
	normalizer2 := NewRobustNormalizer(logger)
	normalizer2.UpdateStats("test_feature", 5.0) // Only 1 value

	normalized = normalizer2.Normalize("test_feature", 5.0)
	assert.Equal(t, 5.0, normalized) // Should return original
}

func TestMemoryFeatureCache(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cache := NewMemoryFeatureCache(logger)

	ctx := context.Background()
	features := &FeatureVector{
		EventID:   "test-event",
		Timestamp: time.Now(),
		Features: map[string]float64{
			"test_feature": 1.0,
		},
	}

	ttl := 1 * time.Hour

	// Test Set and Get
	err := cache.Set(ctx, features, ttl)
	require.NoError(t, err)

	retrieved, err := cache.Get(ctx, "test-event")
	require.NoError(t, err)
	assert.Equal(t, features.EventID, retrieved.EventID)
	assert.Equal(t, features.Features["test_feature"], retrieved.Features["test_feature"])

	// Test Exists
	exists, err := cache.Exists(ctx, "test-event")
	require.NoError(t, err)
	assert.True(t, exists)

	// Test non-existent key
	_, err = cache.Get(ctx, "non-existent")
	assert.Error(t, err)

	exists, err = cache.Exists(ctx, "non-existent")
	require.NoError(t, err)
	assert.False(t, exists)

	// Test Delete
	err = cache.Delete(ctx, "test-event")
	require.NoError(t, err)

	exists, err = cache.Exists(ctx, "test-event")
	require.NoError(t, err)
	assert.False(t, exists)

	// Test Clear
	err = cache.Set(ctx, features, ttl)
	require.NoError(t, err)

	err = cache.Clear(ctx)
	require.NoError(t, err)

	stats := cache.GetStats()
	assert.Equal(t, int64(0), stats.TotalEntries)
}

func TestFeatureNormalizerManager(t *testing.T) {
	logger := zap.NewNop().Sugar()
	manager := NewFeatureNormalizerManager(logger)

	// Test normalization with different types
	manager.UpdateNormalizerStats("test_feature", 10.0)
	manager.UpdateNormalizerStats("test_feature", 20.0)
	manager.UpdateNormalizerStats("test_feature", 30.0)

	// Test Z-score normalization
	zscore := manager.NormalizeFeature("zscore", "test_feature", 20.0)
	assert.InDelta(t, 0.0, zscore, 0.01)

	// Test min-max normalization
	minmax := manager.NormalizeFeature("minmax", "test_feature", 20.0)
	assert.Equal(t, 0.5, minmax)

	// Test robust normalization
	robust := manager.NormalizeFeature("robust", "test_feature", 20.0)
	assert.NotEqual(t, 0.0, robust)

	// Test invalid normalizer
	invalid := manager.NormalizeFeature("invalid", "test_feature", 20.0)
	assert.Equal(t, 20.0, invalid) // Should return original value

	// Test stats
	_, _, _, _, count, err := manager.GetNormalizerStats("zscore", "test_feature")
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func BenchmarkFeatureExtractorManager_ExtractFeatures(b *testing.B) {
	logger := zap.NewNop().Sugar()
	manager := NewFeatureExtractorManager(&FeatureExtractorConfig{
		Logger: logger,
	})

	event := &core.Event{
		EventID:   "bench-event",
		Timestamp: time.Now(),
		SourceIP:  "192.168.1.100",
		EventType: "user_login",
		Fields: map[string]interface{}{
			"destination_port": "443",
			"protocol":         "tcp",
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.ExtractFeatures(ctx, event)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkZScoreNormalizer_Normalize(b *testing.B) {
	logger := zap.NewNop().Sugar()
	normalizer := NewZScoreNormalizer(logger)

	// Pre-populate with training data
	for i := 0; i < 1000; i++ {
		normalizer.UpdateStats("bench_feature", float64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizer.Normalize("bench_feature", 500.0)
	}
}
