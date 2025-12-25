// Package api provides comprehensive tests for feed summary handlers.
// TASK 157.1: Tests GET /api/v1/feeds/summary endpoint.
package api

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/sigma/feeds"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// createTestAPI creates a test API instance with necessary dependencies.
// PRODUCTION: Provides consistent API initialization for all tests.
func createTestAPI(feedManager FeedManagerInterface, logger *zap.SugaredLogger, cfg *config.Config) *API {
	return &API{
		feedManager: feedManager,
		logger:      logger,
		config:      cfg,
		router:      mux.NewRouter(),
	}
}

// respondJSON helper is added to the main api.go file

// TestGetFeedsSummarySuccess tests successful retrieval of feed summary statistics.
// PRODUCTION: Verifies correct aggregation of feeds with various states and stats.
func TestGetFeedsSummarySuccess(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}

	// Create test feeds with varying states
	now := time.Now()
	lastSync1 := now.Add(-1 * time.Hour)
	lastSync2 := now.Add(-30 * time.Minute) // Most recent
	lastSync3 := now.Add(-2 * time.Hour)

	testFeeds := []*feeds.RuleFeed{
		{
			ID:      "feed-1",
			Name:    "Active Feed 1",
			Enabled: true,
			Stats: feeds.FeedStats{
				TotalRules: 150,
			},
			LastSync: lastSync1,
		},
		{
			ID:      "feed-2",
			Name:    "Active Feed 2",
			Enabled: true,
			Stats: feeds.FeedStats{
				TotalRules: 200,
			},
			LastSync: lastSync2, // Most recent sync
		},
		{
			ID:      "feed-3",
			Name:    "Disabled Feed",
			Enabled: false,
			Stats: feeds.FeedStats{
				TotalRules: 50,
			},
			LastSync: lastSync3,
		},
		{
			ID:      "feed-4",
			Name:    "Error Feed",
			Enabled: true,
			Stats: feeds.FeedStats{
				TotalRules: 100,
			},
			LastSync: now,
		},
	}

	healthMap := map[string]string{
		"feed-1": "healthy",
		"feed-2": "healthy",
		"feed-3": "disabled",
		"feed-4": "error", // Has error
	}

	mockFeedManager := &MockFeedManager{
		ListFeedsFunc: func(ctx context.Context) ([]*feeds.RuleFeed, error) {
			return testFeeds, nil
		},
		GetFeedHealthFunc: func(ctx context.Context) (map[string]string, error) {
			return healthMap, nil
		},
	}

	api := createTestAPI(mockFeedManager, logger, cfg)

	// Create test request
	req := httptest.NewRequest("GET", "/api/v1/feeds/summary", nil)
	w := httptest.NewRecorder()

	// Execute handler
	api.getFeedsSummary(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code, "Expected 200 OK")

	var response FeedsSummaryResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err, "Response should be valid JSON")

	// Verify statistics
	assert.Equal(t, 4, response.TotalFeeds, "Should count all feeds")
	assert.Equal(t, 3, response.ActiveFeeds, "Should count only enabled feeds")
	assert.Equal(t, 500, response.TotalRules, "Should sum all rules (150+200+50+100)")
	assert.Equal(t, "error", response.HealthStatus, "Overall health should be 'error' when any feed has error")
	assert.Equal(t, 1, response.ErrorCount, "Should count 1 feed with error status")

	// Verify most recent sync time (feed-4 has LastSync: now, which is the most recent)
	require.NotNil(t, response.LastSync, "LastSync should not be nil when feeds have synced")
	// Use Unix timestamps for comparison to avoid precision issues
	// Feed-4 has now as LastSync, which is the most recent
	assert.Equal(t, now.Unix(), response.LastSync.Unix(), "LastSync should be the most recent sync time")
}

// TestGetFeedsSummaryEmptyFeeds tests summary with no feeds configured.
// PRODUCTION: Ensures proper handling of zero-state scenarios.
func TestGetFeedsSummaryEmptyFeeds(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}

	mockFeedManager := &MockFeedManager{
		ListFeedsFunc: func(ctx context.Context) ([]*feeds.RuleFeed, error) {
			return []*feeds.RuleFeed{}, nil
		},
		GetFeedHealthFunc: func(ctx context.Context) (map[string]string, error) {
			return map[string]string{}, nil
		},
	}

	api := createTestAPI(mockFeedManager, logger, cfg)

	req := httptest.NewRequest("GET", "/api/v1/feeds/summary", nil)
	w := httptest.NewRecorder()

	api.getFeedsSummary(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 even with no feeds")

	var response FeedsSummaryResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err, "Response should be valid JSON")

	// Verify zero state
	assert.Equal(t, 0, response.TotalFeeds, "Should have 0 total feeds")
	assert.Equal(t, 0, response.ActiveFeeds, "Should have 0 active feeds")
	assert.Equal(t, 0, response.TotalRules, "Should have 0 total rules")
	assert.Nil(t, response.LastSync, "LastSync should be nil when no feeds have synced")
	assert.Equal(t, "healthy", response.HealthStatus, "Default health should be 'healthy'")
	assert.Equal(t, 0, response.ErrorCount, "Should have 0 errors")
}

// TestGetFeedsSummaryWithWarning tests summary with warning-level health issues.
// PRODUCTION: Verifies health status escalation logic.
func TestGetFeedsSummaryWithWarning(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}

	testFeeds := []*feeds.RuleFeed{
		{
			ID:      "feed-1",
			Name:    "Healthy Feed",
			Enabled: true,
			Stats: feeds.FeedStats{
				TotalRules: 100,
			},
		},
		{
			ID:      "feed-2",
			Name:    "Warning Feed",
			Enabled: true,
			Stats: feeds.FeedStats{
				TotalRules: 50,
			},
		},
	}

	healthMap := map[string]string{
		"feed-1": "healthy",
		"feed-2": "warning", // Has warning but no error
	}

	mockFeedManager := &MockFeedManager{
		ListFeedsFunc: func(ctx context.Context) ([]*feeds.RuleFeed, error) {
			return testFeeds, nil
		},
		GetFeedHealthFunc: func(ctx context.Context) (map[string]string, error) {
			return healthMap, nil
		},
	}

	api := createTestAPI(mockFeedManager, logger, cfg)

	req := httptest.NewRequest("GET", "/api/v1/feeds/summary", nil)
	w := httptest.NewRecorder()

	api.getFeedsSummary(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected 200 OK")

	var response FeedsSummaryResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err, "Response should be valid JSON")

	assert.Equal(t, "warning", response.HealthStatus, "Overall health should be 'warning' when any feed has warning")
	assert.Equal(t, 0, response.ErrorCount, "Should have 0 errors (warning is not an error)")
}

// TestGetFeedsSummaryNoSync tests summary when no feeds have synced.
// PRODUCTION: Ensures null handling for last_sync field.
func TestGetFeedsSummaryNoSync(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}

	testFeeds := []*feeds.RuleFeed{
		{
			ID:       "feed-1",
			Name:     "Never Synced",
			Enabled:  true,
			LastSync: time.Time{}, // Zero time (never synced)
			Stats: feeds.FeedStats{
				TotalRules: 0,
			},
		},
	}

	healthMap := map[string]string{
		"feed-1": "healthy",
	}

	mockFeedManager := &MockFeedManager{
		ListFeedsFunc: func(ctx context.Context) ([]*feeds.RuleFeed, error) {
			return testFeeds, nil
		},
		GetFeedHealthFunc: func(ctx context.Context) (map[string]string, error) {
			return healthMap, nil
		},
	}

	api := createTestAPI(mockFeedManager, logger, cfg)

	req := httptest.NewRequest("GET", "/api/v1/feeds/summary", nil)
	w := httptest.NewRecorder()

	api.getFeedsSummary(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected 200 OK")

	var response FeedsSummaryResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err, "Response should be valid JSON")

	assert.Nil(t, response.LastSync, "LastSync should be nil when no feeds have synced")
}

// TestGetFeedsSummaryFeedManagerUnavailable tests error when feed manager is nil.
// SECURITY: Ensures proper error handling when feed manager is not initialized.
func TestGetFeedsSummaryFeedManagerUnavailable(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}

	api := &API{
		feedManager: nil, // Feed manager not available
		logger:      logger,
		config:      cfg,
		router:      mux.NewRouter(),
	}

	req := httptest.NewRequest("GET", "/api/v1/feeds/summary", nil)
	w := httptest.NewRecorder()

	api.getFeedsSummary(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Should return 503 when feed manager unavailable")

	// writeError returns plain text, not JSON
	responseBody := w.Body.String()
	assert.Contains(t, responseBody, "Feed manager not available", "Error message should indicate unavailable service")
}

// TestGetFeedsSummaryListFeedsError tests error handling when ListFeeds fails.
// PRODUCTION: Verifies graceful degradation on storage errors.
func TestGetFeedsSummaryListFeedsError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}

	mockFeedManager := &MockFeedManager{
		ListFeedsFunc: func(ctx context.Context) ([]*feeds.RuleFeed, error) {
			return nil, assert.AnError // Inject error
		},
	}

	api := createTestAPI(mockFeedManager, logger, cfg)

	req := httptest.NewRequest("GET", "/api/v1/feeds/summary", nil)
	w := httptest.NewRecorder()

	api.getFeedsSummary(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "Should return 500 on storage error")

	// writeError returns plain text, not JSON
	responseBody := w.Body.String()
	assert.Contains(t, responseBody, "Failed to list feeds", "Error message should indicate list failure")
}

// TestGetFeedsSummaryHealthError tests error handling when GetFeedHealth fails.
// PRODUCTION: Ensures proper error propagation from health check failures.
func TestGetFeedsSummaryHealthError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}

	testFeeds := []*feeds.RuleFeed{
		{
			ID:      "feed-1",
			Name:    "Test Feed",
			Enabled: true,
		},
	}

	mockFeedManager := &MockFeedManager{
		ListFeedsFunc: func(ctx context.Context) ([]*feeds.RuleFeed, error) {
			return testFeeds, nil
		},
		GetFeedHealthFunc: func(ctx context.Context) (map[string]string, error) {
			return nil, assert.AnError // Inject health check error
		},
	}

	api := createTestAPI(mockFeedManager, logger, cfg)

	req := httptest.NewRequest("GET", "/api/v1/feeds/summary", nil)
	w := httptest.NewRecorder()

	api.getFeedsSummary(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "Should return 500 on health check error")

	// writeError returns plain text, not JSON
	responseBody := w.Body.String()
	assert.Contains(t, responseBody, "Failed to get feed health", "Error message should indicate health check failure")
}

// TestCalculateFeedsSummaryLogic tests the summary calculation logic directly.
// PRODUCTION: Unit tests for pure calculation function without HTTP overhead.
func TestCalculateFeedsSummaryLogic(t *testing.T) {
	tests := []struct {
		name              string
		feeds             []*feeds.RuleFeed
		healthMap         map[string]string
		expectedTotal     int
		expectedActive    int
		expectedRules     int
		expectedHealth    string
		expectedErrors    int
		expectedSyncIsNil bool
	}{
		{
			name: "All healthy feeds",
			feeds: []*feeds.RuleFeed{
				{ID: "f1", Enabled: true, Stats: feeds.FeedStats{TotalRules: 100}, LastSync: time.Now()},
				{ID: "f2", Enabled: true, Stats: feeds.FeedStats{TotalRules: 200}, LastSync: time.Now()},
			},
			healthMap: map[string]string{
				"f1": "healthy",
				"f2": "healthy",
			},
			expectedTotal:     2,
			expectedActive:    2,
			expectedRules:     300,
			expectedHealth:    "healthy",
			expectedErrors:    0,
			expectedSyncIsNil: false,
		},
		{
			name: "Mixed health states",
			feeds: []*feeds.RuleFeed{
				{ID: "f1", Enabled: true, Stats: feeds.FeedStats{TotalRules: 100}},
				{ID: "f2", Enabled: true, Stats: feeds.FeedStats{TotalRules: 50}},
				{ID: "f3", Enabled: false, Stats: feeds.FeedStats{TotalRules: 25}},
			},
			healthMap: map[string]string{
				"f1": "healthy",
				"f2": "warning",
				"f3": "disabled",
			},
			expectedTotal:     3,
			expectedActive:    2,
			expectedRules:     175,
			expectedHealth:    "warning",
			expectedErrors:    0,
			expectedSyncIsNil: true, // No syncs
		},
		{
			name: "Feeds with errors",
			feeds: []*feeds.RuleFeed{
				{ID: "f1", Enabled: true, Stats: feeds.FeedStats{TotalRules: 100}},
				{ID: "f2", Enabled: true, Stats: feeds.FeedStats{TotalRules: 50}},
			},
			healthMap: map[string]string{
				"f1": "error",
				"f2": "error",
			},
			expectedTotal:     2,
			expectedActive:    2,
			expectedRules:     150,
			expectedHealth:    "error",
			expectedErrors:    2,
			expectedSyncIsNil: true,
		},
		{
			name:              "No feeds",
			feeds:             []*feeds.RuleFeed{},
			healthMap:         map[string]string{},
			expectedTotal:     0,
			expectedActive:    0,
			expectedRules:     0,
			expectedHealth:    "healthy",
			expectedErrors:    0,
			expectedSyncIsNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateFeedsSummary(tt.feeds, tt.healthMap)

			assert.Equal(t, tt.expectedTotal, result.TotalFeeds, "Total feeds mismatch")
			assert.Equal(t, tt.expectedActive, result.ActiveFeeds, "Active feeds mismatch")
			assert.Equal(t, tt.expectedRules, result.TotalRules, "Total rules mismatch")
			assert.Equal(t, tt.expectedHealth, result.HealthStatus, "Health status mismatch")
			assert.Equal(t, tt.expectedErrors, result.ErrorCount, "Error count mismatch")

			if tt.expectedSyncIsNil {
				assert.Nil(t, result.LastSync, "LastSync should be nil")
			} else {
				assert.NotNil(t, result.LastSync, "LastSync should not be nil")
			}
		})
	}
}

// TestCalculateFeedsSummaryMostRecentSync verifies correct selection of most recent sync time.
// PRODUCTION: Edge case testing for timestamp comparison logic.
func TestCalculateFeedsSummaryMostRecentSync(t *testing.T) {
	now := time.Now()
	old := now.Add(-1 * time.Hour)
	older := now.Add(-2 * time.Hour)

	feeds := []*feeds.RuleFeed{
		{ID: "f1", Enabled: true, LastSync: older},
		{ID: "f2", Enabled: true, LastSync: now}, // Most recent
		{ID: "f3", Enabled: true, LastSync: old},
	}

	healthMap := map[string]string{
		"f1": "healthy",
		"f2": "healthy",
		"f3": "healthy",
	}

	result := calculateFeedsSummary(feeds, healthMap)

	require.NotNil(t, result.LastSync, "LastSync should not be nil")
	// Use Unix timestamps for comparison to avoid precision issues
	assert.Equal(t, now.Unix(), result.LastSync.Unix(), "LastSync should be the most recent sync time")
}

// TestCalculateFeedsSummaryIntegerOverflow verifies that integer overflow is handled correctly
// and that health/sync data is STILL processed when overflow occurs.
// GATEKEEPER FIX #3: Critical test for data integrity during overflow scenario.
func TestCalculateFeedsSummaryIntegerOverflow(t *testing.T) {
	now := time.Now()

	// Create feeds where TotalRules would overflow if summed naively
	feedsWithOverflow := []*feeds.RuleFeed{
		{
			ID:       "overflow-feed-1",
			Enabled:  true,
			LastSync: now.Add(-1 * time.Hour),
			Stats: feeds.FeedStats{
				TotalRules: math.MaxInt - 10, // Near max
			},
		},
		{
			ID:       "overflow-feed-2",
			Enabled:  true,
			LastSync: now, // Most recent - MUST be captured despite overflow
			Stats: feeds.FeedStats{
				TotalRules: 100, // This would cause overflow
			},
		},
		{
			ID:       "overflow-feed-3",
			Enabled:  false, // Disabled
			LastSync: now.Add(-2 * time.Hour),
			Stats: feeds.FeedStats{
				TotalRules: 50,
			},
		},
	}

	healthMap := map[string]string{
		"overflow-feed-1": "healthy",
		"overflow-feed-2": "error",    // MUST be counted despite overflow
		"overflow-feed-3": "disabled",
	}

	result := calculateFeedsSummary(feedsWithOverflow, healthMap)

	// Verify overflow is capped correctly
	assert.Equal(t, math.MaxInt, result.TotalRules, "TotalRules should be capped at MaxInt on overflow")

	// CRITICAL: Verify health/sync data was STILL processed after overflow
	assert.Equal(t, 3, result.TotalFeeds, "All feeds should be counted even with overflow")
	assert.Equal(t, 2, result.ActiveFeeds, "Active feeds should be counted even with overflow")
	assert.Equal(t, "error", result.HealthStatus, "Health status MUST be 'error' - processing must continue after overflow")
	assert.Equal(t, 1, result.ErrorCount, "Error count MUST be 1 - feed-2 has error status")

	// Verify most recent sync time was captured
	require.NotNil(t, result.LastSync, "LastSync MUST be set even with overflow - sync processing must continue")
	assert.Equal(t, now.Unix(), result.LastSync.Unix(), "LastSync should be feed-2's sync time (most recent)")
}

// TestCalculateFeedsSummaryNilFeedInArray verifies that nil feeds in the array are skipped
// without affecting processing of other valid feeds.
// GATEKEEPER FIX #3: Critical test for nil pointer safety.
func TestCalculateFeedsSummaryNilFeedInArray(t *testing.T) {
	now := time.Now()

	// Create array with nil feeds in the middle
	feedsWithNil := []*feeds.RuleFeed{
		{
			ID:       "valid-feed-1",
			Enabled:  true,
			LastSync: now.Add(-1 * time.Hour),
			Stats: feeds.FeedStats{
				TotalRules: 100,
			},
		},
		nil, // Nil feed in the middle - should be safely skipped
		{
			ID:       "valid-feed-2",
			Enabled:  true,
			LastSync: now, // Most recent
			Stats: feeds.FeedStats{
				TotalRules: 200,
			},
		},
		nil, // Another nil feed
		{
			ID:       "valid-feed-3",
			Enabled:  false, // Disabled
			LastSync: now.Add(-2 * time.Hour),
			Stats: feeds.FeedStats{
				TotalRules: 50,
			},
		},
	}

	healthMap := map[string]string{
		"valid-feed-1": "healthy",
		"valid-feed-2": "warning",
		"valid-feed-3": "disabled",
	}

	result := calculateFeedsSummary(feedsWithNil, healthMap)

	// Verify only valid feeds are counted (array length includes nils, but only 3 are valid)
	assert.Equal(t, 5, result.TotalFeeds, "TotalFeeds uses len(allFeeds) which includes nils")
	assert.Equal(t, 2, result.ActiveFeeds, "Only 2 valid enabled feeds should be counted")
	assert.Equal(t, 350, result.TotalRules, "Rules from valid feeds: 100+200+50=350")
	assert.Equal(t, "warning", result.HealthStatus, "Health status should reflect valid feeds")
	assert.Equal(t, 0, result.ErrorCount, "No error feeds among valid feeds")

	// Verify most recent sync from valid feeds
	require.NotNil(t, result.LastSync, "LastSync should be set from valid feeds")
	assert.Equal(t, now.Unix(), result.LastSync.Unix(), "LastSync should be from valid-feed-2")
}

// TestCalculateFeedsSummaryNilFeedAtStart verifies nil at start of array is handled.
// SECURITY: Additional edge case for nil pointer handling.
func TestCalculateFeedsSummaryNilFeedAtStart(t *testing.T) {
	now := time.Now()

	feedsWithNilStart := []*feeds.RuleFeed{
		nil, // Nil at start
		{
			ID:       "valid-feed",
			Enabled:  true,
			LastSync: now,
			Stats: feeds.FeedStats{
				TotalRules: 100,
			},
		},
	}

	healthMap := map[string]string{
		"valid-feed": "healthy",
	}

	result := calculateFeedsSummary(feedsWithNilStart, healthMap)

	// Should not panic and should process valid feed correctly
	assert.Equal(t, 2, result.TotalFeeds, "TotalFeeds includes array length with nil")
	assert.Equal(t, 1, result.ActiveFeeds, "Only 1 valid enabled feed")
	assert.Equal(t, 100, result.TotalRules, "Rules from valid feed")
	assert.Equal(t, "healthy", result.HealthStatus, "Health should be healthy")
	require.NotNil(t, result.LastSync, "LastSync should be set")
}

// TestCalculateFeedsSummaryOnlyNilFeeds verifies handling when all feeds are nil.
// SECURITY: Edge case for completely nil array.
func TestCalculateFeedsSummaryOnlyNilFeeds(t *testing.T) {
	feedsAllNil := []*feeds.RuleFeed{
		nil,
		nil,
		nil,
	}

	healthMap := map[string]string{}

	result := calculateFeedsSummary(feedsAllNil, healthMap)

	// Should not panic and should return zero-state (except TotalFeeds which is array length)
	assert.Equal(t, 3, result.TotalFeeds, "TotalFeeds is array length")
	assert.Equal(t, 0, result.ActiveFeeds, "No valid feeds to count")
	assert.Equal(t, 0, result.TotalRules, "No rules to sum")
	assert.Equal(t, "healthy", result.HealthStatus, "Default health is healthy")
	assert.Nil(t, result.LastSync, "No sync times available")
}
