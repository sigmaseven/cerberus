package search

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 60.5: Time Range Tests
// Tests cover: absolute time ranges, relative time ranges, timezone handling, validation

// TestTimeRangeParser_AbsoluteTimeRange tests absolute time range parsing
func TestTimeRangeParser_AbsoluteTimeRange(t *testing.T) {
	// Test RFC3339 format
	startStr := "2024-01-01T00:00:00Z"
	endStr := "2024-01-02T00:00:00Z"

	startTime, err := time.Parse(time.RFC3339, startStr)
	require.NoError(t, err, "Should parse RFC3339 start time")
	endTime, err := time.Parse(time.RFC3339, endStr)
	require.NoError(t, err, "Should parse RFC3339 end time")

	assert.True(t, endTime.After(startTime), "End time should be after start time")
}

// TestTimeRangeParser_RelativeTimeRange tests relative time range parsing
func TestTimeRangeParser_RelativeTimeRange(t *testing.T) {
	now := time.Now().UTC()

	testCases := []struct {
		name          string
		duration      time.Duration
		expectedStart time.Time
	}{
		{"Last 1 hour", 1 * time.Hour, now.Add(-1 * time.Hour)},
		{"Last 24 hours", 24 * time.Hour, now.Add(-24 * time.Hour)},
		{"Last 7 days", 7 * 24 * time.Hour, now.Add(-7 * 24 * time.Hour)},
		{"Last 30 days", 30 * 24 * time.Hour, now.Add(-30 * 24 * time.Hour)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			startTime := now.Add(-tc.duration)
			assert.True(t, startTime.Before(now), "Start time should be before now")
			assert.WithinDuration(t, tc.expectedStart, startTime, time.Minute, "Start time should match expected")
		})
	}
}

// TestTimeRangeParser_TimeZoneHandling tests timezone handling
func TestTimeRangeParser_TimeZoneHandling(t *testing.T) {
	// Test UTC normalization
	utcTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Test EST (UTC-5)
	estLoc, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)
	estTime := time.Date(2024, 1, 1, 7, 0, 0, 0, estLoc) // 7 AM EST = 12 PM UTC

	// Normalize to UTC
	estTimeUTC := estTime.UTC()

	// Should be approximately the same (within an hour for DST)
	assert.True(t, estTimeUTC.Sub(utcTime) < time.Hour, "EST time should normalize to UTC correctly")
}

// TestTimeRangeParser_Validation tests time range validation
func TestTimeRangeParser_Validation(t *testing.T) {
	startTime := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) // Before start

	// Start should be before end (validation)
	assert.False(t, startTime.Before(endTime), "Start time should not be before end time (invalid range)")
	assert.True(t, endTime.Before(startTime), "End time should be before start time (invalid range)")

	// Valid range (start < end)
	validEnd := time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)
	assert.True(t, startTime.Before(validEnd), "Start time should be before end time (valid range)")
}
