package ml

import (
	"context"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 59.3: Temporal Feature Extractor Tests
// Tests cover: time-of-day, day-of-week, time series, frequency analysis

// TestTemporalFeatureExtractor_WeekendDetection tests weekend detection
func TestTemporalFeatureExtractor_WeekendDetection(t *testing.T) {
	extractor := NewTemporalFeatureExtractor()

	testCases := []struct {
		name            string
		timestamp       time.Time
		expectedWeekend float64
	}{
		{"Saturday", time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC), 1.0}, // Saturday
		{"Sunday", time.Date(2024, 6, 16, 12, 0, 0, 0, time.UTC), 1.0},   // Sunday
		{"Monday", time.Date(2024, 6, 10, 12, 0, 0, 0, time.UTC), 0.0},   // Monday
		{"Friday", time.Date(2024, 6, 14, 12, 0, 0, 0, time.UTC), 0.0},   // Friday
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := &core.Event{
				EventID:   "test-event",
				Timestamp: tc.timestamp,
				RawData:   "test",
				Fields:    make(map[string]interface{}),
			}

			features, err := extractor.Extract(context.Background(), event)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedWeekend, features["is_weekend"], "Weekend detection should match")
		})
	}
}

// TestTemporalFeatureExtractor_BusinessHours tests business hours detection
func TestTemporalFeatureExtractor_BusinessHours(t *testing.T) {
	extractor := NewTemporalFeatureExtractor()

	testCases := []struct {
		name                  string
		timestamp             time.Time
		expectedBusinessHours float64
	}{
		{"Weekday 9 AM", time.Date(2024, 6, 10, 9, 0, 0, 0, time.UTC), 1.0},   // Monday 9 AM
		{"Weekday 5 PM", time.Date(2024, 6, 10, 17, 0, 0, 0, time.UTC), 1.0},  // Monday 5 PM
		{"Weekday 8 AM", time.Date(2024, 6, 10, 8, 0, 0, 0, time.UTC), 0.0},   // Monday 8 AM (before 9)
		{"Weekday 6 PM", time.Date(2024, 6, 10, 18, 0, 0, 0, time.UTC), 0.0},  // Monday 6 PM (after 5)
		{"Saturday 2 PM", time.Date(2024, 6, 15, 14, 0, 0, 0, time.UTC), 0.0}, // Saturday 2 PM (weekend)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := &core.Event{
				EventID:   "test-event",
				Timestamp: tc.timestamp,
				RawData:   "test",
				Fields:    make(map[string]interface{}),
			}

			features, err := extractor.Extract(context.Background(), event)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedBusinessHours, features["is_business_hours"], "Business hours detection should match")
		})
	}
}

// TestTemporalFeatureExtractor_QuarterExtraction tests quarter extraction
func TestTemporalFeatureExtractor_QuarterExtraction(t *testing.T) {
	extractor := NewTemporalFeatureExtractor()

	testCases := []struct {
		name            string
		timestamp       time.Time
		expectedQuarter float64
	}{
		{"Q1", time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC), 1.0},  // January (Q1)
		{"Q2", time.Date(2024, 4, 15, 12, 0, 0, 0, time.UTC), 2.0},  // April (Q2)
		{"Q3", time.Date(2024, 7, 15, 12, 0, 0, 0, time.UTC), 3.0},  // July (Q3)
		{"Q4", time.Date(2024, 10, 15, 12, 0, 0, 0, time.UTC), 4.0}, // October (Q4)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := &core.Event{
				EventID:   "test-event",
				Timestamp: tc.timestamp,
				RawData:   "test",
				Fields:    make(map[string]interface{}),
			}

			features, err := extractor.Extract(context.Background(), event)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedQuarter, features["quarter"], "Quarter should match")
		})
	}
}

// TestTemporalFeatureExtractor_HolidaySeason tests holiday season detection
func TestTemporalFeatureExtractor_HolidaySeason(t *testing.T) {
	extractor := NewTemporalFeatureExtractor()

	testCases := []struct {
		name                  string
		timestamp             time.Time
		expectedHolidaySeason float64
	}{
		{"November", time.Date(2024, 11, 15, 12, 0, 0, 0, time.UTC), 1.0}, // November (holiday season)
		{"December", time.Date(2024, 12, 15, 12, 0, 0, 0, time.UTC), 1.0}, // December (holiday season)
		{"October", time.Date(2024, 10, 15, 12, 0, 0, 0, time.UTC), 0.0},  // October (not holiday season)
		{"January", time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC), 0.0},   // January (not holiday season)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := &core.Event{
				EventID:   "test-event",
				Timestamp: tc.timestamp,
				RawData:   "test",
				Fields:    make(map[string]interface{}),
			}

			features, err := extractor.Extract(context.Background(), event)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedHolidaySeason, features["is_holiday_season"], "Holiday season detection should match")
		})
	}
}

// TestTemporalFeatureExtractor_PeakHours tests peak hours detection
func TestTemporalFeatureExtractor_PeakHours(t *testing.T) {
	extractor := NewTemporalFeatureExtractor()

	testCases := []struct {
		name         string
		timestamp    time.Time
		expectedPeak float64
	}{
		{"Morning peak", time.Date(2024, 6, 10, 9, 0, 0, 0, time.UTC), 1.0},    // 9 AM (8-10 peak)
		{"Afternoon peak", time.Date(2024, 6, 10, 17, 0, 0, 0, time.UTC), 1.0}, // 5 PM (16-18 peak)
		{"Midday", time.Date(2024, 6, 10, 12, 0, 0, 0, time.UTC), 0.0},         // 12 PM (not peak)
		{"Late night", time.Date(2024, 6, 10, 2, 0, 0, 0, time.UTC), 0.0},      // 2 AM (not peak)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := &core.Event{
				EventID:   "test-event",
				Timestamp: tc.timestamp,
				RawData:   "test",
				Fields:    make(map[string]interface{}),
			}

			features, err := extractor.Extract(context.Background(), event)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedPeak, features["is_peak_hours"], "Peak hours detection should match")
		})
	}
}
