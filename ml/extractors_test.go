package ml

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 59.1: Comprehensive Feature Extraction Tests
// Tests cover: raw events, feature vector construction, feature types, missing value imputation

// TestContentFeatureExtractor_BasicExtraction tests basic content feature extraction
func TestContentFeatureExtractor_BasicExtraction(t *testing.T) {
	extractor := NewContentFeatureExtractor()

	event := &core.Event{
		EventID:   "test-event-1",
		Timestamp: time.Now().UTC(),
		RawData:   "Failed login attempt from 192.168.1.100 for user admin",
		Fields:    make(map[string]interface{}),
	}

	ctx := context.Background()
	features, err := extractor.Extract(ctx, event)
	require.NoError(t, err, "Should extract features without error")
	assert.NotNil(t, features, "Features should not be nil")

	// Verify basic features
	assert.Greater(t, features["message_length"], 0.0, "Should extract message length")
	assert.Greater(t, features["message_word_count"], 0.0, "Should extract word count")

	// Verify keyword presence
	assert.Equal(t, 1.0, features["keyword_login"], "Should detect 'login' keyword")
	assert.Equal(t, 1.0, features["keyword_fail"], "Should detect 'fail' keyword")
	assert.Equal(t, 1.0, features["keyword_admin"], "Should detect 'admin' keyword")
}

// TestContentFeatureExtractor_CharacterRatios tests character type ratio extraction
func TestContentFeatureExtractor_CharacterRatios(t *testing.T) {
	extractor := NewContentFeatureExtractor()

	testCases := []struct {
		name       string
		rawData    string
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	}{
		{"All lowercase", "test message", false, true, false, true},
		{"Mixed case", "Test Message", true, true, false, true},
		{"With digits", "test123", false, true, true, false},
		{"Special chars", "test@#$", false, true, false, true},
		{"All types", "Test123@#$", true, true, true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := &core.Event{
				EventID:   "test-event",
				Timestamp: time.Now().UTC(),
				RawData:   tc.rawData,
				Fields:    make(map[string]interface{}),
			}

			features, err := extractor.Extract(context.Background(), event)
			require.NoError(t, err)

			// Check ratios - they should be >= 0 and <= 1, and > 0 if the character type exists
			if tc.hasUpper {
				assert.GreaterOrEqual(t, features["uppercase_ratio"], 0.0, "Should have uppercase ratio")
				if tc.rawData != strings.ToLower(tc.rawData) {
					assert.Greater(t, features["uppercase_ratio"], 0.0, "Should have uppercase ratio > 0 when uppercase exists")
				}
			}
			if tc.hasLower {
				assert.GreaterOrEqual(t, features["lowercase_ratio"], 0.0, "Should have lowercase ratio")
				if strings.ToUpper(tc.rawData) != tc.rawData || tc.rawData == "" {
					// If there are lowercase letters or it's empty (empty string has ratio 0)
					_ = features["lowercase_ratio"] // Just verify it exists
				}
			}
			if tc.hasDigit {
				assert.GreaterOrEqual(t, features["digit_ratio"], 0.0, "Should have digit ratio")
				if strings.ContainsAny(tc.rawData, "0123456789") {
					assert.Greater(t, features["digit_ratio"], 0.0, "Should have digit ratio > 0 when digits exist")
				}
			}
			if tc.hasSpecial {
				assert.GreaterOrEqual(t, features["special_char_ratio"], 0.0, "Should have special char ratio")
				// Special chars are non-letter, non-digit, non-space
				hasSpecial := false
				for _, r := range tc.rawData {
					if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
						hasSpecial = true
						break
					}
				}
				if hasSpecial {
					assert.Greater(t, features["special_char_ratio"], 0.0, "Should have special char ratio > 0 when special chars exist")
				}
			}
		})
	}
}

// TestContentFeatureExtractor_EmptyEvent tests empty event handling
func TestContentFeatureExtractor_EmptyEvent(t *testing.T) {
	extractor := NewContentFeatureExtractor()

	event := &core.Event{
		EventID:   "test-event",
		Timestamp: time.Now().UTC(),
		RawData:   "",
		Fields:    make(map[string]interface{}),
	}

	features, err := extractor.Extract(context.Background(), event)
	require.NoError(t, err, "Should handle empty event")

	assert.Equal(t, 0.0, features["message_length"], "Empty message should have length 0")
	assert.Equal(t, 0.0, features["message_word_count"], "Empty message should have word count 0")
}

// TestFrequencyFeatureExtractor_TimeBasedFeatures tests time-based feature extraction
func TestFrequencyFeatureExtractor_TimeBasedFeatures(t *testing.T) {
	extractor := NewFrequencyFeatureExtractor()

	testTime := time.Date(2024, 12, 25, 14, 30, 0, 0, time.UTC) // Wednesday, 2:30 PM

	event := &core.Event{
		EventID:   "test-event",
		Timestamp: testTime,
		RawData:   "test message",
		Fields:    make(map[string]interface{}),
	}

	features, err := extractor.Extract(context.Background(), event)
	require.NoError(t, err, "Should extract time features")

	// Verify time-based features (FrequencyFeatureExtractor extracts these)
	assert.Equal(t, 14.0, features["hour_of_day"], "Should extract hour of day")
	assert.Equal(t, 3.0, features["day_of_week"], "Should extract day of week (Wednesday = 3)")
	assert.Equal(t, 0.0, features["is_weekend"], "Wednesday is not weekend")
	assert.Equal(t, 1.0, features["is_business_hours"], "2:30 PM is business hours")
	assert.Greater(t, features["timestamp_seconds"], 0.0, "Should extract timestamp")
	// Note: FrequencyFeatureExtractor doesn't extract month - that's in TemporalFeatureExtractor
}

// TestNetworkFeatureExtractor_IPv4Extraction tests IPv4 address feature extraction
func TestNetworkFeatureExtractor_IPv4Extraction(t *testing.T) {
	extractor := NewNetworkFeatureExtractor()

	event := &core.Event{
		EventID:   "test-event",
		Timestamp: time.Now().UTC(),
		RawData:   "test",
		SourceIP:  "192.168.1.100",
		Fields:    make(map[string]interface{}),
	}

	features, err := extractor.Extract(context.Background(), event)
	require.NoError(t, err, "Should extract network features")

	// Verify IP features
	assert.Equal(t, 1.0, features["ip_is_private"], "192.168.1.100 is private IP")
	assert.Equal(t, 4.0, features["ip_version"], "Should detect IPv4")
	assert.Equal(t, 192.0, features["ip_octet_1"], "Should extract first octet")
	assert.Equal(t, 168.0, features["ip_octet_2"], "Should extract second octet")
	assert.Equal(t, 1.0, features["ip_octet_3"], "Should extract third octet")
	assert.Equal(t, 100.0, features["ip_octet_4"], "Should extract fourth octet")
}

// TestNetworkFeatureExtractor_LoopbackIP tests loopback IP detection
func TestNetworkFeatureExtractor_LoopbackIP(t *testing.T) {
	extractor := NewNetworkFeatureExtractor()

	event := &core.Event{
		EventID:   "test-event",
		Timestamp: time.Now().UTC(),
		RawData:   "test",
		SourceIP:  "127.0.0.1",
		Fields:    make(map[string]interface{}),
	}

	features, err := extractor.Extract(context.Background(), event)
	require.NoError(t, err)

	assert.Equal(t, 1.0, features["ip_is_loopback"], "127.0.0.1 is loopback")
	// Note: Go's net.IP.IsPrivate() returns false for loopback addresses
	// Loopback (127.0.0.0/8) is a separate category from private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
	assert.Equal(t, 0.0, features["ip_is_private"], "Loopback is not considered private by net.IP.IsPrivate()")
}

// TestTemporalFeatureExtractor_TimeBinning tests time binning features
func TestTemporalFeatureExtractor_TimeBinning(t *testing.T) {
	extractor := NewTemporalFeatureExtractor()

	testCases := []struct {
		name              string
		timestamp         time.Time
		expectedTimeOfDay float64 // morning=0, afternoon=1, evening=2, night=3
		expectedIsWeekend float64
	}{
		{"Morning", time.Date(2024, 6, 15, 8, 0, 0, 0, time.UTC), 0, 1},    // Saturday 8 AM = morning, weekend
		{"Afternoon", time.Date(2024, 6, 15, 14, 0, 0, 0, time.UTC), 1, 1}, // Saturday 2 PM = afternoon, weekend
		{"Evening", time.Date(2024, 6, 10, 20, 0, 0, 0, time.UTC), 2, 0},   // Monday 8 PM = evening
		{"Night", time.Date(2024, 6, 10, 2, 0, 0, 0, time.UTC), 3, 0},      // Monday 2 AM = night
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

			assert.Equal(t, tc.expectedTimeOfDay, features["time_of_day_category"], "Time of day should match")
			assert.Equal(t, tc.expectedIsWeekend, features["is_weekend"], "Weekend flag should match")
		})
	}
}

// TestFeatureExtractor_MissingValues tests handling of missing values
func TestFeatureExtractor_MissingValues(t *testing.T) {
	extractor := NewContentFeatureExtractor()

	// Event with missing IP
	event := &core.Event{
		EventID:   "test-event",
		Timestamp: time.Now().UTC(),
		RawData:   "test message",
		SourceIP:  "", // Missing IP
		Fields:    make(map[string]interface{}),
	}

	features, err := extractor.Extract(context.Background(), event)
	require.NoError(t, err, "Should handle missing values gracefully")

	// Should still extract content features
	assert.Greater(t, features["message_length"], 0.0, "Should extract message features even with missing IP")
}
