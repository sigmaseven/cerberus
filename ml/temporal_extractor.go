package ml

import (
	"context"
	"math"
	"time"

	"cerberus/core"
)

// TemporalFeatureExtractor extracts time-based features from events
type TemporalFeatureExtractor struct{}

// NewTemporalFeatureExtractor creates a new temporal feature extractor
func NewTemporalFeatureExtractor() *TemporalFeatureExtractor {
	return &TemporalFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *TemporalFeatureExtractor) Name() string {
	return "temporal"
}

// Extract extracts temporal features from an event
func (e *TemporalFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)

	t := event.Timestamp

	// Hour of day (0-23)
	features["hour_of_day"] = float64(t.Hour())

	// Day of week (0-6, Sunday=0)
	features["day_of_week"] = float64(t.Weekday())

	// Is weekend (1 if Saturday/Sunday, 0 otherwise)
	isWeekend := 0.0
	if t.Weekday() == time.Saturday || t.Weekday() == time.Sunday {
		isWeekend = 1.0
	}
	features["is_weekend"] = isWeekend

	// Is business hours (1 if Mon-Fri 9-17, 0 otherwise)
	isBusinessHours := 0.0
	if t.Weekday() >= time.Monday && t.Weekday() <= time.Friday {
		if t.Hour() >= 9 && t.Hour() <= 17 {
			isBusinessHours = 1.0
		}
	}
	features["is_business_hours"] = isBusinessHours

	// Month (1-12)
	features["month"] = float64(t.Month())

	// Quarter (1-4)
	quarter := math.Ceil(float64(t.Month()) / 3.0)
	features["quarter"] = quarter

	// Is holiday season (1 if Nov-Dec, 0 otherwise)
	isHolidaySeason := 0.0
	if t.Month() == time.November || t.Month() == time.December {
		isHolidaySeason = 1.0
	}
	features["is_holiday_season"] = isHolidaySeason

	// Time since Unix epoch (normalized)
	features["timestamp_epoch"] = float64(t.Unix())

	// Minute of hour (0-59)
	features["minute_of_hour"] = float64(t.Minute())

	// Second of minute (0-59)
	features["second_of_minute"] = float64(t.Second())

	// Is peak hours (1 if 8-10 or 16-18, 0 otherwise)
	isPeakHours := 0.0
	hour := t.Hour()
	if (hour >= 8 && hour <= 10) || (hour >= 16 && hour <= 18) {
		isPeakHours = 1.0
	}
	features["is_peak_hours"] = isPeakHours

	// Time of day categories (morning=0, afternoon=1, evening=2, night=3)
	var timeOfDay float64
	switch {
	case hour >= 6 && hour < 12:
		timeOfDay = 0 // morning
	case hour >= 12 && hour < 18:
		timeOfDay = 1 // afternoon
	case hour >= 18 && hour < 22:
		timeOfDay = 2 // evening
	default:
		timeOfDay = 3 // night
	}
	features["time_of_day_category"] = timeOfDay

	// Day of month (1-31)
	features["day_of_month"] = float64(t.Day())

	// Week of year (1-52)
	_, week := t.ISOWeek()
	features["week_of_year"] = float64(week)

	return features, nil
}
