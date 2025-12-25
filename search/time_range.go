package search

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TimeRangeParser parses relative and absolute time expressions for CQL queries
// TASK 27.3: Time range parsing for CQL queries
type TimeRangeParser struct{}

// NewTimeRangeParser creates a new time range parser
func NewTimeRangeParser() *TimeRangeParser {
	return &TimeRangeParser{}
}

// ParseRelativeTime parses relative time expressions like "last 24h", "last 7d"
// TASK 27.3: Parse relative time expressions
func (trp *TimeRangeParser) ParseRelativeTime(expr string) (time.Time, error) {
	expr = strings.ToLower(strings.TrimSpace(expr))

	// Pattern: "last" followed by number and unit (h, d, w, m, y)
	pattern := regexp.MustCompile(`^last\s+(\d+)\s*(h|d|w|m|y|hour|hours|day|days|week|weeks|month|months|year|years)$`)
	matches := pattern.FindStringSubmatch(expr)
	if len(matches) != 3 {
		return time.Time{}, fmt.Errorf("invalid relative time expression: %s (expected format: 'last 24h' or 'last 7d')", expr)
	}

	amount, err := strconv.Atoi(matches[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time amount: %s", matches[1])
	}

	unit := matches[2]
	var duration time.Duration

	switch unit {
	case "h", "hour", "hours":
		duration = time.Duration(amount) * time.Hour
	case "d", "day", "days":
		duration = time.Duration(amount) * 24 * time.Hour
	case "w", "week", "weeks":
		duration = time.Duration(amount) * 7 * 24 * time.Hour
	case "m", "month", "months":
		duration = time.Duration(amount) * 30 * 24 * time.Hour // Approximate month
	case "y", "year", "years":
		duration = time.Duration(amount) * 365 * 24 * time.Hour // Approximate year
	default:
		return time.Time{}, fmt.Errorf("unsupported time unit: %s", unit)
	}

	// Calculate start time: now - duration
	startTime := time.Now().UTC().Add(-duration)
	return startTime, nil
}

// ParseAbsoluteTime parses absolute time expressions in ISO8601 format
// TASK 27.3: Parse ISO8601 absolute timestamps
func (trp *TimeRangeParser) ParseAbsoluteTime(expr string) (time.Time, error) {
	expr = strings.TrimSpace(expr)

	// Try ISO8601 / RFC3339 formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, expr); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid absolute time format: %s (expected ISO8601)", expr)
}

// ParseTimeRange parses either relative or absolute time expressions
// TASK 27.3: Unified time parsing with timezone handling
func (trp *TimeRangeParser) ParseTimeRange(expr string) (time.Time, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return time.Time{}, fmt.Errorf("time expression cannot be empty")
	}

	// Check if it's a relative time expression (starts with "last")
	if strings.HasPrefix(strings.ToLower(expr), "last") {
		return trp.ParseRelativeTime(expr)
	}

	// Try absolute time parsing
	return trp.ParseAbsoluteTime(expr)
}

// TranslateTimeRangeToSQL converts time range expressions to SQL WHERE clauses
// TASK 27.3: Generate SQL timestamp filters with proper timezone handling
func (trp *TimeRangeParser) TranslateTimeRangeToSQL(startExpr, endExpr string) (string, []interface{}, error) {
	var conditions []string
	var params []interface{}

	if startExpr != "" {
		startTime, err := trp.ParseTimeRange(startExpr)
		if err != nil {
			return "", nil, fmt.Errorf("invalid start time expression: %w", err)
		}
		conditions = append(conditions, "timestamp >= ?")
		params = append(params, startTime)
	}

	if endExpr != "" {
		endTime, err := trp.ParseTimeRange(endExpr)
		if err != nil {
			return "", nil, fmt.Errorf("invalid end time expression: %w", err)
		}
		conditions = append(conditions, "timestamp <= ?")
		params = append(params, endTime)
	}

	if len(conditions) == 0 {
		return "", []interface{}{}, nil
	}

	return strings.Join(conditions, " AND "), params, nil
}
