package core

import "time"

// AlertStatus represents the status of an alert
type AlertStatus string

const (
	// HTTP and API timeouts
	HTTPClientTimeout = 30 * time.Second
	// HTTP client connection pool settings
	HTTPClientMaxIdleConns        = 100
	HTTPClientMaxIdleConnsPerHost = 10
	HTTPClientIdleConnTimeout     = 90 * time.Second
	// HTTPServerShutdownTimeout is the grace period for server shutdown
	HTTPServerShutdownTimeout = 5 * time.Second
	// APIRequestTimeout is the default timeout for API requests
	APIRequestTimeout = 5 * time.Second

	// Database operation timeouts
	DBHealthTimeout = 5 * time.Second
	// DefaultDBTimeout is the standard timeout for database operations
	DefaultDBTimeout = 5 * time.Second
	// LongDBTimeout is used for longer-running database operations
	LongDBTimeout = 10 * time.Second
	// ExtendedDBTimeout is used for operations that require more time (e.g., index creation, bulk operations)
	ExtendedDBTimeout = 30 * time.Second
	// MongoDBConnectionTimeout is the timeout for establishing MongoDB connections
	MongoDBConnectionTimeout = 10 * time.Second

	// ML and training timeouts
	// MLTrainingTimeout is the maximum time allowed for ML model training
	MLTrainingTimeout = 10 * time.Minute
	// MLPredictionTimeout is the timeout for ML predictions
	MLPredictionTimeout = 5 * time.Second

	// Collection and cleanup intervals
	StatsCollectionInterval = 60 * time.Second
	// RateLimiterCleanupPeriod is the period for cleaning up old rate limiter entries
	RateLimiterCleanupPeriod = 5 * time.Minute
	// JWTCleanupInterval is the interval for JWT token cleanup
	JWTCleanupInterval = 1 * time.Hour

	// Authentication and security
	// AuthFailureWindow is the time window for tracking authentication failures
	AuthFailureWindow = 15 * time.Minute
	// MaxAuthFailures is the maximum number of auth failures before account lockout
	MaxAuthFailures = 5
	// JWTTokenExpiry is the default JWT token expiration time
	JWTTokenExpiry = 24 * time.Hour

	// Chart and display settings
	// DefaultChartMonths is the default number of months to show in charts
	DefaultChartMonths = 6

	// Correlation and detection limits
	// MaxCorrelationEventsPerWindow is the maximum number of events to keep per correlation window
	MaxCorrelationEventsPerWindow = 1000
	// MaxGroupsPerRule is the maximum number of correlation groups per rule
	MaxGroupsPerRule = 1000
	// MaxDistinctValuesPerField is the maximum distinct values tracked per field
	MaxDistinctValuesPerField = 10000
	// MaxEventsPerGroup is the maximum events stored per correlation group
	MaxEventsPerGroup = 1000
	// MaxMetricsPerGroup is the maximum metric values stored per group
	MaxMetricsPerGroup = 1000

	// Size and rate limits
	// MaxJSONBodySize is the maximum size for JSON request bodies (1MB)
	MaxJSONBodySize = 1024 * 1024
	// MaxErrorMessageLength is the maximum length for error messages sent to clients
	MaxErrorMessageLength = 200
	// DefaultPageLimit is the default number of items per page
	DefaultPageLimit = 100
	// MaxPageLimit is the maximum number of items allowed per page
	MaxPageLimit = 1000
	// MaxPageNumber is the maximum page number to prevent abuse
	MaxPageNumber = 1000000

	// Alert statuses
	// AlertStatusPending indicates an alert that hasn't been reviewed
	AlertStatusPending AlertStatus = "Pending"
	// AlertStatusAcknowledged indicates an alert that has been reviewed and acknowledged
	AlertStatusAcknowledged AlertStatus = "Acknowledged"
	// AlertStatusInvestigating indicates an alert that is under active investigation (TASK 40)
	AlertStatusInvestigating AlertStatus = "Investigating"
	// AlertStatusResolved indicates an alert that has been resolved
	AlertStatusResolved AlertStatus = "Resolved"
	// AlertStatusEscalated indicates an alert that has been escalated to higher level (TASK 40)
	AlertStatusEscalated AlertStatus = "Escalated"
	// AlertStatusClosed indicates an alert that has been closed (final state) (TASK 40)
	AlertStatusClosed AlertStatus = "Closed"
	// AlertStatusDismissed indicates an alert that has been dismissed as false positive
	AlertStatusDismissed AlertStatus = "Dismissed"
	// AlertStatusFalsePositive indicates an alert that has been marked as false positive
	AlertStatusFalsePositive AlertStatus = "FalsePositive"
)

// String returns the string representation
func (s AlertStatus) String() string {
	return string(s)
}

// IsValid checks if the status is valid
func (s AlertStatus) IsValid() bool {
	switch s {
	case AlertStatusPending, AlertStatusAcknowledged, AlertStatusInvestigating, AlertStatusDismissed, AlertStatusResolved, AlertStatusEscalated, AlertStatusClosed, AlertStatusFalsePositive:
		return true
	default:
		return false
	}
}

// AlertDisposition represents the analyst's verdict on an alert
// TASK 102: Disposition workflow for analyst verdicts
type AlertDisposition string

const (
	// DispositionUndetermined indicates the alert has not been reviewed yet
	DispositionUndetermined AlertDisposition = "undetermined"
	// DispositionTruePositive indicates the alert represents a genuine security threat
	DispositionTruePositive AlertDisposition = "true_positive"
	// DispositionFalsePositive indicates the alert was triggered incorrectly
	DispositionFalsePositive AlertDisposition = "false_positive"
	// DispositionBenign indicates the activity is legitimate and expected
	DispositionBenign AlertDisposition = "benign"
	// DispositionSuspicious indicates the alert requires further investigation
	DispositionSuspicious AlertDisposition = "suspicious"
	// DispositionInconclusive indicates insufficient evidence to determine verdict
	DispositionInconclusive AlertDisposition = "inconclusive"
)

// String returns the string representation of the disposition
func (d AlertDisposition) String() string {
	return string(d)
}

// IsValid checks if the disposition value is valid
func (d AlertDisposition) IsValid() bool {
	switch d {
	case DispositionUndetermined, DispositionTruePositive, DispositionFalsePositive,
		DispositionBenign, DispositionSuspicious, DispositionInconclusive:
		return true
	default:
		return false
	}
}

// ValidDispositions returns all valid disposition values
func ValidDispositions() []AlertDisposition {
	return []AlertDisposition{
		DispositionUndetermined,
		DispositionTruePositive,
		DispositionFalsePositive,
		DispositionBenign,
		DispositionSuspicious,
		DispositionInconclusive,
	}
}

// IsValidDisposition checks if a string is a valid disposition value
func IsValidDisposition(d string) bool {
	return AlertDisposition(d).IsValid()
}
