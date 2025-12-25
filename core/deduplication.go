package core

import (
	"context"
	"fmt"
	"time"
)

// TASK 138: Removed unused validHexRegex and isValidFingerprint (fingerprints validated at source)

// AlertStorageInterface defines the interface for alert storage operations
// This allows for mocking in tests and decouples the deduplication engine from storage implementation
type AlertStorageInterface interface {
	FindAlertsByFingerprint(ctx context.Context, fingerprint string, windowStart time.Time) ([]Alert, error)
	UpdateAlert(alert *Alert) error
	InsertAlert(ctx context.Context, alert *Alert) error
}

// DeduplicationEngine handles alert deduplication logic
type DeduplicationEngine struct {
	alertStorage  AlertStorageInterface
	fingerprinter *AlertFingerprinter
}

// DedupResult represents the result of processing an alert through deduplication
type DedupResult struct {
	IsDuplicate   bool
	ExistingAlert *Alert
	Created       bool
	Fingerprint   string
}

// NewDeduplicationEngine creates a new deduplication engine
func NewDeduplicationEngine(alertStorage AlertStorageInterface, fingerprinter *AlertFingerprinter) *DeduplicationEngine {
	return &DeduplicationEngine{
		alertStorage:  alertStorage,
		fingerprinter: fingerprinter,
	}
}

// ProcessAlert processes an alert through the deduplication engine
// If a duplicate is found, it updates the existing alert
// If not, it creates a new alert
func (de *DeduplicationEngine) ProcessAlert(ctx context.Context, alert *Alert, dedupConfig FingerprintConfig) (*DedupResult, error) {
	// If deduplication is not enabled, create alert without fingerprinting
	if !dedupConfig.Enabled {
		return de.createNewAlert(ctx, alert)
	}

	fingerprint := de.generateFingerprintAndSet(alert)
	activeAlert := de.findActiveDuplicate(ctx, fingerprint, dedupConfig.TimeWindow)

	if activeAlert != nil {
		return de.handleDuplicate(ctx, activeAlert, alert, fingerprint)
	}

	return de.createNewAlertWithFingerprint(ctx, alert, fingerprint)
}

// generateFingerprintAndSet generates fingerprint and sets it on the alert
func (de *DeduplicationEngine) generateFingerprintAndSet(alert *Alert) string {
	fingerprint := de.fingerprinter.GenerateFingerprint(alert)
	alert.Fingerprint = fingerprint
	return fingerprint
}

// findActiveDuplicate finds an active duplicate alert within the time window
func (de *DeduplicationEngine) findActiveDuplicate(ctx context.Context, fingerprint string, timeWindow time.Duration) *Alert {
	if timeWindow == 0 {
		timeWindow = 1 * time.Hour // Default 1 hour
	}

	windowStart := time.Now().Add(-timeWindow)

	existingAlerts, err := de.alertStorage.FindAlertsByFingerprint(ctx, fingerprint, windowStart)
	if err != nil {
		return nil
	}

	// Filter out resolved/false positive alerts
	for i := range existingAlerts {
		if existingAlerts[i].Status != AlertStatusResolved &&
			existingAlerts[i].Status != AlertStatusFalsePositive {
			return &existingAlerts[i]
		}
	}

	return nil
}

// handleDuplicate updates the existing alert with duplicate information
func (de *DeduplicationEngine) handleDuplicate(ctx context.Context, activeAlert, newAlert *Alert, fingerprint string) (*DedupResult, error) {
	activeAlert.DuplicateCount++
	activeAlert.LastSeen = newAlert.Timestamp
	activeAlert.EventIDs = append(activeAlert.EventIDs, newAlert.EventID)

	// Cap EventIDs array size to prevent memory exhaustion for frequently-duplicated alerts
	const maxEventIDsCount = 1000
	if len(activeAlert.EventIDs) > maxEventIDsCount {
		// Keep only the most recent maxEventIDsCount entries (FIFO eviction)
		activeAlert.EventIDs = activeAlert.EventIDs[len(activeAlert.EventIDs)-maxEventIDsCount:]
	}

	// Update event reference to latest event
	if newAlert.Event != nil {
		activeAlert.Event = newAlert.Event
	}

	if err := de.alertStorage.UpdateAlert(activeAlert); err != nil {
		return nil, fmt.Errorf("failed to update existing alert: %w", err)
	}

	return &DedupResult{
		IsDuplicate:   true,
		ExistingAlert: activeAlert,
		Created:       false,
		Fingerprint:   fingerprint,
	}, nil
}

// createNewAlert creates a new alert without fingerprinting
func (de *DeduplicationEngine) createNewAlert(ctx context.Context, alert *Alert) (*DedupResult, error) {
	if err := de.alertStorage.InsertAlert(ctx, alert); err != nil {
		return nil, fmt.Errorf("failed to create alert: %w", err)
	}

	return &DedupResult{
		IsDuplicate:   false,
		ExistingAlert: nil,
		Created:       true,
		Fingerprint:   "",
	}, nil
}

// createNewAlertWithFingerprint creates a new alert with fingerprinting
func (de *DeduplicationEngine) createNewAlertWithFingerprint(ctx context.Context, alert *Alert, fingerprint string) (*DedupResult, error) {
	// Initialize EventIDs with the alert's EventID to track all events for this alert
	if alert.EventIDs == nil {
		alert.EventIDs = []string{}
	}
	if alert.EventID != "" {
		alert.EventIDs = append(alert.EventIDs, alert.EventID)
	}

	if err := de.alertStorage.InsertAlert(ctx, alert); err != nil {
		return nil, fmt.Errorf("failed to create alert: %w", err)
	}

	return &DedupResult{
		IsDuplicate:   false,
		ExistingAlert: nil,
		Created:       true,
		Fingerprint:   fingerprint,
	}, nil
}

// isValidFingerprint validates that a fingerprint contains only valid characters
// to prevent NoSQL injection attacks. Fingerprints should be SHA256 hashes (hex strings).
// TASK 138: Removed unused isValidFingerprint function
