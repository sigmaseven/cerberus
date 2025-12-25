package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAlertStorage implements AlertStorageInterface for testing
type mockAlertStorage struct {
	alerts         map[string]*Alert
	insertedAlerts []*Alert
	updatedAlerts  []*Alert
}

func newMockAlertStorage() *mockAlertStorage {
	return &mockAlertStorage{
		alerts:         make(map[string]*Alert),
		insertedAlerts: make([]*Alert, 0),
		updatedAlerts:  make([]*Alert, 0),
	}
}

func (m *mockAlertStorage) FindAlertsByFingerprint(ctx context.Context, fingerprint string, windowStart time.Time) ([]Alert, error) {
	var results []Alert
	for _, alert := range m.alerts {
		if alert.Fingerprint == fingerprint && alert.Timestamp.After(windowStart) {
			results = append(results, *alert)
		}
	}
	return results, nil
}

func (m *mockAlertStorage) UpdateAlert(alert *Alert) error {
	m.updatedAlerts = append(m.updatedAlerts, alert)
	m.alerts[alert.AlertID] = alert
	return nil
}

func (m *mockAlertStorage) InsertAlert(ctx context.Context, alert *Alert) error {
	m.insertedAlerts = append(m.insertedAlerts, alert)
	m.alerts[alert.AlertID] = alert
	return nil
}

// TASK 40: Comprehensive deduplication tests
func TestDeduplicationEngine_ProcessAlert_NewAlert(t *testing.T) {
	storage := newMockAlertStorage()
	fingerprinter := NewAlertFingerprinter(FingerprintConfig{Enabled: true})
	engine := NewDeduplicationEngine(storage, fingerprinter)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Timestamp: time.Now(),
		Event:     &Event{EventID: "event-1"},
	}

	config := FingerprintConfig{
		Enabled:    true,
		TimeWindow: 5 * time.Minute,
	}

	result, err := engine.ProcessAlert(context.Background(), alert, config)
	require.NoError(t, err)
	assert.False(t, result.IsDuplicate)
	assert.True(t, result.Created)
	assert.NotEmpty(t, result.Fingerprint)
	assert.Equal(t, result.Fingerprint, alert.Fingerprint)
	assert.Len(t, storage.insertedAlerts, 1)
	assert.Len(t, storage.updatedAlerts, 0)
}

func TestDeduplicationEngine_ProcessAlert_DuplicateFound(t *testing.T) {
	storage := newMockAlertStorage()
	// Use fingerprint config that only uses rule_id, so alerts with same rule match
	fingerprinter := NewAlertFingerprinter(FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id"}, // Only match on rule_id, not event_id
	})
	engine := NewDeduplicationEngine(storage, fingerprinter)

	// Create first alert
	firstAlert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Timestamp: time.Now().Add(-2 * time.Minute),
		Status:    AlertStatusPending,
		Event:     &Event{EventID: "event-1"},
	}

	// Process first alert to create it and generate fingerprint
	config := FingerprintConfig{
		Enabled:    true,
		Fields:     []string{"rule_id"}, // Same config as fingerprinter
		TimeWindow: 5 * time.Minute,
	}
	firstResult, err := engine.ProcessAlert(context.Background(), firstAlert, config)
	require.NoError(t, err)
	require.False(t, firstResult.IsDuplicate)
	require.True(t, firstResult.Created)
	require.NotEmpty(t, firstResult.Fingerprint)

	// Get the stored alert from storage - it should have EventIDs initialized by createNewAlertWithFingerprint
	storedAlert := storage.alerts[firstAlert.AlertID]
	require.NotNil(t, storedAlert)
	fingerprint := storedAlert.Fingerprint
	// Verify that the first alert's EventID is in the EventIDs list
	require.Contains(t, storedAlert.EventIDs, firstAlert.EventID, "First alert's EventID should be in EventIDs")

	// Create duplicate alert (same rule_id but different event_id - should match based on rule_id only)
	duplicateAlert := &Alert{
		AlertID:   "alert-2",
		RuleID:    "rule-1",  // Same rule_id - will match
		EventID:   "event-2", // Different event_id - but won't matter since we only fingerprint on rule_id
		Timestamp: time.Now(),
		Event:     &Event{EventID: "event-2"},
	}

	result, err := engine.ProcessAlert(context.Background(), duplicateAlert, config)
	require.NoError(t, err)
	assert.True(t, result.IsDuplicate, "Alert should be detected as duplicate when rule_id matches")
	assert.False(t, result.Created, "Duplicate alert should not be created")
	assert.NotNil(t, result.ExistingAlert, "Should return existing alert")
	assert.Equal(t, result.Fingerprint, fingerprint, "Fingerprints should match")
	assert.Equal(t, firstAlert.AlertID, result.ExistingAlert.AlertID, "Should reference first alert")
	assert.Equal(t, 1, result.ExistingAlert.DuplicateCount, "Duplicate count should be incremented")
	assert.Contains(t, result.ExistingAlert.EventIDs, "event-2", "Should include new event ID in list")
	assert.Contains(t, result.ExistingAlert.EventIDs, "event-1", "Should preserve original event ID")
	assert.Len(t, storage.insertedAlerts, 1, "Only first alert should be inserted")
	assert.Len(t, storage.updatedAlerts, 1, "Duplicate alert should update existing one")
}

func TestDeduplicationEngine_ProcessAlert_DeduplicationDisabled(t *testing.T) {
	storage := newMockAlertStorage()
	fingerprinter := NewAlertFingerprinter(FingerprintConfig{Enabled: false})
	engine := NewDeduplicationEngine(storage, fingerprinter)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Timestamp: time.Now(),
		Event:     &Event{EventID: "event-1"},
	}

	config := FingerprintConfig{
		Enabled: false,
	}

	result, err := engine.ProcessAlert(context.Background(), alert, config)
	require.NoError(t, err)
	assert.False(t, result.IsDuplicate)
	assert.True(t, result.Created)
	assert.Empty(t, result.Fingerprint)
	assert.Len(t, storage.insertedAlerts, 1)
}

func TestDeduplicationEngine_ProcessAlert_TimeWindowExpired(t *testing.T) {
	storage := newMockAlertStorage()
	fingerprinter := NewAlertFingerprinter(FingerprintConfig{Enabled: true})
	engine := NewDeduplicationEngine(storage, fingerprinter)

	// Create old alert outside time window
	oldAlert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Timestamp: time.Now().Add(-10 * time.Minute), // 10 minutes ago
		Status:    AlertStatusPending,
		Event:     &Event{EventID: "event-1"},
	}

	fingerprint := fingerprinter.GenerateFingerprint(oldAlert)
	oldAlert.Fingerprint = fingerprint
	storage.alerts[oldAlert.AlertID] = oldAlert

	// Create new alert with same fingerprint but outside time window
	newAlert := &Alert{
		AlertID:   "alert-2",
		RuleID:    "rule-1",
		EventID:   "event-2",
		Timestamp: time.Now(),
		Event:     &Event{EventID: "event-2"},
	}

	config := FingerprintConfig{
		Enabled:    true,
		TimeWindow: 5 * time.Minute, // 5 minute window - old alert is outside
	}

	result, err := engine.ProcessAlert(context.Background(), newAlert, config)
	require.NoError(t, err)
	assert.False(t, result.IsDuplicate) // Should not be duplicate due to time window
	assert.True(t, result.Created)
	assert.Len(t, storage.insertedAlerts, 1)
}

func TestDeduplicationEngine_ProcessAlert_ResolvedAlertNotConsideredDuplicate(t *testing.T) {
	storage := newMockAlertStorage()
	fingerprinter := NewAlertFingerprinter(FingerprintConfig{Enabled: true})
	engine := NewDeduplicationEngine(storage, fingerprinter)

	// Create resolved alert
	resolvedAlert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Timestamp: time.Now().Add(-2 * time.Minute),
		Status:    AlertStatusResolved, // Already resolved
		Event:     &Event{EventID: "event-1"},
	}

	fingerprint := fingerprinter.GenerateFingerprint(resolvedAlert)
	resolvedAlert.Fingerprint = fingerprint
	storage.alerts[resolvedAlert.AlertID] = resolvedAlert

	// Create new alert with same fingerprint
	newAlert := &Alert{
		AlertID:   "alert-2",
		RuleID:    "rule-1",
		EventID:   "event-2",
		Timestamp: time.Now(),
		Event:     &Event{EventID: "event-2"},
	}

	config := FingerprintConfig{
		Enabled:    true,
		TimeWindow: 5 * time.Minute,
	}

	result, err := engine.ProcessAlert(context.Background(), newAlert, config)
	require.NoError(t, err)
	assert.False(t, result.IsDuplicate) // Should not be duplicate - resolved alerts don't count
	assert.True(t, result.Created)
	assert.Len(t, storage.insertedAlerts, 1)
}

func TestDeduplicationEngine_ProcessAlert_MultipleDuplicates(t *testing.T) {
	storage := newMockAlertStorage()
	// Use fingerprint config that only uses rule_id, so alerts with same rule match
	fingerprinter := NewAlertFingerprinter(FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id"}, // Only match on rule_id
	})
	engine := NewDeduplicationEngine(storage, fingerprinter)

	config := FingerprintConfig{
		Enabled:    true,
		Fields:     []string{"rule_id"}, // Same config as fingerprinter
		TimeWindow: 10 * time.Minute,
	}

	// Create first alert and process it
	firstAlert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Timestamp: time.Now().Add(-5 * time.Minute),
		Status:    AlertStatusPending,
		Event:     &Event{EventID: "event-1"},
	}

	firstResult, err := engine.ProcessAlert(context.Background(), firstAlert, config)
	require.NoError(t, err)
	require.False(t, firstResult.IsDuplicate)
	require.True(t, firstResult.Created)

	// Process multiple duplicates (same rule_id, different event_ids)
	for i := 2; i <= 5; i++ {
		duplicateAlert := &Alert{
			AlertID:   fmt.Sprintf("alert-%d", i),
			RuleID:    "rule-1", // Same rule_id - will match
			EventID:   fmt.Sprintf("event-%d", i),
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			Event:     &Event{EventID: fmt.Sprintf("event-%d", i)},
		}

		result, err := engine.ProcessAlert(context.Background(), duplicateAlert, config)
		require.NoError(t, err, "Processing duplicate %d should not error", i)
		assert.True(t, result.IsDuplicate, "Alert %d should be detected as duplicate", i)
		require.NotNil(t, result.ExistingAlert, "ExistingAlert should not be nil for duplicate %d", i)
		assert.Equal(t, i-1, result.ExistingAlert.DuplicateCount, "Duplicate count should be %d after processing duplicate %d", i-1, i)
	}

	// Verify final state
	require.Len(t, storage.updatedAlerts, 4, "Should have 4 updates (one per duplicate)")
	updatedAlert := storage.updatedAlerts[len(storage.updatedAlerts)-1]
	assert.Equal(t, 4, updatedAlert.DuplicateCount, "Final duplicate count should be 4")
	// EventIDs should contain original event-1 plus duplicates event-2 through event-5
	assert.Len(t, updatedAlert.EventIDs, 5, "Should have 5 EventIDs (original + 4 duplicates)")
	assert.Contains(t, updatedAlert.EventIDs, "event-1", "Should contain original event ID")
	for i := 2; i <= 5; i++ {
		assert.Contains(t, updatedAlert.EventIDs, fmt.Sprintf("event-%d", i), "Should contain duplicate event ID %d", i)
	}
	assert.Len(t, storage.insertedAlerts, 1, "Only first alert should be inserted")
}

func TestDeduplicationEngine_ProcessAlert_EventIDsCapped(t *testing.T) {
	storage := newMockAlertStorage()
	// Use fingerprint config that only uses rule_id
	fingerprinter := NewAlertFingerprinter(FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id"}, // Only match on rule_id
	})
	engine := NewDeduplicationEngine(storage, fingerprinter)

	config := FingerprintConfig{
		Enabled:    true,
		Fields:     []string{"rule_id"}, // Same config as fingerprinter
		TimeWindow: 5 * time.Minute,
	}

	// Create first alert and process it
	firstAlert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Timestamp: time.Now(),
		Status:    AlertStatusPending,
		Event:     &Event{EventID: "event-1"},
	}

	firstResult, err := engine.ProcessAlert(context.Background(), firstAlert, config)
	require.NoError(t, err)
	require.False(t, firstResult.IsDuplicate)

	// Get stored alert and manually set EventIDs to max capacity
	storedAlert := storage.alerts[firstAlert.AlertID]
	require.NotNil(t, storedAlert)
	storedAlert.EventIDs = make([]string, 1000)
	for i := 0; i < 1000; i++ {
		storedAlert.EventIDs[i] = fmt.Sprintf("event-%d", i+1)
	}
	storage.alerts[firstAlert.AlertID] = storedAlert

	// Add one more duplicate - should cap EventIDs at 1000
	duplicateAlert := &Alert{
		AlertID:   "alert-2",
		RuleID:    "rule-1", // Same rule_id - will match
		EventID:   "event-1001",
		Timestamp: time.Now(),
		Event:     &Event{EventID: "event-1001"},
	}

	result, err := engine.ProcessAlert(context.Background(), duplicateAlert, config)
	require.NoError(t, err)
	assert.True(t, result.IsDuplicate, "Should detect as duplicate")
	require.NotNil(t, result.ExistingAlert, "ExistingAlert should not be nil")
	// EventIDs should be capped at 1000 (REQUIREMENT: Prevent memory exhaustion)
	assert.LessOrEqual(t, len(result.ExistingAlert.EventIDs), 1000, "EventIDs should be capped at 1000")
	// New event ID should be added (oldest should be removed if at cap)
	assert.Contains(t, result.ExistingAlert.EventIDs, "event-1001", "New event ID should be in the list")
}
