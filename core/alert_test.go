package core

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Requirement: ALERT-001 - Event Preservation
// Source: docs/requirements/alert-requirements.md
// "All security alerts MUST preserve complete event context for forensic analysis"

func TestNewAlert_RejectsNilEvent(t *testing.T) {
	ruleID := "test-rule"
	eventID := "test-event"
	severity := "high"

	// REQUIREMENT: Nil events must be rejected
	// Rationale: Alerts without events violate forensic requirements (PCI-DSS 10.6, HIPAA, SOC 2)
	// TASK 137: Now returns error instead of panicking for production safety
	alert, err := NewAlert(ruleID, eventID, severity, nil)
	assert.Error(t, err, "NewAlert MUST return error for nil events per ALERT-001")
	assert.Nil(t, alert, "Alert must be nil when event is nil")
	assert.ErrorIs(t, err, ErrNilEvent, "Error must be ErrNilEvent")
}

func TestNewAlert_WithValidEvent(t *testing.T) {
	ruleID := "test-rule"
	eventID := "test-event"
	severity := "high"

	// Create a complete event with all required fields
	rawData, _ := json.Marshal("test log line: failed login attempt")
	event := &Event{
		EventID:   "evt-123",
		Timestamp: time.Now().UTC(),
		RawData:   rawData,
		Fields: map[string]interface{}{
			"source_ip":  "192.168.1.100",
			"username":   "admin",
			"action":     "login_failed",
			"event_type": "authentication",
		},
	}

	alert, err := NewAlert(ruleID, eventID, severity, event)
	require.NoError(t, err, "NewAlert should not return error for valid event")
	require.NotNil(t, alert, "Alert should not be nil for valid event")

	// Verify alert metadata
	assert.NotEmpty(t, alert.AlertID, "Alert must have a generated UUID")
	_, parseErr := uuid.Parse(alert.AlertID)
	assert.NoError(t, parseErr, "AlertID must be a valid UUID")

	assert.Equal(t, ruleID, alert.RuleID)
	assert.Equal(t, eventID, alert.EventID)
	assert.Equal(t, severity, alert.Severity)
	assert.Equal(t, AlertStatusPending, alert.Status)
	assert.WithinDuration(t, time.Now().UTC(), alert.Timestamp, time.Second)

	// REQUIREMENT: Alert MUST preserve complete event data
	assert.NotNil(t, alert.Event, "Alert must preserve event per ALERT-001")
	assert.Equal(t, event.EventID, alert.Event.EventID, "Event ID must be preserved")
	assert.Equal(t, event.RawData, alert.Event.RawData, "Raw log data must be preserved for forensics")

	// Verify event fields are preserved (required for forensic analysis)
	assert.Equal(t, event.Fields["source_ip"], alert.Event.Fields["source_ip"], "Source IP must be preserved")
	assert.Equal(t, event.Fields["username"], alert.Event.Fields["username"], "Username must be preserved")
	assert.Equal(t, event.Fields["action"], alert.Event.Fields["action"], "Action must be preserved")
}

// HIGH-001: Enhanced test for complete event data preservation
// REQUIREMENT: alert-requirements.md Section 1, lines 1-125
// Verifies ALL event fields are preserved, not just a subset
func TestAlert_PreservesCompleteEventData_ALERT001(t *testing.T) {
	// REQUIREMENT: alert-requirements.md Section 1
	// Specification: "Every alert MUST preserve the complete event that triggered it"
	// Rationale: Forensic investigation requires complete event data

	// Create event with comprehensive field set
	timestamp := time.Now().UTC()
	syslogRaw, _ := json.Marshal("Oct 31 12:00:00 server sshd[1234]: Failed password for admin from 10.20.30.40 port 22 ssh2")
	event := &Event{
		EventID:      "evt-forensic-123",
		Timestamp:    timestamp,
		SourceFormat: "syslog",
		SourceIP:     "10.20.30.40",
		EventType:    "authentication_failure",
		Severity:     "high",
		RawData:      syslogRaw,
		Fields: map[string]interface{}{
			"user":        "admin",
			"source_ip":   "10.20.30.40",
			"source_port": 22,
			"service":     "sshd",
			"pid":         1234,
			"action":      "failed_password",
			"protocol":    "ssh2",
			"timestamp":   "Oct 31 12:00:00",
			"hostname":    "server",
		},
	}

	alert, err := NewAlert("rule-forensic-001", "evt-forensic-123", "critical", event)
	require.NoError(t, err)
	require.NotNil(t, alert)

	// VERIFY: Complete event data preserved
	assert.NotNil(t, alert.Event, "Alert MUST preserve event reference")

	// Verify all top-level event fields
	assert.Equal(t, event.EventID, alert.Event.EventID, "EventID must be preserved")
	assert.Equal(t, event.Timestamp, alert.Event.Timestamp, "Timestamp must be preserved")
	assert.Equal(t, event.SourceFormat, alert.Event.SourceFormat, "SourceFormat must be preserved")
	assert.Equal(t, event.SourceIP, alert.Event.SourceIP, "SourceIP must be preserved")
	assert.Equal(t, event.EventType, alert.Event.EventType, "EventType must be preserved")
	assert.Equal(t, event.Severity, alert.Event.Severity, "Severity must be preserved")
	assert.Equal(t, event.RawData, alert.Event.RawData, "RawData must be preserved for forensics")

	// VERIFY: ALL custom fields preserved (critical for forensics)
	assert.NotNil(t, alert.Event.Fields, "Event fields map must not be nil")
	assert.Equal(t, len(event.Fields), len(alert.Event.Fields),
		"All event fields must be preserved (expected %d, got %d)",
		len(event.Fields), len(alert.Event.Fields))

	// Verify each custom field individually
	for key, expectedValue := range event.Fields {
		actualValue, exists := alert.Event.Fields[key]
		assert.True(t, exists, "Field %q must exist in alert event", key)
		assert.Equal(t, expectedValue, actualValue,
			"Field %q value mismatch: expected %v, got %v", key, expectedValue, actualValue)
	}

	t.Log("✓ VERIFIED: Complete event data preserved in alert")
	t.Log("  - All top-level event fields preserved")
	t.Log("  - All custom fields preserved")
	t.Log("  - Raw data preserved for forensic analysis")
}

// HIGH-001: Test that alert preserves event fields across different data types
func TestAlert_PreservesEventFieldTypes_ALERT001(t *testing.T) {
	// REQUIREMENT: alert-requirements.md Section 1
	// Test: Verify different data types are correctly preserved
	// Rationale: Events contain mixed data types (strings, ints, floats, bools, arrays, maps)

	mixedRaw, _ := json.Marshal("mixed type event")
	event := &Event{
		EventID:   "evt-types-123",
		Timestamp: time.Now().UTC(),
		RawData:   mixedRaw,
		Fields: map[string]interface{}{
			"string_field": "value",
			"int_field":    123,
			"float_field":  45.67,
			"bool_field":   true,
			"array_field":  []string{"item1", "item2", "item3"},
			"map_field":    map[string]interface{}{"nested": "value"},
			"nil_field":    nil,
		},
	}

	alert, err := NewAlert("rule-types-001", "evt-types-123", "medium", event)
	require.NoError(t, err)
	require.NotNil(t, alert)

	// Verify each type is preserved correctly
	assert.IsType(t, "", alert.Event.Fields["string_field"], "String type must be preserved")
	assert.Equal(t, "value", alert.Event.Fields["string_field"])

	assert.IsType(t, 0, alert.Event.Fields["int_field"], "Int type must be preserved")
	assert.Equal(t, 123, alert.Event.Fields["int_field"])

	assert.IsType(t, 0.0, alert.Event.Fields["float_field"], "Float type must be preserved")
	assert.Equal(t, 45.67, alert.Event.Fields["float_field"])

	assert.IsType(t, true, alert.Event.Fields["bool_field"], "Bool type must be preserved")
	assert.Equal(t, true, alert.Event.Fields["bool_field"])

	assert.IsType(t, []string{}, alert.Event.Fields["array_field"], "Array type must be preserved")
	assert.Equal(t, []string{"item1", "item2", "item3"}, alert.Event.Fields["array_field"])

	assert.IsType(t, map[string]interface{}{}, alert.Event.Fields["map_field"], "Map type must be preserved")
	nestedMap := alert.Event.Fields["map_field"].(map[string]interface{})
	assert.Equal(t, "value", nestedMap["nested"])

	assert.Nil(t, alert.Event.Fields["nil_field"], "Nil value must be preserved")

	t.Log("✓ VERIFIED: All data types preserved correctly")
}

// TASK 102: Tests for Alert Disposition functionality

func TestNewAlert_InitializesDisposition(t *testing.T) {
	// TASK 102: Verify NewAlert initializes disposition to undetermined
	testRaw, _ := json.Marshal("test event")
	event := &Event{
		EventID:   "evt-disposition-init",
		Timestamp: time.Now().UTC(),
		RawData:   testRaw,
		Fields:    map[string]interface{}{},
	}

	alert, err := NewAlert("rule-001", "evt-001", "medium", event)
	require.NoError(t, err)
	require.NotNil(t, alert)

	assert.Equal(t, DispositionUndetermined, alert.Disposition,
		"New alerts must initialize with DispositionUndetermined")
	assert.Empty(t, alert.DispositionReason, "DispositionReason should be empty initially")
	assert.Nil(t, alert.DispositionSetAt, "DispositionSetAt should be nil initially")
	assert.Empty(t, alert.DispositionSetBy, "DispositionSetBy should be empty initially")
	assert.Empty(t, alert.InvestigationID, "InvestigationID should be empty initially")
}

func TestAlertDisposition_IsValid(t *testing.T) {
	tests := []struct {
		name        string
		disposition AlertDisposition
		want        bool
	}{
		{"undetermined is valid", DispositionUndetermined, true},
		{"true_positive is valid", DispositionTruePositive, true},
		{"false_positive is valid", DispositionFalsePositive, true},
		{"benign is valid", DispositionBenign, true},
		{"suspicious is valid", DispositionSuspicious, true},
		{"inconclusive is valid", DispositionInconclusive, true},
		{"empty is invalid", AlertDisposition(""), false},
		{"invalid_value is invalid", AlertDisposition("invalid_value"), false},
		{"TRUE_POSITIVE (wrong case) is invalid", AlertDisposition("TRUE_POSITIVE"), false},
		{"True_Positive (mixed case) is invalid", AlertDisposition("True_Positive"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.disposition.IsValid()
			assert.Equal(t, tt.want, got,
				"AlertDisposition(%q).IsValid() = %v, want %v", tt.disposition, got, tt.want)
		})
	}
}

func TestAlertDisposition_String(t *testing.T) {
	tests := []struct {
		disposition AlertDisposition
		want        string
	}{
		{DispositionUndetermined, "undetermined"},
		{DispositionTruePositive, "true_positive"},
		{DispositionFalsePositive, "false_positive"},
		{DispositionBenign, "benign"},
		{DispositionSuspicious, "suspicious"},
		{DispositionInconclusive, "inconclusive"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.disposition.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsValidDisposition(t *testing.T) {
	// Test valid disposition strings
	validDispositions := []string{
		"undetermined",
		"true_positive",
		"false_positive",
		"benign",
		"suspicious",
		"inconclusive",
	}

	for _, d := range validDispositions {
		assert.True(t, IsValidDisposition(d),
			"IsValidDisposition(%q) should return true", d)
	}

	// Test invalid disposition strings
	invalidDispositions := []string{
		"",
		"invalid",
		"UNDETERMINED",
		"True_Positive",
		"confirmed",
		"resolved",
		"unknown",
	}

	for _, d := range invalidDispositions {
		assert.False(t, IsValidDisposition(d),
			"IsValidDisposition(%q) should return false", d)
	}
}

func TestValidDispositions_ReturnsAllValues(t *testing.T) {
	dispositions := ValidDispositions()

	expectedCount := 6
	assert.Len(t, dispositions, expectedCount,
		"ValidDispositions() should return %d values", expectedCount)

	// Verify all expected dispositions are present
	expected := map[AlertDisposition]bool{
		DispositionUndetermined:  false,
		DispositionTruePositive:  false,
		DispositionFalsePositive: false,
		DispositionBenign:        false,
		DispositionSuspicious:    false,
		DispositionInconclusive:  false,
	}

	for _, d := range dispositions {
		if _, exists := expected[d]; exists {
			expected[d] = true
		}
	}

	for d, found := range expected {
		assert.True(t, found, "ValidDispositions() should include %q", d)
	}
}

func TestAlert_DispositionFieldsCanBeSet(t *testing.T) {
	// TASK 102: Verify disposition fields can be set on alert
	testRaw2, _ := json.Marshal("test event")
	event := &Event{
		EventID:   "evt-disposition-set",
		Timestamp: time.Now().UTC(),
		RawData:   testRaw2,
		Fields:    map[string]interface{}{},
	}

	alert, err := NewAlert("rule-001", "evt-001", "high", event)
	require.NoError(t, err)
	require.NotNil(t, alert)

	// Set disposition fields
	now := time.Now().UTC()
	alert.Disposition = DispositionTruePositive
	alert.DispositionReason = "Confirmed malicious activity from known threat actor"
	alert.DispositionSetAt = &now
	alert.DispositionSetBy = "analyst@company.com"
	alert.InvestigationID = "inv-12345"

	// Verify fields are set correctly
	assert.Equal(t, DispositionTruePositive, alert.Disposition)
	assert.Equal(t, "Confirmed malicious activity from known threat actor", alert.DispositionReason)
	assert.NotNil(t, alert.DispositionSetAt)
	assert.Equal(t, now, *alert.DispositionSetAt)
	assert.Equal(t, "analyst@company.com", alert.DispositionSetBy)
	assert.Equal(t, "inv-12345", alert.InvestigationID)
}
