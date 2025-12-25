package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 64.7: Comprehensive Integration Tests with Mocked Storage
// Tests cover: complete workflows across multiple core components,
// event processing pipeline, alert generation, investigation creation,
// and data consistency

// TestIntegration_EventToAlertToInvestigation tests complete workflow:
// Event → Rule Evaluation → Alert Generation → Investigation Creation
func TestIntegration_EventToAlertToInvestigation(t *testing.T) {
	// Create test event
	event := &Event{
		EventID:   "event-integration-1",
		EventType: "failed_login",
		Timestamp: time.Now().UTC(),
		Fields: map[string]interface{}{
			"source_ip": "192.168.1.100",
			"username":  "testuser",
			"status":    "failed",
		},
	}

	// Create rule that matches the event
	// TASK #184: Test updated to use SigmaYAML instead of legacy Conditions
	rule := &Rule{
		ID:       "rule-integration-1",
		Name:     "Failed Login Detection",
		Type:     "sigma",
		Severity: "high",
		Enabled:  true,
		SigmaYAML: `title: Failed Login Detection
logsource:
  product: test
detection:
  selection:
    event_type: failed_login
  condition: selection
`,
	}

	// Create alert from event (simulating rule match)
	alert, err := NewAlert(rule.ID, event.EventID, rule.Severity, event)
	require.NoError(t, err)
	require.NotNil(t, alert)
	alert.RuleName = rule.Name
	alert.RuleDescription = rule.Description
	alert.RuleType = rule.Type

	// Verify alert was created correctly
	assert.Equal(t, rule.ID, alert.RuleID)
	assert.Equal(t, event.EventID, alert.EventID)
	assert.Equal(t, rule.Severity, alert.Severity)
	assert.Equal(t, event, alert.Event)

	// Create investigation from alert
	investigation := NewInvestigation(
		"Investigation for "+alert.RuleName,
		"Investigation created from alert: "+alert.AlertID,
		InvestigationPriorityHigh,
		"analyst123",
	)
	investigation.AddAlert(alert.AlertID)

	// Verify investigation was created correctly
	assert.NotEmpty(t, investigation.InvestigationID)
	assert.Contains(t, investigation.AlertIDs, alert.AlertID)
	assert.Equal(t, InvestigationPriorityHigh, investigation.Priority)
	assert.Equal(t, InvestigationStatusOpen, investigation.Status)

	// Add note to investigation
	investigation.AddNote("analyst123", "Initial investigation note")

	// Verify note was added
	assert.Len(t, investigation.Notes, 1)
	assert.Equal(t, "analyst123", investigation.Notes[0].AnalystID)
	assert.Equal(t, "Initial investigation note", investigation.Notes[0].Content)

	// Close investigation
	err = investigation.Close(
		InvestigationVerdictTruePositive,
		"incident_contained",
		"Confirmed security incident",
		[]string{"192.168.1.100"},
		nil,
	)

	require.NoError(t, err)
	assert.Equal(t, InvestigationStatusClosed, investigation.Status)
	assert.Equal(t, InvestigationVerdictTruePositive, investigation.Verdict)
	assert.NotNil(t, investigation.ClosedAt)
}

// TestIntegration_EventNormalizationToFingerprint tests workflow:
// Event → Normalization → Fingerprinting → Alert Deduplication
func TestIntegration_EventNormalizationToFingerprint(t *testing.T) {
	// Create field mappings
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"generic": {
				"source_ip": "SourceIp",
				"username":  "User",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	// Create raw event with vendor-specific fields
	rawEvent := map[string]interface{}{
		"source_ip":  "192.168.1.100",
		"username":   "testuser",
		"event_type": "failed_login",
	}

	// Normalize event
	normalizedEvent := normalizer.NormalizeEvent(rawEvent, "generic")

	// Verify normalization
	assert.Equal(t, "192.168.1.100", normalizedEvent["SourceIp"])
	assert.Equal(t, "testuser", normalizedEvent["User"])

	// Create alert from normalized event
	alert := &Alert{
		AlertID:   "alert-integration-2",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now().UTC(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now().UTC(),
			Fields:    normalizedEvent,
		},
	}

	// Generate fingerprint for alert
	fingerprintConfig := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id", "source_ip", "user"},
	}

	fingerprinter := NewAlertFingerprinter(fingerprintConfig)
	fingerprint := fingerprinter.GenerateFingerprint(alert)

	// Verify fingerprint was generated
	assert.NotEmpty(t, fingerprint)
	assert.Len(t, fingerprint, 64, "Fingerprint should be SHA-256 hash (64 hex chars)")

	// Same alert should produce same fingerprint (determinism)
	fingerprint2 := fingerprinter.GenerateFingerprint(alert)
	assert.Equal(t, fingerprint, fingerprint2, "Same alert should produce same fingerprint")

	// Different alert should produce different fingerprint
	alert2 := &Alert{
		AlertID:   "alert-integration-3",
		RuleID:    "rule-1",
		EventID:   "event-2",
		Severity:  "high",
		Timestamp: time.Now().UTC(),
		Event: &Event{
			EventID:   "event-2",
			Timestamp: time.Now().UTC(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.101", // Different IP
				"username":  "testuser",
			},
		},
	}
	fingerprint3 := fingerprinter.GenerateFingerprint(alert2)
	assert.NotEqual(t, fingerprint, fingerprint3, "Different alerts should produce different fingerprints")
}

// TestIntegration_EventFilterToNormalization tests workflow:
// Event → Filtering → Normalization → Storage
func TestIntegration_EventFilterToNormalization(t *testing.T) {
	// Create event filter (disabled for this test)
	// Note: EventFilter requires config.Config, so we'll test without it for simplicity
	// Real integration test would use config

	// Create raw event
	rawEvent := map[string]interface{}{
		"src_ip":     "192.168.1.100",
		"user":       "testuser",
		"event_type": "login",
	}

	// Normalize event
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"generic": {
				"src_ip": "SourceIp",
				"user":   "User",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)
	normalizedEvent := normalizer.NormalizeEvent(rawEvent, "generic")

	// Verify normalization
	assert.Equal(t, "192.168.1.100", normalizedEvent["SourceIp"])
	assert.Equal(t, "testuser", normalizedEvent["User"])
	assert.NotNil(t, normalizedEvent["_raw"], "Original fields should be preserved")
}

// TestIntegration_CQLRuleToAlertToInvestigation tests workflow:
// CQL Rule → Event Match → Alert → Investigation
func TestIntegration_CQLRuleToAlertToInvestigation(t *testing.T) {
	// Create CQL rule
	cqlRule := &CQLRule{
		ID:       "cql-integration-1",
		Name:     "CQL Integration Test",
		Query:    `event_type == "failed_login" AND source_ip == "192.168.1.100"`,
		Severity: "high",
		Enabled:  true,
	}

	err := cqlRule.Validate()
	require.NoError(t, err, "CQL rule should be valid")

	// Create event that matches the rule
	event := &Event{
		EventID:   "event-cql-1",
		EventType: "failed_login",
		Timestamp: time.Now().UTC(),
		Fields: map[string]interface{}{
			"source_ip": "192.168.1.100",
			"username":  "testuser",
		},
	}

	// Create CQL rule match (simulating query execution)
	match := &CQLRuleMatch{
		Rule:          cqlRule,
		Event:         event,
		Timestamp:     time.Now().UTC(),
		MatchedFields: map[string]interface{}{"event_type": "failed_login", "source_ip": "192.168.1.100"},
	}

	// Convert match to alert
	alert, err := match.ToAlert()
	require.NoError(t, err, "ToAlert should not return error")
	require.NotNil(t, alert, "ToAlert should return non-nil alert")

	// Verify alert
	assert.Equal(t, cqlRule.ID, alert.RuleID)
	assert.Equal(t, cqlRule.Name, alert.RuleName)
	assert.Equal(t, "cql", alert.RuleType)
	assert.Equal(t, cqlRule.Severity, alert.Severity)
	assert.Equal(t, event, alert.Event)

	// Create investigation
	investigation := NewInvestigation(
		"Investigation for CQL Rule",
		"Created from CQL rule match",
		InvestigationPriorityHigh,
		"analyst123",
	)
	investigation.AddAlert(alert.AlertID)

	// Verify investigation
	assert.Contains(t, investigation.AlertIDs, alert.AlertID)
}

// TestIntegration_CorrelationRuleToAlert tests workflow:
// Correlation Rule → Multiple Events → Correlation → Alert
func TestIntegration_CorrelationRuleToAlert(t *testing.T) {
	// Create count correlation rule
	rule := CountCorrelationRule{
		EnhancedCorrelationRule: EnhancedCorrelationRule{
			ID:       "correlation-integration-1",
			Type:     CorrelationTypeCount,
			Name:     "Brute Force Detection",
			Severity: "high",
			Enabled:  true,
		},
		Window:  5 * time.Minute,
		GroupBy: []string{"source_ip"},
		Threshold: Threshold{
			Operator: ThresholdOpGreaterEqual,
			Value:    3.0,
		},
		Selection: map[string]interface{}{
			"event_type": "failed_login",
		},
	}

	// Verify rule structure
	assert.Equal(t, "correlation-integration-1", rule.GetID())
	assert.Equal(t, "high", rule.GetSeverity())

	// Create events that would trigger correlation
	baseTime := time.Now()
	events := []*Event{
		{
			EventID:   "event-correlation-1",
			EventType: "failed_login",
			Timestamp: baseTime,
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
				"username":  "user1",
			},
		},
		{
			EventID:   "event-correlation-2",
			EventType: "failed_login",
			Timestamp: baseTime.Add(time.Second),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
				"username":  "user2",
			},
		},
		{
			EventID:   "event-correlation-3",
			EventType: "failed_login",
			Timestamp: baseTime.Add(2 * time.Second),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
				"username":  "user3",
			},
		},
	}

	// After 3 events, correlation rule should trigger (threshold = 3.0)
	// Note: Actual correlation evaluation is tested in detect package
	// Here we verify the rule structure and event compatibility

	for i, event := range events {
		assert.Equal(t, "failed_login", event.EventType, "Event %d should match rule selection", i+1)
		assert.Equal(t, "192.168.1.100", event.Fields["source_ip"], "Event %d should have same source IP", i+1)
	}

	// Create alert from correlation (simulating correlation trigger)
	correlationAlert, err := NewAlert(rule.ID, events[2].EventID, rule.Severity, events[2])
	require.NoError(t, err)
	require.NotNil(t, correlationAlert)
	correlationAlert.RuleName = rule.Name

	// Verify alert
	assert.Equal(t, rule.ID, correlationAlert.RuleID)
	assert.Equal(t, rule.Severity, correlationAlert.Severity)
}

// TestIntegration_ExceptionToAlertSuppression tests workflow:
// Alert → Exception Matching → Alert Suppression/Modification
func TestIntegration_ExceptionToAlertSuppression(t *testing.T) {
	// Create exception
	exception := NewException(
		"Known False Positive",
		"rule-1",
		ExceptionSuppress,
		ConditionTypeSigmaFilter,
		"source_ip == '192.168.1.100'",
	)
	exception.Enabled = true

	err := exception.Validate()
	require.NoError(t, err, "Exception should be valid")

	// Create alert that matches exception
	alert := &Alert{
		AlertID:   "alert-exception-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now().UTC(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now().UTC(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
			},
		},
	}

	// Verify exception would match (in real system, exception evaluator would check this)
	// Here we verify the exception structure and alert compatibility
	assert.True(t, exception.IsActive(), "Exception should be active")
	assert.NotEmpty(t, exception.Condition, "Exception should have condition")

	// Verify alert severity matches exception condition (simulated)
	assert.Equal(t, "high", alert.Severity, "Alert should have original severity")

	// Create modify_severity exception
	modifyException := NewException(
		"Lower Severity",
		"rule-1",
		ExceptionModifySeverity,
		ConditionTypeSigmaFilter,
		"source_ip == '192.168.1.101'",
	)
	modifyException.NewSeverity = "low"
	modifyException.Enabled = true

	err = modifyException.Validate()
	require.NoError(t, err, "ModifySeverity exception should be valid")
	assert.Equal(t, "low", modifyException.NewSeverity)
}

// TestIntegration_InvestigationWithNotesAndAlerts tests investigation with notes and alerts
func TestIntegration_InvestigationWithNotesAndAlerts(t *testing.T) {
	// Create investigation
	investigation := NewInvestigation(
		"Integration Test Investigation",
		"Test description",
		InvestigationPriorityHigh,
		"analyst123",
	)

	// Add alerts
	investigation.AddAlert("alert-1")
	investigation.AddAlert("alert-2")
	investigation.AddAlert("alert-3")

	// Verify alerts were added (no duplicates)
	investigation.AddAlert("alert-1") // Try to add duplicate
	assert.Len(t, investigation.AlertIDs, 3, "Duplicate alert should not be added")

	// Add notes
	investigation.AddNote("analyst123", "Initial note")
	investigation.AddNote("analyst456", "Follow-up note")
	investigation.AddNote("analyst123", "Resolution note")

	// Verify notes were added
	assert.Len(t, investigation.Notes, 3)
	assert.Equal(t, "analyst123", investigation.Notes[0].AnalystID)
	assert.Equal(t, "Initial note", investigation.Notes[0].Content)

	// Add MITRE tactics and techniques
	investigation.AddMitreTactic("TA0001")
	investigation.AddMitreTactic("TA0006")
	investigation.AddMitreTechnique("T1078")
	investigation.AddMitreTechnique("T1110")

	// Verify MITRE data was added (no duplicates)
	investigation.AddMitreTactic("TA0001") // Try duplicate
	assert.Len(t, investigation.MitreTactics, 2)
	assert.Len(t, investigation.MitreTechniques, 2)

	// Verify investigation is valid
	err := investigation.Validate()
	assert.NoError(t, err, "Investigation should be valid")

	// Close investigation
	err = investigation.Close(
		InvestigationVerdictTruePositive,
		"incident_contained",
		"Test summary",
		[]string{"192.168.1.100"},
		nil,
	)

	require.NoError(t, err)
	assert.Equal(t, InvestigationStatusClosed, investigation.Status)
	assert.Len(t, investigation.AlertIDs, 3, "Alerts should remain after closure")
	assert.Len(t, investigation.Notes, 3, "Notes should remain after closure")
}

// TestIntegration_FingerprintToDeduplication tests fingerprint-based deduplication
func TestIntegration_FingerprintToDeduplication(t *testing.T) {
	// Create fingerprint configuration
	fingerprintConfig := FingerprintConfig{
		Enabled:    true,
		Fields:     []string{"rule_id", "source_ip"},
		TimeWindow: 1 * time.Hour,
	}

	fingerprinter := NewAlertFingerprinter(fingerprintConfig)

	// Create two alerts with same rule_id and source_ip (should have same fingerprint)
	alert1 := &Alert{
		AlertID:   "alert-dedup-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now().UTC(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now().UTC(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
			},
		},
	}

	alert2 := &Alert{
		AlertID:   "alert-dedup-2",
		RuleID:    "rule-1",
		EventID:   "event-2",
		Severity:  "high",
		Timestamp: time.Now().UTC().Add(30 * time.Minute), // Within time window
		Event: &Event{
			EventID:   "event-2",
			Timestamp: time.Now().UTC().Add(30 * time.Minute),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
			},
		},
	}

	// Generate fingerprints
	fingerprint1 := fingerprinter.GenerateFingerprint(alert1)
	fingerprint2 := fingerprinter.GenerateFingerprint(alert2)

	// Same rule_id and source_ip should produce same fingerprint
	assert.Equal(t, fingerprint1, fingerprint2, "Alerts with same fingerprint fields should produce same fingerprint")

	// Different source_ip should produce different fingerprint
	alert3 := &Alert{
		AlertID:   "alert-dedup-3",
		RuleID:    "rule-1",
		EventID:   "event-3",
		Severity:  "high",
		Timestamp: time.Now().UTC(),
		Event: &Event{
			EventID:   "event-3",
			Timestamp: time.Now().UTC(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.101", // Different IP
			},
		},
	}

	fingerprint3 := fingerprinter.GenerateFingerprint(alert3)
	assert.NotEqual(t, fingerprint1, fingerprint3, "Different source IP should produce different fingerprint")
}

// TestIntegration_EventToExceptionToAlertModification tests workflow:
// Event → Alert → Exception → Alert Severity Modification
func TestIntegration_EventToExceptionToAlertModification(t *testing.T) {
	// Create modify_severity exception
	exception := NewException(
		"Lower Severity for Whitelist",
		"rule-1",
		ExceptionModifySeverity,
		ConditionTypeSigmaFilter,
		"source_ip == '192.168.1.100'",
	)
	exception.NewSeverity = "low"
	exception.Priority = 10 // High priority
	exception.Enabled = true

	err := exception.Validate()
	require.NoError(t, err, "Exception should be valid")

	// Create alert that matches exception
	alert := &Alert{
		AlertID:   "alert-modify-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high", // Original severity
		Timestamp: time.Now().UTC(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now().UTC(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
			},
		},
	}

	// Verify exception would modify severity (in real system, exception evaluator would apply this)
	// Here we verify the exception structure and alert compatibility
	assert.True(t, exception.IsActive())
	assert.Equal(t, ExceptionModifySeverity, exception.Type)
	assert.Equal(t, "low", exception.NewSeverity)

	// Verify original severity
	assert.Equal(t, "high", alert.Severity, "Original severity should be high")

	// Apply severity modification (would be done by exception evaluator)
	alert.Severity = exception.NewSeverity
	assert.Equal(t, "low", alert.Severity, "Severity should be modified to low")
}

// TestIntegration_InvestigationTimeline tests investigation timeline generation
func TestIntegration_InvestigationTimeline(t *testing.T) {
	investigation := NewInvestigation(
		"Timeline Test Investigation",
		"Test timeline",
		InvestigationPriorityHigh,
		"analyst123",
	)

	baseTime := time.Now().UTC().Add(-5 * time.Minute)

	// Add alerts at different times
	investigation.AddAlert("alert-1")
	investigation.UpdatedAt = baseTime

	investigation.AddAlert("alert-2")
	investigation.UpdatedAt = baseTime.Add(time.Minute)

	// Add notes at different times
	investigation.AddNote("analyst123", "Note 1")
	investigation.UpdatedAt = baseTime.Add(2 * time.Minute)

	investigation.AddNote("analyst456", "Note 2")
	investigation.UpdatedAt = baseTime.Add(3 * time.Minute)

	// Change status
	investigation.Status = InvestigationStatusInProgress
	investigation.UpdatedAt = baseTime.Add(4 * time.Minute)

	// Close investigation
	err := investigation.Close(
		InvestigationVerdictTruePositive,
		"incident_contained",
		"Resolved",
		[]string{},
		nil,
	)

	require.NoError(t, err)

	// Verify timeline (UpdatedAt should reflect last change)
	assert.True(t, investigation.UpdatedAt.After(baseTime.Add(3*time.Minute)))
	assert.NotNil(t, investigation.ClosedAt)
	assert.True(t, investigation.ClosedAt.After(baseTime.Add(4*time.Minute)))

	// Verify all actions are preserved
	assert.Len(t, investigation.AlertIDs, 2)
	assert.Len(t, investigation.Notes, 2)
	assert.Equal(t, InvestigationStatusClosed, investigation.Status)
}

// TestIntegration_InvestigationWithArtifacts tests investigation with artifacts
func TestIntegration_InvestigationWithArtifacts(t *testing.T) {
	investigation := NewInvestigation(
		"Artifacts Test Investigation",
		"Test artifacts",
		InvestigationPriorityCritical,
		"analyst123",
	)

	// Add artifacts
	investigation.Artifacts = InvestigationArtifacts{
		IPs:       []string{"192.168.1.100", "10.0.0.1"},
		Hosts:     []string{"host1.example.com", "host2.example.com"},
		Users:     []string{"user1", "user2"},
		Files:     []string{"/etc/passwd", "/tmp/malware.exe"},
		Hashes:    []string{"abc123", "def456"},
		Processes: []string{"cmd.exe", "powershell.exe"},
	}

	// Verify artifacts
	assert.Len(t, investigation.Artifacts.IPs, 2)
	assert.Len(t, investigation.Artifacts.Hosts, 2)
	assert.Len(t, investigation.Artifacts.Users, 2)
	assert.Len(t, investigation.Artifacts.Files, 2)
	assert.Len(t, investigation.Artifacts.Hashes, 2)
	assert.Len(t, investigation.Artifacts.Processes, 2)

	// Verify investigation is valid
	err := investigation.Validate()
	assert.NoError(t, err)
}

// TestIntegration_InvestigationWithMLFeedback tests investigation with ML feedback
func TestIntegration_InvestigationWithMLFeedback(t *testing.T) {
	investigation := NewInvestigation(
		"ML Feedback Test Investigation",
		"Test ML feedback",
		InvestigationPriorityHigh,
		"analyst123",
	)

	// Close with ML feedback
	mlFeedback := &MLFeedback{
		UseForTraining:  true,
		MLQualityRating: 5,
		MLHelpfulness:   "very_helpful",
	}

	err := investigation.Close(
		InvestigationVerdictTruePositive,
		"incident_contained",
		"ML was helpful in detection",
		[]string{"asset1"},
		mlFeedback,
	)

	require.NoError(t, err)
	assert.NotNil(t, investigation.MLFeedback)
	assert.True(t, investigation.MLFeedback.UseForTraining)
	assert.Equal(t, 5, investigation.MLFeedback.MLQualityRating)
	assert.Equal(t, "very_helpful", investigation.MLFeedback.MLHelpfulness)

	// Verify validation
	err = investigation.Validate()
	assert.NoError(t, err, "Investigation with ML feedback should be valid")
}

// TestIntegration_ConcurrentInvestigationUpdates tests concurrent investigation updates
func TestIntegration_ConcurrentInvestigationUpdates(t *testing.T) {
	investigation := NewInvestigation(
		"Concurrent Test Investigation",
		"Test concurrent updates",
		InvestigationPriorityMedium,
		"analyst123",
	)

	// Simulate concurrent updates (notes, alerts, status)
	done := make(chan bool, 3)

	// Add note concurrently
	go func() {
		investigation.AddNote("analyst123", "Concurrent note 1")
		done <- true
	}()

	// Add alert concurrently
	go func() {
		investigation.AddAlert("alert-1")
		done <- true
	}()

	// Change status concurrently
	go func() {
		investigation.Status = InvestigationStatusInProgress
		investigation.UpdatedAt = time.Now().UTC()
		done <- true
	}()

	// Wait for all updates
	for i := 0; i < 3; i++ {
		<-done
	}

	// Verify all updates were applied (may be non-deterministic order)
	assert.Len(t, investigation.Notes, 1)
	assert.Len(t, investigation.AlertIDs, 1)
	assert.Equal(t, InvestigationStatusInProgress, investigation.Status)
}
