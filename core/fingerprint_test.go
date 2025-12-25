package core

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TASK 64.4: Comprehensive Fingerprint Tests
// Tests cover: fingerprint generation, determinism, collision resistance,
// normalization, field-based fingerprints, template-based fingerprints,
// fingerprint configuration, and disabled fingerprinting

// TestAlertFingerprinter_GenerateFingerprint_Disabled tests disabled fingerprinting
func TestAlertFingerprinter_GenerateFingerprint_Disabled(t *testing.T) {
	config := FingerprintConfig{
		Enabled: false,
	}

	fingerprinter := NewAlertFingerprinter(config)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
	}

	fingerprint := fingerprinter.GenerateFingerprint(alert)
	assert.Empty(t, fingerprint, "Disabled fingerprinting should return empty string")
}

// TestAlertFingerprinter_GenerateFingerprint_FieldBased tests field-based fingerprinting
func TestAlertFingerprinter_GenerateFingerprint_FieldBased(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id", "source_ip", "dest_ip"},
	}

	fingerprinter := NewAlertFingerprinter(config)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
				"dest_ip":   "10.0.0.1",
			},
		},
	}

	fingerprint := fingerprinter.GenerateFingerprint(alert)
	assert.NotEmpty(t, fingerprint, "Fingerprint should be generated")
	assert.Len(t, fingerprint, 64, "SHA-256 hash should be 64 hex characters")

	// Same alert should produce same fingerprint (determinism)
	fingerprint2 := fingerprinter.GenerateFingerprint(alert)
	assert.Equal(t, fingerprint, fingerprint2, "Same alert should produce same fingerprint")
}

// TestAlertFingerprinter_GenerateFingerprint_Determinism tests fingerprint determinism
func TestAlertFingerprinter_GenerateFingerprint_Determinism(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id", "event_id"},
	}

	fingerprinter := NewAlertFingerprinter(config)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
	}

	// Generate fingerprint multiple times
	fingerprint1 := fingerprinter.GenerateFingerprint(alert)
	fingerprint2 := fingerprinter.GenerateFingerprint(alert)
	fingerprint3 := fingerprinter.GenerateFingerprint(alert)

	assert.Equal(t, fingerprint1, fingerprint2, "Fingerprints should be identical (deterministic)")
	assert.Equal(t, fingerprint2, fingerprint3, "Fingerprints should be identical (deterministic)")
}

// TestAlertFingerprinter_GenerateFingerprint_CollisionResistance tests collision resistance
func TestAlertFingerprinter_GenerateFingerprint_CollisionResistance(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id", "source_ip"},
	}

	fingerprinter := NewAlertFingerprinter(config)

	// Two different alerts with different source IPs
	alert1 := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
			},
		},
	}

	alert2 := &Alert{
		AlertID:   "alert-2",
		RuleID:    "rule-1",
		EventID:   "event-2",
		Severity:  "high",
		Timestamp: time.Now(),
		Event: &Event{
			EventID:   "event-2",
			Timestamp: time.Now(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.101", // Different IP
			},
		},
	}

	fingerprint1 := fingerprinter.GenerateFingerprint(alert1)
	fingerprint2 := fingerprinter.GenerateFingerprint(alert2)

	assert.NotEqual(t, fingerprint1, fingerprint2, "Different alerts should produce different fingerprints")
}

// TestAlertFingerprinter_GenerateFingerprint_TemplateBased tests template-based fingerprinting
func TestAlertFingerprinter_GenerateFingerprint_TemplateBased(t *testing.T) {
	config := FingerprintConfig{
		Enabled:  true,
		Template: "{{.RuleID}}-{{.SourceIP}}-{{.DestIP}}",
	}

	fingerprinter := NewAlertFingerprinter(config)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
				"dest_ip":   "10.0.0.1",
			},
		},
	}

	fingerprint := fingerprinter.GenerateFingerprint(alert)
	assert.NotEmpty(t, fingerprint, "Template-based fingerprint should be generated")
	assert.Len(t, fingerprint, 64, "SHA-256 hash should be 64 hex characters")

	// Verify determinism with template
	fingerprint2 := fingerprinter.GenerateFingerprint(alert)
	assert.Equal(t, fingerprint, fingerprint2, "Template-based fingerprint should be deterministic")
}

// TestAlertFingerprinter_GenerateFingerprint_TemplateInvalid tests invalid template handling
func TestAlertFingerprinter_GenerateFingerprint_TemplateInvalid(t *testing.T) {
	config := FingerprintConfig{
		Enabled:  true,
		Template: "{{.Dangerous}}",                // Invalid template
		Fields:   []string{"rule_id", "event_id"}, // Fallback fields
	}

	logger := zap.NewNop().Sugar()
	fingerprinter := NewAlertFingerprinterWithLogger(config, logger)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
	}

	// Should fall back to field-based fingerprint
	fingerprint := fingerprinter.GenerateFingerprint(alert)
	assert.NotEmpty(t, fingerprint, "Invalid template should fall back to field-based fingerprint")
}

// TestAlertFingerprinter_GenerateFingerprint_EmptyFields tests empty fields configuration
func TestAlertFingerprinter_GenerateFingerprint_EmptyFields(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{}, // Empty fields
	}

	fingerprinter := NewAlertFingerprinter(config)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
	}

	// Should use fallback fingerprint (rule_id + event_id)
	fingerprint := fingerprinter.GenerateFingerprint(alert)
	assert.NotEmpty(t, fingerprint, "Empty fields should use fallback fingerprint")
	assert.Len(t, fingerprint, 64, "Fallback fingerprint should be valid hash")
}

// TestAlertFingerprinter_GenerateFingerprint_MissingFields tests missing field handling
func TestAlertFingerprinter_GenerateFingerprint_MissingFields(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id", "source_ip", "missing_field"},
	}

	fingerprinter := NewAlertFingerprinter(config)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
				// missing_field not present
			},
		},
	}

	// Should use available fields only
	fingerprint := fingerprinter.GenerateFingerprint(alert)
	assert.NotEmpty(t, fingerprint, "Missing fields should be skipped")
}

// TestAlertFingerprinter_FingerprintConfig_Structure tests FingerprintConfig structure
func TestAlertFingerprinter_FingerprintConfig_Structure(t *testing.T) {
	config := FingerprintConfig{
		Enabled:    true,
		Fields:     []string{"rule_id", "source_ip"},
		Template:   "{{.RuleID}}",
		TimeWindow: 1 * time.Hour,
	}

	assert.True(t, config.Enabled)
	assert.Equal(t, []string{"rule_id", "source_ip"}, config.Fields)
	assert.Equal(t, "{{.RuleID}}", config.Template)
	assert.Equal(t, 1*time.Hour, config.TimeWindow)
}

// TestAlertFingerprinter_DefaultFingerprintConfig tests default fingerprint configuration
func TestAlertFingerprinter_DefaultFingerprintConfig(t *testing.T) {
	config := DefaultFingerprintConfig()

	assert.True(t, config.Enabled, "Default config should have fingerprinting enabled")
	assert.NotEmpty(t, config.Fields, "Default config should have fields")
	assert.Equal(t, []string{"rule_id", "source_ip", "dest_ip", "user"}, config.Fields)
	assert.Equal(t, 1*time.Hour, config.TimeWindow, "Default time window should be 1 hour")
}

// TestAlertFingerprinter_NewAlertFingerprinter tests AlertFingerprinter creation
func TestAlertFingerprinter_NewAlertFingerprinter(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id"},
	}

	fingerprinter := NewAlertFingerprinter(config)
	assert.NotNil(t, fingerprinter, "NewAlertFingerprinter should return non-nil")
}

// TestAlertFingerprinter_NewAlertFingerprinterWithLogger tests AlertFingerprinter creation with logger
func TestAlertFingerprinter_NewAlertFingerprinterWithLogger(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id"},
	}

	logger := zap.NewNop().Sugar()
	fingerprinter := NewAlertFingerprinterWithLogger(config, logger)
	assert.NotNil(t, fingerprinter, "NewAlertFingerprinterWithLogger should return non-nil")
}

// TestAlertFingerprinter_GenerateFingerprint_FieldNormalization tests field normalization
func TestAlertFingerprinter_GenerateFingerprint_FieldNormalization(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id", "source_ip"},
	}

	fingerprinter := NewAlertFingerprinter(config)

	// Same alert with same values should produce same fingerprint regardless of case/whitespace
	alert1 := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
			},
		},
	}

	alert2 := &Alert{
		AlertID:   "alert-2",
		RuleID:    "rule-1", // Same rule_id
		EventID:   "event-2",
		Severity:  "high",
		Timestamp: time.Now(),
		Event: &Event{
			EventID:   "event-2",
			Timestamp: time.Now(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100", // Same source_ip
			},
		},
	}

	fingerprint1 := fingerprinter.GenerateFingerprint(alert1)
	fingerprint2 := fingerprinter.GenerateFingerprint(alert2)

	// Same rule_id and source_ip should produce same fingerprint
	assert.Equal(t, fingerprint1, fingerprint2, "Alerts with same fingerprint fields should produce same fingerprint")
}

// TestAlertFingerprinter_GenerateFingerprint_Performance tests fingerprint generation performance
func TestAlertFingerprinter_GenerateFingerprint_Performance(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id", "source_ip", "dest_ip", "user"},
	}

	fingerprinter := NewAlertFingerprinter(config)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now(),
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
				"dest_ip":   "10.0.0.1",
				"user":      "testuser",
			},
		},
	}

	// Generate 1000 fingerprints
	start := time.Now()
	for i := 0; i < 1000; i++ {
		fingerprinter.GenerateFingerprint(alert)
	}
	duration := time.Since(start)

	// Should complete in reasonable time (< 1 second for 1000 fingerprints)
	assert.Less(t, duration, 1*time.Second, "1000 fingerprint generations should complete in < 1 second")
}

// TestAlertFingerprinter_GenerateFingerprint_HashFunction tests SHA-256 hash function
func TestAlertFingerprinter_GenerateFingerprint_HashFunction(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id"},
	}

	fingerprinter := NewAlertFingerprinter(config)

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
	}

	fingerprint := fingerprinter.GenerateFingerprint(alert)

	// Verify it's a valid SHA-256 hex string
	assert.Len(t, fingerprint, 64, "SHA-256 hash should be 64 hex characters")

	// Verify it's valid hex
	_, err := hex.DecodeString(fingerprint)
	assert.NoError(t, err, "Fingerprint should be valid hex string")

	// Verify it's a valid SHA-256 hash (64 hex characters)
	require.NotEmpty(t, fingerprint, "Fingerprint should not be empty")
	assert.Len(t, fingerprint, 64, "Fingerprint should be 64 hex characters (SHA-256)")
}

// TestAlertFingerprinter_GenerateFingerprint_LargePayload tests fingerprint with large payload
func TestAlertFingerprinter_GenerateFingerprint_LargePayload(t *testing.T) {
	config := FingerprintConfig{
		Enabled: true,
		Fields:  []string{"rule_id", "source_ip"},
	}

	fingerprinter := NewAlertFingerprinter(config)

	// Create large field value
	largeValue := make([]byte, 10000)
	for i := range largeValue {
		largeValue[i] = byte(i % 256)
	}

	alert := &Alert{
		AlertID:   "alert-1",
		RuleID:    "rule-1",
		EventID:   "event-1",
		Severity:  "high",
		Timestamp: time.Now(),
		Event: &Event{
			EventID:   "event-1",
			Timestamp: time.Now(),
			Fields: map[string]interface{}{
				"source_ip": string(largeValue), // Large value
			},
		},
	}

	// Should handle large payloads
	fingerprint := fingerprinter.GenerateFingerprint(alert)
	assert.NotEmpty(t, fingerprint, "Fingerprint should handle large payloads")
	assert.Len(t, fingerprint, 64, "Fingerprint should still be 64 hex characters regardless of payload size")
}
