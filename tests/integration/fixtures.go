package integration

import (
	"encoding/json"
	"fmt"
	"time"

	"cerberus/core"
	"cerberus/storage"

	"github.com/google/uuid"
)

// TASK 61.1: Test fixtures for integration tests

// GenerateTestEvent creates a test event with optional overrides
func GenerateTestEvent(overrides ...func(*core.Event)) *core.Event {
	event := &core.Event{
		EventID:      uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		IngestedAt:   time.Now().UTC(),
		Source:       "test-source",
		SourceIP:     "192.0.2.1",
		SourceFormat: "json",
		EventType:    "test_event",
		Severity:     "info",
		RawData:      json.RawMessage(`{"message":"Test event message","severity":"info"}`),
		Fields: map[string]interface{}{
			"hostname":    "test-host",
			"username":    "testuser",
			"action":      "test-action",
			"status":      "success",
			"status_code": 200,
			"message":     "Test event message",
		},
	}

	// Apply overrides
	for _, override := range overrides {
		override(event)
	}

	return event
}

// GenerateSyslogEvent creates a test syslog event
func GenerateSyslogEvent(message string, severity string) *core.Event {
	rawSyslog := fmt.Sprintf("<%d>%s %s %s: %s",
		getSyslogPriority(severity),
		time.Now().Format("Jan 2 15:04:05"),
		"test-host",
		"test-service",
		message,
	)
	// Encode syslog string as JSON for proper storage
	rawJSON, _ := json.Marshal(rawSyslog)
	return GenerateTestEvent(
		func(e *core.Event) {
			e.Severity = severity
			e.Source = "syslog"
			e.SourceFormat = "syslog"
			e.RawData = rawJSON
			e.Fields["message"] = message
			e.Fields["syslog_facility"] = "user"
			e.Fields["syslog_severity"] = severity
		},
	)
}

// GenerateCEFEvent creates a test CEF event
func GenerateCEFEvent(cefVersion int, deviceVendor string, deviceProduct string, severity string) *core.Event {
	cefMessage := fmt.Sprintf(
		"CEF:%d|%s|%s|1.0|100|test|%s|src=192.0.2.1",
		cefVersion,
		deviceVendor,
		deviceProduct,
		severity,
	)
	// Encode CEF string as JSON for proper storage
	rawJSON, _ := json.Marshal(cefMessage)

	return GenerateTestEvent(
		func(e *core.Event) {
			e.Severity = severity
			e.Source = "cef"
			e.SourceFormat = "cef"
			e.RawData = rawJSON
			e.Fields["message"] = cefMessage
			e.Fields["cef_version"] = cefVersion
			e.Fields["device_vendor"] = deviceVendor
			e.Fields["device_product"] = deviceProduct
		},
	)
}

// GenerateJSONEvent creates a test JSON event
func GenerateJSONEvent(data map[string]interface{}) *core.Event {
	jsonBytes, _ := json.Marshal(data)

	severity := "info"
	if s, ok := data["severity"].(string); ok {
		severity = s
	}

	return GenerateTestEvent(
		func(e *core.Event) {
			e.Severity = severity
			e.Source = "json"
			e.SourceFormat = "json"
			e.RawData = jsonBytes // json.Marshal returns []byte, directly usable as json.RawMessage
			// Merge all fields from data
			for k, v := range data {
				e.Fields[k] = v
			}
		},
	)
}

// GenerateTestAlert creates a test alert with optional overrides
// Note: Requires an Event to be passed for NewAlert constructor
// Panics if alert creation fails - this is test code, not production
func GenerateTestAlert(event *core.Event, ruleID string, overrides ...func(*core.Alert)) *core.Alert {
	if event == nil {
		event = GenerateTestEvent()
	}

	// TASK 137: Updated to handle NewAlert error return (test code can panic)
	alert, err := core.NewAlert(ruleID, event.EventID, "medium", event)
	if err != nil {
		panic(fmt.Sprintf("GenerateTestAlert: failed to create alert: %v", err))
	}
	alert.RuleName = "Test Rule"

	// Apply overrides
	for _, override := range overrides {
		override(alert)
	}

	return alert
}

// GenerateTestRule creates a test detection rule
// TASK 176: Updated to use SIGMA YAML format instead of legacy Conditions
func GenerateTestRule(name string, enabled bool, overrides ...func(*core.Rule)) *core.Rule {
	ruleID := uuid.New().String()

	// Generate SIGMA YAML that matches the original logic (severity = high)
	sigmaYAML := fmt.Sprintf(`title: %s
id: %s
status: experimental
logsource:
  category: test
detection:
  selection:
    severity: high
  condition: selection
level: medium`, name, ruleID)

	rule := &core.Rule{
		ID:          ruleID,
		Type:        "sigma",
		Name:        name,
		Description: fmt.Sprintf("Test rule: %s", name),
		Enabled:     enabled,
		Severity:    "medium",
		SigmaYAML:   sigmaYAML,
		Version:     1,
		Actions: []core.Action{
			{
				ID:   uuid.New().String(),
				Type: "notify",
				Config: map[string]interface{}{
					"webhook": "http://test-webhook.example.com",
				},
			},
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// Apply overrides
	for _, override := range overrides {
		override(rule)
	}

	return rule
}

// GenerateTestUser creates a test user
func GenerateTestUser(username string, roleID int64) *storage.User {
	return &storage.User{
		Username: username,
		Password: "testpass123", // Will be hashed by CreateUser
		RoleID:   &roleID,
		Active:   true,
	}
}

// GenerateTestAction creates a test action
func GenerateTestAction(actionType string, overrides ...func(*core.Action)) *core.Action {
	action := &core.Action{
		ID:   uuid.New().String(),
		Type: actionType,
		Config: map[string]interface{}{
			"url": "http://test-webhook.example.com/endpoint",
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// Apply overrides
	for _, override := range overrides {
		override(action)
	}

	return action
}

// GenerateFailedLoginEvents generates multiple failed login events (for correlation testing)
func GenerateFailedLoginEvents(count int, sourceIP string, username string, timeWindow time.Duration) []*core.Event {
	events := make([]*core.Event, count)
	baseTime := time.Now().UTC()

	for i := 0; i < count; i++ {
		eventTime := baseTime.Add(time.Duration(i) * (timeWindow / time.Duration(count)))
		events[i] = GenerateTestEvent(
			func(e *core.Event) {
				e.Timestamp = eventTime
				e.IngestedAt = eventTime
				e.Severity = "warning"
				e.SourceIP = sourceIP
				e.EventType = "login_failed"
				e.Fields["username"] = username
				e.Fields["action"] = "login_failed"
				e.Fields["status"] = "failure"
				e.Fields["status_code"] = 401
				e.Fields["message"] = fmt.Sprintf("Failed login attempt for user %s", username)
			},
		)
	}

	return events
}

// GenerateSuccessfulLoginEvents generates successful login events
func GenerateSuccessfulLoginEvents(count int, sourceIP string, username string) []*core.Event {
	events := make([]*core.Event, count)
	baseTime := time.Now().UTC()

	for i := 0; i < count; i++ {
		eventTime := baseTime.Add(time.Duration(i) * time.Minute)
		events[i] = GenerateTestEvent(
			func(e *core.Event) {
				e.Timestamp = eventTime
				e.IngestedAt = eventTime
				e.Severity = "info"
				e.SourceIP = sourceIP
				e.EventType = "login_success"
				e.Fields["username"] = username
				e.Fields["action"] = "login_success"
				e.Fields["status"] = "success"
				e.Fields["status_code"] = 200
				e.Fields["message"] = fmt.Sprintf("Successful login for user %s", username)
			},
		)
	}

	return events
}

// getSyslogPriority converts severity to syslog priority value
func getSyslogPriority(severity string) int {
	severityMap := map[string]int{
		"emergency": 0,
		"alert":     1,
		"critical":  2,
		"error":     3,
		"warning":   4,
		"notice":    5,
		"info":      6,
		"debug":     7,
	}

	if priority, ok := severityMap[severity]; ok {
		return priority
	}
	return 6 // default to info
}
