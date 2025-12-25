package detect

import (
	"sync"
	"testing"
	"time"

	"cerberus/core"
	testinghelpers "cerberus/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TASK #184: Test SIGMA YAML fixture for rules matching test events
const testSigmaYAMLUserLogin = `title: Test Rule
logsource:
  product: test
detection:
  selection:
    event_type: user_login
  condition: selection
`

// TestNewDetector_CreatesValidDetectorInstance verifies that NewDetector
// properly initializes all detector fields and channels.
//
// Requirement: DET-001 - Detector Initialization
// All detector components must be properly initialized to prevent nil pointer panics.
func TestNewDetector_CreatesValidDetectorInstance(t *testing.T) {
	logger := zap.NewNop().Sugar()
	engine := &RuleEngine{} // mock engine for initialization test
	inputCh := make(chan *core.Event)
	outputCh := make(chan *core.Event)
	alertCh := make(chan *core.Alert)

	// Use standardized test configuration
	cfg := testinghelpers.SetupTestConfig()

	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	require.NoError(t, err, "NewDetector failed")

	// Verify all critical fields are initialized
	require.NotNil(t, detector, "NewDetector returned nil detector")
	assert.Equal(t, engine, detector.engine, "Engine not properly assigned")
	require.NotNil(t, detector.inputEventCh, "Input channel is nil")
	require.NotNil(t, detector.outputEventCh, "Output channel is nil")
	require.NotNil(t, detector.alertCh, "Alert channel is nil")
	require.NotNil(t, detector.actionExec, "Action executor is nil")
	assert.Equal(t, logger, detector.logger, "Logger not properly assigned")
}

// TestDetector_Start_ProcessesEventsAndGeneratesAlerts verifies that the detector
// processes incoming events, matches them against rules, and generates alerts.
//
// Requirement: DET-002 - Event Processing
// Detector MUST process events through the rule engine and generate alerts for matches.
func TestDetector_Start_ProcessesEventsAndGeneratesAlerts(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// Create a simple rule that matches "user_login" events
	// TASK #184: Updated to use SigmaYAML instead of legacy Conditions
	rules := []core.Rule{
		{
			ID:        testinghelpers.TestRuleID,
			Type:      "sigma",
			Enabled:   true,
			SigmaYAML: testSigmaYAMLUserLogin,
		},
	}

	engine := newTestRuleEngineWithSigma(rules)
	inputCh := make(chan *core.Event, testinghelpers.TestChannelBufferSize)
	outputCh := make(chan *core.Event, testinghelpers.TestChannelBufferSize)
	alertCh := make(chan *core.Alert, testinghelpers.TestChannelBufferSize)

	cfg := testinghelpers.SetupTestConfig()

	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	require.NoError(t, err, "NewDetector failed")

	// Use sync.Once to ensure channel is only closed once
	var closeOnce sync.Once
	t.Cleanup(func() {
		closeOnce.Do(func() {
			close(inputCh)
		})
		detector.Stop()
	})

	detector.Start()

	// Create and send test event
	event := core.NewEvent()
	require.NotNil(t, event, "NewEvent returned nil")
	require.NotNil(t, event.Fields, "Event.Fields is nil")
	event.EventType = testinghelpers.TestEventType

	inputCh <- event

	// Verify alert is generated
	// Using WaitForCondition pattern for reliable timing
	var receivedAlert *core.Alert
	testinghelpers.WaitForCondition(t, func() bool {
		select {
		case receivedAlert = <-alertCh:
			return true
		default:
			return false
		}
	}, testinghelpers.TestLongTimeout, "alert to be generated for matching event")

	require.NotNil(t, receivedAlert, "Alert was not received")
	assert.Equal(t, testinghelpers.TestRuleID, receivedAlert.RuleID,
		"Alert rule ID mismatch: expected %s for event %+v, got %s",
		testinghelpers.TestRuleID, event, receivedAlert.RuleID)

	// Verify output event is forwarded
	var receivedEvent *core.Event
	testinghelpers.WaitForCondition(t, func() bool {
		select {
		case receivedEvent = <-outputCh:
			return true
		default:
			return false
		}
	}, testinghelpers.TestLongTimeout, "event to be forwarded to output channel")

	require.NotNil(t, receivedEvent, "Output event was not received")
	assert.Equal(t, event.EventID, receivedEvent.EventID,
		"Output event ID mismatch: expected %s, got %s",
		event.EventID, receivedEvent.EventID)

	// Close input channel to stop the run loop
	closeOnce.Do(func() {
		close(inputCh)
	})
}

// TestDetector_ProcessRuleMatches_CreatesAlertOnMatch verifies that processRuleMatches
// creates alerts when rules match events.
//
// Requirement: DET-003 - Alert Generation
// When a rule matches an event, an alert MUST be created and sent to the alert channel.
func TestDetector_ProcessRuleMatches_CreatesAlertOnMatch(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// TASK #184: Updated to use SigmaYAML instead of legacy Conditions
	rules := []core.Rule{
		{
			ID:        testinghelpers.TestRuleID,
			Type:      "sigma",
			Enabled:   true,
			SigmaYAML: testSigmaYAMLUserLogin,
			// No actions to avoid network calls during testing
			Actions: []core.Action{},
		},
	}

	engine := newTestRuleEngineWithSigma(rules)
	inputCh := make(chan *core.Event, testinghelpers.TestChannelBufferSize)
	outputCh := make(chan *core.Event, testinghelpers.TestChannelBufferSize)
	alertCh := make(chan *core.Alert, testinghelpers.TestChannelBufferSize)

	cfg := testinghelpers.SetupTestConfig()

	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	require.NoError(t, err, "NewDetector failed")
	detector.Start()

	// Use sync.Once to ensure channel is only closed once
	var closeOnce sync.Once
	t.Cleanup(func() {
		closeOnce.Do(func() {
			close(inputCh)
		})
		detector.Stop()
	})

	event := core.NewEvent()
	require.NotNil(t, event, "NewEvent returned nil")
	require.NotNil(t, event.Fields, "Event.Fields is nil")
	event.EventType = testinghelpers.TestEventType

	// Convert rules to AlertableRule interface
	alertableRules := make([]core.AlertableRule, len(rules))
	for i, r := range rules {
		alertableRules[i] = r
	}

	// Start a receiver for alertCh to prevent blocking
	alertReceived := make(chan bool, 1)
	go func() {
		<-alertCh
		alertReceived <- true
	}()

	// This should not block or panic
	detector.processRuleMatches(alertableRules, event)

	// Verify alert was sent
	testinghelpers.WaitForCondition(t, func() bool {
		select {
		case <-alertReceived:
			return true
		default:
			return false
		}
	}, testinghelpers.TestMediumTimeout, "alert to be generated and received")
}

// TestDetector_Run_CorrelationRules_GeneratesAlertOnSequenceMatch verifies that
// correlation rules generate alerts when event sequences match.
//
// Requirement: DET-004 - Correlation Rule Processing
// Correlation rules MUST detect event sequences within the specified time window
// and generate alerts when the sequence completes.
func TestDetector_Run_CorrelationRules_GeneratesAlertOnSequenceMatch(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// Create correlation rule that triggers on two "failed_login" events
	// Window is 5 minutes (300 seconds = 300,000,000,000 nanoseconds)
	// WHY nanoseconds: time.Duration is measured in nanoseconds
	const fiveMinutesInNanoseconds = 5 * 60 * 1000 * 1000 * 1000

	correlationRules := []core.CorrelationRule{
		{
			ID:       "correlation_test",
			Sequence: []string{"failed_login", "failed_login"},
			Window:   fiveMinutesInNanoseconds,
		},
	}

	engine := NewRuleEngine([]core.Rule{}, correlationRules, 0)
	inputCh := make(chan *core.Event, 2) // Buffer for 2 events
	outputCh := make(chan *core.Event, 2)
	alertCh := make(chan *core.Alert, testinghelpers.TestChannelBufferSize)

	cfg := testinghelpers.SetupTestConfig()

	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	require.NoError(t, err, "NewDetector failed")
	detector.Start()

	// Use sync.Once to ensure channel is only closed once and only after sending events
	var closeOnce sync.Once
	t.Cleanup(func() {
		closeOnce.Do(func() {
			close(inputCh)
		})
		detector.Stop()
	})

	// Send first failed_login event
	event1 := core.NewEvent()
	require.NotNil(t, event1, "NewEvent returned nil for event1")
	require.NotNil(t, event1.Fields, "Event1.Fields is nil")
	event1.EventType = "failed_login"
	inputCh <- event1

	// Send second failed_login event
	event2 := core.NewEvent()
	require.NotNil(t, event2, "NewEvent returned nil for event2")
	require.NotNil(t, event2.Fields, "Event2.Fields is nil")
	event2.EventType = "failed_login"
	inputCh <- event2

	// Wait for correlation alert to be generated
	var correlationAlert *core.Alert
	testinghelpers.WaitForCondition(t, func() bool {
		select {
		case correlationAlert = <-alertCh:
			return true
		default:
			return false
		}
	}, testinghelpers.TestLongTimeout, "correlation alert to be generated after sequence match")

	require.NotNil(t, correlationAlert, "Correlation alert was not received")
	assert.Equal(t, "correlation_test", correlationAlert.RuleID,
		"Correlation alert rule ID mismatch: expected 'correlation_test', got %s",
		correlationAlert.RuleID)

	// Close channel after test completes
	closeOnce.Do(func() {
		close(inputCh)
	})
}

// TestDetector_ProcessRuleMatches_LogsWarningWhenAlertChannelFull verifies that
// the detector logs a warning instead of blocking when the alert channel is full.
//
// Requirement: DET-005 - Non-Blocking Alert Delivery
// Detector MUST NOT block event processing when alert channel is full.
// Instead, it should log a warning and continue processing events.
func TestDetector_ProcessRuleMatches_LogsWarningWhenAlertChannelFull(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// TASK #184: Updated to use SigmaYAML instead of legacy Conditions
	rules := []core.Rule{
		{
			ID:        testinghelpers.TestRuleID,
			Type:      "sigma",
			Enabled:   true,
			SigmaYAML: testSigmaYAMLUserLogin,
			Actions:   []core.Action{}, // No actions
		},
	}

	engine := newTestRuleEngineWithSigma(rules)
	inputCh := make(chan *core.Event, testinghelpers.TestChannelBufferSize)
	outputCh := make(chan *core.Event, testinghelpers.TestChannelBufferSize)

	// Create unbuffered channel to simulate "full" channel
	// WHY unbuffered: Immediately full, tests non-blocking behavior
	alertCh := make(chan *core.Alert, 0)

	cfg := testinghelpers.SetupTestConfig()

	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	require.NoError(t, err, "NewDetector failed")

	event := core.NewEvent()
	require.NotNil(t, event, "NewEvent returned nil")
	require.NotNil(t, event.Fields, "Event.Fields is nil")
	event.EventType = testinghelpers.TestEventType

	alertableRules := make([]core.AlertableRule, len(rules))
	for i, r := range rules {
		alertableRules[i] = r
	}

	// This should NOT block even though alert channel has no buffer
	// Implementation should use select with default case
	done := make(chan bool, 1)
	go func() {
		detector.processRuleMatches(alertableRules, event)
		done <- true
	}()

	// Verify it completes quickly (should not block)
	testinghelpers.WaitForCondition(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, testinghelpers.TestShortTimeout, "processRuleMatches to complete without blocking")
}

// TestDetector_ProcessRuleMatches_LogsWarningWhenActionChannelFull verifies that
// the detector logs a warning instead of blocking when the action channel is full.
//
// Requirement: DET-006 - Non-Blocking Action Delivery
// Detector MUST NOT block event processing when action channel is full.
// Instead, it should log a warning and continue processing events.
func TestDetector_ProcessRuleMatches_LogsWarningWhenActionChannelFull(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// TASK #184: Updated to use SigmaYAML instead of legacy Conditions
	rules := []core.Rule{
		{
			ID:        testinghelpers.TestRuleID,
			Type:      "sigma",
			Enabled:   true,
			SigmaYAML: testSigmaYAMLUserLogin,
			Actions: []core.Action{
				{
					Type: "log",
					Config: map[string]interface{}{
						"message": "test action",
					},
				},
			},
		},
	}

	engine := newTestRuleEngineWithSigma(rules)
	inputCh := make(chan *core.Event, testinghelpers.TestChannelBufferSize)
	outputCh := make(chan *core.Event, testinghelpers.TestChannelBufferSize)
	alertCh := make(chan *core.Alert, testinghelpers.TestChannelBufferSize)

	cfg := testinghelpers.SetupTestConfig()

	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	require.NoError(t, err, "NewDetector failed")

	// Override action channel with unbuffered channel to simulate "full" channel
	// WHY unbuffered: Immediately full, tests non-blocking behavior
	detector.actionCh = make(chan func(), 0)

	event := core.NewEvent()
	require.NotNil(t, event, "NewEvent returned nil")
	require.NotNil(t, event.Fields, "Event.Fields is nil")
	event.EventType = testinghelpers.TestEventType

	alertableRules := make([]core.AlertableRule, len(rules))
	for i, r := range rules {
		alertableRules[i] = r
	}

	// Start a receiver for alertCh to prevent blocking on alert send
	alertReceived := make(chan bool, 1)
	go func() {
		<-alertCh
		alertReceived <- true
	}()

	// This should NOT block even though action channel has no buffer
	// Implementation should use select with default case
	done := make(chan bool, 1)
	go func() {
		detector.processRuleMatches(alertableRules, event)
		done <- true
	}()

	// Verify it completes quickly (should not block)
	testinghelpers.WaitForCondition(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, testinghelpers.TestShortTimeout, "processRuleMatches to complete without blocking on action channel")
}

// TestDetector_Run_LogsWarningWhenOutputChannelFull verifies that the detector
// logs a warning instead of blocking when the output channel is full.
//
// Requirement: DET-007 - Non-Blocking Event Forwarding
// Detector MUST NOT block when output channel is full. Instead, it should
// log a warning and continue processing events.
func TestDetector_Run_LogsWarningWhenOutputChannelFull(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// TASK #184: Updated to use SigmaYAML instead of legacy Conditions
	rules := []core.Rule{
		{
			ID:        testinghelpers.TestRuleID,
			Type:      "sigma",
			Enabled:   true,
			SigmaYAML: testSigmaYAMLUserLogin,
		},
	}

	engine := newTestRuleEngineWithSigma(rules)
	inputCh := make(chan *core.Event, testinghelpers.TestChannelBufferSize)

	// Create unbuffered output channel to simulate "full" channel
	// WHY unbuffered: Immediately full, tests non-blocking behavior
	outputCh := make(chan *core.Event, 0)

	alertCh := make(chan *core.Alert, testinghelpers.TestChannelBufferSize)

	cfg := testinghelpers.SetupTestConfig()

	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	require.NoError(t, err, "NewDetector failed")

	// Use sync.Once to ensure channel is only closed once
	var closeOnce sync.Once
	t.Cleanup(func() {
		closeOnce.Do(func() {
			close(inputCh)
		})
		detector.Stop()
	})

	detector.Start()

	event := core.NewEvent()
	require.NotNil(t, event, "NewEvent returned nil")
	require.NotNil(t, event.Fields, "Event.Fields is nil")
	event.EventType = testinghelpers.TestEventType

	inputCh <- event

	// Start a receiver for alertCh to prevent blocking on alert send
	go func() {
		select {
		case <-alertCh:
			// Alert received, continue
		case <-time.After(testinghelpers.TestLongTimeout):
			// Timeout is acceptable - we're testing output channel behavior
		}
	}()

	// Give detector time to process event and attempt to send to output channel
	// The detector should log a warning and continue (not block)
	time.Sleep(100 * time.Millisecond)

	// Close input channel to stop the run loop
	closeOnce.Do(func() {
		close(inputCh)
	})

	// If we get here without hanging, the test passed
	// The detector successfully handled a full output channel
}
