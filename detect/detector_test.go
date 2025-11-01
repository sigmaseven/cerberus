package detect

import (
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewDetector(t *testing.T) {
	logger := zap.NewNop().Sugar()
	engine := &RuleEngine{} // mock or nil for test
	inputCh := make(chan *core.Event)
	outputCh := make(chan *core.Event)
	alertCh := make(chan *core.Alert)
	cfg := &config.Config{} // minimal config for test

	detector := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)

	assert.NotNil(t, detector)
	assert.Equal(t, engine, detector.engine)
	assert.NotNil(t, detector.inputEventCh)
	assert.NotNil(t, detector.outputEventCh)
	assert.NotNil(t, detector.alertCh)
	assert.NotNil(t, detector.actionExec)
	assert.Equal(t, logger, detector.logger)
}

func TestDetector_Start(t *testing.T) {
	logger := zap.NewNop().Sugar()
	rules := []core.Rule{
		{
			ID:      "test_rule",
			Enabled: true,
			Conditions: []core.Condition{
				{
					Field:    "event_type",
					Operator: "equals",
					Value:    "user_login",
				},
			},
		},
	}
	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 0)
	inputCh := make(chan *core.Event, 1)
	outputCh := make(chan *core.Event, 1)
	alertCh := make(chan *core.Alert, 1)
	cfg := &config.Config{
		Engine: struct {
			ChannelBufferSize   int `mapstructure:"channel_buffer_size"`
			WorkerCount         int `mapstructure:"worker_count"`
			ActionWorkerCount   int `mapstructure:"action_worker_count"`
			RateLimit           int `mapstructure:"rate_limit"`
			CorrelationStateTTL int `mapstructure:"correlation_state_ttl"`
			ActionTimeout       int `mapstructure:"action_timeout"`
		}{
			ActionWorkerCount: 1,
			ActionTimeout:     10,
		},
	}

	detector := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)

	detector.Start()

	// Send event
	event := core.NewEvent()
	event.EventType = "user_login"
	inputCh <- event
	close(inputCh) // to stop the run loop

	// Check alert
	select {
	case alert := <-alertCh:
		assert.Equal(t, "test_rule", alert.RuleID)
	case <-time.After(5 * time.Second):
		t.Fatal("Alert not received")
	}

	// Check output event
	select {
	case outEvent := <-outputCh:
		assert.Equal(t, event.EventID, outEvent.EventID)
	case <-time.After(5 * time.Second):
		t.Fatal("Output event not received")
	}

	detector.Stop()
}

func TestDetector_ProcessRuleMatches(t *testing.T) {
	logger := zap.NewNop().Sugar()

	rules := []core.Rule{
		{
			ID:      "test_rule",
			Enabled: true,
			Conditions: []core.Condition{
				{
					Field:    "event_type",
					Operator: "equals",
					Value:    "user_login",
				},
			},
			Actions: []core.Action{}, // No actions to avoid network calls
		},
	}
	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 0)
	inputCh := make(chan *core.Event, 1)
	outputCh := make(chan *core.Event, 1)
	alertCh := make(chan *core.Alert, 1)
	cfg := &config.Config{
		Engine: struct {
			ChannelBufferSize   int `mapstructure:"channel_buffer_size"`
			WorkerCount         int `mapstructure:"worker_count"`
			ActionWorkerCount   int `mapstructure:"action_worker_count"`
			RateLimit           int `mapstructure:"rate_limit"`
			CorrelationStateTTL int `mapstructure:"correlation_state_ttl"`
			ActionTimeout       int `mapstructure:"action_timeout"`
		}{
			ActionWorkerCount: 1,
			ActionTimeout:     1,
		},
	}

	detector := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	detector.Start()
	defer func() {
		close(inputCh)
		detector.Stop()
	}()

	event := core.NewEvent()
	event.EventType = "user_login"

	// This should not block or panic
	alertableRules := make([]core.AlertableRule, len(rules))
	for i, r := range rules {
		alertableRules[i] = r
	}
	// Start a receiver for alertCh to make it not full
	go func() {
		<-alertCh
	}()
	detector.processRuleMatches(alertableRules, event)
}

func TestDetector_Run_CorrelationRules(t *testing.T) {
	logger := zap.NewNop().Sugar()
	correlationRules := []core.CorrelationRule{
		{
			ID:       "correlation_test",
			Sequence: []string{"failed_login", "failed_login"},
			Window:   300000000000, // 5 minutes
		},
	}
	engine := NewRuleEngine([]core.Rule{}, correlationRules, 0)
	inputCh := make(chan *core.Event, 2)
	outputCh := make(chan *core.Event, 2)
	alertCh := make(chan *core.Alert, 1)
	cfg := &config.Config{
		Engine: struct {
			ChannelBufferSize   int `mapstructure:"channel_buffer_size"`
			WorkerCount         int `mapstructure:"worker_count"`
			ActionWorkerCount   int `mapstructure:"action_worker_count"`
			RateLimit           int `mapstructure:"rate_limit"`
			CorrelationStateTTL int `mapstructure:"correlation_state_ttl"`
			ActionTimeout       int `mapstructure:"action_timeout"`
		}{
			ActionWorkerCount: 1,
			ActionTimeout:     10,
		},
	}

	detector := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	detector.Start()
	defer detector.Stop()

	// Send first event
	event1 := core.NewEvent()
	event1.EventType = "failed_login"
	inputCh <- event1

	// Send second event
	event2 := core.NewEvent()
	event2.EventType = "failed_login"
	inputCh <- event2

	close(inputCh)

	// Check alert from correlation rule
	select {
	case alert := <-alertCh:
		assert.Equal(t, "correlation_test", alert.RuleID)
	case <-time.After(5 * time.Second):
		t.Fatal("Correlation alert not received")
	}
}

func TestDetector_ProcessRuleMatches_AlertChannelFull(t *testing.T) {
	logger := zap.NewNop().Sugar()

	rules := []core.Rule{
		{
			ID:      "test_rule",
			Enabled: true,
			Conditions: []core.Condition{
				{
					Field:    "event_type",
					Operator: "equals",
					Value:    "user_login",
				},
			},
			Actions: []core.Action{}, // No actions
		},
	}
	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 0)
	inputCh := make(chan *core.Event, 1)
	outputCh := make(chan *core.Event, 1)
	alertCh := make(chan *core.Alert, 0) // No buffer, so full immediately
	cfg := &config.Config{
		Engine: struct {
			ChannelBufferSize   int `mapstructure:"channel_buffer_size"`
			WorkerCount         int `mapstructure:"worker_count"`
			ActionWorkerCount   int `mapstructure:"action_worker_count"`
			RateLimit           int `mapstructure:"rate_limit"`
			CorrelationStateTTL int `mapstructure:"correlation_state_ttl"`
			ActionTimeout       int `mapstructure:"action_timeout"`
		}{
			ActionWorkerCount: 1,
			ActionTimeout:     1,
		},
	}

	detector := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)

	event := core.NewEvent()
	event.EventType = "user_login"

	alertableRules := make([]core.AlertableRule, len(rules))
	for i, r := range rules {
		alertableRules[i] = r
	}

	// This should not block, and log warning
	detector.processRuleMatches(alertableRules, event)
}

func TestDetector_ProcessRuleMatches_ActionChannelFull(t *testing.T) {
	logger := zap.NewNop().Sugar()

	rules := []core.Rule{
		{
			ID:      "test_rule",
			Enabled: true,
			Conditions: []core.Condition{
				{
					Field:    "event_type",
					Operator: "equals",
					Value:    "user_login",
				},
			},
			Actions: []core.Action{
				{
					Type: "log",
					Config: map[string]interface{}{
						"message": "test",
					},
				},
			},
		},
	}
	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 0)
	inputCh := make(chan *core.Event, 1)
	outputCh := make(chan *core.Event, 1)
	alertCh := make(chan *core.Alert, 1)
	cfg := &config.Config{
		Engine: struct {
			ChannelBufferSize   int `mapstructure:"channel_buffer_size"`
			WorkerCount         int `mapstructure:"worker_count"`
			ActionWorkerCount   int `mapstructure:"action_worker_count"`
			RateLimit           int `mapstructure:"rate_limit"`
			CorrelationStateTTL int `mapstructure:"correlation_state_ttl"`
			ActionTimeout       int `mapstructure:"action_timeout"`
		}{
			ActionWorkerCount: 1,
			ActionTimeout:     1,
		},
	}

	detector := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	detector.actionCh = make(chan func(), 0) // No buffer, full immediately

	event := core.NewEvent()
	event.EventType = "user_login"

	alertableRules := make([]core.AlertableRule, len(rules))
	for i, r := range rules {
		alertableRules[i] = r
	}

	// Start a receiver for alertCh
	go func() {
		<-alertCh
	}()

	// This should not block, and log warning for action channel full
	detector.processRuleMatches(alertableRules, event)
}

func TestDetector_Run_OutputChannelFull(t *testing.T) {
	logger := zap.NewNop().Sugar()
	rules := []core.Rule{
		{
			ID:      "test_rule",
			Enabled: true,
			Conditions: []core.Condition{
				{
					Field:    "event_type",
					Operator: "equals",
					Value:    "user_login",
				},
			},
		},
	}
	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 0)
	inputCh := make(chan *core.Event, 1)
	outputCh := make(chan *core.Event, 0) // No buffer, full immediately
	alertCh := make(chan *core.Alert, 1)
	cfg := &config.Config{
		Engine: struct {
			ChannelBufferSize   int `mapstructure:"channel_buffer_size"`
			WorkerCount         int `mapstructure:"worker_count"`
			ActionWorkerCount   int `mapstructure:"action_worker_count"`
			RateLimit           int `mapstructure:"rate_limit"`
			CorrelationStateTTL int `mapstructure:"correlation_state_ttl"`
			ActionTimeout       int `mapstructure:"action_timeout"`
		}{
			ActionWorkerCount: 1,
			ActionTimeout:     10,
		},
	}

	detector := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)

	detector.Start()

	event := core.NewEvent()
	event.EventType = "user_login"
	inputCh <- event
	close(inputCh)

	// Start a receiver for alertCh
	go func() {
		<-alertCh
	}()

	detector.Stop()
}
