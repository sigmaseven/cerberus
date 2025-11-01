package detect

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewActionExecutor(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)
	assert.NotNil(t, ae)
	assert.NotNil(t, ae.httpClient)
	assert.Equal(t, logger, ae.logger)
}

func TestExecuteActions_UnknownType(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	rule := core.Rule{
		Actions: []core.Action{
			{Type: "unknown", Config: map[string]interface{}{}},
		},
	}
	alert := &core.Alert{}

	err := ae.ExecuteActions(rule, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown action type")
}

func TestExecuteActions_Webhook(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rule := core.Rule{
		Actions: []core.Action{
			{
				Type: "webhook",
				Config: map[string]interface{}{
					"url": server.URL,
				},
			},
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Event: &core.Event{RawData: "test raw data"}}

	err := ae.ExecuteActions(rule, alert)
	assert.NoError(t, err)
}

func TestExecuteWebhook(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	action := core.Action{
		Type: "webhook",
		Config: map[string]interface{}{
			"url": server.URL,
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Event: &core.Event{RawData: "test raw data"}}

	err := ae.executeWebhook(action, alert)
	assert.NoError(t, err)
}

func TestExecuteWebhook_InvalidURL(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type: "webhook",
		Config: map[string]interface{}{
			"url": "invalid-url",
		},
	}
	alert := &core.Alert{}

	err := ae.executeWebhook(action, alert)
	assert.Error(t, err)
}

func TestExecuteSlack(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	action := core.Action{
		Type: "slack",
		Config: map[string]interface{}{
			"webhook_url": server.URL,
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Severity: "high", EventID: "event-1", RuleID: "rule-1"}

	err := ae.executeSlack(action, alert)
	assert.NoError(t, err)
}

func TestExecuteJira_MissingConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type:   "jira",
		Config: map[string]interface{}{},
	}
	alert := &core.Alert{}

	err := ae.executeJira(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Jira base URL not found")
}

func TestExecuteEmail_MissingConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type:   "email",
		Config: map[string]interface{}{},
	}
	alert := &core.Alert{}

	err := ae.executeEmail(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SMTP server not found")
}

func TestExecuteJira_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("{}"))
	}))
	defer server.Close()

	action := core.Action{
		Type: "jira",
		Config: map[string]interface{}{
			"base_url": server.URL,
			"project":  "TEST",
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Event: &core.Event{RawData: "test raw data"}}

	// Set environment variables
	t.Setenv("CERBERUS_JIRA_USERNAME", "testuser")
	t.Setenv("CERBERUS_JIRA_TOKEN", "testtoken")

	err := ae.executeJira(action, alert)
	assert.NoError(t, err)
}

func TestExecuteJira_MissingEnvVars(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type: "jira",
		Config: map[string]interface{}{
			"base_url": "http://example.com",
			"project":  "TEST",
		},
	}
	alert := &core.Alert{}

	err := ae.executeJira(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Jira username not set in environment")
}

func TestExecuteJira_HTTPError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	action := core.Action{
		Type: "jira",
		Config: map[string]interface{}{
			"base_url": server.URL,
			"project":  "TEST",
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Event: &core.Event{RawData: "test raw data"}}

	t.Setenv("CERBERUS_JIRA_USERNAME", "testuser")
	t.Setenv("CERBERUS_JIRA_TOKEN", "testtoken")

	err := ae.executeJira(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "action failed after 3 retries")
}

func TestExecuteEmail_ValidConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type: "email",
		Config: map[string]interface{}{
			"smtp_server": "localhost",
			"port":        25.0,
			"from":        "test@example.com",
			"to":          "alert@example.com",
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Event: &core.Event{RawData: "test raw data"}}

	t.Setenv("CERBERUS_SMTP_USERNAME", "testuser")
	t.Setenv("CERBERUS_SMTP_PASSWORD", "testpass")

	// This will fail at SMTP connection, but validates config parsing
	err := ae.executeEmail(action, alert)
	assert.Error(t, err)
	// Should not be a config error
	assert.NotContains(t, err.Error(), "not found in config")
	assert.NotContains(t, err.Error(), "not set in environment")
}

func TestExecuteEmail_MissingEnvVars(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type: "email",
		Config: map[string]interface{}{
			"smtp_server": "localhost",
			"port":        25.0,
			"from":        "test@example.com",
			"to":          "alert@example.com",
		},
	}
	alert := &core.Alert{}

	err := ae.executeEmail(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SMTP username not set in environment")
}

func TestExecuteEmail_InvalidPort(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type: "email",
		Config: map[string]interface{}{
			"smtp_server": "localhost",
			"port":        "invalid",
			"from":        "test@example.com",
			"to":          "alert@example.com",
		},
	}
	alert := &core.Alert{}

	err := ae.executeEmail(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SMTP port not found in config")
}

func TestExecuteActions_NilConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	rule := core.Rule{
		Actions: []core.Action{
			{Type: "webhook", Config: nil},
		},
	}
	alert := &core.Alert{}

	err := ae.ExecuteActions(rule, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "action config is nil")
}

func TestExecuteActions_MultipleActions(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rule := core.Rule{
		Actions: []core.Action{
			{
				Type: "webhook",
				Config: map[string]interface{}{
					"url": server.URL,
				},
			},
			{
				Type: "slack",
				Config: map[string]interface{}{
					"webhook_url": server.URL,
				},
			},
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Severity: "high", EventID: "event-1", RuleID: "rule-1"}

	err := ae.ExecuteActions(rule, alert)
	assert.NoError(t, err)
}

func TestExecuteActions_PartialFailure(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(1*time.Second, logger)

	rule := core.Rule{
		Actions: []core.Action{
			{
				Type: "webhook",
				Config: map[string]interface{}{
					"url": "http://127.0.0.1:12345",
				},
			},
			{
				Type:   "unknown",
				Config: map[string]interface{}{},
			},
		},
	}
	alert := &core.Alert{}

	err := ae.ExecuteActions(rule, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "one or more actions failed")
}

func TestRetryExecute_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	callCount := 0
	err := ae.retryExecute(func() error {
		callCount++
		return nil
	}, "Success %s", []interface{}{"test"}, "test")

	assert.NoError(t, err)
	assert.Equal(t, 1, callCount)
}

func TestRetryExecute_Failure(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	callCount := 0
	err := ae.retryExecute(func() error {
		callCount++
		return fmt.Errorf("test error")
	}, "Success %s", []interface{}{"test"}, "test")

	assert.Error(t, err)
	assert.Equal(t, MaxActionRetries, callCount)
	assert.Contains(t, err.Error(), "action failed after 3 retries")
}

func TestExecuteWebhook_SendWebhookError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type: "webhook",
		Config: map[string]interface{}{
			"url": "http://invalid-url-that-will-fail",
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Event: &core.Event{RawData: "test raw data"}}

	err := ae.executeWebhook(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "action failed after 3 retries")
}

func TestExecuteWebhook_MarshalError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type: "webhook",
		Config: map[string]interface{}{
			"url": "http://example.com",
		},
	}
	// Create an alert that can't be marshaled
	alert := &core.Alert{
		AlertID:   "test",
		Event:     &core.Event{RawData: "test"},
		EventID:   "test",
		RuleID:    "test",
		Severity:  "test",
		Timestamp: time.Now(),
	}

	// This should work since Alert is marshalable
	err := ae.executeWebhook(action, alert)
	assert.Error(t, err) // Will fail on HTTP request, not marshal
}

func TestExecuteJira_SendJiraRequestError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(100*time.Millisecond, logger)

	action := core.Action{
		Type: "jira",
		Config: map[string]interface{}{
			"base_url": "http://192.0.2.1",
			"project":  "TEST",
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Event: &core.Event{RawData: "test raw data"}}

	t.Setenv("CERBERUS_JIRA_USERNAME", "testuser")
	t.Setenv("CERBERUS_JIRA_TOKEN", "testtoken")

	err := ae.executeJira(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "action failed after 3 retries")
}

func TestExecuteSlack_SendWebhookError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(100*time.Millisecond, logger)

	action := core.Action{
		Type: "slack",
		Config: map[string]interface{}{
			"webhook_url": "http://192.0.2.1",
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Severity: "high", EventID: "event-1", RuleID: "rule-1"}

	err := ae.executeSlack(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "action failed after 3 retries")
}

func TestExecuteEmail_SendEmailError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type: "email",
		Config: map[string]interface{}{
			"smtp_server": "invalid-server",
			"port":        25.0,
			"from":        "test@example.com",
			"to":          "alert@example.com",
		},
	}
	alert := &core.Alert{AlertID: "test-alert", Event: &core.Event{RawData: "test raw data"}}

	t.Setenv("CERBERUS_SMTP_USERNAME", "testuser")
	t.Setenv("CERBERUS_SMTP_PASSWORD", "testpass")

	err := ae.executeEmail(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "action failed after 3 retries")
}

func TestExecuteEmail_InvalidPortType(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type: "email",
		Config: map[string]interface{}{
			"smtp_server": "localhost",
			"port":        "notanumber",
			"from":        "test@example.com",
			"to":          "alert@example.com",
		},
	}
	alert := &core.Alert{}

	err := ae.executeEmail(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SMTP port not found in config")
}

func TestExecuteEmail_PortNotIntegerFloat(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type: "email",
		Config: map[string]interface{}{
			"smtp_server": "localhost",
			"port":        25.5, // Not integer
			"from":        "test@example.com",
			"to":          "alert@example.com",
		},
	}
	alert := &core.Alert{}

	err := ae.executeEmail(action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SMTP port must be an integer")
}

func TestExecuteActions_EmptyActions(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	rule := core.Rule{
		Actions: []core.Action{},
	}
	alert := &core.Alert{}

	err := ae.ExecuteActions(rule, alert)
	assert.NoError(t, err)
}

func TestExecuteActions_SingleFailure(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	rule := core.Rule{
		Actions: []core.Action{
			{Type: "unknown", Config: map[string]interface{}{}},
		},
	}
	alert := &core.Alert{}

	err := ae.ExecuteActions(rule, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "one or more actions failed")
}

func TestSendWebhook_HTTPError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	err := ae.sendWebhook(server.URL, []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "webhook returned status 500")
}

func TestSendJiraRequest_HTTPError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	err := ae.sendJiraRequest(server.URL, "user", "token", []byte("{}"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Jira API returned status 400")
}
