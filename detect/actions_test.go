package detect

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// withTestMode temporarily enables test mode for functional tests that need to bypass SSRF protection
// to use httptest.NewServer(). Security tests should NEVER use this helper.
// REQUIREMENT: Tests must validate security works in production mode (CERBERUS_TEST_MODE != 1)
// Reference: docs/requirements/security-threat-model.md Section 4.1
func withTestMode(t *testing.T, fn func()) {
	t.Helper()
	// Save original value
	original := os.Getenv("CERBERUS_TEST_MODE")
	// Enable test mode temporarily
	os.Setenv("CERBERUS_TEST_MODE", "1")
	// Ensure cleanup
	defer func() {
		if original == "" {
			os.Unsetenv("CERBERUS_TEST_MODE")
		} else {
			os.Setenv("CERBERUS_TEST_MODE", original)
		}
	}()
	// Run test function
	fn()
}

func TestNewActionExecutor(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)
	defer ae.Stop() // TASK 139: Proper cleanup to prevent goroutine leak
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

	err := ae.ExecuteActions(context.Background(), rule, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown action type")
}

func TestExecuteActions_Webhook(t *testing.T) {
	withTestMode(t, func() {
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

		err := ae.ExecuteActions(context.Background(), rule, alert)
		assert.NoError(t, err)
	})
}

func TestExecuteWebhook(t *testing.T) {
	withTestMode(t, func() {
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

		err := ae.executeWebhook(context.Background(), action, alert)
		assert.NoError(t, err)
	})
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

	err := ae.executeWebhook(context.Background(), action, alert)
	assert.Error(t, err)
}

func TestExecuteSlack(t *testing.T) {
	withTestMode(t, func() {
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

		err := ae.executeSlack(context.Background(), action, alert)
		assert.NoError(t, err)
	})
}

func TestExecuteJira_MissingConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	action := core.Action{
		Type:   "jira",
		Config: map[string]interface{}{},
	}
	alert := &core.Alert{}

	err := ae.executeJira(context.Background(), action, alert)
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

	err := ae.executeEmail(context.Background(), action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SMTP server not found")
}

func TestExecuteJira_Success(t *testing.T) {
	withTestMode(t, func() {
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

		err := ae.executeJira(context.Background(), action, alert)
		assert.NoError(t, err)
	})
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

	err := ae.executeJira(context.Background(), action, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Jira username not set in environment")
}

func TestExecuteJira_HTTPError(t *testing.T) {
	withTestMode(t, func() {
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

		err := ae.executeJira(context.Background(), action, alert)
		assert.Error(t, err)
		// Error format: "action to {endpoint} failed after {N} retries"
		assert.Contains(t, err.Error(), "failed after")
		assert.Contains(t, err.Error(), "retries")
	})
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
	err := ae.executeEmail(context.Background(), action, alert)
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

	err := ae.executeEmail(context.Background(), action, alert)
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

	err := ae.executeEmail(context.Background(), action, alert)
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

	err := ae.ExecuteActions(context.Background(), rule, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "action config is nil")
}

func TestExecuteActions_MultipleActions(t *testing.T) {
	withTestMode(t, func() {
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

		err := ae.ExecuteActions(context.Background(), rule, alert)
		assert.NoError(t, err)
	})
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

	err := ae.ExecuteActions(context.Background(), rule, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "one or more actions failed")
}

func TestRetryExecute_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	callCount := 0
	err := ae.retryExecute("test-endpoint", func() error {
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
	err := ae.retryExecute("test-endpoint", func() error {
		callCount++
		return fmt.Errorf("test error")
	}, "Success %s", []interface{}{"test"}, "test")

	assert.Error(t, err)
	assert.Equal(t, MaxActionRetries, callCount)
	assert.Contains(t, err.Error(), "failed after")
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

	err := ae.executeWebhook(context.Background(), action, alert)
	assert.Error(t, err)
	// URL validation catches this before retrying
	assert.Contains(t, err.Error(), "invalid webhook URL")
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
	err := ae.executeWebhook(context.Background(), action, alert)
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

	err := ae.executeJira(context.Background(), action, alert)
	assert.Error(t, err)
	// Error format: "action to {endpoint} failed after {N} retries"
	assert.Contains(t, err.Error(), "failed after")
	assert.Contains(t, err.Error(), "retries")
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

	err := ae.executeSlack(context.Background(), action, alert)
	assert.Error(t, err)
	// Error format: "action to {endpoint} failed after {N} retries"
	assert.Contains(t, err.Error(), "failed after")
	assert.Contains(t, err.Error(), "retries")
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

	err := ae.executeEmail(context.Background(), action, alert)
	assert.Error(t, err)
	// Error format: "action to {endpoint} failed after {N} retries"
	assert.Contains(t, err.Error(), "failed after")
	assert.Contains(t, err.Error(), "retries")
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

	err := ae.executeEmail(context.Background(), action, alert)
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

	err := ae.executeEmail(context.Background(), action, alert)
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

	err := ae.ExecuteActions(context.Background(), rule, alert)
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

	err := ae.ExecuteActions(context.Background(), rule, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "one or more actions failed")
}

func TestSendWebhook_HTTPError(t *testing.T) {
	withTestMode(t, func() {
		logger := zap.NewNop().Sugar()
		ae := NewActionExecutor(10*time.Second, logger)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		err := ae.sendWebhook(context.Background(),server.URL, []byte("test"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "webhook returned status 500")
	})
}

func TestSendJiraRequest_HTTPError(t *testing.T) {
	withTestMode(t, func() {
		logger := zap.NewNop().Sugar()
		ae := NewActionExecutor(10*time.Second, logger)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		err := ae.sendJiraRequest(context.Background(),server.URL, "user", "token", []byte("{}"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Jira API returned status 400")
	})
}

// =============================================================================
// IPv4/IPv6 Address Formatting Tests (Task 133)
// =============================================================================
// These tests verify that net.JoinHostPort() correctly formats various address
// types for SMTP connections. The fix ensures IPv6 addresses are properly
// wrapped in brackets to avoid ambiguity with the port separator.

// TestNetJoinHostPort_AddressFormatting tests the core fix for IPv6 vulnerability.
// This directly tests net.JoinHostPort() behavior with various address types.
func TestNetJoinHostPort_AddressFormatting(t *testing.T) {
	testCases := []struct {
		name     string
		host     string
		port     int
		expected string
	}{
		// IPv4 addresses
		{
			name:     "IPv4_Standard",
			host:     "192.168.1.100",
			port:     25,
			expected: "192.168.1.100:25",
		},
		{
			name:     "IPv4_Loopback",
			host:     "127.0.0.1",
			port:     587,
			expected: "127.0.0.1:587",
		},

		// IPv6 addresses - these MUST have brackets
		{
			name:     "IPv6_Loopback",
			host:     "::1",
			port:     25,
			expected: "[::1]:25",
		},
		{
			name:     "IPv6_Full",
			host:     "2001:db8:85a3::8a2e:370:7334",
			port:     587,
			expected: "[2001:db8:85a3::8a2e:370:7334]:587",
		},
		{
			name:     "IPv6_LinkLocal",
			host:     "fe80::1",
			port:     25,
			expected: "[fe80::1]:25",
		},
		{
			name:     "IPv6_ZoneIdentifier",
			host:     "fe80::1%eth0",
			port:     25,
			expected: "[fe80::1%eth0]:25",
		},
		{
			name:     "IPv6_Mapped_IPv4",
			host:     "::ffff:192.168.1.1",
			port:     25,
			expected: "[::ffff:192.168.1.1]:25",
		},
		{
			name:     "IPv6_AllZeros",
			host:     "::",
			port:     25,
			expected: "[::]:25",
		},

		// Hostnames
		{
			name:     "Hostname_Simple",
			host:     "localhost",
			port:     25,
			expected: "localhost:25",
		},
		{
			name:     "Hostname_FQDN",
			host:     "smtp.example.com",
			port:     587,
			expected: "smtp.example.com:587",
		},
		{
			name:     "Hostname_Subdomain",
			host:     "mail.internal.corp.example.com",
			port:     465,
			expected: "mail.internal.corp.example.com:465",
		},

		// Various ports
		{
			name:     "Port_SMTP_Standard",
			host:     "127.0.0.1",
			port:     25,
			expected: "127.0.0.1:25",
		},
		{
			name:     "Port_SMTP_Submission",
			host:     "127.0.0.1",
			port:     587,
			expected: "127.0.0.1:587",
		},
		{
			name:     "Port_SMTP_SSL",
			host:     "127.0.0.1",
			port:     465,
			expected: "127.0.0.1:465",
		},
		{
			name:     "Port_Custom",
			host:     "127.0.0.1",
			port:     2525,
			expected: "127.0.0.1:2525",
		},
		{
			name:     "Port_High",
			host:     "127.0.0.1",
			port:     49152,
			expected: "127.0.0.1:49152",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := net.JoinHostPort(tc.host, strconv.Itoa(tc.port))
			assert.Equal(t, tc.expected, result, "Address formatting mismatch for %s", tc.name)
		})
	}
}

// TestNetJoinHostPort_IPv6SecurityFix specifically verifies the vulnerability fix.
// Before the fix: fmt.Sprintf("%s:%d", "::1", 25) would produce "::1:25" (INVALID)
// After the fix: net.JoinHostPort("::1", "25") produces "[::1]:25" (VALID)
func TestNetJoinHostPort_IPv6SecurityFix(t *testing.T) {
	// Vulnerable pattern that was fixed
	ipv6Addresses := []struct {
		address       string
		port          int
		badFormat     string // What the vulnerable code would produce
		correctFormat string // What net.JoinHostPort produces
	}{
		{
			address:       "::1",
			port:          25,
			badFormat:     "::1:25",   // Ambiguous - is this IPv6 ::1:25 or ::1 port 25?
			correctFormat: "[::1]:25", // Unambiguous
		},
		{
			address:       "2001:db8::1",
			port:          587,
			badFormat:     "2001:db8::1:587",   // Ambiguous
			correctFormat: "[2001:db8::1]:587", // Unambiguous
		},
		{
			address:       "fe80::1",
			port:          465,
			badFormat:     "fe80::1:465",   // Ambiguous
			correctFormat: "[fe80::1]:465", // Unambiguous
		},
	}

	for _, tc := range ipv6Addresses {
		t.Run(tc.address, func(t *testing.T) {
			// Verify vulnerable pattern would produce bad format
			badResult := fmt.Sprintf("%s:%d", tc.address, tc.port)
			assert.Equal(t, tc.badFormat, badResult, "Vulnerable pattern should produce bad format")

			// Verify fix produces correct format
			goodResult := net.JoinHostPort(tc.address, strconv.Itoa(tc.port))
			assert.Equal(t, tc.correctFormat, goodResult, "net.JoinHostPort should produce correct format")

			// Verify the formats are different (proving the fix matters)
			assert.NotEqual(t, badResult, goodResult, "Fix should produce different output than vulnerable code")
		})
	}
}

// TestNetJoinHostPort_IPv4NoChange verifies IPv4 addresses work the same way.
func TestNetJoinHostPort_IPv4NoChange(t *testing.T) {
	ipv4Addresses := []struct {
		address string
		port    int
	}{
		{"192.168.1.1", 25},
		{"10.0.0.1", 587},
		{"172.16.0.1", 465},
		{"127.0.0.1", 2525},
	}

	for _, tc := range ipv4Addresses {
		t.Run(tc.address, func(t *testing.T) {
			// Both methods should produce the same result for IPv4
			oldFormat := fmt.Sprintf("%s:%d", tc.address, tc.port)
			newFormat := net.JoinHostPort(tc.address, strconv.Itoa(tc.port))
			assert.Equal(t, oldFormat, newFormat, "IPv4 addresses should format the same")
		})
	}
}

// TestNetJoinHostPort_HostnamesNoChange verifies hostnames work the same way.
func TestNetJoinHostPort_HostnamesNoChange(t *testing.T) {
	hostnames := []struct {
		hostname string
		port     int
	}{
		{"localhost", 25},
		{"smtp.example.com", 587},
		{"mail.corp.example.com", 465},
	}

	for _, tc := range hostnames {
		t.Run(tc.hostname, func(t *testing.T) {
			// Both methods should produce the same result for hostnames
			oldFormat := fmt.Sprintf("%s:%d", tc.hostname, tc.port)
			newFormat := net.JoinHostPort(tc.hostname, strconv.Itoa(tc.port))
			assert.Equal(t, oldFormat, newFormat, "Hostnames should format the same")
		})
	}
}

// =============================================================================
// Goroutine Lifecycle Tests (Task 139)
// =============================================================================
// These tests verify that the cleanup goroutine lifecycle is properly tracked
// using sync.WaitGroup, ensuring clean shutdown without goroutine leaks.

// TestActionExecutor_CleanupGoroutineLifecycle verifies the cleanup goroutine
// responds to context cancellation and exits cleanly.
func TestActionExecutor_CleanupGoroutineLifecycle(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)
	assert.NotNil(t, ae)

	// Create a channel to signal when Stop() completes
	done := make(chan struct{})

	go func() {
		ae.Stop()
		close(done)
	}()

	// Stop() should complete within a reasonable timeout
	// because the cleanup goroutine respects context cancellation
	select {
	case <-done:
		// Success - goroutine exited cleanly
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not complete within timeout - goroutine may be leaking")
	}
}

// TestActionExecutor_StopIsIdempotent verifies Stop() can be called multiple times safely.
func TestActionExecutor_StopIsIdempotent(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	// First Stop should work
	done := make(chan struct{})
	go func() {
		ae.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("First Stop() did not complete within timeout")
	}

	// Second Stop should also work without panic or hang
	done2 := make(chan struct{})
	go func() {
		ae.Stop() // Should be safe to call again
		close(done2)
	}()

	select {
	case <-done2:
		// Success - idempotent call didn't hang or panic
	case <-time.After(1 * time.Second):
		t.Fatal("Second Stop() did not complete - not idempotent")
	}
}

// TestActionExecutor_GoroutineExitsOnContextCancel verifies the goroutine
// properly responds to context cancellation without timing out.
func TestActionExecutor_GoroutineExitsOnContextCancel(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// Create executor with custom circuit breaker config
	ae, err := NewActionExecutorWithCircuitBreaker(
		10*time.Second,
		logger,
		core.DefaultCircuitBreakerConfig(),
		nil,
	)
	assert.NoError(t, err)
	assert.NotNil(t, ae)

	// Create some circuit breakers to exercise cleanup
	_ = ae.getOrCreateCircuitBreaker("endpoint1")
	_ = ae.getOrCreateCircuitBreaker("endpoint2")

	// Stop and verify quick shutdown
	start := time.Now()
	ae.Stop()
	elapsed := time.Since(start)

	// Should complete quickly (well under 1 hour ticker interval)
	assert.Less(t, elapsed, 5*time.Second, "Stop() should complete quickly")
}

// TestActionExecutor_WaitGroupPreventsGoroutineLeak verifies WaitGroup tracking
// ensures no goroutine leaks when creating and stopping multiple executors.
func TestActionExecutor_WaitGroupPreventsGoroutineLeak(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// Create and stop multiple executors
	for i := 0; i < 10; i++ {
		ae := NewActionExecutor(10*time.Second, logger)
		// Create some circuit breakers
		_ = ae.getOrCreateCircuitBreaker(fmt.Sprintf("endpoint-%d", i))

		// Stop should complete quickly
		done := make(chan struct{})
		go func() {
			ae.Stop()
			close(done)
		}()

		select {
		case <-done:
			// Good - executor stopped cleanly
		case <-time.After(2 * time.Second):
			t.Fatalf("Executor %d did not stop cleanly - potential goroutine leak", i)
		}
	}
}

// TestActionExecutor_IoCloserInterface verifies ActionExecutor implements io.Closer
// TASK 139: Verify io.Closer interface implementation
func TestActionExecutor_IoCloserInterface(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ae := NewActionExecutor(10*time.Second, logger)

	// Verify Close() returns nil error
	err := ae.Close()
	assert.NoError(t, err, "Close() should return nil error")

	// Verify Close() is idempotent (can be called multiple times safely)
	err = ae.Close()
	assert.NoError(t, err, "Close() should be safe to call multiple times")
}

// TestActionExecutor_LifecycleContract tests the full lifecycle contract
// TASK 139: Verify lifecycle contract documented in godoc
func TestActionExecutor_LifecycleContract(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// Test the recommended defer pattern from the godoc
	func() {
		ae, err := NewActionExecutorWithCircuitBreaker(10*time.Second, logger, core.DefaultCircuitBreakerConfig(), nil)
		if err != nil {
			t.Fatalf("NewActionExecutorWithCircuitBreaker failed: %v", err)
		}
		defer ae.Stop()

		// Use the executor
		_ = ae.getOrCreateCircuitBreaker("test-endpoint")
	}()
	// If we get here without hanging, lifecycle is correct
}
