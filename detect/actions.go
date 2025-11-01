package detect

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"cerberus/core"
	"cerberus/metrics"
	"go.uber.org/zap"
)

// ActionExecutor handles executing response actions
type ActionExecutor struct {
	httpClient *http.Client
	logger     *zap.SugaredLogger
}

const MaxActionRetries = 3

// NewActionExecutor creates a new action executor
func NewActionExecutor(timeout time.Duration, logger *zap.SugaredLogger) *ActionExecutor {
	return &ActionExecutor{
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
			},
		},
		logger: logger,
	}
}

// retryExecute executes a function with retry logic
func (ae *ActionExecutor) retryExecute(executeFunc func() error, successFormat string, successArgs []interface{}, actionType string) error {
	for i := 0; i < MaxActionRetries; i++ {
		err := executeFunc()
		if err == nil {
			ae.logger.Infof(successFormat, successArgs...)
			metrics.ActionsExecuted.WithLabelValues(actionType).Inc()
			return nil
		}
		ae.logger.Warnf("Action failed (attempt %d/%d): %v", i+1, MaxActionRetries, err)
		if i < MaxActionRetries-1 {
			backoff := time.Duration(1<<uint(i)) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			time.Sleep(backoff)
		}
	}
	return fmt.Errorf("action failed after %d retries", MaxActionRetries)
}

// ExecuteActions executes all actions for a rule match
func (ae *ActionExecutor) ExecuteActions(rule core.AlertableRule, alert *core.Alert) error {
	var errs []error
	for _, action := range rule.GetActions() {
		if action.Config == nil {
			errs = append(errs, fmt.Errorf("action config is nil for type %s", action.Type))
			continue
		}
		switch action.Type {
		case "webhook":
			if err := ae.executeWebhook(action, alert); err != nil {
				ae.logger.Errorf("Error executing webhook action: %v", err)
				errs = append(errs, fmt.Errorf("webhook action failed: %w", err))
			}
		case "jira":
			if err := ae.executeJira(action, alert); err != nil {
				ae.logger.Errorf("Error executing jira action: %v", err)
				errs = append(errs, fmt.Errorf("jira action failed: %w", err))
			}
		case "slack":
			if err := ae.executeSlack(action, alert); err != nil {
				ae.logger.Errorf("Error executing slack action: %v", err)
				errs = append(errs, fmt.Errorf("slack action failed: %w", err))
			}
		case "email":
			if err := ae.executeEmail(action, alert); err != nil {
				ae.logger.Errorf("Error executing email action: %v", err)
				errs = append(errs, fmt.Errorf("email action failed: %w", err))
			}
		default:
			ae.logger.Errorf("Unknown action type: %s", action.Type)
			errs = append(errs, fmt.Errorf("unknown action type: %s", action.Type))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("one or more actions failed: %v", errs)
	}
	return nil
}

// executeWebhook executes a webhook action with retry logic
func (ae *ActionExecutor) executeWebhook(action core.Action, alert *core.Alert) error {
	url, ok := action.Config["url"].(string)
	if !ok {
		ae.logger.Warnf("Webhook URL not found in config")
		return fmt.Errorf("webhook URL not found in config")
	}

	payload, err := json.Marshal(alert)
	if err != nil {
		ae.logger.Errorf("Failed to marshal alert: %v", err)
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	return ae.retryExecute(func() error { return ae.sendWebhook(url, payload) }, "Webhook sent successfully to %s", []interface{}{url}, "webhook")
}

// sendWebhook sends the HTTP POST request
func (ae *ActionExecutor) sendWebhook(url string, payload []byte) error {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ae.httpClient.Do(req)

	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ae.logger.Errorf("Failed to close response body: %v", err)
		}
	}(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// executeJira creates a Jira ticket for the alert
func (ae *ActionExecutor) executeJira(action core.Action, alert *core.Alert) error {
	baseURL, ok := action.Config["base_url"].(string)
	if !ok {
		ae.logger.Warnf("Jira base URL not found in config")
		return fmt.Errorf("Jira base URL not found in config")
	}
	username := os.Getenv("CERBERUS_JIRA_USERNAME")
	if username == "" {
		ae.logger.Warnf("Jira username not set in environment")
		return fmt.Errorf("Jira username not set in environment")
	}
	token := os.Getenv("CERBERUS_JIRA_TOKEN")
	if token == "" {
		ae.logger.Warnf("Jira token not set in environment")
		return fmt.Errorf("Jira token not set in environment")
	}
	project, ok := action.Config["project"].(string)
	if !ok {
		ae.logger.Warnf("Jira project not found in config")
		return fmt.Errorf("Jira project not found in config")
	}

	// Create issue payload
	issue := map[string]interface{}{
		"fields": map[string]interface{}{
			"project":     map[string]string{"key": project},
			"summary":     fmt.Sprintf("Alert: %s", alert.AlertID),
			"description": fmt.Sprintf("Severity: %s\nEvent ID: %s\nRaw Data: %s", alert.Severity, alert.EventID, alert.Event.RawData),
			"issuetype":   map[string]string{"name": "Task"},
		},
	}

	payload, err := json.Marshal(issue)
	if err != nil {
		ae.logger.Errorf("Failed to marshal Jira issue: %v", err)
		return fmt.Errorf("failed to marshal Jira issue: %w", err)
	}

	return ae.retryExecute(func() error { return ae.sendJiraRequest(baseURL, username, token, payload) }, "Jira ticket created successfully for alert %s", []interface{}{alert.AlertID}, "jira")
}

// sendJiraRequest sends the Jira API request
func (ae *ActionExecutor) sendJiraRequest(baseURL, username, token string, payload []byte) error {
	url := fmt.Sprintf("%s/rest/api/2/issue", baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, token)

	resp, err := ae.httpClient.Do(req)

	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ae.logger.Errorf("Failed to close response body: %v", err)
		}
	}(resp.Body)

	if resp.StatusCode != 201 {
		return fmt.Errorf("Jira API returned status %d", resp.StatusCode)
	}
	return nil
}

// executeSlack sends a message to a Slack channel
func (ae *ActionExecutor) executeSlack(action core.Action, alert *core.Alert) error {
	webhookURL, ok := action.Config["webhook_url"].(string)
	if !ok {
		ae.logger.Warnf("Slack webhook URL not found in config")
		return fmt.Errorf("Slack webhook URL not found in config")
	}

	message := map[string]string{
		"text": fmt.Sprintf("Alert: %s\nSeverity: %s\nEvent ID: %s\nRule: %s", alert.AlertID, alert.Severity, alert.EventID, alert.RuleID),
	}

	payload, err := json.Marshal(message)
	if err != nil {
		ae.logger.Errorf("Failed to marshal Slack message: %v", err)
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	return ae.retryExecute(func() error { return ae.sendWebhook(webhookURL, payload) }, "Slack message sent successfully for alert %s", []interface{}{alert.AlertID}, "slack")
}

// executeEmail sends an email notification
func (ae *ActionExecutor) executeEmail(action core.Action, alert *core.Alert) error {
	smtpServer, ok := action.Config["smtp_server"].(string)
	if !ok {
		ae.logger.Warnf("SMTP server not found in config")
		return fmt.Errorf("SMTP server not found in config")
	}
	portFloat, ok := action.Config["port"].(float64)
	if !ok {
		return fmt.Errorf("SMTP port not found in config")
	}
	if portFloat != float64(int(portFloat)) {
		return fmt.Errorf("SMTP port must be an integer")
	}
	port := int(portFloat)
	username := os.Getenv("CERBERUS_SMTP_USERNAME")
	if username == "" {
		ae.logger.Warnf("SMTP username not set in environment")
		return fmt.Errorf("SMTP username not set in environment")
	}
	password := os.Getenv("CERBERUS_SMTP_PASSWORD")
	if password == "" {
		ae.logger.Warnf("SMTP password not set in environment")
		return fmt.Errorf("SMTP password not set in environment")
	}
	from, ok := action.Config["from"].(string)
	if !ok {
		ae.logger.Warnf("From email not found in config")
		return fmt.Errorf("From email not found in config")
	}
	to, ok := action.Config["to"].(string)
	if !ok {
		ae.logger.Warnf("To email not found in config")
		return fmt.Errorf("To email not found in config")
	}

	subject := fmt.Sprintf("Alert: %s", alert.AlertID)
	body := fmt.Sprintf("Severity: %s\nEvent ID: %s\nRule: %s\nRaw Data: %s", alert.Severity, alert.EventID, alert.RuleID, alert.Event.RawData)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", from, to, subject, body)

	auth := smtp.PlainAuth("", username, password, smtpServer)

	sendFunc := func() error {
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", smtpServer, port))
		if err != nil {
			return fmt.Errorf("failed to dial SMTP server: %w", err)
		}
		client, err := smtp.NewClient(conn, smtpServer)
		if err != nil {
			conn.Close()
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Close()

		// Enforce TLS: require STARTTLS support
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not support STARTTLS, refusing to send email without TLS")
		}
		config := &tls.Config{ServerName: smtpServer}
		if err = client.StartTLS(config); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}

		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}

		if err = client.Mail(from); err != nil {
			return fmt.Errorf("failed to set sender: %w", err)
		}

		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("failed to set recipient: %w", err)
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("failed to start data: %w", err)
		}

		_, err = w.Write([]byte(msg))
		if err != nil {
			return fmt.Errorf("failed to write message: %w", err)
		}

		err = w.Close()
		if err != nil {
			return fmt.Errorf("failed to close data: %w", err)
		}

		return client.Quit()
	}

	return ae.retryExecute(sendFunc, "Email sent successfully for alert %s", []interface{}{alert.AlertID}, "email")
}
