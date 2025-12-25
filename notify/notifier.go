package notify

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/smtp"
	"sync"
	"time"

	"cerberus/core"
	"go.uber.org/zap"
)

// NotificationType represents the type of notification channel
type NotificationType string

const (
	// NotificationEmail represents email notification type
	NotificationEmail NotificationType = "email"
	// NotificationWebhook represents webhook notification type
	NotificationWebhook NotificationType = "webhook"
	NotificationSlack   NotificationType = "slack"
)

// NotificationConfig holds configuration for notifications
type NotificationConfig struct {
	Enabled bool             `json:"enabled"`
	Type    NotificationType `json:"type"`

	// Email configuration
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	SMTPUsername string   `json:"smtp_username"`
	SMTPPassword string   `json:"smtp_password"`
	FromAddress  string   `json:"from_address"`
	ToAddresses  []string `json:"to_addresses"`

	// Webhook configuration
	WebhookURL     string            `json:"webhook_url"`
	WebhookMethod  string            `json:"webhook_method"`
	WebhookHeaders map[string]string `json:"webhook_headers"`

	// Filtering
	MinSeverity string   `json:"min_severity"` // critical, high, medium, low
	Statuses    []string `json:"statuses"`     // Filter by alert status
}

// Notifier handles sending notifications for alerts
type Notifier struct {
	configs         []NotificationConfig
	logger          *zap.SugaredLogger
	circuitBreakers map[string]*core.CircuitBreaker // Circuit breakers per notification channel
	cbMu            sync.RWMutex                    // Protects circuitBreakers map
}

// NewNotifier creates a new notifier instance
func NewNotifier(configs []NotificationConfig, logger *zap.SugaredLogger) *Notifier {
	return &Notifier{
		configs:         configs,
		logger:          logger,
		circuitBreakers: make(map[string]*core.CircuitBreaker),
	}
}

// getOrCreateCircuitBreaker gets or creates a circuit breaker for a notification channel
func (n *Notifier) getOrCreateCircuitBreaker(key string) *core.CircuitBreaker {
	n.cbMu.RLock()
	cb, exists := n.circuitBreakers[key]
	n.cbMu.RUnlock()

	if exists {
		return cb
	}

	// Create new circuit breaker
	n.cbMu.Lock()
	defer n.cbMu.Unlock()

	// Double-check after acquiring write lock
	if cb, exists := n.circuitBreakers[key]; exists {
		return cb
	}

	// Create circuit breaker with sensible defaults for notifications
	config := core.CircuitBreakerConfig{
		MaxFailures:         3,                // Open after 3 consecutive failures
		Timeout:             60 * time.Second, // Try again after 1 minute
		MaxHalfOpenRequests: 1,                // Only allow 1 test request
	}
	// TASK 137: Use MustNewCircuitBreaker since this config is hardcoded and guaranteed valid
	cb = core.MustNewCircuitBreaker(config)
	n.circuitBreakers[key] = cb
	n.logger.Infof("Created circuit breaker for notification channel: %s", key)
	return cb
}

// NotifySystemAlert sends notifications for system issues (database failures, etc.)
func (n *Notifier) NotifySystemAlert(title, message string, severity string) error {
	for _, config := range n.configs {
		if !config.Enabled {
			continue
		}

		// For system alerts, use severity filtering if configured
		if config.MinSeverity != "" {
			severityOrder := map[string]int{
				"low":      1,
				"medium":   2,
				"high":     3,
				"critical": 4,
			}

			alertSeverityOrder, exists := severityOrder[severity]
			if !exists {
				alertSeverityOrder = 1 // default to low
			}

			minSeverityOrder, exists := severityOrder[config.MinSeverity]
			if !exists {
				minSeverityOrder = 1 // default to low
			}

			if alertSeverityOrder < minSeverityOrder {
				continue
			}
		}

		// Send notification based on type with circuit breaker protection
		switch config.Type {
		case NotificationEmail:
			key := fmt.Sprintf("system-email:%s", config.SMTPHost)
			cb := n.getOrCreateCircuitBreaker(key)
			if err := cb.Allow(); err != nil {
				n.logger.Warnf("Circuit breaker open for system email notifications to %s: %v", config.SMTPHost, err)
				continue
			}
			if err := n.sendSystemEmailNotification(title, message, severity, config); err != nil {
				cb.RecordFailure()
				n.logger.Errorf("Failed to send system email notification: %v", err)
			} else {
				cb.RecordSuccess()
			}
		case NotificationWebhook:
			key := fmt.Sprintf("system-webhook:%s", config.WebhookURL)
			cb := n.getOrCreateCircuitBreaker(key)
			if err := cb.Allow(); err != nil {
				n.logger.Warnf("Circuit breaker open for system webhook notifications to %s: %v", config.WebhookURL, err)
				continue
			}
			if err := n.sendSystemWebhookNotification(title, message, severity, config); err != nil {
				cb.RecordFailure()
				n.logger.Errorf("Failed to send system webhook notification: %v", err)
			} else {
				cb.RecordSuccess()
			}
		case NotificationSlack:
			key := fmt.Sprintf("system-slack:%s", config.WebhookURL)
			cb := n.getOrCreateCircuitBreaker(key)
			if err := cb.Allow(); err != nil {
				n.logger.Warnf("Circuit breaker open for system Slack notifications to %s: %v", config.WebhookURL, err)
				continue
			}
			if err := n.sendSystemSlackNotification(title, message, severity, config); err != nil {
				cb.RecordFailure()
				n.logger.Errorf("Failed to send system Slack notification: %v", err)
			} else {
				cb.RecordSuccess()
			}
		}
	}

	return nil
}

// NotifyAlert sends notifications for an alert through all configured channels
func (n *Notifier) NotifyAlert(alert *core.Alert) error {
	for _, config := range n.configs {
		if !config.Enabled {
			continue
		}

		// Check if alert matches filter criteria
		if !n.shouldNotify(alert, config) {
			continue
		}

		// Send notification based on type with circuit breaker protection
		switch config.Type {
		case NotificationEmail:
			key := fmt.Sprintf("email:%s", config.SMTPHost)
			cb := n.getOrCreateCircuitBreaker(key)
			if err := cb.Allow(); err != nil {
				n.logger.Warnf("Circuit breaker open for email notifications to %s: %v", config.SMTPHost, err)
				continue
			}
			if err := n.sendEmailNotification(alert, config); err != nil {
				cb.RecordFailure()
				n.logger.Errorf("Failed to send email notification for alert %s: %v", alert.AlertID, err)
			} else {
				cb.RecordSuccess()
			}
		case NotificationWebhook:
			key := fmt.Sprintf("webhook:%s", config.WebhookURL)
			cb := n.getOrCreateCircuitBreaker(key)
			if err := cb.Allow(); err != nil {
				n.logger.Warnf("Circuit breaker open for webhook notifications to %s: %v", config.WebhookURL, err)
				continue
			}
			if err := n.sendWebhookNotification(alert, config); err != nil {
				cb.RecordFailure()
				n.logger.Errorf("Failed to send webhook notification for alert %s: %v", alert.AlertID, err)
			} else {
				cb.RecordSuccess()
			}
		case NotificationSlack:
			key := fmt.Sprintf("slack:%s", config.WebhookURL)
			cb := n.getOrCreateCircuitBreaker(key)
			if err := cb.Allow(); err != nil {
				n.logger.Warnf("Circuit breaker open for Slack notifications to %s: %v", config.WebhookURL, err)
				continue
			}
			if err := n.sendSlackNotification(alert, config); err != nil {
				cb.RecordFailure()
				n.logger.Errorf("Failed to send Slack notification for alert %s: %v", alert.AlertID, err)
			} else {
				cb.RecordSuccess()
			}
		}
	}

	return nil
}

// shouldNotify checks if alert matches notification filters
func (n *Notifier) shouldNotify(alert *core.Alert, config NotificationConfig) bool {
	// Check severity filter
	if config.MinSeverity != "" {
		severityOrder := map[string]int{
			"low":      1,
			"medium":   2,
			"high":     3,
			"critical": 4,
		}

		alertSeverity := severityOrder[alert.Severity]
		minSeverity := severityOrder[config.MinSeverity]

		if alertSeverity < minSeverity {
			return false
		}
	}

	// Check status filter
	if len(config.Statuses) > 0 {
		statusMatch := false
		for _, status := range config.Statuses {
			if status == string(alert.Status) {
				statusMatch = true
				break
			}
		}
		if !statusMatch {
			return false
		}
	}

	return true
}

// sendEmailNotification sends email notification
func (n *Notifier) sendEmailNotification(alert *core.Alert, config NotificationConfig) error {
	subject := fmt.Sprintf("[%s] Alert: %s", alert.Severity, alert.RuleID)
	body := n.formatEmailBody(alert)

	// Setup email message
	message := fmt.Sprintf("From: %s\r\n", config.FromAddress)

	// Check if we have recipients
	if len(config.ToAddresses) == 0 {
		return fmt.Errorf("no recipients specified for email notification")
	}

	// Format To header with all recipients (comma-separated)
	toHeader := ""
	for i, addr := range config.ToAddresses {
		if i > 0 {
			toHeader += ", "
		}
		toHeader += addr
	}
	message += fmt.Sprintf("To: %s\r\n", toHeader)
	message += fmt.Sprintf("Subject: %s\r\n", subject)
	message += "Content-Type: text/html; charset=UTF-8\r\n"
	message += "\r\n" + body

	// Setup TLS configuration for secure connection
	tlsConfig := &tls.Config{
		ServerName: config.SMTPHost,
		MinVersion: tls.VersionTLS12,
	}

	// Setup authentication - prefer secure methods over PLAIN auth
	// PLAIN auth sends credentials in cleartext format (even over TLS)
	// Try CRAM-MD5 first (challenge-response, more secure), fallback to PLAIN over TLS
	auth := smtp.CRAMMD5Auth(config.SMTPUsername, config.SMTPPassword)
	// Note: If CRAM-MD5 fails, the code will fallback to PLAIN auth in the error handling below

	// Send email with TLS - try CRAM-MD5 first, fallback to PLAIN auth
	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)
	err := smtp.SendMail(addr, auth, config.FromAddress, config.ToAddresses, []byte(message))
	if err != nil {
		// If CRAM-MD5 fails, fallback to PLAIN auth over TLS
		// PLAIN auth is acceptable when used over properly configured TLS
		auth = smtp.PlainAuth("", config.SMTPUsername, config.SMTPPassword, config.SMTPHost)
		err = smtp.SendMail(addr, auth, config.FromAddress, config.ToAddresses, []byte(message))
		if err != nil {
			// If both auth methods fail, try with explicit TLS client
			client, err := smtp.Dial(addr)
			if err != nil {
				return fmt.Errorf("failed to connect to SMTP server: %w", err)
			}
			defer func() {
				if err := client.Close(); err != nil {
					n.logger.Warnf("Failed to close SMTP client: %v", err)
				}
			}()

			// Start TLS
			if err = client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("failed to start TLS: %w", err)
			}

			// Authenticate
			if err = client.Auth(auth); err != nil {
				return fmt.Errorf("failed to authenticate: %w", err)
			}

			// Set sender and recipients
			if err = client.Mail(config.FromAddress); err != nil {
				return fmt.Errorf("failed to set sender: %w", err)
			}

			for _, addr := range config.ToAddresses {
				if err = client.Rcpt(addr); err != nil {
					return fmt.Errorf("failed to set recipient %s: %w", addr, err)
				}
			}

			// Send data
			w, err := client.Data()
			if err != nil {
				return fmt.Errorf("failed to initiate data transfer: %w", err)
			}

			_, err = w.Write([]byte(message))
			if err != nil {
				return fmt.Errorf("failed to write message: %w", err)
			}

			if err = w.Close(); err != nil {
				return fmt.Errorf("failed to close data transfer: %w", err)
			}

			err = client.Quit()
			if err != nil {
				return fmt.Errorf("failed to quit: %w", err)
			}
		}
	}

	n.logger.Infof("Sent email notification for alert %s to %d recipients", alert.AlertID, len(config.ToAddresses))
	return nil
}

// formatEmailBody formats alert details for email
func (n *Notifier) formatEmailBody(alert *core.Alert) string {
	// Extract source_ip from event Fields if present
	var eventSourceIP string
	if alert.Event != nil && alert.Event.Fields != nil {
		if ip, ok := alert.Event.Fields["source_ip"].(string); ok {
			eventSourceIP = ip
		}
	}

	// Extract event_type from event Fields if present
	var eventType string
	if alert.Event != nil && alert.Event.Fields != nil {
		if et, ok := alert.Event.Fields["event_type"].(string); ok {
			eventType = et
		}
	}

	// Create safe template data with HTML escaping
	templateData := struct {
		Severity      string
		RuleID        string
		AlertID       string
		Status        string
		Timestamp     string
		EventSourceIP string
		EventType     string
	}{
		Severity:      html.EscapeString(alert.Severity),
		RuleID:        html.EscapeString(alert.RuleID),
		AlertID:       html.EscapeString(alert.AlertID),
		Status:        html.EscapeString(string(alert.Status)),
		Timestamp:     html.EscapeString(alert.Timestamp.Format(time.RFC3339)),
		EventSourceIP: html.EscapeString(eventSourceIP),
		EventType:     html.EscapeString(eventType),
	}

	tmpl := `
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .alert { border-left: 4px solid #f44336; padding: 15px; background: #f9f9f9; }
        .alert.critical { border-color: #d32f2f; }
        .alert.high { border-color: #f44336; }
        .alert.medium { border-color: #ff9800; }
        .alert.low { border-color: #2196f3; }
        .field { margin: 10px 0; }
        .label { font-weight: bold; color: #555; }
        .value { color: #333; }
        .code { background: #f5f5f5; padding: 5px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="alert {{.Severity}}">
        <h2>🚨 Security Alert: {{.RuleID}}</h2>

        <div class="field">
            <span class="label">Alert ID:</span>
            <span class="value code">{{.AlertID}}</span>
        </div>

        <div class="field">
            <span class="label">Severity:</span>
            <span class="value">{{.Severity}}</span>
        </div>

        <div class="field">
            <span class="label">Status:</span>
            <span class="value">{{.Status}}</span>
        </div>

        <div class="field">
            <span class="label">Timestamp:</span>
            <span class="value">{{.Timestamp}}</span>
        </div>

        <div class="field">
            <span class="label">Source IP:</span>
            <span class="value code">{{.EventSourceIP}}</span>
        </div>

        <div class="field">
            <span class="label">Event Type:</span>
            <span class="value">{{.EventType}}</span>
        </div>

        <hr>
        <p><a href="http://localhost:8080">View in Cerberus Dashboard</a></p>
    </div>
</body>
</html>
`

	t := template.Must(template.New("email").Parse(tmpl))
	var buf bytes.Buffer
	t.Execute(&buf, templateData)
	return buf.String()
}

// sendWebhookNotification sends webhook notification
func (n *Notifier) sendWebhookNotification(alert *core.Alert, config NotificationConfig) error {
	// Extract source_ip from event Fields if present
	var eventSourceIP string
	if alert.Event != nil && alert.Event.Fields != nil {
		if ip, ok := alert.Event.Fields["source_ip"].(string); ok {
			eventSourceIP = ip
		}
	}

	// Extract event_type from event Fields if present
	var eventType string
	if alert.Event != nil && alert.Event.Fields != nil {
		if et, ok := alert.Event.Fields["event_type"].(string); ok {
			eventType = et
		}
	}

	// Prepare payload
	payload := map[string]interface{}{
		"alert_id":  alert.AlertID,
		"rule_id":   alert.RuleID,
		"severity":  alert.Severity,
		"status":    alert.Status,
		"timestamp": alert.Timestamp,
		"event": map[string]interface{}{
			"event_id":   alert.Event.EventID,
			"event_type": eventType,
			"source_ip":  eventSourceIP,
			"timestamp":  alert.Event.Timestamp,
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	// Create HTTP request
	method := config.WebhookMethod
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequest(method, config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Cerberus-SIEM/1.0")
	for key, value := range config.WebhookHeaders {
		req.Header.Set(key, value)
	}

	// Send request with proper TLS configuration
	// FIX #33: Ensure TLS certificate validation is enabled
	client := &http.Client{
		Timeout: core.HTTPClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// InsecureSkipVerify is intentionally set to false (default)
				// to ensure proper certificate validation
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			n.logger.Debugf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-2xx status: %d", resp.StatusCode)
	}

	n.logger.Infof("Sent webhook notification for alert %s", alert.AlertID)
	return nil
}

// sendSlackNotification sends Slack notification
func (n *Notifier) sendSlackNotification(alert *core.Alert, config NotificationConfig) error {
	severityColor := map[string]string{
		"critical": "#d32f2f",
		"high":     "#f44336",
		"medium":   "#ff9800",
		"low":      "#2196f3",
	}

	color := severityColor[alert.Severity]
	if color == "" {
		color = "#757575"
	}

	// Extract source_ip from event Fields if present
	var eventSourceIP string
	if alert.Event != nil && alert.Event.Fields != nil {
		if ip, ok := alert.Event.Fields["source_ip"].(string); ok {
			eventSourceIP = ip
		}
	}

	// Extract event_type from event Fields if present
	var eventType string
	if alert.Event != nil && alert.Event.Fields != nil {
		if et, ok := alert.Event.Fields["event_type"].(string); ok {
			eventType = et
		}
	}

	// Slack message format
	payload := map[string]interface{}{
		"text": fmt.Sprintf("🚨 *%s Severity Alert*", alert.Severity),
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"fields": []map[string]interface{}{
					{
						"title": "Rule",
						"value": alert.RuleID,
						"short": true,
					},
					{
						"title": "Alert ID",
						"value": fmt.Sprintf("`%s`", alert.AlertID),
						"short": true,
					},
					{
						"title": "Source IP",
						"value": fmt.Sprintf("`%s`", eventSourceIP),
						"short": true,
					},
					{
						"title": "Event Type",
						"value": eventType,
						"short": true,
					},
				},
				"footer": "Cerberus SIEM",
				"ts":     time.Now().Unix(),
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	// Send to Slack webhook
	resp, err := http.Post(config.WebhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send Slack notification: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			n.logger.Debugf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned non-OK status: %d", resp.StatusCode)
	}

	n.logger.Infof("Sent Slack notification for alert %s", alert.AlertID)
	return nil
}

// sendSystemEmailNotification sends email notification for system alerts
func (n *Notifier) sendSystemEmailNotification(title, message, severity string, config NotificationConfig) error {
	// Create email body
	body := fmt.Sprintf(`Subject: [%s] Cerberus System Alert: %s

%s

This is an automated notification from Cerberus SIEM.
Time: %s
Severity: %s

Please check the system logs and dashboard for more details.
`, severity, title, message, time.Now().Format(time.RFC3339), severity)

	// Send email
	err := smtp.SendMail(
		fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort),
		smtp.PlainAuth("", config.SMTPUsername, config.SMTPPassword, config.SMTPHost),
		config.FromAddress,
		config.ToAddresses,
		[]byte(body),
	)
	if err != nil {
		return fmt.Errorf("failed to send system email: %w", err)
	}

	n.logger.Infof("Sent system email notification: %s", title)
	return nil
}

// sendSystemWebhookNotification sends webhook notification for system alerts
func (n *Notifier) sendSystemWebhookNotification(title, message, severity string, config NotificationConfig) error {
	// Prepare payload
	payload := map[string]interface{}{
		"type":      "system_alert",
		"title":     title,
		"message":   message,
		"severity":  severity,
		"timestamp": time.Now().Format(time.RFC3339),
		"system":    "cerberus-siem",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal system webhook payload: %w", err)
	}

	// Create HTTP request
	method := config.WebhookMethod
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequest(method, config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create system webhook request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Cerberus-SIEM/1.0")
	for key, value := range config.WebhookHeaders {
		req.Header.Set(key, value)
	}

	// Send request with proper TLS configuration
	// FIX #33: Ensure TLS certificate validation is enabled
	client := &http.Client{
		Timeout: core.HTTPClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// InsecureSkipVerify is intentionally set to false (default)
				// to ensure proper certificate validation
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send system webhook: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			n.logger.Debugf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("system webhook returned non-2xx status: %d", resp.StatusCode)
	}

	n.logger.Infof("Sent system webhook notification: %s", title)
	return nil
}

// sendSystemSlackNotification sends Slack notification for system alerts
func (n *Notifier) sendSystemSlackNotification(title, message, severity string, config NotificationConfig) error {
	severityEmoji := map[string]string{
		"critical": "🚨",
		"high":     "🔴",
		"medium":   "🟡",
		"low":      "🔵",
	}

	emoji := severityEmoji[severity]
	if emoji == "" {
		emoji = "⚠️"
	}

	// Slack message format
	payload := map[string]interface{}{
		"text": fmt.Sprintf("%s *System Alert: %s*", emoji, title),
		"attachments": []map[string]interface{}{
			{
				"color": "#d32f2f", // Red for system alerts
				"fields": []map[string]interface{}{
					{
						"title": "Severity",
						"value": severity,
						"short": true,
					},
					{
						"title": "Time",
						"value": time.Now().Format(time.RFC3339),
						"short": true,
					},
				},
				"text":   message,
				"footer": "Cerberus SIEM - System Alert",
				"ts":     time.Now().Unix(),
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal system Slack payload: %w", err)
	}

	// Send to Slack webhook
	resp, err := http.Post(config.WebhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send system Slack notification: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			n.logger.Debugf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("system Slack notification returned non-OK status: %d", resp.StatusCode)
	}

	n.logger.Infof("Sent system Slack notification: %s", title)
	return nil
}
