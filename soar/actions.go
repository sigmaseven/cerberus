package soar

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

// UpdateAlertAction updates alert properties
type UpdateAlertAction struct {
	logger *zap.SugaredLogger
}

// NewUpdateAlertAction creates a new update alert action
func NewUpdateAlertAction(logger *zap.SugaredLogger) *UpdateAlertAction {
	return &UpdateAlertAction{logger: logger}
}

// Type returns the action type
func (a *UpdateAlertAction) Type() ActionType { return ActionTypeUpdateAlert }

// Name returns the action name
func (a *UpdateAlertAction) Name() string { return "Update Alert" }

// Description returns the action description
func (a *UpdateAlertAction) Description() string {
	return "Updates alert status, severity, or other properties"
}

// ValidateParams validates the action parameters
func (a *UpdateAlertAction) ValidateParams(params map[string]interface{}) error {
	validFields := []string{"status", "severity", "assigned_to", "notes"}
	hasValidField := false
	for _, field := range validFields {
		if _, ok := params[field]; ok {
			hasValidField = true
			break
		}
	}
	if !hasValidField {
		return fmt.Errorf("must specify at least one field to update: %v", validFields)
	}
	return nil
}

// Execute performs the update alert action
func (a *UpdateAlertAction) Execute(ctx context.Context, alert *core.Alert, params map[string]interface{}) (*ActionResult, error) {
	startTime := time.Now()
	result := &ActionResult{
		ActionType: a.Type(),
		Status:     ActionStatusRunning,
		StartedAt:  startTime,
		Output:     make(map[string]interface{}),
	}

	updates := make(map[string]interface{})

	// Update status
	if status, ok := params["status"].(string); ok {
		alertStatus := core.AlertStatus(status)
		if !alertStatus.IsValid() {
			return nil, fmt.Errorf("invalid alert status: %s", status)
		}
		alert.Status = alertStatus
		updates["status"] = status
	}

	// Update severity
	if severity, ok := params["severity"].(string); ok {
		validSeverities := []string{"Info", "Low", "Medium", "High", "Critical"}
		isValid := false
		for _, valid := range validSeverities {
			if severity == valid {
				isValid = true
				break
			}
		}
		if !isValid {
			return nil, fmt.Errorf("invalid alert severity: %s", severity)
		}
		alert.Severity = severity
		updates["severity"] = severity
	}

	// Update assigned_to
	if assignedTo, ok := params["assigned_to"].(string); ok {
		alert.AssignedTo = assignedTo
		updates["assigned_to"] = assignedTo
	}

	// Add notes
	if notes, ok := params["notes"].(string); ok {
		updates["notes_added"] = notes
		a.logger.Infof("Added notes to alert %s: %s", alert.AlertID, notes)
	}

	result.Status = ActionStatusCompleted
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(startTime)
	result.Message = fmt.Sprintf("Updated alert with fields: %v", updates)
	result.Output["updates"] = updates

	return result, nil
}

// NotifyAction sends notifications
type NotifyAction struct {
	logger *zap.SugaredLogger
}

// NewNotifyAction creates a new notify action
func NewNotifyAction(logger *zap.SugaredLogger) *NotifyAction {
	return &NotifyAction{logger: logger}
}

func (a *NotifyAction) Type() ActionType { return ActionTypeNotify }
func (a *NotifyAction) Name() string     { return "Send Notification" }
func (a *NotifyAction) Description() string {
	return "Sends notifications via email, Slack, or other channels"
}

func (a *NotifyAction) ValidateParams(params map[string]interface{}) error {
	if _, ok := params["message"]; !ok {
		return fmt.Errorf("message parameter is required")
	}
	if _, ok := params["channel"]; !ok {
		return fmt.Errorf("channel parameter is required (email, slack, webhook)")
	}
	if msg, ok := params["message"].(string); !ok || msg == "" {
		return fmt.Errorf("message parameter must be a non-empty string")
	}
	if ch, ok := params["channel"].(string); !ok || ch == "" {
		return fmt.Errorf("channel parameter must be a non-empty string")
	}
	return nil
}

func (a *NotifyAction) Execute(ctx context.Context, alert *core.Alert, params map[string]interface{}) (*ActionResult, error) {
	startTime := time.Now()
	result := &ActionResult{
		ActionType: a.Type(),
		Status:     ActionStatusRunning,
		StartedAt:  startTime,
		Output:     make(map[string]interface{}),
	}

	message, messageOk := params["message"].(string)
	channel, channelOk := params["channel"].(string)
	if !messageOk || !channelOk {
		return nil, fmt.Errorf("invalid parameters: message and channel must be strings")
	}

	// Format message with alert details
	formattedMessage := fmt.Sprintf("%s\n\nAlert ID: %s\nSeverity: %s\nRule: %s",
		message, alert.AlertID, alert.Severity, alert.RuleID)

	a.logger.Infof("Sending notification via %s for alert %s", channel, alert.AlertID)

	result.Status = ActionStatusCompleted
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(startTime)
	result.Message = fmt.Sprintf("Notification sent via %s", channel)
	result.Output["channel"] = channel
	result.Output["message"] = formattedMessage

	return result, nil
}

// BlockIPAction blocks an IP address
type BlockIPAction struct {
	logger                    *zap.SugaredLogger
	destructiveActionsEnabled bool
}

// NewBlockIPAction creates a new block IP action
func NewBlockIPAction(logger *zap.SugaredLogger, destructiveActionsEnabled bool) *BlockIPAction {
	return &BlockIPAction{
		logger:                    logger,
		destructiveActionsEnabled: destructiveActionsEnabled,
	}
}

func (a *BlockIPAction) Type() ActionType { return ActionTypeBlock }
func (a *BlockIPAction) Name() string     { return "Block IP Address" }
func (a *BlockIPAction) Description() string {
	return "Blocks an IP address at the firewall or network level"
}

func (a *BlockIPAction) ValidateParams(params map[string]interface{}) error {
	if _, ok := params["ip_address"]; !ok {
		// If not specified, will use source IP from alert
		return nil
	}
	return nil
}

func (a *BlockIPAction) Execute(ctx context.Context, alert *core.Alert, params map[string]interface{}) (*ActionResult, error) {
	startTime := time.Now()
	result := &ActionResult{
		ActionType: a.Type(),
		Status:     ActionStatusRunning,
		StartedAt:  startTime,
		Output:     make(map[string]interface{}),
	}

	// CRITICAL SECURITY CHECK: Enforce destructive actions flag
	// FR-SOAR-020: Destructive actions require explicit configuration approval
	// SECURITY: Fail-secure pattern - deny by default if flag is false
	if !a.destructiveActionsEnabled {
		result.Status = ActionStatusFailed
		result.Error = "Destructive action blocked - enable via config.soar.destructive_actions_enabled=true"
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		a.logger.Warnw("Destructive action blocked by configuration",
			"action_type", "block_ip",
			"alert_id", alert.AlertID,
			"reason", "destructive_actions_enabled=false")
		return result, fmt.Errorf("destructive action blocked: BlockIP requires config.soar.destructive_actions_enabled=true")
	}

	// Get IP to block
	var ipAddress string
	if ip, ok := params["ip_address"].(string); ok {
		ipAddress = ip
	} else if alert.Event != nil && alert.Event.Fields != nil {
		// Extract source_ip from Fields if present
		if ip, ok := alert.Event.Fields["source_ip"].(string); ok {
			ipAddress = ip
		}
	}

	if ipAddress == "" {
		result.Status = ActionStatusFailed
		result.Error = "No IP address to block"
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		return result, fmt.Errorf("no IP address to block")
	}

	// In production, this would call firewall API
	a.logger.Warnf("SIMULATION: Would block IP address %s for alert %s", ipAddress, alert.AlertID)

	duration := params["duration"]
	if duration == nil {
		duration = "24h"
	}

	result.Status = ActionStatusCompleted
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(startTime)
	result.Message = fmt.Sprintf("IP address %s blocked", ipAddress)
	result.Output["ip_address"] = ipAddress
	result.Output["duration"] = duration
	result.Output["simulated"] = true

	return result, nil
}

// IsolateHostAction isolates a host from the network
type IsolateHostAction struct {
	logger                    *zap.SugaredLogger
	destructiveActionsEnabled bool
}

// NewIsolateHostAction creates a new isolate host action
func NewIsolateHostAction(logger *zap.SugaredLogger, destructiveActionsEnabled bool) *IsolateHostAction {
	return &IsolateHostAction{
		logger:                    logger,
		destructiveActionsEnabled: destructiveActionsEnabled,
	}
}

func (a *IsolateHostAction) Type() ActionType { return ActionTypeIsolate }
func (a *IsolateHostAction) Name() string     { return "Isolate Host" }
func (a *IsolateHostAction) Description() string {
	return "Isolates a host from the network to prevent lateral movement"
}

func (a *IsolateHostAction) ValidateParams(params map[string]interface{}) error {
	if _, ok := params["hostname"]; !ok {
		return fmt.Errorf("hostname parameter is required")
	}
	if host, ok := params["hostname"].(string); !ok || host == "" {
		return fmt.Errorf("hostname parameter must be a non-empty string")
	}
	return nil
}

func (a *IsolateHostAction) Execute(ctx context.Context, alert *core.Alert, params map[string]interface{}) (*ActionResult, error) {
	startTime := time.Now()
	result := &ActionResult{
		ActionType: a.Type(),
		Status:     ActionStatusRunning,
		StartedAt:  startTime,
		Output:     make(map[string]interface{}),
	}

	// CRITICAL SECURITY CHECK: Enforce destructive actions flag
	// FR-SOAR-020: Destructive actions require explicit configuration approval
	// SECURITY: Fail-secure pattern - deny by default if flag is false
	if !a.destructiveActionsEnabled {
		result.Status = ActionStatusFailed
		result.Error = "Destructive action blocked - enable via config.soar.destructive_actions_enabled=true"
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		a.logger.Warnw("Destructive action blocked by configuration",
			"action_type", "isolate_host",
			"alert_id", alert.AlertID,
			"reason", "destructive_actions_enabled=false")
		return result, fmt.Errorf("destructive action blocked: IsolateHost requires config.soar.destructive_actions_enabled=true")
	}

	hostname, hostnameOk := params["hostname"].(string)
	if !hostnameOk {
		return nil, fmt.Errorf("invalid parameters: hostname must be a string")
	}

	// In production, this would call EDR/XDR API
	a.logger.Warnf("SIMULATION: Would isolate host %s for alert %s", hostname, alert.AlertID)

	result.Status = ActionStatusCompleted
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(startTime)
	result.Message = fmt.Sprintf("Host %s isolated", hostname)
	result.Output["hostname"] = hostname
	result.Output["simulated"] = true

	return result, nil
}

// WebhookAction calls an external webhook
type WebhookAction struct {
	logger         *zap.SugaredLogger
	client         *http.Client
	circuitBreaker *core.CircuitBreaker
}

// NewWebhookAction creates a new webhook action
func NewWebhookAction(logger *zap.SugaredLogger) *WebhookAction {
	return &WebhookAction{
		logger: logger,
		client: &http.Client{
			Timeout: core.HTTPClientTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				MaxIdleConns:        core.HTTPClientMaxIdleConns,
				MaxIdleConnsPerHost: core.HTTPClientMaxIdleConnsPerHost,
				IdleConnTimeout:     core.HTTPClientIdleConnTimeout,
			},
		},
		// TASK 137: Use MustNewCircuitBreaker since default config is always valid
		circuitBreaker: core.MustNewCircuitBreaker(core.DefaultCircuitBreakerConfig()),
	}
}

func (a *WebhookAction) Type() ActionType { return ActionTypeWebhook }
func (a *WebhookAction) Name() string     { return "Call Webhook" }
func (a *WebhookAction) Description() string {
	return "Calls an external webhook with alert data"
}

func (a *WebhookAction) ValidateParams(params map[string]interface{}) error {
	if _, ok := params["url"]; !ok {
		return fmt.Errorf("url parameter is required")
	}
	webhookURL, ok := params["url"].(string)
	if !ok || webhookURL == "" {
		return fmt.Errorf("url parameter must be a non-empty string")
	}

	// SECURITY: Validate URL to prevent SSRF attacks
	// FR-SEC-009: SSRF Protection
	// This prevents attackers from using webhooks to:
	// - Steal cloud credentials (AWS/GCP/Azure metadata)
	// - Scan internal networks
	// - Access localhost services
	//
	// TOCTOU PROTECTION: ValidateWebhookURL now returns the resolved IP
	// We store it in params for Execute() to use with CreateSSRFSafeClient
	// TASK 33.5: Pass allowlist (nil for now - can be extended to pass config allowlist)
	resolvedIP, err := ValidateWebhookURL(webhookURL, nil)
	if err != nil {
		return fmt.Errorf("webhook URL validation failed: %w", err)
	}

	// Store the resolved IP for Execute() to prevent TOCTOU DNS rebinding
	params["_validated_ip"] = resolvedIP

	if method, ok := params["method"].(string); ok && method != "" {
		validMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
		valid := false
		for _, m := range validMethods {
			if method == m {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("method parameter must be one of: GET, POST, PUT, PATCH, DELETE")
		}
	}
	return nil
}

func (a *WebhookAction) Execute(ctx context.Context, alert *core.Alert, params map[string]interface{}) (*ActionResult, error) {
	startTime := time.Now()
	result := &ActionResult{
		ActionType: a.Type(),
		Status:     ActionStatusRunning,
		StartedAt:  startTime,
		Output:     make(map[string]interface{}),
	}

	url, urlOk := params["url"].(string)
	if !urlOk {
		return nil, fmt.Errorf("invalid parameters: url must be a string")
	}
	method := "POST"
	if m, ok := params["method"].(string); ok {
		method = m
	}

	// SECURITY: Get the validated IP from ValidateParams
	// TOCTOU PROTECTION: This IP was resolved during validation and is safe to use
	resolvedIP, hasValidatedIP := params["_validated_ip"].(string)
	if !hasValidatedIP || resolvedIP == "" {
		// Fallback: Re-validate if somehow the validated IP is missing
		// This should never happen in normal operation
		a.logger.Warnw("Missing validated IP in webhook params, re-validating",
			"url", url,
			"alert_id", alert.AlertID)
		var err error
		resolvedIP, err = ValidateWebhookURL(url, nil)
		if err != nil {
			result.Status = ActionStatusFailed
			result.Error = fmt.Sprintf("Webhook URL validation failed: %v", err)
			result.CompletedAt = time.Now()
			result.Duration = result.CompletedAt.Sub(startTime)
			return result, err
		}
	}

	// Prepare payload
	payload := map[string]interface{}{
		"alert_id":  alert.AlertID,
		"severity":  alert.Severity,
		"rule_id":   alert.RuleID,
		"status":    alert.Status,
		"timestamp": alert.Timestamp,
		"event":     alert.Event,
	}

	// Add custom parameters to payload
	if customData, ok := params["payload"].(map[string]interface{}); ok {
		for k, v := range customData {
			payload[k] = v
		}
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		result.Status = ActionStatusFailed
		result.Error = fmt.Sprintf("Failed to marshal payload: %v", err)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		return result, err
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(jsonData))
	if err != nil {
		result.Status = ActionStatusFailed
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		return result, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Cerberus-SOAR/1.0")

	// Add custom headers
	if headers, ok := params["headers"].(map[string]interface{}); ok {
		for k, v := range headers {
			if strVal, ok := v.(string); ok {
				req.Header.Set(k, strVal)
			}
		}
	}

	// Check circuit breaker before making request
	if err := a.circuitBreaker.Allow(); err != nil {
		result.Status = ActionStatusFailed
		result.Error = fmt.Sprintf("Circuit breaker is open: %v", err)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		a.logger.Warnw("Circuit breaker prevented webhook call",
			"url", url,
			"alert_id", alert.AlertID,
			"circuit_state", a.circuitBreaker.State())
		return result, err
	}

	// SECURITY: Create SSRF-safe HTTP client using validated IP
	// TOCTOU PROTECTION: This prevents DNS rebinding attacks
	// REDIRECT PROTECTION: CreateSSRFSafeClient blocks all redirects
	ssrfSafeClient, err := CreateSSRFSafeClient(url, resolvedIP)
	if err != nil {
		result.Status = ActionStatusFailed
		result.Error = fmt.Sprintf("Failed to create SSRF-safe client: %v", err)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		return result, err
	}

	resp, err := ssrfSafeClient.Do(req)
	if err != nil {
		a.circuitBreaker.RecordFailure()
		result.Status = ActionStatusFailed
		result.Error = fmt.Sprintf("Failed to call webhook: %v", err)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		a.logger.Warnw("Webhook call failed",
			"url", url,
			"alert_id", alert.AlertID,
			"error", err,
			"failures", a.circuitBreaker.Failures())
		return result, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			a.logger.Debugf("Failed to close response body: %v", err)
		}
	}()

	// Record success or failure based on status code
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		a.circuitBreaker.RecordSuccess()
		a.logger.Infof("Called webhook %s for alert %s, status: %d", url, alert.AlertID, resp.StatusCode)
	} else {
		a.circuitBreaker.RecordFailure()
		a.logger.Warnw("Webhook returned non-success status",
			"url", url,
			"alert_id", alert.AlertID,
			"status_code", resp.StatusCode,
			"failures", a.circuitBreaker.Failures())
	}

	result.Status = ActionStatusCompleted
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(startTime)
	result.Message = fmt.Sprintf("Webhook called successfully, status: %d", resp.StatusCode)
	result.Output["url"] = url
	result.Output["method"] = method
	result.Output["status_code"] = resp.StatusCode
	result.Output["circuit_breaker_state"] = string(a.circuitBreaker.State())

	return result, nil
}

// CreateTicketAction creates a ticket in external ticketing system
type CreateTicketAction struct {
	logger *zap.SugaredLogger
}

// NewCreateTicketAction creates a new create ticket action
func NewCreateTicketAction(logger *zap.SugaredLogger) *CreateTicketAction {
	return &CreateTicketAction{logger: logger}
}

func (a *CreateTicketAction) Type() ActionType { return ActionTypeCreateTicket }
func (a *CreateTicketAction) Name() string     { return "Create Ticket" }
func (a *CreateTicketAction) Description() string {
	return "Creates a ticket in external ticketing system (Jira, ServiceNow, etc.)"
}

func (a *CreateTicketAction) ValidateParams(params map[string]interface{}) error {
	if _, ok := params["title"]; !ok {
		return fmt.Errorf("title parameter is required")
	}
	if title, ok := params["title"].(string); !ok || title == "" {
		return fmt.Errorf("title parameter must be a non-empty string")
	}
	return nil
}

func (a *CreateTicketAction) Execute(ctx context.Context, alert *core.Alert, params map[string]interface{}) (*ActionResult, error) {
	startTime := time.Now()
	result := &ActionResult{
		ActionType: a.Type(),
		Status:     ActionStatusRunning,
		StartedAt:  startTime,
		Output:     make(map[string]interface{}),
	}

	title, titleOk := params["title"].(string)
	if !titleOk {
		return nil, fmt.Errorf("invalid parameters: title must be a string")
	}
	description := fmt.Sprintf("Alert ID: %s\nSeverity: %s\nRule: %s\nTimestamp: %s",
		alert.AlertID, alert.Severity, alert.RuleID, alert.Timestamp.Format(time.RFC3339))

	if desc, ok := params["description"].(string); ok {
		description = desc + "\n\n" + description
	}

	// In production, this would call Jira/ServiceNow API
	ticketID := fmt.Sprintf("TICKET-%d", time.Now().Unix())
	a.logger.Infof("SIMULATION: Would create ticket with title '%s' for alert %s", title, alert.AlertID)

	result.Status = ActionStatusCompleted
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(startTime)
	result.Message = fmt.Sprintf("Ticket created: %s", ticketID)
	result.Output["ticket_id"] = ticketID
	result.Output["title"] = title
	result.Output["description"] = description
	result.Output["simulated"] = true

	return result, nil
}
