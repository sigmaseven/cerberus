package api

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
	"unicode"

	"cerberus/core"
	"cerberus/storage"

	"github.com/gorilla/mux"
)

// getAlerts godoc
//
//	@Summary		Get alerts
//	@Description	Retrieves a paginated list of alerts with filtering, sorting, and search.
//	@Description
//	@Description	**Disposition Filters Behavior:**
//	@Description	- `disposition`: Filter by specific values (case-insensitive). Multiple values allowed.
//	@Description	- `has_disposition`: Boolean filter (true=any verdict set, false=undetermined only)
//	@Description
//	@Description	**Conflicting Filter Auto-Resolution:**
//	@Description	When both filters are specified, conflicts are automatically resolved:
//	@Description	- `has_disposition=true&disposition=undetermined`: undetermined is removed from disposition filter
//	@Description	- `has_disposition=false&disposition=[any value]`: disposition filter is ignored (only undetermined returned)
//	@Description
//	@Description	Invalid disposition values are silently ignored. Maximum 10 disposition values per request.
//	@Tags			alerts
//	@Produce		json
//	@Param			page			query		int		false	"Page number (default 1)"
//	@Param			limit			query		int		false	"Items per page (default 100, max 10000)"
//	@Param			q				query		string	false	"Search query (title, description, rule name)"
//	@Param			severity		query		string	false	"Filter by severity (critical, high, medium, low)"
//	@Param			status			query		string	false	"Filter by status (pending, acknowledged, investigating, resolved, escalated, closed)"
//	@Param			rule_id			query		string	false	"Filter by rule ID"
//	@Param			assigned_to		query		string	false	"Filter by assignee username"
//	@Param			tags			query		string	false	"Filter by tags"
//	@Param			disposition		query		string	false	"Filter by disposition (true_positive, false_positive, benign, undetermined). Case-insensitive. Multiple values allowed."
//	@Param			has_disposition	query		boolean	false	"Filter by disposition status (true = any verdict set, false = undetermined only)"
//	@Param			mitre_tactic	query		string	false	"Filter by MITRE tactic"
//	@Param			mitre_technique	query		string	false	"Filter by MITRE technique"
//	@Param			created_after	query		string	false	"Filter by creation date (RFC3339)"
//	@Param			created_before	query		string	false	"Filter by creation date (RFC3339)"
//	@Param			updated_after	query		string	false	"Filter by update date (RFC3339)"
//	@Param			updated_before	query		string	false	"Filter by update date (RFC3339)"
//	@Param			sort			query		string	false	"Sort field (created_at, updated_at, severity, status) with optional - prefix for desc"
//	@Param			sort_order		query		string	false	"Sort order (asc, desc)"
//	@Success		200				{object}	PaginationResponse
//	@Failure		500				{string}	string	"Internal server error"
//	@Router			/api/alerts [get]
//	TASK 47: Collection endpoint filtering for alerts
//	TASK 110: Updated to use GetAlertsWithFilters for comprehensive disposition filtering
//	TASK 145.2: Refactored to use AlertService for business logic separation
func (a *API) getAlerts(w http.ResponseWriter, r *http.Request) {
	// Parse filters from query parameters
	filters := ParseAlertFilters(r)

	// TASK 145.2: Use alert service for business logic (filtering, pagination, enrichment)
	if a.alertService == nil {
		// Fallback to direct storage access if service not initialized
		a.getAlertsLegacy(w, r, filters)
		return
	}

	// Get alerts with filtering and enrichment via service layer
	alerts, total, err := a.alertService.ListAlerts(r.Context(), filters)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve alerts", err, a.logger)
		return
	}

	// Convert []*Alert to []Alert for response
	alertsVal := make([]core.Alert, len(alerts))
	for i, alert := range alerts {
		if alert != nil {
			alertsVal[i] = *alert
		}
	}

	// Create paginated response
	response := NewPaginationResponse(alertsVal, total, filters.Page, filters.Limit)
	a.respondJSON(w, response, http.StatusOK)
}

// getAlertsLegacy is the legacy implementation for backward compatibility
// TASK 145.2: Will be removed once all tests migrate to service layer
func (a *API) getAlertsLegacy(w http.ResponseWriter, r *http.Request, filters *core.AlertFilters) {
	var alerts []core.Alert
	var total int64
	var err error

	// Use ClickHouse alert storage
	if a.alertStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert storage not available", nil, a.logger)
		return
	}

	// TASK 110: Use GetAlertsWithFilters for comprehensive filtering including disposition
	if hasFilters(filters) {
		alertList, total, err := a.alertStorage.GetAlertsWithFilters(r.Context(), filters)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve alerts", err, a.logger)
			return
		}

		// Convert []*Alert to []Alert
		alerts = make([]core.Alert, len(alertList))
		for i, alert := range alertList {
			if alert != nil {
				alerts[i] = *alert
			}
		}

		// Enrich alerts with rule information (name, type, MITRE techniques)
		a.enrichAlertsWithRuleInfo(alerts)

		// Create paginated response
		response := NewPaginationResponse(alerts, total, filters.Page, filters.Limit)
		a.respondJSON(w, response, http.StatusOK)
		return
	}

	// No filters, use simple query
	offset := (filters.Page - 1) * filters.Limit
	alerts, err = a.alertStorage.GetAlerts(r.Context(), filters.Limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve alerts", err, a.logger)
		return
	}

	total, err = a.alertStorage.GetAlertCount(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get alert count", err, a.logger)
		return
	}

	// Enrich alerts with rule information (name, type, MITRE techniques)
	a.enrichAlertsWithRuleInfo(alerts)

	// Create paginated response
	response := NewPaginationResponse(alerts, total, filters.Page, filters.Limit)
	a.respondJSON(w, response, http.StatusOK)
}

// Helper functions for filtering
func hasFilters(filters *core.AlertFilters) bool {
	return filters.Search != "" ||
		len(filters.Severities) > 0 ||
		len(filters.Statuses) > 0 ||
		len(filters.RuleIDs) > 0 ||
		len(filters.AssignedTo) > 0 ||
		len(filters.Tags) > 0 ||
		len(filters.MitreTactics) > 0 ||
		len(filters.MitreTechniques) > 0 ||
		filters.CreatedAfter != nil ||
		filters.CreatedBefore != nil ||
		filters.UpdatedAfter != nil ||
		filters.UpdatedBefore != nil ||
		len(filters.Dispositions) > 0 || // TASK 110: Disposition filter
		filters.HasDisposition != nil // TASK 110: HasDisposition boolean filter
}

// TASK 138: Removed unused getFirst function

// enrichAlertWithRuleInfo populates RuleName and RuleType from the rules storage
func (a *API) enrichAlertWithRuleInfo(alert *core.Alert) {
	if alert == nil || alert.RuleID == "" {
		return
	}

	// Try to get rule from storage
	if a.ruleStorage != nil {
		rule, err := a.ruleStorage.GetRule(alert.RuleID)
		if err == nil && rule != nil {
			alert.RuleName = rule.Name
			alert.RuleDescription = rule.Description
			alert.RuleType = rule.Type
			if len(rule.Tags) > 0 {
				// Extract MITRE techniques from tags if not already set
				if len(alert.MitreTechniques) == 0 {
					for _, tag := range rule.Tags {
						if strings.HasPrefix(tag, "attack.t") {
							alert.MitreTechniques = append(alert.MitreTechniques, tag)
						}
					}
				}
			}
			return
		}
	}

	// Rule not found - generate human-friendly name from event data
	alert.RuleName = generateAlertTitle(alert)
}

// generateAlertTitle creates a human-friendly title for alerts without matching rules
func generateAlertTitle(alert *core.Alert) string {
	// Try to extract useful info from event fields
	if alert.Event != nil && alert.Event.Fields != nil {
		fields := alert.Event.Fields

		// Check for a message field first (most descriptive)
		if msg, ok := fields["message"].(string); ok && msg != "" {
			return msg
		}

		// Try event_type and make it human-readable
		if eventType, ok := fields["event_type"].(string); ok && eventType != "" {
			return humanizeEventType(eventType)
		}

		// Try EventID field
		if eventID, ok := fields["EventID"].(string); ok && eventID != "" {
			return humanizeEventType(eventID)
		}
	}

	// Last resort: humanize the rule_id
	return humanizeEventType(alert.RuleID)
}

// humanizeEventType converts snake_case or kebab-case identifiers to Title Case
func humanizeEventType(s string) string {
	if s == "" {
		return "Unknown Alert"
	}

	// Replace underscores and hyphens with spaces
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.ReplaceAll(s, "-", " ")

	// Title case each word
	words := strings.Fields(s)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(string(word[0])) + strings.ToLower(word[1:])
		}
	}

	return strings.Join(words, " ")
}

// enrichAlertsWithRuleInfo enriches a slice of alerts with rule information
func (a *API) enrichAlertsWithRuleInfo(alerts []core.Alert) {
	for i := range alerts {
		a.enrichAlertWithRuleInfo(&alerts[i])
	}
}

// getAlertByID godoc
//
//	@Summary		Get alert by ID
//	@Description	Retrieves a single alert by its ID
//	@Tags			alerts
//	@Produce		json
//	@Param			id	path		string	true	"Alert ID (UUID format)"
//	@Success		200	{object}	core.Alert
//	@Failure		400	{object}	ErrorResponse	"Invalid alert ID format"
//	@Failure		404	{object}	ErrorResponse	"Alert not found"
//	@Failure		500	{object}	ErrorResponse	"Internal server error"
//	@Router			/api/v1/alerts/{id} [get]
func (a *API) getAlertByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID format (should be UUID)
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	if a.alertStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert storage not available", nil, a.logger)
		return
	}

	alert, err := a.alertStorage.GetAlertByID(r.Context(), alertID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Alert not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve alert", err, a.logger)
		return
	}

	// Enrich alert with rule information (name, type, MITRE techniques)
	a.enrichAlertWithRuleInfo(alert)

	a.respondJSON(w, alert, http.StatusOK)
}

// acknowledgeAlert godoc
//
//	@Summary		Acknowledge an alert
//	@Description	Updates an alert status to acknowledged
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Param			id	path	string	true	"Alert ID"
//	@Success		200	{object}	map[string]string
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		404	{string}	string	"Alert not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/alerts/{id}/acknowledge [put]
func (a *API) acknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID format (should be UUID)
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	// Get user for audit trail
	username := getUsernameFromContext(r.Context())
	if username == "" {
		username = r.Header.Get("X-Username")
	}

	// TASK 145.2: Use alert service for business logic (service layer required)
	if a.alertService == nil {
		writeError(w, http.StatusServiceUnavailable, "Alert service not available", nil, a.logger)
		return
	}

	err := a.alertService.AcknowledgeAlert(r.Context(), alertID, username)
	if err != nil {
		// AUDIT: Failed alert acknowledgment
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
		a.logger.Infow("AUDIT: Alert acknowledgment failed",
			"action", "acknowledge_alert",
			"outcome", "failure",
			"username", username,
			"source_ip", ip,
			"resource_type", "alert",
			"resource_id", alertID,
			"error", err.Error(),
			"timestamp", time.Now().UTC())

		if errors.Is(err, storage.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "Alert not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to acknowledge alert", err, a.logger)
		}
		return
	}

	// AUDIT: Successful alert acknowledgment
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: Alert acknowledged successfully",
		"action", "acknowledge_alert",
		"outcome", "success",
		"username", username,
		"source_ip", ip,
		"resource_type", "alert",
		"resource_id", alertID,
		"timestamp", time.Now().UTC())

	a.respondJSON(w, map[string]string{"message": "Alert acknowledged successfully"}, http.StatusOK)
}

// dismissAlert godoc
//
//	@Summary		Dismiss alert
//	@Description	Mark an alert as dismissed
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Param			id	path	string	true	"Alert ID"
//	@Success		200	{object}	map[string]string
//	@Failure		404	{string}	string	"Alert not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/alerts/{id}/dismiss [post]
func (a *API) dismissAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID format (should be UUID)
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	// Get user for audit trail
	username := getUsernameFromContext(r.Context())
	if username == "" {
		username = r.Header.Get("X-Username")
	}

	// TASK 145.2: Use alert service for business logic (service layer required)
	if a.alertService == nil {
		writeError(w, http.StatusServiceUnavailable, "Alert service not available", nil, a.logger)
		return
	}

	err := a.alertService.DismissAlert(r.Context(), alertID, "Dismissed by user", username)
	if err != nil {
		// AUDIT: Failed alert dismissal
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
		a.logger.Infow("AUDIT: Alert dismissal failed",
			"action", "dismiss_alert",
			"outcome", "failure",
			"username", username,
			"source_ip", ip,
			"resource_type", "alert",
			"resource_id", alertID,
			"error", err.Error(),
			"timestamp", time.Now().UTC())

		if errors.Is(err, storage.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "Alert not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to dismiss alert", err, a.logger)
		}
		return
	}

	// AUDIT: Successful alert dismissal
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: Alert dismissed successfully",
		"action", "dismiss_alert",
		"outcome", "success",
		"username", username,
		"source_ip", ip,
		"resource_type", "alert",
		"resource_id", alertID,
		"timestamp", time.Now().UTC())

	a.respondJSON(w, map[string]string{"message": "Alert dismissed successfully"}, http.StatusOK)
}

// updateAlertStatus godoc
//
//	@Summary		Update alert status
//	@Description	Updates an alert's status to any valid status value
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Alert ID"
//	@Param			request	body		object{status=string,note=string}	true	"Status update request"
//	@Success		200		{object}	map[string]string
//	@Failure		400		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Router			/alerts/{id}/status [put]
func (a *API) updateAlertStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID format (should be UUID)
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	if a.alertStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert storage not available", nil, a.logger)
		return
	}

	// Parse request body
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note,omitempty"`
	}

	if err := a.decodeJSONBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate status is a known valid status
	alertStatus := core.AlertStatus(req.Status)
	if !alertStatus.IsValid() {
		writeError(w, http.StatusBadRequest, "Invalid alert status", nil, a.logger)
		return
	}

	// Get the current alert to capture previous status for history
	existingAlert, err := a.alertStorage.GetAlertByID(r.Context(), alertID)
	if err != nil {
		if err == storage.ErrAlertNotFound {
			writeError(w, http.StatusNotFound, "Alert not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to get alert", err, a.logger)
		}
		return
	}

	previousStatus := existingAlert.Status

	// Skip if status hasn't changed
	if previousStatus == alertStatus {
		response := map[string]string{
			"message": "Alert status unchanged",
		}
		a.respondJSON(w, response, http.StatusOK)
		return
	}

	// Get username for history tracking
	username := r.Header.Get("X-Username")
	if username == "" {
		username = "anonymous"
	}

	// Update alert status
	err = a.alertStorage.UpdateAlertStatus(r.Context(), alertID, alertStatus)
	if err != nil {
		// AUDIT: Failed alert status update
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
		a.logger.Infow("AUDIT: Alert status update failed",
			"action", "update_alert_status",
			"outcome", "failure",
			"username", username,
			"source_ip", ip,
			"resource_type", "alert",
			"resource_id", alertID,
			"new_status", string(alertStatus),
			"error", err.Error(),
			"timestamp", time.Now().UTC())
		if err == storage.ErrAlertNotFound {
			writeError(w, http.StatusNotFound, "Alert not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to update alert status", err, a.logger)
		}
		return
	}

	// Record the status change in history for timeline display
	statusChange := core.NewStatusChange(alertID, previousStatus, alertStatus, username, req.Note)
	if err := a.alertStorage.RecordStatusChange(r.Context(), statusChange); err != nil {
		// Log but don't fail - status was updated successfully, history is secondary
		a.logger.Warnw("Failed to record status change in history",
			"alert_id", alertID,
			"from_status", previousStatus,
			"to_status", alertStatus,
			"error", err)
	}

	// AUDIT: Successful alert status update
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: Alert status updated successfully",
		"action", "update_alert_status",
		"outcome", "success",
		"username", username,
		"source_ip", ip,
		"resource_type", "alert",
		"resource_id", alertID,
		"previous_status", string(previousStatus),
		"new_status", string(alertStatus),
		"note", req.Note,
		"timestamp", time.Now().UTC())

	response := map[string]string{
		"message": "Alert status updated successfully",
	}
	a.respondJSON(w, response, http.StatusOK)
}

// getAlertHistory godoc
//
//	@Summary		Get alert status history
//	@Description	Returns the status change history for an alert
//	@Tags			alerts
//	@Produce		json
//	@Param			id	path		string	true	"Alert ID"
//	@Success		200	{array}		core.StatusChange
//	@Failure		400	{object}	ErrorResponse
//	@Failure		404	{object}	ErrorResponse
//	@Failure		500	{object}	ErrorResponse
//	@Router			/alerts/{id}/history [get]
func (a *API) getAlertHistory(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID format (should be UUID)
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	if a.alertStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert storage not available", nil, a.logger)
		return
	}

	// Get alert history from storage
	history, err := a.alertStorage.GetAlertHistory(r.Context(), alertID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get alert history", err, a.logger)
		return
	}

	// Return empty array if no history (not an error)
	if history == nil {
		history = []*core.StatusChange{}
	}

	a.respondJSON(w, history, http.StatusOK)
}

// assignAlert godoc
//
//	@Summary		Assign alert
//	@Description	Assigns an alert to a user
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Alert ID"
//	@Param			request	body		map[string]string	true	"Assignment request"
//	@Success		200		{object}	map[string]string
//	@Failure		400		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Router			/alerts/{id}/assign [put]
func (a *API) assignAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID format (should be UUID)
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	if a.alertStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert storage not available", nil, a.logger)
		return
	}

	// Parse request body
	var req struct {
		AssignTo string `json:"assign_to"`
		Note     string `json:"note,omitempty"`
	}

	if err := a.decodeJSONBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	if req.AssignTo == "" {
		writeError(w, http.StatusBadRequest, "assign_to field is required", nil, a.logger)
		return
	}

	// Update alert assignment
	err := a.alertStorage.AssignAlert(r.Context(), alertID, req.AssignTo)
	if err != nil {
		// AUDIT: Failed alert assignment
		username := r.Header.Get("X-Username")
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
		a.logger.Infow("AUDIT: Alert assignment failed",
			"action", "assign_alert",
			"outcome", "failure",
			"username", username,
			"source_ip", ip,
			"resource_type", "alert",
			"resource_id", alertID,
			"assign_to", req.AssignTo,
			"error", err.Error(),
			"timestamp", time.Now().UTC())
		if err == storage.ErrAlertNotFound {
			writeError(w, http.StatusNotFound, "Alert not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to assign alert", err, a.logger)
		}
		return
	}

	// AUDIT: Successful alert assignment
	username := r.Header.Get("X-Username")
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: Alert assigned successfully",
		"action", "assign_alert",
		"outcome", "success",
		"username", username,
		"source_ip", ip,
		"resource_type", "alert",
		"resource_id", alertID,
		"assign_to", req.AssignTo,
		"note", req.Note,
		"timestamp", time.Now().UTC())

	response := map[string]string{
		"message": "Alert assigned successfully",
	}
	a.respondJSON(w, response, http.StatusOK)
}

// UpdateDispositionRequest represents a request to update alert disposition
// TASK 104: Request struct for disposition updates
type UpdateDispositionRequest struct {
	Disposition string `json:"disposition" validate:"required"`
	Reason      string `json:"reason"`
}

// UpdateDispositionResponse represents the response after updating disposition
// TASK 104: Response struct for disposition updates
type UpdateDispositionResponse struct {
	ID                string     `json:"id"`
	Disposition       string     `json:"disposition"`
	DispositionReason string     `json:"dispositionReason,omitempty"`
	DispositionSetAt  *time.Time `json:"dispositionSetAt,omitempty"`
	DispositionSetBy  string     `json:"dispositionSetBy,omitempty"`
	Message           string     `json:"message"`
}

// updateAlertDisposition godoc
//
//	@Summary		Update alert disposition
//	@Description	Updates an alert's disposition (analyst verdict) with reason and audit logging
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"Alert ID"
//	@Param			request	body		UpdateDispositionRequest	true	"Disposition update"
//	@Success		200		{object}	UpdateDispositionResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Router			/api/alerts/{id}/disposition [patch]
//
// TASK 104: Implement disposition update endpoint
// SECURITY: RBAC authorization is enforced at route level via RequirePermission(storage.PermReadAlerts)
func (a *API) updateAlertDisposition(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID format (should be UUID)
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	if a.alertStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert storage not available", nil, a.logger)
		return
	}

	// SECURITY: Validate Content-Type header
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.Contains(contentType, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json", nil, a.logger)
		return
	}

	// Parse and validate request body
	var req UpdateDispositionRequest
	if err := a.decodeJSONBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// SECURITY: Sanitize and validate inputs
	req.Disposition = strings.TrimSpace(req.Disposition)
	req.Reason = strings.TrimSpace(req.Reason)

	// SECURITY: Validate disposition is not empty
	if req.Disposition == "" {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("Disposition cannot be empty. Valid values: %v", core.ValidDispositions()),
			nil, a.logger)
		return
	}

	// SECURITY: Validate reason length to prevent DoS/storage abuse
	const maxReasonLength = 1000
	if len(req.Reason) > maxReasonLength {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("Reason exceeds maximum length of %d characters", maxReasonLength),
			nil, a.logger)
		return
	}

	// SECURITY: Validate printable characters only in reason (reject control characters)
	for _, r := range req.Reason {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' { // Allow tab, newline, carriage return
			writeError(w, http.StatusBadRequest,
				"Reason contains invalid control characters",
				nil, a.logger)
			return
		}
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			writeError(w, http.StatusBadRequest,
				"Reason contains invalid non-printable characters",
				nil, a.logger)
			return
		}
	}

	// SECURITY: XSS sanitization - escape HTML entities in reason
	req.Reason = html.EscapeString(req.Reason)

	// Validate disposition value using core validation
	disposition := core.AlertDisposition(req.Disposition)
	if !disposition.IsValid() {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("Invalid disposition value: %q. Valid values: %v", req.Disposition, core.ValidDispositions()),
			nil, a.logger)
		return
	}

	// Get authenticated user from context
	username := getUsernameFromContext(r.Context())
	if username == "" {
		// Fallback to header for non-authenticated requests
		username = r.Header.Get("X-Username")
	}
	if username == "" {
		username = "anonymous"
	}

	// TASK 111 FIX: Validate username for defense-in-depth (BLOCKING-4)
	// Prevents potential SQL injection context issues even with parameterized queries
	if err := validateUsername(username); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid username format", err, a.logger)
		return
	}

	// Log warning if false_positive without reason (but still allow)
	if disposition == core.DispositionFalsePositive && req.Reason == "" {
		a.logger.Warnw("Alert marked as false_positive without reason",
			"alert_id", alertID,
			"username", username,
			"timestamp", time.Now().UTC())
	}

	// Update disposition in storage
	// TASK 111: Storage layer returns previous disposition for activity logging (atomic read-update)
	// TASK 111 FIX: Pass request context for proper cancellation handling (BLOCKING-5)
	previousDisposition, err := a.alertStorage.UpdateAlertDisposition(r.Context(), alertID, disposition, req.Reason, username)
	if err != nil {
		// AUDIT: Failed disposition update
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)

		// Check if alert not found using proper sentinel error comparison
		if errors.Is(err, storage.ErrAlertNotFound) {
			// TASK 111 FIX: Don't log previous_disposition when alert doesn't exist (BLOCKING-3)
			// Empty string is ambiguous (could mean unset disposition vs non-existent alert)
			a.logger.Infow("AUDIT: Alert disposition update failed - alert not found",
				"action", "update_alert_disposition",
				"outcome", "failure",
				"username", username,
				"source_ip", ip,
				"resource_type", "alert",
				"resource_id", alertID,
				"disposition", string(disposition),
				"error", "alert_not_found",
				"timestamp", time.Now().UTC())
			writeError(w, http.StatusNotFound, "Alert not found", nil, a.logger)
		} else {
			// Alert exists but update failed - include previous_disposition
			a.logger.Infow("AUDIT: Alert disposition update failed",
				"action", "update_alert_disposition",
				"outcome", "failure",
				"username", username,
				"source_ip", ip,
				"resource_type", "alert",
				"resource_id", alertID,
				"disposition", string(disposition),
				"previous_disposition", previousDisposition,
				"error", err.Error(),
				"timestamp", time.Now().UTC())
			writeError(w, http.StatusInternalServerError, "Failed to update alert disposition", nil, a.logger)
		}
		return
	}

	// AUDIT: Successful disposition update
	// TASK 111: Include previous_disposition for complete activity trail
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: Alert disposition updated successfully",
		"action", "update_alert_disposition",
		"outcome", "success",
		"username", username,
		"source_ip", ip,
		"resource_type", "alert",
		"resource_id", alertID,
		"disposition", string(disposition),
		"previous_disposition", previousDisposition,
		"reason", req.Reason,
		"timestamp", time.Now().UTC())

	// Build response with disposition details
	now := time.Now().UTC()
	response := UpdateDispositionResponse{
		ID:                alertID,
		Disposition:       string(disposition),
		DispositionReason: req.Reason,
		DispositionSetAt:  &now,
		DispositionSetBy:  username,
		Message:           "Alert disposition updated successfully",
	}

	a.respondJSON(w, response, http.StatusOK)
}

// UpdateAssigneeRequest represents a request to update alert assignee
// TASK 105: Request struct with pointer for nullable assignee support
type UpdateAssigneeRequest struct {
	AssigneeID *string `json:"assigneeId"` // Pointer for null support (unassign)
}

// UpdateAssigneeResponse represents the response after updating assignee
// TASK 105: Response struct for assignee updates
type UpdateAssigneeResponse struct {
	ID               string `json:"id"`
	AssignedTo       string `json:"assignedTo,omitempty"`
	PreviousAssignee string `json:"previousAssignee,omitempty"`
	Message          string `json:"message"`
}

// updateAlertAssignee godoc
//
//	@Summary		Update alert assignee
//	@Description	Updates an alert's assignee with nullable support for unassignment
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Alert ID"
//	@Param			request	body		UpdateAssigneeRequest	true	"Assignee update"
//	@Success		200		{object}	UpdateAssigneeResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Router			/api/alerts/{id}/assignee [patch]
//
// TASK 105: Implement assignee update endpoint with nullable support
// SECURITY: RBAC authorization is enforced at route level via RequirePermission(storage.PermAcknowledgeAlerts)
func (a *API) updateAlertAssignee(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID format (should be UUID)
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	if a.alertStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert storage not available", nil, a.logger)
		return
	}

	// SECURITY: Validate Content-Type header
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.Contains(contentType, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json", nil, a.logger)
		return
	}

	// Parse and validate request body
	var req UpdateAssigneeRequest
	if err := a.decodeJSONBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Get authenticated user from context for audit logging
	username := getUsernameFromContext(r.Context())
	if username == "" {
		username = r.Header.Get("X-Username")
	}
	if username == "" {
		username = "anonymous"
	}

	// SECURITY: Validate assignee exists if provided (not nil and not empty)
	var sanitizedAssignee *string
	if req.AssigneeID != nil {
		trimmedAssignee := strings.TrimSpace(*req.AssigneeID)
		if trimmedAssignee != "" {
			// Validate assignee ID length (max 255 characters for username)
			const maxAssigneeLength = 255
			if len(trimmedAssignee) > maxAssigneeLength {
				writeError(w, http.StatusBadRequest,
					fmt.Sprintf("Assignee ID exceeds maximum length of %d characters", maxAssigneeLength),
					nil, a.logger)
				return
			}

			// SECURITY: Validate only printable characters
			for _, r := range trimmedAssignee {
				if !unicode.IsPrint(r) {
					writeError(w, http.StatusBadRequest,
						"Assignee ID contains invalid characters",
						nil, a.logger)
					return
				}
			}

			// Validate assignee exists in users table BEFORE any sanitization
			if a.userStorage != nil {
				ctx := r.Context()
				_, err := a.userStorage.GetUserByUsername(ctx, trimmedAssignee)
				if err != nil {
					writeError(w, http.StatusBadRequest,
						fmt.Sprintf("Assignee %q does not exist", trimmedAssignee),
						nil, a.logger)
					return
				}
			}

			// SECURITY: XSS sanitization AFTER successful user lookup
			// This ensures we store sanitized values while not breaking lookup
			trimmedAssignee = html.EscapeString(trimmedAssignee)
			sanitizedAssignee = &trimmedAssignee
		}
	}

	// Get previous assignee for activity logging
	existingAlert, err := a.alertStorage.GetAlertByID(r.Context(), alertID)
	if err != nil {
		// AUDIT: Failed to get alert for assignee lookup
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
		a.logger.Infow("AUDIT: Alert assignee update failed - could not retrieve alert",
			"action", "update_alert_assignee",
			"outcome", "failure",
			"username", username,
			"source_ip", ip,
			"resource_type", "alert",
			"resource_id", alertID,
			"error", err.Error(),
			"timestamp", time.Now().UTC())

		if errors.Is(err, storage.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "Alert not found", nil, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve alert", nil, a.logger)
		}
		return
	}
	if existingAlert == nil {
		writeError(w, http.StatusNotFound, "Alert not found", nil, a.logger)
		return
	}

	previousAssignee := existingAlert.AssignedTo

	// IDEMPOTENCY CHECK: Skip update if assignee is unchanged
	newAssigneeValue := ""
	if sanitizedAssignee != nil {
		newAssigneeValue = *sanitizedAssignee
	}
	if previousAssignee == newAssigneeValue {
		// No change needed - return success without modification
		response := UpdateAssigneeResponse{
			ID:               alertID,
			AssignedTo:       newAssigneeValue,
			PreviousAssignee: previousAssignee,
			Message:          "Alert assignee unchanged (already set to this value)",
		}
		a.respondJSON(w, response, http.StatusOK)
		return
	}

	// Update assignee in storage
	err = a.alertStorage.UpdateAlertAssignee(r.Context(), alertID, sanitizedAssignee)
	if err != nil {
		// AUDIT: Failed assignee update
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
		newAssignee := ""
		if sanitizedAssignee != nil {
			newAssignee = *sanitizedAssignee
		}
		a.logger.Infow("AUDIT: Alert assignee update failed",
			"action", "update_alert_assignee",
			"outcome", "failure",
			"username", username,
			"source_ip", ip,
			"resource_type", "alert",
			"resource_id", alertID,
			"previous_assignee", previousAssignee,
			"new_assignee", newAssignee,
			"error", err.Error(),
			"timestamp", time.Now().UTC())

		if errors.Is(err, storage.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "Alert not found", nil, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to update alert assignee", nil, a.logger)
		}
		return
	}

	// Build response
	newAssignee := ""
	message := "Alert unassigned successfully"
	if sanitizedAssignee != nil {
		newAssignee = *sanitizedAssignee
		message = "Alert assigned successfully"
	}

	// AUDIT: Successful assignee update
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: Alert assignee updated successfully",
		"action", "update_alert_assignee",
		"outcome", "success",
		"username", username,
		"source_ip", ip,
		"resource_type", "alert",
		"resource_id", alertID,
		"previous_assignee", previousAssignee,
		"new_assignee", newAssignee,
		"timestamp", time.Now().UTC())

	response := UpdateAssigneeResponse{
		ID:               alertID,
		AssignedTo:       newAssignee,
		PreviousAssignee: previousAssignee,
		Message:          message,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// TASK 106: Constants for investigation from alert
const (
	maxInvestigationTitleLength        = 200
	maxInvestigationDescriptionLength  = 2000
	maxMitreTechniquesPerInvestigation = 100
)

// CreateInvestigationFromAlertRequest represents the request body for creating an investigation from an alert
// TASK 106: Optional fields with auto-generation support
type CreateInvestigationFromAlertRequest struct {
	Title       string `json:"title,omitempty"`       // Optional: auto-generated as "Investigation: [RuleName]"
	Description string `json:"description,omitempty"` // Optional: auto-generated as "Investigation created from alert [alertID]"
	Priority    string `json:"priority,omitempty"`    // Optional: auto-mapped from alert severity
}

// CreateInvestigationFromAlertResponse represents the response for creating an investigation from an alert
type CreateInvestigationFromAlertResponse struct {
	Investigation *core.Investigation `json:"investigation"`
	AlertID       string              `json:"alertId"`
	LinkedAt      time.Time           `json:"linkedAt"`
	Message       string              `json:"message"`
	Warnings      []string            `json:"warnings,omitempty"` // TASK 145.2: Return warnings for non-fatal issues (e.g., MITRE truncation)
}

// mapAlertSeverityToInvestigationPriority maps alert severity to investigation priority
// TASK 106: Severity-to-priority mapping for auto-generation
func mapAlertSeverityToInvestigationPriority(severity string) core.InvestigationPriority {
	switch strings.ToLower(severity) {
	case "critical":
		return core.InvestigationPriorityCritical
	case "high":
		return core.InvestigationPriorityHigh
	case "medium", "warning":
		return core.InvestigationPriorityMedium
	case "low", "informational", "info":
		return core.InvestigationPriorityLow
	default:
		return core.InvestigationPriorityMedium // Default to medium
	}
}

// createInvestigationFromAlert godoc
//
//	@Summary		Create investigation from alert
//	@Description	Creates a new investigation from an alert with auto-generated title/description
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"Alert ID"
//	@Param			body	body		CreateInvestigationFromAlertRequest	false	"Optional investigation details"
//	@Success		201		{object}	CreateInvestigationFromAlertResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		401		{object}	ErrorResponse	"Authentication required"
//	@Failure		404		{object}	ErrorResponse
//	@Failure		409		{object}	ErrorResponse	"Alert already linked to an investigation"
//	@Failure		500		{object}	ErrorResponse
//	@Router			/api/alerts/{id}/investigation [post]
//
// TASK 106: Create investigation from alert with auto-generation
// SECURITY: RBAC authorization enforced at route level via RequirePermission(storage.PermCreateInvestigations)
func (a *API) createInvestigationFromAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Get authenticated user for audit trail
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		userID = getUsernameFromContext(r.Context())
	}
	if userID == "" {
		userID = r.Header.Get("X-Username")
	}

	// SECURITY: Fail if no authenticated user
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
		return
	}

	// Get IP for audit logging
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)

	// Validate alert ID format
	if err := validateUUID(alertID); err != nil {
		a.logger.Warnw("AUDIT: Investigation creation failed - invalid alert ID",
			"action", "create_investigation_from_alert",
			"outcome", "failure",
			"username", userID,
			"source_ip", ip,
			"alert_id", alertID,
			"error", "invalid UUID format")
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	// Parse optional request body
	var req CreateInvestigationFromAlertRequest
	if r.ContentLength > 0 {
		if err := a.decodeJSONBody(w, r, &req); err != nil {
			a.logger.Warnw("AUDIT: Investigation creation failed - invalid request body",
				"action", "create_investigation_from_alert",
				"outcome", "failure",
				"username", userID,
				"source_ip", ip,
				"alert_id", alertID,
				"error", err.Error())
			writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
			return
		}
	}

	// Sanitize and truncate inputs
	title := sanitizeAndTruncate(req.Title, maxInvestigationTitleLength)
	description := sanitizeAndTruncate(req.Description, maxInvestigationDescriptionLength)

	// Parse priority
	var priority core.InvestigationPriority
	if req.Priority != "" {
		priority = core.InvestigationPriority(strings.ToLower(strings.TrimSpace(req.Priority)))
		if !priority.IsValid() {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("Invalid priority %q. Valid values: critical, high, medium, low", req.Priority),
				nil, a.logger)
			return
		}
	}

	// TASK 145.2: Use alert service for business logic
	var investigation *core.Investigation
	var warnings []string
	var err error

	if a.alertService != nil {
		investigation, warnings, err = a.alertService.CreateInvestigationFromAlert(
			r.Context(), alertID, title, description, priority, userID)
	} else {
		// Fallback to direct storage (legacy) - not implementing full logic here
		writeError(w, http.StatusServiceUnavailable, "Service layer not available", nil, a.logger)
		return
	}

	if err != nil {
		// AUDIT: Failed to create investigation
		a.logger.Errorw("AUDIT: Investigation creation failed",
			"action", "create_investigation_from_alert",
			"outcome", "failure",
			"username", userID,
			"source_ip", ip,
			"alert_id", alertID,
			"error", err.Error())

		if errors.Is(err, storage.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "Alert not found", nil, a.logger)
		} else if errors.Is(err, storage.ErrAlertAlreadyLinked) {
			writeError(w, http.StatusConflict, "Alert is already linked to an investigation", nil, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to create investigation", nil, a.logger)
		}
		return
	}

	// AUDIT: Log successful investigation creation
	a.logger.Infow("AUDIT: Investigation created from alert",
		"action", "create_investigation_from_alert",
		"outcome", "success",
		"username", userID,
		"source_ip", ip,
		"resource_type", "investigation",
		"resource_id", investigation.InvestigationID,
		"alert_id", alertID,
		"priority", investigation.Priority)

	response := CreateInvestigationFromAlertResponse{
		Investigation: investigation,
		AlertID:       alertID,
		LinkedAt:      time.Now().UTC(),
		Message:       "Investigation created and linked to alert successfully",
		Warnings:      warnings, // TASK 145.2: Include warnings (e.g., MITRE truncation)
	}

	a.respondJSON(w, response, http.StatusCreated)
}

// sanitizeAndTruncate escapes HTML and truncates to max length.
func sanitizeAndTruncate(s string, maxLen int) string {
	sanitized := html.EscapeString(strings.TrimSpace(s))
	if len(sanitized) > maxLen {
		return sanitized[:maxLen]
	}
	return sanitized
}

// LinkInvestigationRequest represents the request body for linking an alert to an existing investigation
// TASK 107: Link alert to existing investigation
type LinkInvestigationRequest struct {
	InvestigationID string `json:"investigationId" validate:"required"`
}

// LinkInvestigationResponse represents the response for linking an alert to an investigation
type LinkInvestigationResponse struct {
	AlertID                 string   `json:"alertId"`
	InvestigationID         string   `json:"investigationId"`
	PreviousInvestigationID string   `json:"previousInvestigationId,omitempty"`
	Message                 string   `json:"message"`
	Warnings                []string `json:"warnings,omitempty"` // TASK 107: Partial failure warnings
}

// linkAlertToInvestigation godoc
//
//	@Summary		Link alert to existing investigation
//	@Description	Links an alert to an existing investigation (bidirectional linking)
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"Alert ID"
//	@Param			body	body		LinkInvestigationRequest	true	"Investigation to link"
//	@Success		200		{object}	LinkInvestigationResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		401		{object}	ErrorResponse	"Authentication required"
//	@Failure		404		{object}	ErrorResponse	"Alert or investigation not found"
//	@Failure		500		{object}	ErrorResponse
//	@Router			/api/alerts/{id}/investigation [patch]
//
// TASK 107: Link alert to existing investigation (PATCH)
// SECURITY: RBAC authorization enforced at route level via RequirePermission(storage.PermCreateInvestigations)
func (a *API) linkAlertToInvestigation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Get authenticated user for audit trail
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		userID = getUsernameFromContext(r.Context())
	}
	if userID == "" {
		userID = r.Header.Get("X-Username")
	}

	// SECURITY: Fail if no authenticated user
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
		return
	}

	// Get IP for audit logging
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)

	// Validate alert ID format
	if err := validateUUID(alertID); err != nil {
		a.logger.Warnw("AUDIT: Alert linking failed - invalid alert ID",
			"action", "link_alert_to_investigation",
			"outcome", "failure",
			"username", userID,
			"source_ip", ip,
			"alert_id", alertID,
			"error", "invalid UUID format")
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	// Parse request body
	var req LinkInvestigationRequest
	if err := a.decodeJSONBody(w, r, &req); err != nil {
		a.logger.Warnw("AUDIT: Alert linking failed - invalid request body",
			"action", "link_alert_to_investigation",
			"outcome", "failure",
			"username", userID,
			"source_ip", ip,
			"alert_id", alertID,
			"error", err.Error())
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate investigationID is provided
	investigationID := strings.TrimSpace(req.InvestigationID)
	if investigationID == "" {
		writeError(w, http.StatusBadRequest, "investigationId is required", nil, a.logger)
		return
	}

	// Validate investigation ID format
	if err := validateUUID(investigationID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid investigation ID format", nil, a.logger)
		return
	}

	// TASK 145.2: Use alert service for business logic
	var warnings []string
	var err error

	if a.alertService != nil {
		warnings, err = a.alertService.LinkAlertToInvestigation(r.Context(), alertID, investigationID, userID)
	} else {
		// Fallback to direct storage (legacy) - not implementing full logic here
		writeError(w, http.StatusServiceUnavailable, "Service layer not available", nil, a.logger)
		return
	}

	if err != nil {
		// AUDIT: Failed to link alert
		a.logger.Errorw("AUDIT: Alert linking failed",
			"action", "link_alert_to_investigation",
			"outcome", "failure",
			"username", userID,
			"source_ip", ip,
			"alert_id", alertID,
			"investigation_id", investigationID,
			"error", err.Error())

		if errors.Is(err, storage.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "Alert not found", nil, a.logger)
		} else if errors.Is(err, storage.ErrAlertAlreadyLinked) {
			writeError(w, http.StatusConflict, "Alert is already linked to another investigation", nil, a.logger)
		} else if strings.Contains(err.Error(), "investigation not found") {
			writeError(w, http.StatusNotFound, "Investigation not found", nil, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to link alert to investigation", nil, a.logger)
		}
		return
	}

	// AUDIT: Log successful linking
	outcome := "success"
	if len(warnings) > 0 {
		outcome = "partial_success"
	}
	a.logger.Infow("AUDIT: Alert linked to investigation",
		"action", "link_alert_to_investigation",
		"outcome", outcome,
		"username", userID,
		"source_ip", ip,
		"alert_id", alertID,
		"investigation_id", investigationID,
		"warnings_count", len(warnings))

	response := LinkInvestigationResponse{
		AlertID:         alertID,
		InvestigationID: investigationID,
		Message:         "Alert linked to investigation successfully",
		Warnings:        warnings,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// deleteAlert godoc
//
//	@Summary		Delete alert
//	@Description	Permanently deletes an alert by ID
//	@Tags			alerts
//	@Produce		json
//	@Param			id	path		string	true	"Alert ID"
//	@Success		200	{object}	map[string]string
//	@Failure		400	{object}	ErrorResponse
//	@Failure		404	{object}	ErrorResponse
//	@Failure		500	{object}	ErrorResponse
//	@Router			/alerts/{id} [delete]
func (a *API) deleteAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID format (should be UUID)
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	var err error

	// SECURITY FIX: Safe storage type check with proper error handling
	if a.alertStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert storage not available", nil, a.logger)
		return
	}

	// Try to use storage's native DeleteAlert method
	err = a.alertStorage.DeleteAlert(r.Context(), alertID)

	if err != nil {
		// AUDIT: Failed alert deletion
		username := r.Header.Get("X-Username")
		ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
		a.logger.Infow("AUDIT: Alert deletion failed",
			"action", "delete_alert",
			"outcome", "failure",
			"username", username,
			"source_ip", ip,
			"resource_type", "alert",
			"resource_id", alertID,
			"error", err.Error(),
			"timestamp", time.Now().UTC())
		if err == storage.ErrAlertNotFound {
			writeError(w, http.StatusNotFound, "Alert not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to delete alert", err, a.logger)
		}
		return
	}

	// AUDIT: Successful alert deletion
	username := r.Header.Get("X-Username")
	ip := getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks)
	a.logger.Infow("AUDIT: Alert deleted successfully",
		"action", "delete_alert",
		"outcome", "success",
		"username", username,
		"source_ip", ip,
		"resource_type", "alert",
		"resource_id", alertID,
		"timestamp", time.Now().UTC())

	response := map[string]string{
		"message": "Alert deleted successfully",
	}
	a.respondJSON(w, response, http.StatusOK)
}
