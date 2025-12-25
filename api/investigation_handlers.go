package api

import (
	"context"
	"encoding/json"
	"net/http"

	"cerberus/core"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
)

// InvestigationStorer interface for investigation storage
type InvestigationStorer interface {
	GetInvestigations(limit int, offset int, filters map[string]interface{}) ([]core.Investigation, error)
	GetInvestigationCount(filters map[string]interface{}) (int64, error)
	GetInvestigation(id string) (*core.Investigation, error)
	CreateInvestigation(investigation *core.Investigation) error
	UpdateInvestigation(id string, investigation *core.Investigation) error
	DeleteInvestigation(id string) error
	CloseInvestigation(id string, verdict core.InvestigationVerdict, resolutionCategory, summary string, affectedAssets []string, mlFeedback *core.MLFeedback) error
	AddNote(investigationID, analystID, content string) error
	AddAlert(investigationID, alertID string) error
	GetInvestigationsByAlertID(alertID string) ([]core.Investigation, error)
	GetInvestigationsByAssignee(assigneeID string, limit int, offset int) ([]core.Investigation, error)
	GetInvestigationStatistics() (interface{}, error)
}

// getInvestigations godoc
//
//	@Summary		Get investigations
//	@Description	Returns a list of investigations with pagination and optional filters
//	@Tags			investigations
//	@Accept			json
//	@Produce		json
//	@Param			page		query	int		false	"Page number (1-based)"					minimum(1)	default(1)
//	@Param			limit		query	int		false	"Items per page (1-1000)"				minimum(1)	maximum(1000)	default(20)
//	@Param			status		query	string	false	"Filter by status"						example(open)
//	@Param			priority	query	string	false	"Filter by priority"					example(critical)
//	@Param			assignee	query	string	false	"Filter by assignee ID"					example(user123)
//	@Success		200			{object}	PaginationResponse
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/investigations [get]
func (a *API) getInvestigations(w http.ResponseWriter, r *http.Request) {
	if a.investigationStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Investigation storage not available", nil, a.logger)
		return
	}

	// Parse filters from query parameters (TASK 47: Use enhanced filter parser)
	filters := ParseInvestigationFilters(r)
	offset := (filters.Page - 1) * filters.Limit

	// Convert InvestigationFilters to map format for storage layer
	filterMap := investigationFiltersToMap(filters)

	// Get investigations
	investigations, err := a.investigationStorage.GetInvestigations(filters.Limit, offset, filterMap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve investigations", err, a.logger)
		return
	}

	// Get total count
	total, err := a.investigationStorage.GetInvestigationCount(filterMap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get investigation count", err, a.logger)
		return
	}

	// Create paginated response
	response := NewPaginationResponse(investigations, total, filters.Page, filters.Limit)
	a.respondJSON(w, response, http.StatusOK)
}

// investigationFiltersToMap converts InvestigationFilters to map format for storage layer
// TASK 47: Helper function for filter conversion
func investigationFiltersToMap(filters *core.InvestigationFilters) map[string]interface{} {
	result := make(map[string]interface{})

	if len(filters.Statuses) > 0 {
		result["statuses"] = filters.Statuses
	}
	if len(filters.Priorities) > 0 {
		result["priorities"] = filters.Priorities
	}
	if len(filters.AssigneeIDs) > 0 {
		result["assignee_ids"] = filters.AssigneeIDs
	}
	if len(filters.CreatedBy) > 0 {
		result["created_by"] = filters.CreatedBy
	}
	if filters.Search != "" {
		result["search"] = filters.Search
	}
	if filters.CreatedAfter != nil {
		result["created_after"] = filters.CreatedAfter
	}
	if filters.CreatedBefore != nil {
		result["created_before"] = filters.CreatedBefore
	}
	if filters.UpdatedAfter != nil {
		result["updated_after"] = filters.UpdatedAfter
	}
	if filters.UpdatedBefore != nil {
		result["updated_before"] = filters.UpdatedBefore
	}
	if filters.ClosedAfter != nil {
		result["closed_after"] = filters.ClosedAfter
	}
	if filters.ClosedBefore != nil {
		result["closed_before"] = filters.ClosedBefore
	}
	if filters.SortBy != "" {
		result["sort_by"] = filters.SortBy
	}
	if filters.SortOrder != "" {
		result["sort_order"] = filters.SortOrder
	}

	return result
}

// getInvestigation godoc
//
//	@Summary		Get investigation
//	@Description	Returns a single investigation by ID
//	@Tags			investigations
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Investigation ID"	example(INV-20250108-0042)
//	@Success		200	{object}	core.Investigation
//	@Failure		404	{string}	string	"Investigation not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/investigations/{id} [get]
func (a *API) getInvestigation(w http.ResponseWriter, r *http.Request) {
	if a.investigationStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Investigation storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	investigation, err := a.investigationStorage.GetInvestigation(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Investigation not found", err, a.logger)
		return
	}

	a.respondJSON(w, investigation, http.StatusOK)
}

// CreateInvestigationRequest represents the request body for creating an investigation
type CreateInvestigationRequest struct {
	Title       string                     `json:"title" validate:"required,min=1,max=200"`
	Description string                     `json:"description" validate:"max=2000"`
	Priority    core.InvestigationPriority `json:"priority" validate:"required"`
	AssigneeID  string                     `json:"assignee_id,omitempty"`
	AlertIDs    []string                   `json:"alert_ids,omitempty"`
}

// createInvestigation godoc
//
//	@Summary		Create investigation
//	@Description	Creates a new investigation
//	@Tags			investigations
//	@Accept			json
//	@Produce		json
//	@Param			investigation	body		CreateInvestigationRequest	true	"Investigation to create"
//	@Success		201				{object}	core.Investigation
//	@Failure		400				{string}	string	"Invalid request"
//	@Failure		500				{string}	string	"Internal server error"
//	@Router			/api/v1/investigations [post]
func (a *API) createInvestigation(w http.ResponseWriter, r *http.Request) {
	if a.investigationStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Investigation storage not available", nil, a.logger)
		return
	}

	var req CreateInvestigationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate request
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, "Validation failed", err, a.logger)
		return
	}

	// Get user from context (set by auth middleware)
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		userID = "system" // Fallback
	}

	// Create investigation
	investigation := core.NewInvestigation(req.Title, req.Description, req.Priority, userID)

	// Set assignee if provided, otherwise defaults to creator
	if req.AssigneeID != "" {
		investigation.AssigneeID = req.AssigneeID
	}

	// Add alert IDs if provided
	if len(req.AlertIDs) > 0 {
		investigation.AlertIDs = req.AlertIDs

		// Update alerts to link to this investigation
		if a.alertStorage != nil {
			for _, alertID := range req.AlertIDs {
				// This will be implemented when we update alert storage
				_ = alertID
			}
		}
	}

	// Save investigation
	if err := a.investigationStorage.CreateInvestigation(investigation); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create investigation", err, a.logger)
		return
	}

	a.respondJSON(w, investigation, http.StatusCreated)
}

// UpdateInvestigationRequest represents the request body for updating an investigation
type UpdateInvestigationRequest struct {
	Title       *string                     `json:"title,omitempty" validate:"omitempty,min=1,max=200"`
	Description *string                     `json:"description,omitempty" validate:"omitempty,max=2000"`
	Priority    *core.InvestigationPriority `json:"priority,omitempty"`
	Status      *core.InvestigationStatus   `json:"status,omitempty"`
	AssigneeID  *string                     `json:"assignee_id,omitempty"`
}

// updateInvestigation godoc
//
//	@Summary		Update investigation
//	@Description	Updates an existing investigation
//	@Tags			investigations
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string						true	"Investigation ID"
//	@Param			investigation	body		UpdateInvestigationRequest	true	"Investigation updates"
//	@Success		200				{object}	core.Investigation
//	@Failure		400				{string}	string	"Invalid request"
//	@Failure		404				{string}	string	"Investigation not found"
//	@Failure		500				{string}	string	"Internal server error"
//	@Router			/api/v1/investigations/{id} [put]
func (a *API) updateInvestigation(w http.ResponseWriter, r *http.Request) {
	if a.investigationStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Investigation storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Get existing investigation
	investigation, err := a.investigationStorage.GetInvestigation(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Investigation not found", err, a.logger)
		return
	}

	// Parse update request
	var req UpdateInvestigationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate request
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, "Validation failed", err, a.logger)
		return
	}

	// Apply updates
	if req.Title != nil {
		investigation.Title = *req.Title
	}
	if req.Description != nil {
		investigation.Description = *req.Description
	}
	if req.Priority != nil {
		investigation.Priority = *req.Priority
	}
	if req.Status != nil {
		investigation.Status = *req.Status
	}
	if req.AssigneeID != nil {
		investigation.AssigneeID = *req.AssigneeID
	}

	// Update investigation
	if err := a.investigationStorage.UpdateInvestigation(id, investigation); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update investigation", err, a.logger)
		return
	}

	a.respondJSON(w, investigation, http.StatusOK)
}

// deleteInvestigation godoc
//
//	@Summary		Delete investigation
//	@Description	Deletes an investigation
//	@Tags			investigations
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Investigation ID"
//	@Success		204	{string}	string	"No content"
//	@Failure		404	{string}	string	"Investigation not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/investigations/{id} [delete]
func (a *API) deleteInvestigation(w http.ResponseWriter, r *http.Request) {
	if a.investigationStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Investigation storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.investigationStorage.DeleteInvestigation(id); err != nil {
		writeError(w, http.StatusNotFound, "Investigation not found", err, a.logger)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CloseInvestigationRequest represents the request body for closing an investigation
type CloseInvestigationRequest struct {
	Verdict            core.InvestigationVerdict `json:"verdict" validate:"required"`
	ResolutionCategory string                    `json:"resolution_category" validate:"required"`
	Summary            string                    `json:"summary" validate:"required,max=5000"`
	AffectedAssets     []string                  `json:"affected_assets,omitempty"`
	MLFeedback         *core.MLFeedback          `json:"ml_feedback,omitempty"`
}

// closeInvestigation godoc
//
//	@Summary		Close investigation
//	@Description	Closes an investigation with a verdict
//	@Tags			investigations
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Investigation ID"
//	@Param			verdict		body		CloseInvestigationRequest	true	"Closure details"
//	@Success		200			{object}	core.Investigation
//	@Failure		400			{string}	string	"Invalid request"
//	@Failure		404			{string}	string	"Investigation not found"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/investigations/{id}/close [post]
func (a *API) closeInvestigation(w http.ResponseWriter, r *http.Request) {
	if a.investigationStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Investigation storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var req CloseInvestigationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate request
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, "Validation failed", err, a.logger)
		return
	}

	// Close investigation
	err := a.investigationStorage.CloseInvestigation(
		id,
		req.Verdict,
		req.ResolutionCategory,
		req.Summary,
		req.AffectedAssets,
		req.MLFeedback,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to close investigation", err, a.logger)
		return
	}

	// Get updated investigation
	investigation, err := a.investigationStorage.GetInvestigation(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve updated investigation", err, a.logger)
		return
	}

	a.respondJSON(w, investigation, http.StatusOK)
}

// AddNoteRequest represents the request body for adding a note
type AddNoteRequest struct {
	Content string `json:"content" validate:"required,min=1,max=5000"`
}

// addInvestigationNote godoc
//
//	@Summary		Add note to investigation
//	@Description	Adds a note to an investigation
//	@Tags			investigations
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string			true	"Investigation ID"
//	@Param			note	body		AddNoteRequest	true	"Note content"
//	@Success		200		{object}	core.Investigation
//	@Failure		400		{string}	string	"Invalid request"
//	@Failure		404		{string}	string	"Investigation not found"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/investigations/{id}/notes [post]
func (a *API) addInvestigationNote(w http.ResponseWriter, r *http.Request) {
	if a.investigationStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Investigation storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var req AddNoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate request
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, "Validation failed", err, a.logger)
		return
	}

	// Get user from context
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		userID = "system"
	}

	// Add note
	if err := a.investigationStorage.AddNote(id, userID, req.Content); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to add note", err, a.logger)
		return
	}

	// Get updated investigation
	investigation, err := a.investigationStorage.GetInvestigation(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve updated investigation", err, a.logger)
		return
	}

	a.respondJSON(w, investigation, http.StatusOK)
}

// AddAlertRequest represents the request body for adding an alert
type AddAlertRequest struct {
	AlertID string `json:"alert_id" validate:"required"`
}

// addInvestigationAlert godoc
//
//	@Summary		Add alert to investigation
//	@Description	Links an alert to an investigation
//	@Tags			investigations
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string			true	"Investigation ID"
//	@Param			alert	body		AddAlertRequest	true	"Alert ID"
//	@Success		200		{object}	core.Investigation
//	@Failure		400		{string}	string	"Invalid request"
//	@Failure		404		{string}	string	"Investigation not found"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/investigations/{id}/alerts [post]
func (a *API) addInvestigationAlert(w http.ResponseWriter, r *http.Request) {
	if a.investigationStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Investigation storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var req AddAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate request
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, "Validation failed", err, a.logger)
		return
	}

	// Add alert
	if err := a.investigationStorage.AddAlert(id, req.AlertID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to add alert", err, a.logger)
		return
	}

	// TODO: Update alert to link back to investigation

	// Get updated investigation
	investigation, err := a.investigationStorage.GetInvestigation(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve updated investigation", err, a.logger)
		return
	}

	a.respondJSON(w, investigation, http.StatusOK)
}

// getInvestigationTimeline godoc
//
//	@Summary		Get investigation timeline
//	@Description	Returns chronological events for an investigation
//	@Tags			investigations
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Investigation ID"
//	@Success		200	{object}	map[string]interface{}
//	@Failure		404	{string}	string	"Investigation not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/investigations/{id}/timeline [get]
func (a *API) getInvestigationTimeline(w http.ResponseWriter, r *http.Request) {
	if a.investigationStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Investigation storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Get investigation
	investigation, err := a.investigationStorage.GetInvestigation(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Investigation not found", err, a.logger)
		return
	}

	// Get all alerts for this investigation
	var timelineEvents []map[string]interface{}

	if a.alertStorage != nil {
		for _, alertID := range investigation.AlertIDs {
			alert, err := a.alertStorage.GetAlert(r.Context(), alertID)
			if err != nil {
				a.logger.Warnf("Failed to get alert %s: %v", alertID, err)
				continue
			}

			timelineEvent := map[string]interface{}{
				"type":      "alert",
				"id":        alert.AlertID,
				"timestamp": alert.Timestamp,
				"severity":  alert.Severity,
				"rule_id":   alert.RuleID,
				"rule_name": alert.RuleName,
				"event_id":  alert.EventID,
				"source_ip": "",
			}

			// Extract source IP from event if available
			if alert.Event != nil {
				// Extract source_ip from Fields
				if alert.Event.Fields != nil {
					if ip, ok := alert.Event.Fields["source_ip"]; ok {
						timelineEvent["source_ip"] = ip
					}
				}
			}

			timelineEvents = append(timelineEvents, timelineEvent)
		}
	}

	// Add investigation notes as timeline events
	for _, note := range investigation.Notes {
		timelineEvent := map[string]interface{}{
			"type":       "note",
			"id":         note.ID,
			"timestamp":  note.CreatedAt,
			"analyst_id": note.AnalystID,
			"content":    note.Content,
		}
		timelineEvents = append(timelineEvents, timelineEvent)
	}

	response := map[string]interface{}{
		"investigation_id": investigation.InvestigationID,
		"timeline":         timelineEvents,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// Helper function to get user ID from context (set by auth middleware)
func getUserIDFromContext(ctx context.Context) string {
	// Try to get from ContextKeyUser first (interface{})
	if user, ok := GetUser(ctx); ok {
		if userStr, ok := user.(string); ok {
			return userStr
		}
	}
	// Fallback to username
	username, _ := GetUsername(ctx)
	return username
}

// getInvestigationStatistics godoc
//
//	@Summary		Get investigation statistics
//	@Description	Returns statistical data about investigations including counts by status, priority, and average resolution time
//	@Tags			investigations
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}
//	@Failure		500	{string}	string	"Internal server error"
//	@Failure		503	{string}	string	"Investigation storage not available"
//	@Router			/api/v1/investigations/statistics [get]
func (a *API) getInvestigationStatistics(w http.ResponseWriter, r *http.Request) {
	if a.investigationStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Investigation storage not available", nil, a.logger)
		return
	}

	// Get statistics from storage
	stats, err := a.investigationStorage.GetInvestigationStatistics()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve investigation statistics", err, a.logger)
		return
	}

	a.respondJSON(w, stats, http.StatusOK)
}
