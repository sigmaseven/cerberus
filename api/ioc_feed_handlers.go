package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"cerberus/core"
	"cerberus/threat/feeds"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
)

// =============================================================================
// IOC Feed Request/Response Types
// =============================================================================

// CreateIOCFeedRequest represents the request body for creating an IOC feed
type CreateIOCFeedRequest struct {
	Name           string                      `json:"name" validate:"required,min=1,max=200"`
	Description    string                      `json:"description,omitempty" validate:"max=2000"`
	Type           feeds.IOCFeedType           `json:"type" validate:"required"`
	URL            string                      `json:"url,omitempty" validate:"omitempty,url,max=2048"`
	Path           string                      `json:"path,omitempty" validate:"max=1024"`
	AuthConfig     map[string]interface{}      `json:"auth_config,omitempty"`
	CollectionID   string                      `json:"collection_id,omitempty" validate:"max=200"`
	APIRoot        string                      `json:"api_root,omitempty" validate:"max=500"`
	OrgID          string                      `json:"org_id,omitempty" validate:"max=100"`
	EventFilters   string                      `json:"event_filters,omitempty"`
	PulseIDs       []string                    `json:"pulse_ids,omitempty"`
	FieldMapping   map[string]string           `json:"field_mapping,omitempty"`
	Delimiter      string                      `json:"delimiter,omitempty" validate:"max=1"`
	SkipHeader     bool                        `json:"skip_header,omitempty"`
	CommentChar    string                      `json:"comment_char,omitempty" validate:"max=1"`
	ValueColumn    int                         `json:"value_column,omitempty"`
	TypeColumn     int                         `json:"type_column,omitempty"`
	FilePatterns   []string                    `json:"file_patterns,omitempty"`
	IncludeTypes   []core.IOCType              `json:"include_types,omitempty"`
	ExcludeTypes   []core.IOCType              `json:"exclude_types,omitempty"`
	DefaultType    core.IOCType                `json:"default_type,omitempty"`
	MinConfidence  float64                     `json:"min_confidence,omitempty"`
	DefaultSeverity core.IOCSeverity           `json:"default_severity,omitempty"`
	AutoExpireDays int                         `json:"auto_expire_days,omitempty"`
	Tags           []string                    `json:"tags,omitempty"`
	Priority       int                         `json:"priority,omitempty"`
	UpdateStrategy feeds.IOCFeedUpdateStrategy `json:"update_strategy,omitempty"`
	UpdateSchedule string                      `json:"update_schedule,omitempty" validate:"max=100"`
	Enabled        *bool                       `json:"enabled,omitempty"`
	TemplateID     string                      `json:"template_id,omitempty"`
}

// UpdateIOCFeedRequest represents the request body for updating an IOC feed
type UpdateIOCFeedRequest struct {
	Name           *string                      `json:"name,omitempty" validate:"omitempty,min=1,max=200"`
	Description    *string                      `json:"description,omitempty" validate:"omitempty,max=2000"`
	URL            *string                      `json:"url,omitempty" validate:"omitempty,url,max=2048"`
	Path           *string                      `json:"path,omitempty" validate:"omitempty,max=1024"`
	AuthConfig     map[string]interface{}       `json:"auth_config,omitempty"`
	CollectionID   *string                      `json:"collection_id,omitempty" validate:"omitempty,max=200"`
	APIRoot        *string                      `json:"api_root,omitempty" validate:"omitempty,max=500"`
	OrgID          *string                      `json:"org_id,omitempty" validate:"omitempty,max=100"`
	EventFilters   *string                      `json:"event_filters,omitempty"`
	PulseIDs       []string                     `json:"pulse_ids,omitempty"`
	FieldMapping   map[string]string            `json:"field_mapping,omitempty"`
	Delimiter      *string                      `json:"delimiter,omitempty" validate:"omitempty,max=1"`
	SkipHeader     *bool                        `json:"skip_header,omitempty"`
	CommentChar    *string                      `json:"comment_char,omitempty" validate:"omitempty,max=1"`
	ValueColumn    *int                         `json:"value_column,omitempty"`
	TypeColumn     *int                         `json:"type_column,omitempty"`
	FilePatterns   []string                     `json:"file_patterns,omitempty"`
	IncludeTypes   []core.IOCType               `json:"include_types,omitempty"`
	ExcludeTypes   []core.IOCType               `json:"exclude_types,omitempty"`
	DefaultType    *core.IOCType                `json:"default_type,omitempty"`
	MinConfidence  *float64                     `json:"min_confidence,omitempty"`
	DefaultSeverity *core.IOCSeverity           `json:"default_severity,omitempty"`
	AutoExpireDays *int                         `json:"auto_expire_days,omitempty"`
	Tags           []string                     `json:"tags,omitempty"`
	Priority       *int                         `json:"priority,omitempty"`
	UpdateStrategy *feeds.IOCFeedUpdateStrategy `json:"update_strategy,omitempty"`
	UpdateSchedule *string                      `json:"update_schedule,omitempty" validate:"omitempty,max=100"`
	Enabled        *bool                        `json:"enabled,omitempty"`
}

// IOCFeedListResponse represents a list of IOC feeds
type IOCFeedListResponse struct {
	Feeds []*feeds.IOCFeed `json:"feeds"`
	Total int              `json:"total"`
}

// IOCFeedSyncResponse represents a sync operation response
type IOCFeedSyncResponse struct {
	Result  *feeds.IOCFeedSyncResult `json:"result"`
	Message string                   `json:"message"`
}

// IOCSyncHistoryResponse represents sync history
type IOCSyncHistoryResponse struct {
	History []*feeds.IOCFeedSyncResult `json:"history"`
	Total   int                        `json:"total"`
}

// =============================================================================
// IOC Feed CRUD Handlers
// =============================================================================

// getIOCFeeds godoc
//
//	@Summary		Get IOC Feeds
//	@Description	Returns a list of all IOC feeds
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	IOCFeedListResponse
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds [get]
//	@Security		BearerAuth
func (a *API) getIOCFeeds(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	feedList, err := a.iocFeedManager.ListFeeds(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve IOC feeds", err, a.logger)
		return
	}

	response := IOCFeedListResponse{
		Feeds: feedList,
		Total: len(feedList),
	}

	a.respondJSON(w, response, http.StatusOK)
}

// getIOCFeed godoc
//
//	@Summary		Get IOC Feed
//	@Description	Returns a single IOC feed by ID
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Feed ID"
//	@Success		200	{object}	feeds.IOCFeed
//	@Failure		404	{string}	string	"Feed not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds/{id} [get]
//	@Security		BearerAuth
func (a *API) getIOCFeed(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	feed, err := a.iocFeedManager.GetFeed(r.Context(), id)
	if err != nil {
		if err == feeds.ErrFeedNotFound {
			writeError(w, http.StatusNotFound, "IOC feed not found", nil, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve IOC feed", err, a.logger)
		return
	}

	a.respondJSON(w, feed, http.StatusOK)
}

// createIOCFeed godoc
//
//	@Summary		Create IOC Feed
//	@Description	Creates a new IOC feed
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Param			feed	body		CreateIOCFeedRequest	true	"Feed configuration"
//	@Success		201		{object}	feeds.IOCFeed
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds [post]
//	@Security		BearerAuth
func (a *API) createIOCFeed(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	var req CreateIOCFeedRequest
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

	// Create feed from template if specified
	var feed *feeds.IOCFeed
	if req.TemplateID != "" {
		template := feeds.GetTemplateByID(req.TemplateID)
		if template == nil {
			writeError(w, http.StatusBadRequest, "Invalid template ID", nil, a.logger)
			return
		}
		name := req.Name
		if name == "" {
			name = template.Name
		}
		feed = feeds.CreateFeedFromTemplate(template, name, req.AuthConfig)
	} else {
		feed = &feeds.IOCFeed{
			Name:        req.Name,
			Description: req.Description,
			Type:        req.Type,
			URL:         req.URL,
			AuthConfig:  req.AuthConfig,
			Enabled:     true,
		}
	}

	// Apply additional fields from request
	a.applyFeedRequestFields(feed, &req)

	// Get user from context for created_by
	if userID, ok := GetUserID(r.Context()); ok {
		feed.CreatedBy = userID
	}

	// Create feed
	if err := a.iocFeedManager.CreateFeed(r.Context(), feed); err != nil {
		if err == feeds.ErrInvalidFeedName || err == feeds.ErrInvalidFeedType {
			writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
			return
		}
		if err == feeds.ErrDuplicateFeedID {
			writeError(w, http.StatusConflict, err.Error(), nil, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to create IOC feed", err, a.logger)
		return
	}

	a.respondJSON(w, feed, http.StatusCreated)
}

// updateIOCFeed godoc
//
//	@Summary		Update IOC Feed
//	@Description	Updates an existing IOC feed
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Feed ID"
//	@Param			feed	body		UpdateIOCFeedRequest	true	"Feed updates"
//	@Success		200		{object}	feeds.IOCFeed
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		404		{string}	string	"Feed not found"
//	@Failure		409		{string}	string	"Feed is syncing"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds/{id} [put]
//	@Security		BearerAuth
func (a *API) updateIOCFeed(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Get existing feed
	feed, err := a.iocFeedManager.GetFeed(r.Context(), id)
	if err != nil {
		if err == feeds.ErrFeedNotFound {
			writeError(w, http.StatusNotFound, "IOC feed not found", nil, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve IOC feed", err, a.logger)
		return
	}

	var req UpdateIOCFeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Apply updates
	a.applyFeedUpdateFields(feed, &req)

	// Update feed
	if err := a.iocFeedManager.UpdateFeed(r.Context(), id, feed); err != nil {
		if err == feeds.ErrFeedSyncing {
			writeError(w, http.StatusConflict, "Feed is currently syncing", nil, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to update IOC feed", err, a.logger)
		return
	}

	a.respondJSON(w, feed, http.StatusOK)
}

// deleteIOCFeed godoc
//
//	@Summary		Delete IOC Feed
//	@Description	Deletes an IOC feed
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Param			id	path	string	true	"Feed ID"
//	@Success		204	"No Content"
//	@Failure		404	{string}	string	"Feed not found"
//	@Failure		409	{string}	string	"Feed is syncing"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds/{id} [delete]
//	@Security		BearerAuth
func (a *API) deleteIOCFeed(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.iocFeedManager.DeleteFeed(r.Context(), id); err != nil {
		if err == feeds.ErrFeedNotFound {
			writeError(w, http.StatusNotFound, "IOC feed not found", nil, a.logger)
			return
		}
		if err == feeds.ErrFeedSyncing {
			writeError(w, http.StatusConflict, "Feed is currently syncing", nil, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete IOC feed", err, a.logger)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// IOC Feed Operations Handlers
// =============================================================================

// enableIOCFeed godoc
//
//	@Summary		Enable IOC Feed
//	@Description	Enables an IOC feed for syncing
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Feed ID"
//	@Success		200	{object}	map[string]string
//	@Failure		404	{string}	string	"Feed not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds/{id}/enable [post]
//	@Security		BearerAuth
func (a *API) enableIOCFeed(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.iocFeedManager.EnableFeed(r.Context(), id); err != nil {
		if err == feeds.ErrFeedNotFound {
			writeError(w, http.StatusNotFound, "IOC feed not found", nil, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to enable IOC feed", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]string{"message": "Feed enabled successfully"}, http.StatusOK)
}

// disableIOCFeed godoc
//
//	@Summary		Disable IOC Feed
//	@Description	Disables an IOC feed
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Feed ID"
//	@Success		200	{object}	map[string]string
//	@Failure		404	{string}	string	"Feed not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds/{id}/disable [post]
//	@Security		BearerAuth
func (a *API) disableIOCFeed(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.iocFeedManager.DisableFeed(r.Context(), id); err != nil {
		if err == feeds.ErrFeedNotFound {
			writeError(w, http.StatusNotFound, "IOC feed not found", nil, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to disable IOC feed", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]string{"message": "Feed disabled successfully"}, http.StatusOK)
}

// testIOCFeed godoc
//
//	@Summary		Test IOC Feed
//	@Description	Tests connectivity to an IOC feed
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Feed ID"
//	@Success		200	{object}	map[string]string
//	@Failure		400	{string}	string	"Test failed"
//	@Failure		404	{string}	string	"Feed not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds/{id}/test [post]
//	@Security		BearerAuth
func (a *API) testIOCFeed(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.iocFeedManager.TestFeed(r.Context(), id); err != nil {
		if err == feeds.ErrFeedNotFound {
			writeError(w, http.StatusNotFound, "IOC feed not found", nil, a.logger)
			return
		}
		if err == feeds.ErrAuthFailed {
			writeError(w, http.StatusUnauthorized, "Authentication failed", nil, a.logger)
			return
		}
		if err == feeds.ErrConnectionFailed {
			writeError(w, http.StatusBadGateway, "Connection to feed failed", err, a.logger)
			return
		}
		writeError(w, http.StatusBadRequest, "Feed test failed", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]string{"message": "Feed test successful"}, http.StatusOK)
}

// syncIOCFeed godoc
//
//	@Summary		Sync IOC Feed
//	@Description	Triggers a sync for an IOC feed
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Feed ID"
//	@Success		200	{object}	IOCFeedSyncResponse
//	@Failure		404	{string}	string	"Feed not found"
//	@Failure		409	{string}	string	"Feed is already syncing"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds/{id}/sync [post]
//	@Security		BearerAuth
func (a *API) syncIOCFeed(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Create progress callback for WebSocket if available
	var callback feeds.ProgressCallback
	if a.wsHub != nil {
		callback = func(eventType string, message string, progress int) {
			_ = a.wsHub.BroadcastMessage("ioc_feed_sync_progress", map[string]interface{}{
				"feed_id":  id,
				"event":    eventType,
				"message":  message,
				"progress": progress,
			})
		}
	}

	result, err := a.iocFeedManager.SyncFeedWithProgress(r.Context(), id, callback)
	if err != nil {
		if err == feeds.ErrFeedNotFound {
			writeError(w, http.StatusNotFound, "IOC feed not found", nil, a.logger)
			return
		}
		if err == feeds.ErrFeedDisabled {
			writeError(w, http.StatusBadRequest, "Feed is disabled", nil, a.logger)
			return
		}
		if err == feeds.ErrFeedSyncing {
			writeError(w, http.StatusConflict, "Feed is already syncing", nil, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to sync IOC feed", err, a.logger)
		return
	}

	message := "Sync completed"
	if !result.Success {
		message = "Sync completed with errors"
	}

	a.respondJSON(w, IOCFeedSyncResponse{
		Result:  result,
		Message: message,
	}, http.StatusOK)
}

// getIOCFeedSyncHistory godoc
//
//	@Summary		Get IOC Feed Sync History
//	@Description	Returns sync history for an IOC feed
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string	true	"Feed ID"
//	@Param			limit	query		int		false	"Maximum results"	default(10)
//	@Success		200		{object}	IOCSyncHistoryResponse
//	@Failure		404		{string}	string	"Feed not found"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds/{id}/history [get]
//	@Security		BearerAuth
func (a *API) getIOCFeedSyncHistory(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	history, err := a.iocFeedManager.GetSyncHistory(r.Context(), id, limit)
	if err != nil {
		if err == feeds.ErrFeedNotFound {
			writeError(w, http.StatusNotFound, "IOC feed not found", nil, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve sync history", err, a.logger)
		return
	}

	a.respondJSON(w, IOCSyncHistoryResponse{
		History: history,
		Total:   len(history),
	}, http.StatusOK)
}

// =============================================================================
// IOC Feed Summary and Templates
// =============================================================================

// getIOCFeedsSummary godoc
//
//	@Summary		Get IOC Feeds Summary
//	@Description	Returns aggregate statistics for all IOC feeds
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	feeds.IOCFeedsSummary
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/ioc-feeds/summary [get]
//	@Security		BearerAuth
func (a *API) getIOCFeedsSummary(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	summary, err := a.iocFeedManager.GetFeedsSummary(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve feeds summary", err, a.logger)
		return
	}

	a.respondJSON(w, summary, http.StatusOK)
}

// getIOCFeedTemplates godoc
//
//	@Summary		Get IOC Feed Templates
//	@Description	Returns available feed templates
//	@Tags			ioc-feeds
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}	feeds.IOCFeedTemplate
//	@Router			/api/v1/ioc-feeds/templates [get]
//	@Security		BearerAuth
func (a *API) getIOCFeedTemplates(w http.ResponseWriter, r *http.Request) {
	if a.iocFeedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC feed manager not available", nil, a.logger)
		return
	}

	templates := a.iocFeedManager.GetTemplates()
	a.respondJSON(w, templates, http.StatusOK)
}

// =============================================================================
// Helper Functions
// =============================================================================

// applyFeedRequestFields applies create request fields to feed
func (a *API) applyFeedRequestFields(feed *feeds.IOCFeed, req *CreateIOCFeedRequest) {
	if req.Description != "" {
		feed.Description = req.Description
	}
	if req.URL != "" {
		feed.URL = req.URL
	}
	if req.Path != "" {
		feed.Path = req.Path
	}
	if req.AuthConfig != nil {
		feed.AuthConfig = req.AuthConfig
	}
	if req.CollectionID != "" {
		feed.CollectionID = req.CollectionID
	}
	if req.APIRoot != "" {
		feed.APIRoot = req.APIRoot
	}
	if req.OrgID != "" {
		feed.OrgID = req.OrgID
	}
	if req.EventFilters != "" {
		feed.EventFilters = req.EventFilters
	}
	if len(req.PulseIDs) > 0 {
		feed.PulseIDs = req.PulseIDs
	}
	if req.FieldMapping != nil {
		feed.FieldMapping = req.FieldMapping
	}
	if req.Delimiter != "" {
		feed.Delimiter = req.Delimiter
	}
	feed.SkipHeader = req.SkipHeader
	if req.CommentChar != "" {
		feed.CommentChar = req.CommentChar
	}
	feed.ValueColumn = req.ValueColumn
	feed.TypeColumn = req.TypeColumn
	if len(req.FilePatterns) > 0 {
		feed.FilePatterns = req.FilePatterns
	}
	if len(req.IncludeTypes) > 0 {
		feed.IncludeTypes = req.IncludeTypes
	}
	if len(req.ExcludeTypes) > 0 {
		feed.ExcludeTypes = req.ExcludeTypes
	}
	if req.DefaultType != "" {
		feed.DefaultType = req.DefaultType
	}
	feed.MinConfidence = req.MinConfidence
	if req.DefaultSeverity != "" {
		feed.DefaultSeverity = req.DefaultSeverity
	}
	feed.AutoExpireDays = req.AutoExpireDays
	if len(req.Tags) > 0 {
		feed.Tags = req.Tags
	}
	feed.Priority = req.Priority
	if req.UpdateStrategy != "" {
		feed.UpdateStrategy = req.UpdateStrategy
	}
	if req.UpdateSchedule != "" {
		feed.UpdateSchedule = req.UpdateSchedule
	}
	if req.Enabled != nil {
		feed.Enabled = *req.Enabled
	}
}

// applyFeedUpdateFields applies update request fields to feed
func (a *API) applyFeedUpdateFields(feed *feeds.IOCFeed, req *UpdateIOCFeedRequest) {
	if req.Name != nil {
		feed.Name = *req.Name
	}
	if req.Description != nil {
		feed.Description = *req.Description
	}
	if req.URL != nil {
		feed.URL = *req.URL
	}
	if req.Path != nil {
		feed.Path = *req.Path
	}
	if req.AuthConfig != nil {
		feed.AuthConfig = req.AuthConfig
	}
	if req.CollectionID != nil {
		feed.CollectionID = *req.CollectionID
	}
	if req.APIRoot != nil {
		feed.APIRoot = *req.APIRoot
	}
	if req.OrgID != nil {
		feed.OrgID = *req.OrgID
	}
	if req.EventFilters != nil {
		feed.EventFilters = *req.EventFilters
	}
	if req.PulseIDs != nil {
		feed.PulseIDs = req.PulseIDs
	}
	if req.FieldMapping != nil {
		feed.FieldMapping = req.FieldMapping
	}
	if req.Delimiter != nil {
		feed.Delimiter = *req.Delimiter
	}
	if req.SkipHeader != nil {
		feed.SkipHeader = *req.SkipHeader
	}
	if req.CommentChar != nil {
		feed.CommentChar = *req.CommentChar
	}
	if req.ValueColumn != nil {
		feed.ValueColumn = *req.ValueColumn
	}
	if req.TypeColumn != nil {
		feed.TypeColumn = *req.TypeColumn
	}
	if req.FilePatterns != nil {
		feed.FilePatterns = req.FilePatterns
	}
	if req.IncludeTypes != nil {
		feed.IncludeTypes = req.IncludeTypes
	}
	if req.ExcludeTypes != nil {
		feed.ExcludeTypes = req.ExcludeTypes
	}
	if req.DefaultType != nil {
		feed.DefaultType = *req.DefaultType
	}
	if req.MinConfidence != nil {
		feed.MinConfidence = *req.MinConfidence
	}
	if req.DefaultSeverity != nil {
		feed.DefaultSeverity = *req.DefaultSeverity
	}
	if req.AutoExpireDays != nil {
		feed.AutoExpireDays = *req.AutoExpireDays
	}
	if req.Tags != nil {
		feed.Tags = req.Tags
	}
	if req.Priority != nil {
		feed.Priority = *req.Priority
	}
	if req.UpdateStrategy != nil {
		feed.UpdateStrategy = *req.UpdateStrategy
	}
	if req.UpdateSchedule != nil {
		feed.UpdateSchedule = *req.UpdateSchedule
	}
	if req.Enabled != nil {
		feed.Enabled = *req.Enabled
	}
}
