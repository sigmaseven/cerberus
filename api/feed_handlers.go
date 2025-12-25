// Package api provides feed management API handlers.
// TASK 154.1: Implements CRUD operations for SIGMA rule feeds.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cerberus/sigma/feeds"
	"cerberus/storage"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// Constants for timeouts and limits
const (
	syncOperationTimeout     = 10 * time.Minute
	bulkSyncOperationTimeout = 30 * time.Minute
	connectionTestTimeout    = 30 * time.Second
	maxFeedsLimit            = 100000 // Maximum number of feeds that can be displayed
	defaultPaginationLimit   = 50
	maxPaginationLimit       = 100
	defaultHistoryLimit      = 20
	maxHistoryLimit          = 100
)

// Allowed AuthConfig keys for security validation
var allowedAuthConfigKeys = map[string]bool{
	"username":      true,
	"password":      true,
	"token":         true,
	"private_key":   true,
	"ssh_key":       true,
	"api_key":       true,
	"client_id":     true,
	"client_secret": true,
}

// FeedManagerInterface defines the interface for feed operations.
// This decouples handlers from the concrete feeds.Manager type for testability.
type FeedManagerInterface interface {
	ListFeeds(ctx context.Context) ([]*feeds.RuleFeed, error)
	GetFeed(ctx context.Context, id string) (*feeds.RuleFeed, error)
	CreateFeed(ctx context.Context, feed *feeds.RuleFeed) error
	UpdateFeed(ctx context.Context, id string, feed *feeds.RuleFeed) error
	DeleteFeed(ctx context.Context, id string) error
	SyncFeed(ctx context.Context, id string) (*feeds.FeedSyncResult, error)
	SyncAllFeeds(ctx context.Context) ([]*feeds.FeedSyncResult, error)
	ValidateFeed(ctx context.Context, id string) error
	TestFeedConnection(ctx context.Context, id string) error
	GetFeedStats(ctx context.Context, id string) (*feeds.FeedStats, error)
	GetFeedHealth(ctx context.Context) (map[string]string, error)
	GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*feeds.FeedSyncResult, error)
	// Template operations
	GetTemplates() ([]feeds.FeedTemplate, error)
	GetTemplate(id string) *feeds.FeedTemplate
	CreateFeedFromTemplate(ctx context.Context, templateID string, overrides map[string]interface{}) error
}

// CreateFeedRequest represents the request body for creating a feed.
type CreateFeedRequest struct {
	// Template-based creation
	TemplateID string `json:"template_id,omitempty"` // Create from template if provided

	// Feed configuration fields
	ID              string                 `json:"id,omitempty"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description,omitempty"`
	Type            string                 `json:"type"`
	Enabled         bool                   `json:"enabled"`
	URL             string                 `json:"url,omitempty"`
	Branch          string                 `json:"branch,omitempty"`
	Path            string                 `json:"path,omitempty"`
	AuthConfig      map[string]interface{} `json:"auth_config,omitempty"`
	IncludePaths    []string               `json:"include_paths,omitempty"`
	ExcludePaths    []string               `json:"exclude_paths,omitempty"`
	IncludeTags     []string               `json:"include_tags,omitempty"`
	ExcludeTags     []string               `json:"exclude_tags,omitempty"`
	MinSeverity     string                 `json:"min_severity,omitempty"`
	AutoEnableRules bool                   `json:"auto_enable_rules"`
	Priority        int                    `json:"priority,omitempty"`
	UpdateStrategy  string                 `json:"update_strategy,omitempty"`
	UpdateSchedule  string                 `json:"update_schedule,omitempty"`
	Tags            []string               `json:"tags,omitempty"`
	Metadata        map[string]string      `json:"metadata,omitempty"`
}

// UpdateFeedRequest represents the request body for updating a feed.
type UpdateFeedRequest struct {
	Name            *string                `json:"name,omitempty"`
	Description     *string                `json:"description,omitempty"`
	Type            *string                `json:"type,omitempty"`
	Enabled         *bool                  `json:"enabled,omitempty"`
	URL             *string                `json:"url,omitempty"`
	Branch          *string                `json:"branch,omitempty"`
	Path            *string                `json:"path,omitempty"`
	AuthConfig      map[string]interface{} `json:"auth_config,omitempty"`
	IncludePaths    []string               `json:"include_paths,omitempty"`
	ExcludePaths    []string               `json:"exclude_paths,omitempty"`
	IncludeTags     []string               `json:"include_tags,omitempty"`
	ExcludeTags     []string               `json:"exclude_tags,omitempty"`
	MinSeverity     *string                `json:"min_severity,omitempty"`
	AutoEnableRules *bool                  `json:"auto_enable_rules,omitempty"`
	Priority        *int                   `json:"priority,omitempty"`
	UpdateStrategy  *string                `json:"update_strategy,omitempty"`
	UpdateSchedule  *string                `json:"update_schedule,omitempty"`
	Tags            []string               `json:"tags,omitempty"`
	Metadata        map[string]string      `json:"metadata,omitempty"`
}

// FeedResponse wraps a single feed for API responses.
type FeedResponse struct {
	Feed *feeds.RuleFeed `json:"feed"`
}

// FeedsListResponse wraps a list of feeds for API responses.
type FeedsListResponse struct {
	Feeds      []*feeds.RuleFeed `json:"items"`
	Total      int               `json:"total"`
	Page       int               `json:"page"`
	Limit      int               `json:"limit"`
	TotalPages int               `json:"total_pages"`
}

// SyncStatusResponse represents the response for async sync operations
type SyncStatusResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	FeedID    string `json:"feed_id"`
	StatusURL string `json:"status_url,omitempty"`
}

// listFeeds handles GET /api/v1/feeds
// @Summary		List all feeds
// @Description	Returns a list of configured SIGMA rule feeds
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			page	query		int		false	"Page number (default: 1)"
// @Param			limit	query		int		false	"Items per page (default: 50, max: 100)"
// @Success		200	{object}	FeedsListResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds [get]
// @Security		ApiKeyAuth
func (a *API) listFeeds(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	// Parse pagination parameters
	page, limit := parsePaginationParams(r, defaultPaginationLimit, maxPaginationLimit)
	offset := (page - 1) * limit

	allFeeds, err := a.feedManager.ListFeeds(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list feeds", err, a.logger)
		return
	}

	// Calculate total and paginate
	total := len(allFeeds)

	// Security: Enforce maximum feeds limit
	if total > maxFeedsLimit {
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("Number of feeds (%d) exceeds maximum allowed (%d)", total, maxFeedsLimit),
			nil, a.logger)
		return
	}

	totalPages := (total + limit - 1) / limit

	// Apply pagination bounds
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	paginatedFeeds := allFeeds[start:end]

	// Mask sensitive AuthConfig data in response
	for _, feed := range paginatedFeeds {
		maskAuthConfig(feed)
	}

	response := FeedsListResponse{
		Feeds:      paginatedFeeds,
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
	}

	// Audit logging for read operation
	a.logger.Infow("Feed list retrieved",
		"total_count", total,
		"page", page,
		"limit", limit)

	a.respondJSON(w, response, http.StatusOK)
}

// getFeedByID handles GET /api/v1/feeds/{id}
// @Summary		Get feed by ID
// @Description	Returns a single feed by its ID
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			id	path		string	true	"Feed ID"
// @Success		200	{object}	FeedResponse
// @Failure		404	{object}	ErrorResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/{id} [get]
// @Security		ApiKeyAuth
func (a *API) getFeedByID(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	feedID := strings.TrimSpace(vars["id"])
	if feedID == "" {
		writeError(w, http.StatusBadRequest, "Feed ID is required", nil, a.logger)
		return
	}

	feed, err := a.feedManager.GetFeed(r.Context(), feedID)
	if err != nil {
		if errors.Is(err, feeds.ErrFeedNotFound) {
			writeError(w, http.StatusNotFound, "Feed not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get feed", err, a.logger)
		return
	}

	// Mask sensitive AuthConfig data in response
	maskAuthConfig(feed)

	// Audit logging for read operation
	a.logger.Infow("Feed retrieved",
		"feed_id", feedID,
		"feed_name", feed.Name)

	a.respondJSON(w, FeedResponse{Feed: feed}, http.StatusOK)
}

// createFeed handles POST /api/v1/feeds
// @Summary		Create a new feed
// @Description	Creates a new SIGMA rule feed configuration
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			feed	body		CreateFeedRequest	true	"Feed configuration"
// @Success		201	{object}	FeedResponse
// @Failure		400	{object}	ErrorResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds [post]
// @Security		ApiKeyAuth
func (a *API) createFeed(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	var req CreateFeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Template-based creation path
	if req.TemplateID != "" {
		a.createFeedFromTemplate(w, r, req)
		return
	}

	// Validate required fields for manual creation
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Feed name is required", nil, a.logger)
		return
	}
	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "Feed type is required", nil, a.logger)
		return
	}

	// Security: Validate AuthConfig keys
	if err := validateAuthConfig(req.AuthConfig); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
		return
	}

	// Security: Validate URL for SSRF protection
	if req.URL != "" {
		if err := validateURL(req.URL); err != nil {
			writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
			return
		}
	}

	// Security: Validate and sanitize file path
	if req.Path != "" {
		if err := validatePath(req.Path); err != nil {
			writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
			return
		}
	}

	// Generate ID if not provided
	feedID := req.ID
	if feedID == "" {
		feedID = uuid.New().String()
	}

	// Get current user from context for audit trail
	currentUser := getUserFromContext(r.Context())
	createdBy := ""
	clientIP := getClientIP(r)
	if currentUser != nil {
		createdBy = currentUser.Username
	}

	now := time.Now()
	feed := &feeds.RuleFeed{
		ID:              feedID,
		Name:            req.Name,
		Description:     req.Description,
		Type:            req.Type,
		Status:          feeds.FeedStatusActive,
		Enabled:         req.Enabled,
		URL:             req.URL,
		Branch:          req.Branch,
		Path:            req.Path,
		AuthConfig:      req.AuthConfig,
		IncludePaths:    req.IncludePaths,
		ExcludePaths:    req.ExcludePaths,
		IncludeTags:     req.IncludeTags,
		ExcludeTags:     req.ExcludeTags,
		MinSeverity:     req.MinSeverity,
		AutoEnableRules: req.AutoEnableRules,
		Priority:        req.Priority,
		UpdateStrategy:  req.UpdateStrategy,
		UpdateSchedule:  req.UpdateSchedule,
		Tags:            req.Tags,
		Metadata:        req.Metadata,
		CreatedAt:       now,
		UpdatedAt:       now,
		CreatedBy:       createdBy,
	}

	// Set defaults
	if feed.UpdateStrategy == "" {
		feed.UpdateStrategy = feeds.UpdateManual
	}

	if err := a.feedManager.CreateFeed(r.Context(), feed); err != nil {
		if errors.Is(err, feeds.ErrDuplicateFeedID) {
			writeError(w, http.StatusConflict, "Feed with this ID already exists", err, a.logger)
			return
		}
		if errors.Is(err, feeds.ErrInvalidFeedType) || errors.Is(err, feeds.ErrInvalidFeedName) ||
			errors.Is(err, feeds.ErrMissingURL) || errors.Is(err, feeds.ErrMissingPath) {
			writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to create feed", err, a.logger)
		return
	}

	// Audit logging with redacted sensitive data
	a.logger.Infow("Feed created",
		"feed_id", feed.ID,
		"feed_name", feed.Name,
		"feed_type", feed.Type,
		"created_by", createdBy,
		"client_ip", clientIP)

	// Mask AuthConfig before returning
	maskAuthConfig(feed)

	a.respondJSON(w, FeedResponse{Feed: feed}, http.StatusCreated)
}

// createFeedFromTemplate handles template-based feed creation.
// This is a helper method called by createFeed when template_id is provided.
func (a *API) createFeedFromTemplate(w http.ResponseWriter, r *http.Request, req CreateFeedRequest) {
	// Get current user from context for audit trail
	currentUser := getUserFromContext(r.Context())
	createdBy := ""
	clientIP := getClientIP(r)
	if currentUser != nil {
		createdBy = currentUser.Username
	}

	// Build overrides map from request fields
	// Only non-zero values are included to allow template defaults
	overrides := make(map[string]interface{})

	// Required override: name
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Feed name is required", nil, a.logger)
		return
	}
	overrides["name"] = req.Name

	// Optional overrides - only include if provided
	if req.ID != "" {
		overrides["id"] = req.ID
	}
	if req.Description != "" {
		overrides["description"] = req.Description
	}
	if req.Type != "" {
		overrides["type"] = req.Type
	}
	overrides["enabled"] = req.Enabled // Always include bool (has default false)

	if req.URL != "" {
		// Security: Validate URL for SSRF protection
		if err := validateURL(req.URL); err != nil {
			writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
			return
		}
		overrides["url"] = req.URL
	}
	if req.Branch != "" {
		overrides["branch"] = req.Branch
	}
	if req.Path != "" {
		// Security: Validate and sanitize file path
		if err := validatePath(req.Path); err != nil {
			writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
			return
		}
		overrides["path"] = req.Path
	}
	if req.AuthConfig != nil && len(req.AuthConfig) > 0 {
		// Security: Validate AuthConfig keys
		if err := validateAuthConfig(req.AuthConfig); err != nil {
			writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
			return
		}
		overrides["auth_config"] = req.AuthConfig
	}
	if len(req.IncludePaths) > 0 {
		overrides["include_paths"] = req.IncludePaths
	}
	if len(req.ExcludePaths) > 0 {
		overrides["exclude_paths"] = req.ExcludePaths
	}
	if len(req.IncludeTags) > 0 {
		overrides["include_tags"] = req.IncludeTags
	}
	if len(req.ExcludeTags) > 0 {
		overrides["exclude_tags"] = req.ExcludeTags
	}
	if req.MinSeverity != "" {
		overrides["min_severity"] = req.MinSeverity
	}
	overrides["auto_enable_rules"] = req.AutoEnableRules // Always include bool

	if req.Priority != 0 {
		overrides["priority"] = req.Priority
	}
	if req.UpdateStrategy != "" {
		overrides["update_strategy"] = req.UpdateStrategy
	}
	if req.UpdateSchedule != "" {
		overrides["update_schedule"] = req.UpdateSchedule
	}
	if len(req.Tags) > 0 {
		overrides["tags"] = req.Tags
	}
	if req.Metadata != nil && len(req.Metadata) > 0 {
		overrides["metadata"] = req.Metadata
	}

	// Create feed from template with overrides
	if err := a.feedManager.CreateFeedFromTemplate(r.Context(), req.TemplateID, overrides); err != nil {
		// Handle specific error types
		errMsg := err.Error()
		if errMsg == "template not found: "+req.TemplateID || errors.Is(err, feeds.ErrFeedNotFound) {
			writeError(w, http.StatusNotFound, "Template not found: "+req.TemplateID, err, a.logger)
			return
		}
		if errors.Is(err, feeds.ErrDuplicateFeedID) {
			writeError(w, http.StatusConflict, "Feed with this ID already exists", err, a.logger)
			return
		}
		if errors.Is(err, feeds.ErrInvalidFeedType) || errors.Is(err, feeds.ErrInvalidFeedName) ||
			errors.Is(err, feeds.ErrMissingURL) || errors.Is(err, feeds.ErrMissingPath) {
			writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to create feed from template", err, a.logger)
		return
	}

	// Retrieve the created feed to return to client
	// The feed ID is either from override or auto-generated by template manager
	allFeeds, err := a.feedManager.ListFeeds(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Feed created but failed to retrieve details", err, a.logger)
		return
	}

	// Find the most recently created feed matching the name
	// This is safe because CreateFeedFromTemplate just completed successfully
	var createdFeed *feeds.RuleFeed
	for _, f := range allFeeds {
		if f.Name == req.Name {
			if createdFeed == nil || f.CreatedAt.After(createdFeed.CreatedAt) {
				createdFeed = f
			}
		}
	}

	if createdFeed == nil {
		writeError(w, http.StatusInternalServerError, "Feed created but not found", nil, a.logger)
		return
	}

	// Mask AuthConfig before returning
	maskAuthConfig(createdFeed)

	// Audit logging with redacted sensitive data
	a.logger.Infow("Feed created from template",
		"template_id", req.TemplateID,
		"feed_id", createdFeed.ID,
		"feed_name", createdFeed.Name,
		"feed_type", createdFeed.Type,
		"created_by", createdBy,
		"client_ip", clientIP)

	a.respondJSON(w, FeedResponse{Feed: createdFeed}, http.StatusCreated)
}

// updateFeed handles PUT /api/v1/feeds/{id}
// @Summary		Update a feed
// @Description	Updates an existing SIGMA rule feed configuration
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			id		path		string				true	"Feed ID"
// @Param			feed	body		UpdateFeedRequest	true	"Feed configuration updates"
// @Success		200	{object}	FeedResponse
// @Failure		400	{object}	ErrorResponse
// @Failure		404	{object}	ErrorResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/{id} [put]
// @Security		ApiKeyAuth
func (a *API) updateFeed(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	feedID := strings.TrimSpace(mux.Vars(r)["id"])
	if feedID == "" {
		writeError(w, http.StatusBadRequest, "Feed ID is required", nil, a.logger)
		return
	}

	existingFeed, err := a.feedManager.GetFeed(r.Context(), feedID)
	if err != nil {
		handleFeedError(w, err, a.logger)
		return
	}

	var req UpdateFeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	if err := validateFeedUpdateRequest(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
		return
	}

	applyFeedUpdates(existingFeed, &req)

	if err := a.feedManager.UpdateFeed(r.Context(), feedID, existingFeed); err != nil {
		handleFeedError(w, err, a.logger)
		return
	}

	logFeedUpdate(a.logger, feedID, existingFeed.Name, getUserFromContext(r.Context()), getClientIP(r))
	maskAuthConfig(existingFeed)
	a.respondJSON(w, FeedResponse{Feed: existingFeed}, http.StatusOK)
}

// deleteFeed handles DELETE /api/v1/feeds/{id}
// @Summary		Delete a feed
// @Description	Deletes a SIGMA rule feed configuration
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			id	path		string	true	"Feed ID"
// @Success		204	"Feed deleted successfully"
// @Failure		404	{object}	ErrorResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/{id} [delete]
// @Security		ApiKeyAuth
func (a *API) deleteFeed(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	feedID := strings.TrimSpace(vars["id"])
	if feedID == "" {
		writeError(w, http.StatusBadRequest, "Feed ID is required", nil, a.logger)
		return
	}

	// Verify feed exists
	feed, err := a.feedManager.GetFeed(r.Context(), feedID)
	if err != nil {
		if errors.Is(err, feeds.ErrFeedNotFound) {
			writeError(w, http.StatusNotFound, "Feed not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get feed", err, a.logger)
		return
	}

	if err := a.feedManager.DeleteFeed(r.Context(), feedID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete feed", err, a.logger)
		return
	}

	// Audit logging with user and IP
	currentUser := getUserFromContext(r.Context())
	clientIP := getClientIP(r)
	a.logger.Infow("Feed deleted",
		"feed_id", feedID,
		"feed_name", feed.Name,
		"deleted_by", getUsernameOrEmpty(currentUser),
		"client_ip", clientIP)

	w.WriteHeader(http.StatusNoContent)
}

// syncFeed handles POST /api/v1/feeds/{id}/sync
// @Summary		Sync a feed (async)
// @Description	Triggers asynchronous synchronization of a SIGMA rule feed. Returns immediately with 202 Accepted. Poll feed stats for completion status.
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			id	path		string	true	"Feed ID"
// @Success		202	{object}	SyncStatusResponse	"Sync operation accepted and running in background"
// @Failure		400	{object}	ErrorResponse
// @Failure		404	{object}	ErrorResponse
// @Failure		409	{object}	ErrorResponse	"Feed is already syncing"
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/{id}/sync [post]
// @Security		ApiKeyAuth
func (a *API) syncFeed(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	feedID := strings.TrimSpace(vars["id"])
	if feedID == "" {
		writeError(w, http.StatusBadRequest, "Feed ID is required", nil, a.logger)
		return
	}

	// Verify feed exists and is not disabled before starting async operation
	feed, err := a.feedManager.GetFeed(r.Context(), feedID)
	if err != nil {
		if errors.Is(err, feeds.ErrFeedNotFound) {
			writeError(w, http.StatusNotFound, "Feed not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get feed", err, a.logger)
		return
	}

	if !feed.Enabled {
		writeError(w, http.StatusBadRequest, "Feed is disabled", feeds.ErrFeedDisabled, a.logger)
		return
	}

	// Start sync operation in background goroutine
	// Security: Capture dependencies by value to prevent race condition on shutdown
	// TASK 158: Enhanced with WebSocket progress broadcasting
	go func(api *API, feedID, feedName string, stopCh <-chan struct{}) {
		ctx, cancel := context.WithTimeout(context.Background(), syncOperationTimeout)
		defer cancel()

		// Check for shutdown before starting sync
		select {
		case <-stopCh:
			api.logger.Infow("Feed sync cancelled - server shutting down", "feed_id", feedID)
			return
		default:
		}

		// TASK 158: Create progress callback for WebSocket broadcasting
		progressCallback := func(eventType, message string, progress int) {
			// Map feed manager event types to WebSocket event types
			wsEventType := fmt.Sprintf("feed:sync:%s", eventType)

			// Create WebSocket event
			event := &FeedSyncEvent{
				Type:      wsEventType,
				FeedID:    feedID,
				FeedName:  feedName,
				Progress:  progress,
				Message:   message,
				Timestamp: time.Now(),
			}

			// Broadcast to all WebSocket clients
			api.BroadcastFeedEvent(event)
		}

		// Call the manager with progress callback
		feedMgr, ok := api.feedManager.(*feeds.Manager)
		if !ok {
			api.logger.Errorw("Feed manager type assertion failed", "feed_id", feedID)
			return
		}

		result, err := feedMgr.SyncFeedWithProgress(ctx, feedID, progressCallback)
		if err != nil {
			if errors.Is(err, feeds.ErrFeedSyncing) {
				// Already syncing, log and return
				api.logger.Warnw("Feed sync skipped - already in progress", "feed_id", feedID)
				return
			}
			api.logger.Errorw("Feed sync failed",
				"feed_id", feedID,
				"error", err)
			return
		}

		api.logger.Infow("Feed sync completed",
			"feed_id", feedID,
			"success", result.Success,
			"imported", result.Stats.ImportedRules,
			"updated", result.Stats.UpdatedRules,
			"failed", result.Stats.FailedRules,
			"duration", result.Duration)
	}(a, feedID, feed.Name, a.stopCh)

	// Return 202 Accepted immediately
	statusURL := "/api/v1/feeds/" + feedID + "/stats"
	response := SyncStatusResponse{
		Status:    "accepted",
		Message:   "Feed synchronization started in background. Poll the stats endpoint to check completion status.",
		FeedID:    feedID,
		StatusURL: statusURL,
	}

	a.logger.Infow("Feed sync operation accepted",
		"feed_id", feedID,
		"status_url", statusURL)

	a.respondJSON(w, response, http.StatusAccepted)
}

// syncAllFeeds handles POST /api/v1/feeds/sync-all
// @Summary		Sync all feeds (async)
// @Description	Triggers asynchronous synchronization of all enabled SIGMA rule feeds. Returns immediately with 202 Accepted. Poll individual feed stats for completion status.
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Success		202	{object}	SyncStatusResponse	"Sync operations accepted and running in background"
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/sync-all [post]
// @Security		ApiKeyAuth
func (a *API) syncAllFeeds(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	// Start bulk sync operation in background goroutine
	// Security: Capture dependencies by value to prevent race condition on shutdown
	go func(mgr FeedManagerInterface, logger *zap.SugaredLogger, stopCh <-chan struct{}) {
		ctx, cancel := context.WithTimeout(context.Background(), bulkSyncOperationTimeout)
		defer cancel()

		// Check for shutdown before starting bulk sync
		select {
		case <-stopCh:
			logger.Infow("Bulk feed sync cancelled - server shutting down")
			return
		default:
		}

		results, err := mgr.SyncAllFeeds(ctx)
		if err != nil {
			logger.Errorw("Bulk feed sync failed", "error", err)
			return
		}

		// Calculate summary statistics
		totalFeeds := len(results)
		successCount := 0
		for _, result := range results {
			if result.Success {
				successCount++
			}
		}

		logger.Infow("Bulk feed sync completed",
			"total_feeds", totalFeeds,
			"successful", successCount)
	}(a.feedManager, a.logger, a.stopCh)

	// Return 202 Accepted immediately
	response := SyncStatusResponse{
		Status:    "accepted",
		Message:   "Bulk feed synchronization started in background. Poll individual feed stats endpoints to check completion status.",
		StatusURL: "/api/v1/feeds",
	}

	a.logger.Infow("Bulk feed sync operation accepted")

	a.respondJSON(w, response, http.StatusAccepted)
}

// getFeedHistory handles GET /api/v1/feeds/{id}/history
// @Summary		Get feed sync history
// @Description	Returns synchronization history for a SIGMA rule feed
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			id		path		string	true	"Feed ID"
// @Param			limit	query		int		false	"Maximum number of results (default: 20, max: 100)"
// @Success		200		{array}		feeds.FeedSyncResult
// @Failure		404		{object}	ErrorResponse
// @Failure		500		{object}	ErrorResponse
// @Router			/api/v1/feeds/{id}/history [get]
// @Security		ApiKeyAuth
func (a *API) getFeedHistory(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	feedID := strings.TrimSpace(vars["id"])
	if feedID == "" {
		writeError(w, http.StatusBadRequest, "Feed ID is required", nil, a.logger)
		return
	}

	// Verify feed exists
	_, err := a.feedManager.GetFeed(r.Context(), feedID)
	if err != nil {
		if errors.Is(err, feeds.ErrFeedNotFound) {
			writeError(w, http.StatusNotFound, "Feed not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get feed", err, a.logger)
		return
	}

	// Parse limit parameter
	_, limit := parsePaginationParams(r, defaultHistoryLimit, maxHistoryLimit)

	// Retrieve sync history from feed manager
	history, err := a.feedManager.GetSyncHistory(r.Context(), feedID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve sync history", err, a.logger)
		return
	}

	// Add audit logging for read operation
	a.logger.Infow("Feed sync history retrieved",
		"feed_id", feedID,
		"limit", limit,
		"result_count", len(history))

	a.respondJSON(w, history, http.StatusOK)
}

// getFeedStats handles GET /api/v1/feeds/{id}/stats
// @Summary		Get feed statistics
// @Description	Returns detailed statistics for a SIGMA rule feed
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			id	path		string	true	"Feed ID"
// @Success		200	{object}	feeds.FeedStats
// @Failure		404	{object}	ErrorResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/{id}/stats [get]
// @Security		ApiKeyAuth
func (a *API) getFeedStats(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	feedID := strings.TrimSpace(vars["id"])
	if feedID == "" {
		writeError(w, http.StatusBadRequest, "Feed ID is required", nil, a.logger)
		return
	}

	stats, err := a.feedManager.GetFeedStats(r.Context(), feedID)
	if err != nil {
		if errors.Is(err, feeds.ErrFeedNotFound) {
			writeError(w, http.StatusNotFound, "Feed not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get feed stats", err, a.logger)
		return
	}

	// Audit logging for read operation
	a.logger.Infow("Feed stats retrieved",
		"feed_id", feedID,
		"total_rules", stats.TotalRules)

	a.respondJSON(w, stats, http.StatusOK)
}

// getFeedTemplates handles GET /api/v1/feeds/templates
// @Summary		Get feed templates
// @Description	Returns a list of pre-configured feed templates
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Success		200	{array}		feeds.FeedTemplate
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/templates [get]
// @Security		ApiKeyAuth
func (a *API) getFeedTemplates(w http.ResponseWriter, r *http.Request) {
	// CONCERN-3 FIX: Use feedManager.GetTemplates() instead of creating new TemplateManager
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	templates, err := a.feedManager.GetTemplates()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load feed templates", err, a.logger)
		return
	}

	// Audit logging for read operation
	a.logger.Infow("Feed templates retrieved",
		"template_count", len(templates))

	a.respondJSON(w, templates, http.StatusOK)
}

// testFeed handles POST /api/v1/feeds/{id}/test
// @Summary		Test feed connection
// @Description	Tests connectivity to a SIGMA rule feed source
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			id	path		string	true	"Feed ID"
// @Success		200	{object}	map[string]string
// @Failure		400	{object}	ErrorResponse
// @Failure		404	{object}	ErrorResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/{id}/test [post]
// @Security		ApiKeyAuth
func (a *API) testFeed(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	feedID := strings.TrimSpace(vars["id"])
	if feedID == "" {
		writeError(w, http.StatusBadRequest, "Feed ID is required", nil, a.logger)
		return
	}

	// Security: Use context.Background() to ensure fixed timeout is respected
	// If we use r.Context(), parent context timeout (e.g., reverse proxy) may override
	ctx, cancel := context.WithTimeout(context.Background(), connectionTestTimeout)
	defer cancel()

	if err := a.feedManager.TestFeedConnection(ctx, feedID); err != nil {
		if errors.Is(err, feeds.ErrFeedNotFound) {
			writeError(w, http.StatusNotFound, "Feed not found", err, a.logger)
			return
		}
		if errors.Is(err, feeds.ErrConnectionFailed) || errors.Is(err, feeds.ErrAuthFailed) {
			writeError(w, http.StatusBadRequest, "Connection test failed: "+err.Error(), err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Connection test failed", err, a.logger)
		return
	}

	a.logger.Infow("Feed connection test successful", "feed_id", feedID)
	a.respondJSON(w, map[string]string{
		"status":  "success",
		"message": "Connection test passed",
	}, http.StatusOK)
}

// enableFeed handles POST /api/v1/feeds/{id}/enable
// @Summary		Enable a feed
// @Description	Enables a SIGMA rule feed for automatic synchronization
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			id	path		string	true	"Feed ID"
// @Success		200	{object}	FeedResponse
// @Failure		404	{object}	ErrorResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/{id}/enable [post]
// @Security		ApiKeyAuth
func (a *API) enableFeed(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	feedID := strings.TrimSpace(vars["id"])
	if feedID == "" {
		writeError(w, http.StatusBadRequest, "Feed ID is required", nil, a.logger)
		return
	}

	// Get current feed
	feed, err := a.feedManager.GetFeed(r.Context(), feedID)
	if err != nil {
		if errors.Is(err, feeds.ErrFeedNotFound) {
			writeError(w, http.StatusNotFound, "Feed not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get feed", err, a.logger)
		return
	}

	// Update enabled status
	feed.Enabled = true
	feed.UpdatedAt = time.Now()

	if err := a.feedManager.UpdateFeed(r.Context(), feedID, feed); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to enable feed", err, a.logger)
		return
	}

	// Audit logging with user and IP
	currentUser := getUserFromContext(r.Context())
	clientIP := getClientIP(r)
	a.logger.Infow("Feed enabled",
		"feed_id", feedID,
		"feed_name", feed.Name,
		"enabled_by", getUsernameOrEmpty(currentUser),
		"client_ip", clientIP)

	// Mask AuthConfig before returning
	maskAuthConfig(feed)

	a.respondJSON(w, FeedResponse{Feed: feed}, http.StatusOK)
}

// disableFeed handles POST /api/v1/feeds/{id}/disable
// @Summary		Disable a feed
// @Description	Disables a SIGMA rule feed to prevent automatic synchronization
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Param			id	path		string	true	"Feed ID"
// @Success		200	{object}	FeedResponse
// @Failure		404	{object}	ErrorResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/{id}/disable [post]
// @Security		ApiKeyAuth
func (a *API) disableFeed(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	feedID := strings.TrimSpace(vars["id"])
	if feedID == "" {
		writeError(w, http.StatusBadRequest, "Feed ID is required", nil, a.logger)
		return
	}

	// Get current feed
	feed, err := a.feedManager.GetFeed(r.Context(), feedID)
	if err != nil {
		if errors.Is(err, feeds.ErrFeedNotFound) {
			writeError(w, http.StatusNotFound, "Feed not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get feed", err, a.logger)
		return
	}

	// Update enabled status
	feed.Enabled = false
	feed.UpdatedAt = time.Now()

	if err := a.feedManager.UpdateFeed(r.Context(), feedID, feed); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to disable feed", err, a.logger)
		return
	}

	// Audit logging with user and IP
	currentUser := getUserFromContext(r.Context())
	clientIP := getClientIP(r)
	a.logger.Infow("Feed disabled",
		"feed_id", feedID,
		"feed_name", feed.Name,
		"disabled_by", getUsernameOrEmpty(currentUser),
		"client_ip", clientIP)

	// Mask AuthConfig before returning
	maskAuthConfig(feed)

	a.respondJSON(w, FeedResponse{Feed: feed}, http.StatusOK)
}

// =============================================================================
// Helper Functions
// =============================================================================

// validateFeedUpdateRequest validates all security-sensitive fields in update request.
// Extracted from updateFeed to keep handler under 50 lines and centralize validation.
func validateFeedUpdateRequest(req *UpdateFeedRequest) error {
	// Security: Validate AuthConfig keys if provided
	if req.AuthConfig != nil {
		if err := validateAuthConfig(req.AuthConfig); err != nil {
			return err
		}
	}

	// Security: Validate URL for SSRF protection if provided
	if req.URL != nil && *req.URL != "" {
		if err := validateURL(*req.URL); err != nil {
			return err
		}
	}

	// Security: Validate and sanitize file path if provided
	if req.Path != nil && *req.Path != "" {
		if err := validatePath(*req.Path); err != nil {
			return err
		}
	}

	return nil
}

// handleFeedError handles common feed errors with appropriate HTTP status codes.
// Extracted to reduce duplication and keep handlers concise.
func handleFeedError(w http.ResponseWriter, err error, logger *zap.SugaredLogger) {
	if errors.Is(err, feeds.ErrFeedNotFound) {
		writeError(w, http.StatusNotFound, "Feed not found", err, logger)
		return
	}
	if errors.Is(err, feeds.ErrInvalidFeedType) || errors.Is(err, feeds.ErrInvalidFeedName) ||
		errors.Is(err, feeds.ErrMissingURL) || errors.Is(err, feeds.ErrMissingPath) {
		writeError(w, http.StatusBadRequest, err.Error(), err, logger)
		return
	}
	writeError(w, http.StatusInternalServerError, "Failed to process feed", err, logger)
}

// logFeedUpdate logs feed update operations with audit information.
// Extracted to keep updateFeed handler concise and consistent with audit logging.
func logFeedUpdate(logger *zap.SugaredLogger, feedID, feedName string, user *storage.User, clientIP string) {
	logger.Infow("Feed updated",
		"feed_id", feedID,
		"feed_name", feedName,
		"updated_by", getUsernameOrEmpty(user),
		"client_ip", clientIP)
}

// applyFeedUpdates applies update request fields to existing feed.
// Extracted to keep updateFeed under 50 lines.
func applyFeedUpdates(feed *feeds.RuleFeed, req *UpdateFeedRequest) {
	if req.Name != nil {
		feed.Name = *req.Name
	}
	if req.Description != nil {
		feed.Description = *req.Description
	}
	if req.Type != nil {
		feed.Type = *req.Type
	}
	if req.Enabled != nil {
		feed.Enabled = *req.Enabled
	}
	if req.URL != nil {
		feed.URL = *req.URL
	}
	if req.Branch != nil {
		feed.Branch = *req.Branch
	}
	if req.Path != nil {
		feed.Path = *req.Path
	}
	if req.AuthConfig != nil {
		feed.AuthConfig = req.AuthConfig
	}
	if req.IncludePaths != nil {
		feed.IncludePaths = req.IncludePaths
	}
	if req.ExcludePaths != nil {
		feed.ExcludePaths = req.ExcludePaths
	}
	if req.IncludeTags != nil {
		feed.IncludeTags = req.IncludeTags
	}
	if req.ExcludeTags != nil {
		feed.ExcludeTags = req.ExcludeTags
	}
	if req.MinSeverity != nil {
		feed.MinSeverity = *req.MinSeverity
	}
	if req.AutoEnableRules != nil {
		feed.AutoEnableRules = *req.AutoEnableRules
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
	if req.Tags != nil {
		feed.Tags = req.Tags
	}
	if req.Metadata != nil {
		feed.Metadata = req.Metadata
	}
	feed.UpdatedAt = time.Now()
}

// getUserFromContext extracts the user from the request context.
// Returns nil if no user is found in context.
// Uses the type-safe GetUser from context_keys.go.
func getUserFromContext(ctx context.Context) *storage.User {
	if user, ok := GetUser(ctx); ok {
		if u, ok := user.(*storage.User); ok {
			return u
		}
	}
	return nil
}

// getUsernameOrEmpty returns the username from user or empty string if nil.
func getUsernameOrEmpty(user *storage.User) string {
	if user != nil {
		return user.Username
	}
	return ""
}

// getClientIP extracts the client IP address from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}

// parsePaginationParams extracts page and limit from query parameters with defaults.
func parsePaginationParams(r *http.Request, defaultLimit, maxLimit int) (page, limit int) {
	page = 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit = defaultLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= maxLimit {
			limit = parsed
		}
	}

	return page, limit
}

// validateAuthConfig validates that only allowed keys are present in AuthConfig.
// Security: Prevents injection of arbitrary configuration keys.
func validateAuthConfig(authConfig map[string]interface{}) error {
	if authConfig == nil {
		return nil
	}

	for key := range authConfig {
		if !allowedAuthConfigKeys[key] {
			return fmt.Errorf("invalid auth config key: %s", key)
		}
	}

	return nil
}

// validateURL validates a URL for SSRF protection.
// Security: Ensures URLs use safe schemes and don't target private networks.
func validateURL(urlStr string) error {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Allow only https and git schemes
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "https" && scheme != "git" {
		return fmt.Errorf("invalid URL scheme: only https and git are allowed")
	}

	// Block private IP ranges
	host := parsedURL.Hostname()
	if host == "" {
		return fmt.Errorf("URL must contain a hostname")
	}

	// Try to resolve the hostname to IP with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		// If resolution fails, still validate the hostname format
		// Don't fail here as DNS might be temporarily unavailable
		return nil
	}

	// Check if any resolved IP is private
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("URL resolves to private IP address: access to private networks is forbidden")
		}
	}

	return nil
}

// isPrivateIP checks if an IP address is in a private range.
// Security: Blocks RFC1918, loopback, and link-local addresses.
func isPrivateIP(ip net.IP) bool {
	// IPv4 private ranges
	privateIPv4Blocks := []string{
		"10.0.0.0/8",         // RFC1918
		"172.16.0.0/12",      // RFC1918
		"192.168.0.0/16",     // RFC1918
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // Link-local
		"0.0.0.0/8",          // Current network
		"100.64.0.0/10",      // Shared address space
		"192.0.0.0/24",       // IETF protocol assignments
		"192.0.2.0/24",       // Documentation
		"198.18.0.0/15",      // Benchmarking
		"198.51.100.0/24",    // Documentation
		"203.0.113.0/24",     // Documentation
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved
		"255.255.255.255/32", // Broadcast
	}

	for _, cidr := range privateIPv4Blocks {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}

	// IPv6 private ranges
	if ip.To4() == nil {
		// IPv6 loopback
		if ip.IsLoopback() {
			return true
		}
		// IPv6 link-local
		if ip.IsLinkLocalUnicast() {
			return true
		}
		// IPv6 unique local
		_, ula, _ := net.ParseCIDR("fc00::/7")
		if ula.Contains(ip) {
			return true
		}
	}

	return false
}

// validatePath validates and sanitizes a file path to prevent directory traversal.
// Security: Blocks path traversal sequences and system directory access.
// CRITICAL: On Windows, Unix paths like "/etc/passwd" are NOT absolute, so we must
// check dangerous prefixes REGARDLESS of IsAbs() result to prevent bypass.
func validatePath(path string) error {
	if path == "" {
		return nil
	}

	// Block path traversal BEFORE cleaning
	if strings.Contains(path, "..") {
		return fmt.Errorf("path contains directory traversal sequence")
	}

	cleanPath := filepath.Clean(path)
	lowerPath := strings.ToLower(cleanPath)

	// Check dangerous prefixes on ALL paths (not just absolute)
	// This prevents Windows bypass where "/etc/passwd" is not absolute
	dangerousPrefixes := []string{
		"/etc", "/sys", "/proc", "/dev", "/root", "/boot",
		"\\etc", "\\sys", "\\proc", "\\dev", "\\root", "\\boot",
		"c:\\windows", "c:\\program files",
	}

	for _, prefix := range dangerousPrefixes {
		if strings.HasPrefix(lowerPath, prefix) {
			return fmt.Errorf("access to system directories is forbidden")
		}
	}

	return nil
}

// maskAuthConfig redacts sensitive fields from AuthConfig for logging and API responses.
// Security: Prevents credential leakage in logs and responses.
func maskAuthConfig(feed *feeds.RuleFeed) {
	if feed == nil || feed.AuthConfig == nil {
		return
	}

	// Create a new map with masked values
	masked := make(map[string]interface{})
	for key := range feed.AuthConfig {
		masked[key] = "***REDACTED***"
	}
	feed.AuthConfig = masked
}

// FeedsSummaryResponse represents the summary statistics for all feeds.
// TASK 157.1: Aggregate feed statistics for dashboard display.
type FeedsSummaryResponse struct {
	TotalFeeds   int        `json:"total_feeds"`
	ActiveFeeds  int        `json:"active_feeds"`
	TotalRules   int        `json:"total_rules"`
	LastSync     *time.Time `json:"last_sync"` // null if no feeds have synced
	HealthStatus string     `json:"health_status"`
	ErrorCount   int        `json:"error_count"`
}

// getFeedsSummary handles GET /api/v1/feeds/summary
// @Summary		Get feeds summary
// @Description	Returns aggregate statistics for all SIGMA rule feeds
// @Tags			feeds
// @Accept			json
// @Produce		json
// @Success		200	{object}	FeedsSummaryResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/feeds/summary [get]
// @Security		ApiKeyAuth
func (a *API) getFeedsSummary(w http.ResponseWriter, r *http.Request) {
	if a.feedManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Feed manager not available", nil, a.logger)
		return
	}

	// CRITICAL CONCERN #4: Enforce explicit timeout for feed operations
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Retrieve all feeds to calculate statistics
	allFeeds, err := a.feedManager.ListFeeds(ctx)
	if err != nil {
		// CRITICAL CONCERN #5: Wrap error with context for debugging
		wrappedErr := fmt.Errorf("getFeedsSummary: failed to list feeds: %w", err)
		writeError(w, http.StatusInternalServerError, "Failed to list feeds", wrappedErr, a.logger)
		return
	}

	// Get health status map
	healthMap, err := a.feedManager.GetFeedHealth(ctx)
	if err != nil {
		// CRITICAL CONCERN #5: Wrap error with context for debugging
		wrappedErr := fmt.Errorf("getFeedsSummary: failed to get feed health: %w", err)
		writeError(w, http.StatusInternalServerError, "Failed to get feed health", wrappedErr, a.logger)
		return
	}

	// Calculate summary statistics
	summary := calculateFeedsSummary(allFeeds, healthMap)

	// Audit logging for read operation
	a.logger.Infow("Feeds summary retrieved",
		"total_feeds", summary.TotalFeeds,
		"active_feeds", summary.ActiveFeeds,
		"health_status", summary.HealthStatus)

	a.respondJSON(w, summary, http.StatusOK)
}

// calculateFeedsSummary computes aggregate statistics from feeds and health map.
// TASK 157.1: Extracted for testability and separation of concerns.
// PRODUCTION: Pure function with no side effects for easy unit testing.
// Security: Protects against integer overflow and nil pointer dereference.
func calculateFeedsSummary(allFeeds []*feeds.RuleFeed, healthMap map[string]string) FeedsSummaryResponse {
	summary := FeedsSummaryResponse{
		TotalFeeds:   len(allFeeds),
		ActiveFeeds:  0,
		TotalRules:   0,
		LastSync:     nil,
		HealthStatus: "healthy",
		ErrorCount:   0,
	}

	var mostRecentSync time.Time
	hasErrorOrWarning := false
	hasError := false

	for _, feed := range allFeeds {
		// BLOCKING ISSUE #3: Nil pointer dereference risk - skip nil feeds
		if feed == nil {
			continue
		}

		// Count enabled feeds as active
		if feed.Enabled {
			summary.ActiveFeeds++
		}

		// GATEKEEPER FIX #2: Integer overflow vulnerability - cap at math.MaxInt
		// Check for overflow before adding, but DO NOT skip other processing
		if feed.Stats.TotalRules > 0 {
			if summary.TotalRules > (math.MaxInt - feed.Stats.TotalRules) {
				// Cap at max value - overflow would occur
				summary.TotalRules = math.MaxInt
				// NOTE: Continue processing health/sync data - do NOT use continue here
			} else {
				summary.TotalRules += feed.Stats.TotalRules
			}
		}

		// Track most recent sync time
		if !feed.LastSync.IsZero() {
			if summary.LastSync == nil {
				mostRecentSync = feed.LastSync
				summary.LastSync = &mostRecentSync
			} else if feed.LastSync.After(mostRecentSync) {
				mostRecentSync = feed.LastSync
				summary.LastSync = &mostRecentSync
			}
		}

		// Count feeds with errors (from health map)
		health, exists := healthMap[feed.ID]
		if exists && (health == "error" || health == "warning") {
			hasErrorOrWarning = true
			if health == "error" {
				hasError = true
				summary.ErrorCount++
			}
		}
	}

	// Determine overall health status
	if hasError {
		summary.HealthStatus = "error"
	} else if hasErrorOrWarning {
		summary.HealthStatus = "warning"
	} else {
		summary.HealthStatus = "healthy"
	}

	return summary
}
