package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cerberus/core"
	"cerberus/storage"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
)

// =============================================================================
// IOC Request/Response Types
// =============================================================================

// CreateIOCRequest represents the request body for creating an IOC
type CreateIOCRequest struct {
	Type            core.IOCType     `json:"type" validate:"required"`
	Value           string           `json:"value" validate:"required,min=1,max=4096"`
	Status          core.IOCStatus   `json:"status,omitempty"`
	Severity        core.IOCSeverity `json:"severity,omitempty"`
	Confidence      *float64         `json:"confidence,omitempty"`
	Description     string           `json:"description,omitempty" validate:"max=2000"`
	Tags            []string         `json:"tags,omitempty" validate:"max=50,dive,max=100"`
	Source          string           `json:"source,omitempty" validate:"max=200"`
	References      []string         `json:"references,omitempty" validate:"max=20,dive,max=2048"`
	MitreTechniques []string         `json:"mitre_techniques,omitempty" validate:"max=50,dive,max=20"`
	ExpiresAt       *time.Time       `json:"expires_at,omitempty"`
}

// UpdateIOCRequest represents the request body for updating an IOC
type UpdateIOCRequest struct {
	Status          *core.IOCStatus   `json:"status,omitempty"`
	Severity        *core.IOCSeverity `json:"severity,omitempty"`
	Confidence      *float64          `json:"confidence,omitempty"`
	Description     *string           `json:"description,omitempty" validate:"omitempty,max=2000"`
	Tags            []string          `json:"tags,omitempty" validate:"max=50,dive,max=100"`
	References      []string          `json:"references,omitempty" validate:"max=20,dive,max=2048"`
	MitreTechniques []string          `json:"mitre_techniques,omitempty" validate:"max=50,dive,max=20"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
}

// BulkImportIOCRequest represents a single IOC in a bulk import
type BulkImportIOCRequest struct {
	Type            core.IOCType     `json:"type" validate:"required"`
	Value           string           `json:"value" validate:"required,min=1,max=4096"`
	Status          core.IOCStatus   `json:"status,omitempty"`
	Severity        core.IOCSeverity `json:"severity,omitempty"`
	Confidence      *float64         `json:"confidence,omitempty"`
	Description     string           `json:"description,omitempty" validate:"max=2000"`
	Tags            []string         `json:"tags,omitempty"`
	Source          string           `json:"source,omitempty"`
	References      []string         `json:"references,omitempty"`
	MitreTechniques []string         `json:"mitre_techniques,omitempty"`
	ExpiresAt       *time.Time       `json:"expires_at,omitempty"`
}

// BulkImportIOCsRequest represents the request body for bulk importing IOCs
type BulkImportIOCsRequest struct {
	IOCs []BulkImportIOCRequest `json:"iocs" validate:"required,min=1,max=1000,dive"`
}

// BulkImportIOCsResponse represents the response from bulk import
type BulkImportIOCsResponse struct {
	Created int    `json:"created"`
	Skipped int    `json:"skipped"`
	Message string `json:"message"`
}

// BulkUpdateStatusRequest represents the request for bulk status update
type BulkUpdateStatusRequest struct {
	IDs    []string       `json:"ids" validate:"required,min=1,max=1000"`
	Status core.IOCStatus `json:"status" validate:"required"`
}

// CreateHuntRequest represents the request body for creating a threat hunt
type CreateHuntRequest struct {
	IOCIDs         []string  `json:"ioc_ids" validate:"required,min=1,max=100"`
	TimeRangeStart time.Time `json:"time_range_start" validate:"required"`
	TimeRangeEnd   time.Time `json:"time_range_end" validate:"required"`
}

// LinkIOCRequest represents the request body for linking an IOC
type LinkIOCRequest struct {
	InvestigationID string `json:"investigation_id,omitempty"`
	AlertID         string `json:"alert_id,omitempty"`
}

// IOCListResponse represents a paginated list of IOCs
type IOCListResponse struct {
	IOCs       []*core.IOC `json:"iocs"`
	Total      int64       `json:"total"`
	Page       int         `json:"page"`
	Limit      int         `json:"limit"`
	TotalPages int         `json:"total_pages"`
}

// =============================================================================
// IOC CRUD Handlers
// =============================================================================

// getIOCs godoc
//
//	@Summary		Get IOCs
//	@Description	Returns a list of IOCs with pagination and optional filters
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Param			page			query	int		false	"Page number (1-based)"					minimum(1)	default(1)
//	@Param			limit			query	int		false	"Items per page (1-1000)"				minimum(1)	maximum(1000)	default(100)
//	@Param			type			query	string	false	"Filter by IOC type (comma-separated)"	example(ip,domain)
//	@Param			status			query	string	false	"Filter by status (comma-separated)"	example(active,deprecated)
//	@Param			severity		query	string	false	"Filter by severity"					example(high)
//	@Param			source			query	string	false	"Filter by source"						example(threat_intel_feed)
//	@Param			search			query	string	false	"Search in value/description"			example(192.168)
//	@Param			min_confidence	query	number	false	"Minimum confidence threshold"			example(75)
//	@Param			feed_id			query	string	false	"Filter by feed ID"						example(abc123)
//	@Param			feed_name		query	string	false	"Filter by feed name (partial match)"	example(alienvault)
//	@Param			source_type		query	string	false	"Filter by source type"					example(manual)	enums(manual,feed)
//	@Param			sort_by			query	string	false	"Sort field"							example(created_at)
//	@Param			sort_order		query	string	false	"Sort order (asc/desc)"					example(desc)
//	@Success		200				{object}	IOCListResponse
//	@Failure		400				{string}	string	"Bad request"
//	@Failure		500				{string}	string	"Internal server error"
//	@Router			/api/v1/iocs [get]
//	@Security		BearerAuth
func (a *API) getIOCs(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	// Parse query parameters
	filters := parseIOCFilters(r)

	// Get IOCs
	iocs, total, err := a.iocStorage.ListIOCs(r.Context(), filters)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve IOCs", err, a.logger)
		return
	}

	page := 1
	if filters.Offset > 0 && filters.Limit > 0 {
		page = (filters.Offset / filters.Limit) + 1
	}

	totalPages := int(total) / filters.Limit
	if int(total)%filters.Limit > 0 {
		totalPages++
	}

	response := IOCListResponse{
		IOCs:       iocs,
		Total:      total,
		Page:       page,
		Limit:      filters.Limit,
		TotalPages: totalPages,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// parseIOCFilters parses query parameters into IOCFilters
func parseIOCFilters(r *http.Request) *core.IOCFilters {
	query := r.URL.Query()

	filters := &core.IOCFilters{
		SortBy:    "created_at",
		SortOrder: "desc",
		Limit:     100,
		Offset:    0,
	}

	// Parse types
	if types := query.Get("type"); types != "" {
		for _, t := range strings.Split(types, ",") {
			filters.Types = append(filters.Types, core.IOCType(strings.TrimSpace(t)))
		}
	}

	// Parse statuses
	if statuses := query.Get("status"); statuses != "" {
		for _, s := range strings.Split(statuses, ",") {
			filters.Statuses = append(filters.Statuses, core.IOCStatus(strings.TrimSpace(s)))
		}
	}

	// Parse severities
	if severities := query.Get("severity"); severities != "" {
		for _, s := range strings.Split(severities, ",") {
			filters.Severities = append(filters.Severities, core.IOCSeverity(strings.TrimSpace(s)))
		}
	}

	// Parse tags
	if tags := query.Get("tags"); tags != "" {
		for _, t := range strings.Split(tags, ",") {
			filters.Tags = append(filters.Tags, strings.TrimSpace(t))
		}
	}

	filters.Source = query.Get("source")
	filters.Search = query.Get("search")

	// Parse feed filtering parameters
	filters.FeedID = query.Get("feed_id")
	filters.FeedName = query.Get("feed_name")
	filters.SourceType = query.Get("source_type") // "manual", "feed", or "" for all

	// Parse min confidence
	if minConf := query.Get("min_confidence"); minConf != "" {
		if conf, err := strconv.ParseFloat(minConf, 64); err == nil {
			filters.MinConfidence = conf
		}
	}

	// Parse pagination
	if page := query.Get("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			if limit := query.Get("limit"); limit != "" {
				if l, err := strconv.Atoi(limit); err == nil && l > 0 {
					filters.Limit = l
				}
			}
			filters.Offset = (p - 1) * filters.Limit
		}
	}

	if limit := query.Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 1000 {
			filters.Limit = l
		}
	}

	// Parse sort parameters
	if sortBy := query.Get("sort_by"); sortBy != "" {
		filters.SortBy = sortBy
	}
	if sortOrder := query.Get("sort_order"); sortOrder != "" {
		filters.SortOrder = sortOrder
	}

	return filters
}

// getIOC godoc
//
//	@Summary		Get IOC
//	@Description	Returns a single IOC by ID
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"IOC ID"	example(550e8400-e29b-41d4-a716-446655440000)
//	@Success		200	{object}	core.IOC
//	@Failure		404	{string}	string	"IOC not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/iocs/{id} [get]
//	@Security		BearerAuth
func (a *API) getIOC(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	ioc, err := a.iocStorage.GetIOC(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "IOC not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve IOC", err, a.logger)
		return
	}

	// Load related investigations and alerts
	invIDs, _ := a.iocStorage.GetLinkedInvestigations(r.Context(), id)
	alertIDs, _ := a.iocStorage.GetLinkedAlerts(r.Context(), id)
	ioc.InvestigationIDs = invIDs
	ioc.AlertIDs = alertIDs

	a.respondJSON(w, ioc, http.StatusOK)
}

// createIOC godoc
//
//	@Summary		Create IOC
//	@Description	Creates a new indicator of compromise
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Param			ioc	body		CreateIOCRequest	true	"IOC to create"
//	@Success		201	{object}	core.IOC
//	@Failure		400	{string}	string	"Invalid request"
//	@Failure		409	{string}	string	"IOC already exists"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/iocs [post]
//	@Security		BearerAuth
func (a *API) createIOC(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	var req CreateIOCRequest
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

	// Validate IOC type
	if !req.Type.IsValid() {
		writeError(w, http.StatusBadRequest, "Invalid IOC type", nil, a.logger)
		return
	}

	// Get user from context
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		userID = "system"
	}

	// Create IOC
	ioc, err := core.NewIOC(req.Type, req.Value, req.Source, userID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
		return
	}

	// Apply optional fields
	if req.Status != "" && req.Status.IsValid() {
		ioc.Status = req.Status
	}
	if req.Severity != "" && req.Severity.IsValid() {
		ioc.Severity = req.Severity
	}
	if req.Confidence != nil && *req.Confidence >= 0 && *req.Confidence <= 100 {
		ioc.Confidence = *req.Confidence
	}
	if req.Description != "" {
		ioc.Description = req.Description
	}
	if len(req.Tags) > 0 {
		ioc.Tags = req.Tags
	}
	if len(req.References) > 0 {
		ioc.References = req.References
	}
	if len(req.MitreTechniques) > 0 {
		ioc.MitreTechniques = req.MitreTechniques
	}
	if req.ExpiresAt != nil {
		ioc.ExpiresAt = req.ExpiresAt
	}

	// Save to storage
	if err := a.iocStorage.CreateIOC(r.Context(), ioc); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, "IOC with this type and value already exists", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to create IOC", err, a.logger)
		return
	}

	a.logger.Infow("IOC created via API",
		"ioc_id", ioc.ID,
		"type", ioc.Type,
		"created_by", userID,
	)

	a.respondJSON(w, ioc, http.StatusCreated)
}

// updateIOC godoc
//
//	@Summary		Update IOC
//	@Description	Updates an existing IOC
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string				true	"IOC ID"
//	@Param			ioc	body		UpdateIOCRequest	true	"IOC updates"
//	@Success		200	{object}	core.IOC
//	@Failure		400	{string}	string	"Invalid request"
//	@Failure		404	{string}	string	"IOC not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/iocs/{id} [put]
//	@Security		BearerAuth
func (a *API) updateIOC(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Get existing IOC
	ioc, err := a.iocStorage.GetIOC(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "IOC not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve IOC", err, a.logger)
		return
	}

	// Parse update request
	var req UpdateIOCRequest
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
	if req.Status != nil && req.Status.IsValid() {
		ioc.Status = *req.Status
	}
	if req.Severity != nil && req.Severity.IsValid() {
		ioc.Severity = *req.Severity
	}
	if req.Confidence != nil && *req.Confidence >= 0 && *req.Confidence <= 100 {
		ioc.Confidence = *req.Confidence
	}
	if req.Description != nil {
		ioc.Description = *req.Description
	}
	if req.Tags != nil {
		ioc.Tags = req.Tags
	}
	if req.References != nil {
		ioc.References = req.References
	}
	if req.MitreTechniques != nil {
		ioc.MitreTechniques = req.MitreTechniques
	}
	if req.ExpiresAt != nil {
		ioc.ExpiresAt = req.ExpiresAt
	}

	// Update IOC
	if err := a.iocStorage.UpdateIOC(r.Context(), ioc); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update IOC", err, a.logger)
		return
	}

	a.respondJSON(w, ioc, http.StatusOK)
}

// deleteIOC godoc
//
//	@Summary		Delete IOC
//	@Description	Deletes an IOC
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"IOC ID"
//	@Success		204	{string}	string	"No content"
//	@Failure		404	{string}	string	"IOC not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/iocs/{id} [delete]
//	@Security		BearerAuth
func (a *API) deleteIOC(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.iocStorage.DeleteIOC(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "IOC not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete IOC", err, a.logger)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Bulk Operations
// =============================================================================

// bulkImportIOCs godoc
//
//	@Summary		Bulk import IOCs
//	@Description	Import multiple IOCs in a single request (max 1000)
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Param			iocs	body		BulkImportIOCsRequest	true	"IOCs to import"
//	@Success		200		{object}	BulkImportIOCsResponse
//	@Failure		400		{string}	string	"Invalid request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/iocs/bulk [post]
//	@Security		BearerAuth
func (a *API) bulkImportIOCs(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024) // 10MB max

	var req BulkImportIOCsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "Empty request body", err, a.logger)
			return
		}
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate request
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, "Validation failed", err, a.logger)
		return
	}

	// Enforce maximum batch size
	if len(req.IOCs) > 1000 {
		writeError(w, http.StatusBadRequest, "Maximum 1000 IOCs per batch", nil, a.logger)
		return
	}

	// Get user from context
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		userID = "system"
	}

	// Convert to core.IOC slice
	iocs := make([]*core.IOC, 0, len(req.IOCs))
	for _, iocReq := range req.IOCs {
		ioc, err := core.NewIOC(iocReq.Type, iocReq.Value, iocReq.Source, userID)
		if err != nil {
			continue // Skip invalid IOCs
		}

		// Apply optional fields
		if iocReq.Status != "" && iocReq.Status.IsValid() {
			ioc.Status = iocReq.Status
		}
		if iocReq.Severity != "" && iocReq.Severity.IsValid() {
			ioc.Severity = iocReq.Severity
		}
		if iocReq.Confidence != nil && *iocReq.Confidence >= 0 && *iocReq.Confidence <= 100 {
			ioc.Confidence = *iocReq.Confidence
		}
		if iocReq.Description != "" {
			ioc.Description = iocReq.Description
		}
		if len(iocReq.Tags) > 0 {
			ioc.Tags = iocReq.Tags
		}
		if len(iocReq.References) > 0 {
			ioc.References = iocReq.References
		}
		if len(iocReq.MitreTechniques) > 0 {
			ioc.MitreTechniques = iocReq.MitreTechniques
		}
		if iocReq.ExpiresAt != nil {
			ioc.ExpiresAt = iocReq.ExpiresAt
		}

		iocs = append(iocs, ioc)
	}

	// Bulk create
	created, skipped, err := a.iocStorage.BulkCreateIOCs(r.Context(), iocs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Bulk import failed", err, a.logger)
		return
	}

	response := BulkImportIOCsResponse{
		Created: created,
		Skipped: skipped,
		Message: "Bulk import completed",
	}

	a.logger.Infow("Bulk IOC import completed",
		"created", created,
		"skipped", skipped,
		"imported_by", userID,
	)

	a.respondJSON(w, response, http.StatusOK)
}

// bulkUpdateIOCStatus godoc
//
//	@Summary		Bulk update IOC status
//	@Description	Update status for multiple IOCs (max 1000)
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Param			request	body		BulkUpdateStatusRequest	true	"Status update request"
//	@Success		200		{object}	map[string]string
//	@Failure		400		{string}	string	"Invalid request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/iocs/bulk/status [put]
//	@Security		BearerAuth
func (a *API) bulkUpdateIOCStatus(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	var req BulkUpdateStatusRequest
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

	// Validate status
	if !req.Status.IsValid() {
		writeError(w, http.StatusBadRequest, "Invalid status value", nil, a.logger)
		return
	}

	// Enforce maximum batch size
	if len(req.IDs) > 1000 {
		writeError(w, http.StatusBadRequest, "Maximum 1000 IOC IDs per request", nil, a.logger)
		return
	}

	// Bulk update
	if err := a.iocStorage.BulkUpdateStatus(r.Context(), req.IDs, req.Status); err != nil {
		writeError(w, http.StatusInternalServerError, "Bulk status update failed", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]string{
		"message": "Status updated successfully",
		"count":   strconv.Itoa(len(req.IDs)),
	}, http.StatusOK)
}

// =============================================================================
// IOC Statistics
// =============================================================================

// getIOCStats godoc
//
//	@Summary		Get IOC statistics
//	@Description	Returns aggregated IOC metrics
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	core.IOCStatistics
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/iocs/stats [get]
//	@Security		BearerAuth
func (a *API) getIOCStats(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	stats, err := a.iocStorage.GetIOCStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve IOC statistics", err, a.logger)
		return
	}

	a.respondJSON(w, stats, http.StatusOK)
}

// =============================================================================
// IOC Relationship Handlers
// =============================================================================

// linkIOCToInvestigation godoc
//
//	@Summary		Link IOC to investigation
//	@Description	Links an IOC to an investigation
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string	true	"IOC ID"
//	@Param			investigationId	path		string	true	"Investigation ID"
//	@Success		200				{object}	map[string]string
//	@Failure		400				{string}	string	"Invalid request"
//	@Failure		404				{string}	string	"IOC not found"
//	@Failure		500				{string}	string	"Internal server error"
//	@Router			/api/v1/iocs/{id}/investigations/{investigationId} [post]
//	@Security		BearerAuth
func (a *API) linkIOCToInvestigation(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	iocID := vars["id"]
	investigationID := vars["investigationId"]

	// Verify IOC exists
	if _, err := a.iocStorage.GetIOC(r.Context(), iocID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "IOC not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to verify IOC", err, a.logger)
		return
	}

	userID := getUserIDFromContext(r.Context())
	if err := a.iocStorage.LinkToInvestigation(r.Context(), iocID, investigationID, userID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to link IOC to investigation", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]string{"message": "IOC linked to investigation"}, http.StatusOK)
}

// unlinkIOCFromInvestigation godoc
//
//	@Summary		Unlink IOC from investigation
//	@Description	Removes link between IOC and investigation
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string	true	"IOC ID"
//	@Param			investigationId	path		string	true	"Investigation ID"
//	@Success		204				{string}	string	"No content"
//	@Failure		404				{string}	string	"IOC not found"
//	@Failure		500				{string}	string	"Internal server error"
//	@Router			/api/v1/iocs/{id}/investigations/{investigationId} [delete]
//	@Security		BearerAuth
func (a *API) unlinkIOCFromInvestigation(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	iocID := vars["id"]
	investigationID := vars["investigationId"]

	if err := a.iocStorage.UnlinkFromInvestigation(r.Context(), iocID, investigationID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to unlink IOC from investigation", err, a.logger)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// getIOCMatches godoc
//
//	@Summary		Get IOC matches
//	@Description	Returns detection matches for an IOC
//	@Tags			iocs
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string	true	"IOC ID"
//	@Param			limit	query		int		false	"Items per page"	default(100)
//	@Param			offset	query		int		false	"Offset"			default(0)
//	@Success		200		{object}	PaginationResponse
//	@Failure		404		{string}	string	"IOC not found"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/iocs/{id}/matches [get]
//	@Security		BearerAuth
func (a *API) getIOCMatches(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	iocID := vars["id"]

	// Verify IOC exists
	if _, err := a.iocStorage.GetIOC(r.Context(), iocID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "IOC not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to verify IOC", err, a.logger)
		return
	}

	// Parse pagination
	limit := 100
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if lv, err := strconv.Atoi(l); err == nil && lv > 0 && lv <= 1000 {
			limit = lv
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if ov, err := strconv.Atoi(o); err == nil && ov >= 0 {
			offset = ov
		}
	}

	matches, total, err := a.iocStorage.GetMatchesByIOC(r.Context(), iocID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve matches", err, a.logger)
		return
	}

	page := 1
	if offset > 0 && limit > 0 {
		page = (offset / limit) + 1
	}

	response := NewPaginationResponse(matches, total, page, limit)
	a.respondJSON(w, response, http.StatusOK)
}

// =============================================================================
// Threat Hunt Handlers
// =============================================================================

// createHunt godoc
//
//	@Summary		Create threat hunt
//	@Description	Creates a new threat hunt job to search for IOCs in historical logs
//	@Tags			hunts
//	@Accept			json
//	@Produce		json
//	@Param			hunt	body		CreateHuntRequest	true	"Hunt configuration"
//	@Success		201		{object}	core.IOCHunt
//	@Failure		400		{string}	string	"Invalid request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/hunts [post]
//	@Security		BearerAuth
func (a *API) createHunt(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	var req CreateHuntRequest
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

	// Create hunt
	hunt, err := core.NewIOCHunt(req.IOCIDs, req.TimeRangeStart, req.TimeRangeEnd, userID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
		return
	}

	// Verify all IOCs exist
	for _, iocID := range req.IOCIDs {
		if _, err := a.iocStorage.GetIOC(r.Context(), iocID); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeError(w, http.StatusBadRequest, "IOC not found: "+iocID, err, a.logger)
				return
			}
		}
	}

	// Save hunt
	if err := a.iocStorage.CreateHunt(r.Context(), hunt); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create hunt", err, a.logger)
		return
	}

	a.logger.Infow("Threat hunt created",
		"hunt_id", hunt.ID,
		"ioc_count", len(hunt.IOCIDs),
		"created_by", userID,
	)

	a.respondJSON(w, hunt, http.StatusCreated)
}

// getHunts godoc
//
//	@Summary		Get hunts
//	@Description	Returns a list of threat hunt jobs
//	@Tags			hunts
//	@Accept			json
//	@Produce		json
//	@Param			limit	query		int	false	"Items per page"	default(20)
//	@Param			offset	query		int	false	"Offset"			default(0)
//	@Success		200		{object}	PaginationResponse
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/hunts [get]
//	@Security		BearerAuth
func (a *API) getHunts(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	// Parse pagination
	limit := 20
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if lv, err := strconv.Atoi(l); err == nil && lv > 0 && lv <= 100 {
			limit = lv
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if ov, err := strconv.Atoi(o); err == nil && ov >= 0 {
			offset = ov
		}
	}

	hunts, total, err := a.iocStorage.ListHunts(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve hunts", err, a.logger)
		return
	}

	page := 1
	if offset > 0 && limit > 0 {
		page = (offset / limit) + 1
	}

	response := NewPaginationResponse(hunts, total, page, limit)
	a.respondJSON(w, response, http.StatusOK)
}

// getHunt godoc
//
//	@Summary		Get hunt
//	@Description	Returns a single threat hunt by ID
//	@Tags			hunts
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Hunt ID"
//	@Success		200	{object}	core.IOCHunt
//	@Failure		404	{string}	string	"Hunt not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/hunts/{id} [get]
//	@Security		BearerAuth
func (a *API) getHunt(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	hunt, err := a.iocStorage.GetHunt(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Hunt not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve hunt", err, a.logger)
		return
	}

	a.respondJSON(w, hunt, http.StatusOK)
}

// getHuntMatches godoc
//
//	@Summary		Get hunt matches
//	@Description	Returns detection matches from a threat hunt
//	@Tags			hunts
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string	true	"Hunt ID"
//	@Param			limit	query		int		false	"Items per page"	default(100)
//	@Param			offset	query		int		false	"Offset"			default(0)
//	@Success		200		{object}	PaginationResponse
//	@Failure		404		{string}	string	"Hunt not found"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/hunts/{id}/matches [get]
//	@Security		BearerAuth
func (a *API) getHuntMatches(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	huntID := vars["id"]

	// Verify hunt exists
	if _, err := a.iocStorage.GetHunt(r.Context(), huntID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Hunt not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to verify hunt", err, a.logger)
		return
	}

	// Parse pagination
	limit := 100
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if lv, err := strconv.Atoi(l); err == nil && lv > 0 && lv <= 1000 {
			limit = lv
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if ov, err := strconv.Atoi(o); err == nil && ov >= 0 {
			offset = ov
		}
	}

	matches, total, err := a.iocStorage.GetMatchesByHunt(r.Context(), huntID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve matches", err, a.logger)
		return
	}

	page := 1
	if offset > 0 && limit > 0 {
		page = (offset / limit) + 1
	}

	response := NewPaginationResponse(matches, total, page, limit)
	a.respondJSON(w, response, http.StatusOK)
}

// cancelHunt godoc
//
//	@Summary		Cancel hunt
//	@Description	Cancels a running threat hunt
//	@Tags			hunts
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Hunt ID"
//	@Success		200	{object}	core.IOCHunt
//	@Failure		400	{string}	string	"Hunt cannot be cancelled"
//	@Failure		404	{string}	string	"Hunt not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/hunts/{id}/cancel [post]
//	@Security		BearerAuth
func (a *API) cancelHunt(w http.ResponseWriter, r *http.Request) {
	if a.iocStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "IOC storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Get hunt
	hunt, err := a.iocStorage.GetHunt(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Hunt not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve hunt", err, a.logger)
		return
	}

	// Check if hunt can be cancelled
	if hunt.Status.IsTerminal() {
		writeError(w, http.StatusBadRequest, "Hunt is already in terminal state: "+string(hunt.Status), nil, a.logger)
		return
	}

	// Update status
	if err := a.iocStorage.UpdateHuntStatus(r.Context(), id, core.HuntStatusCancelled); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to cancel hunt", err, a.logger)
		return
	}

	// Get updated hunt
	hunt, _ = a.iocStorage.GetHunt(r.Context(), id)
	a.respondJSON(w, hunt, http.StatusOK)
}
