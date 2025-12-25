package api

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"cerberus/ingest"
	"cerberus/storage"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// maxListenerConfigSize is the maximum size in bytes for listener configuration JSON
const maxListenerConfigSize = 1 * 1024 * 1024 // 1MB

// templateIDPattern validates template IDs (alphanumeric + hyphens only)
var templateIDPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// listDynamicListeners godoc
//
//	@Summary		List all dynamic listeners
//	@Description	Returns all configured dynamic listeners with pagination and runtime statistics
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			page	query		int	false	"Page number (default: 1)"	minimum(1)
//	@Param			limit	query		int	false	"Items per page (default: 50, max: 1000)"	minimum(1)	maximum(1000)
//	@Success		200		{object}	PaginationResponse{items=[]storage.DynamicListener}
//	@Failure		503		{string}	string	"Listener manager not available"
//	@Failure		500		{string}	string	"Failed to retrieve listeners"
//	@Router			/api/v1/listeners [get]
//	@Security		ApiKeyAuth
func (a *API) listDynamicListeners(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Parse and validate pagination parameters (MUST BE FIRST - validate input before checking service state)
	params := ParsePaginationParams(r, 50, 1000)

	// STEP 2: Validate service availability (after all input validation)
	if a.listenerManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Listener manager not available", nil, a.logger)
		return
	}

	// STEP 3: Retrieve all listeners (with runtime stats)
	listeners, err := a.listenerManager.ListListeners()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve listeners", err, a.logger)
		return
	}

	// STEP 4: Convert to pagination response
	// Note: ListListeners returns all listeners; manual pagination applied
	total := int64(len(listeners))
	offset := params.CalculateOffset()

	// Apply pagination bounds checking
	var paginatedListeners []*storage.DynamicListener
	if offset >= len(listeners) {
		paginatedListeners = []*storage.DynamicListener{}
	} else {
		end := offset + params.Limit
		if end > len(listeners) {
			end = len(listeners)
		}
		paginatedListeners = listeners[offset:end]
	}

	// STEP 5: Return paginated response
	response := NewPaginationResponse(paginatedListeners, total, params.Page, params.Limit)
	a.respondJSON(w, response, http.StatusOK)
}

// getDynamicListener godoc
//
//	@Summary		Get a dynamic listener
//	@Description	Returns a single dynamic listener by ID with runtime statistics
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Listener ID (UUID)"
//	@Success		200	{object}	storage.DynamicListener
//	@Failure		400	{string}	string	"Invalid listener ID format"
//	@Failure		404	{string}	string	"Listener not found"
//	@Failure		503	{string}	string	"Listener manager not available"
//	@Failure		500	{string}	string	"Failed to retrieve listener"
//	@Router			/api/v1/listeners/{id} [get]
//	@Security		ApiKeyAuth
func (a *API) getDynamicListener(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Extract and validate ID (MUST BE FIRST - validate input before checking service state)
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY: Validate UUID format to prevent injection attacks
	if err := validateUUID(id); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid listener ID format", err, a.logger)
		return
	}

	// STEP 2: Validate service availability
	if a.listenerManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Listener manager not available", nil, a.logger)
		return
	}

	// STEP 3: Retrieve listener
	listener, err := a.listenerManager.GetListener(id)
	if err != nil {
		// Use sentinel errors for proper HTTP status code mapping
		if errors.Is(err, ingest.ErrListenerNotFound) {
			writeError(w, http.StatusNotFound, "Listener not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve listener", err, a.logger)
		}
		return
	}

	// STEP 4: Return listener
	a.respondJSON(w, listener, http.StatusOK)
}

// createDynamicListener godoc
//
//	@Summary		Create a dynamic listener
//	@Description	Creates a new dynamic listener with specified configuration
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			listener	body		storage.DynamicListener	true	"Listener configuration"
//	@Success		201			{object}	storage.DynamicListener
//	@Failure		400			{string}	string	"Invalid JSON or validation error"
//	@Failure		503			{string}	string	"Listener manager not available"
//	@Failure		500			{string}	string	"Failed to create listener"
//	@Router			/api/v1/listeners [post]
//	@Security		ApiKeyAuth
func (a *API) createDynamicListener(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Parse and validate request body (MUST BE FIRST - validate input before checking service state)
	var config storage.DynamicListener
	// SECURITY: Use size-limited decoding to prevent DoS attacks
	if err := a.decodeJSONBodyWithLimit(w, r, &config, maxListenerConfigSize); err != nil {
		// Error already written by decodeJSONBodyWithLimit
		return
	}

	// STEP 2: Validate service availability
	if a.listenerManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Listener manager not available", nil, a.logger)
		return
	}

	// STEP 3: Set audit fields
	username := getUsernameFromContext(r.Context())
	config.CreatedBy = username
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	// STEP 4: Create listener (validation happens in ListenerManager)
	listener, err := a.listenerManager.CreateListener(&config)
	if err != nil {
		// SECURITY: Don't expose internal implementation details
		writeError(w, http.StatusBadRequest, "Failed to create listener", err, a.logger)
		return
	}

	// STEP 5: Return created listener
	a.logger.Infow("Dynamic listener created",
		"listener_id", listener.ID,
		"listener_name", listener.Name,
		"created_by", username,
		"type", listener.Type,
		"protocol", listener.Protocol,
		"port", listener.Port)

	a.respondJSON(w, listener, http.StatusCreated)
}

// updateDynamicListener godoc
//
//	@Summary		Update a dynamic listener
//	@Description	Updates an existing dynamic listener configuration (must be stopped first)
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string					true	"Listener ID (UUID)"
//	@Param			listener	body		storage.DynamicListener	true	"Updated listener configuration"
//	@Success		200			{object}	storage.DynamicListener
//	@Failure		400			{string}	string	"Invalid JSON, validation error, or listener is running"
//	@Failure		404			{string}	string	"Listener not found"
//	@Failure		503			{string}	string	"Listener manager not available"
//	@Failure		500			{string}	string	"Failed to update listener"
//	@Router			/api/v1/listeners/{id} [put]
//	@Security		ApiKeyAuth
func (a *API) updateDynamicListener(w http.ResponseWriter, r *http.Request) {
	// BLOCKING-3 FIX: Validate UUID FIRST (cheap) before parsing JSON body (expensive)
	// This prevents DoS attacks where attackers send 1MB of JSON to invalid UUIDs

	// STEP 1: Extract and validate ID (MUST BE FIRST - cheap validation)
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY: Validate UUID format to prevent injection attacks
	if err := validateUUID(id); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid listener ID format", err, a.logger)
		return
	}

	// STEP 2: Parse and validate request body (expensive - up to 1MB)
	var updates storage.DynamicListener
	// SECURITY: Use size-limited decoding to prevent DoS attacks
	if err := a.decodeJSONBodyWithLimit(w, r, &updates, maxListenerConfigSize); err != nil {
		// Error already written by decodeJSONBodyWithLimit
		return
	}

	// STEP 3: Validate service availability
	if a.listenerManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Listener manager not available", nil, a.logger)
		return
	}

	// STEP 4: Set audit fields
	updates.UpdatedAt = time.Now()
	// Note: CreatedBy and CreatedAt are preserved by UpdateListener

	// STEP 5: Update listener (validation and running check happens in ListenerManager)
	if err := a.listenerManager.UpdateListener(id, &updates); err != nil {
		// Use sentinel errors for proper HTTP status code mapping
		if errors.Is(err, ingest.ErrListenerNotFound) {
			writeError(w, http.StatusNotFound, "Listener not found", err, a.logger)
		} else if errors.Is(err, ingest.ErrListenerRunning) {
			writeError(w, http.StatusBadRequest, "Cannot update running listener", err, a.logger)
		} else {
			writeError(w, http.StatusBadRequest, "Failed to update listener", err, a.logger)
		}
		return
	}

	// STEP 6: Retrieve updated listener to return full object
	listener, err := a.listenerManager.GetListener(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Listener updated but failed to retrieve", err, a.logger)
		return
	}

	// STEP 7: Return updated listener
	username := getUsernameFromContext(r.Context())
	a.logger.Infow("Dynamic listener updated",
		"listener_id", id,
		"listener_name", listener.Name,
		"updated_by", username)

	a.respondJSON(w, listener, http.StatusOK)
}

// deleteDynamicListener godoc
//
//	@Summary		Delete a dynamic listener
//	@Description	Deletes a dynamic listener by ID (must be stopped first)
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Listener ID (UUID)"
//	@Success		200	{object}	map[string]string{status=string}
//	@Failure		400	{string}	string	"Invalid ID format or listener is running"
//	@Failure		404	{string}	string	"Listener not found"
//	@Failure		503	{string}	string	"Listener manager not available"
//	@Failure		500	{string}	string	"Failed to delete listener"
//	@Router			/api/v1/listeners/{id} [delete]
//	@Security		ApiKeyAuth
func (a *API) deleteDynamicListener(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Extract and validate ID (MUST BE FIRST - validate input before checking service state)
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY: Validate UUID format to prevent injection attacks
	if err := validateUUID(id); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid listener ID format", err, a.logger)
		return
	}

	// STEP 2: Validate service availability
	if a.listenerManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Listener manager not available", nil, a.logger)
		return
	}

	// STEP 3: Get listener for audit logging before deletion
	listener, err := a.listenerManager.GetListener(id)
	if err != nil {
		if errors.Is(err, ingest.ErrListenerNotFound) {
			writeError(w, http.StatusNotFound, "Listener not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve listener", err, a.logger)
		}
		return
	}

	// STEP 4: Delete listener (running check happens in ListenerManager)
	if err := a.listenerManager.DeleteListener(id); err != nil {
		// Use sentinel errors for proper HTTP status code mapping
		if errors.Is(err, ingest.ErrListenerRunning) {
			writeError(w, http.StatusBadRequest, "Cannot delete running listener", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to delete listener", err, a.logger)
		}
		return
	}

	// STEP 5: Return success response
	username := getUsernameFromContext(r.Context())
	a.logger.Infow("Dynamic listener deleted",
		"listener_id", id,
		"listener_name", listener.Name,
		"listener_type", listener.Type,
		"deleted_by", username)

	a.respondJSON(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

// startDynamicListener godoc
//
//	@Summary		Start a dynamic listener
//	@Description	Starts a stopped dynamic listener
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Listener ID (UUID)"
//	@Success		200	{object}	map[string]string{status=string,message=string}
//	@Failure		400	{string}	string	"Invalid ID format or listener already running"
//	@Failure		404	{string}	string	"Listener not found"
//	@Failure		503	{string}	string	"Listener manager not available"
//	@Failure		500	{string}	string	"Failed to start listener"
//	@Router			/api/v1/listeners/{id}/start [post]
//	@Security		ApiKeyAuth
func (a *API) startDynamicListener(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Extract and validate ID (MUST BE FIRST - validate input before checking service state)
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY: Validate UUID format to prevent injection attacks
	if err := validateUUID(id); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid listener ID format", err, a.logger)
		return
	}

	// STEP 2: Validate service availability
	if a.listenerManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Listener manager not available", nil, a.logger)
		return
	}

	// STEP 3: Get listener for audit logging
	listener, err := a.listenerManager.GetListener(id)
	if err != nil {
		if errors.Is(err, ingest.ErrListenerNotFound) {
			writeError(w, http.StatusNotFound, "Listener not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve listener", err, a.logger)
		}
		return
	}

	// STEP 4: Start listener
	if err := a.listenerManager.StartListener(id); err != nil {
		// Use sentinel errors for proper HTTP status code mapping
		if errors.Is(err, ingest.ErrListenerAlreadyRunning) {
			writeError(w, http.StatusBadRequest, "Listener is already running", err, a.logger)
		} else if errors.Is(err, ingest.ErrListenerNotFound) {
			writeError(w, http.StatusNotFound, "Listener not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to start listener", err, a.logger)
		}
		return
	}

	// STEP 5: Return success response with comprehensive audit logging
	username := getUsernameFromContext(r.Context())
	a.logger.Infow("Dynamic listener started",
		"listener_id", id,
		"listener_name", listener.Name,
		"listener_type", listener.Type,
		"listener_port", listener.Port,
		"started_by", username)

	a.respondJSON(w, map[string]string{
		"status":  "started",
		"message": "Listener started successfully",
	}, http.StatusOK)
}

// stopDynamicListener godoc
//
//	@Summary		Stop a dynamic listener
//	@Description	Stops a running dynamic listener
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Listener ID (UUID)"
//	@Success		200	{object}	map[string]string{status=string,message=string}
//	@Failure		400	{string}	string	"Invalid ID format or listener not running"
//	@Failure		404	{string}	string	"Listener not found"
//	@Failure		503	{string}	string	"Listener manager not available"
//	@Failure		500	{string}	string	"Failed to stop listener"
//	@Router			/api/v1/listeners/{id}/stop [post]
//	@Security		ApiKeyAuth
func (a *API) stopDynamicListener(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Extract and validate ID (MUST BE FIRST - validate input before checking service state)
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY: Validate UUID format to prevent injection attacks
	if err := validateUUID(id); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid listener ID format", err, a.logger)
		return
	}

	// STEP 2: Validate service availability
	if a.listenerManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Listener manager not available", nil, a.logger)
		return
	}

	// STEP 3: Get listener for audit logging
	listener, err := a.listenerManager.GetListener(id)
	if err != nil {
		if errors.Is(err, ingest.ErrListenerNotFound) {
			writeError(w, http.StatusNotFound, "Listener not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve listener", err, a.logger)
		}
		return
	}

	// STEP 4: Stop listener
	if err := a.listenerManager.StopListener(id); err != nil {
		// Use sentinel errors for proper HTTP status code mapping
		if errors.Is(err, ingest.ErrListenerNotRunning) {
			writeError(w, http.StatusBadRequest, "Listener is not running", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to stop listener", err, a.logger)
		}
		return
	}

	// STEP 5: Return success response with comprehensive audit logging
	username := getUsernameFromContext(r.Context())
	a.logger.Infow("Dynamic listener stopped",
		"listener_id", id,
		"listener_name", listener.Name,
		"listener_type", listener.Type,
		"listener_port", listener.Port,
		"stopped_by", username)

	a.respondJSON(w, map[string]string{
		"status":  "stopped",
		"message": "Listener stopped successfully",
	}, http.StatusOK)
}

// restartDynamicListener godoc
//
//	@Summary		Restart a dynamic listener
//	@Description	Restarts a running dynamic listener (stop then start)
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Listener ID (UUID)"
//	@Success		200	{object}	map[string]string{status=string,message=string}
//	@Failure		400	{string}	string	"Invalid ID format or listener not running"
//	@Failure		404	{string}	string	"Listener not found"
//	@Failure		503	{string}	string	"Listener manager not available"
//	@Failure		500	{string}	string	"Failed to restart listener"
//	@Router			/api/v1/listeners/{id}/restart [post]
//	@Security		ApiKeyAuth
func (a *API) restartDynamicListener(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Extract and validate ID (MUST BE FIRST - validate input before checking service state)
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY: Validate UUID format to prevent injection attacks
	if err := validateUUID(id); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid listener ID format", err, a.logger)
		return
	}

	// STEP 2: Validate service availability
	if a.listenerManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Listener manager not available", nil, a.logger)
		return
	}

	// STEP 3: Get listener for audit logging
	listener, err := a.listenerManager.GetListener(id)
	if err != nil {
		if errors.Is(err, ingest.ErrListenerNotFound) {
			writeError(w, http.StatusNotFound, "Listener not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve listener", err, a.logger)
		}
		return
	}

	// STEP 4: Stop listener
	if err := a.listenerManager.StopListener(id); err != nil {
		// Use sentinel errors - if listener is not running, that's acceptable for restart
		if !errors.Is(err, ingest.ErrListenerNotRunning) {
			writeError(w, http.StatusInternalServerError, "Failed to stop listener during restart", err, a.logger)
			return
		}
		// Log but continue if listener was already stopped
		a.logger.Infow("Listener was already stopped, proceeding with start", "listener_id", id)
	}

	// STEP 5: Start listener
	if err := a.listenerManager.StartListener(id); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to start listener during restart", err, a.logger)
		return
	}

	// STEP 6: Return success response with comprehensive audit logging
	username := getUsernameFromContext(r.Context())
	a.logger.Infow("Dynamic listener restarted",
		"listener_id", id,
		"listener_name", listener.Name,
		"listener_type", listener.Type,
		"listener_port", listener.Port,
		"restarted_by", username)

	a.respondJSON(w, map[string]string{
		"status":  "restarted",
		"message": "Listener restarted successfully",
	}, http.StatusOK)
}

// getDynamicListenerStats godoc
//
//	@Summary		Get listener statistics
//	@Description	Returns real-time statistics for a running dynamic listener
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Listener ID (UUID)"
//	@Success		200	{object}	storage.ListenerStats
//	@Failure		400	{string}	string	"Invalid listener ID format or listener not running"
//	@Failure		404	{string}	string	"Listener not found"
//	@Failure		503	{string}	string	"Listener manager not available"
//	@Failure		500	{string}	string	"Failed to retrieve statistics"
//	@Router			/api/v1/listeners/{id}/stats [get]
//	@Security		ApiKeyAuth
func (a *API) getDynamicListenerStats(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Extract and validate ID (MUST BE FIRST - validate input before checking service state)
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY: Validate UUID format to prevent injection attacks
	if err := validateUUID(id); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid listener ID format", err, a.logger)
		return
	}

	// STEP 2: Validate service availability
	if a.listenerManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Listener manager not available", nil, a.logger)
		return
	}

	// STEP 3: Get statistics
	stats, err := a.listenerManager.GetStatistics(id)
	if err != nil {
		// Use sentinel errors for proper HTTP status code mapping
		if errors.Is(err, ingest.ErrListenerNotRunning) {
			writeError(w, http.StatusBadRequest, "Listener is not running", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve statistics", err, a.logger)
		}
		return
	}

	// STEP 4: Return statistics
	a.respondJSON(w, stats, http.StatusOK)
}

// getListenerTemplates godoc
//
//	@Summary		List listener templates
//	@Description	Returns all available built-in listener templates
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}	ListenerTemplate
//	@Router			/api/v1/listener-templates [get]
//	@Security		ApiKeyAuth
func (a *API) getListenerTemplates(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Get all built-in templates
	templates := GetBuiltInTemplates()

	// STEP 2: Return templates
	a.respondJSON(w, templates, http.StatusOK)
}

// getListenerTemplate godoc
//
//	@Summary		Get a listener template
//	@Description	Returns a single listener template by ID
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Template ID"
//	@Success		200	{object}	ListenerTemplate
//	@Failure		404	{string}	string	"Template not found"
//	@Router			/api/v1/listener-templates/{id} [get]
//	@Security		ApiKeyAuth
func (a *API) getListenerTemplate(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Extract template ID
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY: Validate template ID format (alphanumeric + hyphens only)
	// Note: Empty ID check removed - router returns 404 for empty path segments
	if len(id) > 50 || !templateIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "Invalid template ID format", nil, a.logger)
		return
	}

	// STEP 2: Get template by ID
	template := GetTemplateByID(id)
	if template == nil {
		writeError(w, http.StatusNotFound, "Template not found", nil, a.logger)
		return
	}

	// STEP 3: Return template
	a.respondJSON(w, template, http.StatusOK)
}

// createListenerFromTemplate godoc
//
//	@Summary		Create listener from template
//	@Description	Creates a new dynamic listener from a built-in template with optional overrides
//	@Tags			listeners
//	@Accept			json
//	@Produce		json
//	@Param			templateId	path		string					true	"Template ID"
//	@Param			overrides	body		storage.DynamicListener	false	"Optional configuration overrides"
//	@Success		201			{object}	storage.DynamicListener
//	@Failure		400			{string}	string	"Invalid JSON or validation error"
//	@Failure		404			{string}	string	"Template not found"
//	@Failure		503			{string}	string	"Listener manager not available"
//	@Failure		500			{string}	string	"Failed to create listener"
//	@Router			/api/v1/listeners/from-template/{templateId} [post]
//	@Security		ApiKeyAuth
func (a *API) createListenerFromTemplate(w http.ResponseWriter, r *http.Request) {
	// STEP 1: Extract and validate template ID (MUST BE FIRST - validate input before checking service state)
	vars := mux.Vars(r)
	templateID := vars["templateId"]

	// SECURITY: Validate template ID format (alphanumeric + hyphens only)
	// Note: Empty ID check removed - router returns 404 for empty path segments
	if len(templateID) > 50 || !templateIDPattern.MatchString(templateID) {
		writeError(w, http.StatusBadRequest, "Invalid template ID format", nil, a.logger)
		return
	}

	// STEP 2: Get template (validate template exists - no service dependency)
	template := GetTemplateByID(templateID)
	if template == nil {
		writeError(w, http.StatusNotFound, "Template not found", nil, a.logger)
		return
	}

	// STEP 3: Validate service availability (after all input validation)
	if a.listenerManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Listener manager not available", nil, a.logger)
		return
	}

	// STEP 4: Deep copy template config (prevent race condition)
	// We must copy the struct and its slices to avoid concurrent modification
	config := storage.DynamicListener{
		Name:         template.Config.Name,
		Description:  template.Config.Description,
		Type:         template.Config.Type,
		Protocol:     template.Config.Protocol,
		Host:         template.Config.Host,
		Port:         template.Config.Port,
		TLS:          template.Config.TLS,
		CertFile:     template.Config.CertFile,
		KeyFile:      template.Config.KeyFile,
		Source:       template.Config.Source,
		FieldMapping: template.Config.FieldMapping,
	}
	// Deep copy tags slice
	if len(template.Config.Tags) > 0 {
		config.Tags = make([]string, len(template.Config.Tags))
		copy(config.Tags, template.Config.Tags)
	}

	// STEP 5: Parse optional overrides from request body
	var overrides storage.DynamicListener
	if r.ContentLength > 0 {
		// SECURITY: Use size-limited decoding to prevent DoS attacks
		if err := a.decodeJSONBodyWithLimit(w, r, &overrides, maxListenerConfigSize); err != nil {
			// Error already written by decodeJSONBodyWithLimit
			return
		}

		// Apply overrides (only non-zero values)
		if overrides.Name != "" {
			config.Name = overrides.Name
		}
		if overrides.Description != "" {
			config.Description = overrides.Description
		}
		if overrides.Host != "" {
			config.Host = overrides.Host
		}
		if overrides.Port != 0 {
			// Validate port range
			if overrides.Port < 1 || overrides.Port > 65535 {
				writeError(w, http.StatusBadRequest, "Port must be between 1 and 65535", nil, a.logger)
				return
			}
			config.Port = overrides.Port
		}
		if overrides.Source != "" {
			config.Source = overrides.Source
		}
		if overrides.FieldMapping != "" {
			config.FieldMapping = overrides.FieldMapping
		}
		if len(overrides.Tags) > 0 {
			config.Tags = make([]string, len(overrides.Tags))
			copy(config.Tags, overrides.Tags)
		}
		// TLS overrides
		if overrides.TLS {
			config.TLS = overrides.TLS
			if overrides.CertFile != "" {
				config.CertFile = overrides.CertFile
			}
			if overrides.KeyFile != "" {
				config.KeyFile = overrides.KeyFile
			}
		}
	}

	// STEP 6: Generate new ID
	config.ID = uuid.New().String()

	// STEP 7: Set audit fields
	username := getUsernameFromContext(r.Context())
	config.CreatedBy = username
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	// STEP 8: Create listener
	listener, err := a.listenerManager.CreateListener(&config)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Failed to create listener from template", err, a.logger)
		return
	}

	// STEP 9: Return created listener
	a.logger.Infow("Dynamic listener created from template",
		"listener_id", listener.ID,
		"listener_name", listener.Name,
		"template_id", templateID,
		"created_by", username)

	a.respondJSON(w, listener, http.StatusCreated)
}
