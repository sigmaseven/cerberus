package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cerberus/soar"
	"cerberus/storage"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// =============================================================================
// Playbook Validation Constants and Functions - TASK 95
// =============================================================================

const (
	// MaxTriggersPerPlaybook is the maximum number of triggers allowed per playbook.
	MaxTriggersPerPlaybook = 10

	// MaxStepsPerPlaybook is the maximum number of steps allowed per playbook.
	MaxStepsPerPlaybook = 50

	// MaxConditionsPerTrigger is the maximum number of conditions allowed per trigger.
	MaxConditionsPerTrigger = 20

	// MaxParameterSizeBytes is the maximum size of parameters per step (10KB).
	MaxParameterSizeBytes = 10 * 1024

	// MinStepTimeout is the minimum step timeout duration.
	MinStepTimeout = 1 * time.Second

	// MaxStepTimeout is the maximum step timeout duration.
	MaxStepTimeout = 30 * time.Minute

	// MaxPlaybookNameLength is the maximum length for playbook name.
	MaxPlaybookNameLength = 200

	// MaxPlaybookDescriptionLength is the maximum length for playbook description.
	MaxPlaybookDescriptionLength = 2000

	// MaxStepNameLength is the maximum length for step name.
	MaxStepNameLength = 200
)

// playbookIDPattern validates playbook IDs against the allowed format.
// Pattern is ReDoS-safe: character class with fixed quantifier {1,64} prevents backtracking.
// IMMUTABLE: This variable is initialized once and never modified. Safe for concurrent access.
var playbookIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// validActionTypes maps all valid action types from soar/types.go.
// IMMUTABLE: This map is initialized once and never modified at runtime.
// DO NOT modify this map after package initialization - it is accessed concurrently
// from HTTP handlers without synchronization.
var validActionTypes = map[soar.ActionType]bool{
	soar.ActionTypeBlock:        true,
	soar.ActionTypeIsolate:      true,
	soar.ActionTypeQuarantine:   true,
	soar.ActionTypeNotify:       true,
	soar.ActionTypeEnrich:       true,
	soar.ActionTypeCreateTicket: true,
	soar.ActionTypeUpdateAlert:  true,
	soar.ActionTypeWebhook:      true,
	soar.ActionTypeScript:       true,
}

// validatePlaybookID validates a playbook ID against the required format.
// Returns an error if the ID is empty or doesn't match the pattern ^[a-zA-Z0-9_-]{1,64}$.
func validatePlaybookID(id string) error {
	if id == "" {
		return fmt.Errorf("playbook ID cannot be empty")
	}
	if !playbookIDPattern.MatchString(id) {
		return fmt.Errorf("playbook ID must be 1-64 characters, alphanumeric with underscores and hyphens only")
	}
	return nil
}

// validateActionType validates that an action type is one of the known valid types.
func validateActionType(at soar.ActionType) error {
	if at == "" {
		return fmt.Errorf("action type cannot be empty")
	}
	if !validActionTypes[at] {
		validTypes := make([]string, 0, len(validActionTypes))
		for t := range validActionTypes {
			validTypes = append(validTypes, string(t))
		}
		// Sort for deterministic error messages (map iteration order is non-deterministic)
		sort.Strings(validTypes)
		return fmt.Errorf("invalid action type %q: must be one of %s", at, strings.Join(validTypes, ", "))
	}
	return nil
}

// validatePlaybook performs comprehensive validation of a playbook.
// Returns a slice of validation error messages. An empty slice indicates a valid playbook.
func validatePlaybook(p *soar.Playbook) []string {
	var errs []string

	if p == nil {
		return []string{"playbook cannot be nil"}
	}

	// Validate ID format only if provided (ID is generated on create if not provided)
	if p.ID != "" {
		if err := validatePlaybookID(p.ID); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate name
	name := strings.TrimSpace(p.Name)
	if name == "" {
		errs = append(errs, "name is required")
	} else if len(name) > MaxPlaybookNameLength {
		errs = append(errs, fmt.Sprintf("name too long: %d characters (max %d)", len(name), MaxPlaybookNameLength))
	}

	// Validate description length
	if len(p.Description) > MaxPlaybookDescriptionLength {
		errs = append(errs, fmt.Sprintf("description too long: %d characters (max %d)", len(p.Description), MaxPlaybookDescriptionLength))
	}

	// Validate triggers count
	if len(p.Triggers) > MaxTriggersPerPlaybook {
		errs = append(errs, fmt.Sprintf("too many triggers: %d (max %d)", len(p.Triggers), MaxTriggersPerPlaybook))
	}

	// Validate each trigger
	for i, trigger := range p.Triggers {
		triggerErrs := validatePlaybookTrigger(i, trigger)
		errs = append(errs, triggerErrs...)
	}

	// Validate steps
	if len(p.Steps) == 0 {
		errs = append(errs, "at least one step is required")
	} else if len(p.Steps) > MaxStepsPerPlaybook {
		errs = append(errs, fmt.Sprintf("too many steps: %d (max %d)", len(p.Steps), MaxStepsPerPlaybook))
	}

	// Validate step uniqueness and each step
	stepIDs := make(map[string]bool)
	for i, step := range p.Steps {
		stepErrs := validatePlaybookStep(i, step, stepIDs)
		errs = append(errs, stepErrs...)
	}

	// Validate priority range (optional, but if set should be reasonable)
	if p.Priority < 0 {
		errs = append(errs, fmt.Sprintf("priority cannot be negative: %d", p.Priority))
	}

	return errs
}

// validatePlaybookTrigger validates a single trigger.
func validatePlaybookTrigger(index int, trigger soar.PlaybookTrigger) []string {
	var errs []string

	triggerPrefix := fmt.Sprintf("trigger %d", index)

	// Validate trigger type
	if strings.TrimSpace(trigger.Type) == "" {
		errs = append(errs, fmt.Sprintf("%s: type is required", triggerPrefix))
	}

	// Validate conditions count
	if len(trigger.Conditions) > MaxConditionsPerTrigger {
		errs = append(errs, fmt.Sprintf("%s: too many conditions: %d (max %d)",
			triggerPrefix, len(trigger.Conditions), MaxConditionsPerTrigger))
	}

	// Validate each condition
	for j, cond := range trigger.Conditions {
		if strings.TrimSpace(cond.Field) == "" {
			errs = append(errs, fmt.Sprintf("%s: condition %d: field is required", triggerPrefix, j))
		}
		if strings.TrimSpace(cond.Operator) == "" {
			errs = append(errs, fmt.Sprintf("%s: condition %d: operator is required", triggerPrefix, j))
		}
	}

	return errs
}

// MaxStepIDLength is the maximum length for step ID.
const MaxStepIDLength = 64

// validatePlaybookStep validates a single playbook step.
func validatePlaybookStep(index int, step soar.PlaybookStep, seenIDs map[string]bool) []string {
	var errs []string

	stepPrefix := fmt.Sprintf("step %d", index)

	// Validate step ID
	stepID := strings.TrimSpace(step.ID)
	if stepID == "" {
		errs = append(errs, fmt.Sprintf("%s: ID is required", stepPrefix))
	} else if stepID != step.ID {
		errs = append(errs, fmt.Sprintf("%s: ID cannot have leading/trailing whitespace", stepPrefix))
	} else if len(stepID) > MaxStepIDLength {
		errs = append(errs, fmt.Sprintf("%s: ID too long: %d characters (max %d)",
			stepPrefix, len(stepID), MaxStepIDLength))
	} else {
		// Check for duplicate IDs
		if seenIDs[stepID] {
			errs = append(errs, fmt.Sprintf("%s: duplicate step ID %q", stepPrefix, stepID))
		}
		seenIDs[stepID] = true
	}

	// Validate step name
	stepName := strings.TrimSpace(step.Name)
	if stepName == "" {
		errs = append(errs, fmt.Sprintf("%s: name is required", stepPrefix))
	} else if len(stepName) > MaxStepNameLength {
		errs = append(errs, fmt.Sprintf("%s: name too long: %d characters (max %d)",
			stepPrefix, len(stepName), MaxStepNameLength))
	}

	// Validate action type
	if err := validateActionType(step.ActionType); err != nil {
		errs = append(errs, fmt.Sprintf("%s: %s", stepPrefix, err.Error()))
	}

	// Validate timeout range
	// Note: Zero timeout means "use executor default timeout" (defined in playbook executor)
	if step.Timeout != 0 {
		if step.Timeout < 0 {
			errs = append(errs, fmt.Sprintf("%s: timeout cannot be negative: %v",
				stepPrefix, step.Timeout))
		} else if step.Timeout < MinStepTimeout {
			errs = append(errs, fmt.Sprintf("%s: timeout too short: %v (min %v)",
				stepPrefix, step.Timeout, MinStepTimeout))
		} else if step.Timeout > MaxStepTimeout {
			errs = append(errs, fmt.Sprintf("%s: timeout too long: %v (max %v)",
				stepPrefix, step.Timeout, MaxStepTimeout))
		}
	}

	// Validate parameters size
	if step.Parameters != nil {
		paramBytes, err := json.Marshal(step.Parameters)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: parameters cannot be JSON serialized: %v", stepPrefix, err))
		} else if len(paramBytes) > MaxParameterSizeBytes {
			errs = append(errs, fmt.Sprintf("%s: parameters too large: %d bytes (max %d)",
				stepPrefix, len(paramBytes), MaxParameterSizeBytes))
		}
	}

	return errs
}

// PlaybookExecutionRequest represents a request to execute a playbook
// TASK 35.5: API endpoint for triggering playbook execution
type PlaybookExecutionRequest struct {
	AlertID string `json:"alert_id" binding:"required"`
}

// PlaybookExecutionResponse represents the response from playbook execution
type PlaybookExecutionResponse struct {
	ExecutionID string                        `json:"execution_id"`
	Status      string                        `json:"status"`
	StartedAt   time.Time                     `json:"started_at"`
	StepResults map[string]*soar.ActionResult `json:"step_results,omitempty"`
	Error       string                        `json:"error,omitempty"`
}

// executePlaybook handles POST /api/v1/playbooks/{id}/execute
// TASK 35.5: Trigger playbook execution for an alert
//
//	@Summary		Execute a playbook for an alert
//	@Description	Trigger execution of a playbook for a specific alert. TASK 100: Now loads playbook from storage.
//	@Tags			playbooks
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"Playbook ID"
//	@Param			request	body		PlaybookExecutionRequest	true	"Execution request with alert ID"
//	@Success		200		{object}	PlaybookExecutionResponse	"Playbook execution started"
//	@Failure		400		{object}	map[string]string			"Invalid request or playbook disabled"
//	@Failure		404		{object}	map[string]string			"Playbook or alert not found"
//	@Failure		500		{object}	map[string]string			"Execution error"
//	@Failure		503		{string}	string						"Service unavailable - playbook storage or executor not configured"
//	@Router			/api/v1/playbooks/{id}/execute [post]
func (a *API) executePlaybook(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	playbookID := vars["id"]

	if playbookID == "" {
		writeError(w, http.StatusBadRequest, "Playbook ID is required", nil, a.logger)
		return
	}

	// Parse request body
	var req PlaybookExecutionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	if req.AlertID == "" {
		writeError(w, http.StatusBadRequest, "Alert ID is required", nil, a.logger)
		return
	}

	// TASK 100: Load playbook from storage by ID BEFORE checking executor
	// Fail fast: verify playbook exists before attempting any execution
	if a.playbookStorage == nil {
		a.logger.Error("Playbook storage not configured")
		writeError(w, http.StatusServiceUnavailable, "Playbook management not available", nil, a.logger)
		return
	}

	playbook, err := a.playbookStorage.GetPlaybook(playbookID)
	if err != nil {
		if errors.Is(err, storage.ErrPlaybookNotFound) {
			writeError(w, http.StatusNotFound, "Playbook not found", err, a.logger)
			return
		}
		a.logger.Errorw("Failed to get playbook from storage", "playbook_id", playbookID, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve playbook", err, a.logger)
		return
	}

	// TASK 100.4: Check if playbook is enabled before execution
	if !playbook.Enabled {
		writeError(w, http.StatusBadRequest, "Playbook is disabled and cannot be executed", nil, a.logger)
		return
	}

	// Check if playbook executor is available
	if a.playbookExecutor == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook executor not available", nil, a.logger)
		return
	}

	// Get alert
	ctx := r.Context()
	alert, err := a.alertStorage.GetAlert(r.Context(), req.AlertID)
	if err != nil {
		if errors.Is(err, storage.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "Alert not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get alert", err, a.logger)
		return
	}

	// Create execution record first
	executionID := fmt.Sprintf("exec-%d", time.Now().UnixNano())
	if a.playbookExecutionStorage != nil {
		if err := a.playbookExecutionStorage.CreatePlaybookExecution(ctx, executionID, playbookID, req.AlertID); err != nil {
			a.logger.Errorw("Failed to create playbook execution record", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to create execution record", err, a.logger)
			return
		}
	}

	// Execute playbook asynchronously
	go func() {
		// Context: Using Background() because this is an async goroutine with independent lifecycle
		// The HTTP request context will be cancelled after the response is sent, but playbook
		// execution must continue to completion in the background.
		execCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		execution, err := a.playbookExecutor.ExecutePlaybook(execCtx, playbook, alert)
		if err != nil {
			a.logger.Errorw("Playbook execution failed",
				"playbook_id", playbookID,
				"alert_id", req.AlertID,
				"execution_id", executionID,
				"error", err)

			// Persist failure - use execCtx (not request ctx which is cancelled after HTTP response)
			if a.playbookExecutionStorage != nil {
				if err := a.playbookExecutionStorage.CompleteExecution(execCtx, executionID, soar.ActionStatusFailed, err.Error(), nil); err != nil {
					a.logger.Errorw("Failed to persist playbook execution failure", "error", err)
				}
			}
			return
		}

		// Update execution ID if executor returned one
		if execution.ID != "" {
			executionID = execution.ID
		}

		a.logger.Infow("Playbook execution completed",
			"playbook_id", playbookID,
			"alert_id", req.AlertID,
			"execution_id", executionID,
			"status", execution.Status)

		// Persist execution state if storage is available - use execCtx (not request ctx)
		if a.playbookExecutionStorage != nil {
			if execution.Status == soar.ActionStatusCompleted || execution.Status == soar.ActionStatusFailed {
				if err := a.playbookExecutionStorage.CompleteExecution(execCtx, executionID, execution.Status, execution.Error, execution.StepResults); err != nil {
					a.logger.Errorw("Failed to persist playbook execution state",
						"execution_id", executionID,
						"error", err)
				}
			}
		}
	}()

	// Return execution ID immediately (async execution)
	response := PlaybookExecutionResponse{
		ExecutionID: executionID,
		Status:      "running",
		StartedAt:   time.Now(),
	}

	a.respondJSON(w, response, http.StatusOK)
}

// getPlaybookExecution handles GET /api/v1/playbook-executions/{id}
// TASK 35.5: Get playbook execution status and results
//
//	@Summary		Get playbook execution status
//	@Description	Retrieve status, step results, and metadata for a playbook execution
//	@Tags			playbooks
//	@Produce		json
//	@Param			id	path		string	true	"Execution ID"
//	@Success		200	{object}	PlaybookExecutionResponse	"Execution status and results"
//	@Failure		404	{object}	map[string]string			"Execution not found"
//	@Router			/api/v1/playbook-executions/{id} [get]
func (a *API) getPlaybookExecution(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	executionID := vars["id"]

	if executionID == "" {
		writeError(w, http.StatusBadRequest, "Execution ID is required", nil, a.logger)
		return
	}

	if a.playbookExecutionStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook execution storage not available", nil, a.logger)
		return
	}

	ctx := r.Context()
	exec, err := a.playbookExecutionStorage.GetExecution(ctx, executionID)
	if err != nil {
		if err.Error() == fmt.Sprintf("execution %s not found", executionID) {
			writeError(w, http.StatusNotFound, "Execution not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get execution", err, a.logger)
		return
	}

	response := PlaybookExecutionResponse{
		ExecutionID: exec.ID,
		Status:      exec.Status,
		StartedAt:   exec.StartedAt,
		StepResults: exec.StepResults,
		Error:       exec.ErrorMessage,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// listPlaybookExecutions handles GET /api/v1/playbook-executions
// TASK 35.5: List playbook executions with filtering and pagination
//
//	@Summary		List playbook executions
//	@Description	Retrieve list of playbook executions with optional filtering by playbook_id, alert_id, status
//	@Tags			playbooks
//	@Produce		json
//	@Param			playbook_id	query		string	false	"Filter by playbook ID"
//	@Param			alert_id	query		string	false	"Filter by alert ID"
//	@Param			status		query		string	false	"Filter by status (running, completed, failed)"
//	@Param			page		query		int		false	"Page number (default: 1)"
//	@Param			limit		query		int		false	"Items per page (default: 50, max: 100)"
//	@Success		200			{object}	map[string]interface{}	"Paginated list of executions"
//	@Router			/api/v1/playbook-executions [get]
func (a *API) listPlaybookExecutions(w http.ResponseWriter, r *http.Request) {
	if a.playbookExecutionStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook execution storage not available", nil, a.logger)
		return
	}

	// Parse query parameters
	playbookID := r.URL.Query().Get("playbook_id")
	alertID := r.URL.Query().Get("alert_id")
	status := r.URL.Query().Get("status")
	page := 1
	limit := 50

	if p := r.URL.Query().Get("page"); p != "" {
		if parsedPage, err := strconv.Atoi(p); err == nil && parsedPage > 0 {
			page = parsedPage
		}
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsedLimit, err := strconv.Atoi(l); err == nil && parsedLimit > 0 {
			if parsedLimit > 100 {
				parsedLimit = 100 // Max limit
			}
			limit = parsedLimit
		}
	}

	// Build filters
	filters := make(map[string]interface{})
	if playbookID != "" {
		filters["playbook_id"] = playbookID
	}
	if alertID != "" {
		filters["alert_id"] = alertID
	}
	if status != "" {
		filters["status"] = status
	}

	// Query executions
	ctx := r.Context()
	offset := (page - 1) * limit
	executions, total, err := a.playbookExecutionStorage.ListExecutions(ctx, filters, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list executions", err, a.logger)
		return
	}

	// Convert to response format
	executionResponses := make([]map[string]interface{}, len(executions))
	for i, exec := range executions {
		executionResponses[i] = map[string]interface{}{
			"id":           exec.ID,
			"playbook_id":  exec.PlaybookID,
			"alert_id":     exec.AlertID,
			"status":       exec.Status,
			"started_at":   exec.StartedAt,
			"completed_at": exec.CompletedAt,
			"error":        exec.ErrorMessage,
			"step_results": exec.StepResults,
		}
	}

	response := map[string]interface{}{
		"executions": executionResponses,
		"total":      total,
		"page":       page,
		"limit":      limit,
		"has_more":   int64(offset+limit) < total,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// getApprovalStats handles GET /api/v1/approvals/stats
// Returns approval workflow statistics for dashboard
//
//	@Summary		Get approval statistics
//	@Description	Get statistics about playbook approval workflows
//	@Tags			playbooks
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"Approval statistics"
//	@Router			/api/v1/approvals/stats [get]
func (a *API) getApprovalStats(w http.ResponseWriter, r *http.Request) {
	// STUB: Return empty stats for now until approval workflow is fully implemented
	stats := map[string]interface{}{
		"pending_approvals":     0,
		"approved_today":        0,
		"rejected_today":        0,
		"total_approvals":       0,
		"approval_rate":         0.0,
		"average_approval_time": "0s",
	}

	a.respondJSON(w, stats, http.StatusOK)
}

// =============================================================================
// Playbook CRUD Handlers - TASK 96
// =============================================================================

const (
	// DefaultPlaybookPageSize is the default number of playbooks per page.
	DefaultPlaybookPageSize = 50

	// MaxPlaybookPageSize is the maximum number of playbooks per page.
	MaxPlaybookPageSize = 100

	// MaxPlaybookBodySize is the maximum size of playbook request body (1MB).
	MaxPlaybookBodySize = 1 * 1024 * 1024
)

// listPlaybooks handles GET /api/v1/playbooks
// TASK 96: List playbooks with pagination and optional filters
//
//	@Summary		List playbooks
//	@Description	Retrieve a paginated list of playbooks with optional filtering
//	@Tags			playbooks
//	@Produce		json
//	@Param			page		query		int		false	"Page number (default: 1)"
//	@Param			limit		query		int		false	"Items per page (default: 50, max: 100)"
//	@Param			enabled		query		bool	false	"Filter by enabled status"
//	@Param			tag			query		string	false	"Filter by tag"
//	@Success		200			{object}	map[string]interface{}	"Paginated list of playbooks"
//	@Failure		500			{object}	map[string]string		"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks [get]
func (a *API) listPlaybooks(w http.ResponseWriter, r *http.Request) {
	if a.playbookStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook storage not available", nil, a.logger)
		return
	}

	// Parse pagination parameters
	page := 1
	limit := DefaultPlaybookPageSize

	if p := r.URL.Query().Get("page"); p != "" {
		if parsedPage, err := strconv.Atoi(p); err == nil && parsedPage > 0 {
			page = parsedPage
		}
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsedLimit, err := strconv.Atoi(l); err == nil && parsedLimit > 0 {
			if parsedLimit > MaxPlaybookPageSize {
				parsedLimit = MaxPlaybookPageSize
			}
			limit = parsedLimit
		}
	}

	offset := (page - 1) * limit

	// Check for filters
	enabledFilter := r.URL.Query().Get("enabled")
	tagFilter := r.URL.Query().Get("tag")
	searchFilter := r.URL.Query().Get("search")

	var playbooks []soar.Playbook
	var err error

	// Apply filters if specified (search takes priority)
	if searchFilter != "" {
		playbooks, err = a.playbookStorage.SearchPlaybooks(searchFilter)
	} else if enabledFilter != "" {
		enabled := enabledFilter == "true"
		playbooks, err = a.playbookStorage.GetPlaybooksByStatus(enabled)
	} else if tagFilter != "" {
		playbooks, err = a.playbookStorage.GetPlaybooksByTag(tagFilter)
	} else {
		playbooks, err = a.playbookStorage.GetPlaybooks(limit, offset)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list playbooks", err, a.logger)
		return
	}

	// Get total count
	total, err := a.playbookStorage.GetPlaybookCount()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get playbook count", err, a.logger)
		return
	}

	// Apply manual pagination for filtered results
	if searchFilter != "" || enabledFilter != "" || tagFilter != "" {
		total = int64(len(playbooks))
		// Apply offset and limit manually for filtered results
		if offset >= len(playbooks) {
			playbooks = []soar.Playbook{}
		} else {
			end := offset + limit
			if end > len(playbooks) {
				end = len(playbooks)
			}
			playbooks = playbooks[offset:end]
		}
	}

	response := map[string]interface{}{
		"playbooks": playbooks,
		"total":     total,
		"page":      page,
		"limit":     limit,
		"has_more":  int64(offset+limit) < total,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// createPlaybook handles POST /api/v1/playbooks
// TASK 96: Create a new playbook
//
//	@Summary		Create playbook
//	@Description	Create a new playbook with validation
//	@Tags			playbooks
//	@Accept			json
//	@Produce		json
//	@Param			playbook	body		soar.Playbook	true	"Playbook to create"
//	@Success		201			{object}	soar.Playbook	"Created playbook"
//	@Failure		400			{object}	map[string]interface{}	"Validation error"
//	@Failure		409			{object}	map[string]string		"Name conflict"
//	@Failure		500			{object}	map[string]string		"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks [post]
func (a *API) createPlaybook(w http.ResponseWriter, r *http.Request) {
	if a.playbookStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook storage not available", nil, a.logger)
		return
	}

	// Decode request body with size limit
	var playbook soar.Playbook
	if err := a.decodeJSONBodyWithLimit(w, r, &playbook, MaxPlaybookBodySize); err != nil {
		// Error already written by decodeJSONBodyWithLimit
		return
	}

	// Generate ID if empty
	if playbook.ID == "" {
		playbook.ID = fmt.Sprintf("pb-%s", uuid.New().String()[:8])
	}

	// Validate ID format
	if err := validatePlaybookID(playbook.ID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	// Validate playbook structure
	validationErrors := validatePlaybook(&playbook)
	if len(validationErrors) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Playbook validation failed",
			"details": validationErrors,
		})
		return
	}

	// Check for name conflict
	exists, err := a.playbookStorage.PlaybookNameExists(playbook.Name, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check playbook name", err, a.logger)
		return
	}
	if exists {
		writeError(w, http.StatusConflict, "Playbook with this name already exists", nil, a.logger)
		return
	}

	// Set audit fields
	username := getUsernameFromContext(r.Context())
	now := time.Now()
	playbook.CreatedBy = username
	playbook.CreatedAt = now
	playbook.UpdatedAt = now

	// Initialize empty slices if nil (for proper JSON serialization)
	if playbook.Triggers == nil {
		playbook.Triggers = make([]soar.PlaybookTrigger, 0)
	}
	if playbook.Steps == nil {
		playbook.Steps = make([]soar.PlaybookStep, 0)
	}
	if playbook.Tags == nil {
		playbook.Tags = make([]string, 0)
	}

	// Store playbook
	if err := a.playbookStorage.CreatePlaybook(&playbook); err != nil {
		if errors.Is(err, storage.ErrPlaybookNameExists) {
			writeError(w, http.StatusConflict, "Playbook with this name already exists", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to create playbook", err, a.logger)
		return
	}

	// Audit log
	a.logger.Infow("Playbook created",
		"playbook_id", playbook.ID,
		"name", playbook.Name,
		"created_by", username,
		"enabled", playbook.Enabled,
		"step_count", len(playbook.Steps),
		"trigger_count", len(playbook.Triggers))

	a.respondJSON(w, playbook, http.StatusCreated)
}

// getPlaybook handles GET /api/v1/playbooks/{id}
// TASK 96: Get a single playbook by ID
//
//	@Summary		Get playbook
//	@Description	Retrieve a specific playbook by ID
//	@Tags			playbooks
//	@Produce		json
//	@Param			id	path		string	true	"Playbook ID"
//	@Success		200	{object}	soar.Playbook			"Playbook details"
//	@Failure		400	{object}	map[string]string		"Invalid ID"
//	@Failure		404	{object}	map[string]string		"Playbook not found"
//	@Failure		500	{object}	map[string]string		"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks/{id} [get]
func (a *API) getPlaybook(w http.ResponseWriter, r *http.Request) {
	if a.playbookStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID
	if err := validatePlaybookID(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	// Get playbook
	playbook, err := a.playbookStorage.GetPlaybook(id)
	if err != nil {
		if errors.Is(err, storage.ErrPlaybookNotFound) {
			writeError(w, http.StatusNotFound, "Playbook not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get playbook", err, a.logger)
		return
	}

	a.respondJSON(w, playbook, http.StatusOK)
}

// updatePlaybook handles PUT /api/v1/playbooks/{id}
// TASK 96: Update an existing playbook
//
//	@Summary		Update playbook
//	@Description	Update an existing playbook
//	@Tags			playbooks
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string			true	"Playbook ID"
//	@Param			playbook	body		soar.Playbook	true	"Updated playbook"
//	@Success		200			{object}	soar.Playbook	"Updated playbook"
//	@Failure		400			{object}	map[string]interface{}	"Validation error"
//	@Failure		404			{object}	map[string]string		"Playbook not found"
//	@Failure		409			{object}	map[string]string		"Name conflict"
//	@Failure		500			{object}	map[string]string		"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks/{id} [put]
func (a *API) updatePlaybook(w http.ResponseWriter, r *http.Request) {
	if a.playbookStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID
	if err := validatePlaybookID(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	// Check if playbook exists first
	existing, err := a.playbookStorage.GetPlaybook(id)
	if err != nil {
		if errors.Is(err, storage.ErrPlaybookNotFound) {
			writeError(w, http.StatusNotFound, "Playbook not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get playbook", err, a.logger)
		return
	}

	// Decode request body with size limit
	var playbook soar.Playbook
	if err := a.decodeJSONBodyWithLimit(w, r, &playbook, MaxPlaybookBodySize); err != nil {
		// Error already written by decodeJSONBodyWithLimit
		return
	}

	// Ensure ID matches path parameter
	playbook.ID = id

	// Validate playbook structure
	validationErrors := validatePlaybook(&playbook)
	if len(validationErrors) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Playbook validation failed",
			"details": validationErrors,
		})
		return
	}

	// Check for name conflict (exclude current playbook)
	if playbook.Name != existing.Name {
		exists, err := a.playbookStorage.PlaybookNameExists(playbook.Name, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to check playbook name", err, a.logger)
			return
		}
		if exists {
			writeError(w, http.StatusConflict, "Another playbook with this name already exists", nil, a.logger)
			return
		}
	}

	// Preserve immutable audit fields
	playbook.CreatedBy = existing.CreatedBy
	playbook.CreatedAt = existing.CreatedAt
	playbook.UpdatedAt = time.Now()

	// Initialize empty slices if nil
	if playbook.Triggers == nil {
		playbook.Triggers = make([]soar.PlaybookTrigger, 0)
	}
	if playbook.Steps == nil {
		playbook.Steps = make([]soar.PlaybookStep, 0)
	}
	if playbook.Tags == nil {
		playbook.Tags = make([]string, 0)
	}

	// Update playbook
	if err := a.playbookStorage.UpdatePlaybook(id, &playbook); err != nil {
		if errors.Is(err, storage.ErrPlaybookNotFound) {
			writeError(w, http.StatusNotFound, "Playbook not found", err, a.logger)
			return
		}
		if errors.Is(err, storage.ErrPlaybookNameExists) {
			writeError(w, http.StatusConflict, "Another playbook with this name already exists", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to update playbook", err, a.logger)
		return
	}

	// Audit log
	username := getUsernameFromContext(r.Context())
	a.logger.Infow("Playbook updated",
		"playbook_id", id,
		"name", playbook.Name,
		"updated_by", username,
		"enabled", playbook.Enabled,
		"step_count", len(playbook.Steps),
		"trigger_count", len(playbook.Triggers))

	a.respondJSON(w, playbook, http.StatusOK)
}

// deletePlaybook handles DELETE /api/v1/playbooks/{id}
// TASK 96: Delete a playbook
//
//	@Summary		Delete playbook
//	@Description	Delete a playbook by ID
//	@Tags			playbooks
//	@Param			id	path	string	true	"Playbook ID"
//	@Success		204	"Playbook deleted"
//	@Failure		400	{object}	map[string]string	"Invalid ID"
//	@Failure		404	{object}	map[string]string	"Playbook not found"
//	@Failure		500	{object}	map[string]string	"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks/{id} [delete]
func (a *API) deletePlaybook(w http.ResponseWriter, r *http.Request) {
	if a.playbookStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID
	if err := validatePlaybookID(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	// Get playbook first for audit logging
	playbook, err := a.playbookStorage.GetPlaybook(id)
	if err != nil {
		if errors.Is(err, storage.ErrPlaybookNotFound) {
			writeError(w, http.StatusNotFound, "Playbook not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get playbook", err, a.logger)
		return
	}

	// Delete playbook
	if err := a.playbookStorage.DeletePlaybook(id); err != nil {
		if errors.Is(err, storage.ErrPlaybookNotFound) {
			writeError(w, http.StatusNotFound, "Playbook not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete playbook", err, a.logger)
		return
	}

	// Audit log
	username := getUsernameFromContext(r.Context())
	a.logger.Infow("Playbook deleted",
		"playbook_id", id,
		"name", playbook.Name,
		"deleted_by", username)

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// TASK 97: Additional Playbook API Endpoints
// =============================================================================

// PlaybookValidationResponse represents the response for playbook validation
type PlaybookValidationResponse struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// enablePlaybook handles POST /api/v1/playbooks/{id}/enable
// TASK 97: Enable a playbook
//
//	@Summary		Enable playbook
//	@Description	Enable a playbook by ID
//	@Tags			playbooks
//	@Param			id	path		string	true	"Playbook ID"
//	@Success		200	{object}	soar.Playbook
//	@Failure		400	{object}	map[string]string	"Invalid ID"
//	@Failure		404	{object}	map[string]string	"Playbook not found"
//	@Failure		500	{object}	map[string]string	"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks/{id}/enable [post]
func (a *API) enablePlaybook(w http.ResponseWriter, r *http.Request) {
	if a.playbookStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID
	if err := validatePlaybookID(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	// Enable playbook
	if err := a.playbookStorage.EnablePlaybook(id); err != nil {
		if errors.Is(err, storage.ErrPlaybookNotFound) {
			writeError(w, http.StatusNotFound, "Playbook not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to enable playbook", err, a.logger)
		return
	}

	// Fetch updated playbook
	playbook, err := a.playbookStorage.GetPlaybook(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get updated playbook", err, a.logger)
		return
	}

	// Audit log
	username := getUsernameFromContext(r.Context())
	a.logger.Infow("Playbook enabled",
		"playbook_id", id,
		"name", playbook.Name,
		"enabled_by", username)

	a.respondJSON(w, playbook, http.StatusOK)
}

// disablePlaybook handles POST /api/v1/playbooks/{id}/disable
// TASK 97: Disable a playbook
//
//	@Summary		Disable playbook
//	@Description	Disable a playbook by ID
//	@Tags			playbooks
//	@Param			id	path		string	true	"Playbook ID"
//	@Success		200	{object}	soar.Playbook
//	@Failure		400	{object}	map[string]string	"Invalid ID"
//	@Failure		404	{object}	map[string]string	"Playbook not found"
//	@Failure		500	{object}	map[string]string	"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks/{id}/disable [post]
func (a *API) disablePlaybook(w http.ResponseWriter, r *http.Request) {
	if a.playbookStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID
	if err := validatePlaybookID(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	// Disable playbook
	if err := a.playbookStorage.DisablePlaybook(id); err != nil {
		if errors.Is(err, storage.ErrPlaybookNotFound) {
			writeError(w, http.StatusNotFound, "Playbook not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to disable playbook", err, a.logger)
		return
	}

	// Fetch updated playbook
	playbook, err := a.playbookStorage.GetPlaybook(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get updated playbook", err, a.logger)
		return
	}

	// Audit log
	username := getUsernameFromContext(r.Context())
	a.logger.Infow("Playbook disabled",
		"playbook_id", id,
		"name", playbook.Name,
		"disabled_by", username)

	a.respondJSON(w, playbook, http.StatusOK)
}

// validatePlaybookHandler handles POST /api/v1/playbooks/validate
// TASK 97: Validate playbook without creating
//
//	@Summary		Validate playbook
//	@Description	Validate playbook configuration without creating it
//	@Tags			playbooks
//	@Accept			json
//	@Produce		json
//	@Param			playbook	body		soar.Playbook	true	"Playbook to validate"
//	@Success		200			{object}	PlaybookValidationResponse
//	@Failure		400			{object}	map[string]string	"Invalid JSON"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks/validate [post]
func (a *API) validatePlaybookHandler(w http.ResponseWriter, r *http.Request) {
	var playbook soar.Playbook
	if err := json.NewDecoder(r.Body).Decode(&playbook); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error(), err, a.logger)
		return
	}

	response := PlaybookValidationResponse{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Run validation
	validationErrors := validatePlaybook(&playbook)
	if len(validationErrors) > 0 {
		response.Valid = false
		response.Errors = validationErrors
	}

	// Check ID format if provided
	if playbook.ID != "" {
		if err := validatePlaybookID(playbook.ID); err != nil {
			response.Valid = false
			response.Errors = append(response.Errors, err.Error())
		}
	}

	// Check name uniqueness as warning (not error) - only if storage is available
	if a.playbookStorage != nil && playbook.Name != "" {
		exists, err := a.playbookStorage.PlaybookNameExists(playbook.Name, playbook.ID)
		if err == nil && exists {
			response.Warnings = append(response.Warnings, "A playbook with this name already exists")
		}
	}

	a.respondJSON(w, response, http.StatusOK)
}

// duplicatePlaybook handles POST /api/v1/playbooks/{id}/duplicate
// TASK 97: Duplicate a playbook
//
//	@Summary		Duplicate playbook
//	@Description	Create a copy of an existing playbook
//	@Tags			playbooks
//	@Param			id	path		string	true	"Original playbook ID"
//	@Success		201	{object}	soar.Playbook
//	@Failure		400	{object}	map[string]string	"Invalid ID"
//	@Failure		404	{object}	map[string]string	"Playbook not found"
//	@Failure		500	{object}	map[string]string	"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks/{id}/duplicate [post]
func (a *API) duplicatePlaybook(w http.ResponseWriter, r *http.Request) {
	if a.playbookStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID
	if err := validatePlaybookID(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	// Get original playbook
	original, err := a.playbookStorage.GetPlaybook(id)
	if err != nil {
		if errors.Is(err, storage.ErrPlaybookNotFound) {
			writeError(w, http.StatusNotFound, "Playbook not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get playbook", err, a.logger)
		return
	}

	// Create deep copy
	duplicate := deepCopyPlaybook(original)

	// Set new ID and metadata
	duplicate.ID = fmt.Sprintf("pb-%s", uuid.New().String()[:8])
	duplicate.Name = original.Name + " (Copy)"
	duplicate.Enabled = false // Disabled by default
	duplicate.CreatedBy = getUsernameFromContext(r.Context())
	duplicate.CreatedAt = time.Now()
	duplicate.UpdatedAt = time.Now()

	// Create duplicate
	if err := a.playbookStorage.CreatePlaybook(duplicate); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create duplicate playbook", err, a.logger)
		return
	}

	// Audit log
	a.logger.Infow("Playbook duplicated",
		"original_id", id,
		"duplicate_id", duplicate.ID,
		"duplicated_by", duplicate.CreatedBy)

	a.respondJSON(w, duplicate, http.StatusCreated)
}

// deepCopyPlaybook creates a deep copy of a playbook
func deepCopyPlaybook(original *soar.Playbook) *soar.Playbook {
	duplicate := &soar.Playbook{
		Name:        original.Name,
		Description: original.Description,
		Enabled:     original.Enabled,
		Priority:    original.Priority,
	}

	// Deep copy Tags
	if original.Tags != nil {
		duplicate.Tags = make([]string, len(original.Tags))
		copy(duplicate.Tags, original.Tags)
	} else {
		duplicate.Tags = make([]string, 0)
	}

	// Deep copy Triggers
	if original.Triggers != nil {
		duplicate.Triggers = make([]soar.PlaybookTrigger, len(original.Triggers))
		for i, trigger := range original.Triggers {
			duplicate.Triggers[i] = deepCopyTrigger(trigger)
		}
	} else {
		duplicate.Triggers = make([]soar.PlaybookTrigger, 0)
	}

	// Deep copy Steps with new step IDs
	if original.Steps != nil {
		duplicate.Steps = make([]soar.PlaybookStep, len(original.Steps))
		for i, step := range original.Steps {
			duplicate.Steps[i] = deepCopyStep(step)
			// Generate new step ID
			duplicate.Steps[i].ID = fmt.Sprintf("step-%s", uuid.New().String()[:8])
		}
	} else {
		duplicate.Steps = make([]soar.PlaybookStep, 0)
	}

	return duplicate
}

// deepCopyTrigger creates a deep copy of a trigger
func deepCopyTrigger(original soar.PlaybookTrigger) soar.PlaybookTrigger {
	trigger := soar.PlaybookTrigger{
		Type: original.Type,
	}

	// Deep copy Conditions
	if original.Conditions != nil {
		trigger.Conditions = make([]soar.PlaybookCondition, len(original.Conditions))
		for i, cond := range original.Conditions {
			trigger.Conditions[i] = deepCopyCondition(cond)
		}
	} else {
		trigger.Conditions = make([]soar.PlaybookCondition, 0)
	}

	return trigger
}

// deepCopyStep creates a deep copy of a step
func deepCopyStep(original soar.PlaybookStep) soar.PlaybookStep {
	step := soar.PlaybookStep{
		ID:              original.ID,
		Name:            original.Name,
		ActionType:      original.ActionType,
		ContinueOnError: original.ContinueOnError,
		Timeout:         original.Timeout,
	}

	// Deep copy Parameters map
	if original.Parameters != nil {
		step.Parameters = make(map[string]interface{}, len(original.Parameters))
		for k, v := range original.Parameters {
			step.Parameters[k] = deepCopyValue(v)
		}
	} else {
		step.Parameters = make(map[string]interface{})
	}

	// Deep copy Conditions
	if original.Conditions != nil {
		step.Conditions = make([]soar.PlaybookCondition, len(original.Conditions))
		for i, cond := range original.Conditions {
			step.Conditions[i] = deepCopyCondition(cond)
		}
	} else {
		step.Conditions = make([]soar.PlaybookCondition, 0)
	}

	return step
}

// deepCopyCondition creates a deep copy of a condition
func deepCopyCondition(original soar.PlaybookCondition) soar.PlaybookCondition {
	return soar.PlaybookCondition{
		Field:    original.Field,
		Operator: original.Operator,
		Value:    deepCopyValue(original.Value),
	}
}

// deepCopyValue creates a deep copy of an interface{} value
func deepCopyValue(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, v := range val {
			result[k] = deepCopyValue(v)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = deepCopyValue(v)
		}
		return result
	default:
		// Primitive types (string, int, float64, bool) are copied by value
		return val
	}
}

// =============================================================================
// TASK 98: Playbook Stats Endpoint
// =============================================================================

// getPlaybookStats retrieves aggregated playbook statistics
// @Summary Get playbook statistics
// @Description Returns aggregated statistics for all playbooks (total, enabled, disabled counts)
// @Tags playbooks
// @Accept json
// @Produce json
// @Success 200 {object} storage.PlaybookStats "Playbook statistics"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden - insufficient permissions"
// @Failure 500 {string} string "Internal server error"
// @Failure 503 {string} string "Service unavailable - playbook management not configured"
// @Router /api/v1/playbooks/stats [get]
func (a *API) getPlaybookStats(w http.ResponseWriter, r *http.Request) {
	// Check if playbook storage is available
	if a.playbookStorage == nil {
		a.logger.Error("Playbook storage not configured")
		http.Error(w, "Playbook management not available", http.StatusServiceUnavailable)
		return
	}

	// Get stats from storage
	stats, err := a.playbookStorage.GetPlaybookStats()
	if err != nil {
		a.logger.Errorf("Failed to get playbook stats: %v", err)
		http.Error(w, "Failed to retrieve playbook statistics", http.StatusInternalServerError)
		return
	}

	// Encode to buffer first to catch encoding errors before writing headers
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(stats); err != nil {
		a.logger.Errorf("Failed to encode playbook stats: %v", err)
		http.Error(w, "Failed to encode statistics", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(buf.Bytes()); err != nil {
		a.logger.Errorf("Failed to write playbook stats response: %v", err)
	}
}

// =============================================================================
// Playbook Execution Approval Workflow Endpoints
// =============================================================================

// MaxApprovalCommentLength is the maximum length for approval comments (5KB)
const MaxApprovalCommentLength = 5000

// executionIDPattern validates execution IDs against allowed format
// Pattern is ReDoS-safe: character class with fixed quantifier {1,100} prevents backtracking.
// IMMUTABLE: This variable is initialized once and never modified. Safe for concurrent access.
var executionIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,100}$`)

// ApprovalRequest represents a request to approve or reject a playbook execution
type ApprovalRequest struct {
	ApprovedBy string `json:"approvedBy,omitempty"` // User ID of approver
	Comment    string `json:"comment,omitempty"`    // Optional comment (max 5000 chars)
}

// ApprovalResponse represents the response from an approval/rejection action
type ApprovalResponse struct {
	Success     bool      `json:"success"`
	ExecutionID string    `json:"executionId"`
	Status      string    `json:"status"`
	ApprovedAt  time.Time `json:"approvedAt,omitempty"`
	RejectedAt  time.Time `json:"rejectedAt,omitempty"`
	ApprovedBy  string    `json:"approvedBy,omitempty"`
	RejectedBy  string    `json:"rejectedBy,omitempty"`
	Comment     string    `json:"comment,omitempty"`
}

// ApprovalError represents an approval-related error response
type ApprovalError struct {
	Success bool   `json:"success"`
	Error   struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// approvePlaybookExecution handles POST /api/v1/playbooks/executions/{executionId}/approve
// Approve a playbook execution that is awaiting approval
//
//	@Summary		Approve playbook execution
//	@Description	Approve a playbook execution that is in awaiting_approval status.
//	@Tags			playbooks
//	@Accept			json
//	@Produce		json
//	@Param			executionId	path		string				true	"Execution ID"
//	@Param			request		body		ApprovalRequest		true	"Approval request"
//	@Success		200			{object}	ApprovalResponse	"Execution approved"
//	@Failure		400			{object}	ApprovalError		"Invalid request or expired"
//	@Failure		404			{object}	map[string]string	"Execution not found"
//	@Failure		500			{object}	map[string]string	"Internal server error"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks/executions/{executionId}/approve [post]
func (a *API) approvePlaybookExecution(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	executionID := vars["executionId"]

	if executionID == "" {
		writeError(w, http.StatusBadRequest, "Execution ID is required", nil, a.logger)
		return
	}

	// Validate execution ID format (alphanumeric, underscore, hyphen only)
	if !executionIDPattern.MatchString(executionID) {
		writeError(w, http.StatusBadRequest, "Invalid execution ID format: must be 1-100 alphanumeric characters, underscores, or hyphens", nil, a.logger)
		return
	}

	// Parse request body
	var req ApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Empty body is OK - just means no comment
		req = ApprovalRequest{}
	}

	// Validate comment length to prevent DoS
	if len(req.Comment) > MaxApprovalCommentLength {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Comment too long: %d characters (max %d)", len(req.Comment), MaxApprovalCommentLength), nil, a.logger)
		return
	}

	// Get username from context if approvedBy not provided
	username := getUsernameFromContext(r.Context())
	if req.ApprovedBy == "" {
		req.ApprovedBy = username
	}

	// Check if execution storage is available
	if a.playbookExecutionStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook execution storage not available", nil, a.logger)
		return
	}

	// Get current execution state
	ctx := r.Context()
	exec, err := a.playbookExecutionStorage.GetExecution(ctx, executionID)
	if err != nil {
		if err.Error() == fmt.Sprintf("execution %s not found", executionID) {
			writeError(w, http.StatusNotFound, "Execution not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get execution", err, a.logger)
		return
	}

	// Check if execution is in awaiting_approval status
	if exec.Status != "awaiting_approval" && exec.Status != "pending" {
		a.writeApprovalError(w, http.StatusBadRequest, "INVALID_STATE",
			fmt.Sprintf("Execution is in '%s' status and cannot be approved", exec.Status))
		return
	}

	// Check for expiration (approval window is 24 hours)
	if time.Since(exec.StartedAt) > 24*time.Hour {
		a.writeApprovalError(w, http.StatusBadRequest, "APPROVAL_EXPIRED", "Approval window has expired")
		return
	}

	// PLACEHOLDER: In production, update execution status in database
	// For now, just log and return success
	a.logger.Infow("Playbook execution approved",
		"execution_id", executionID,
		"playbook_id", exec.PlaybookID,
		"approved_by", req.ApprovedBy,
		"comment", sanitizeLogField(req.Comment))

	response := ApprovalResponse{
		Success:     true,
		ExecutionID: executionID,
		Status:      "running",
		ApprovedAt:  time.Now(),
		ApprovedBy:  req.ApprovedBy,
		Comment:     req.Comment,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// rejectPlaybookExecution handles POST /api/v1/playbooks/executions/{executionId}/reject
// Reject a playbook execution that is awaiting approval
//
//	@Summary		Reject playbook execution
//	@Description	Reject a playbook execution that is in awaiting_approval status.
//	@Tags			playbooks
//	@Accept			json
//	@Produce		json
//	@Param			executionId	path		string				true	"Execution ID"
//	@Param			request		body		ApprovalRequest		true	"Rejection request"
//	@Success		200			{object}	ApprovalResponse	"Execution rejected"
//	@Failure		400			{object}	ApprovalError		"Invalid request"
//	@Failure		404			{object}	map[string]string	"Execution not found"
//	@Failure		500			{object}	map[string]string	"Internal server error"
//	@Security		BearerAuth
//	@Router			/api/v1/playbooks/executions/{executionId}/reject [post]
func (a *API) rejectPlaybookExecution(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	executionID := vars["executionId"]

	if executionID == "" {
		writeError(w, http.StatusBadRequest, "Execution ID is required", nil, a.logger)
		return
	}

	// Validate execution ID format (alphanumeric, underscore, hyphen only)
	if !executionIDPattern.MatchString(executionID) {
		writeError(w, http.StatusBadRequest, "Invalid execution ID format: must be 1-100 alphanumeric characters, underscores, or hyphens", nil, a.logger)
		return
	}

	// Parse request body
	var req ApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Empty body is OK - just means no comment
		req = ApprovalRequest{}
	}

	// Validate comment length to prevent DoS
	if len(req.Comment) > MaxApprovalCommentLength {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Comment too long: %d characters (max %d)", len(req.Comment), MaxApprovalCommentLength), nil, a.logger)
		return
	}

	// Get username from context if rejectedBy not provided
	username := getUsernameFromContext(r.Context())
	rejectedBy := req.ApprovedBy // Reuse field for rejectedBy
	if rejectedBy == "" {
		rejectedBy = username
	}

	// Check if execution storage is available
	if a.playbookExecutionStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Playbook execution storage not available", nil, a.logger)
		return
	}

	// Get current execution state
	ctx := r.Context()
	exec, err := a.playbookExecutionStorage.GetExecution(ctx, executionID)
	if err != nil {
		if err.Error() == fmt.Sprintf("execution %s not found", executionID) {
			writeError(w, http.StatusNotFound, "Execution not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get execution", err, a.logger)
		return
	}

	// Check if execution is in awaiting_approval status
	if exec.Status != "awaiting_approval" && exec.Status != "pending" {
		a.writeApprovalError(w, http.StatusBadRequest, "INVALID_STATE",
			fmt.Sprintf("Execution is in '%s' status and cannot be rejected", exec.Status))
		return
	}

	// PLACEHOLDER: In production, update execution status in database
	// For now, just log and return success
	a.logger.Infow("Playbook execution rejected",
		"execution_id", executionID,
		"playbook_id", exec.PlaybookID,
		"rejected_by", rejectedBy,
		"comment", sanitizeLogField(req.Comment))

	response := ApprovalResponse{
		Success:     true,
		ExecutionID: executionID,
		Status:      "rejected",
		RejectedAt:  time.Now(),
		RejectedBy:  rejectedBy,
		Comment:     req.Comment,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// writeApprovalError writes a JSON error response in the approval error format
func (a *API) writeApprovalError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := ApprovalError{
		Success: false,
	}
	response.Error.Code = code
	response.Error.Message = message
	if err := json.NewEncoder(w).Encode(response); err != nil {
		a.logger.Errorw("Failed to encode approval error response",
			"error", err,
			"code", code,
			"message", message)
	}
}

// sanitizeLogField removes control characters from log field values
// Duplicated here to avoid import cycle - consider moving to utils package
func sanitizeLogField(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' || r == 127 {
			return -1
		}
		return r
	}, s)
}
