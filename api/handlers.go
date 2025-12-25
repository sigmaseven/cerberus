package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"cerberus/core"
	"cerberus/storage"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// respondJSON writes a JSON response with proper error handling
func (a *API) respondJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		a.logger.Errorw("Failed to encode JSON response",
			"error", err,
			"data_type", fmt.Sprintf("%T", data))
		// Response already started, can't send error to client
		// Error is logged for monitoring
	}
}

// getEvents godoc
//
//	@Summary		Get events
//	@Description	Returns a list of recent security events
//	@Tags			events
//	@Accept			json
//	@Produce		json
//	@Param			limit	query	int	false	"Maximum number of results (1-1000)"	minimum(1)	maximum(1000)	default(100)
//	@Success		200	{array}		core.Event
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/events [get]
func (a *API) getEvents(w http.ResponseWriter, r *http.Request) {
	if a.eventStorage == nil {
		http.Error(w, "Event storage not available", http.StatusInternalServerError)
		return
	}

	// Parse pagination parameters
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	offset := (page - 1) * limit
	events, err := a.eventStorage.GetEvents(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get events", err, a.logger)
		return
	}

	// Return pagination response format expected by frontend
	response := map[string]interface{}{
		"items":       events,
		"total":       len(events), // TODO: Get actual total count from storage
		"page":        page,
		"limit":       limit,
		"total_pages": 1, // TODO: Calculate based on actual total
	}
	a.respondJSON(w, response, http.StatusOK)
}

// getRules godoc
//
//	@Summary		Get rules
//	@Description	Returns a paginated list of detection rules with optional search filtering
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			page	query		int		false	"Page number (default: 1)"
//	@Param			limit	query		int		false	"Items per page (default: 50, max: 1000)"
//	@Param			search	query		string	false	"Search term to filter rules by name or description"
//	@Success		200	{object}	map[string]interface{}	"Paginated rules response"
//	@Failure		503	{string}	string	"Rule storage not available"
//	@Router			/api/rules [get]
func (a *API) getRules(w http.ResponseWriter, r *http.Request) {
	if a.ruleStorage == nil {
		http.Error(w, "Rule storage not available", http.StatusServiceUnavailable)
		return
	}

	// Parse pagination parameters
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	// Parse search parameter
	search := r.URL.Query().Get("search")

	var rules []core.Rule
	var totalCount int64
	var err error

	// Use filtered query if search is provided, otherwise use simple query
	if search != "" {
		filters := &core.RuleFilters{
			Page:   page,
			Limit:  limit,
			Search: search,
		}
		rules, totalCount, err = a.ruleStorage.GetRulesWithFilters(filters)
	} else {
		offset := (page - 1) * limit
		rules, err = a.ruleStorage.GetRules(limit, offset)
		if err == nil {
			totalCount, err = a.ruleStorage.GetRuleCount()
		}
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get rules", err, a.logger)
		return
	}

	totalPages := int(totalCount) / limit
	if int(totalCount)%limit > 0 {
		totalPages++
	}

	// Return pagination response format expected by frontend
	response := map[string]interface{}{
		"items":       rules,
		"total":       totalCount,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	}
	a.respondJSON(w, response, http.StatusOK)
}

// getRule godoc
//
//	@Summary		Get rule
//	@Description	Get a detection rule by ID
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Rule ID"
//	@Success		200	{object}	core.Rule
//	@Failure		400	{string}	string
//	@Failure		404	{string}	string
//	@Failure		500	{string}	string
//	@Router			/api/v1/rules/{id} [get]
func (a *API) getRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY FIX: Validate ID format to prevent injection attacks
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid rule ID format", nil, a.logger)
		return
	}

	if a.ruleStorage == nil {
		http.Error(w, "Rule storage not available", http.StatusServiceUnavailable)
		return
	}

	rule, err := a.ruleStorage.GetRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "Rule not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to get rule", err, a.logger)
		}
		return
	}

	a.respondJSON(w, rule, http.StatusOK)
}

// createRule godoc
//
//	@Summary		Create rule
//	@Description	Create a new detection rule
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			rule	body		core.Rule	true	"Rule object"
//	@Success		201	{object}	core.Rule
//	@Failure		400	{string}	string	"Invalid JSON"
//	@Failure		503	{string}	string	"Rule storage not available"
//	@Router			/api/rules [post]
func (a *API) createRule(w http.ResponseWriter, r *http.Request) {
	var rule core.Rule
	// SECURITY FIX: Use size-limited decoding to prevent DoS attacks
	if err := a.decodeJSONBodyWithLimit(w, r, &rule, 1*1024*1024); err != nil {
		// Error already written by decodeJSONBodyWithLimit
		return
	}
	a.createRuleInternal(w, r, &rule)
}

// createRuleInternal creates a rule from an already-decoded struct
// This allows both createRule (which decodes the body) and handleCreateRule
// (which pre-decodes for category detection) to share the same logic
func (a *API) createRuleInternal(w http.ResponseWriter, r *http.Request, rule *core.Rule) {
	// ATOMIC OPERATION FIX: STEP 1 - Fail-fast check for detector availability BEFORE any database modification
	if a.detector == nil {
		writeError(w, http.StatusServiceUnavailable, "Detection engine not available", nil, a.logger)
		return
	}

	// ATOMIC OPERATION FIX: STEP 2 - Fail-fast check for storage availability
	if a.ruleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Rule storage not available", nil, a.logger)
		return
	}

	// TASK 179: Validate rule format (SIGMA YAML enforcement, reject legacy Conditions)
	if err := ValidateRuleForCreation(rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	if err := validateRule(rule); err != nil {
		// Validation errors are safe to return to client
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	rule.ID = uuid.New().String()

	// STEP 4 - Persist to database (only after all pre-flight checks pass)
	if err := a.ruleStorage.CreateRule(rule); err != nil {
		// SECURITY FIX: Don't expose internal storage errors
		writeError(w, http.StatusInternalServerError, "Failed to create rule", err, a.logger)
		return
	}

	// STEP 5 - Hot-reload with ROLLBACK on failure to maintain atomicity
	rules, err := a.ruleStorage.GetAllRules()
	if err != nil {
		// ROLLBACK: Delete the rule we just created to maintain consistency
		if deleteErr := a.ruleStorage.DeleteRule(rule.ID); deleteErr != nil {
			a.logger.Errorw("Failed to rollback rule creation after GetAllRules failure",
				"rule_id", rule.ID, "rollback_error", deleteErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back rule creation", "rule_id", rule.ID, "reason", "GetAllRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to activate rule", err, a.logger)
		return
	}

	if err := a.detector.ReloadRules(rules); err != nil {
		// ROLLBACK: Delete the rule we just created to maintain consistency
		if deleteErr := a.ruleStorage.DeleteRule(rule.ID); deleteErr != nil {
			a.logger.Errorw("Failed to rollback rule creation after ReloadRules failure",
				"rule_id", rule.ID, "rollback_error", deleteErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back rule creation", "rule_id", rule.ID, "reason", "ReloadRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to activate rule", err, a.logger)
		return
	}

	// STEP 6 - Success only if all steps completed
	a.logger.Infow("Rule created and activated atomically", "rule_id", rule.ID, "total_rules", len(rules))
	a.respondJSON(w, *rule, http.StatusCreated)
}

// updateRule godoc
//
//	@Summary		Update rule
//	@Description	Update an existing detection rule
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string		true	"Rule ID"
//	@Param			rule	body		core.Rule	true	"Rule object"
//	@Success		200		{object}	core.Rule
//	@Failure		400		{string}	string		"Invalid JSON"
//	@Failure		404		{string}	string		"Rule not found"
//	@Failure		503		{string}	string		"Rule storage not available"
//	@Router			/api/rules/{id} [put]
func (a *API) updateRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY FIX: Validate ID format to prevent injection attacks
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid rule ID format", nil, a.logger)
		return
	}

	var rule core.Rule
	// SECURITY FIX: Use size-limited decoding to prevent DoS attacks
	if err := a.decodeJSONBodyWithLimit(w, r, &rule, 1*1024*1024); err != nil {
		// Error already written by decodeJSONBodyWithLimit
		return
	}
	a.updateRuleInternal(w, r, id, &rule)
}

// updateRuleInternal updates a rule from an already-decoded struct
// This allows both updateRule (which decodes the body) and handleUpdateRule
// (which pre-decodes for category detection) to share the same logic
func (a *API) updateRuleInternal(w http.ResponseWriter, r *http.Request, id string, rule *core.Rule) {
	// ATOMIC OPERATION FIX: STEP 1 - Fail-fast check for detector availability BEFORE any database modification
	if a.detector == nil {
		writeError(w, http.StatusServiceUnavailable, "Detection engine not available", nil, a.logger)
		return
	}

	// ATOMIC OPERATION FIX: STEP 2 - Fail-fast check for storage availability
	if a.ruleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Rule storage not available", nil, a.logger)
		return
	}

	// TASK 179: Validate rule format (SIGMA YAML enforcement, reject legacy Conditions)
	if err := ValidateRuleForCreation(rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	if err := validateRule(rule); err != nil {
		// Validation errors are safe to return to client
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	rule.ID = id

	// STEP 4 - Get old rule for rollback capability
	oldRule, err := a.ruleStorage.GetRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "Rule not found", nil, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to get existing rule", err, a.logger)
		}
		return
	}

	// STEP 5 - Persist update to database (only after all pre-flight checks pass)
	if err := a.ruleStorage.UpdateRule(id, rule); err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "Rule not found", nil, a.logger)
		} else {
			// SECURITY FIX: Don't expose internal storage errors
			writeError(w, http.StatusInternalServerError, "Failed to update rule", err, a.logger)
		}
		return
	}

	// STEP 6 - Hot-reload with ROLLBACK on failure to maintain atomicity
	rules, err := a.ruleStorage.GetAllRules()
	if err != nil {
		// ROLLBACK: Restore the old rule to maintain consistency
		if rollbackErr := a.ruleStorage.UpdateRule(id, oldRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback rule update after GetAllRules failure",
				"rule_id", id, "rollback_error", rollbackErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back rule update", "rule_id", id, "reason", "GetAllRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to activate rule", err, a.logger)
		return
	}

	if err := a.detector.ReloadRules(rules); err != nil {
		// ROLLBACK: Restore the old rule to maintain consistency
		if rollbackErr := a.ruleStorage.UpdateRule(id, oldRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback rule update after ReloadRules failure",
				"rule_id", id, "rollback_error", rollbackErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back rule update", "rule_id", id, "reason", "ReloadRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to activate rule", err, a.logger)
		return
	}

	// STEP 7 - Success only if all steps completed
	a.logger.Infow("Rule updated and activated atomically", "rule_id", id, "total_rules", len(rules))
	a.respondJSON(w, *rule, http.StatusOK)
}

// deleteRule godoc
//
//	@Summary		Delete rule
//	@Description	Delete a detection rule by ID
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Rule ID"
//	@Success		200	{string}	string	"Rule deleted"
//	@Failure		404	{string}	string	"Rule not found"
//	@Failure		503	{string}	string	"Rule storage not available"
//	@Router			/api/rules/{id} [delete]
func (a *API) deleteRule(w http.ResponseWriter, r *http.Request) {
	// ATOMIC OPERATION FIX: STEP 1 - Fail-fast check for detector availability BEFORE any database modification
	if a.detector == nil {
		writeError(w, http.StatusServiceUnavailable, "Detection engine not available", nil, a.logger)
		return
	}

	// ATOMIC OPERATION FIX: STEP 2 - Fail-fast check for storage availability
	if a.ruleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Rule storage not available", nil, a.logger)
		return
	}

	// STEP 3 - Validate input
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY FIX: Validate ID format to prevent injection attacks
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid rule ID format", nil, a.logger)
		return
	}

	// STEP 4 - Get rule for rollback capability
	deletedRule, err := a.ruleStorage.GetRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "Rule not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to get rule", err, a.logger)
		}
		return
	}

	// STEP 5 - Delete from database (only after all pre-flight checks pass)
	if err := a.ruleStorage.DeleteRule(id); err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "Rule not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to delete rule", err, a.logger)
		}
		return
	}

	// STEP 6 - Hot-reload with ROLLBACK on failure to maintain atomicity
	rules, err := a.ruleStorage.GetAllRules()
	if err != nil {
		// ROLLBACK: Re-create the deleted rule to maintain consistency
		if rollbackErr := a.ruleStorage.CreateRule(deletedRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback rule deletion after GetAllRules failure",
				"rule_id", id, "rollback_error", rollbackErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back rule deletion", "rule_id", id, "reason", "GetAllRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to deactivate rule", err, a.logger)
		return
	}

	if err := a.detector.ReloadRules(rules); err != nil {
		// ROLLBACK: Re-create the deleted rule to maintain consistency
		if rollbackErr := a.ruleStorage.CreateRule(deletedRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback rule deletion after ReloadRules failure",
				"rule_id", id, "rollback_error", rollbackErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back rule deletion", "rule_id", id, "reason", "ReloadRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to deactivate rule", err, a.logger)
		return
	}

	// STEP 7 - Success only if all steps completed
	a.logger.Infow("Rule deleted and deactivated atomically", "rule_id", id, "total_rules", len(rules))
	a.respondJSON(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

// getActions godoc
//
//	@Summary		Get actions
//	@Description	Returns a list of all actions
//	@Tags			actions
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		core.Action
//	@Failure		503	{string}	string	"Action storage not available"
//	@Router			/api/actions [get]
func (a *API) getActions(w http.ResponseWriter, r *http.Request) {
	if a.actionStorage == nil {
		http.Error(w, "Action storage not available", http.StatusServiceUnavailable)
		return
	}

	actions, err := a.actionStorage.GetActions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get actions", err, a.logger)
		return
	}

	a.respondJSON(w, actions, http.StatusOK)
}

// getAction godoc
//
//	@Summary		Get action
//	@Description	Get an action by ID
//	@Tags			actions
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Action ID"
//	@Success		200	{object}	core.Action
//	@Failure		404	{string}	string	"Action not found"
//	@Failure		503	{string}	string	"Action storage not available"
//	@Router			/api/actions/{id} [get]
func (a *API) getAction(w http.ResponseWriter, r *http.Request) {
	if a.actionStorage == nil {
		http.Error(w, "Action storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY FIX: Validate ID format to prevent injection attacks
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid action ID format", nil, a.logger)
		return
	}

	action, err := a.actionStorage.GetAction(id)
	if err != nil {
		if errors.Is(err, storage.ErrActionNotFound) {
			writeError(w, http.StatusNotFound, "Action not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to get action", err, a.logger)
		}
		return
	}

	a.respondJSON(w, action, http.StatusOK)
}

// createAction godoc
//
//	@Summary		Create action
//	@Description	Create a new action
//	@Tags			actions
//	@Accept			json
//	@Produce		json
//	@Param			action	body		core.Action	true	"Action object"
//	@Success		201		{object}	core.Action
//	@Failure		400		{string}	string		"Invalid JSON"
//	@Failure		503		{string}	string		"Action storage not available"
//	@Router			/api/actions [post]
func (a *API) createAction(w http.ResponseWriter, r *http.Request) {
	if a.actionStorage == nil {
		http.Error(w, "Action storage not available", http.StatusServiceUnavailable)
		return
	}

	var action core.Action
	// SECURITY FIX: Use size-limited decoding to prevent DoS attacks
	if err := a.decodeJSONBodyWithLimit(w, r, &action, 512*1024); err != nil {
		// Error already written by decodeJSONBodyWithLimit
		return
	}

	if err := validateAction(&action); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	action.ID = uuid.New().String()

	if err := a.actionStorage.CreateAction(&action); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create action", err, a.logger)
		return
	}

	a.respondJSON(w, action, http.StatusCreated)
}

// updateAction godoc
//
//	@Summary		Update action
//	@Description	Update an existing action
//	@Tags			actions
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string		true	"Action ID"
//	@Param			action		body		core.Action	true	"Action object"
//	@Success		200			{object}	core.Action
//	@Failure		400			{string}	string		"Invalid JSON"
//	@Failure		404			{string}	string		"Action not found"
//	@Failure		503			{string}	string		"Action storage not available"
//	@Router			/api/actions/{id} [put]
func (a *API) updateAction(w http.ResponseWriter, r *http.Request) {
	if a.actionStorage == nil {
		http.Error(w, "Action storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY FIX: Validate ID format to prevent injection attacks
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid action ID format", nil, a.logger)
		return
	}

	var action core.Action
	// SECURITY FIX: Use size-limited decoding to prevent DoS attacks
	if err := a.decodeJSONBodyWithLimit(w, r, &action, 512*1024); err != nil {
		// Error already written by decodeJSONBodyWithLimit
		return
	}

	if err := validateAction(&action); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	action.ID = id

	if err := a.actionStorage.UpdateAction(id, &action); err != nil {
		if errors.Is(err, storage.ErrActionNotFound) {
			writeError(w, http.StatusNotFound, "Action not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to update action", err, a.logger)
		}
		return
	}

	a.respondJSON(w, action, http.StatusOK)
}

// deleteAction godoc
//
//	@Summary		Delete action
//	@Description	Delete an action by ID
//	@Tags			actions
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Action ID"
//	@Success		200	{string}	string	"Action deleted"
//	@Failure		404	{string}	string	"Action not found"
//	@Failure		503	{string}	string	"Action storage not available"
//	@Router			/api/actions/{id} [delete]
func (a *API) deleteAction(w http.ResponseWriter, r *http.Request) {
	if a.actionStorage == nil {
		http.Error(w, "Action storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY FIX: Validate ID format to prevent injection attacks
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid action ID format", nil, a.logger)
		return
	}

	if err := a.actionStorage.DeleteAction(id); err != nil {
		if errors.Is(err, storage.ErrActionNotFound) {
			writeError(w, http.StatusNotFound, "Action not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to delete action", err, a.logger)
		}
		return
	}

	a.respondJSON(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

// getCorrelationRules godoc
//
//	@Summary		Get correlation rules
//	@Description	Returns a list of all correlation rules
//	@Tags			correlation-rules
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		core.CorrelationRule
//	@Failure		503	{string}	string	"Correlation rule storage not available"
//	@Router			/api/correlation-rules [get]
func (a *API) getCorrelationRules(w http.ResponseWriter, r *http.Request) {
	if a.correlationRuleStorage == nil {
		http.Error(w, "Correlation rule storage not available", http.StatusServiceUnavailable)
		return
	}

	// Parse pagination parameters
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	// Parse search parameter
	search := r.URL.Query().Get("search")

	offset := (page - 1) * limit
	var rules []core.CorrelationRule
	var totalCount int64
	var err error

	// Use search query if search parameter is provided
	if search != "" {
		rules, totalCount, err = a.correlationRuleStorage.SearchCorrelationRules(search, limit, offset)
	} else {
		rules, err = a.correlationRuleStorage.GetCorrelationRules(limit, offset)
		if err == nil {
			totalCount, err = a.correlationRuleStorage.GetCorrelationRuleCount()
		}
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get correlation rules", err, a.logger)
		return
	}

	total := int(totalCount)

	// Return pagination response format expected by frontend
	totalPages := (total + limit - 1) / limit
	if totalPages < 1 {
		totalPages = 1
	}

	response := map[string]interface{}{
		"items":       rules,
		"total":       total,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	}
	a.respondJSON(w, response, http.StatusOK)
}

// getCorrelationRule godoc
//
//	@Summary		Get correlation rule
//	@Description	Get a correlation rule by ID
//	@Tags			correlation-rules
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Correlation Rule ID"
//	@Success		200	{object}	core.CorrelationRule
//	@Failure		404	{string}	string	"Correlation rule not found"
//	@Failure		503	{string}	string	"Correlation rule storage not available"
//	@Router			/api/correlation-rules/{id} [get]
func (a *API) getCorrelationRule(w http.ResponseWriter, r *http.Request) {
	if a.correlationRuleStorage == nil {
		http.Error(w, "Correlation rule storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY FIX: Validate ID format to prevent injection attacks
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid correlation rule ID format", nil, a.logger)
		return
	}

	rule, err := a.correlationRuleStorage.GetCorrelationRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			writeError(w, http.StatusNotFound, "Correlation rule not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to get correlation rule", err, a.logger)
		}
		return
	}

	a.respondJSON(w, rule, http.StatusOK)
}

// createCorrelationRule godoc
//
//	@Summary		Create correlation rule
//	@Description	Create a new correlation rule
//	@Tags			correlation-rules
//	@Accept			json
//	@Produce		json
//	@Param			rule	body		core.CorrelationRule	true	"Correlation Rule object"
//	@Success		201		{object}	core.CorrelationRule
//	@Failure		400		{string}	string				"Invalid JSON"
//	@Failure		503		{string}	string				"Correlation rule storage not available"
//	@Router			/api/correlation-rules [post]
func (a *API) createCorrelationRule(w http.ResponseWriter, r *http.Request) {
	// ATOMIC OPERATION FIX: STEP 1 - Fail-fast check for detector availability BEFORE any database modification
	if a.detector == nil {
		writeError(w, http.StatusServiceUnavailable, "Detection engine not available", nil, a.logger)
		return
	}

	// ATOMIC OPERATION FIX: STEP 2 - Fail-fast check for storage availability
	if a.correlationRuleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Correlation rule storage not available", nil, a.logger)
		return
	}

	// STEP 3 - Validate input
	var rule core.CorrelationRule
	// SECURITY FIX: Use size-limited decoding to prevent DoS attacks
	if err := a.decodeJSONBodyWithLimit(w, r, &rule, 1*1024*1024); err != nil {
		// Error already written by decodeJSONBodyWithLimit
		return
	}

	if err := validateCorrelationRule(&rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	rule.ID = uuid.New().String()

	// STEP 4 - Persist to database (only after all pre-flight checks pass)
	if err := a.correlationRuleStorage.CreateCorrelationRule(&rule); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create correlation rule", err, a.logger)
		return
	}

	// STEP 5 - Hot-reload with ROLLBACK on failure to maintain atomicity
	rules, err := a.correlationRuleStorage.GetAllCorrelationRules()
	if err != nil {
		// ROLLBACK: Delete the correlation rule we just created to maintain consistency
		if deleteErr := a.correlationRuleStorage.DeleteCorrelationRule(rule.ID); deleteErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule creation after GetAllCorrelationRules failure",
				"rule_id", rule.ID, "rollback_error", deleteErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back correlation rule creation", "rule_id", rule.ID, "reason", "GetAllCorrelationRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to activate correlation rule", err, a.logger)
		return
	}

	if err := a.detector.ReloadCorrelationRules(rules); err != nil {
		// ROLLBACK: Delete the correlation rule we just created to maintain consistency
		if deleteErr := a.correlationRuleStorage.DeleteCorrelationRule(rule.ID); deleteErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule creation after ReloadCorrelationRules failure",
				"rule_id", rule.ID, "rollback_error", deleteErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back correlation rule creation", "rule_id", rule.ID, "reason", "ReloadCorrelationRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to activate correlation rule", err, a.logger)
		return
	}

	// STEP 6 - Success only if all steps completed
	a.logger.Infow("Correlation rule created and activated atomically", "rule_id", rule.ID, "total_rules", len(rules))
	a.respondJSON(w, rule, http.StatusCreated)
}

// updateCorrelationRule godoc
//
//	@Summary		Update correlation rule
//	@Description	Update an existing correlation rule
//	@Tags			correlation-rules
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Correlation Rule ID"
//	@Param			rule	body		core.CorrelationRule	true	"Correlation Rule object"
//	@Success		200		{object}	core.CorrelationRule
//	@Failure		400		{string}	string				"Invalid JSON"
//	@Failure		404		{string}	string				"Correlation rule not found"
//	@Failure		503		{string}	string				"Correlation rule storage not available"
//	@Router			/api/correlation-rules/{id} [put]
func (a *API) updateCorrelationRule(w http.ResponseWriter, r *http.Request) {
	// ATOMIC OPERATION FIX: STEP 1 - Fail-fast check for detector availability BEFORE any database modification
	if a.detector == nil {
		writeError(w, http.StatusServiceUnavailable, "Detection engine not available", nil, a.logger)
		return
	}

	// ATOMIC OPERATION FIX: STEP 2 - Fail-fast check for storage availability
	if a.correlationRuleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Correlation rule storage not available", nil, a.logger)
		return
	}

	// STEP 3 - Validate input
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY FIX: Validate ID format to prevent injection attacks
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid correlation rule ID format", nil, a.logger)
		return
	}

	var rule core.CorrelationRule
	// SECURITY FIX: Use size-limited decoding to prevent DoS attacks
	if err := a.decodeJSONBodyWithLimit(w, r, &rule, 1*1024*1024); err != nil {
		// Error already written by decodeJSONBodyWithLimit
		return
	}

	if err := validateCorrelationRule(&rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	rule.ID = id

	// STEP 4 - Get old rule for rollback capability
	oldRule, err := a.correlationRuleStorage.GetCorrelationRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			writeError(w, http.StatusNotFound, "Correlation rule not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to get existing correlation rule", err, a.logger)
		}
		return
	}

	// STEP 5 - Persist update to database (only after all pre-flight checks pass)
	if err := a.correlationRuleStorage.UpdateCorrelationRule(id, &rule); err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			writeError(w, http.StatusNotFound, "Correlation rule not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to update correlation rule", err, a.logger)
		}
		return
	}

	// STEP 6 - Hot-reload with ROLLBACK on failure to maintain atomicity
	rules, err := a.correlationRuleStorage.GetAllCorrelationRules()
	if err != nil {
		// ROLLBACK: Restore the old correlation rule to maintain consistency
		if rollbackErr := a.correlationRuleStorage.UpdateCorrelationRule(id, oldRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule update after GetAllCorrelationRules failure",
				"rule_id", id, "rollback_error", rollbackErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back correlation rule update", "rule_id", id, "reason", "GetAllCorrelationRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to activate correlation rule", err, a.logger)
		return
	}

	if err := a.detector.ReloadCorrelationRules(rules); err != nil {
		// ROLLBACK: Restore the old correlation rule to maintain consistency
		if rollbackErr := a.correlationRuleStorage.UpdateCorrelationRule(id, oldRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule update after ReloadCorrelationRules failure",
				"rule_id", id, "rollback_error", rollbackErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back correlation rule update", "rule_id", id, "reason", "ReloadCorrelationRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to activate correlation rule", err, a.logger)
		return
	}

	// STEP 7 - Success only if all steps completed
	a.logger.Infow("Correlation rule updated and activated atomically", "rule_id", id, "total_rules", len(rules))
	a.respondJSON(w, rule, http.StatusOK)
}

// deleteCorrelationRule godoc
//
//	@Summary		Delete correlation rule
//	@Description	Delete a correlation rule by ID
//	@Tags			correlation-rules
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Correlation Rule ID"
//	@Success		200	{string}	string	"Correlation rule deleted"
//	@Failure		404	{string}	string	"Correlation rule not found"
//	@Failure		503	{string}	string	"Correlation rule storage not available"
//	@Router			/api/correlation-rules/{id} [delete]
func (a *API) deleteCorrelationRule(w http.ResponseWriter, r *http.Request) {
	// ATOMIC OPERATION FIX: STEP 1 - Fail-fast check for detector availability BEFORE any database modification
	if a.detector == nil {
		writeError(w, http.StatusServiceUnavailable, "Detection engine not available", nil, a.logger)
		return
	}

	// ATOMIC OPERATION FIX: STEP 2 - Fail-fast check for storage availability
	if a.correlationRuleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Correlation rule storage not available", nil, a.logger)
		return
	}

	// STEP 3 - Validate input
	vars := mux.Vars(r)
	id := vars["id"]

	// SECURITY FIX: Validate ID format to prevent injection attacks
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid correlation rule ID format", nil, a.logger)
		return
	}

	// STEP 4 - Get correlation rule for rollback capability
	deletedRule, err := a.correlationRuleStorage.GetCorrelationRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			writeError(w, http.StatusNotFound, "Correlation rule not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to get correlation rule", err, a.logger)
		}
		return
	}

	// STEP 5 - Delete from database (only after all pre-flight checks pass)
	if err := a.correlationRuleStorage.DeleteCorrelationRule(id); err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			writeError(w, http.StatusNotFound, "Correlation rule not found", err, a.logger)
		} else {
			writeError(w, http.StatusInternalServerError, "Failed to delete correlation rule", err, a.logger)
		}
		return
	}

	// STEP 6 - Hot-reload with ROLLBACK on failure to maintain atomicity
	rules, err := a.correlationRuleStorage.GetAllCorrelationRules()
	if err != nil {
		// ROLLBACK: Re-create the deleted correlation rule to maintain consistency
		if rollbackErr := a.correlationRuleStorage.CreateCorrelationRule(deletedRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule deletion after GetAllCorrelationRules failure",
				"rule_id", id, "rollback_error", rollbackErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back correlation rule deletion", "rule_id", id, "reason", "GetAllCorrelationRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to deactivate correlation rule", err, a.logger)
		return
	}

	if err := a.detector.ReloadCorrelationRules(rules); err != nil {
		// ROLLBACK: Re-create the deleted correlation rule to maintain consistency
		if rollbackErr := a.correlationRuleStorage.CreateCorrelationRule(deletedRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule deletion after ReloadCorrelationRules failure",
				"rule_id", id, "rollback_error", rollbackErr, "original_error", err)
		} else {
			a.logger.Infow("Successfully rolled back correlation rule deletion", "rule_id", id, "reason", "ReloadCorrelationRules failed")
		}
		writeError(w, http.StatusInternalServerError, "Failed to deactivate correlation rule", err, a.logger)
		return
	}

	// STEP 7 - Success only if all steps completed
	a.logger.Infow("Correlation rule deleted and deactivated atomically", "rule_id", id, "total_rules", len(rules))
	a.respondJSON(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

// TASK 138: Removed unused getListeners function (listener endpoints moved to listener_handlers.go)

// getDashboardStats godoc
//
//	@Summary		Get dashboard stats
//	@Description	Returns dashboard statistics
//	@Tags			dashboard
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}
//	@Failure		503	{string}	string	"Storage not available"
//	@Router			/api/dashboard [get]
func (a *API) getDashboardStats(w http.ResponseWriter, r *http.Request) {
	if a.eventStorage == nil || a.alertStorage == nil {
		http.Error(w, "Storage not available", http.StatusServiceUnavailable)
		return
	}

	eventCount, err := a.eventStorage.GetEventCount(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get event count", err, a.logger)
		return
	}

	alertCount, err := a.alertStorage.GetAlertCount(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get alert count", err, a.logger)
		return
	}

	// Return stats with field names that match frontend DashboardStatsSchema
	stats := map[string]interface{}{
		"total_events":  eventCount,
		"active_alerts": alertCount,
		"rules_fired":   0, // TODO: Implement rules_fired counter
		"system_health": "OK",
	}

	a.respondJSON(w, stats, http.StatusOK)
}

// getDashboardChart godoc
//
//	@Summary		Get dashboard chart data
//	@Description	Returns historical chart data for events and alerts
//	@Tags			dashboard
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}	map[string]interface{}
//	@Failure		503	{string}	string	"Storage not available"
//	@Router			/api/dashboard/chart [get]
func (a *API) getDashboardChart(w http.ResponseWriter, r *http.Request) {
	if a.eventStorage == nil || a.alertStorage == nil {
		http.Error(w, "Storage not available", http.StatusServiceUnavailable)
		return
	}

	eventData, err := a.eventStorage.GetEventCountsByMonth(r.Context())
	if err != nil {
		a.logger.Errorw("Failed to get event counts", "error", err)
		http.Error(w, "Failed to retrieve event data", http.StatusInternalServerError)
		return
	}

	alertData, err := a.alertStorage.GetAlertCountsByMonth(r.Context())
	if err != nil {
		a.logger.Errorw("Failed to get alert counts", "error", err)
		http.Error(w, "Failed to retrieve alert data", http.StatusInternalServerError)
		return
	}

	// Merge event and alert data
	alertMap := make(map[string]int)
	for _, alert := range alertData {
		if name, ok := alert["name"].(string); ok {
			if a, ok := alert["alerts"].(int); ok {
				alertMap[name] = a
			}
		}
	}
	chartData := make([]map[string]interface{}, len(eventData))
	for i, event := range eventData {
		name := event["name"]
		events := event["events"]
		alerts := 0
		if nameStr, ok := name.(string); ok {
			alerts = alertMap[nameStr]
		}
		// Frontend ChartDataSchema expects: timestamp, events, alerts
		chartData[i] = map[string]interface{}{
			"timestamp": name, // Month name acts as timestamp label
			"events":    events,
			"alerts":    alerts,
		}
	}

	a.respondJSON(w, chartData, http.StatusOK)
}

// healthCheck godoc
//
//	@Summary		Health check
//	@Description	Returns the health status of the service
//	@Tags			system
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]string
//	@Router			/health [get]
func (a *API) healthCheck(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	if a.eventStorage == nil || a.alertStorage == nil {
		status = "degraded"
	}

	response := map[string]string{
		"status": status,
		"time":   time.Now().Format(time.RFC3339),
	}

	a.respondJSON(w, response, http.StatusOK)
}

// healthLive returns 200 if the process is running (liveness probe)
// Used by orchestrators to detect hung processes
// @Summary		Liveness probe
// @Description	Returns 200 if the process is running. No external dependency checks.
// @Tags		health
// @Produce		json
// @Success		200	{object}	map[string]string	"Process is running"
// @Router		/health/live [get]
func (a *API) healthLive(w http.ResponseWriter, r *http.Request) {
	a.respondJSON(w, map[string]string{
		"status": "alive",
		"time":   time.Now().Format(time.RFC3339),
	}, http.StatusOK)
}

// HealthReadyResponse represents the readiness probe response
type HealthReadyResponse struct {
	Status     string                     `json:"status"` // "ready" or "not_ready"
	Time       string                     `json:"time"`
	Components map[string]ComponentHealth `json:"components"`
}

// ComponentHealth represents the health of a single component
type ComponentHealth struct {
	Status  string `json:"status"` // "healthy", "unhealthy", "degraded"
	Message string `json:"message,omitempty"`
	Latency string `json:"latency,omitempty"` // How long the check took
}

// healthReady performs readiness checks on all critical components
// Used by orchestrators to determine if the service can receive traffic
// @Summary		Readiness probe
// @Description	Checks if ClickHouse and SQLite are accessible
// @Tags		health
// @Produce		json
// @Success		200	{object}	HealthReadyResponse	"Service is ready"
// @Failure		503	{object}	HealthReadyResponse	"Service is not ready"
// @Router		/health/ready [get]
func (a *API) healthReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	response := HealthReadyResponse{
		Status:     "ready",
		Time:       time.Now().Format(time.RFC3339),
		Components: make(map[string]ComponentHealth),
	}

	allHealthy := true

	// Check ClickHouse
	if a.clickhouse != nil {
		start := time.Now()
		err := a.clickhouse.Conn.Ping(ctx)
		latency := time.Since(start)

		if err != nil {
			allHealthy = false
			response.Components["clickhouse"] = ComponentHealth{
				Status:  "unhealthy",
				Message: err.Error(),
				Latency: latency.String(),
			}
		} else {
			response.Components["clickhouse"] = ComponentHealth{
				Status:  "healthy",
				Latency: latency.String(),
			}
		}
	} else {
		allHealthy = false
		response.Components["clickhouse"] = ComponentHealth{
			Status:  "unhealthy",
			Message: "not initialized",
		}
	}

	// Check SQLite
	if a.sqlite != nil {
		start := time.Now()
		err := a.sqlite.DB.PingContext(ctx)
		latency := time.Since(start)

		if err != nil {
			allHealthy = false
			response.Components["sqlite"] = ComponentHealth{
				Status:  "unhealthy",
				Message: err.Error(),
				Latency: latency.String(),
			}
		} else {
			response.Components["sqlite"] = ComponentHealth{
				Status:  "healthy",
				Latency: latency.String(),
			}
		}
	} else {
		allHealthy = false
		response.Components["sqlite"] = ComponentHealth{
			Status:  "unhealthy",
			Message: "not initialized",
		}
	}

	// Check event storage
	if a.eventStorage == nil {
		allHealthy = false
		response.Components["event_storage"] = ComponentHealth{
			Status:  "unhealthy",
			Message: "not initialized",
		}
	} else {
		response.Components["event_storage"] = ComponentHealth{Status: "healthy"}
	}

	// Check alert storage
	if a.alertStorage == nil {
		allHealthy = false
		response.Components["alert_storage"] = ComponentHealth{
			Status:  "unhealthy",
			Message: "not initialized",
		}
	} else {
		response.Components["alert_storage"] = ComponentHealth{Status: "healthy"}
	}

	if !allHealthy {
		response.Status = "not_ready"
		a.respondJSON(w, response, http.StatusServiceUnavailable)
		return
	}

	a.respondJSON(w, response, http.StatusOK)
}

// HealthDetailedResponse represents detailed health information
type HealthDetailedResponse struct {
	Status     string                     `json:"status"`
	Time       string                     `json:"time"`
	Uptime     string                     `json:"uptime"`
	Version    string                     `json:"version"`
	Components map[string]ComponentHealth `json:"components"`
	System     SystemInfo                 `json:"system"`
	Database   DatabaseInfo               `json:"database,omitempty"`
}

// SystemInfo represents system-level metrics
type SystemInfo struct {
	Goroutines int    `json:"goroutines"`
	HeapAlloc  string `json:"heap_alloc"`
	HeapSys    string `json:"heap_sys"`
	NumGC      uint32 `json:"num_gc"`
	CPUCores   int    `json:"cpu_cores"`
}

// DatabaseInfo represents database-specific information
type DatabaseInfo struct {
	SQLiteWALMode     string `json:"sqlite_wal_mode,omitempty"`
	ClickHouseVersion string `json:"clickhouse_version,omitempty"`
}

// healthDetailed returns comprehensive health and diagnostic information
// @Summary		Detailed health information
// @Description	Returns comprehensive health information including system metrics
// @Tags		health
// @Produce		json
// @Success		200	{object}	HealthDetailedResponse
// @Router		/health/detailed [get]
func (a *API) healthDetailed(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	response := HealthDetailedResponse{
		Status:     "healthy",
		Time:       time.Now().Format(time.RFC3339),
		Uptime:     time.Since(a.startTime).String(),
		Version:    "1.0.0", // TODO: Get from build info
		Components: make(map[string]ComponentHealth),
		System: SystemInfo{
			Goroutines: runtime.NumGoroutine(),
			HeapAlloc:  formatBytes(memStats.HeapAlloc),
			HeapSys:    formatBytes(memStats.HeapSys),
			NumGC:      memStats.NumGC,
			CPUCores:   runtime.NumCPU(),
		},
	}

	allHealthy := true
	dbInfo := DatabaseInfo{}

	// Check ClickHouse with version query
	if a.clickhouse != nil {
		start := time.Now()
		err := a.clickhouse.Conn.Ping(ctx)
		latency := time.Since(start)

		if err != nil {
			allHealthy = false
			response.Components["clickhouse"] = ComponentHealth{
				Status:  "unhealthy",
				Message: err.Error(),
				Latency: latency.String(),
			}
		} else {
			response.Components["clickhouse"] = ComponentHealth{
				Status:  "healthy",
				Latency: latency.String(),
			}

			// Get ClickHouse version
			var version string
			if err := a.clickhouse.Conn.QueryRow(ctx, "SELECT version()").Scan(&version); err == nil {
				dbInfo.ClickHouseVersion = version
			}
		}
	} else {
		allHealthy = false
		response.Components["clickhouse"] = ComponentHealth{
			Status:  "unhealthy",
			Message: "not initialized",
		}
	}

	// Check SQLite with WAL mode query
	if a.sqlite != nil {
		start := time.Now()
		err := a.sqlite.DB.PingContext(ctx)
		latency := time.Since(start)

		if err != nil {
			allHealthy = false
			response.Components["sqlite"] = ComponentHealth{
				Status:  "unhealthy",
				Message: err.Error(),
				Latency: latency.String(),
			}
		} else {
			response.Components["sqlite"] = ComponentHealth{
				Status:  "healthy",
				Latency: latency.String(),
			}

			// Get WAL mode
			var journalMode string
			if err := a.sqlite.DB.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err == nil {
				dbInfo.SQLiteWALMode = journalMode
			}
		}
	} else {
		allHealthy = false
		response.Components["sqlite"] = ComponentHealth{
			Status:  "unhealthy",
			Message: "not initialized",
		}
	}

	// Check event storage
	if a.eventStorage == nil {
		allHealthy = false
		response.Components["event_storage"] = ComponentHealth{
			Status:  "unhealthy",
			Message: "not initialized",
		}
	} else {
		response.Components["event_storage"] = ComponentHealth{Status: "healthy"}
	}

	// Check alert storage
	if a.alertStorage == nil {
		allHealthy = false
		response.Components["alert_storage"] = ComponentHealth{
			Status:  "unhealthy",
			Message: "not initialized",
		}
	} else {
		response.Components["alert_storage"] = ComponentHealth{Status: "healthy"}
	}

	// Check rule storage
	if a.ruleStorage == nil {
		response.Components["rule_storage"] = ComponentHealth{
			Status:  "degraded",
			Message: "not initialized",
		}
	} else {
		response.Components["rule_storage"] = ComponentHealth{Status: "healthy"}
	}

	// Check ML system
	if a.mlSystem == nil {
		response.Components["ml_system"] = ComponentHealth{
			Status:  "degraded",
			Message: "not initialized",
		}
	} else {
		response.Components["ml_system"] = ComponentHealth{Status: "healthy"}
	}

	// Check detector
	if a.detector == nil {
		response.Components["detector"] = ComponentHealth{
			Status:  "degraded",
			Message: "not initialized",
		}
	} else {
		response.Components["detector"] = ComponentHealth{Status: "healthy"}
	}

	response.Database = dbInfo

	if !allHealthy {
		response.Status = "degraded"
	}

	a.respondJSON(w, response, http.StatusOK)
}

// formatBytes converts bytes to human-readable format
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
