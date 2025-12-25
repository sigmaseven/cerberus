package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"cerberus/core"
	"cerberus/search"
	"cerberus/storage"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Visual Correlation Builder Handlers
// Implements the API contract from VISUAL_BUILDER_BACKEND_INTEGRATION.md

// UUID validation regex (UUID v4 format)
var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// createVisualCorrelation godoc
//
//	@Summary		Create visual correlation rule
//	@Description	Create a new correlation rule from the visual builder
//	@Tags			correlations
//	@Accept			json
//	@Produce		json
//	@Param			rule	body		CorrelationCreateRequest	true	"Visual correlation rule"
//	@Success		201		{object}	VisualCorrelationResponse
//	@Failure		400		{object}	VisualCorrelationResponse	"Validation error"
//	@Failure		503		{object}	VisualCorrelationResponse	"Service unavailable"
//	@Router			/api/correlations [post]
func (a *API) createVisualCorrelation(w http.ResponseWriter, r *http.Request) {
	// Fail-fast checks
	if a.detector == nil {
		a.respondVisualError(w, http.StatusServiceUnavailable, "Detection engine not available", nil)
		return
	}
	if a.correlationRuleStorage == nil {
		a.respondVisualError(w, http.StatusServiceUnavailable, "Correlation rule storage not available", nil)
		return
	}

	// Decode request
	var req CorrelationCreateRequest
	if err := a.decodeJSONBodyWithLimit(w, r, &req, 1*1024*1024); err != nil {
		return // Error already written
	}

	// Validate the request
	if err := a.validateVisualCorrelationCreate(&req); err != nil {
		a.respondVisualError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Convert to core.CorrelationRule
	rule, err := a.convertVisualToCorrelationRule(&req)
	if err != nil {
		a.respondVisualError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	rule.ID = uuid.New().String()
	rule.CreatedAt = time.Now().UTC()
	rule.UpdatedAt = time.Now().UTC()

	// Store the rule
	if err := a.correlationRuleStorage.CreateCorrelationRule(rule); err != nil {
		a.logger.Errorw("Failed to create visual correlation rule", "error", err)
		a.respondVisualError(w, http.StatusInternalServerError, "Failed to create correlation rule", nil)
		return
	}

	// Hot-reload with rollback on failure
	rules, err := a.correlationRuleStorage.GetAllCorrelationRules()
	if err != nil {
		if deleteErr := a.correlationRuleStorage.DeleteCorrelationRule(rule.ID); deleteErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule creation", "rule_id", rule.ID, "error", deleteErr)
		}
		a.respondVisualError(w, http.StatusInternalServerError, "Failed to activate correlation rule", nil)
		return
	}

	if err := a.detector.ReloadCorrelationRules(rules); err != nil {
		if deleteErr := a.correlationRuleStorage.DeleteCorrelationRule(rule.ID); deleteErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule creation", "rule_id", rule.ID, "error", deleteErr)
		}
		a.respondVisualError(w, http.StatusInternalServerError, "Failed to activate correlation rule", nil)
		return
	}

	a.logger.Infow("Visual correlation rule created", "rule_id", rule.ID, "type", req.Type, "name", req.Name)

	// Return success response
	a.respondVisualSuccess(w, http.StatusCreated, map[string]interface{}{
		"id": rule.ID,
	})
}

// updateVisualCorrelation godoc
//
//	@Summary		Update visual correlation rule
//	@Description	Update an existing correlation rule from the visual builder
//	@Tags			correlations
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"Correlation Rule ID"
//	@Param			rule	body		CorrelationUpdateRequest	true	"Visual correlation rule update"
//	@Success		200		{object}	VisualCorrelationResponse
//	@Failure		400		{object}	VisualCorrelationResponse	"Validation error"
//	@Failure		404		{object}	VisualCorrelationResponse	"Not found"
//	@Failure		503		{object}	VisualCorrelationResponse	"Service unavailable"
//	@Router			/api/correlations/{id} [put]
func (a *API) updateVisualCorrelation(w http.ResponseWriter, r *http.Request) {
	// Fail-fast checks
	if a.detector == nil {
		a.respondVisualError(w, http.StatusServiceUnavailable, "Detection engine not available", nil)
		return
	}
	if a.correlationRuleStorage == nil {
		a.respondVisualError(w, http.StatusServiceUnavailable, "Correlation rule storage not available", nil)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID format
	if id == "" || len(id) > 100 {
		a.respondVisualError(w, http.StatusBadRequest, "Invalid correlation rule ID format", nil)
		return
	}

	// Get existing rule for rollback
	oldRule, err := a.correlationRuleStorage.GetCorrelationRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			a.respondVisualError(w, http.StatusNotFound, "Correlation rule not found", nil)
		} else {
			a.respondVisualError(w, http.StatusInternalServerError, "Failed to get existing correlation rule", nil)
		}
		return
	}

	// Decode request
	var req CorrelationUpdateRequest
	if err := a.decodeJSONBodyWithLimit(w, r, &req, 1*1024*1024); err != nil {
		return // Error already written
	}

	// Validate the update request
	if err := a.validateVisualCorrelationUpdate(&req); err != nil {
		a.respondVisualError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Apply updates to the rule
	rule, err := a.applyVisualCorrelationUpdate(oldRule, &req)
	if err != nil {
		a.respondVisualError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	rule.ID = id
	rule.UpdatedAt = time.Now().UTC()

	// Update the rule
	if err := a.correlationRuleStorage.UpdateCorrelationRule(id, rule); err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			a.respondVisualError(w, http.StatusNotFound, "Correlation rule not found", nil)
		} else {
			a.respondVisualError(w, http.StatusInternalServerError, "Failed to update correlation rule", nil)
		}
		return
	}

	// Hot-reload with rollback on failure
	rules, err := a.correlationRuleStorage.GetAllCorrelationRules()
	if err != nil {
		if rollbackErr := a.correlationRuleStorage.UpdateCorrelationRule(id, oldRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule update", "rule_id", id, "error", rollbackErr)
		}
		a.respondVisualError(w, http.StatusInternalServerError, "Failed to activate correlation rule", nil)
		return
	}

	if err := a.detector.ReloadCorrelationRules(rules); err != nil {
		if rollbackErr := a.correlationRuleStorage.UpdateCorrelationRule(id, oldRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule update", "rule_id", id, "error", rollbackErr)
		}
		a.respondVisualError(w, http.StatusInternalServerError, "Failed to activate correlation rule", nil)
		return
	}

	a.logger.Infow("Visual correlation rule updated", "rule_id", id, "name", rule.Name)

	// Return success response
	a.respondVisualSuccess(w, http.StatusOK, map[string]interface{}{
		"id": id,
	})
}

// getVisualCorrelation godoc
//
//	@Summary		Get visual correlation rule
//	@Description	Get a correlation rule by ID with visual builder format
//	@Tags			correlations
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Correlation Rule ID"
//	@Success		200	{object}	VisualCorrelationResponse
//	@Failure		404	{object}	VisualCorrelationResponse	"Not found"
//	@Failure		503	{object}	VisualCorrelationResponse	"Service unavailable"
//	@Router			/api/correlations/{id} [get]
func (a *API) getVisualCorrelation(w http.ResponseWriter, r *http.Request) {
	if a.correlationRuleStorage == nil {
		a.respondVisualError(w, http.StatusServiceUnavailable, "Correlation rule storage not available", nil)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if id == "" || len(id) > 100 {
		a.respondVisualError(w, http.StatusBadRequest, "Invalid correlation rule ID format", nil)
		return
	}

	rule, err := a.correlationRuleStorage.GetCorrelationRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			a.respondVisualError(w, http.StatusNotFound, "Correlation rule not found", nil)
		} else {
			a.respondVisualError(w, http.StatusInternalServerError, "Failed to get correlation rule", nil)
		}
		return
	}

	// Convert to visual format
	visualData := a.convertCorrelationRuleToVisual(rule)

	a.respondVisualSuccess(w, http.StatusOK, visualData)
}

// listVisualCorrelations godoc
//
//	@Summary		List visual correlation rules
//	@Description	List all correlation rules with visual builder format
//	@Tags			correlations
//	@Accept			json
//	@Produce		json
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Items per page"
//	@Success		200		{object}	VisualCorrelationResponse
//	@Failure		503		{object}	VisualCorrelationResponse	"Service unavailable"
//	@Router			/api/correlations [get]
func (a *API) listVisualCorrelations(w http.ResponseWriter, r *http.Request) {
	if a.correlationRuleStorage == nil {
		a.respondVisualError(w, http.StatusServiceUnavailable, "Correlation rule storage not available", nil)
		return
	}

	// Parse pagination
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := parseInt(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := parseInt(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	offset := (page - 1) * limit

	rules, err := a.correlationRuleStorage.GetCorrelationRules(limit, offset)
	if err != nil {
		a.respondVisualError(w, http.StatusInternalServerError, "Failed to get correlation rules", nil)
		return
	}

	totalCount, err := a.correlationRuleStorage.GetCorrelationRuleCount()
	if err != nil {
		a.respondVisualError(w, http.StatusInternalServerError, "Failed to get correlation rule count", nil)
		return
	}

	// Convert rules to visual format
	visualRules := make([]map[string]interface{}, len(rules))
	for i, rule := range rules {
		visualRules[i] = a.convertCorrelationRuleToVisual(&rule)
	}

	totalPages := int(totalCount) / limit
	if int(totalCount)%limit > 0 {
		totalPages++
	}
	if totalPages < 1 {
		totalPages = 1
	}

	a.respondVisualSuccess(w, http.StatusOK, map[string]interface{}{
		"items":       visualRules,
		"total":       totalCount,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	})
}

// deleteVisualCorrelation godoc
//
//	@Summary		Delete visual correlation rule
//	@Description	Delete a correlation rule by ID
//	@Tags			correlations
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Correlation Rule ID"
//	@Success		200	{object}	VisualCorrelationResponse
//	@Failure		404	{object}	VisualCorrelationResponse	"Not found"
//	@Failure		503	{object}	VisualCorrelationResponse	"Service unavailable"
//	@Router			/api/correlations/{id} [delete]
func (a *API) deleteVisualCorrelation(w http.ResponseWriter, r *http.Request) {
	// Fail-fast checks
	if a.detector == nil {
		a.respondVisualError(w, http.StatusServiceUnavailable, "Detection engine not available", nil)
		return
	}
	if a.correlationRuleStorage == nil {
		a.respondVisualError(w, http.StatusServiceUnavailable, "Correlation rule storage not available", nil)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if id == "" || len(id) > 100 {
		a.respondVisualError(w, http.StatusBadRequest, "Invalid correlation rule ID format", nil)
		return
	}

	// Get rule for rollback
	deletedRule, err := a.correlationRuleStorage.GetCorrelationRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			a.respondVisualError(w, http.StatusNotFound, "Correlation rule not found", nil)
		} else {
			a.respondVisualError(w, http.StatusInternalServerError, "Failed to get correlation rule", nil)
		}
		return
	}

	// Delete the rule
	if err := a.correlationRuleStorage.DeleteCorrelationRule(id); err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			a.respondVisualError(w, http.StatusNotFound, "Correlation rule not found", nil)
		} else {
			a.respondVisualError(w, http.StatusInternalServerError, "Failed to delete correlation rule", nil)
		}
		return
	}

	// Hot-reload with rollback on failure
	rules, err := a.correlationRuleStorage.GetAllCorrelationRules()
	if err != nil {
		if rollbackErr := a.correlationRuleStorage.CreateCorrelationRule(deletedRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule deletion", "rule_id", id, "error", rollbackErr)
		}
		a.respondVisualError(w, http.StatusInternalServerError, "Failed to deactivate correlation rule", nil)
		return
	}

	if err := a.detector.ReloadCorrelationRules(rules); err != nil {
		if rollbackErr := a.correlationRuleStorage.CreateCorrelationRule(deletedRule); rollbackErr != nil {
			a.logger.Errorw("Failed to rollback correlation rule deletion", "rule_id", id, "error", rollbackErr)
		}
		a.respondVisualError(w, http.StatusInternalServerError, "Failed to deactivate correlation rule", nil)
		return
	}

	a.logger.Infow("Visual correlation rule deleted", "rule_id", id)

	a.respondVisualSuccess(w, http.StatusOK, map[string]interface{}{
		"id":     id,
		"status": "deleted",
	})
}

// Response helpers

func (a *API) respondVisualSuccess(w http.ResponseWriter, statusCode int, data map[string]interface{}) {
	response := VisualCorrelationResponse{
		Success: true,
		Data:    data,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func (a *API) respondVisualError(w http.ResponseWriter, statusCode int, message string, detail *ValidationErrorDetail) {
	response := VisualCorrelationResponse{
		Success: false,
		Error:   message,
		Details: detail,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// Validation functions

func (a *API) validateVisualCorrelationCreate(req *CorrelationCreateRequest) error {
	// Validate name
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(req.Name) > 100 {
		return fmt.Errorf("name must be at most 100 characters")
	}

	// Validate description
	if len(req.Description) > 2000 {
		return fmt.Errorf("description must be at most 2000 characters")
	}

	// Validate type
	if !isValidCorrelationType(req.Type) {
		return fmt.Errorf("invalid correlation type: %s", req.Type)
	}

	// Validate severity
	if !isValidSeverity(req.Severity) {
		return fmt.Errorf("invalid severity: %s", req.Severity)
	}

	// Validate config based on type
	if req.Config == nil {
		return fmt.Errorf("config is required")
	}

	return a.validateCorrelationConfig(req.Type, req.Config)
}

func (a *API) validateVisualCorrelationUpdate(req *CorrelationUpdateRequest) error {
	// Validate name if provided
	if req.Name != nil {
		if *req.Name == "" {
			return fmt.Errorf("name cannot be empty")
		}
		if len(*req.Name) > 100 {
			return fmt.Errorf("name must be at most 100 characters")
		}
	}

	// Validate description if provided
	if req.Description != nil && len(*req.Description) > 2000 {
		return fmt.Errorf("description must be at most 2000 characters")
	}

	// Validate severity if provided
	if req.Severity != nil && !isValidSeverity(*req.Severity) {
		return fmt.Errorf("invalid severity: %s", *req.Severity)
	}

	// Validate type if provided
	if req.Type != nil && !isValidCorrelationType(*req.Type) {
		return fmt.Errorf("invalid correlation type: %s", *req.Type)
	}

	// Validate config if type is provided
	if req.Type != nil && req.Config != nil {
		return a.validateCorrelationConfig(*req.Type, req.Config)
	}

	return nil
}

func (a *API) validateCorrelationConfig(corrType CorrelationType, config map[string]interface{}) error {
	switch corrType {
	case CorrelationTypeCount:
		return a.validateCountConfig(config)
	case CorrelationTypeValueCount:
		return a.validateValueCountConfig(config)
	case CorrelationTypeSequence:
		return a.validateSequenceConfig(config)
	case CorrelationTypeRare:
		return a.validateRareConfig(config)
	case CorrelationTypeStatistical:
		return a.validateStatisticalConfig(config)
	case CorrelationTypeCrossEntity:
		return a.validateCrossEntityConfig(config)
	case CorrelationTypeChain:
		return a.validateChainConfig(config)
	default:
		return fmt.Errorf("unsupported correlation type: %s", corrType)
	}
}

func (a *API) validateCountConfig(config map[string]interface{}) error {
	// Validate baseQuery
	if err := a.validateCqlQueryInConfig(config, "baseQuery"); err != nil {
		return err
	}

	// Validate threshold
	threshold, ok := config["threshold"]
	if !ok {
		return fmt.Errorf("config.threshold is required")
	}
	if t, ok := threshold.(float64); ok {
		if t < 1 {
			return fmt.Errorf("config.threshold must be at least 1")
		}
	}

	// Validate timeWindow
	if err := validateTimeWindowInConfig(config, "timeWindow"); err != nil {
		return err
	}

	return nil
}

func (a *API) validateValueCountConfig(config map[string]interface{}) error {
	if err := a.validateCqlQueryInConfig(config, "baseQuery"); err != nil {
		return err
	}

	// Validate countField
	if _, ok := config["countField"]; !ok {
		return fmt.Errorf("config.countField is required")
	}

	// Validate distinctThreshold
	threshold, ok := config["distinctThreshold"]
	if !ok {
		return fmt.Errorf("config.distinctThreshold is required")
	}
	if t, ok := threshold.(float64); ok {
		if t < 1 {
			return fmt.Errorf("config.distinctThreshold must be at least 1")
		}
	}

	if err := validateTimeWindowInConfig(config, "timeWindow"); err != nil {
		return err
	}

	return nil
}

func (a *API) validateSequenceConfig(config map[string]interface{}) error {
	// Validate steps
	steps, ok := config["steps"]
	if !ok {
		return fmt.Errorf("config.steps is required")
	}
	stepsSlice, ok := steps.([]interface{})
	if !ok {
		return fmt.Errorf("config.steps must be an array")
	}
	if len(stepsSlice) < 2 {
		return fmt.Errorf("config.steps must have at least 2 steps")
	}

	// Validate each step's query
	for i, step := range stepsSlice {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			return fmt.Errorf("config.steps[%d] must be an object", i)
		}
		if err := a.validateCqlQueryInConfig(stepMap, "query"); err != nil {
			return fmt.Errorf("config.steps[%d].query: %w", i, err)
		}
	}

	if err := validateTimeWindowInConfig(config, "maxTotalWindow"); err != nil {
		return err
	}

	return nil
}

func (a *API) validateRareConfig(config map[string]interface{}) error {
	if err := a.validateCqlQueryInConfig(config, "baseQuery"); err != nil {
		return err
	}

	if _, ok := config["rarityField"]; !ok {
		return fmt.Errorf("config.rarityField is required")
	}

	// Validate rarityThreshold (0-100)
	threshold, ok := config["rarityThreshold"]
	if !ok {
		return fmt.Errorf("config.rarityThreshold is required")
	}
	if t, ok := threshold.(float64); ok {
		if t < 0 || t > 100 {
			return fmt.Errorf("config.rarityThreshold must be between 0 and 100")
		}
	}

	if err := validateTimeWindowInConfig(config, "baselinePeriod"); err != nil {
		return err
	}

	return nil
}

func (a *API) validateStatisticalConfig(config map[string]interface{}) error {
	if err := a.validateCqlQueryInConfig(config, "baseQuery"); err != nil {
		return err
	}

	if _, ok := config["metricField"]; !ok {
		return fmt.Errorf("config.metricField is required")
	}

	if _, ok := config["aggregation"]; !ok {
		return fmt.Errorf("config.aggregation is required")
	}

	if err := validateTimeWindowInConfig(config, "baselinePeriod"); err != nil {
		return err
	}

	if err := validateTimeWindowInConfig(config, "detectionWindow"); err != nil {
		return err
	}

	return nil
}

func (a *API) validateCrossEntityConfig(config map[string]interface{}) error {
	if err := a.validateCqlQueryInConfig(config, "sourceQuery"); err != nil {
		return err
	}
	if err := a.validateCqlQueryInConfig(config, "targetQuery"); err != nil {
		return err
	}

	// Validate entityMappings
	mappings, ok := config["entityMappings"]
	if !ok {
		return fmt.Errorf("config.entityMappings is required")
	}
	mappingsSlice, ok := mappings.([]interface{})
	if !ok || len(mappingsSlice) == 0 {
		return fmt.Errorf("config.entityMappings must be a non-empty array")
	}

	if err := validateTimeWindowInConfig(config, "timeWindow"); err != nil {
		return err
	}

	return nil
}

func (a *API) validateChainConfig(config map[string]interface{}) error {
	// Validate steps
	steps, ok := config["steps"]
	if !ok {
		return fmt.Errorf("config.steps is required")
	}
	stepsSlice, ok := steps.([]interface{})
	if !ok {
		return fmt.Errorf("config.steps must be an array")
	}
	if len(stepsSlice) < 2 {
		return fmt.Errorf("config.steps must have at least 2 rule references")
	}

	// Validate each step has a valid rule reference
	for i, step := range stepsSlice {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			return fmt.Errorf("config.steps[%d] must be an object", i)
		}

		ruleID, ok := stepMap["ruleId"].(string)
		if !ok || ruleID == "" {
			return fmt.Errorf("config.steps[%d].ruleId is required", i)
		}

		// Validate UUID format
		if !uuidRegex.MatchString(strings.ToLower(ruleID)) {
			return fmt.Errorf("config.steps[%d].ruleId must be a valid UUID", i)
		}

		// Verify rule exists
		if a.ruleStorage != nil {
			if _, err := a.ruleStorage.GetRule(ruleID); err != nil {
				if errors.Is(err, storage.ErrRuleNotFound) {
					return fmt.Errorf("config.steps[%d].ruleId references non-existent rule: %s", i, ruleID)
				}
			}
		}
	}

	return nil
}

func (a *API) validateCqlQueryInConfig(config map[string]interface{}, fieldName string) error {
	queryObj, ok := config[fieldName]
	if !ok {
		return fmt.Errorf("config.%s is required", fieldName)
	}

	queryMap, ok := queryObj.(map[string]interface{})
	if !ok {
		return fmt.Errorf("config.%s must be an object", fieldName)
	}

	query, ok := queryMap["query"].(string)
	if !ok || query == "" {
		return fmt.Errorf("config.%s.query is required", fieldName)
	}

	// Validate CQL syntax
	if err := a.validateCqlQuery(query); err != nil {
		return fmt.Errorf("config.%s.query: %w", fieldName, err)
	}

	return nil
}

func (a *API) validateCqlQuery(query string) error {
	// Check for dangerous patterns (SQL injection attempts)
	dangerousPatterns := []string{
		`;`,         // Stacked queries
		`--`,        // SQL comments
		`/*`,        // Block comments
		`#`,         // MySQL comments
		`UNION`,     // UNION attacks
		`WAITFOR`,   // Time-based attacks
		`SLEEP`,     // Time-based attacks
		`BENCHMARK`, // Time-based attacks
	}

	upperQuery := strings.ToUpper(query)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(upperQuery, pattern) {
			return fmt.Errorf("query contains potentially dangerous pattern: %s", pattern)
		}
	}

	// Parse the CQL query to validate syntax
	parser := search.NewParser(query)
	_, err := parser.Parse()
	if err != nil {
		return fmt.Errorf("invalid CQL syntax: %w", err)
	}

	return nil
}

func validateTimeWindowInConfig(config map[string]interface{}, fieldName string) error {
	tw, ok := config[fieldName]
	if !ok {
		return fmt.Errorf("config.%s is required", fieldName)
	}

	twMap, ok := tw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("config.%s must be an object", fieldName)
	}

	value, ok := twMap["value"].(float64)
	if !ok || value <= 0 {
		return fmt.Errorf("config.%s.value must be a positive number", fieldName)
	}

	unit, ok := twMap["unit"].(string)
	if !ok {
		return fmt.Errorf("config.%s.unit is required", fieldName)
	}

	validUnits := map[string]bool{
		"seconds": true,
		"minutes": true,
		"hours":   true,
		"days":    true,
	}
	if !validUnits[unit] {
		return fmt.Errorf("config.%s.unit must be one of: seconds, minutes, hours, days", fieldName)
	}

	return nil
}

func isValidCorrelationType(t CorrelationType) bool {
	validTypes := map[CorrelationType]bool{
		CorrelationTypeCount:       true,
		CorrelationTypeValueCount:  true,
		CorrelationTypeSequence:    true,
		CorrelationTypeRare:        true,
		CorrelationTypeStatistical: true,
		CorrelationTypeCrossEntity: true,
		CorrelationTypeChain:       true,
	}
	return validTypes[t]
}

func isValidSeverity(s string) bool {
	validSeverities := map[string]bool{
		"low":           true,
		"medium":        true,
		"high":          true,
		"critical":      true,
		"informational": true,
	}
	return validSeverities[strings.ToLower(s)]
}

// Conversion functions

func (a *API) convertVisualToCorrelationRule(req *CorrelationCreateRequest) (*core.CorrelationRule, error) {
	// Extract time window from config
	var window time.Duration
	if tw := extractTimeWindow(req.Config, "timeWindow"); tw != nil {
		window = tw.ToDuration()
	} else if tw := extractTimeWindow(req.Config, "maxTotalWindow"); tw != nil {
		window = tw.ToDuration()
	} else {
		window = 5 * time.Minute // Default
	}

	// Extract sequence from config if applicable
	var sequence []string
	if req.Type == CorrelationTypeSequence || req.Type == CorrelationTypeChain {
		if steps, ok := req.Config["steps"].([]interface{}); ok {
			for _, step := range steps {
				if stepMap, ok := step.(map[string]interface{}); ok {
					if name, ok := stepMap["name"].(string); ok {
						sequence = append(sequence, name)
					} else if ruleID, ok := stepMap["ruleId"].(string); ok {
						sequence = append(sequence, ruleID)
					}
				}
			}
		}
	}

	// Store the full config as JSON for advanced types
	configJSON, _ := json.Marshal(req.Config)

	rule := &core.CorrelationRule{
		Name:        sanitizeString(req.Name, 100),
		Description: sanitizeString(req.Description, 2000),
		Severity:    req.Severity,
		Window:      window,
		Sequence:    sequence,
		Actions:     []core.Action{}, // Visual builder creates rules without actions initially
		Version:     1,
	}

	// Store visual builder metadata in the Actions field as a special marker
	// This allows us to reconstruct the visual format later
	rule.Actions = append(rule.Actions, core.Action{
		ID:   "_visual_config",
		Type: string(req.Type),
		Config: map[string]interface{}{
			"type":   string(req.Type),
			"config": string(configJSON),
		},
	})

	return rule, nil
}

func (a *API) applyVisualCorrelationUpdate(existing *core.CorrelationRule, req *CorrelationUpdateRequest) (*core.CorrelationRule, error) {
	rule := *existing // Copy

	if req.Name != nil {
		rule.Name = sanitizeString(*req.Name, 100)
	}
	if req.Description != nil {
		rule.Description = sanitizeString(*req.Description, 2000)
	}
	if req.Severity != nil {
		rule.Severity = *req.Severity
	}

	// Update config if provided
	if req.Config != nil && req.Type != nil {
		// Extract time window
		if tw := extractTimeWindow(req.Config, "timeWindow"); tw != nil {
			rule.Window = tw.ToDuration()
		} else if tw := extractTimeWindow(req.Config, "maxTotalWindow"); tw != nil {
			rule.Window = tw.ToDuration()
		}

		// Update sequence
		if *req.Type == CorrelationTypeSequence || *req.Type == CorrelationTypeChain {
			var sequence []string
			if steps, ok := req.Config["steps"].([]interface{}); ok {
				for _, step := range steps {
					if stepMap, ok := step.(map[string]interface{}); ok {
						if name, ok := stepMap["name"].(string); ok {
							sequence = append(sequence, name)
						} else if ruleID, ok := stepMap["ruleId"].(string); ok {
							sequence = append(sequence, ruleID)
						}
					}
				}
			}
			rule.Sequence = sequence
		}

		// Update visual config marker
		configJSON, _ := json.Marshal(req.Config)
		found := false
		for i, action := range rule.Actions {
			if action.ID == "_visual_config" {
				rule.Actions[i].Type = string(*req.Type)
				rule.Actions[i].Config = map[string]interface{}{
					"type":   string(*req.Type),
					"config": string(configJSON),
				}
				found = true
				break
			}
		}
		if !found {
			rule.Actions = append(rule.Actions, core.Action{
				ID:   "_visual_config",
				Type: string(*req.Type),
				Config: map[string]interface{}{
					"type":   string(*req.Type),
					"config": string(configJSON),
				},
			})
		}
	}

	return &rule, nil
}

func (a *API) convertCorrelationRuleToVisual(rule *core.CorrelationRule) map[string]interface{} {
	result := map[string]interface{}{
		"id":          rule.ID,
		"name":        rule.Name,
		"description": rule.Description,
		"severity":    rule.Severity,
		"version":     rule.Version,
		"createdAt":   rule.CreatedAt.Format(time.RFC3339),
		"updatedAt":   rule.UpdatedAt.Format(time.RFC3339),
	}

	// Try to extract visual config from actions
	for _, action := range rule.Actions {
		if action.ID == "_visual_config" {
			if typeStr, ok := action.Config["type"].(string); ok {
				result["type"] = typeStr
			}
			if configStr, ok := action.Config["config"].(string); ok {
				var config map[string]interface{}
				if json.Unmarshal([]byte(configStr), &config) == nil {
					result["config"] = config
				}
			}
			break
		}
	}

	// If no visual config found, construct basic info
	if _, hasType := result["type"]; !hasType {
		result["type"] = "count" // Default
		result["config"] = map[string]interface{}{
			"timeWindow": map[string]interface{}{
				"value": int(rule.Window.Minutes()),
				"unit":  "minutes",
			},
		}
		result["supportsVisualEdit"] = false
	} else {
		result["supportsVisualEdit"] = true
	}

	return result
}

// Helper functions

func extractTimeWindow(config map[string]interface{}, fieldName string) *TimeWindow {
	tw, ok := config[fieldName]
	if !ok {
		return nil
	}

	twMap, ok := tw.(map[string]interface{})
	if !ok {
		return nil
	}

	value, ok := twMap["value"].(float64)
	if !ok {
		return nil
	}

	unit, ok := twMap["unit"].(string)
	if !ok {
		return nil
	}

	return &TimeWindow{
		Value: int(value),
		Unit:  TimeUnit(unit),
	}
}

// ToDuration converts TimeWindow to time.Duration
func (tw TimeWindow) ToDuration() time.Duration {
	switch tw.Unit {
	case TimeUnitSeconds:
		return time.Duration(tw.Value) * time.Second
	case TimeUnitMinutes:
		return time.Duration(tw.Value) * time.Minute
	case TimeUnitHours:
		return time.Duration(tw.Value) * time.Hour
	case TimeUnitDays:
		return time.Duration(tw.Value) * 24 * time.Hour
	default:
		return time.Duration(tw.Value) * time.Second
	}
}

func sanitizeString(s string, maxLen int) string {
	// Strip HTML entities
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "&", "&amp;")

	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}
