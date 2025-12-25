package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cerberus/core"
	"cerberus/search"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// SearchRequest represents a CQL search request
// TASK 4.7: API integration with error handling
type SearchRequest struct {
	Query          string     `json:"query" binding:"required"`
	Limit          int        `json:"limit,omitempty"`
	Offset         int        `json:"offset,omitempty"`
	Page           int        `json:"page,omitempty"` // Alternative to offset: page number (1-indexed)
	StartTime      *time.Time `json:"start_time,omitempty"`
	EndTime        *time.Time `json:"end_time,omitempty"`
	OrderBy        string     `json:"order_by,omitempty"`
	OrderDirection string     `json:"order_direction,omitempty"`
}

// SearchResponse represents a search response
// Matches frontend schema expectations: page, execution_time_ms at top level
type SearchResponse struct {
	Events          []*core.Event `json:"events"`
	Total           int64         `json:"total"`
	Page            int           `json:"page"`
	Limit           int           `json:"limit"`
	ExecutionTimeMs float64       `json:"execution_time_ms"`
	Query           string        `json:"query"`
	HasMore         bool          `json:"has_more,omitempty"`
}

// QueryValidationResponse represents query validation result
type QueryValidationResponse struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// searchEvents handles POST /api/v1/events/search
// TASK 4.7: API endpoint for CQL query execution with comprehensive error handling
//
//	@Summary		Search events with CQL
//	@Description	Execute a CQL query to search and filter security events
//	@Tags			events
//	@Accept			json
//	@Produce		json
//	@Param			request	body		SearchRequest	true	"Search request with CQL query"
//	@Success		200		{object}	SearchResponse	"Search results with pagination"
//	@Failure		400		{object}	map[string]string	"Invalid query syntax or request"
//	@Failure		500		{object}	map[string]string	"Query execution error"
//	@Failure		503		{object}	map[string]string	"Query timeout or service unavailable"
//	@Router			/api/v1/events/search [post]
func (a *API) searchEvents(w http.ResponseWriter, r *http.Request) {
	// Parse request body first (before checking connection)
	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate request (before checking connection)
	if err := a.validateSearchRequest(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	// Check if ClickHouse connection is available
	if a.eventStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Event storage not available", nil, a.logger)
		return
	}

	// Check if ClickHouse connection supports query execution
	clickhouseConn, ok := a.getClickHouseConnection()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "ClickHouse connection not available for query execution", nil, a.logger)
		return
	}

	// Create query executor
	executor := search.NewQueryExecutor(clickhouseConn, a.logger)

	// Calculate offset from page if page is provided
	offset := req.Offset
	page := 1
	if req.Page > 0 {
		page = req.Page
		offset = (req.Page - 1) * req.Limit
	} else if req.Offset > 0 && req.Limit > 0 {
		// Calculate page from offset
		page = (req.Offset / req.Limit) + 1
	}

	// Set query options
	opts := search.QueryOptions{
		Limit:          req.Limit,
		Offset:         offset,
		OrderBy:        req.OrderBy,
		OrderDirection: req.OrderDirection,
	}
	if req.StartTime != nil {
		opts.StartTime = *req.StartTime
	}
	if req.EndTime != nil {
		opts.EndTime = *req.EndTime
	}

	// Execute query
	ctx := r.Context()
	result, err := executor.Execute(ctx, req.Query, opts)

	// Handle errors with appropriate status codes
	// TASK 4.7: Map errors to appropriate HTTP status codes
	if err != nil {
		a.handleQueryError(w, err)
		return
	}

	// Build response matching frontend schema
	var executionTimeMs float64
	if result.Stats != nil {
		executionTimeMs = float64(result.Stats.ExecutionTime.Microseconds()) / 1000.0
	}

	response := SearchResponse{
		Events:          result.Events,
		Total:           result.Total,
		Page:            page,
		Limit:           result.Limit,
		ExecutionTimeMs: executionTimeMs,
		Query:           req.Query,
		HasMore:         result.HasMore,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// validateQuery handles POST /api/v1/events/search/validate
// TASK 4.7: Query validation endpoint with user-friendly error messages
//
//	@Summary		Validate CQL query
//	@Description	Validate a CQL query syntax without executing it
//	@Tags			events
//	@Accept			json
//	@Produce		json
//	@Param			query	body		map[string]string	true	"Query to validate"	example({"query": "source_ip = \"192.168.1.100\""})
//	@Success		200		{object}	QueryValidationResponse	"Validation result"
//	@Failure		400		{object}	map[string]string	"Invalid request"
//	@Router			/api/v1/events/search/validate [post]
func (a *API) validateQuery(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	query, ok := req["query"]
	if !ok || query == "" {
		writeError(w, http.StatusBadRequest, "Query parameter is required", nil, a.logger)
		return
	}

	// Parse query
	parser := search.NewParser(query)
	ast, err := parser.Parse()

	var validationResponse QueryValidationResponse
	if err != nil {
		// Parse error - provide user-friendly message
		validationResponse = QueryValidationResponse{
			Valid:  false,
			Errors: []string{a.formatParseError(err)},
		}
		a.respondJSON(w, validationResponse, http.StatusOK)
		return
	}

	// Validate AST
	if err := ast.Validate(); err != nil {
		validationResponse = QueryValidationResponse{
			Valid:  false,
			Errors: []string{a.formatValidationError(err)},
		}
		a.respondJSON(w, validationResponse, http.StatusOK)
		return
	}

	// Query is valid
	validationResponse = QueryValidationResponse{
		Valid: true,
	}
	a.respondJSON(w, validationResponse, http.StatusOK)
}

// getSearchFields handles GET /api/v1/events/search/fields
// TASK 4.7: Return available search fields
//
//	@Summary		Get search fields
//	@Description	Returns a list of available fields for event search
//	@Tags			events
//	@Produce		json
//	@Success		200	{array}		string	"List of searchable fields"
//	@Router			/api/v1/events/search/fields [get]
func (a *API) getSearchFields(w http.ResponseWriter, r *http.Request) {
	// Return common searchable fields
	fields := []string{
		"event_id",
		"timestamp",
		"@timestamp",
		"source_ip",
		"dest_ip",
		"source_port",
		"dest_port",
		"port",
		"severity",
		"event_type",
		"message",
		"source",
		"source_format",
		"listener_id",
		"listener_name",
		"bytes_sent",
		"bytes_received",
		"user.name",
		"user.id",
	}

	a.respondJSON(w, fields, http.StatusOK)
}

// getSearchOperators handles GET /api/v1/events/search/operators
// TASK 4.7: Return available operators
//
//	@Summary		Get search operators
//	@Description	Returns a list of available CQL operators
//	@Tags			events
//	@Produce		json
//	@Success		200	{array}		string	"List of operators"
//	@Router			/api/v1/events/search/operators [get]
func (a *API) getSearchOperators(w http.ResponseWriter, r *http.Request) {
	operators := []string{
		"=", "equals",
		"!=", "not_equals",
		">", "gt",
		"<", "lt",
		">=", "gte",
		"<=", "lte",
		"contains",
		"startswith",
		"endswith",
		"in",
		"not in",
		"exists",
		"not exists",
		"matches", "~=",
	}

	a.respondJSON(w, operators, http.StatusOK)
}

// Helper functions

// validateSearchRequest validates search request parameters
// TASK 4.7: Input validation with user-friendly error messages
func (a *API) validateSearchRequest(req *SearchRequest) error {
	// Trim whitespace and check for empty query
	req.Query = strings.TrimSpace(req.Query)
	if req.Query == "" {
		return errors.New("query parameter is required")
	}

	// Set defaults
	if req.Limit <= 0 {
		req.Limit = 100 // Default limit
	}
	if req.Limit > 10000 {
		return fmt.Errorf("limit cannot exceed 10000 (got %d)", req.Limit)
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	// Validate order direction
	if req.OrderDirection != "" && req.OrderDirection != "ASC" && req.OrderDirection != "DESC" {
		return fmt.Errorf("order_direction must be 'ASC' or 'DESC' (got '%s')", req.OrderDirection)
	}

	// Validate time range
	if req.StartTime != nil && req.EndTime != nil {
		if req.StartTime.After(*req.EndTime) {
			return errors.New("start_time must be before end_time")
		}
	}

	return nil
}

// handleQueryError maps query execution errors to HTTP status codes
// TASK 4.7: Comprehensive error handling with appropriate status codes
func (a *API) handleQueryError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}

	errStr := err.Error()

	// Check for timeout errors
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "context deadline exceeded") {
		writeError(w, http.StatusServiceUnavailable, "Query execution timeout - query took too long", err, a.logger)
		return
	}

	// Check for parse errors (should be caught earlier, but handle just in case)
	if strings.Contains(errStr, "failed to parse") || strings.Contains(errStr, "invalid query") {
		writeError(w, http.StatusBadRequest, a.formatParseError(err), err, a.logger)
		return
	}

	// Check for validation errors
	if strings.Contains(errStr, "validate") || strings.Contains(errStr, "validation") {
		writeError(w, http.StatusBadRequest, a.formatValidationError(err), err, a.logger)
		return
	}

	// Check for database connection errors
	if strings.Contains(errStr, "connection") || strings.Contains(errStr, "clickhouse") {
		writeError(w, http.StatusServiceUnavailable, "Database connection error - please try again later", err, a.logger)
		return
	}

	// Default to 500 Internal Server Error
	writeError(w, http.StatusInternalServerError, "Query execution failed", err, a.logger)
}

// formatParseError formats parse errors for user-friendly display
// TASK 4.7: User-friendly error messages
func (a *API) formatParseError(err error) string {
	if err == nil {
		return "Unknown parse error"
	}

	errStr := err.Error()

	// Extract position information if available
	if strings.Contains(errStr, "position") || strings.Contains(errStr, "line") {
		// Try to extract position
		return fmt.Sprintf("Syntax error in query: %s", errStr)
	}

	// Generic parse error
	if strings.Contains(errStr, "unexpected") {
		return fmt.Sprintf("Unexpected token in query: %s", errStr)
	}

	if strings.Contains(errStr, "expected") {
		return fmt.Sprintf("Expected token: %s", errStr)
	}

	// Return original error if no specific formatting
	return fmt.Sprintf("Query parse error: %s", errStr)
}

// formatValidationError formats validation errors for user-friendly display
// TASK 4.7: User-friendly error messages
func (a *API) formatValidationError(err error) string {
	if err == nil {
		return "Unknown validation error"
	}

	errStr := err.Error()

	// Format common validation errors
	if strings.Contains(errStr, "empty field name") {
		return "Field name cannot be empty"
	}

	if strings.Contains(errStr, "invalid operator") {
		// Extract operator name
		return fmt.Sprintf("Invalid operator: %s", errStr)
	}

	if strings.Contains(errStr, "missing value") {
		return fmt.Sprintf("Missing value for operator: %s", errStr)
	}

	// Return original error
	return fmt.Sprintf("Query validation error: %s", errStr)
}

// getClickHouseConnection retrieves ClickHouse connection from storage
// Helper to access ClickHouse connection for query execution
func (a *API) getClickHouseConnection() (driver.Conn, bool) {
	// Use stored connection if available
	if a.clickhouseConn != nil {
		return a.clickhouseConn, true
	}
	return nil, false
}

// SetClickHouseConnection sets the ClickHouse connection for query execution
// TASK 4.7: Set ClickHouse connection for search endpoints
func (a *API) SetClickHouseConnection(conn driver.Conn) {
	a.clickhouseConn = conn
}
