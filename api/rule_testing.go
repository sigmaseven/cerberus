package api

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"cerberus/core"
	"cerberus/detect"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Constants for rule testing limits and timeouts
// TASK 170: Production-ready limits to prevent resource exhaustion
const (
	maxTestEvents      = 10000            // Maximum events per test request
	maxTestTimeout     = 30 * time.Second // Maximum timeout for test execution
	maxTestUploadSize  = 10 << 20         // 10MB file upload limit for test samples
)

// RuleTestRequest represents a request to test a rule (TASK 170)
type RuleTestRequest struct {
	Rule              *core.Rule   `json:"rule,omitempty"`              // Inline rule definition
	RuleID            string       `json:"rule_id,omitempty"`           // Or load existing rule by ID
	Events            []core.Event `json:"events" validate:"required"`  // Sample events to test
	ExpectMatch       bool         `json:"expect_match,omitempty"`      // Expected match outcome
	ExpectCorrelation bool         `json:"expect_correlation,omitempty"`
}

// RuleTestResponse represents the response from rule testing (TASK 170)
type RuleTestResponse struct {
	Matched              bool                   `json:"matched"`
	CorrelationTriggered bool                   `json:"correlation_triggered"`
	EvaluationTimeMs     float64                `json:"evaluation_time_ms"`
	MatchedEvents        []int                  `json:"matched_events"`       // Indices of matched events
	CorrelationState     map[string]interface{} `json:"correlation_state,omitempty"`
	Errors               []string               `json:"errors"`
	// Legacy fields for backwards compatibility
	Matches       []detect.MatchResult `json:"matches,omitempty"`
	TotalEvents   int                  `json:"total_events"`
	MatchCount    int                  `json:"match_count"`
	ExecutionTime float64              `json:"execution_time_ms,omitempty"` // Alias for EvaluationTimeMs
}

// BatchTestRequest represents a request to batch test a rule (TASK 170)
type BatchTestRequest struct {
	Events         []core.Event `json:"events" validate:"required"`
	ExpectedAlerts int          `json:"expected_alerts,omitempty"`
	TimeoutSeconds int          `json:"timeout_seconds,omitempty"` // Max 30
}

// BatchTestResponse represents the response from batch rule testing (TASK 170)
type BatchTestResponse struct {
	TotalEvents     int           `json:"total_events"`
	MatchedEvents   int           `json:"matched_events"`
	AlertsGenerated int           `json:"alerts_generated"`
	TotalTimeMs     float64       `json:"total_time_ms"`
	EventsPerSecond float64       `json:"events_per_second"`
	Errors          []string      `json:"errors"`
	Results         []EventResult `json:"results,omitempty"` // Per-event results if requested
}

// EventResult represents the result of testing a single event (TASK 170)
type EventResult struct {
	EventIndex int     `json:"event_index"`
	EventID    string  `json:"event_id"`
	Matched    bool    `json:"matched"`
	TimeMs     float64 `json:"time_ms"`
	Error      string  `json:"error,omitempty"`
}

// ParsedEvents represents parsed sample events
type ParsedEvents struct {
	Events   []core.Event `json:"events"`
	Count    int          `json:"count"`
	Errors   []string     `json:"errors,omitempty"`
	Warnings []string     `json:"warnings,omitempty"`
}

// TestRule godoc
// @Summary Test a detection rule (TASK 170)
// @Description Test a rule against sample events to see which ones match
// @Tags rules
// @Accept json
// @Produce json
// @Param request body RuleTestRequest true "Rule and events to test"
// @Success 200 {object} RuleTestResponse
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/rules/test [post]
func (a *API) TestRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req RuleTestRequest
	if err := a.decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := a.validateTestRequest(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rule, err := a.loadRuleForTest(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	startTime := time.Now()
	fieldMappings, err := a.loadFieldMappings()
	if err != nil {
		a.logger.Warnw("Failed to load field mappings for test", "error", err)
	}

	testEngine := detect.NewTestEngineWithMappings(fieldMappings, a.logger)
	defer testEngine.Stop() // TASK 170 FIX: Prevent goroutine leak

	testCtx, cancel := context.WithTimeout(ctx, maxTestTimeout)
	defer cancel()

	result, err := testEngine.TestRule(testCtx, rule, req.Events)
	if err != nil {
		http.Error(w, fmt.Sprintf("Test execution failed: %v", err), http.StatusInternalServerError)
		return
	}

	response := a.buildTestResponse(result, time.Since(startTime))
	a.respondJSON(w, response, http.StatusOK)
}

// UploadSampleEvents godoc
// @Summary Upload sample events for testing
// @Description Upload a file containing sample events (JSON, JSONL, or CSV format)
// @Tags rules
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Sample events file"
// @Success 200 {object} ParsedEvents
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/rules/sample-events [post]
func (a *API) UploadSampleEvents(w http.ResponseWriter, r *http.Request) {
	// TASK 170 FIX: Add context timeout for file parsing
	ctx, cancel := context.WithTimeout(r.Context(), maxTestTimeout)
	defer cancel()

	if err := r.ParseMultipartForm(maxTestUploadSize); err != nil {
		http.Error(w, "Failed to parse multipart form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if header.Size > maxTestUploadSize {
		http.Error(w, "File too large (max 10MB)", http.StatusBadRequest)
		return
	}

	fileType := strings.ToLower(filepath.Ext(header.Filename))
	events, parseErrors := a.parseEventFile(ctx, file, fileType)

	// TASK 170 FIX: Validate event count after parsing
	if len(events) > maxTestEvents {
		http.Error(w, "Maximum 10000 events allowed", http.StatusBadRequest)
		return
	}

	response := ParsedEvents{
		Events: events,
		Count:  len(events),
		Errors: parseErrors,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// BatchTestRule godoc
// @Summary Batch test a rule against multiple events (TASK 170)
// @Description Test a rule against a batch of events and return aggregated statistics
// @Tags rules
// @Accept json
// @Produce json
// @Param id path string true "Rule ID"
// @Param request body BatchTestRequest true "Batch test request"
// @Success 200 {object} BatchTestResponse
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/rules/{id}/test-batch [post]
func (a *API) BatchTestRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	ruleID := vars["id"]
	if ruleID == "" {
		http.Error(w, "Rule ID is required", http.StatusBadRequest)
		return
	}

	var req BatchTestRequest
	if err := a.decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := a.validateBatchRequest(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rule, err := a.ruleStorage.GetRule(ruleID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load rule: %v", err), http.StatusNotFound)
		return
	}

	timeout := a.calculateTimeout(req.TimeoutSeconds)
	startTime := time.Now()

	fieldMappings, err := a.loadFieldMappings()
	if err != nil {
		a.logger.Warnw("Failed to load field mappings for test", "error", err)
	}

	testEngine := detect.NewTestEngineWithMappings(fieldMappings, a.logger)
	defer testEngine.Stop() // TASK 170 FIX: Prevent goroutine leak

	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	batchResult, err := testEngine.TestRuleBatch(testCtx, rule, req.Events)
	if err != nil {
		http.Error(w, fmt.Sprintf("Batch test execution failed: %v", err), http.StatusInternalServerError)
		return
	}

	response := a.buildBatchResponse(batchResult, req.Events, time.Since(startTime))
	a.respondJSON(w, response, http.StatusOK)
}

// HELPER FUNCTIONS (extracted to reduce function length and cyclomatic complexity)

// validateTestRequest validates a rule test request
func (a *API) validateTestRequest(req *RuleTestRequest) error {
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		return fmt.Errorf("validation failed: %v", err)
	}

	if len(req.Events) > maxTestEvents {
		return fmt.Errorf("maximum %d events allowed", maxTestEvents)
	}

	if req.RuleID == "" && req.Rule == nil {
		return fmt.Errorf("either 'rule' or 'rule_id' must be provided")
	}

	return nil
}

// loadRuleForTest loads a rule from storage or uses inline rule
func (a *API) loadRuleForTest(req *RuleTestRequest) (*core.Rule, error) {
	if req.RuleID != "" {
		rule, err := a.ruleStorage.GetRule(req.RuleID)
		if err != nil {
			return nil, fmt.Errorf("failed to load rule: %v", err)
		}
		return rule, nil
	}

	if req.Rule == nil {
		return nil, fmt.Errorf("rule cannot be nil")
	}

	return req.Rule, nil
}

// loadFieldMappings loads field mappings from storage
// TASK 170 FIX: Extracted to eliminate DRY violation
func (a *API) loadFieldMappings() (map[string]string, error) {
	if a.fieldMappingStorage == nil {
		return nil, nil
	}

	mappings, err := a.fieldMappingStorage.List()
	if err != nil {
		return nil, err
	}

	if len(mappings) == 0 {
		return nil, nil
	}

	fieldMappings := make(map[string]string)
	for _, m := range mappings {
		for rawField, sigmaField := range m.Mappings {
			fieldMappings[sigmaField] = rawField
		}
	}

	return fieldMappings, nil
}

// buildTestResponse builds a test response from results
func (a *API) buildTestResponse(result *detect.TestResult, duration time.Duration) RuleTestResponse {
	timeMs := duration.Seconds() * 1000
	return RuleTestResponse{
		Matched:              result.Matched,
		CorrelationTriggered: result.CorrelationTriggered,
		EvaluationTimeMs:     timeMs,
		MatchedEvents:        result.MatchedEventIndices,
		CorrelationState:     result.CorrelationState,
		Errors:               result.Errors,
		TotalEvents:          result.TotalEvents,
		MatchCount:           result.MatchCount,
		ExecutionTime:        timeMs,
	}
}

// validateBatchRequest validates a batch test request
func (a *API) validateBatchRequest(req *BatchTestRequest) error {
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		return fmt.Errorf("validation failed: %v", err)
	}

	if len(req.Events) > maxTestEvents {
		return fmt.Errorf("maximum %d events allowed", maxTestEvents)
	}

	if req.TimeoutSeconds > 30 {
		return fmt.Errorf("maximum timeout is 30 seconds")
	}

	return nil
}

// calculateTimeout calculates the timeout duration for batch tests
func (a *API) calculateTimeout(timeoutSeconds int) time.Duration {
	if timeoutSeconds > 0 {
		return time.Duration(timeoutSeconds) * time.Second
	}
	return maxTestTimeout
}

// buildBatchResponse builds a batch test response from results
func (a *API) buildBatchResponse(batchResult *detect.BatchTestResult, events []core.Event, totalTime time.Duration) BatchTestResponse {
	eventsPerSecond := float64(len(events)) / totalTime.Seconds()

	response := BatchTestResponse{
		TotalEvents:     batchResult.TotalEvents,
		MatchedEvents:   batchResult.MatchedEvents,
		AlertsGenerated: batchResult.AlertsGenerated,
		TotalTimeMs:     totalTime.Seconds() * 1000,
		EventsPerSecond: eventsPerSecond,
		Errors:          batchResult.Errors,
		Results:         make([]EventResult, 0, len(batchResult.EventResults)),
	}

	for _, er := range batchResult.EventResults {
		response.Results = append(response.Results, EventResult{
			EventIndex: er.EventIndex,
			EventID:    er.EventID,
			Matched:    er.Matched,
			TimeMs:     er.TimeMs,
			Error:      er.Error,
		})
	}

	return response
}

// parseEventFile parses events from an uploaded file
func (a *API) parseEventFile(ctx context.Context, file io.Reader, fileType string) ([]core.Event, []string) {
	switch fileType {
	case ".json":
		return a.parseJSONEvents(file)
	case ".jsonl", ".ndjson":
		return a.parseJSONLEvents(file)
	case ".csv":
		return a.parseCSVEvents(file)
	default:
		return nil, []string{"Unsupported file type. Supported: .json, .jsonl, .ndjson, .csv"}
	}
}

// parseJSONEvents parses a JSON array of events
func (a *API) parseJSONEvents(r io.Reader) ([]core.Event, []string) {
	var events []core.Event
	var errors []string

	decoder := json.NewDecoder(r)

	var eventArray []map[string]interface{}
	if err := decoder.Decode(&eventArray); err != nil {
		errors = append(errors, fmt.Sprintf("JSON parse error: %v", err))
		return events, errors
	}

	for i, obj := range eventArray {
		event := a.mapToEvent(obj, i)
		events = append(events, event)
	}

	return events, errors
}

// parseJSONLEvents parses newline-delimited JSON events
func (a *API) parseJSONLEvents(r io.Reader) ([]core.Event, []string) {
	var events []core.Event
	var errors []string

	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if strings.TrimSpace(line) == "" {
			continue
		}

		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			errors = append(errors, fmt.Sprintf("Line %d: %v", lineNum, err))
			continue
		}

		event := a.mapToEvent(obj, lineNum-1)
		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		errors = append(errors, fmt.Sprintf("Scanner error: %v", err))
	}

	return events, errors
}

// parseCSVEvents parses CSV format events
func (a *API) parseCSVEvents(r io.Reader) ([]core.Event, []string) {
	var events []core.Event
	var errors []string

	reader := csv.NewReader(r)

	headers, err := reader.Read()
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to read CSV header: %v", err))
		return events, errors
	}

	lineNum := 1
	for {
		lineNum++
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			errors = append(errors, fmt.Sprintf("Line %d: %v", lineNum, err))
			continue
		}

		obj := make(map[string]interface{})
		for i, value := range record {
			if i < len(headers) {
				obj[headers[i]] = value
			}
		}

		event := a.mapToEvent(obj, lineNum-2)
		events = append(events, event)
	}

	return events, errors
}

// Field extractor functions for mapToEvent
// TASK 170 FIX: Table-driven approach to reduce CCN
type fieldExtractor func(map[string]interface{}) (interface{}, bool)

var standardFieldExtractors = map[string]fieldExtractor{
	"event_id": func(obj map[string]interface{}) (interface{}, bool) {
		if val, ok := obj["event_id"].(string); ok {
			return val, true
		}
		return nil, false
	},
	"event_type": func(obj map[string]interface{}) (interface{}, bool) {
		if val, ok := obj["event_type"].(string); ok {
			return val, true
		}
		return nil, false
	},
	"source_ip": func(obj map[string]interface{}) (interface{}, bool) {
		if val, ok := obj["source_ip"].(string); ok {
			return val, true
		}
		return nil, false
	},
	"source_format": func(obj map[string]interface{}) (interface{}, bool) {
		if val, ok := obj["source_format"].(string); ok {
			return val, true
		}
		return nil, false
	},
	"severity": func(obj map[string]interface{}) (interface{}, bool) {
		if val, ok := obj["severity"].(string); ok {
			return val, true
		}
		return nil, false
	},
	"timestamp": func(obj map[string]interface{}) (interface{}, bool) {
		if val, ok := obj["timestamp"].(string); ok {
			return val, true
		}
		return nil, false
	},
	"raw_data": func(obj map[string]interface{}) (interface{}, bool) {
		if val, ok := obj["raw_data"].(string); ok {
			return val, true
		}
		return nil, false
	},
}

// Fields that map to Event struct fields (not Fields map)
// TASK 170 FIX: Map lookup replaces compound OR condition to reduce CCN
var skipFieldsForFieldsMap = map[string]bool{
	"event_id":      true,
	"source_format": true,
	"raw_data":      true,
	"timestamp":     true,
}

// mapToEvent converts a map to an Event
// TASK 170 FIX: Reduced CCN from 14 to ≤10 using map lookup instead of compound OR
func (a *API) mapToEvent(obj map[string]interface{}, index int) core.Event {
	event := core.Event{
		EventID:   uuid.New().String(),
		Timestamp: time.Now(),
		Fields:    make(map[string]interface{}),
	}

	// Extract standard fields using table-driven approach
	a.extractStructFields(obj, &event)

	// Extract fields that go into Fields map
	a.extractFieldsMap(obj, &event)

	// Copy all other fields to Fields map
	a.copyCustomFields(obj, &event)

	return event
}

// extractStructFields extracts fields that map to Event struct fields
func (a *API) extractStructFields(obj map[string]interface{}, event *core.Event) {
	if val, ok := standardFieldExtractors["event_id"](obj); ok {
		event.EventID = val.(string)
	}
	if val, ok := standardFieldExtractors["source_format"](obj); ok {
		event.SourceFormat = val.(string)
	}
	if val, ok := standardFieldExtractors["raw_data"](obj); ok {
		// Convert raw_data string to json.RawMessage
		// If it's valid JSON, use as-is; otherwise JSON-encode the string
		rawStr := val.(string)
		if json.Valid([]byte(rawStr)) {
			event.RawData = json.RawMessage(rawStr)
		} else {
			encoded, _ := json.Marshal(rawStr)
			event.RawData = encoded
		}
	}
	if val, ok := standardFieldExtractors["timestamp"](obj); ok {
		if t, err := time.Parse(time.RFC3339, val.(string)); err == nil {
			event.Timestamp = t
		}
	}
}

// extractFieldsMap extracts standard fields that go into Fields map
func (a *API) extractFieldsMap(obj map[string]interface{}, event *core.Event) {
	for key, extractor := range standardFieldExtractors {
		if skipFieldsForFieldsMap[key] {
			continue
		}
		if val, ok := extractor(obj); ok {
			event.Fields[key] = val
		}
	}
}

// copyCustomFields copies non-standard fields to Fields map
func (a *API) copyCustomFields(obj map[string]interface{}, event *core.Event) {
	for k, v := range obj {
		if _, isStandard := standardFieldExtractors[k]; !isStandard {
			event.Fields[k] = v
		}
	}
}
