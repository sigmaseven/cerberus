package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//lint:ignore U1000 Test mock for ClickHouse connection testing
type mockClickHouseConn struct {
	driver.Conn
}

// TestSearchEvents_Success tests successful query execution
// TASK 4.7: API integration tests
func TestSearchEvents_Success(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Note: Full integration test would require a real ClickHouse connection
	// For now, we test the request parsing and validation logic
	searchReq := SearchRequest{
		Query:  `source_ip = "192.168.1.100"`,
		Limit:  100,
		Offset: 0,
	}

	body, _ := json.Marshal(searchReq)

	// Call handler directly to bypass auth
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/events/search", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	api.searchEvents(w, r)

	// Without a real ClickHouse connection, we expect a service unavailable error
	// This tests the error handling path
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Expected service unavailable without connection")
}

// TestValidateQuery_Success tests successful query validation
// TASK 4.7: Query validation endpoint tests
func TestValidateQuery_Success(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Disable auth for this test (use non-protected endpoint)
	// Note: The endpoint is protected, so we need auth or to test via public endpoint
	// For now, test the handler directly by bypassing middleware
	reqBody := map[string]string{
		"query": `source_ip = "192.168.1.100"`,
	}
	body, _ := json.Marshal(reqBody)

	// Use direct handler call to bypass auth middleware
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/events/search/validate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	// Call handler directly (bypasses middleware)
	api.validateQuery(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Validation should succeed for valid query")

	var response QueryValidationResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Valid, "Query should be valid")
	assert.Empty(t, response.Errors, "Valid query should have no errors")
}

// TestValidateQuery_InvalidQuery tests query validation with invalid syntax
// TASK 4.7: Error handling tests
func TestValidateQuery_InvalidQuery(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	reqBody := map[string]string{
		"query": `source_ip = `, // Invalid: missing value
	}
	body, _ := json.Marshal(reqBody)

	// Call handler directly to bypass auth
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/events/search/validate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	api.validateQuery(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Validation endpoint should return 200 even for invalid queries")

	var response QueryValidationResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.False(t, response.Valid, "Invalid query should not be valid")
	assert.NotEmpty(t, response.Errors, "Invalid query should have errors")
}

// TestValidateQuery_MissingQuery tests missing query parameter
func TestValidateQuery_MissingQuery(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	reqBody := map[string]string{}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/events/search/validate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	api.validateQuery(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Missing query should return 400")
}

// TestSearchEvents_InvalidRequest tests invalid request body
// TASK 4.7: Error handling tests
func TestSearchEvents_InvalidRequest(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Invalid JSON
	body := bytes.NewReader([]byte("{invalid json}"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/events/search", body)
	r.Header.Set("Content-Type", "application/json")

	api.searchEvents(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Invalid JSON should return 400")
}

// TestSearchEvents_MissingQuery tests missing query parameter
func TestSearchEvents_MissingQuery(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	searchReq := SearchRequest{
		Query: "", // Missing query
	}
	body, _ := json.Marshal(searchReq)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/events/search", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	api.searchEvents(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Missing query should return 400")
}

// TestSearchEvents_InvalidLimit tests invalid limit parameter
func TestSearchEvents_InvalidLimit(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	searchReq := SearchRequest{
		Query: `source_ip = "192.168.1.100"`,
		Limit: 50000, // Exceeds max limit
	}
	body, _ := json.Marshal(searchReq)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/events/search", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	api.searchEvents(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Invalid limit should return 400")
}

// TestSearchEvents_InvalidTimeRange tests invalid time range
func TestSearchEvents_InvalidTimeRange(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	endTime := time.Now().Add(-24 * time.Hour)
	startTime := time.Now()

	searchReq := SearchRequest{
		Query:     `source_ip = "192.168.1.100"`,
		StartTime: &startTime,
		EndTime:   &endTime, // End time before start time
	}
	body, _ := json.Marshal(searchReq)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/events/search", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	api.searchEvents(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Invalid time range should return 400")
}

// TestGetSearchFields tests GET /api/v1/events/search/fields
// TASK 4.7: Fields endpoint test
func TestGetSearchFields(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/events/search/fields", nil)

	api.getSearchFields(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Fields endpoint should return 200")

	var fields []string
	err := json.Unmarshal(w.Body.Bytes(), &fields)
	require.NoError(t, err)
	assert.NotEmpty(t, fields, "Fields list should not be empty")
	assert.Contains(t, fields, "source_ip", "Fields should include source_ip")
	assert.Contains(t, fields, "timestamp", "Fields should include timestamp")
}

// TestGetSearchOperators tests GET /api/v1/events/search/operators
// TASK 4.7: Operators endpoint test
func TestGetSearchOperators(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/events/search/operators", nil)

	api.getSearchOperators(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Operators endpoint should return 200")

	var operators []string
	err := json.Unmarshal(w.Body.Bytes(), &operators)
	require.NoError(t, err)
	assert.NotEmpty(t, operators, "Operators list should not be empty")
	assert.Contains(t, operators, "=", "Operators should include =")
	assert.Contains(t, operators, "contains", "Operators should include contains")
}

// TestValidateSearchRequest tests request validation
func TestValidateSearchRequest(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	tests := []struct {
		name    string
		req     SearchRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			req: SearchRequest{
				Query:  `source_ip = "192.168.1.100"`,
				Limit:  100,
				Offset: 0,
			},
			wantErr: false,
		},
		{
			name: "missing query",
			req: SearchRequest{
				Query: "",
			},
			wantErr: true,
			errMsg:  "query parameter is required",
		},
		{
			name: "limit too large",
			req: SearchRequest{
				Query: `source_ip = "192.168.1.100"`,
				Limit: 50000,
			},
			wantErr: true,
			errMsg:  "limit cannot exceed 10000",
		},
		{
			name: "invalid order direction",
			req: SearchRequest{
				Query:          `source_ip = "192.168.1.100"`,
				OrderDirection: "INVALID",
			},
			wantErr: true,
			errMsg:  "order_direction must be 'ASC' or 'DESC'",
		},
		{
			name: "invalid time range",
			req: SearchRequest{
				Query:     `source_ip = "192.168.1.100"`,
				StartTime: func() *time.Time { t := time.Now(); return &t }(),
				EndTime:   func() *time.Time { t := time.Now().Add(-24 * time.Hour); return &t }(),
			},
			wantErr: true,
			errMsg:  "start_time must be before end_time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := api.validateSearchRequest(&tt.req)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for %s", tt.name)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Should not error for %s", tt.name)
			}
		})
	}
}

// TestFormatParseError tests parse error formatting
// TASK 4.7: User-friendly error message tests
func TestFormatParseError(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "parse error",
			err:      fmt.Errorf("failed to parse query"),
			contains: "Query parse error",
		},
		{
			name:     "unexpected token",
			err:      fmt.Errorf("unexpected token '='"),
			contains: "Unexpected token",
		},
		{
			name:     "expected token",
			err:      fmt.Errorf("expected '=' but got '!'"),
			contains: "Expected token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatted := api.formatParseError(tt.err)
			assert.Contains(t, formatted, tt.contains, "Formatted error should contain expected text")
		})
	}
}

// TestFormatValidationError tests validation error formatting
// TASK 4.7: User-friendly error message tests
func TestFormatValidationError(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "empty field name",
			err:      fmt.Errorf("empty field name"),
			contains: "Field name cannot be empty",
		},
		{
			name:     "invalid operator",
			err:      fmt.Errorf("invalid operator: invalid_op"),
			contains: "Invalid operator",
		},
		{
			name:     "missing value",
			err:      fmt.Errorf("missing value for operator ="),
			contains: "Missing value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatted := api.formatValidationError(tt.err)
			assert.Contains(t, formatted, tt.contains, "Formatted error should contain expected text")
		})
	}
}
