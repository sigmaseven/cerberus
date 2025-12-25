package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cerberus/config"

	"go.uber.org/zap/zaptest"
)

func TestSanitizeRequestID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid UUID",
			input:    "550e8400-e29b-41d4-a716-446655440000",
			expected: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:     "alphanumeric only",
			input:    "abc123XYZ",
			expected: "abc123XYZ",
		},
		{
			name:     "with underscore",
			input:    "req_abc_123",
			expected: "req_abc_123",
		},
		{
			name:     "with special characters",
			input:    "req<script>alert(1)</script>123",
			expected: "reqscriptalert1script123",
		},
		{
			name:     "with newlines (log injection attempt)",
			input:    "abc\n\rINFO: fake log",
			expected: "abcINFOfakelog",
		},
		{
			name:     "with SQL injection attempt",
			input:    "abc'; DROP TABLE users; --",
			expected: "abcDROPTABLEusers--",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "too long (should truncate)",
			input:    strings.Repeat("a", 100),
			expected: strings.Repeat("a", 64),
		},
		{
			name:     "unicode characters",
			input:    "req-\u0000\u001f\u007f-123",
			expected: "req--123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeRequestID(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeRequestID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDefaultTracingConfig(t *testing.T) {
	config := DefaultTracingConfig()

	if config.HeaderName != "X-Request-ID" {
		t.Errorf("HeaderName = %q, want %q", config.HeaderName, "X-Request-ID")
	}
	if !config.GenerateIfMissing {
		t.Error("GenerateIfMissing should be true by default")
	}
	if !config.PropagateHeader {
		t.Error("PropagateHeader should be true by default")
	}
	if !config.LogRequests {
		t.Error("LogRequests should be true by default")
	}
}

func TestGetRequestID(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expectID string
		expectOK bool
	}{
		{
			name:     "with request ID",
			ctx:      WithRequestID(context.Background(), "test-id-123"),
			expectID: "test-id-123",
			expectOK: true,
		},
		{
			name:     "without request ID",
			ctx:      context.Background(),
			expectID: "",
			expectOK: false,
		},
		{
			name:     "with empty request ID",
			ctx:      WithRequestID(context.Background(), ""),
			expectID: "",
			expectOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, ok := GetRequestID(tt.ctx)
			if id != tt.expectID {
				t.Errorf("GetRequestID() id = %q, want %q", id, tt.expectID)
			}
			if ok != tt.expectOK {
				t.Errorf("GetRequestID() ok = %v, want %v", ok, tt.expectOK)
			}
		})
	}
}

func TestGetRequestIDOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name:     "with request ID",
			ctx:      WithRequestID(context.Background(), "test-id-123"),
			expected: "test-id-123",
		},
		{
			name:     "without request ID",
			ctx:      context.Background(),
			expected: "unknown",
		},
		{
			name:     "with empty request ID",
			ctx:      WithRequestID(context.Background(), ""),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRequestIDOrDefault(tt.ctx)
			if result != tt.expected {
				t.Errorf("GetRequestIDOrDefault() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestWithRequestID(t *testing.T) {
	ctx := context.Background()
	requestID := "test-request-id"

	newCtx := WithRequestID(ctx, requestID)

	// Verify the context is different
	if ctx == newCtx {
		t.Error("WithRequestID should return a new context")
	}

	// Verify the value is stored
	id, ok := GetRequestID(newCtx)
	if !ok || id != requestID {
		t.Errorf("GetRequestID() = (%q, %v), want (%q, true)", id, ok, requestID)
	}
}

func TestTraceOperation(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctx := WithRequestID(context.Background(), "test-trace-123")

	// Verify TraceOperation returns a function
	done := TraceOperation(ctx, logger, "test-component", "test-operation")
	if done == nil {
		t.Error("TraceOperation should return a non-nil function")
	}

	// Call the done function (should not panic)
	done()
}

func TestTraceOperation_NilLogger(t *testing.T) {
	ctx := WithRequestID(context.Background(), "test-trace-123")

	// Should not panic with nil logger
	done := TraceOperation(ctx, nil, "test-component", "test-operation")
	done() // Should not panic
}

func TestTraceOperation_NilContext(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	// Should not panic with nil context
	done := TraceOperation(nil, logger, "test-component", "test-operation")
	done() // Should not panic
}

func TestLogWithRequestID(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctx := WithRequestID(context.Background(), "test-log-123")

	// Should return a logger with request_id field
	loggerWithID := LogWithRequestID(ctx, logger)
	if loggerWithID == nil {
		t.Error("LogWithRequestID should return a non-nil logger")
	}

	// The logger should be usable
	loggerWithID.Info("test message")
}

func TestLogWithRequestID_NilLogger(t *testing.T) {
	ctx := WithRequestID(context.Background(), "test-log-123")

	// Should return nil for nil logger
	result := LogWithRequestID(ctx, nil)
	if result != nil {
		t.Error("LogWithRequestID with nil logger should return nil")
	}
}

func TestLogWithRequestID_NoRequestID(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctx := context.Background()

	// Should return a logger even without request ID
	loggerWithID := LogWithRequestID(ctx, logger)
	if loggerWithID == nil {
		t.Error("LogWithRequestID should return a non-nil logger")
	}
}

func TestAddRequestIDToHeader(t *testing.T) {
	tests := []struct {
		name           string
		ctx            context.Context
		expectedHeader string
	}{
		{
			name:           "with request ID",
			ctx:            WithRequestID(context.Background(), "header-test-123"),
			expectedHeader: "header-test-123",
		},
		{
			name:           "without request ID",
			ctx:            context.Background(),
			expectedHeader: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			AddRequestIDToHeader(tt.ctx, req)

			header := req.Header.Get("X-Request-ID")
			if header != tt.expectedHeader {
				t.Errorf("X-Request-ID header = %q, want %q", header, tt.expectedHeader)
			}
		})
	}
}

func TestAddRequestIDToHeader_NilRequest(t *testing.T) {
	ctx := WithRequestID(context.Background(), "test-123")

	// Should not panic with nil request
	AddRequestIDToHeader(ctx, nil)
}

func TestFormatQueryWithRequestID(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		query    string
		expected string
	}{
		{
			name:     "with request ID",
			ctx:      WithRequestID(context.Background(), "query-test-123"),
			query:    "SELECT * FROM events",
			expected: "/* request_id: query-test-123 */ SELECT * FROM events",
		},
		{
			name:     "without request ID",
			ctx:      context.Background(),
			query:    "SELECT * FROM events",
			expected: "SELECT * FROM events",
		},
		{
			name:     "with SQL injection in request ID",
			ctx:      WithRequestID(context.Background(), "'; DROP TABLE users; --"),
			query:    "SELECT * FROM events",
			expected: "/* request_id: DROPTABLEusers-- */ SELECT * FROM events",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatQueryWithRequestID(tt.ctx, tt.query)
			if result != tt.expected {
				t.Errorf("FormatQueryWithRequestID() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestResponseWriterWrapper(t *testing.T) {
	recorder := httptest.NewRecorder()
	wrapper := &responseWriterWrapper{
		ResponseWriter: recorder,
		statusCode:     http.StatusOK,
	}

	// Test default status code
	if wrapper.statusCode != http.StatusOK {
		t.Errorf("default statusCode = %d, want %d", wrapper.statusCode, http.StatusOK)
	}

	// Test WriteHeader
	wrapper.WriteHeader(http.StatusCreated)
	if wrapper.statusCode != http.StatusCreated {
		t.Errorf("after WriteHeader statusCode = %d, want %d", wrapper.statusCode, http.StatusCreated)
	}

	// Test that WriteHeader only captures once
	wrapper.WriteHeader(http.StatusBadRequest)
	if wrapper.statusCode != http.StatusCreated {
		t.Errorf("after second WriteHeader statusCode = %d, want %d (should not change)", wrapper.statusCode, http.StatusCreated)
	}
}

func TestResponseWriterWrapper_Write(t *testing.T) {
	recorder := httptest.NewRecorder()
	wrapper := &responseWriterWrapper{
		ResponseWriter: recorder,
		statusCode:     http.StatusOK,
	}

	// Write should set written flag
	_, err := wrapper.Write([]byte("test"))
	if err != nil {
		t.Errorf("Write error: %v", err)
	}
	if !wrapper.written {
		t.Error("Write should set written flag")
	}
}

func TestWithTraceStart(t *testing.T) {
	ctx := context.Background()
	start := time.Now()

	newCtx := WithTraceStart(ctx, start)

	// Verify the context is different
	if ctx == newCtx {
		t.Error("WithTraceStart should return a new context")
	}

	// Verify the value is stored
	val, ok := GetTraceStart(newCtx)
	if !ok {
		t.Error("GetTraceStart should return true")
	}
	if val != start {
		t.Errorf("GetTraceStart() value mismatch")
	}
}

func TestGetTraceStart_NotSet(t *testing.T) {
	ctx := context.Background()

	val, ok := GetTraceStart(ctx)
	if ok {
		t.Error("GetTraceStart should return false when not set")
	}
	if val != nil {
		t.Error("GetTraceStart should return nil when not set")
	}
}

// TestRequestIDMiddleware_Integration tests the middleware in isolation
// using a mock API structure
func TestRequestIDMiddleware_Integration(t *testing.T) {
	// Create a mock API with minimal configuration
	logger := zaptest.NewLogger(t).Sugar()

	tests := []struct {
		name                string
		inputRequestID      string
		expectedIDPresent   bool
		expectedIDGenerated bool
	}{
		{
			name:                "provided request ID is used",
			inputRequestID:      "provided-id-123",
			expectedIDPresent:   true,
			expectedIDGenerated: false,
		},
		{
			name:                "request ID generated when missing",
			inputRequestID:      "",
			expectedIDPresent:   true,
			expectedIDGenerated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedRequestID string

			// Create a handler that captures the request ID from context
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id, _ := GetRequestID(r.Context())
				capturedRequestID = id
				w.WriteHeader(http.StatusOK)
			})

			// Create minimal API for middleware test
			cfg := &config.Config{}
			cfg.API.TrustProxy = false
			cfg.API.TrustedProxyNetworks = nil
			api := &API{
				logger: logger,
				config: cfg,
			}

			// Wrap with middleware
			wrapped := api.requestIDMiddleware(handler)

			// Create request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.inputRequestID != "" {
				req.Header.Set("X-Request-ID", tt.inputRequestID)
			}

			// Execute
			recorder := httptest.NewRecorder()
			wrapped.ServeHTTP(recorder, req)

			// Verify response header
			responseID := recorder.Header().Get("X-Request-ID")
			if tt.expectedIDPresent && responseID == "" {
				t.Error("X-Request-ID header should be present in response")
			}

			// Verify context had request ID
			if tt.expectedIDPresent && capturedRequestID == "" {
				t.Error("Request ID should be in context")
			}

			// If provided, verify it matches
			if tt.inputRequestID != "" && capturedRequestID != tt.inputRequestID {
				t.Errorf("Request ID = %q, want %q", capturedRequestID, tt.inputRequestID)
			}

			// If generated, verify format (UUID)
			if tt.expectedIDGenerated && len(capturedRequestID) != 36 {
				t.Errorf("Generated request ID should be UUID format, got %q", capturedRequestID)
			}
		})
	}
}
