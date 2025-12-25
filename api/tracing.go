// Package api provides request tracing and correlation ID utilities.
// TASK 152: Implements distributed tracing for request correlation and latency tracking.
package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RequestTracingConfig holds configuration for request tracing behavior.
type RequestTracingConfig struct {
	// HeaderName is the HTTP header used for request IDs (default: X-Request-ID)
	HeaderName string
	// GenerateIfMissing controls whether to generate a new ID if not provided
	GenerateIfMissing bool
	// PropagateHeader controls whether to echo the request ID in the response
	PropagateHeader bool
	// LogRequests controls whether to log request start/end
	LogRequests bool
}

// DefaultTracingConfig returns the default tracing configuration.
func DefaultTracingConfig() RequestTracingConfig {
	return RequestTracingConfig{
		HeaderName:        "X-Request-ID",
		GenerateIfMissing: true,
		PropagateHeader:   true,
		LogRequests:       true,
	}
}

// requestIDMiddleware adds request ID tracking and timing to all requests.
// TASK 152.1: Implements X-Request-ID header handling for distributed tracing.
//
// Behavior:
//   - If X-Request-ID header is present in request, use that value
//   - If not present, generate a new UUID v4
//   - Set X-Request-ID in response headers for client correlation
//   - Store request ID and start time in context for downstream use
//   - Log request start (if enabled) with structured fields
//
// Security:
//   - Request IDs are sanitized to prevent log injection
//   - Maximum length enforced to prevent memory exhaustion
//   - Only alphanumeric characters, dashes, and underscores allowed
func (a *API) requestIDMiddleware(next http.Handler) http.Handler {
	config := DefaultTracingConfig()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Extract or generate request ID
		requestID := r.Header.Get(config.HeaderName)
		if requestID == "" && config.GenerateIfMissing {
			requestID = uuid.New().String()
		}

		// Sanitize request ID to prevent log injection attacks
		requestID = sanitizeRequestID(requestID)

		// Set response header for client correlation
		if config.PropagateHeader && requestID != "" {
			w.Header().Set(config.HeaderName, requestID)
		}

		// Create context with request ID and trace start time
		ctx := WithRequestID(r.Context(), requestID)
		ctx = WithTraceStart(ctx, start)

		// Log request start if enabled
		if config.LogRequests && a.logger != nil {
			a.logger.Debugw("request_started",
				"request_id", requestID,
				"method", r.Method,
				"path", r.URL.Path,
				"remote_addr", getRealIP(r, a.config.API.TrustProxy, a.config.API.TrustedProxyNetworks),
				"user_agent", r.UserAgent(),
			)
		}

		// Create response writer wrapper to capture status code
		wrapped := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default to 200
		}

		// Call next handler with updated context
		next.ServeHTTP(wrapped, r.WithContext(ctx))

		// Log request completion
		if config.LogRequests && a.logger != nil {
			duration := time.Since(start)
			a.logger.Infow("request_completed",
				"request_id", requestID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration_ms", duration.Milliseconds(),
				"duration", duration.String(),
			)
		}
	})
}

// responseWriterWrapper wraps http.ResponseWriter to capture the status code.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code before writing it.
func (w *responseWriterWrapper) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write implements http.ResponseWriter.Write and ensures status code is captured.
func (w *responseWriterWrapper) Write(b []byte) (int, error) {
	if !w.written {
		w.statusCode = http.StatusOK
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

// sanitizeRequestID cleans request ID to prevent log injection.
// Only allows alphanumeric characters, dashes, and underscores.
// Truncates to maximum 64 characters to prevent memory issues.
func sanitizeRequestID(id string) string {
	const maxLen = 64

	if id == "" {
		return ""
	}

	// Truncate if too long
	if len(id) > maxLen {
		id = id[:maxLen]
	}

	// Filter to safe characters only
	result := make([]byte, 0, len(id))
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' {
			result = append(result, c)
		}
	}

	return string(result)
}

// TraceOperation creates a function that logs operation completion with latency.
// TASK 152.3: Implements component latency tracking for distributed tracing.
//
// Usage:
//
//	defer TraceOperation(ctx, a.logger, "storage", "create_rule")()
//
// This will log when the operation completes with duration and request_id.
func TraceOperation(ctx interface{}, logger *zap.SugaredLogger, component, operation string) func() {
	start := time.Now()

	return func() {
		duration := time.Since(start)

		// Handle both context.Context and nil
		var requestID string
		if ctxVal, ok := ctx.(interface{ Value(interface{}) interface{} }); ok {
			if id, ok := ctxVal.Value(ContextKeyRequestID).(string); ok {
				requestID = id
			}
		}
		if requestID == "" {
			requestID = "unknown"
		}

		if logger != nil {
			logger.Debugw("operation_completed",
				"request_id", requestID,
				"component", component,
				"operation", operation,
				"duration_ms", duration.Milliseconds(),
				"duration", duration.String(),
			)
		}
	}
}

// LogWithRequestID creates a logger with the request ID field pre-attached.
// TASK 152.2: Creates correlation ID helper for structured logging.
//
// Usage:
//
//	logger := LogWithRequestID(ctx, a.logger)
//	logger.Info("processing event")  // Will include request_id field
func LogWithRequestID(ctx interface{}, logger *zap.SugaredLogger) *zap.SugaredLogger {
	if logger == nil {
		return nil
	}

	// Handle both context.Context and nil
	var requestID string
	if ctxVal, ok := ctx.(interface{ Value(interface{}) interface{} }); ok {
		if id, ok := ctxVal.Value(ContextKeyRequestID).(string); ok {
			requestID = id
		}
	}
	if requestID == "" {
		requestID = "unknown"
	}

	return logger.With("request_id", requestID)
}

// AddRequestIDToHeader adds the request ID from context to an outgoing HTTP request.
// TASK 152.4: Propagates request ID to external service calls.
//
// Usage:
//
//	req, _ := http.NewRequest("POST", url, body)
//	AddRequestIDToHeader(ctx, req)
//	client.Do(req)
func AddRequestIDToHeader(ctx interface{}, req *http.Request) {
	if req == nil {
		return
	}

	// Handle both context.Context and nil
	var requestID string
	if ctxVal, ok := ctx.(interface{ Value(interface{}) interface{} }); ok {
		if id, ok := ctxVal.Value(ContextKeyRequestID).(string); ok {
			requestID = id
		}
	}

	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
}

// FormatQueryWithRequestID adds a SQL comment with the request ID for query tracing.
// TASK 152.4: Adds request ID to database queries for correlation.
//
// Usage:
//
//	query := FormatQueryWithRequestID(ctx, "SELECT * FROM events WHERE id = $1")
//	// Returns: /* request_id: abc123 */ SELECT * FROM events WHERE id = $1
//
// Security: Request ID is sanitized to prevent SQL injection.
func FormatQueryWithRequestID(ctx interface{}, query string) string {
	// Handle both context.Context and nil
	var requestID string
	if ctxVal, ok := ctx.(interface{ Value(interface{}) interface{} }); ok {
		if id, ok := ctxVal.Value(ContextKeyRequestID).(string); ok {
			requestID = sanitizeRequestID(id)
		}
	}

	if requestID == "" {
		return query
	}

	// SQL comment syntax - request ID is already sanitized
	return "/* request_id: " + requestID + " */ " + query
}
