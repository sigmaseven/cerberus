# Task ID: 152

**Title:** Implement Request Tracing and Correlation IDs

**Status:** done

**Dependencies:** 144 ✓

**Priority:** high

**Description:** Add request ID generation, context propagation, and structured logging with correlation IDs across all service boundaries for distributed tracing.

**Details:**

Currently no request ID propagation or distributed tracing.

Missing:
- Request ID generation at API boundary
- Context value propagation
- Correlation in logs
- Tracing to external services (webhooks, ML APIs)

Impact:
- Cannot trace request flow through system
- Log aggregation impossible
- Debugging production issues takes hours
- No latency breakdown by component

Implementation:
1. Add request ID middleware:
   ```go
   // api/middleware.go
   func RequestIDMiddleware(next http.Handler) http.Handler {
     return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
       requestID := r.Header.Get("X-Request-ID")
       if requestID == "" {
         requestID = uuid.New().String()
       }
       ctx := context.WithValue(r.Context(), api.RequestIDKey, requestID)
       w.Header().Set("X-Request-ID", requestID)
       next.ServeHTTP(w, r.WithContext(ctx))
     })
   }
   ```
2. Create context key constants (use existing api/context_keys.go):
   ```go
   // api/context_keys.go
   const (
     RequestIDKey ctxKey = "request_id"
     UserIDKey    ctxKey = "user_id"
     SessionIDKey ctxKey = "session_id"
   )
   ```
3. Extract request ID in all logging:
   ```go
   func GetRequestID(ctx context.Context) string {
     if id, ok := ctx.Value(api.RequestIDKey).(string); ok {
       return id
     }
     return "unknown"
   }
   
   logger.Infow("processing request",
     "request_id", GetRequestID(ctx),
     "user_id", GetUserID(ctx),
     "operation", "create_rule")
   ```
4. Propagate to external services:
   ```go
   // HTTP client
   req.Header.Set("X-Request-ID", GetRequestID(ctx))
   
   // Database operations (add to query comments)
   query := fmt.Sprintf("/* request_id: %s */ SELECT ...", GetRequestID(ctx))
   ```
5. Add latency tracking by component:
   ```go
   func TraceOperation(ctx context.Context, component string, operation string) func() {
     start := time.Now()
     return func() {
       duration := time.Since(start)
       logger.Infow("operation_completed",
         "request_id", GetRequestID(ctx),
         "component", component,
         "operation", operation,
         "duration_ms", duration.Milliseconds())
       metrics.RecordLatency(component, operation, duration)
     }
   }
   
   // Usage
   defer TraceOperation(ctx, "storage", "create_rule")()
   ```
6. Structured logging format:
   - Use zap sugared logger throughout
   - Always include request_id field
   - Use consistent field names
   - Log levels: debug, info, warn, error

Integration with existing:
- api/context_keys.go already exists
- zap logger already configured
- Middleware chain already set up

**Test Strategy:**

1. Request ID generation test - verify unique IDs generated
2. Context propagation test - trace ID through all layers
3. Header propagation test - verify X-Request-ID in responses
4. External service test - verify request ID in webhook calls
5. Log aggregation test - query logs by request_id
6. Latency tracking test - verify component timing metrics
7. Integration test - end-to-end request trace validation

## Subtasks

### 152.1. Implement RequestIDMiddleware with X-Request-ID header handling

**Status:** pending  
**Dependencies:** None  

Create middleware to generate or extract request IDs from X-Request-ID headers and store in context using existing api/context_keys.go constants

**Details:**

Add RequestIDMiddleware function in api/middleware.go that: (1) checks for existing X-Request-ID header, (2) generates new UUID if missing, (3) stores in context using api.RequestIDKey from context_keys.go, (4) sets X-Request-ID response header, (5) integrates into existing middleware chain in main.go. Leverage existing context key infrastructure from Task 134. Handle edge cases: empty header values, malformed UUIDs, concurrent requests.

### 152.2. Create correlation ID helper utilities and integrate with zap logger

**Status:** pending  
**Dependencies:** 152.1  

Implement GetRequestID, GetUserID, GetSessionID context extraction helpers and update all logging statements to include correlation IDs

**Details:**

Create api/tracing.go with helper functions: GetRequestID(ctx), GetUserID(ctx), GetSessionID(ctx) that safely extract values from context using api/context_keys.go constants. Update existing zap logger calls across codebase (200+ statements in api/, detect/, storage/, ingest/) to include request_id field. Establish structured logging standards: consistent field names (request_id, user_id, operation, component), appropriate log levels. Handle nil context gracefully with 'unknown' fallback.

### 152.3. Implement component latency tracking with TraceOperation helper

**Status:** pending  
**Dependencies:** 152.2  

Create TraceOperation helper function for timing component operations and integrate with metrics recording system

**Details:**

Implement TraceOperation(ctx, component, operation) in api/tracing.go that returns defer-able closure for timing. Records: (1) operation start/completion in logs with request_id, (2) duration in milliseconds, (3) metrics via metrics.RecordLatency. Add component tracking for: API handlers, storage operations (SQLite/ClickHouse), detection engine, ingest pipeline, external service calls. Use defer pattern for automatic cleanup. Integrate with existing metrics/metrics.go infrastructure.

### 152.4. Propagate request IDs to external services and database queries

**Status:** pending  
**Dependencies:** 152.2  

Add request ID propagation to HTTP clients, webhook calls, ML API requests, and database query comments for audit logging

**Details:**

Implement request ID propagation: (1) HTTP client wrapper that adds X-Request-ID header to outgoing requests (webhooks in detect/actions.go, ML API calls), (2) database query comment injection for ClickHouse and SQLite (format: /* request_id: <id> */ SELECT...), (3) update notify/ package for notification tracking, (4) integrate with soar/ playbook execution. Create propagation utilities in api/tracing.go: PropagateRequestID(ctx, req), AddQueryComment(ctx, query). Handle external service failures gracefully.

### 152.5. Create end-to-end request tracing integration tests and log queries

**Status:** pending  
**Dependencies:** 152.1, 152.2, 152.3, 152.4  

Implement comprehensive integration tests validating request ID flow through entire system and create log aggregation queries for operational debugging

**Details:**

Create api/tracing_integration_test.go with tests: (1) full request lifecycle from API → storage → detection → action execution, (2) concurrent request isolation (verify no ID collisions), (3) error path tracing (verify request_id in error logs), (4) external service propagation validation, (5) log aggregation by request_id. Document log query patterns for operations team: filter by request_id, calculate latency percentiles by component, identify slow requests. Test async workflows: correlation rules, scheduled actions, background jobs.
