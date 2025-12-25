# Backend Improvements PRD - Cerberus SIEM

## Overview
This PRD outlines critical backend improvements identified through comprehensive code analysis of the Cerberus SIEM codebase.

## Goals
- Improve code quality and maintainability
- Enhance security posture
- Optimize performance
- Increase test coverage
- Reduce technical debt

---

## Feature 1: Fix Go Vet Static Analysis Violations

### Priority: Critical

### Description
Fix all Go vet violations that prevent clean builds and indicate potential runtime issues.

### Requirements
1. Fix context leaks in testing package (context_benchmark_test.go, context_propagation_test.go) - ensure all context.WithCancel/WithTimeout have defer cancel()
2. Fix undefined symbol in main_sigma_init_test.go:33 (initializeDetector)
3. Fix mock interface mismatch in tests/integration/alert_lifecycle_e2e_test.go:83 (mockAlertStorage missing InsertAlert)
4. Fix variable redeclaration in ingest/manager_leak_test.go:45

### Success Criteria
- `go vet ./...` passes with zero warnings
- All tests compile and run successfully

---

## Feature 2: Replace context.Background() with Request Context

### Priority: Critical

### Description
Replace 45+ instances of context.Background() in production code with proper request context propagation to enable request cancellation and timeout enforcement.

### Requirements
1. Audit all context.Background() usage in api/, storage/, detect/ packages
2. Create context propagation middleware that injects request context
3. Update all handler functions to pass r.Context() to downstream calls
4. Add request timeout enforcement (default 30 seconds configurable)
5. Ensure graceful cancellation propagates to database queries

### Success Criteria
- Zero context.Background() calls in request handling paths
- Request cancellation properly terminates database queries
- 30-second default timeout on all API requests

---

## Feature 3: Add Missing Database Indexes

### Priority: High

### Description
Add database indexes on frequently queried columns to improve query performance.

### Requirements
1. Add index on alerts.created_at for time range queries
2. Add index on alerts.rule_id for filtering
3. Add index on alerts.assigned_to for user assignment queries
4. Add index on events.timestamp for retention policies
5. Add composite index on alerts(severity, status) for common filters
6. Create migration script for SQLite indexes
7. Create migration script for ClickHouse indexes

### Success Criteria
- All indexes created via migrations
- Query performance improved by 50%+ on filtered queries
- Backward compatible with existing data

---

## Feature 4: Implement Pagination for GetAll Methods

### Priority: High

### Description
Replace unbounded GetAll* methods with paginated queries to prevent memory exhaustion on large datasets.

### Requirements
1. Add pagination to GetAllRules() - currently called 71+ times in codebase
2. Add pagination to GetAllCorrelationRules()
3. Add pagination to GetAllAlerts() with proper total count
4. Fix TODO in api/handlers.go:76-79 - return actual total count from storage
5. Add MaxResults constant (default 10000) for safety limits
6. Update API responses to include pagination metadata

### Success Criteria
- All GetAll* methods support limit/offset parameters
- API responses include total count and pagination links
- No single query returns more than MaxResults items

---

## Feature 5: Complete TODO/FIXME Items in Production Code

### Priority: High

### Description
Address incomplete implementations marked with TODO/FIXME comments in production code paths.

### Requirements
1. Fix api/handlers.go:76-79 - implement actual total count query
2. Fix api/handlers.go:1061 - implement rules_fired counter
3. Fix api/handlers_ml.go:303 - implement actual memory usage metrics
4. Fix api/investigation_handlers.go:518 - implement alert linkback
5. Fix ml/extractors.go - implement 5 feature extractors (patterns, risk, anomaly, correlation, sequence)
6. Document remaining TODOs and create tickets

### Success Criteria
- All critical-path TODOs resolved
- Remaining TODOs have associated tickets
- No hardcoded placeholder values in production responses

---

## Feature 6: Reduce Function Complexity

### Priority: High

### Description
Refactor large functions exceeding 50 lines to improve testability and maintainability.

### Requirements
1. Refactor detect/engine.go processCorrelationEvents (70+ lines)
2. Refactor detect/engine.go evaluateCorrelationRule (85+ lines)
3. Refactor api/handlers.go getAlerts (150+ lines)
4. Refactor api/alert_handlers.go getAlerts (120+ lines)
5. Refactor storage/clickhouse_alerts.go query builders (60-80+ lines)
6. Refactor detect/sigma_condition_parser.go parse functions (75+ lines)
7. Extract helper functions to achieve max 30 lines per function

### Success Criteria
- No function exceeds 50 lines
- Cyclomatic complexity under 10 for all functions
- Unit tests cover extracted helper functions

---

## Feature 7: Implement Test Stubs

### Priority: High

### Description
Complete the 19+ test stubs identified in the codebase to ensure security and functionality coverage.

### Requirements
1. Implement api/mfa_test.go:294 - token reuse prevention tests
2. Implement api/mfa_test.go:660,676 - backup code functionality tests
3. Implement api/password_policy_test.go:403 - HIBP breach checking integration
4. Implement api/rate_limiting_test.go:252,266,280,631 - Redis failover scenarios
5. Implement ml/persistence_test.go:18,46,109 - custom serialization tests
6. Implement ml/network_extractor_test.go:129 - geo-IP enrichment tests
7. Implement ml/feedback_loop_test.go - all feedback tests
8. Implement config/secrets_test.go - 9 security test stubs

### Success Criteria
- All test stubs implemented with meaningful assertions
- Security-related tests achieve 90%+ coverage
- All tests pass in CI/CD pipeline

---

## Feature 8: Standardize Error Handling

### Priority: Medium

### Description
Implement consistent error handling patterns across the codebase with proper categorization and response formatting.

### Requirements
1. Create error categorization system (ValidationError, NotFoundError, AuthorizationError, InternalError)
2. Implement error response builder with consistent JSON format
3. Ensure all handlers use standardized error responses
4. Add error codes for client-side handling
5. Prevent internal error details from leaking to responses
6. Add structured logging for all errors with correlation IDs

### Success Criteria
- All API errors use consistent JSON format
- Error responses include error codes and messages
- Internal errors return generic messages to clients
- All errors logged with correlation IDs

---

## Feature 9: Implement Input Validation Middleware

### Priority: High

### Description
Create centralized input validation to prevent injection attacks and ensure data integrity.

### Requirements
1. Create validation middleware that validates all incoming requests
2. Implement ID format validation (UUID pattern)
3. Implement field name validation (regex whitelist)
4. Add length limits for all string inputs
5. Validate query parameters before processing
6. Sanitize user input to prevent XSS/injection

### Success Criteria
- All endpoints validate input before processing
- Invalid input returns 400 Bad Request with details
- No SQL injection possible through any input
- No XSS possible through any input

---

## Feature 10: Eliminate Circular Dependencies

### Priority: Medium

### Description
Restructure packages to eliminate circular dependencies and code duplication.

### Requirements
1. Create shared interfaces package (core/interfaces.go) for common types
2. Move duplicated circuitbreaker code from core/circuitbreaker_test.go to shared location
3. Move duplicated sigma_validator code from core/sigma_validator.go:410 to detect package
4. Refactor mitre/importer.go local interface to use shared interfaces
5. Resolve storage/sqlite_users.go SetRoleStorage circular dependency
6. Document package dependency graph

### Success Criteria
- No circular import errors
- No duplicated interface definitions
- Clear package dependency hierarchy
- Build time reduced

---

## Feature 11: Add Panic Recovery Middleware

### Priority: Medium

### Description
Implement consistent panic recovery across all handlers with structured logging and alerting.

### Requirements
1. Create panic recovery middleware for all HTTP handlers
2. Ensure panics are logged with structured fields (stack trace, request ID, user)
3. Return 500 Internal Server Error on panic
4. Add alerting hook for unexpected panics
5. Remove panic() usage from production code (except init)
6. Standardize 33 existing recover() statements

### Success Criteria
- All handlers wrapped in panic recovery
- Panics logged with full context
- Alerting triggered on production panics
- No panic() calls outside init functions

---

## Feature 12: Add Integration Test Suite

### Priority: Medium

### Description
Create comprehensive integration tests for critical workflows.

### Requirements
1. Add multi-user concurrent alert processing tests
2. Add correlation rule state machine transition tests
3. Add SIGMA engine field mapping validation tests
4. Add ClickHouse failover scenario tests
5. Add Redis-backed session management tests
6. Add SOAR playbook execution end-to-end tests
7. Add alert lifecycle tests (create, assign, investigate, resolve)

### Success Criteria
- Integration tests cover all critical workflows
- Tests run against real database instances
- Tests can run in CI/CD pipeline
- 80%+ coverage of integration points

---

## Feature 13: Create Architecture Documentation

### Priority: Low

### Description
Document system architecture, design decisions, and security model.

### Requirements
1. Create docs/architecture.md with system design overview
2. Create docs/api-design.md with API patterns and conventions
3. Create docs/security-model.md with threat model and mitigations
4. Add godoc comments to all exported symbols in storage/interfaces.go
5. Document correlation rule evaluation algorithm
6. Document SIGMA engine integration

### Success Criteria
- New developers can understand system in < 1 day
- All exported symbols have godoc comments
- Security model documented and reviewed

---

## Feature 14: Configure Connection Pool Tuning

### Priority: Medium

### Description
Add explicit connection pool configuration for database connections.

### Requirements
1. Add MaxIdleConns configuration for SQLite read pool
2. Add ConnMaxLifetime configuration (1 hour default)
3. Add connection pool metrics for monitoring
4. Document optimal settings for different deployment sizes
5. Add health check for database connections

### Success Criteria
- Connection pool properly configured
- Pool metrics available in monitoring
- No connection exhaustion under load

---

## Feature 15: Implement Request Correlation IDs

### Priority: Medium

### Description
Add correlation IDs to all requests for distributed tracing and debugging.

### Requirements
1. Generate unique correlation ID for each request
2. Pass correlation ID through all service calls
3. Include correlation ID in all log entries
4. Return correlation ID in response headers
5. Support accepting correlation ID from upstream services

### Success Criteria
- All requests have unique correlation IDs
- Logs can be filtered by correlation ID
- Response headers include X-Correlation-ID
