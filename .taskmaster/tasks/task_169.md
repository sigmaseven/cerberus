# Task ID: 169

**Title:** Implement Rule Lifecycle Management API

**Status:** done

**Dependencies:** 164 ✓

**Priority:** medium

**Description:** Add lifecycle state transitions (experimental→test→stable→deprecated→archived) with audit trail and automated deprecation workflow

**Details:**

Implementation: Create api/rule_lifecycle.go:

1. POST /api/v1/rules/{id}/lifecycle handler:
type LifecycleAction struct {
    Action       string `json:"action"` // promote, deprecate, archive, activate
    TargetStatus string `json:"target_status"`
    Reason       string `json:"reason"`
    SunsetDate   *time.Time `json:"sunset_date,omitempty"`
}

2. State machine validation:
   experimental -> test -> stable -> deprecated -> archived
   Any state -> active (shortcut)

3. Deprecation workflow:
   - Set lifecycle_status='deprecated'
   - Set deprecated_at=now(), deprecated_reason
   - Continue rule evaluation but flag alerts
   - Auto-disable on sunset_date via background job

4. GET /api/v1/rules/{id}/lifecycle-history:
   - Query lifecycle_audit table for state changes
   - Return chronological transitions

5. Create storage/sqlite_lifecycle_audit.go:
   - CREATE TABLE lifecycle_audit (rule_id, old_status, new_status, reason, changed_by, changed_at)

6. Add background job to check sunset dates daily

**Test Strategy:**

Create api/rule_lifecycle_test.go:
1. Test valid state transitions
2. Test invalid state transitions rejected
3. Test deprecation workflow end-to-end
4. Test sunset date enforcement
5. Test lifecycle audit trail creation
6. Test RBAC permissions for lifecycle actions
7. Test deprecated rule alert flagging

## Subtasks

### 169.1. Create api/rule_lifecycle.go with POST handler and state machine validation

**Status:** pending  
**Dependencies:** None  

Implement the core lifecycle management API endpoint with request/response types and state machine validation logic for rule lifecycle transitions

**Details:**

Create api/rule_lifecycle.go file containing:
1. LifecycleAction struct with Action, TargetStatus, Reason, and SunsetDate fields
2. POST /api/v1/rules/{id}/lifecycle handler implementation
3. State machine validation function enforcing valid transitions: experimental→test→stable→deprecated→archived, with any state→active shortcut allowed
4. Validation logic to reject invalid state transitions with appropriate error messages
5. Integration with existing RBAC permission checks (using api/rbac.go patterns)
6. Request validation for required fields (action, target_status, reason)
7. Response JSON formatting with updated rule status and transition details

### 169.2. Implement deprecation workflow with status updates and alert flagging

**Status:** pending  
**Dependencies:** 169.1  

Build the deprecation workflow logic including status updates, deprecated alert flagging, and sunset date handling in the rule lifecycle system

**Details:**

Extend api/rule_lifecycle.go with deprecation workflow:
1. Implement deprecate action handler that sets lifecycle_status='deprecated'
2. Record deprecated_at timestamp and deprecated_reason in core.Rule schema
3. Update rule evaluation logic in detect/engine.go to flag alerts from deprecated rules (add 'deprecated_rule' metadata field to alerts)
4. Implement sunset_date storage and validation (must be future date)
5. Add GET /api/v1/rules endpoint filter to show deprecated rules separately
6. Ensure deprecated rules continue evaluation but alerts are clearly marked
7. Add database migration for deprecated_at, deprecated_reason, sunset_date columns in rules table

### 169.3. Create storage/sqlite_lifecycle_audit.go with audit table and CRUD operations

**Status:** pending  
**Dependencies:** 169.1  

Implement the audit trail storage layer for tracking all lifecycle state transitions with full CRUD operations and query capabilities

**Details:**

Create storage/sqlite_lifecycle_audit.go containing:
1. CREATE TABLE lifecycle_audit schema with columns: id, rule_id, old_status, new_status, reason, changed_by, changed_at, sunset_date
2. Database migration in storage/migrations_sqlite.go for lifecycle_audit table creation
3. RecordLifecycleTransition(ctx context.Context, ruleID, oldStatus, newStatus, reason, changedBy string, sunsetDate *time.Time) error function
4. GetLifecycleHistory(ctx context.Context, ruleID string) ([]LifecycleAuditEntry, error) function for GET /api/v1/rules/{id}/lifecycle-history endpoint
5. Proper context propagation following TASK 144.4 patterns
6. Foreign key constraint linking to rules table with ON DELETE CASCADE
7. Index on rule_id and changed_at for efficient queries

### 169.4. Add background job for sunset date enforcement

**Status:** pending  
**Dependencies:** 169.2, 169.3  

Implement a background job scheduler that runs daily to check sunset dates and automatically disable deprecated rules that have reached their sunset date

**Details:**

Create background job in main.go or new scheduler package:
1. Implement daily cron job using time.Ticker or github.com/robfig/cron library
2. Query all rules where lifecycle_status='deprecated' AND sunset_date <= NOW() AND enabled=true
3. For each matching rule, call lifecycle API internally to transition to 'archived' status
4. Record transition in lifecycle_audit table with reason='automatic sunset enforcement'
5. Proper context.Context creation with timeout for background operations (following TASK 144.4 context propagation patterns)
6. Graceful shutdown handling to prevent job interruption
7. Add metrics/logging for sunset enforcement actions
8. Configuration option for sunset check frequency (default: daily at midnight)

### 169.5. Write comprehensive tests for lifecycle state transitions, RBAC, and audit trail

**Status:** pending  
**Dependencies:** 169.1, 169.2, 169.3, 169.4  

Create complete test suite covering all lifecycle management functionality including state machine validation, RBAC permissions, audit trail, and edge cases

**Details:**

Create api/rule_lifecycle_test.go with comprehensive test coverage:
1. TestValidStateTransitions: Test all valid state transitions (experimental→test→stable→deprecated→archived, any→active)
2. TestInvalidStateTransitions: Verify rejection of invalid transitions with proper error messages
3. TestDeprecationWorkflowEndToEnd: Full workflow from deprecation API call to flagged alert generation
4. TestSunsetDateEnforcement: Verify background job correctly archives rules on sunset date
5. TestLifecycleAuditTrail: Verify all transitions recorded in audit table with correct metadata
6. TestRBACPermissions: Verify only authorized users can perform lifecycle actions (admin/rule_manager roles)
7. TestConcurrentLifecycleUpdates: Race condition testing for simultaneous state changes
8. TestLifecycleHistoryRetrieval: Verify GET /api/v1/rules/{id}/lifecycle-history returns correct chronological data
9. Edge cases: nil sunset_date handling, missing reason field, non-existent rule_id
