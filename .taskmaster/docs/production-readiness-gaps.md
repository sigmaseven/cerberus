# Production Readiness Gap Analysis PRD

## Overview
This PRD documents all identified gaps between the current Cerberus SIEM implementation and the functional requirements. These tasks are required to achieve production readiness.

## Priority Levels
- **P0 (Critical)**: Must be fixed before any production deployment - security vulnerabilities or core functionality broken
- **P1 (High)**: Should be fixed for production - important functionality gaps
- **P2 (Medium)**: Nice to have for production - improvements and optimizations

---

## P0 Critical Tasks

### Task: Implement SSRF Protection for Webhook Actions
**Priority**: P0 - CRITICAL SECURITY
**Location**: `detect/actions.go` - webhook action execution
**Effort**: 16-24 hours

**Description**:
The webhook action executor is vulnerable to Server-Side Request Forgery (SSRF) attacks. An attacker can craft malicious rules that make the server send requests to internal services, cloud metadata endpoints (169.254.169.254), or private networks.

**Requirements**:
1. Implement URL validation with configurable allowlist
2. Block private IP ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
3. Block link-local addresses (169.254.0.0/16)
4. Block loopback addresses (127.0.0.0/8)
5. Block cloud metadata endpoints (169.254.169.254, metadata.google.internal)
6. Implement DNS rebinding protection
7. Add configuration option to enable/disable localhost for development
8. Log all blocked requests with reason

**Test Strategy**:
- Unit tests for URL validation functions
- Tests with malicious URLs (metadata service, private IPs, localhost)
- Integration tests for webhook actions with blocked destinations
- Tests for DNS rebinding attack patterns

---

### Task: Implement RBAC Authorization System
**Priority**: P0 - CRITICAL SECURITY
**Location**: `api/middleware.go`, `api/rbac.go`, `storage/sqlite_users.go`
**Effort**: 40-56 hours

**Description**:
Currently only JWT authentication exists. There is no authorization - any authenticated user can access any endpoint. A complete Role-Based Access Control (RBAC) system is required for multi-user production deployment.

**Requirements**:
1. Define permission model with scopes: `read:events`, `read:alerts`, `write:rules`, `write:actions`, `write:users`, `admin`
2. Define roles: Viewer (read-only), Analyst (read + acknowledge alerts), Engineer (read + write rules), Admin (full access)
3. Create RBAC middleware that checks permissions before handler execution
4. Store user roles in database (already have RoleID in User struct)
5. Implement permission inheritance (Admin inherits all permissions)
6. Return 403 Forbidden with clear error message on unauthorized access
7. Add audit logging for permission denied events
8. Create API endpoints for role management (admin only)

**Test Strategy**:
- Unit tests for permission checking logic
- Integration tests for each role accessing each endpoint type
- Tests for permission denied scenarios (403 responses)
- Tests for role inheritance
- Tests for audit logging

---

### Task: Enable SQLite Foreign Key Enforcement
**Priority**: P0 - HIGH
**Location**: `storage/sqlite.go`
**Effort**: 1-2 hours

**Description**:
SQLite foreign keys are defined in schema but not enforced because PRAGMA foreign_keys is not enabled. This allows orphaned records and data integrity issues.

**Requirements**:
1. Add `_foreign_keys=ON` to SQLite connection string
2. Or execute `PRAGMA foreign_keys = ON` after connection
3. Test that foreign key violations are properly rejected
4. Ensure existing data has no orphaned records before enabling

**Test Strategy**:
- Test foreign key violation is rejected (insert child without parent)
- Test cascade delete works correctly
- Test existing data integrity
- Integration tests with foreign key enforcement enabled

---

### Task: Implement Explicit Transaction Management
**Priority**: P0 - HIGH
**Location**: All `storage/sqlite_*.go` files
**Effort**: 24-40 hours

**Description**:
Multi-statement operations are not wrapped in explicit transactions, leading to potential data inconsistency if operations partially fail.

**Requirements**:
1. Audit all storage methods for multi-statement operations
2. Wrap multi-statement operations in explicit transactions (db.Begin/Commit/Rollback)
3. Implement proper error handling with rollback on failure
4. Add transaction timeout handling
5. Document transaction boundaries in code comments

**Files to audit**:
- storage/sqlite_rules.go (CreateRule, UpdateRule with metadata extraction)
- storage/sqlite_users.go (CreateUser with role assignment)
- storage/sqlite_investigations.go (CreateInvestigation with linked alerts)
- storage/sqlite_playbooks.go (CreatePlaybook with steps)

**Test Strategy**:
- Test partial failure scenarios roll back completely
- Test concurrent transaction isolation
- Test transaction timeout behavior
- Integration tests simulating failures mid-transaction

---

### Task: Implement Performance Load Testing Suite
**Priority**: P0 - CRITICAL
**Location**: `testing/performance/`, `performance/`
**Effort**: 80-120 hours

**Description**:
No load testing has been performed to validate the documented SLAs. Production deployment requires validation of performance targets.

**Requirements**:
1. Create load testing infrastructure using k6 or similar tool
2. Implement test scenarios:
   - Sustained ingestion: 10,000 EPS for 24 hours
   - Burst ingestion: 50,000 EPS for 5 minutes
   - Query latency under load: P95 < 1 second
   - API response time: P95 < 300ms
   - Concurrent users: 100 simultaneous API users
3. Implement metrics collection during load tests
4. Create performance dashboards
5. Document baseline performance numbers
6. Identify and fix performance bottlenecks

**Test Scenarios**:
- Syslog ingestion at 10K EPS sustained
- Mixed workload (ingestion + queries + API calls)
- Memory usage under sustained load (must stay < 4GB)
- CPU usage average (must stay < 70%)
- Database connection pool behavior

**Test Strategy**:
- Run 24-hour sustained load test
- Run 5-minute burst test
- Measure and record all latency percentiles
- Generate performance report with graphs

---

## P1 High Priority Tasks

### Task: Import SigmaHQ Community Rules
**Priority**: P1 - HIGH
**Location**: `storage/sqlite_rules.go`, `scripts/`
**Effort**: 16-24 hours

**Description**:
The data/feeds/sigmahq-community directory contains 3000+ SIGMA rules from the SigmaHQ community, but they are not imported into the database. Users need a curated set of detection rules out of the box.

**Requirements**:
1. Create import script to load YAML rules from data/feeds/sigmahq-community/rules/
2. Filter out deprecated rules (in deprecated/ subdirectory)
3. Validate each rule with core.ValidateSigmaYAML before import
4. Extract metadata (title, description, severity, tags, MITRE ATT&CK mappings)
5. Handle duplicate detection (same rule ID or title)
6. Create import progress reporting
7. Support incremental import (only new rules)
8. Create default rule categories/tags for organization

**Test Strategy**:
- Test import of valid rules
- Test rejection of invalid/malformed rules
- Test duplicate handling
- Test incremental import (re-run doesn't duplicate)
- Performance test importing 3000+ rules

---

### Task: Implement MFA/TOTP Authentication
**Priority**: P1 - HIGH
**Location**: `api/mfa.go`, `api/auth_handlers.go`, `storage/sqlite_users.go`
**Effort**: 24-32 hours

**Description**:
Multi-factor authentication is required for security-sensitive applications. TOTP (Time-based One-Time Password) should be supported.

**Requirements**:
1. Add TOTP secret storage to user model
2. Implement TOTP setup flow (generate secret, show QR code, verify first code)
3. Implement TOTP verification during login
4. Add backup codes for account recovery
5. Allow admin to reset user MFA
6. Make MFA optional but encourageable (or mandatory via config)
7. Support standard TOTP apps (Google Authenticator, Authy, etc.)

**Test Strategy**:
- Unit tests for TOTP code generation and verification
- Integration tests for MFA setup flow
- Tests for backup code usage
- Tests for MFA reset by admin

---

### Task: Complete Password Policy Enforcement
**Priority**: P1 - HIGH
**Location**: `api/password_policy.go`, `api/auth_handlers.go`
**Effort**: 8-16 hours

**Description**:
Password policy exists but is not fully enforced. Need comprehensive password requirements and history tracking.

**Requirements**:
1. Enforce minimum length (12 characters)
2. Require complexity (uppercase, lowercase, number, special character)
3. Check against common password lists
4. Implement password history (prevent reuse of last N passwords)
5. Implement password expiration (configurable)
6. Force password change on first login
7. Add password strength meter feedback

**Test Strategy**:
- Unit tests for each password requirement
- Tests for password history checking
- Tests for expiration and forced change flows
- Integration tests for password change API

---

### Task: Implement Account Lockout with Notification
**Priority**: P1 - HIGH
**Location**: `api/auth.go`, `api/rate_limiting.go`
**Effort**: 8-16 hours

**Description**:
Brute force protection exists but account lockout notification is missing. Admins and users should be notified of suspicious activity.

**Requirements**:
1. Lock account after N failed attempts (configurable, default 5)
2. Implement progressive lockout (1 min, 5 min, 15 min, 1 hour)
3. Send email/notification to user on lockout
4. Send alert to admin on multiple lockouts (potential attack)
5. Provide admin interface to unlock accounts
6. Log all lockout events for audit
7. Implement CAPTCHA after N failed attempts (optional)

**Test Strategy**:
- Test lockout triggers after N failures
- Test progressive timeout increases
- Test notification delivery
- Test admin unlock functionality
- Test lockout audit logging

---

### Task: Implement API Collection Filtering and Sorting
**Priority**: P1 - HIGH
**Location**: `api/filtering.go`, `api/handlers.go`
**Effort**: 16-24 hours

**Description**:
List endpoints return all items with basic pagination. Need filtering and sorting capabilities for better usability.

**Requirements**:
1. Implement query parameter parsing for filters (e.g., `?status=active&severity=high`)
2. Implement sorting (e.g., `?sort=created_at&order=desc`)
3. Support multiple filter conditions with AND logic
4. Support date range filtering (e.g., `?created_after=2024-01-01`)
5. Apply to endpoints: /api/v1/rules, /api/v1/alerts, /api/v1/events, /api/v1/users
6. Document filter syntax in API documentation
7. Validate filter field names against allowed fields

**Test Strategy**:
- Test single filter application
- Test multiple filters combined
- Test sorting in both directions
- Test date range filters
- Test invalid filter rejection

---

### Task: Complete Dead Letter Queue Implementation
**Priority**: P1 - HIGH
**Location**: `ingest/dlq.go`, `api/dlq_handlers.go`
**Effort**: 16-24 hours

**Description**:
DLQ partially exists but needs completion for production use. Failed events must be captured, viewable, and replayable.

**Requirements**:
1. Ensure all ingestion errors route to DLQ
2. Store original event data, error message, timestamp, source
3. Implement DLQ viewer API (list, filter, paginate)
4. Implement DLQ replay functionality (reprocess events)
5. Implement DLQ purge (delete old entries)
6. Add DLQ metrics (count, rate, error types)
7. Add DLQ alerts (threshold-based)
8. Create UI for DLQ management

**Test Strategy**:
- Test various error types route to DLQ
- Test DLQ viewer pagination and filtering
- Test replay functionality
- Test purge functionality
- Test metrics accuracy

---

## P2 Medium Priority Tasks

### Task: Implement LDAP/Active Directory Integration
**Priority**: P2 - MEDIUM
**Location**: `api/auth_ldap.go`, `config/config.go`
**Effort**: 32-48 hours

**Description**:
Enterprise deployments require LDAP/Active Directory integration for centralized user management.

**Requirements**:
1. Implement LDAP bind authentication
2. Support LDAP group to role mapping
3. Implement LDAP user sync (periodic or on-demand)
4. Support LDAPS (LDAP over TLS)
5. Implement LDAP connection pooling
6. Support multiple LDAP servers (failover)
7. Create LDAP configuration in config.yaml

**Test Strategy**:
- Integration tests with test LDAP server
- Test group to role mapping
- Test TLS connection
- Test failover behavior

---

### Task: Implement Query Aggregation and Grouping
**Priority**: P2 - MEDIUM
**Location**: `search/executor.go`, `search/parser.go`
**Effort**: 24-32 hours

**Description**:
CQL search supports filtering but not aggregation. Analytics queries require GROUP BY, COUNT, SUM, AVG support.

**Requirements**:
1. Extend CQL parser for aggregation syntax (e.g., `| stats count() by source`)
2. Implement aggregation in query executor
3. Support functions: count(), sum(), avg(), min(), max(), distinct_count()
4. Support GROUP BY with multiple fields
5. Support HAVING clause for filtering aggregated results
6. Implement time-based bucketing (per hour, per day)

**Test Strategy**:
- Test each aggregation function
- Test GROUP BY with single and multiple fields
- Test HAVING clause filtering
- Test time bucketing accuracy
- Performance test large aggregations

---

### Task: Remove Deprecated and Unused Code
**Priority**: P2 - MEDIUM
**Location**: Various
**Effort**: 8-16 hours

**Description**:
Cleanup deprecated code, disabled tests, and unused files to reduce maintenance burden and codebase complexity.

**Requirements**:
1. Remove or re-enable disabled test files (8 .disabled files)
2. Clean up nul files (Windows build artifacts)
3. Review and remove unused imports
4. Remove dead code paths identified by static analysis
5. Archive or document intentionally kept but unused code
6. Update .gitignore to prevent future artifact commits

**Files to review**:
- config/config_comprehensive_test.go.disabled
- storage/retention_test.go.disabled
- storage/sqlite_comprehensive_test.go.disabled
- Various frontend test artifacts

**Test Strategy**:
- Run full test suite after cleanup
- Verify build still succeeds
- Static analysis should show reduced warnings

---

### Task: Implement Backup and Restore Procedures
**Priority**: P2 - MEDIUM
**Location**: `scripts/backup.go`, `storage/`
**Effort**: 24-32 hours

**Description**:
Production systems require documented and tested backup/restore procedures.

**Requirements**:
1. Create backup script for SQLite database
2. Create backup procedure for ClickHouse data
3. Implement point-in-time recovery documentation
4. Create restore procedure with validation
5. Implement automated backup scheduling
6. Add backup integrity verification (checksums)
7. Document disaster recovery procedures

**Test Strategy**:
- Test full backup and restore cycle
- Test partial restore (specific tables)
- Test backup integrity verification
- Test restore to different instance

---

### Task: Implement Comprehensive API Documentation
**Priority**: P2 - MEDIUM
**Location**: `docs/swagger.yaml`, `api/`
**Effort**: 16-24 hours

**Description**:
OpenAPI/Swagger documentation exists but is incomplete. Full API documentation is required.

**Requirements**:
1. Document all API endpoints
2. Include request/response schemas
3. Add example requests and responses
4. Document error codes and messages
5. Document authentication requirements
6. Generate API documentation site (Swagger UI or similar)
7. Keep documentation in sync with code (consider code generation)

**Test Strategy**:
- Validate OpenAPI spec against actual API
- Test all example requests work
- Review documentation for completeness

---

## Summary

| Priority | Task Count | Total Effort |
|----------|------------|--------------|
| P0 Critical | 5 | 160-240 hours |
| P1 High | 6 | 88-136 hours |
| P2 Medium | 5 | 104-152 hours |
| **Total** | **16** | **352-528 hours** |

Estimated timeline: 9-13 developer-weeks for full production readiness.
