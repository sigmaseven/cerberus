# API Design and Contract Requirements

**Document Owner**: Backend Team
**Created**: 2025-01-16
**Status**: DRAFT
**Last Updated**: 2025-01-16
**Version**: 1.0
**Authoritative Sources**:
- REST API Design Best Practices (Microsoft REST API Guidelines)
- OpenAPI Specification 3.0
- RFC 7231 (HTTP/1.1 Semantics and Content)
- RFC 6749 (OAuth 2.0 Authorization Framework)
- OWASP API Security Top 10

---

## 1. Executive Summary

The Cerberus SIEM API is the primary integration point for all client applications, external tools, and automation workflows. This document defines the comprehensive requirements for API design, versioning, contract management, and backwards compatibility to ensure a stable, secure, and developer-friendly API surface.

**Critical Requirements**:
- RESTful API design following industry standards
- API versioning and deprecation policy
- Request/response schema validation
- Rate limiting and throttling
- Authentication and authorization
- WebSocket API for real-time updates
- Comprehensive error handling
- API performance SLAs

**Known Gaps**:
- WebSocket protocol specification needs formalization
- API versioning strategy needs stakeholder approval
- Performance SLAs require load testing data

---

## 2. Functional Requirements

### 2.1 RESTful API Design Principles

#### FR-API-001: Resource-Oriented URLs
**Requirement**: All API endpoints MUST follow resource-oriented URL design patterns.

**Rationale**: Resource-oriented URLs provide predictable, intuitive API surface that reduces integration errors and improves developer experience.

**Specification**:
- Collection endpoints MUST use plural nouns: `/api/v1/events`, `/api/v1/rules`, `/api/v1/alerts`
- Individual resources MUST use ID-based access: `/api/v1/rules/{id}`
- Sub-resources MUST be nested under parent: `/api/v1/investigations/{id}/notes`
- Actions on resources MUST use POST with action suffix: `/api/v1/alerts/{id}/acknowledge`
- Avoid deeply nested URLs (max 3 levels): `/api/v1/resource/{id}/subresource/{id}/action`

**Examples**:
```
GET    /api/v1/events              # List events
GET    /api/v1/events?page=2       # Paginated events
GET    /api/v1/rules/{id}          # Get specific rule
POST   /api/v1/rules               # Create rule
PUT    /api/v1/rules/{id}          # Update rule (full replacement)
PATCH  /api/v1/rules/{id}          # Update rule (partial)
DELETE /api/v1/rules/{id}          # Delete rule
POST   /api/v1/alerts/{id}/dismiss # Dismiss specific alert
```

**Acceptance Criteria**:
- [x] All API endpoints follow resource-oriented URL pattern
- [ ] API documentation includes URL design guidelines
- [ ] Code review checklist includes URL pattern validation

**Current Implementation**: ✅ COMPLIANT (api/api.go:166-323)

---

#### FR-API-002: HTTP Method Semantics
**Requirement**: All API endpoints MUST use HTTP methods according to RFC 7231 semantics.

**Rationale**: Correct HTTP method usage enables caching, idempotency guarantees, and proper HTTP intermediary behavior.

**Specification**:
| Method | Semantics | Idempotent | Safe | Use Case |
|--------|-----------|------------|------|----------|
| GET | Retrieve resource | Yes | Yes | Fetch data without side effects |
| POST | Create resource or action | No | No | Create new resource or trigger action |
| PUT | Replace resource | Yes | No | Full resource replacement |
| PATCH | Partial update | No | No | Modify specific fields |
| DELETE | Remove resource | Yes | No | Delete resource |
| HEAD | GET without body | Yes | Yes | Check resource existence |
| OPTIONS | Get supported methods | Yes | Yes | CORS preflight |

**Acceptance Criteria**:
- [x] GET requests are read-only and produce no side effects
- [x] POST creates new resources and returns 201 Created
- [x] PUT replaces entire resource and is idempotent
- [ ] PATCH updates partial fields (not implemented)
- [x] DELETE removes resources and returns appropriate status
- [ ] HEAD and OPTIONS methods supported for all endpoints

**Current Implementation**: ⚠️ PARTIAL (PATCH, HEAD, OPTIONS not implemented)

---

#### FR-API-003: HTTP Status Codes
**Requirement**: API responses MUST use semantically correct HTTP status codes.

**Rationale**: Correct status codes enable clients to programmatically handle success, errors, and edge cases.

**Specification**:

**Success Codes** (2xx):
- `200 OK`: Successful GET, PUT, DELETE
- `201 Created`: Successful POST creating new resource (include Location header)
- `202 Accepted`: Request accepted for async processing
- `204 No Content`: Successful request with no response body (DELETE)

**Client Error Codes** (4xx):
- `400 Bad Request`: Malformed request, validation errors
- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Authenticated but insufficient permissions
- `404 Not Found`: Resource does not exist
- `409 Conflict`: Request conflicts with current state (duplicate)
- `422 Unprocessable Entity`: Valid syntax but semantic errors
- `429 Too Many Requests`: Rate limit exceeded

**Server Error Codes** (5xx):
- `500 Internal Server Error`: Unexpected server error
- `503 Service Unavailable`: Temporary unavailability (maintenance, overload)

**Acceptance Criteria**:
- [x] All success responses use 2xx codes appropriately
- [x] Validation errors return 400 with error details
- [x] Authentication failures return 401
- [ ] Authorization failures return 403 (currently 401)
- [x] Missing resources return 404
- [ ] Conflict scenarios return 409
- [x] Server errors return 500
- [x] Rate limiting returns 429

**Current Implementation**: ⚠️ PARTIAL (handlers.go uses most codes correctly, 403/409 not fully implemented)

---

#### FR-API-004: Request Content Negotiation
**Requirement**: API MUST support content negotiation via Accept and Content-Type headers.

**Rationale**: Content negotiation enables clients to request data in preferred formats and signals request payload format.

**Specification**:
- API MUST support `Content-Type: application/json` for request bodies
- API MUST support `Accept: application/json` for response bodies
- API SHOULD return `415 Unsupported Media Type` for unsupported Content-Type
- API SHOULD return `406 Not Acceptable` for unsupported Accept headers
- Export endpoints MUST support multiple formats via Accept or query parameter

**Supported Content Types**:
- `application/json`: Primary format for all API requests/responses
- `text/csv`: Export format for events/alerts (future)
- `application/x-ndjson`: Streaming JSON (future)

**Acceptance Criteria**:
- [x] All endpoints accept `application/json` request bodies
- [x] All endpoints return `application/json` response bodies
- [ ] Unsupported Content-Type returns 415
- [ ] Unsupported Accept returns 406
- [ ] Export endpoints support CSV format

**Current Implementation**: ⚠️ PARTIAL (JSON-only, no validation of Content-Type/Accept headers)

---

### 2.2 API Versioning

#### FR-API-005: URL-Based Versioning
**Requirement**: API MUST use URL-based versioning with major version in path.

**Rationale**: URL versioning is explicit, visible, and easiest for clients to understand and migrate between versions.

**Specification**:
- Version prefix MUST be `/api/v{major}` (e.g., `/api/v1`, `/api/v2`)
- Only major version appears in URL (minor/patch versions are backwards compatible)
- Authentication endpoints MAY omit version for compatibility: `/api/auth/login`
- Public endpoints (health, metrics) MAY omit version: `/health`, `/metrics`

**Version Lifecycle**:
1. **Active**: Current version receiving new features
2. **Deprecated**: Previous version in maintenance mode (bug fixes only)
3. **Sunset**: Version no longer supported

**Acceptance Criteria**:
- [x] All API endpoints include `/api/v1` prefix
- [x] Authentication endpoints use `/api/auth/*` (no version)
- [x] Health endpoint uses `/health` (no version)
- [ ] API version metadata exposed via `/api/version` endpoint
- [ ] Multiple versions can coexist (v1, v2)

**Current Implementation**: ✅ COMPLIANT (api/api.go:192-322)

---

#### FR-API-006: API Deprecation Policy
**Requirement**: API version deprecation MUST follow a defined timeline and communication process.

**Rationale**: Predictable deprecation policy allows clients to plan migrations without disruption.

**Specification**:

**Deprecation Timeline**:
- **Announcement**: 6 months before deprecation (release notes, email, API header)
- **Deprecated**: Version marked deprecated, fully supported but no new features
- **Sunset**: 12 months after deprecation announcement, version removed

**Deprecation Signals**:
- HTTP Header: `Deprecation: true` (RFC 8594)
- HTTP Header: `Sunset: Sat, 31 Dec 2025 23:59:59 GMT` (RFC 8594)
- HTTP Header: `Link: </docs/migration>; rel="deprecation"`
- Response field: `"api_version": "v1", "deprecated": true`

**Breaking Changes** (require new major version):
- Removing fields from responses
- Changing field types
- Removing endpoints
- Changing authentication mechanism
- Modifying error response format

**Non-Breaking Changes** (allowed in same version):
- Adding new endpoints
- Adding optional fields to requests
- Adding fields to responses
- Relaxing validation rules

**Acceptance Criteria**:
- [ ] Deprecation HTTP headers implemented
- [ ] Migration guide published 6 months before sunset
- [ ] Deprecated endpoints logged with usage metrics
- [ ] Version sunset enforcement automated
- [ ] Client SDK version compatibility matrix published

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] Deprecation announcement process (email list, changelog, dashboard)
- [ ] Automated deprecation header injection
- [ ] Version usage analytics

---

### 2.3 Request and Response Schemas

#### FR-API-007: JSON Schema Validation
**Requirement**: All request and response payloads MUST conform to documented JSON schemas.

**Rationale**: Schema validation prevents malformed data from propagating through the system and provides clear API contracts.

**Specification**:
- Request payloads MUST be validated against JSON schema before processing
- Validation errors MUST return 400 Bad Request with detailed error messages
- Response payloads SHOULD be validated in development/test environments
- Schemas MUST be documented in OpenAPI specification
- Schema validation MUST enforce:
  - Required fields presence
  - Field type constraints (string, number, boolean, array, object)
  - String length limits
  - Number ranges
  - Enum value restrictions
  - Array length limits
  - Nested object validation

**Example Validation Error Response**:
```json
{
  "error": "Validation failed",
  "details": [
    {
      "field": "severity",
      "message": "must be one of: Low, Medium, High, Critical",
      "value": "CRITICAL"
    },
    {
      "field": "name",
      "message": "field is required",
      "value": null
    }
  ],
  "timestamp": "2025-01-16T12:00:00Z",
  "correlation_id": "req_abc123"
}
```

**Acceptance Criteria**:
- [x] Request validation implemented for all POST/PUT endpoints
- [x] Validation errors return structured error response
- [ ] JSON schemas published in OpenAPI spec
- [ ] Response validation enabled in test environment
- [ ] Schema version included in responses

**Current Implementation**: ✅ PARTIAL (validation.go provides validation, schemas not formalized)

---

#### FR-API-008: Field Naming Conventions
**Requirement**: All JSON fields MUST follow consistent naming conventions.

**Rationale**: Consistent naming reduces cognitive load and prevents integration errors.

**Specification**:
- Field names MUST use `snake_case`: `event_type`, `source_ip`, `created_at`
- Field names MUST be descriptive and unambiguous
- Boolean fields SHOULD use `is_`, `has_`, or `can_` prefix: `is_enabled`, `has_alerts`
- Timestamps MUST use ISO 8601 format with timezone: `2025-01-16T12:00:00Z`
- Timestamps MUST use `_at` suffix: `created_at`, `updated_at`, `deleted_at`
- IDs MUST use `_id` suffix: `rule_id`, `alert_id`, `user_id`
- Collections MUST use plural nouns: `events`, `rules`, `tags`

**Reserved Field Names**:
- `id`: Primary identifier for resource
- `created_at`: Resource creation timestamp
- `updated_at`: Last modification timestamp
- `deleted_at`: Soft deletion timestamp (if applicable)
- `version`: Resource version for optimistic locking

**Acceptance Criteria**:
- [x] All API responses use snake_case
- [x] Timestamps use ISO 8601 format
- [x] Boolean fields use descriptive prefixes
- [ ] Field naming validated in code review
- [ ] Linter enforces naming conventions

**Current Implementation**: ✅ COMPLIANT (core/schema.go, frontend types match)

---

#### FR-API-009: Pagination
**Requirement**: Collection endpoints MUST support pagination to prevent large response payloads.

**Rationale**: Pagination protects server and client from resource exhaustion when dealing with large datasets.

**Specification**:

**Pagination Parameters** (query string):
- `page`: 1-indexed page number (default: 1)
- `limit`: Items per page (default: 50, max: 1000)
- Alternative: `offset` for offset-based pagination

**Pagination Response Format**:
```json
{
  "items": [...],
  "total": 1523,
  "page": 2,
  "limit": 50,
  "total_pages": 31
}
```

**Link Header** (optional, for cursor-based pagination):
```
Link: </api/v1/events?page=3>; rel="next",
      </api/v1/events?page=1>; rel="first",
      </api/v1/events?page=31>; rel="last"
```

**Pagination Limits**:
- Default `limit`: 50 items
- Maximum `limit`: 1000 items (prevents excessive memory usage)
- Maximum `page`: 10,000 (prevents deep pagination performance issues)

**Acceptance Criteria**:
- [x] All collection endpoints support `page` and `limit` parameters
- [x] Responses include total count and pagination metadata
- [x] `limit` capped at maximum value
- [ ] Link headers provided for navigation
- [ ] Cursor-based pagination for large datasets (future)

**Current Implementation**: ✅ PARTIAL (handlers.go:42-78, needs Link headers)

---

#### FR-API-010: Filtering, Sorting, and Search
**Requirement**: Collection endpoints SHOULD support filtering, sorting, and search capabilities.

**Rationale**: Clients need to retrieve specific subsets of data without client-side filtering.

**Specification**:

**Filtering** (query parameters):
- Field-based filters: `?severity=High&status=Open`
- Comparison operators: `?created_at_gte=2025-01-01&created_at_lt=2025-02-01`
- Array filters: `?tags=malware&tags=ransomware` (OR logic)

**Sorting** (query parameter):
- `sort`: Field name with optional `-` prefix for descending
- Examples: `?sort=-created_at`, `?sort=severity,created_at`
- Default: Resource-specific (usually `-created_at` for recent-first)

**Full-Text Search** (query parameter):
- `q`: Search query string
- Example: `?q=brute force attack`
- Searches across multiple fields (title, description, tags)

**Combined Example**:
```
GET /api/v1/alerts?severity=High&severity=Critical&status=Open&sort=-created_at&page=1&limit=50
```

**Acceptance Criteria**:
- [ ] Endpoints support field-based filtering
- [ ] Endpoints support comparison operators
- [ ] Endpoints support sorting by field
- [ ] Search endpoint supports full-text queries
- [ ] Filter syntax documented in API specification

**Current Implementation**: ❌ NOT IMPLEMENTED (TBD: search functionality in progress)

---

### 2.4 Authentication and Authorization

#### FR-API-011: JWT-Based Authentication
**Requirement**: API MUST use JWT (JSON Web Tokens) for stateless authentication.

**Rationale**: JWT enables stateless, scalable authentication without server-side session storage.

**Specification**:

**Authentication Flow**:
1. Client sends credentials to `/api/auth/login` (POST)
2. Server validates credentials and returns JWT in httpOnly cookie
3. Client includes JWT cookie in subsequent requests
4. Server validates JWT signature and expiration
5. Server extracts user identity and permissions from JWT claims

**JWT Claims** (payload):
```json
{
  "sub": "user_id_123",
  "username": "analyst@example.com",
  "role": "analyst",
  "permissions": ["read:events", "write:rules", "read:alerts"],
  "iat": 1705401600,
  "exp": 1705488000,
  "jti": "jwt_abc123"
}
```

**JWT Storage**:
- JWT MUST be stored in httpOnly, secure, SameSite=Strict cookie
- Cookie name: `auth_token`
- Prevents XSS attacks (JavaScript cannot access httpOnly cookie)
- Prevents CSRF attacks (SameSite=Strict)

**Token Lifetime**:
- Access token: 24 hours
- Refresh token: 7 days (future enhancement)
- Token blacklist on logout

**Acceptance Criteria**:
- [x] JWT issued on successful login
- [x] JWT stored in httpOnly cookie
- [x] JWT validated on protected endpoints
- [x] Expired tokens rejected with 401
- [x] Token blacklist implemented for logout
- [ ] Refresh token mechanism implemented
- [x] CSRF protection via CSRF token in separate cookie

**Current Implementation**: ✅ COMPLIANT (api/jwt.go, api/auth.go)

---

#### FR-API-012: Role-Based Access Control (RBAC)
**Requirement**: API MUST enforce role-based access control for protected endpoints.

**Rationale**: RBAC ensures users can only access resources and perform actions permitted by their role.

**Specification**:

**Roles**:
- `viewer`: Read-only access to events, alerts, rules
- `analyst`: Viewer + acknowledge/dismiss alerts, create investigations
- `engineer`: Analyst + create/update/delete rules, actions, correlation rules
- `admin`: Engineer + user management, system configuration

**Permission Model**:
```
{
  "viewer": ["read:events", "read:alerts", "read:rules", "read:investigations"],
  "analyst": [...viewer, "write:alerts", "write:investigations"],
  "engineer": [...analyst, "write:rules", "write:actions", "write:correlation_rules"],
  "admin": [...engineer, "write:users", "write:config"]
}
```

**Authorization Enforcement**:
- Middleware extracts role/permissions from JWT
- Endpoint handler checks required permission
- Insufficient permissions return 403 Forbidden

**Acceptance Criteria**:
- [x] RBAC middleware implemented
- [x] Permissions checked on all protected endpoints
- [x] Permission denied returns 403 with clear message
- [x] Audit log records authorization failures
- [x] RBAC model documented in API specification

**Current Implementation**: ✅ FULLY IMPLEMENTED (api/rbac.go, api/rbac_permission_registry.go, storage/sqlite_roles.go)

**Implementation Details**:
- Permission middleware: `RequirePermission`, `RequireAnyPermission`, `RequireAllPermissions`
- Permission registry: Maps HTTP methods and paths to required permissions
- Role storage: SQLite-based role storage with default roles (viewer, analyst, engineer, admin)
- Permission checking: Uses `CheckPermission` function with wildcard support
- Audit logging: All authorization failures are logged with user, permission, and reason
- Default roles:
  - `viewer`: Read-only access (read:events, read:alerts, read:rules, read:investigations)
  - `analyst`: Viewer + write access to alerts/investigations (write:alerts, write:investigations, acknowledge:alerts, comment:alerts)
  - `engineer`: Analyst + write access to rules/actions (write:rules, write:actions, write:correlation_rules)
  - `admin`: Engineer + system administration (admin:system, write:users, write:config)

#### FR-API-RBAC-001: Permission-Based Access Control
**Requirement**: API MUST enforce permission-based access control on all protected endpoints.

**Specification**:
- Permissions are granular (e.g., `read:events`, `write:rules`, `admin:system`)
- Permissions are checked via middleware before request processing
- Insufficient permissions return 403 Forbidden
- Permissions are extracted from user's role

**Implementation**: `api/rbac.go:19-81` (RequirePermission middleware)

**Acceptance Criteria**:
- [x] Permission middleware is implemented
- [x] Permissions are checked on protected endpoints
- [x] 403 Forbidden returned for insufficient permissions

---

#### FR-API-RBAC-002: Role-Based Permission Assignment
**Requirement**: System MUST support role-based permission assignment.

**Specification**:
- Roles are collections of permissions
- Default roles: viewer, analyst, engineer, admin
- Roles stored in SQLite database
- Permissions stored as JSON array in role record

**Implementation**: `storage/sqlite_roles.go` (role storage), `storage/user.go` (default roles)

**Acceptance Criteria**:
- [x] Roles are stored in database
- [x] Default roles are defined
- [x] Permissions are assigned to roles

---

#### FR-API-RBAC-003: Permission Middleware
**Requirement**: API MUST provide permission checking middleware for route protection.

**Specification**:
- `RequirePermission`: Requires specific permission
- `RequireAnyPermission`: Requires any of specified permissions
- `RequireAllPermissions`: Requires all specified permissions
- Middleware extracts user role from JWT context
- Middleware checks role permissions against required permission

**Implementation**: `api/rbac.go` (all middleware functions)

**Acceptance Criteria**:
- [x] Permission middleware functions are implemented
- [x] Middleware extracts user role
- [x] Middleware checks permissions correctly

---

#### FR-API-RBAC-004: Permission Registry
**Requirement**: System MUST maintain a registry mapping endpoints to required permissions.

**Specification**:
- Permission registry maps HTTP methods and path patterns to required permissions
- Path patterns support parameterized routes (e.g., `/api/v1/rules/{id}`)
- Registry used for automatic permission assignment
- Registry supports wildcard permissions

**Implementation**: `api/rbac_permission_registry.go` (PermissionRegistry, GetRequiredPermission)

**Acceptance Criteria**:
- [x] Permission registry exists
- [x] Registry maps endpoints to permissions
- [x] Registry supports parameterized routes

---

#### FR-API-RBAC-005: Wildcard Permission Support
**Requirement**: System MUST support wildcard permissions for hierarchical access control.

**Specification**:
- Wildcard permissions (e.g., `admin:*`) grant all permissions
- Permission checking supports wildcard matching
- Wildcards checked before specific permission checks
- Wildcard permissions stored in role definitions

**Implementation**: `api/rbac_permission_registry.go:78-106` (CheckPermission with wildcard support)

**Acceptance Criteria**:
- [x] Wildcard permissions are supported
- [x] Wildcard matching is correct
- [x] Wildcards grant appropriate access

---

#### FR-API-RBAC-006: Authorization Failure Handling
**Requirement**: API MUST return appropriate status codes and messages for authorization failures.

**Specification**:
- Insufficient permissions return 403 Forbidden
- Unauthenticated requests return 401 Unauthorized
- Error messages are clear but don't leak information
- Authorization failures are logged for audit

**Implementation**: `api/rbac.go:70` (403 Forbidden), `api/rbac.go:69` (audit logging)

**Acceptance Criteria**:
- [x] 403 Forbidden returned for insufficient permissions
- [x] Error messages are appropriate
- [x] Authorization failures are logged

---

#### FR-API-RBAC-007: Permission Audit Logging
**Requirement**: All authorization failures MUST be logged for audit purposes.

**Specification**:
- Log entries include: username, permission, reason, source IP, timestamp
- Log level: WARN for authorization failures
- Log format: Structured logging (JSON)
- Logs used for security monitoring and compliance

**Implementation**: `api/rbac.go:32,44,52,60,69` (auditPermissionDenial calls)

**Acceptance Criteria**:
- [x] Authorization failures are logged
- [x] Logs include required metadata
- [x] Logs are structured

---

#### FR-API-RBAC-008: Role Management API
**Requirement**: System MUST provide API endpoints for role management.

**Specification**:
- `GET /api/v1/roles`: List all roles
- `GET /api/v1/roles/{id}`: Get role by ID
- `POST /api/v1/roles`: Create custom role (admin only)
- `PUT /api/v1/roles/{id}`: Update role (admin only)
- `DELETE /api/v1/roles/{id}`: Delete role (admin only, default roles protected)

**Implementation**: `api/api.go` (role routes), role handlers to be implemented

**Acceptance Criteria**:
- [ ] Role management endpoints are implemented
- [ ] Default roles are protected from deletion
- [ ] RBAC is enforced on role management endpoints

---

#### FR-API-RBAC-009: User Role Assignment
**Requirement**: System MUST support assigning roles to users.

**Specification**:
- Users can have one role assigned
- Role assignment via user management API
- Role changes require admin permission
- Role changes are logged for audit

**Implementation**: `storage/sqlite_users.go` (user storage with role_id), `api/user_management_handlers.go` (user management)

**Acceptance Criteria**:
- [x] Users can be assigned roles
- [x] Role assignment is stored in database
- [x] Role changes are logged

---

#### FR-API-RBAC-010: Default Role Permissions
**Requirement**: System MUST define default roles with appropriate permissions.

**Specification**:
- `viewer`: Read-only permissions (read:events, read:alerts, read:rules, read:investigations)
- `analyst`: Viewer + write access to alerts/investigations (write:alerts, write:investigations, acknowledge:alerts, comment:alerts)
- `engineer`: Analyst + write access to rules/actions (write:rules, write:actions, write:correlation_rules)
- `admin`: Engineer + system administration (admin:system, write:users, write:config)
- Default roles are seeded on database initialization

**Implementation**: `storage/user.go:54-143` (GetDefaultRoles), `storage/sqlite_roles.go` (SeedDefaultRoles)

**Acceptance Criteria**:
- [x] Default roles are defined
- [x] Permissions are assigned to default roles
- [x] Default roles are seeded on initialization

---

#### FR-API-013: CSRF Protection
**Requirement**: API MUST implement CSRF protection for state-changing operations.

**Rationale**: CSRF attacks trick authenticated users into performing unwanted actions. Double-submit cookie pattern prevents these attacks.

**Specification**:

**CSRF Token Flow**:
1. Server sets CSRF token in non-httpOnly cookie: `csrf_token=abc123`
2. Client reads CSRF token from cookie
3. Client includes token in `X-CSRF-Token` request header
4. Server validates token matches cookie value
5. Mismatched or missing token returns 403 Forbidden

**CSRF Protection Scope**:
- Applied to: POST, PUT, PATCH, DELETE requests
- Exempted: GET, HEAD, OPTIONS (safe methods)
- Exempted: Public endpoints (login, health check)

**Token Properties**:
- Token length: 32 characters (hex-encoded 16 bytes)
- Token lifetime: Same as session (24 hours)
- Token rotation: New token on login

**Acceptance Criteria**:
- [x] CSRF token generated on login
- [x] CSRF token stored in non-httpOnly cookie
- [x] CSRF middleware validates token on protected routes
- [x] Missing/invalid token returns 403
- [ ] CSRF token rotation implemented

**Current Implementation**: ✅ COMPLIANT (api/csrf.go, api/middleware.go:csrfProtectionMiddleware)

---

### 2.5 Rate Limiting and Throttling

#### FR-API-014: Rate Limiting
**Requirement**: API MUST implement rate limiting to prevent abuse and ensure fair resource allocation.

**Rationale**: Rate limiting protects the system from DoS attacks, brute force attacks, and resource exhaustion.

**Specification**:

**Rate Limit Strategy**:
- Algorithm: Token bucket (allows bursts, smooths traffic)
- Scope: Per-IP address (or per-user for authenticated requests)
- Limit: Configurable (default: 100 requests/minute)
- Burst: 2x rate limit

**Rate Limit Tiers**:
- **Anonymous**: 60 requests/minute
- **Authenticated**: 100 requests/minute
- **Admin**: 200 requests/minute (higher limit for legitimate heavy users)

**Rate Limit Headers**:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 47
X-RateLimit-Reset: 1705401660
Retry-After: 60
```

**Rate Limit Exceeded Response**:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Reset: 1705401660

{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Please try again in 60 seconds.",
  "retry_after": 60,
  "timestamp": "2025-01-16T12:00:00Z"
}
```

**Acceptance Criteria**:
- [x] Rate limiting enforced on all API endpoints
- [x] Rate limits per IP address
- [ ] Rate limits per authenticated user
- [ ] Rate limit headers included in responses
- [x] 429 status returned when limit exceeded
- [ ] Rate limit metrics tracked

**Current Implementation**: ✅ PARTIAL (api/middleware.go:rateLimitMiddleware, needs headers)

---

#### FR-API-015: Authentication Brute Force Protection
**Requirement**: API MUST implement additional protection against authentication brute force attacks.

**Rationale**: Attackers attempt to guess passwords through repeated login attempts. Progressive backoff increases attack cost.

**Specification**:

**Failed Login Tracking**:
- Track failed login attempts per IP address
- Track failed login attempts per username
- Failed attempts reset after successful login or timeout

**Progressive Backoff**:
- 3 failures: No delay
- 4-5 failures: 5 second delay
- 6-10 failures: 30 second delay
- 11+ failures: 5 minute delay (account lockout)

**Account Lockout**:
- After 10 failed attempts: Account locked for 15 minutes
- Lockout notification sent to account email
- Admin can manually unlock account

**Acceptance Criteria**:
- [x] Failed login attempts tracked per IP
- [x] Progressive delays enforced
- [ ] Account lockout after threshold
- [ ] Lockout notification sent
- [ ] Admin unlock capability
- [x] Brute force attempts logged

**Current Implementation**: ✅ PARTIAL (api/middleware.go, needs account lockout notification)

---

### 2.6 Error Handling

#### FR-API-016: Consistent Error Response Format
**Requirement**: All API error responses MUST follow a consistent JSON structure.

**Rationale**: Consistent error format enables generic error handling in client applications.

**Specification**:

**Error Response Schema**:
```json
{
  "error": "Brief error category (e.g., 'Validation failed')",
  "message": "Human-readable error description",
  "details": [ /* Optional array of detailed error information */ ],
  "timestamp": "2025-01-16T12:00:00Z",
  "correlation_id": "req_abc123",
  "path": "/api/v1/rules",
  "method": "POST"
}
```

**Error Detail Schema** (for validation errors):
```json
{
  "field": "severity",
  "message": "must be one of: Low, Medium, High, Critical",
  "value": "CRITICAL",
  "code": "INVALID_ENUM"
}
```

**Error Categories**:
- `Validation failed`: Request validation errors (400)
- `Authentication required`: Missing/invalid auth (401)
- `Access denied`: Insufficient permissions (403)
- `Not found`: Resource doesn't exist (404)
- `Conflict`: Resource already exists or state conflict (409)
- `Rate limit exceeded`: Too many requests (429)
- `Internal server error`: Unexpected server error (500)

**Security Considerations**:
- MUST NOT expose internal error details (stack traces, DB errors)
- MUST NOT expose system information (versions, paths)
- MUST NOT expose sensitive data in error messages
- SHOULD sanitize user input in error messages to prevent XSS

**Acceptance Criteria**:
- [x] All error responses use consistent JSON format
- [x] Error responses include correlation ID
- [x] Validation errors include field-level details
- [x] Internal errors sanitized (no stack traces)
- [ ] Error codes standardized across endpoints

**Current Implementation**: ✅ COMPLIANT (api/middleware.go:errorSanitizationMiddleware, api/validation.go:writeError)

---

#### FR-API-017: Error Logging and Monitoring
**Requirement**: All API errors MUST be logged with sufficient context for debugging and monitoring.

**Rationale**: Comprehensive error logging enables rapid incident response and root cause analysis.

**Specification**:

**Error Log Fields**:
```json
{
  "timestamp": "2025-01-16T12:00:00Z",
  "level": "error",
  "correlation_id": "req_abc123",
  "user_id": "user_123",
  "ip_address": "192.168.1.100",
  "method": "POST",
  "path": "/api/v1/rules",
  "status_code": 500,
  "error_message": "Failed to create rule: database connection timeout",
  "error_category": "database",
  "latency_ms": 5234,
  "request_id": "req_abc123"
}
```

**Error Severity Levels**:
- **DEBUG**: Verbose diagnostic information (disabled in production)
- **INFO**: Normal operational events
- **WARN**: Unexpected but handled conditions (rate limit, invalid input)
- **ERROR**: Error conditions requiring investigation (500 errors, database failures)
- **FATAL**: Critical errors causing service shutdown

**Error Monitoring**:
- 4xx errors: Log at WARN level (client errors)
- 5xx errors: Log at ERROR level (server errors)
- 5xx errors: Trigger alerts if rate > threshold
- Authentication failures: Track for security monitoring

**Acceptance Criteria**:
- [x] All errors logged with correlation ID
- [x] Error logs include user context
- [x] 5xx errors logged with full context
- [ ] Error rate monitoring alerts configured
- [ ] Error logs indexed for search

**Current Implementation**: ✅ PARTIAL (logging implemented, monitoring alerts TBD)

---

### 2.7 WebSocket API

#### FR-API-018: WebSocket Real-Time Updates
**Requirement**: API MUST provide WebSocket endpoint for real-time event and alert updates.

**Rationale**: SOC analysts require real-time visibility into events and alerts without polling overhead.

**Specification**:

**WebSocket Endpoint**:
- URL: `ws://localhost:8081/ws` (or wss:// for TLS)
- Protocol: WebSocket (RFC 6455)
- Authentication: JWT token passed via query parameter `?token=<jwt>` or Sec-WebSocket-Protocol header

**Message Format**:
```json
{
  "type": "event" | "alert" | "rule_update" | "heartbeat",
  "data": { ... },
  "timestamp": "2025-01-16T12:00:00Z"
}
```

**Message Types**:
- `event`: New event ingested
- `alert`: New alert generated
- `alert_update`: Alert status changed (acknowledged, dismissed)
- `rule_update`: Rule created/updated/deleted
- `heartbeat`: Keep-alive ping (every 30 seconds)

**Client Subscription**:
Clients can optionally filter messages by type:
```json
{
  "action": "subscribe",
  "types": ["alert", "event"]
}
```

**Connection Management**:
- Heartbeat every 30 seconds
- Client must respond with pong within 60 seconds
- Connection timeout: 120 seconds idle
- Reconnection: Exponential backoff (1s, 2s, 4s, 8s, max 30s)

**Acceptance Criteria**:
- [x] WebSocket endpoint implemented
- [ ] JWT authentication enforced
- [x] Real-time event/alert broadcasting
- [ ] Client subscription filtering
- [ ] Heartbeat/pong mechanism
- [ ] Connection metrics (active connections, message rate)

**Current Implementation**: ⚠️ PARTIAL (WebSocket exists but subscription filtering and formal authentication TBD)

**TBD**:
- [ ] WebSocket authentication mechanism (query param vs header)
- [ ] Subscription filtering implementation
- [ ] Heartbeat protocol formalization

---

### 2.8 API Performance

#### FR-API-019: Response Time SLAs
**Requirement**: API responses MUST meet defined latency SLAs under normal load conditions.

**Rationale**: Predictable response times ensure acceptable user experience and prevent timeout failures.

**Specification**:

**Response Time Targets** (p95 latency):
- **List Endpoints** (GET /events, /alerts, /rules): < 300ms
- **Single Resource** (GET /rules/{id}): < 100ms
- **Create/Update** (POST /rules, PUT /rules/{id}): < 500ms
- **Search** (POST /events/search): < 1000ms
- **Dashboard** (GET /dashboard): < 200ms
- **Authentication** (POST /auth/login): < 200ms

**Load Conditions**:
- Normal load: 100 concurrent users, 500 req/min
- Peak load: 500 concurrent users, 2500 req/min

**Timeout Configuration**:
- Request read timeout: 15 seconds
- Request write timeout: 15 seconds
- Idle timeout: 60 seconds
- Header read timeout: 5 seconds

**Acceptance Criteria**:
- [ ] Response time SLAs documented
- [ ] Load testing validates SLAs under normal load
- [ ] Load testing validates SLAs under peak load
- [x] Server timeouts configured
- [ ] Response time metrics tracked per endpoint
- [ ] Slow query alerts configured

**Current Implementation**: ⚠️ PARTIAL (timeouts configured in api.go:331-334, SLA validation TBD)

**TBD**:
- [ ] Load testing to validate SLAs
- [ ] Per-endpoint latency metrics
- [ ] Slow query identification and optimization

---

#### FR-API-020: Request Size Limits
**Requirement**: API MUST enforce request size limits to prevent resource exhaustion.

**Rationale**: Unbounded request sizes enable DoS attacks via memory exhaustion.

**Specification**:

**Size Limits**:
- Request body: 10 MB (api.go:37)
- Request headers: 1 MB (api.go:38)
- File uploads: 50 MB (for rule imports, future)
- URL length: 8 KB (HTTP server default)

**Limit Enforcement**:
- Request exceeding body limit returns 413 Payload Too Large
- Headers exceeding limit cause connection closure
- Size limits logged and monitored

**Per-Endpoint Limits**:
- Rule creation: 1 MB (api/handlers.go:167)
- Action creation: 512 KB (api/handlers.go:370)
- Correlation rule: 1 MB (api/handlers.go:569)
- Event search: 10 MB (for complex queries)

**Acceptance Criteria**:
- [x] Request body size limited globally
- [x] Request header size limited
- [x] Per-endpoint size limits enforced
- [x] Oversized requests rejected with 413
- [ ] Size limit violations logged

**Current Implementation**: ✅ COMPLIANT (api/api.go:36-48, api/handlers.go per-endpoint limits)

---

### 2.9 API Documentation

#### FR-API-021: OpenAPI Specification
**Requirement**: API MUST be fully documented using OpenAPI 3.0 specification.

**Rationale**: OpenAPI spec enables automated client generation, interactive documentation, and contract testing.

**Specification**:

**OpenAPI Components**:
- All endpoints documented with paths, methods, parameters
- Request/response schemas defined
- Authentication schemes documented
- Error responses documented
- Examples provided for all operations

**Documentation Tools**:
- Swagger UI: Interactive API explorer at `/swagger/`
- OpenAPI JSON: Machine-readable spec at `/swagger/swagger.json`
- Code generation: Support for client SDK generation

**Required Fields per Endpoint**:
- Summary: Brief description
- Description: Detailed explanation
- Parameters: Query, path, header parameters with types
- Request body: Schema with examples
- Responses: All possible status codes with schemas
- Security: Required authentication
- Tags: Logical grouping

**Acceptance Criteria**:
- [x] Swagger annotations present in code
- [x] Swagger UI accessible at `/swagger/`
- [ ] All endpoints documented with examples
- [ ] Request/response schemas complete
- [ ] Error responses documented
- [ ] Client SDK generation validated

**Current Implementation**: ✅ PARTIAL (Swagger setup in api.go:1-16, annotations partial)

---

#### FR-API-022: API Changelog
**Requirement**: API changes MUST be documented in a changelog following Keep a Changelog format.

**Rationale**: Changelog enables clients to track breaking changes, deprecations, and new features.

**Specification**:

**Changelog Sections**:
- `[Added]`: New endpoints, parameters, features
- `[Changed]`: Modifications to existing functionality
- `[Deprecated]`: Soon-to-be-removed features
- `[Removed]`: Deleted endpoints or features
- `[Fixed]`: Bug fixes
- `[Security]`: Security-related changes

**Example Entry**:
```markdown
## [1.2.0] - 2025-01-16

### Added
- New endpoint: POST /api/v1/investigations for creating investigations
- Support for RBAC with role-based permissions
- Rate limiting headers in all responses

### Changed
- Pagination format now includes `total_pages` field
- Event timestamps now include millisecond precision

### Deprecated
- GET /api/v1/events without pagination (use `page` and `limit` parameters)
- Sunset date: 2025-07-16

### Security
- Fixed CSRF token validation bypass in PATCH requests
```

**Acceptance Criteria**:
- [ ] CHANGELOG.md file created
- [ ] All API changes documented
- [ ] Breaking changes clearly marked
- [ ] Deprecation dates specified
- [ ] Changelog published in docs

**Current Implementation**: ❌ NOT IMPLEMENTED

---

## 3. Non-Functional Requirements

### 3.1 Performance

**NFR-API-001: Concurrent Request Handling**
- API MUST handle 500 concurrent requests without degradation
- Request queuing MUST not exceed 5 seconds under peak load
- Connection pool MUST support 1000 concurrent connections

**NFR-API-002: Throughput**
- API MUST sustain 2500 requests/minute under normal load
- API MUST sustain 10,000 requests/minute burst load for 1 minute
- Database connection pool sized appropriately for throughput

### 3.2 Reliability

**NFR-API-003: Availability**
- API MUST achieve 99.9% uptime (43.8 minutes downtime/month)
- API MUST recover from crashes within 30 seconds
- API MUST handle graceful shutdown without dropping requests

**NFR-API-004: Error Rate**
- 5xx error rate MUST be < 0.1% of total requests
- Transient errors MUST be retried automatically (circuit breaker)
- Database failures MUST not cascade to API failures

### 3.3 Security

**NFR-API-005: Transport Security**
- API MUST support TLS 1.2 and TLS 1.3
- API MUST reject SSLv3, TLS 1.0, TLS 1.1
- API MUST use strong cipher suites only
- HSTS header MUST be set: `Strict-Transport-Security: max-age=31536000; includeSubDomains`

**NFR-API-006: Input Validation**
- ALL input MUST be validated before processing
- SQL/NoSQL injection MUST be prevented via parameterized queries
- XSS MUST be prevented via output encoding
- Path traversal MUST be prevented via whitelist validation

**NFR-API-007: Audit Logging**
- All authentication events MUST be logged
- All authorization failures MUST be logged
- All data modifications MUST be logged with user context
- Logs MUST be tamper-proof (write-only)

### 3.4 Scalability

**NFR-API-008: Horizontal Scaling**
- API MUST be stateless (no local session storage)
- API MUST support deployment across multiple instances
- Load balancer MUST distribute traffic evenly
- No server affinity required (any instance can handle any request)

**NFR-API-009: Database Connection Pooling**
- Connection pool MUST be configurable (default: 100 connections)
- Connection pool MUST implement health checks
- Failed connections MUST be retired and replaced
- Connection leaks MUST be prevented via timeouts

---

## 4. Test Requirements

### 4.1 Unit Tests

**TEST-API-001: Request Validation**
- GIVEN a request with missing required field
- WHEN the request is validated
- THEN 400 Bad Request is returned with field error details

**TEST-API-002: Authentication**
- GIVEN an unauthenticated request to protected endpoint
- WHEN the request is processed
- THEN 401 Unauthorized is returned

**TEST-API-003: Rate Limiting**
- GIVEN 101 requests from same IP in 1 minute
- WHEN the 101st request is sent
- THEN 429 Too Many Requests is returned

### 4.2 Integration Tests

**TEST-API-004: End-to-End CRUD**
- GIVEN authenticated user
- WHEN creating, reading, updating, deleting a rule
- THEN all operations succeed with correct status codes

**TEST-API-005: Pagination**
- GIVEN 150 rules exist
- WHEN requesting page 2 with limit 50
- THEN items 51-100 are returned with correct pagination metadata

### 4.3 Performance Tests

**TEST-API-006: Load Test**
- GIVEN 500 concurrent users
- WHEN each user makes 10 requests
- THEN p95 latency < 300ms and 0% errors

**TEST-API-007: Stress Test**
- GIVEN increasing load from 100 to 1000 concurrent users
- WHEN requests sent continuously for 10 minutes
- THEN identify breaking point and degradation curve

### 4.4 Security Tests

**TEST-API-008: SQL Injection**
- GIVEN malicious input with SQL injection payload
- WHEN submitted to API endpoint
- THEN input is sanitized and query returns safely

**TEST-API-009: CSRF Protection**
- GIVEN POST request without CSRF token
- WHEN request is sent to protected endpoint
- THEN 403 Forbidden is returned

**TEST-API-010: JWT Validation**
- GIVEN expired JWT token
- WHEN request is sent to protected endpoint
- THEN 401 Unauthorized is returned

---

## 5. TBD Tracker

| ID | Description | Owner | Target Date | Status |
|----|-------------|-------|-------------|--------|
| TBD-001 | Finalize RBAC permission model | Backend Team | 2025-02-15 | Open |
| TBD-002 | Implement PATCH support for partial updates | Backend Team | 2025-03-01 | Open |
| TBD-003 | Implement API deprecation headers | Backend Team | 2025-02-01 | Open |
| TBD-004 | Complete OpenAPI schema documentation | Backend Team | 2025-02-15 | Open |
| TBD-005 | Load testing to validate performance SLAs | QA Team | 2025-03-15 | Open |
| TBD-006 | WebSocket authentication formalization | Backend Team | 2025-02-01 | Open |
| TBD-007 | Implement filtering and sorting on collections | Backend Team | 2025-03-15 | Open |
| TBD-008 | Create API changelog | Backend Team | 2025-02-01 | Open |
| TBD-009 | Implement Link headers for pagination | Backend Team | 2025-03-01 | Open |
| TBD-010 | Account lockout notification mechanism | Backend Team | 2025-02-15 | Open |

---

## 6. Compliance Verification Checklist

### RESTful API Design
- [x] Resource-oriented URLs
- [x] Correct HTTP method usage
- [x] Appropriate HTTP status codes
- [x] JSON content negotiation

### Versioning
- [x] URL-based versioning implemented
- [ ] API deprecation policy documented
- [ ] Deprecation headers implemented
- [ ] Migration guides available

### Request/Response
- [x] JSON schema validation
- [x] Consistent field naming (snake_case)
- [x] Pagination support
- [ ] Filtering and sorting
- [x] Error response format

### Security
- [x] JWT authentication
- [ ] RBAC authorization
- [x] CSRF protection
- [x] Rate limiting
- [x] Input validation
- [x] Error sanitization

### Performance
- [x] Request size limits
- [x] Timeouts configured
- [ ] Performance SLAs validated
- [ ] Load testing completed

### Documentation
- [x] Swagger/OpenAPI spec
- [x] Swagger UI available
- [ ] All endpoints documented
- [ ] API changelog maintained

---

## 7. References

### Industry Standards
- [Microsoft REST API Guidelines](https://github.com/microsoft/api-guidelines)
- [OpenAPI Specification 3.0](https://spec.openapis.org/oas/v3.0.0)
- [RFC 7231: HTTP/1.1 Semantics](https://tools.ietf.org/html/rfc7231)
- [RFC 6749: OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 8594: Sunset HTTP Header](https://tools.ietf.org/html/rfc8594)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

### Internal Documents
- `docs/requirements/security-threat-model.md`: Security requirements
- `docs/requirements/performance-requirements.md`: Performance SLAs
- `api/api.go`: Current API implementation
- `frontend/src/services/api.ts`: Frontend API client

### Related Code
- `api/api.go:166-323`: Route definitions
- `api/handlers.go`: Request handlers
- `api/middleware.go`: Authentication, CSRF, rate limiting
- `api/validation.go`: Request validation
- `api/jwt.go`: JWT token management
- `frontend/src/schemas/api.schemas.ts`: Response validation schemas

---

## 8. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-16 | Requirements Team | Initial draft based on codebase analysis |

---

**Document Status**: DRAFT - Awaiting technical review and stakeholder approval

**Next Steps**:
1. Technical review by backend team (target: 2025-01-23)
2. Security review by security team (target: 2025-01-30)
3. Stakeholder approval (target: 2025-02-06)
4. Address TBD items and implement missing requirements
