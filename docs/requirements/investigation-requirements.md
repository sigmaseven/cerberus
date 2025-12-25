# Investigation Management Requirements

**Document Owner**: Backend Team  
**Created**: 2025-01-19  
**Status**: ACTIVE  
**Last Updated**: 2025-01-19  
**Version**: 1.0  

**Reference Implementation**: `api/investigation_handlers.go`, `storage/investigation_lifecycle.go`

---

## 1. Executive Summary

The Cerberus SIEM investigation management system provides comprehensive capabilities for creating, managing, and tracking security investigations throughout their lifecycle. This document defines the requirements for investigation creation, lifecycle management, alert association, timeline generation, and closure operations.

**Critical Requirements**:
- Investigation lifecycle management (open → in-progress → closed)
- Many-to-many alert-to-investigation association
- Immutable investigation notes (audit trail)
- Chronological timeline generation
- Investigation closure with verdict and resolution details
- Investigation statistics and reporting

**Implementation Status**: ✅ 100% IMPLEMENTED

---

## 2. Functional Requirements

### FR-INV-001: Investigation Creation
**Requirement**: The system MUST support creating new security investigations.

**Specification**:
- Required fields:
  - `title`: Investigation title (1-200 characters)
  - `description`: Investigation description (max 2000 characters)
  - `priority`: Investigation priority (critical, high, medium, low)
- Optional fields:
  - `assignee_id`: Assigned analyst (defaults to creator)
  - `alert_ids`: Initial alerts to associate
- Auto-generated fields:
  - `investigation_id`: Unique identifier (format: INV-YYYYMMDD-XXXX)
  - `created_by`: Creator user ID
  - `created_at`: Creation timestamp
  - `status`: Initial status (open)
  - `updated_at`: Update timestamp

**Implementation**: `api/investigation_handlers.go:137-189` (createInvestigation)

**Acceptance Criteria**:
- [x] Investigations can be created with required fields
- [x] Investigations get unique IDs
- [x] Investigations default to "open" status
- [x] Creator is automatically recorded

---

### FR-INV-002: Investigation Lifecycle Management
**Requirement**: The system MUST support investigation state transitions with validation.

**Specification**:
- Valid state transitions:
  - `open` → `in_progress`
  - `in_progress` → `awaiting_review`, `resolved`, `false_positive`
  - `awaiting_review` → `resolved`, `in_progress`
  - `resolved` → `closed`
  - `false_positive` → `closed`
  - `closed` → (no transitions allowed)
- State transitions MUST be validated before execution
- State transitions MUST be logged for audit trail
- Invalid transitions MUST be rejected with clear error messages

**Implementation**: 
- `storage/investigation_lifecycle.go:14-58` (ValidateStateTransition)
- `storage/investigation_lifecycle.go:60-82` (LogStateTransition)
- `storage/sqlite_investigations.go:241-361` (UpdateInvestigation with transaction)

**Acceptance Criteria**:
- [x] State transitions are validated
- [x] Invalid transitions are rejected
- [x] State transitions are logged
- [x] State transitions are atomic (wrapped in transactions)

---

### FR-INV-003: Investigation Metadata
**Requirement**: Investigations MUST include comprehensive metadata for tracking and organization.

**Specification**:
- Core metadata:
  - `investigation_id`: Unique identifier
  - `title`: Investigation title
  - `description`: Investigation description
  - `priority`: Priority level (critical, high, medium, low)
  - `status`: Current status
  - `assignee_id`: Assigned analyst
  - `created_by`: Creator user ID
  - `created_at`: Creation timestamp
  - `updated_at`: Last update timestamp
  - `closed_at`: Closure timestamp (if closed)
- MITRE ATT&CK metadata:
  - `mitre_tactics`: Associated MITRE tactics
  - `mitre_techniques`: Associated MITRE techniques
- Investigation artifacts:
  - `artifacts`: Extracted artifacts (IPs, hosts, users, files, hashes, processes)
  - `affected_assets`: Affected assets list
- Tags and categorization:
  - `tags`: Custom tags for categorization

**Implementation**: `core/investigation.go:103-127` (Investigation struct)

**Acceptance Criteria**:
- [x] All metadata fields are supported
- [x] Metadata is validated on creation/update
- [x] Metadata is stored and retrievable

---

### FR-INV-004: Investigation Notes
**Requirement**: The system MUST support immutable investigation notes as an audit trail.

**Specification**:
- Notes are immutable (cannot be modified or deleted)
- Each note includes:
  - `id`: Unique note identifier
  - `analyst_id`: Analyst who created the note
  - `content`: Note content (1-5000 characters)
  - `created_at`: Note creation timestamp
- Notes are ordered chronologically
- Notes are included in investigation timeline

**Implementation**: 
- `core/investigation.go:78-84` (InvestigationNote struct)
- `api/investigation_handlers.go:388-430` (addInvestigationNote)
- `storage/sqlite_investigations.go:532-553` (AddNote)

**Acceptance Criteria**:
- [x] Notes can be added to investigations
- [x] Notes are immutable
- [x] Notes include analyst ID and timestamp
- [x] Notes appear in timeline

---

### FR-INV-005: Alert-to-Investigation Association
**Requirement**: The system MUST support many-to-many alert-to-investigation association.

**Specification**:
- Alerts can be associated with multiple investigations
- Investigations can contain multiple alerts
- Association is tracked via junction table (`investigation_alerts`)
- Association metadata:
  - `investigation_id`: Investigation identifier
  - `alert_id`: Alert identifier
  - `associated_at`: Association timestamp
  - `associated_by`: User who created association
- Alerts can be dissociated from investigations
- Alert association changes are logged

**Implementation**:
- `storage/investigation_lifecycle.go:86-104` (AssociateAlert)
- `storage/investigation_lifecycle.go:108-129` (DissociateAlert)
- `api/investigation_handlers.go:451-489` (addInvestigationAlert)

**Acceptance Criteria**:
- [x] Alerts can be associated with investigations
- [x] Alerts can be dissociated from investigations
- [x] Association metadata is tracked
- [x] Many-to-many relationship is supported

---

### FR-INV-006: Investigation Timeline Generation
**Requirement**: The system MUST generate chronological timelines of investigation events.

**Specification**:
- Timeline includes:
  - Associated alerts (with metadata: alert_id, rule_id, severity, timestamp)
  - State transitions (from_status → to_status, changed_by, timestamp)
  - Investigation notes (analyst_id, content, timestamp)
- Timeline is ordered chronologically (newest first)
- Timeline supports pagination (limit: 100-1000, offset)
- Timeline includes total count for pagination

**Implementation**:
- `storage/investigation_lifecycle.go:248-356` (GenerateTimeline)
- `api/investigation_handlers.go:491-573` (getInvestigationTimeline)

**Acceptance Criteria**:
- [x] Timeline includes alerts, transitions, and notes
- [x] Timeline is chronologically ordered
- [x] Timeline supports pagination
- [x] Timeline returns total count

---

### FR-INV-007: Investigation Closure
**Requirement**: The system MUST support investigation closure with verdict and resolution details.

**Specification**:
- Closure requires:
  - `verdict`: Investigation verdict (true_positive, false_positive, inconclusive)
  - `resolution_category`: Resolution category (incident_contained, incident_resolved, false_alarm, etc.)
  - `summary`: Closure summary (max 5000 characters)
- Optional closure fields:
  - `affected_assets`: List of affected assets
  - `ml_feedback`: ML model feedback for training
- Closure requirements MUST be validated before closure
- Closure sets status to "closed" and records `closed_at` timestamp
- Closure triggers state transition validation and logging

**Implementation**:
- `api/investigation_handlers.go:323-367` (closeInvestigation)
- `storage/sqlite_investigations.go:586-612` (CloseInvestigation)
- `storage/investigation_lifecycle.go:434-471` (ValidateClosureRequirements)

**Acceptance Criteria**:
- [x] Investigations can be closed with verdict
- [x] Closure requirements are validated
- [x] Closure records resolution details
- [x] Closure updates status and timestamp

---

### FR-INV-008: Investigation Statistics
**Requirement**: The system MUST provide detailed statistics for investigations.

**Specification**:
- Statistics include:
  - `total_alerts`: Total number of associated alerts
  - `severity_distribution`: Count of alerts by severity (high, medium, low)
  - `mitre_techniques`: Unique list of MITRE techniques from alerts
  - `mitre_tactics`: Unique list of MITRE tactics
  - `first_alert_timestamp`: Timestamp of first alert
  - `last_alert_timestamp`: Timestamp of last alert
  - `time_range_hours`: Duration between first and last alert

**Implementation**: `storage/investigation_lifecycle.go:370-441` (CalculateStatistics)

**Acceptance Criteria**:
- [x] Statistics include alert counts and distributions
- [x] Statistics include MITRE aggregation
- [x] Statistics include time range calculations

---

### FR-INV-009: Investigation Retrieval
**Requirement**: The system MUST support retrieving investigations with filtering and pagination.

**Specification**:
- List investigations with filters:
  - `status`: Filter by status
  - `priority`: Filter by priority
  - `assignee_id`: Filter by assignee
  - `created_at`: Filter by creation date range
- Pagination support:
  - `page`: Page number (1-based)
  - `limit`: Items per page (1-1000, default: 20)
- Single investigation retrieval by ID
- Investigation retrieval includes all metadata and associated data

**Implementation**: 
- `api/investigation_handlers.go:45-84` (getInvestigations)
- `api/investigation_handlers.go:98-114` (getInvestigation)

**Acceptance Criteria**:
- [x] Investigations can be listed with filters
- [x] Investigations support pagination
- [x] Single investigation can be retrieved by ID
- [x] All metadata is included in retrieval

---

### FR-INV-010: Investigation Updates
**Requirement**: The system MUST support updating investigation metadata.

**Specification**:
- Updatable fields:
  - `title`: Investigation title
  - `description`: Investigation description
  - `priority`: Investigation priority
  - `status`: Investigation status (with state transition validation)
  - `assignee_id`: Assigned analyst
- Immutable fields:
  - `investigation_id`: Cannot be changed
  - `created_by`: Cannot be changed
  - `created_at`: Cannot be changed
- Updates MUST trigger state transition validation if status changes
- Updates MUST update `updated_at` timestamp

**Implementation**: `api/investigation_handlers.go:215-269` (updateInvestigation)

**Acceptance Criteria**:
- [x] Investigation metadata can be updated
- [x] Immutable fields are protected
- [x] State transitions are validated
- [x] Timestamps are updated

---

### FR-INV-011: Investigation Deletion
**Requirement**: The system MUST support deleting investigations (admin only).

**Specification**:
- Investigation deletion requires `admin:system` permission
- Deletion removes investigation and associated data:
  - Investigation record
  - Alert associations (via CASCADE)
  - State transition logs (via CASCADE)
- Deletion is permanent (no soft delete)
- Deletion SHOULD be logged for audit

**Implementation**: `api/investigation_handlers.go:283-298` (deleteInvestigation)

**Acceptance Criteria**:
- [x] Investigations can be deleted
- [x] RBAC enforcement for deletion
- [x] Associated data is cleaned up

---

### FR-INV-012: Investigation API Endpoints
**Requirement**: The system MUST provide REST API endpoints for investigation operations.

**Specification**:
- `GET /api/v1/investigations`: List investigations (with filters and pagination)
- `GET /api/v1/investigations/{id}`: Get single investigation
- `POST /api/v1/investigations`: Create investigation
- `PUT /api/v1/investigations/{id}`: Update investigation
- `DELETE /api/v1/investigations/{id}`: Delete investigation
- `POST /api/v1/investigations/{id}/notes`: Add note to investigation
- `POST /api/v1/investigations/{id}/alerts`: Add alert to investigation
- `POST /api/v1/investigations/{id}/close`: Close investigation
- `GET /api/v1/investigations/{id}/timeline`: Get investigation timeline
- `GET /api/v1/investigations/{id}/statistics`: Get investigation statistics

**RBAC Requirements**:
- List investigations: `read:alerts` permission
- Get investigation: `read:alerts` permission
- Create investigation: `write:alerts` permission
- Update investigation: `write:alerts` permission
- Delete investigation: `admin:system` permission
- Add note: `write:alerts` permission
- Add alert: `write:alerts` permission
- Close investigation: `write:alerts` permission
- Get timeline: `read:alerts` permission
- Get statistics: `read:alerts` permission

**Implementation**: `api/investigation_handlers.go` (all endpoints)

**Acceptance Criteria**:
- [x] All endpoints are implemented
- [x] RBAC is enforced
- [x] Endpoints validate input
- [x] Endpoints return appropriate status codes

---

### FR-INV-013: Investigation State Transition Logging
**Requirement**: All investigation state transitions MUST be logged for audit purposes.

**Specification**:
- State transition logs include:
  - `investigation_id`: Investigation identifier
  - `from_status`: Previous status
  - `to_status`: New status
  - `changed_by`: User who made the change
  - `changed_at`: Timestamp of change
  - `reason`: Optional reason for transition
- State transition logs are stored in `investigation_state_transitions` table
- State transition logs are immutable (cannot be modified or deleted)
- State transition logs are included in timeline generation

**Implementation**: 
- `storage/investigation_lifecycle.go:60-82` (LogStateTransition)
- `storage/sqlite_investigations.go:259` (LogStateTransition called in UpdateInvestigation)

**Acceptance Criteria**:
- [x] State transitions are logged
- [x] Logs include all required metadata
- [x] Logs are immutable
- [x] Logs appear in timeline

---

### FR-INV-014: Investigation Alert Queries
**Requirement**: The system MUST support querying alerts and investigations bidirectionally.

**Specification**:
- Get alerts for investigation: `GetAlertsForInvestigation(investigationID)`
  - Returns all alerts associated with an investigation
  - Ordered by timestamp (newest first)
- Get investigations for alert: `GetInvestigationsForAlert(alertID)`
  - Returns all investigations associated with an alert
  - Ordered by creation date (newest first)

**Implementation**:
- `storage/investigation_lifecycle.go:133-200` (GetAlertsForInvestigation)
- `storage/investigation_lifecycle.go:203-242` (GetInvestigationsForAlert)

**Acceptance Criteria**:
- [x] Alerts can be queried for an investigation
- [x] Investigations can be queried for an alert
- [x] Queries return ordered results

---

### FR-INV-015: Investigation Closure Requirements Validation
**Requirement**: Investigation closure MUST validate that all required information is present.

**Specification**:
- Closure validation checks:
  - Verdict is provided and valid
  - Resolution category is provided
  - Summary is provided and non-empty
- Validation occurs before closure
- Invalid closure requests are rejected with clear error messages

**Implementation**: `storage/investigation_lifecycle.go:434-471` (ValidateClosureRequirements)

**Acceptance Criteria**:
- [x] Closure requirements are validated
- [x] Invalid closures are rejected
- [x] Error messages are clear

---

## 3. Non-Functional Requirements

### NFR-INV-001: Investigation Performance
**Requirement**: Investigation operations MUST complete within reasonable time limits.

**Specification**:
- Create investigation: < 100ms p95
- Update investigation: < 200ms p95
- Get investigation: < 50ms p95
- List investigations (20 items): < 200ms p95
- Generate timeline (100 items): < 500ms p95
- Calculate statistics: < 1000ms p95

**Acceptance Criteria**:
- [ ] Performance targets are met
- [ ] Performance scales with data size

---

### NFR-INV-002: Investigation Scalability
**Requirement**: The system MUST support large numbers of investigations and associations.

**Specification**:
- Support 10,000+ active investigations
- Support 100,000+ alert-investigation associations
- Support 1,000+ notes per investigation
- Timeline generation scales to 10,000+ timeline entries

**Acceptance Criteria**:
- [ ] System handles scale requirements
- [ ] Performance degrades gracefully

---

### NFR-INV-003: Investigation Data Integrity
**Requirement**: Investigation data MUST maintain referential integrity and consistency.

**Specification**:
- Foreign key constraints enforce alert-investigation associations
- State transitions are atomic (wrapped in transactions)
- Notes are immutable (no updates or deletes)
- Closure data is validated before persistence

**Implementation**: 
- Transaction wrapping: `storage/sqlite_investigations.go:279-360`
- Foreign key constraints: `storage/sqlite.go` (table creation)

**Acceptance Criteria**:
- [x] Foreign keys are enforced
- [x] Transactions ensure atomicity
- [x] Data integrity is maintained

---

### NFR-INV-004: Investigation Audit Trail
**Requirement**: All investigation changes MUST be auditable.

**Specification**:
- State transitions are logged
- Notes are immutable (audit trail)
- Closure records verdict and resolution
- All changes include user ID and timestamp

**Implementation**: 
- State transition logging: `storage/investigation_lifecycle.go:60-82`
- Immutable notes: `core/investigation.go:78-84`

**Acceptance Criteria**:
- [x] All changes are logged
- [x] Audit trail is complete
- [x] Audit trail is immutable

---

### NFR-INV-005: Investigation Security
**Requirement**: Investigation operations MUST enforce RBAC and prevent unauthorized access.

**Specification**:
- All endpoints require authentication
- RBAC permissions are enforced on all operations
- Investigation data is protected from unauthorized access
- Investigation deletion requires `admin:system` permission

**Implementation**: `api/api.go:325-331` (RBAC-protected routes)

**Acceptance Criteria**:
- [x] RBAC is enforced
- [x] Unauthorized access is prevented
- [x] Admin-only operations are protected

---

## 4. API Endpoints

### GET /api/v1/investigations
List investigations with optional filtering and pagination.

**Query Parameters**:
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20, max: 1000)
- `status`: Filter by status
- `priority`: Filter by priority
- `assignee`: Filter by assignee ID

**Response**: 200 OK
```json
{
  "items": [...],
  "total": 100,
  "page": 1,
  "limit": 20,
  "total_pages": 5
}
```

**RBAC**: Requires `read:alerts` permission

---

### GET /api/v1/investigations/{id}
Get single investigation by ID.

**Response**: 200 OK
```json
{
  "investigation_id": "INV-20250108-0042",
  "title": "Suspected Lateral Movement",
  ...
}
```

**RBAC**: Requires `read:alerts` permission

---

### POST /api/v1/investigations
Create new investigation.

**Request Body**:
```json
{
  "title": "Suspected Lateral Movement",
  "description": "Multiple failed login attempts...",
  "priority": "critical",
  "assignee_id": "user123",
  "alert_ids": ["alert-001", "alert-002"]
}
```

**Response**: 201 Created
```json
{
  "investigation_id": "INV-20250108-0042",
  ...
}
```

**RBAC**: Requires `write:alerts` permission

---

### PUT /api/v1/investigations/{id}
Update investigation.

**Request Body**:
```json
{
  "title": "Updated Title",
  "priority": "high",
  "status": "in_progress"
}
```

**Response**: 200 OK

**RBAC**: Requires `write:alerts` permission

---

### DELETE /api/v1/investigations/{id}
Delete investigation.

**Response**: 204 No Content

**RBAC**: Requires `admin:system` permission

---

### POST /api/v1/investigations/{id}/notes
Add note to investigation.

**Request Body**:
```json
{
  "content": "Initial analysis complete..."
}
```

**Response**: 200 OK

**RBAC**: Requires `write:alerts` permission

---

### POST /api/v1/investigations/{id}/alerts
Add alert to investigation.

**Request Body**:
```json
{
  "alert_id": "alert-003"
}
```

**Response**: 200 OK

**RBAC**: Requires `write:alerts` permission

---

### POST /api/v1/investigations/{id}/close
Close investigation.

**Request Body**:
```json
{
  "verdict": "true_positive",
  "resolution_category": "incident_contained",
  "summary": "Investigation complete...",
  "affected_assets": ["host-001", "host-002"]
}
```

**Response**: 200 OK

**RBAC**: Requires `write:alerts` permission

---

### GET /api/v1/investigations/{id}/timeline
Get investigation timeline.

**Query Parameters**:
- `limit`: Items per page (default: 100, max: 1000)
- `offset`: Offset for pagination

**Response**: 200 OK
```json
{
  "investigation_id": "INV-20250108-0042",
  "timeline": [...]
}
```

**RBAC**: Requires `read:alerts` permission

---

### GET /api/v1/investigations/{id}/statistics
Get investigation statistics.

**Response**: 200 OK
```json
{
  "total_alerts": 10,
  "severity_distribution": {
    "high": 5,
    "medium": 3,
    "low": 2
  },
  "mitre_techniques": ["T1078", "T1110"],
  ...
}
```

**RBAC**: Requires `read:alerts` permission

---

## 5. Data Models

### Investigation
```go
type Investigation struct {
    InvestigationID    string
    Title              string
    Description        string
    Priority           InvestigationPriority
    Status             InvestigationStatus
    AssigneeID         string
    CreatedBy          string
    CreatedAt          time.Time
    UpdatedAt          time.Time
    ClosedAt           *time.Time
    AlertIDs           []string
    EventIDs           []string
    MitreTactics       []string
    MitreTechniques    []string
    Artifacts          InvestigationArtifacts
    Notes              []InvestigationNote
    Verdict            InvestigationVerdict
    ResolutionCategory string
    Summary            string
    AffectedAssets     []string
    MLFeedback         *MLFeedback
    Tags               []string
}
```

### InvestigationNote
```go
type InvestigationNote struct {
    ID        string
    AnalystID string
    Content   string
    CreatedAt time.Time
}
```

### TimelineEntry
```go
type TimelineEntry struct {
    ID          string
    Type        string  // "alert", "state_change", "note"
    Timestamp   time.Time
    Title       string
    Description string
    UserID      string
    Metadata    map[string]interface{}
}
```

---

## 6. Security Considerations

1. **RBAC Enforcement**: All investigation operations require appropriate permissions
2. **Immutable Notes**: Notes cannot be modified or deleted (audit trail)
3. **State Transition Validation**: Invalid state transitions are prevented
4. **Audit Logging**: All state transitions are logged for audit
5. **Data Protection**: Investigation data is protected from unauthorized access

---

## 7. Testing Requirements

1. **Unit Tests**:
   - Test investigation creation
   - Test state transition validation
   - Test timeline generation
   - Test statistics calculation
   - Test closure validation

2. **Integration Tests**:
   - Test alert association/dissociation
   - Test note addition
   - Test investigation closure
   - Test API endpoints

3. **Security Tests**:
   - Test RBAC enforcement
   - Test unauthorized access prevention
   - Test state transition validation

---

## 8. Known Limitations

1. **Soft Delete**: Investigations are permanently deleted (no soft delete)
2. **Bulk Operations**: Bulk investigation operations are not yet supported
3. **Investigation Templates**: Investigation templates are not yet implemented
4. **Investigation Collaboration**: Real-time collaboration features are not yet implemented

---

## 9. Future Enhancements

1. **Investigation Templates**: Pre-defined investigation templates for common scenarios
2. **Investigation Workflows**: Customizable investigation workflows
3. **Investigation Collaboration**: Real-time collaboration features (comments, mentions)
4. **Investigation Automation**: Automated investigation creation from alerts
5. **Investigation Reporting**: Advanced investigation reporting and analytics
6. **Investigation Export**: Export investigations to PDF, CSV, JSON formats
7. **Investigation Archival**: Archive closed investigations for long-term storage

---

_This document defines the comprehensive requirements for investigation management in Cerberus SIEM. All functional requirements marked with [x] are implemented. Future enhancements are documented for roadmap planning._



