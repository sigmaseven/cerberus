# Alert Lifecycle Management - Backend API Requirements

This document outlines the backend changes required to support the new Alert Lifecycle Management features implemented in the frontend.

---

## Overview

The frontend now supports comprehensive alert lifecycle management including:
- **Status management** (workflow state)
- **Disposition management** (threat classification)
- **Assignee management**
- **Investigation linking**

---

## 1. Database Schema Changes

### 1.1 New Fields on `alerts` Table

Add the following columns to the `alerts` table:

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `disposition` | `VARCHAR(20)` / `ENUM` | Yes | `'undetermined'` | Threat classification |
| `disposition_reason` | `TEXT` | Yes | `NULL` | Analyst's justification for disposition |
| `disposition_set_at` | `TIMESTAMP` | Yes | `NULL` | When disposition was last changed |
| `disposition_set_by` | `UUID` (FK to users) | Yes | `NULL` | User who set the disposition |

### 1.2 Disposition Enum Values

```sql
CREATE TYPE alert_disposition AS ENUM (
  'undetermined',    -- Default - not yet analyzed
  'true_positive',   -- Confirmed malicious activity (displayed as "Malicious" in UI)
  'false_positive',  -- Not malicious (false alarm)
  'benign',          -- Activity is expected/approved
  'suspicious',      -- Potentially malicious, needs more analysis
  'inconclusive'     -- Cannot determine with available evidence
);
```

### 1.3 New Activity Type

Add `'disposition_changed'` to the `activity_type` enum:

```sql
ALTER TYPE activity_type ADD VALUE 'disposition_changed';
```

---

## 2. API Endpoints

### 2.1 Update Alert Disposition

**Endpoint:** `PATCH /api/alerts/{alertId}/disposition`

**Request Body:**
```json
{
  "disposition": "true_positive",
  "reason": "Confirmed malicious PowerShell execution based on behavioral analysis"
}
```

**Validation Rules:**
- `disposition` must be one of: `undetermined`, `true_positive`, `false_positive`, `benign`, `suspicious`, `inconclusive`
- `reason` is optional but **recommended** when disposition is `false_positive`
- If `disposition` is set to `undetermined`, clear `reason`, `disposition_set_at`, and `disposition_set_by`

**Response:** `200 OK`
```json
{
  "id": "ALT-2024-001234",
  "disposition": "true_positive",
  "dispositionReason": "Confirmed malicious PowerShell execution based on behavioral analysis",
  "dispositionSetAt": "2024-12-09T15:30:00Z",
  "dispositionSetBy": {
    "id": "user-123",
    "name": "John Smith",
    "email": "john.smith@example.com"
  }
}
```

**Side Effects:**
- Create an activity log entry with type `disposition_changed`
- Set `disposition_set_at` to current timestamp
- Set `disposition_set_by` to authenticated user

---

### 2.2 Update Alert Assignee

**Endpoint:** `PATCH /api/alerts/{alertId}/assignee`

**Request Body:**
```json
{
  "assigneeId": "user-456"
}
```

To unassign:
```json
{
  "assigneeId": null
}
```

**Response:** `200 OK`
```json
{
  "id": "ALT-2024-001234",
  "assignee": {
    "id": "user-456",
    "name": "Jane Doe",
    "email": "jane.doe@example.com"
  }
}
```

**Side Effects:**
- Create an activity log entry with type `assignment`
- Activity description should include previous and new assignee names

---

### 2.3 Create Investigation from Alert

**Endpoint:** `POST /api/alerts/{alertId}/investigation`

**Request Body:**
```json
{
  "title": "Investigation: Suspicious PowerShell Activity",
  "description": "Investigation created from alert ALT-2024-001234"
}
```

If no body provided, auto-generate title/description from alert data.

**Response:** `201 Created`
```json
{
  "investigation": {
    "id": "INV-2024-000567",
    "title": "Investigation: Suspicious PowerShell Activity",
    "status": "open",
    "createdAt": "2024-12-09T15:30:00Z"
  },
  "alert": {
    "id": "ALT-2024-001234",
    "investigationId": "INV-2024-000567"
  }
}
```

**Side Effects:**
- Create new investigation record
- Link alert to investigation (`investigation_id` field)
- Create activity log entry with type `investigation_linked`
- Optionally copy alert evidence to investigation

---

### 2.4 Link Alert to Existing Investigation

**Endpoint:** `PATCH /api/alerts/{alertId}/investigation`

**Request Body:**
```json
{
  "investigationId": "INV-2024-000567"
}
```

**Response:** `200 OK`
```json
{
  "id": "ALT-2024-001234",
  "investigationId": "INV-2024-000567"
}
```

**Side Effects:**
- Create activity log entry with type `investigation_linked`
- Add alert reference to investigation's linked alerts

---

### 2.5 Get Available Users for Assignment

**Endpoint:** `GET /api/users/assignable`

**Query Parameters:**
- `role` (optional): Filter by role (e.g., `analyst`, `investigator`)
- `team` (optional): Filter by team

**Response:** `200 OK`
```json
{
  "users": [
    {
      "id": "user-123",
      "name": "John Smith",
      "email": "john.smith@example.com",
      "role": "analyst"
    },
    {
      "id": "user-456",
      "name": "Jane Doe",
      "email": "jane.doe@example.com",
      "role": "senior_analyst"
    }
  ]
}
```

---

## 3. Activity Log Schema

### 3.1 Disposition Changed Activity

When disposition changes, create an activity record:

```json
{
  "id": "act-789",
  "type": "disposition_changed",
  "alertId": "ALT-2024-001234",
  "timestamp": "2024-12-09T15:30:00Z",
  "user": {
    "id": "user-123",
    "name": "John Smith"
  },
  "description": "Changed disposition from undetermined to true_positive",
  "previousValue": "undetermined",
  "newValue": "true_positive",
  "metadata": {
    "reason": "Confirmed malicious PowerShell execution"
  }
}
```

---

## 4. Alert Response Schema Updates

### 4.1 Full Alert Response

Update the alert response to include new disposition fields:

```json
{
  "id": "ALT-2024-001234",
  "title": "Suspicious PowerShell Activity Detected",
  "description": "...",
  "status": "investigating",
  "severity": "high",
  "priority": "P2",

  "disposition": "true_positive",
  "dispositionReason": "Confirmed malicious PowerShell execution",
  "dispositionSetAt": "2024-12-09T15:30:00Z",
  "dispositionSetBy": {
    "id": "user-123",
    "name": "John Smith",
    "email": "john.smith@example.com"
  },

  "assignee": {
    "id": "user-456",
    "name": "Jane Doe",
    "email": "jane.doe@example.com"
  },

  "investigationId": "INV-2024-000567",

  "createdAt": "2024-12-09T10:00:00Z",
  "updatedAt": "2024-12-09T15:30:00Z"
}
```

### 4.2 Alert List Item Response

For list views, include summary disposition info:

```json
{
  "id": "ALT-2024-001234",
  "title": "Suspicious PowerShell Activity Detected",
  "status": "investigating",
  "severity": "high",
  "priority": "P2",
  "disposition": "true_positive",
  "assignee": {
    "id": "user-456",
    "name": "Jane Doe"
  },
  "createdAt": "2024-12-09T10:00:00Z"
}
```

---

## 5. Filtering and Sorting

### 5.1 New Filter Parameters

Add disposition filter to alert list endpoint:

**Endpoint:** `GET /api/alerts`

**New Query Parameters:**
- `disposition`: Filter by disposition value(s)
  - Example: `?disposition=true_positive,suspicious`
- `hasDisposition`: Boolean to filter alerts with/without disposition set
  - Example: `?hasDisposition=false` (returns only undetermined alerts)

### 5.2 Sorting

Add sorting by disposition-related fields:
- `dispositionSetAt`: Sort by when disposition was set

---

## 6. Business Rules

### 6.1 Disposition Validation

1. Any status can have any disposition (they are independent)
2. When marking as `false_positive` disposition, frontend will warn if no reason provided
3. Disposition changes should be audited (activity log)

### 6.2 Status Transitions

Existing status transition rules remain unchanged:

```
new -> acknowledged, investigating, escalated, closed
acknowledged -> investigating, escalated, resolved, closed
investigating -> escalated, resolved, false_positive, closed
escalated -> investigating, resolved, closed
resolved -> closed, investigating (reopen)
false_positive -> closed, investigating (reopen)
closed -> investigating (reopen)
```

### 6.3 Alert-Investigation Linking

1. An alert can only be linked to one investigation at a time
2. Unlinking requires explicit action (not covered in current frontend)
3. Multiple alerts can be linked to the same investigation

---

## 7. Migration Strategy

### 7.1 Database Migration

```sql
-- Add new columns
ALTER TABLE alerts
ADD COLUMN disposition VARCHAR(20) DEFAULT 'undetermined',
ADD COLUMN disposition_reason TEXT,
ADD COLUMN disposition_set_at TIMESTAMP,
ADD COLUMN disposition_set_by UUID REFERENCES users(id);

-- Add index for filtering
CREATE INDEX idx_alerts_disposition ON alerts(disposition);

-- Add activity type
ALTER TYPE activity_type ADD VALUE 'disposition_changed';
```

### 7.2 Data Migration

For existing alerts:
- Set `disposition = 'undetermined'` for all existing alerts
- Alerts with `status = 'false_positive'` could optionally be migrated to have `disposition = 'false_positive'`

---

## 8. API Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| `PATCH` | `/api/alerts/{alertId}/disposition` | Update alert disposition |
| `PATCH` | `/api/alerts/{alertId}/assignee` | Update alert assignee |
| `POST` | `/api/alerts/{alertId}/investigation` | Create investigation from alert |
| `PATCH` | `/api/alerts/{alertId}/investigation` | Link alert to existing investigation |
| `GET` | `/api/users/assignable` | Get users available for assignment |

---

## 9. Frontend Contract

The frontend expects the following response field names (camelCase):

```typescript
interface Alert {
  id: string;
  title: string;
  description: string;
  status: AlertStatus;
  severity: AlertSeverity;
  priority: AlertPriority;

  // New disposition fields
  disposition?: AlertDisposition;
  dispositionReason?: string;
  dispositionSetAt?: string;      // ISO 8601 timestamp
  dispositionSetBy?: UserReference;

  // Existing fields
  assignee?: UserReference;
  investigationId?: string;
  // ... other fields
}

interface UserReference {
  id: string;
  name: string;
  email?: string;
}

type AlertDisposition =
  | 'undetermined'
  | 'true_positive'   // Displayed as "Malicious" in UI
  | 'false_positive'
  | 'benign'
  | 'suspicious'
  | 'inconclusive';
```

---

## 10. Questions for Backend Team

1. **Permissions**: Should disposition changes require specific roles/permissions?
2. **Audit**: Should disposition changes trigger any additional audit logging beyond activity feed?
3. **Notifications**: Should disposition changes trigger notifications (e.g., when marked malicious)?
4. **Bulk Operations**: Is bulk disposition update needed (e.g., mark 10 alerts as false_positive)?
5. **Investigation Unlink**: Should we support unlinking an alert from an investigation?
