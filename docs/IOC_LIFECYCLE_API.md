# IOC Lifecycle API Documentation

## Overview

The IOC (Indicators of Compromise) Lifecycle feature provides comprehensive management of threat indicators including creation, tracking, threat hunting, and integration with investigations and alerts.

### Key Capabilities
- CRUD operations for IOCs with type-specific validation
- Bulk import/export (up to 1000 IOCs per batch)
- Threat hunting across historical log data
- Linking IOCs to investigations and alerts
- Real-time statistics and match tracking

---

## Authentication

All endpoints require JWT authentication via Bearer token:

```
Authorization: Bearer <jwt_token>
```

### Required Permissions

| Action | Permission |
|--------|-----------|
| View IOCs | `iocs:read` |
| Create/Update IOCs | `iocs:write` |
| Delete IOCs | `iocs:delete` |
| Manage Hunts | `iocs:hunt` |
| View Statistics | `iocs:read` |

---

## Data Models

### IOC Types

```typescript
type IOCType =
  | 'ip'           // IPv4 or IPv6 address
  | 'cidr'         // CIDR notation (e.g., 192.168.0.0/24)
  | 'domain'       // Domain name
  | 'hash'         // MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128) hex chars
  | 'url'          // HTTP/HTTPS URL
  | 'email'        // Email address
  | 'filename'     // File name
  | 'registry_key' // Windows registry key
  | 'cve'          // CVE identifier (CVE-YYYY-NNNNN)
  | 'ja3';         // JA3 TLS fingerprint (32-char hex)
```

### IOC Status

```typescript
type IOCStatus =
  | 'active'      // Actively monitored, triggers alerts
  | 'deprecated'  // Still matched but flagged as old
  | 'archived'    // No longer matched
  | 'whitelist';  // Known-good, suppresses alerts
```

### IOC Severity

```typescript
type IOCSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info';
```

### IOC Object

```typescript
interface IOC {
  id: string;                        // UUID
  type: IOCType;
  value: string;                     // Original value
  normalized: string;                // Normalized for matching
  status: IOCStatus;
  severity: IOCSeverity;
  confidence: number;                // 0-100

  // Metadata
  description?: string;              // Max 2000 chars
  tags?: string[];                   // Max 50 tags, each max 100 chars
  source?: string;                   // Feed name, analyst, etc.
  references?: string[];             // URLs to reports (max 20)
  mitre_techniques?: string[];       // MITRE ATT&CK IDs (e.g., T1566)
  threat_intel?: Record<string, any>; // Enrichment data

  // Tracking
  created_by: string;
  created_at: string;                // ISO 8601
  updated_at: string;                // ISO 8601
  first_seen?: string;               // First detection in logs
  last_seen?: string;                // Most recent detection
  expires_at?: string;               // Auto-archive date
  hit_count: number;                 // Detection counter

  // Relationships (populated on GET by ID)
  investigation_ids?: string[];
  alert_ids?: string[];
}
```

### Hunt Status

```typescript
type HuntStatus =
  | 'pending'     // Queued, not started
  | 'running'     // Currently executing
  | 'completed'   // Finished successfully
  | 'failed'      // Finished with error
  | 'cancelled';  // Stopped by user
```

### IOC Hunt Object

```typescript
interface IOCHunt {
  id: string;                        // UUID
  status: HuntStatus;
  ioc_ids: string[];                 // IOCs being hunted
  time_range_start: string;          // ISO 8601
  time_range_end: string;            // ISO 8601
  created_by: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  progress: number;                  // 0-100%
  total_events: number;              // Events scanned
  match_count: number;               // Hits found
  error?: string;                    // Error message if failed
}
```

### IOC Match Object

```typescript
interface IOCMatch {
  id: string;
  ioc_id: string;
  hunt_id?: string;                  // If from a hunt job
  event_id: string;
  matched_field: string;             // e.g., "source_ip", "domain"
  matched_value: string;
  event_timestamp: string;           // ISO 8601
  detected_at: string;               // ISO 8601
}
```

---

## API Endpoints

### IOC Management

#### List IOCs
```
GET /api/v1/iocs
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number (1-based) |
| `limit` | integer | 100 | Items per page (max 1000) |
| `type` | string | - | Filter by type (comma-separated) |
| `status` | string | - | Filter by status (comma-separated) |
| `severity` | string | - | Filter by severity |
| `source` | string | - | Filter by source |
| `search` | string | - | Search in value/description |
| `min_confidence` | number | - | Minimum confidence threshold |
| `tags` | string | - | Filter by tags (comma-separated) |
| `sort_by` | string | created_at | Sort field |
| `sort_order` | string | desc | Sort order (asc/desc) |

**Response:**
```typescript
interface IOCListResponse {
  iocs: IOC[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}
```

**Example:**
```bash
GET /api/v1/iocs?type=ip,domain&status=active&min_confidence=75&page=1&limit=50
```

---

#### Get Single IOC
```
GET /api/v1/iocs/{id}
```

**Response:** `IOC` object with `investigation_ids` and `alert_ids` populated

**Status Codes:**
- `200` - Success
- `404` - IOC not found

---

#### Create IOC
```
POST /api/v1/iocs
```

**Request Body:**
```typescript
interface CreateIOCRequest {
  type: IOCType;                     // Required
  value: string;                     // Required (max 4096 chars)
  status?: IOCStatus;                // Default: 'active'
  severity?: IOCSeverity;            // Default: 'medium'
  confidence?: number;               // Default: 50 (0-100)
  description?: string;              // Max 2000 chars
  tags?: string[];                   // Max 50 tags
  source?: string;                   // Max 200 chars
  references?: string[];             // Max 20 URLs
  mitre_techniques?: string[];       // Max 50 technique IDs
  expires_at?: string;               // ISO 8601
}
```

**Response:** `201` with created `IOC` object

**Status Codes:**
- `201` - Created successfully
- `400` - Validation error (invalid type, value format, etc.)
- `409` - IOC with same type+value already exists

**Example:**
```json
{
  "type": "ip",
  "value": "192.168.1.100",
  "severity": "high",
  "confidence": 85,
  "description": "Known C2 server",
  "tags": ["malware", "apt29"],
  "source": "threat_intel_feed",
  "mitre_techniques": ["T1071", "T1105"]
}
```

---

#### Update IOC
```
PUT /api/v1/iocs/{id}
```

**Request Body:**
```typescript
interface UpdateIOCRequest {
  status?: IOCStatus;
  severity?: IOCSeverity;
  confidence?: number;
  description?: string;
  tags?: string[];
  references?: string[];
  mitre_techniques?: string[];
  expires_at?: string;
}
```

**Note:** Type and value cannot be changed after creation.

**Response:** `200` with updated `IOC` object

---

#### Delete IOC
```
DELETE /api/v1/iocs/{id}
```

**Response:** `204` No Content

---

### Bulk Operations

#### Bulk Import IOCs
```
POST /api/v1/iocs/bulk
```

**Request Body:**
```typescript
interface BulkImportRequest {
  iocs: CreateIOCRequest[];  // Max 1000 items
}
```

**Response:**
```typescript
interface BulkImportResponse {
  created: number;
  skipped: number;  // Duplicates or invalid
  message: string;
}
```

**Notes:**
- Maximum 1000 IOCs per request
- Request body limited to 10MB
- Invalid IOCs are skipped, not rejected
- Duplicates (same type+value) are skipped

---

#### Bulk Update Status
```
PUT /api/v1/iocs/bulk/status
```

**Request Body:**
```typescript
interface BulkUpdateStatusRequest {
  ids: string[];       // Max 1000 IDs
  status: IOCStatus;
}
```

**Response:**
```json
{
  "message": "Status updated successfully",
  "count": "150"
}
```

---

### Statistics

#### Get IOC Statistics
```
GET /api/v1/iocs/stats
```

**Response:**
```typescript
interface IOCStatistics {
  total_count: number;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  active_count: number;
  whitelist_count: number;
  recent_matches_24h: number;
}
```

**Example Response:**
```json
{
  "total_count": 15420,
  "by_type": {
    "ip": 8500,
    "domain": 4200,
    "hash": 2100,
    "url": 620
  },
  "by_status": {
    "active": 12000,
    "deprecated": 2500,
    "archived": 800,
    "whitelist": 120
  },
  "by_severity": {
    "critical": 450,
    "high": 2800,
    "medium": 8000,
    "low": 3500,
    "info": 670
  },
  "active_count": 12000,
  "whitelist_count": 120,
  "recent_matches_24h": 342
}
```

---

### IOC Relationships

#### Link IOC to Investigation
```
POST /api/v1/iocs/{id}/investigations/{investigationId}
```

**Response:** `200`
```json
{ "message": "IOC linked to investigation" }
```

---

#### Unlink IOC from Investigation
```
DELETE /api/v1/iocs/{id}/investigations/{investigationId}
```

**Response:** `204` No Content

---

#### Get IOC Matches
```
GET /api/v1/iocs/{id}/matches
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 100 | Max 1000 |
| `offset` | integer | 0 | Pagination offset |

**Response:** Paginated list of `IOCMatch` objects

---

### Threat Hunting

#### Create Hunt
```
POST /api/v1/hunts
```

**Request Body:**
```typescript
interface CreateHuntRequest {
  ioc_ids: string[];           // 1-100 IOC IDs
  time_range_start: string;    // ISO 8601
  time_range_end: string;      // ISO 8601
}
```

**Validation:**
- Maximum 100 IOCs per hunt
- Time range cannot exceed 90 days
- End time cannot be in the future
- All IOC IDs must exist

**Response:** `201` with created `IOCHunt` object

**Example:**
```json
{
  "ioc_ids": ["uuid-1", "uuid-2", "uuid-3"],
  "time_range_start": "2024-01-01T00:00:00Z",
  "time_range_end": "2024-01-15T23:59:59Z"
}
```

---

#### List Hunts
```
GET /api/v1/hunts
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 20 | Max 100 |
| `offset` | integer | 0 | Pagination offset |

**Response:** Paginated list of `IOCHunt` objects

---

#### Get Hunt Details
```
GET /api/v1/hunts/{id}
```

**Response:** `IOCHunt` object

---

#### Get Hunt Matches
```
GET /api/v1/hunts/{id}/matches
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 100 | Max 1000 |
| `offset` | integer | 0 | Pagination offset |

**Response:** Paginated list of `IOCMatch` objects

---

#### Cancel Hunt
```
POST /api/v1/hunts/{id}/cancel
```

**Response:** `200` with updated `IOCHunt` object

**Status Codes:**
- `200` - Hunt cancelled
- `400` - Hunt already in terminal state (completed/failed/cancelled)
- `404` - Hunt not found

---

## Value Validation Rules

Each IOC type has specific validation requirements:

| Type | Format | Examples |
|------|--------|----------|
| `ip` | IPv4 or IPv6 | `192.168.1.1`, `2001:db8::1` |
| `cidr` | IP/prefix | `10.0.0.0/8`, `2001:db8::/32` |
| `domain` | FQDN | `example.com`, `sub.example.org` |
| `hash` | Hex string | MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128) chars |
| `url` | HTTP/HTTPS URL | `https://example.com/path` |
| `email` | RFC 5322 | `user@example.com` |
| `filename` | Safe filename | `malware.exe` (no path chars) |
| `registry_key` | Windows hive | `HKLM\SOFTWARE\...`, `HKEY_LOCAL_MACHINE\...` |
| `cve` | CVE-YYYY-NNNNN | `CVE-2021-44228` |
| `ja3` | 32-char hex | MD5 fingerprint |

---

## Error Responses

All errors follow this format:

```typescript
interface ErrorResponse {
  error: string;
  message: string;
  details?: any;
}
```

**Common Status Codes:**

| Code | Meaning |
|------|---------|
| `400` | Bad Request - Validation failed |
| `401` | Unauthorized - Missing/invalid token |
| `403` | Forbidden - Insufficient permissions |
| `404` | Not Found - Resource doesn't exist |
| `409` | Conflict - Duplicate IOC |
| `500` | Internal Server Error |
| `503` | Service Unavailable - Storage not configured |

---

## TypeScript Interface Summary

```typescript
// Complete TypeScript definitions for frontend use

// Enums
type IOCType = 'ip' | 'cidr' | 'domain' | 'hash' | 'url' | 'email' | 'filename' | 'registry_key' | 'cve' | 'ja3';
type IOCStatus = 'active' | 'deprecated' | 'archived' | 'whitelist';
type IOCSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type HuntStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

// Core Types
interface IOC {
  id: string;
  type: IOCType;
  value: string;
  normalized: string;
  status: IOCStatus;
  severity: IOCSeverity;
  confidence: number;
  description?: string;
  tags?: string[];
  source?: string;
  references?: string[];
  mitre_techniques?: string[];
  threat_intel?: Record<string, unknown>;
  created_by: string;
  created_at: string;
  updated_at: string;
  first_seen?: string;
  last_seen?: string;
  expires_at?: string;
  hit_count: number;
  investigation_ids?: string[];
  alert_ids?: string[];
}

interface IOCHunt {
  id: string;
  status: HuntStatus;
  ioc_ids: string[];
  time_range_start: string;
  time_range_end: string;
  created_by: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  progress: number;
  total_events: number;
  match_count: number;
  error?: string;
}

interface IOCMatch {
  id: string;
  ioc_id: string;
  hunt_id?: string;
  event_id: string;
  matched_field: string;
  matched_value: string;
  event_timestamp: string;
  detected_at: string;
}

interface IOCStatistics {
  total_count: number;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  active_count: number;
  whitelist_count: number;
  recent_matches_24h: number;
}

// Request Types
interface CreateIOCRequest {
  type: IOCType;
  value: string;
  status?: IOCStatus;
  severity?: IOCSeverity;
  confidence?: number;
  description?: string;
  tags?: string[];
  source?: string;
  references?: string[];
  mitre_techniques?: string[];
  expires_at?: string;
}

interface UpdateIOCRequest {
  status?: IOCStatus;
  severity?: IOCSeverity;
  confidence?: number;
  description?: string;
  tags?: string[];
  references?: string[];
  mitre_techniques?: string[];
  expires_at?: string;
}

interface BulkImportRequest {
  iocs: CreateIOCRequest[];
}

interface BulkUpdateStatusRequest {
  ids: string[];
  status: IOCStatus;
}

interface CreateHuntRequest {
  ioc_ids: string[];
  time_range_start: string;
  time_range_end: string;
}

// Response Types
interface IOCListResponse {
  iocs: IOC[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}

interface BulkImportResponse {
  created: number;
  skipped: number;
  message: string;
}

interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}
```

---

## Usage Examples

### Create and Track an IOC

```typescript
// 1. Create IOC
const response = await fetch('/api/v1/iocs', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    type: 'ip',
    value: '192.168.1.100',
    severity: 'high',
    confidence: 85,
    description: 'Suspicious C2 server',
    tags: ['malware', 'c2'],
    source: 'manual_analysis'
  })
});

const ioc = await response.json();

// 2. Link to investigation
await fetch(`/api/v1/iocs/${ioc.id}/investigations/${investigationId}`, {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${token}` }
});

// 3. Check for matches
const matches = await fetch(`/api/v1/iocs/${ioc.id}/matches`, {
  headers: { 'Authorization': `Bearer ${token}` }
});
```

### Run a Threat Hunt

```typescript
// 1. Create hunt
const huntResponse = await fetch('/api/v1/hunts', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    ioc_ids: ['ioc-uuid-1', 'ioc-uuid-2'],
    time_range_start: '2024-01-01T00:00:00Z',
    time_range_end: '2024-01-31T23:59:59Z'
  })
});

const hunt = await huntResponse.json();

// 2. Poll for progress
const pollHunt = async () => {
  const res = await fetch(`/api/v1/hunts/${hunt.id}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const status = await res.json();

  if (status.status === 'running') {
    console.log(`Progress: ${status.progress}%`);
    setTimeout(pollHunt, 5000);
  } else if (status.status === 'completed') {
    console.log(`Found ${status.match_count} matches`);
    // Fetch matches
    const matches = await fetch(`/api/v1/hunts/${hunt.id}/matches`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
  }
};

pollHunt();
```

### Bulk Import from Threat Feed

```typescript
const iocs = threatFeedData.map(item => ({
  type: item.indicator_type,
  value: item.indicator,
  severity: item.severity || 'medium',
  confidence: item.confidence || 50,
  source: 'external_feed',
  tags: item.tags || [],
  references: [item.report_url]
}));

// Chunk into batches of 1000
const chunks = [];
for (let i = 0; i < iocs.length; i += 1000) {
  chunks.push(iocs.slice(i, i + 1000));
}

for (const chunk of chunks) {
  const res = await fetch('/api/v1/iocs/bulk', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ iocs: chunk })
  });

  const result = await res.json();
  console.log(`Created: ${result.created}, Skipped: ${result.skipped}`);
}
```

---

## Notes for Frontend Implementation

1. **IOC Type Icons**: Consider using distinct icons for each IOC type in the UI
2. **Confidence Visualization**: Show confidence as a percentage bar or color gradient
3. **Status Colors**: Suggested mapping:
   - `active` - Green
   - `deprecated` - Yellow
   - `archived` - Gray
   - `whitelist` - Blue
4. **Hunt Progress**: Use polling (5-second intervals) or WebSocket for real-time updates
5. **Bulk Operations**: Show progress indicator for large imports
6. **MITRE Mapping**: Link `mitre_techniques` to MITRE ATT&CK knowledge base
7. **Expiration Warning**: Highlight IOCs nearing `expires_at` date
