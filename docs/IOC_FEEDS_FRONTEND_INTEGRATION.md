# IOC Feeds Frontend Integration Guide

This document provides comprehensive guidance for frontend developers to integrate the new IOC Feeds feature into the Cerberus SIEM application.

## Overview

The IOC Feeds feature allows importing Indicators of Compromise (IOCs) from external threat intelligence feeds. This is similar to the existing SIGMA rule feeds functionality but for IOC data (IP addresses, domains, URLs, file hashes, etc.).

## API Endpoints

All endpoints are under `/api/v1/ioc-feeds` and require authentication.

### Feed CRUD Operations

#### List All Feeds
```http
GET /api/v1/ioc-feeds
```

**Response:**
```typescript
interface IOCFeedListResponse {
  feeds: IOCFeed[];
  total: number;
}
```

#### Get Single Feed
```http
GET /api/v1/ioc-feeds/{id}
```

**Response:** `IOCFeed`

#### Create Feed
```http
POST /api/v1/ioc-feeds
```

**Request Body:**
```typescript
interface CreateIOCFeedRequest {
  name: string;                     // Required, 1-200 chars
  description?: string;             // Max 2000 chars
  type: IOCFeedType;               // Required
  url?: string;                     // Feed URL (required for most types)
  path?: string;                    // Local file path (for filesystem feeds)
  auth_config?: Record<string, any>; // Authentication config (api_key, etc.)
  collection_id?: string;           // For STIX/TAXII feeds
  api_root?: string;                // For STIX/TAXII feeds
  org_id?: string;                  // For MISP feeds
  event_filters?: string;           // For MISP feeds
  pulse_ids?: string[];             // For OTX feeds
  field_mapping?: Record<string, string>; // Custom field mappings
  delimiter?: string;               // For CSV feeds
  skip_header?: boolean;            // For CSV feeds
  value_column?: number;            // For CSV feeds
  type_column?: number;             // For CSV feeds
  file_patterns?: string[];         // For filesystem feeds
  include_types?: IOCType[];        // Filter by IOC types
  exclude_types?: IOCType[];        // Exclude IOC types
  default_type?: IOCType;           // Default IOC type
  min_confidence?: number;          // Minimum confidence threshold
  default_severity?: IOCSeverity;   // Default severity level
  auto_expire_days?: number;        // Auto-expiration in days
  tags?: string[];                  // Tags for filtering
  priority?: number;                // Feed priority (higher wins)
  update_strategy?: UpdateStrategy; // manual, startup, scheduled
  update_schedule?: string;         // Cron expression
  enabled?: boolean;                // Enable feed
  template_id?: string;             // Use predefined template
}
```

#### Update Feed
```http
PUT /api/v1/ioc-feeds/{id}
```

**Request Body:** Same as create, all fields optional with pointer semantics.

#### Delete Feed
```http
DELETE /api/v1/ioc-feeds/{id}
```

**Response:** `204 No Content`

### Feed Operations

#### Enable Feed
```http
POST /api/v1/ioc-feeds/{id}/enable
```

**Response:**
```json
{"message": "Feed enabled successfully"}
```

#### Disable Feed
```http
POST /api/v1/ioc-feeds/{id}/disable
```

**Response:**
```json
{"message": "Feed disabled successfully"}
```

#### Test Feed Connection
```http
POST /api/v1/ioc-feeds/{id}/test
```

Tests connectivity without performing a full sync.

**Response:**
```json
{"message": "Feed test successful"}
```

**Error Response (400/401/502):**
```json
{"error": "Connection to feed failed", "details": "..."}
```

#### Sync Feed
```http
POST /api/v1/ioc-feeds/{id}/sync
```

Triggers a manual synchronization. WebSocket progress events are emitted during sync.

**Response:**
```typescript
interface IOCFeedSyncResponse {
  result: IOCFeedSyncResult;
  message: string;
}

interface IOCFeedSyncResult {
  feed_id: string;
  success: boolean;
  started_at: string;
  completed_at: string;
  duration: number;
  iocs_fetched: number;
  iocs_added: number;
  iocs_updated: number;
  iocs_skipped: number;
  iocs_expired: number;
  errors: string[];
}
```

#### Get Sync History
```http
GET /api/v1/ioc-feeds/{id}/history?limit=10
```

**Response:**
```typescript
interface IOCSyncHistoryResponse {
  history: IOCFeedSyncResult[];
  total: number;
}
```

### Summary and Templates

#### Get Feeds Summary
```http
GET /api/v1/ioc-feeds/summary
```

**Response:**
```typescript
interface IOCFeedsSummary {
  total_feeds: number;
  enabled_feeds: number;
  disabled_feeds: number;
  syncing_feeds: number;
  error_feeds: number;
  total_iocs: number;
  last_sync: string;
  feeds_by_type: Record<IOCFeedType, number>;
  feeds_by_status: Record<IOCFeedStatus, number>;
}
```

#### Get Feed Templates
```http
GET /api/v1/ioc-feeds/templates
```

Returns pre-configured templates for common threat intelligence sources.

**Response:**
```typescript
interface IOCFeedTemplate {
  id: string;                        // e.g., "alienvault-otx", "abuse-ch-urlhaus"
  name: string;                      // Display name
  description: string;               // Template description
  type: IOCFeedType;                 // Feed type
  url?: string;                      // Default URL
  requires_auth: boolean;            // Whether auth is required
  auth_fields?: string[];            // Required auth fields
  default_config: Record<string, any>; // Default configuration
  field_mapping?: Record<string, string>;
  recommended_priority: number;
  estimated_ioc_count: number;
  tags: string[];
}
```

## Type Definitions

### IOCFeed
```typescript
interface IOCFeed {
  id: string;
  name: string;
  description: string;
  type: IOCFeedType;
  url: string;
  path: string;
  auth_config: Record<string, any>;
  collection_id: string;
  api_root: string;
  org_id: string;
  event_filters: string;
  pulse_ids: string[];
  field_mapping: Record<string, string>;
  delimiter: string;
  skip_header: boolean;
  value_column: number;
  type_column: number;
  file_patterns: string[];
  include_types: IOCType[];
  exclude_types: IOCType[];
  default_type: IOCType;
  min_confidence: number;
  default_severity: IOCSeverity;
  auto_expire_days: number;
  tags: string[];
  priority: number;
  enabled: boolean;
  status: IOCFeedStatus;
  update_strategy: UpdateStrategy;
  update_schedule: string;
  last_sync: string;
  next_sync: string;
  stats: IOCFeedStats;
  created_at: string;
  updated_at: string;
  created_by: string;
}
```

### Enums

```typescript
type IOCFeedType =
  | "stix"       // STIX/TAXII 2.x
  | "misp"       // MISP platform
  | "otx"        // AlienVault OTX
  | "csv"        // CSV format
  | "json"       // JSON format
  | "http"       // Generic HTTP
  | "filesystem" // Local files

type IOCFeedStatus =
  | "active"     // Feed is healthy
  | "disabled"   // Feed is disabled
  | "error"      // Last sync failed
  | "syncing"    // Currently syncing

type UpdateStrategy =
  | "manual"     // Manual sync only
  | "startup"    // Sync on application start
  | "scheduled"  // Cron-based scheduling

type IOCType =
  | "ip"
  | "domain"
  | "url"
  | "hash"
  | "email"
  | "filename"
  | "registry"
  | "cve"
  | "cidr"
  | "user_agent"

type IOCSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"

type IOCStatus =
  | "active"    // IOC is active and valid
  | "archived"  // IOC has expired or been archived
```

## IOC Expiration System

IOCs can have automatic expiration to handle indicators that "burn up" over time. Different IOC types have different default expiration periods based on their typical lifespan in threat intelligence.

### Expiration Priority

When an IOC is imported, expiration is determined in this priority order:

1. **Source-provided expiration**: If the feed provides an explicit expiration date, it's used
2. **Feed-level setting**: If `auto_expire_days` is configured on the feed, it's used
3. **Type-specific default**: System defaults based on IOC type (see table below)

### Setting "Never Expire"

To prevent IOCs from expiring, set `auto_expire_days` to `-1`:

```typescript
// Create feed that never expires its IOCs
const feed = {
  name: "My Permanent Watchlist",
  type: "csv",
  auto_expire_days: -1,  // Special value: never expire
  // ... other fields
};
```

### Type-Specific Default Expiration

| IOC Type | Default Days | Rationale |
|----------|-------------|-----------|
| IP Address | 30 | IPs are frequently rotated by attackers |
| CIDR Range | 30 | Network ranges change with IP rotation |
| Domain | 60 | Domains persist longer than IPs but still rotate |
| URL | 30 | URLs are ephemeral, often taken down quickly |
| User Agent | 90 | Less frequently changed |
| Email | 180 | Semi-persistent indicator |
| Filename | 180 | File names may be reused |
| CVE | 365 | Vulnerabilities remain relevant for patching |
| Hash (MD5/SHA1/SHA256) | 730 | File hashes are persistent, rarely change |
| Registry Key | 365 | Registry artifacts persist |
| JA3/JA3S | 365 | TLS fingerprints are semi-stable |

### Feed Template Expiration Defaults

Pre-configured templates include appropriate expiration settings:

| Template | IOC Types | Default Expiration |
|----------|-----------|-------------------|
| Abuse.ch URLhaus | URLs | 30 days |
| Abuse.ch MalwareBazaar | Hashes | 730 days (2 years) |
| Abuse.ch Feodo Tracker | IPs (C2) | 30 days |
| SANS ISC Suspicious | Domains | 60 days |
| EmergingThreats Compromised | IPs | 30 days |
| OpenPhish | URLs | 30 days |
| PhishTank | URLs | 30 days |
| Spamhaus DROP | CIDR | 30 days |
| DShield Top Attackers | IPs | 30 days |
| Blocklist.de | IPs | 30 days |
| AlienVault OTX | Mixed | Type-specific defaults |
| MISP/STIX-TAXII | Mixed | Type-specific defaults |
| Custom CSV/JSON | User-defined | User choice |

### Automatic Expiration Sweeper

The backend runs an hourly expiration sweeper that:

1. Finds all IOCs where `expires_at < now()` and `status = 'active'`
2. Updates their status to `'archived'`
3. Logs the number of expired IOCs

Archived IOCs remain in the database for historical reference but are excluded from active matching.

### API for Expired IOCs

#### Query Active vs Archived IOCs

```http
GET /api/v1/iocs?status=active      # Only active IOCs (default)
GET /api/v1/iocs?status=archived    # Only archived/expired IOCs
GET /api/v1/iocs?include_archived=true  # Include both
```

#### IOC Response Fields

```typescript
interface IOC {
  // ... existing fields ...

  status: IOCStatus;       // "active" or "archived"
  expires_at?: string;     // ISO timestamp when IOC expires (null = never)
}
```

### Frontend UI Recommendations

1. **Feed Configuration**
   - Add "Auto-Expire Days" input field
   - Show "Never Expire" checkbox that sets value to -1
   - Display type-specific default when field is empty

2. **IOC List**
   - Show expiration date column (sortable)
   - Badge for "Expires Soon" (within 7 days)
   - Filter toggle: "Show Archived IOCs"
   - Visual distinction for archived IOCs (grayed out, strikethrough)

3. **IOC Detail View**
   - Display expiration countdown
   - Show status badge (Active/Archived)
   - Manual "Archive" button for active IOCs
   - Manual "Restore" button for archived IOCs (resets expiration)

4. **Dashboard Widget**
   - "Expiring Soon" count (next 7 days)
   - "Recently Expired" count (last 24 hours)

### IOCFeedStats
```typescript
interface IOCFeedStats {
  total_iocs: number;
  active_iocs: number;
  expired_iocs: number;
  iocs_by_type: Record<IOCType, number>;
  last_sync_added: number;
  last_sync_updated: number;
  last_sync_duration: number;
}
```

## WebSocket Events

Connect to the WebSocket endpoint and listen for feed sync progress events:

```typescript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:8081/api/v1/ws');

// Listen for IOC feed sync progress
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);

  if (message.type === 'ioc_feed_sync_progress') {
    const data = message.data;
    // data.feed_id: string - Feed being synced
    // data.event: string - Event type (started, progress, completed, error)
    // data.message: string - Human-readable message
    // data.progress: number - Progress percentage (0-100)

    console.log(`Feed ${data.feed_id}: ${data.message} (${data.progress}%)`);
  }
};
```

### Event Types

| Event | Description |
|-------|-------------|
| `started` | Sync has started |
| `fetching` | Fetching IOCs from source |
| `processing` | Processing fetched IOCs |
| `completed` | Sync completed successfully |
| `error` | Sync encountered an error |

## IOC Page Integration

The existing IOC page now supports filtering by feed source:

### Extended Query Parameters for `/api/v1/iocs`

```http
GET /api/v1/iocs?feed_id=abc123&source=feed
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `feed_id` | string | Filter by specific feed ID |
| `source` | string | `manual` (user-created) or `feed` (feed-imported) |

### Extended IOC Model

IOCs imported from feeds include additional fields:

```typescript
interface IOC {
  // ... existing fields ...

  // New feed attribution fields
  feed_id?: string;      // Source feed ID
  feed_name?: string;    // Source feed name
  external_id?: string;  // ID in source system
  imported_at?: string;  // When imported from feed
}
```

You can use `ioc.feed_id` to determine if an IOC came from a feed or was manually created.

## Available Feed Templates

The following pre-configured templates are available:

| Template ID | Name | Type | Auth Required |
|-------------|------|------|---------------|
| `alienvault-otx` | AlienVault OTX | otx | Yes (API key) |
| `abuse-ch-urlhaus` | Abuse.ch URLhaus | csv | No |
| `abuse-ch-malwarebazaar` | Abuse.ch MalwareBazaar | json | No |
| `abuse-ch-feodo` | Abuse.ch Feodo Tracker | csv | No |
| `sans-isc-suspicious` | SANS ISC Suspicious Domains | csv | No |
| `et-compromised` | EmergingThreats Compromised IPs | csv | No |
| `openphish` | OpenPhish | csv | No |
| `phishtank` | PhishTank | json | No |
| `misp` | MISP Threat Intelligence | misp | Yes (API key + URL) |
| `stix-taxii` | STIX/TAXII Feed | stix | Yes (URL + collection) |
| `custom-csv` | Custom CSV Feed | csv | Optional |
| `custom-json` | Custom JSON Feed | json | Optional |
| `spamhaus-drop` | Spamhaus DROP | csv | No |
| `dshield-top-attackers` | DShield Top Attackers | csv | No |
| `blocklist-de` | Blocklist.de All Attackers | csv | No |

## Recommended UI Components

### Settings Page Integration

Add a new "IOC Feeds" section to the Settings page:

1. **Feed List View**
   - Table showing all configured feeds
   - Columns: Name, Type, Status, IOC Count, Last Sync, Actions
   - Status badges (Active, Disabled, Error, Syncing)
   - Quick actions: Enable/Disable, Sync, Test, Edit, Delete

2. **Feed Creation Wizard**
   - Step 1: Select template or custom feed type
   - Step 2: Configure URL/authentication
   - Step 3: Set update schedule
   - Step 4: Configure filtering options
   - Step 5: Review and create

3. **Feed Detail Modal**
   - Feed configuration (editable)
   - Statistics panel
   - Sync history timeline
   - Real-time sync progress (WebSocket)

4. **Summary Dashboard Card**
   - Total feeds count
   - Active/Disabled counts
   - Total IOCs imported
   - Next scheduled sync

### IOC Page Enhancements

1. **Source Filter Dropdown**
   - "All Sources"
   - "Manual Only"
   - "Feed Imported"
   - Individual feed names

2. **IOC Table Enhancement**
   - Add "Source" column showing feed name or "Manual"
   - Add "Imported At" column for feed IOCs
   - Badge indicator for feed vs manual

3. **IOC Detail View Enhancement**
   - Show feed attribution section
   - Link to parent feed
   - External ID from source system

## Example Service Implementation

```typescript
// frontend/src/services/iocFeedsService.ts

import { apiClient } from './api';

export interface IOCFeed {
  id: string;
  name: string;
  type: string;
  status: string;
  enabled: boolean;
  last_sync: string;
  stats: {
    total_iocs: number;
    active_iocs: number;
  };
  // ... other fields
}

export interface IOCFeedTemplate {
  id: string;
  name: string;
  description: string;
  type: string;
  requires_auth: boolean;
  auth_fields: string[];
}

export const iocFeedsService = {
  // List all feeds
  async getFeeds(): Promise<{ feeds: IOCFeed[]; total: number }> {
    const response = await apiClient.get('/api/v1/ioc-feeds');
    return response.data;
  },

  // Get single feed
  async getFeed(id: string): Promise<IOCFeed> {
    const response = await apiClient.get(`/api/v1/ioc-feeds/${id}`);
    return response.data;
  },

  // Create feed
  async createFeed(data: Partial<IOCFeed>): Promise<IOCFeed> {
    const response = await apiClient.post('/api/v1/ioc-feeds', data);
    return response.data;
  },

  // Update feed
  async updateFeed(id: string, data: Partial<IOCFeed>): Promise<IOCFeed> {
    const response = await apiClient.put(`/api/v1/ioc-feeds/${id}`, data);
    return response.data;
  },

  // Delete feed
  async deleteFeed(id: string): Promise<void> {
    await apiClient.delete(`/api/v1/ioc-feeds/${id}`);
  },

  // Enable feed
  async enableFeed(id: string): Promise<void> {
    await apiClient.post(`/api/v1/ioc-feeds/${id}/enable`);
  },

  // Disable feed
  async disableFeed(id: string): Promise<void> {
    await apiClient.post(`/api/v1/ioc-feeds/${id}/disable`);
  },

  // Test feed connection
  async testFeed(id: string): Promise<void> {
    await apiClient.post(`/api/v1/ioc-feeds/${id}/test`);
  },

  // Sync feed
  async syncFeed(id: string): Promise<{ result: any; message: string }> {
    const response = await apiClient.post(`/api/v1/ioc-feeds/${id}/sync`);
    return response.data;
  },

  // Get sync history
  async getSyncHistory(id: string, limit = 10): Promise<{ history: any[]; total: number }> {
    const response = await apiClient.get(`/api/v1/ioc-feeds/${id}/history`, {
      params: { limit }
    });
    return response.data;
  },

  // Get summary
  async getSummary(): Promise<any> {
    const response = await apiClient.get('/api/v1/ioc-feeds/summary');
    return response.data;
  },

  // Get templates
  async getTemplates(): Promise<IOCFeedTemplate[]> {
    const response = await apiClient.get('/api/v1/ioc-feeds/templates');
    return response.data;
  }
};
```

## Error Handling

| Status Code | Meaning |
|-------------|---------|
| 400 | Bad Request - Invalid input or validation failed |
| 401 | Unauthorized - Authentication failed (for feed auth) |
| 404 | Not Found - Feed doesn't exist |
| 409 | Conflict - Feed is currently syncing |
| 502 | Bad Gateway - Connection to feed source failed |
| 503 | Service Unavailable - IOC feed manager not initialized |

## RBAC Permissions

The following permissions are required:

| Endpoint | Permission |
|----------|------------|
| GET /ioc-feeds | `iocs.view` |
| POST /ioc-feeds | `iocs.manage` |
| PUT /ioc-feeds/{id} | `iocs.manage` |
| DELETE /ioc-feeds/{id} | `iocs.manage` |
| POST /ioc-feeds/{id}/enable | `iocs.manage` |
| POST /ioc-feeds/{id}/disable | `iocs.manage` |
| POST /ioc-feeds/{id}/test | `iocs.manage` |
| POST /ioc-feeds/{id}/sync | `iocs.manage` |
| GET /ioc-feeds/{id}/history | `iocs.view` |
| GET /ioc-feeds/summary | `iocs.view` |
| GET /ioc-feeds/templates | `iocs.view` |

## Migration Notes

1. The existing IOC page should continue to work without changes
2. New filter parameters are backward compatible (optional)
3. IOCs created before this feature will have `feed_id = null`
4. Use the `IsManual()` check on the backend or `!ioc.feed_id` on frontend

## Testing Checklist

- [ ] List feeds endpoint returns correct structure
- [ ] Create feed with template pre-populates fields
- [ ] Create custom feed validates required fields
- [ ] Test connection shows appropriate success/error messages
- [ ] Sync triggers WebSocket progress events
- [ ] Sync history displays correctly
- [ ] Summary dashboard shows accurate counts
- [ ] IOC page filters by source work
- [ ] Feed-imported IOCs show source attribution
- [ ] Enable/Disable toggles work correctly
- [ ] Delete feed prompts for confirmation
- [ ] RBAC permissions are enforced
- [ ] IOC expiration displays correctly
- [ ] "Never expire" setting (-1) works
- [ ] Archived IOCs are visually distinct
- [ ] Expiration filters work correctly
