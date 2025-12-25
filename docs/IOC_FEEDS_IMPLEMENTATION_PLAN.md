# IOC Feeds Implementation Plan

## Executive Summary

This plan extends Cerberus's threat intelligence capabilities by adding **IOC Feed Management** - a system to automatically import, synchronize, and manage Indicators of Compromise from external threat intelligence sources. The implementation leverages the existing SIGMA rule feed infrastructure patterns while creating a parallel, cleanly-separated IOC-specific system.

---

## Objectives

1. **Automated IOC Ingestion** - Import IOCs from multiple threat intelligence sources
2. **Feed Management** - CRUD operations, enable/disable, scheduling, templates
3. **Source Attribution** - Track which feed each IOC came from
4. **Conflict Resolution** - Handle duplicates between feeds and manual IOCs
5. **UI Integration** - Settings page for feed management, IOC page for viewing
6. **Real-time Sync** - WebSocket progress updates during synchronization

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Frontend                                       │
├─────────────────────────────────────────────────────────────────────────┤
│  Settings Page              │  IOC Page                                 │
│  ┌────────────────────┐     │  ┌──────────────────────────────────────┐ │
│  │ Sigma Feeds Tab    │     │  │ IOC List (filterable by source)     │ │
│  │ IOC Feeds Tab  ◄───┼─────┼──│ - Manual IOCs                        │ │
│  │   - Feed List      │     │  │ - Feed-imported IOCs (read-only)     │ │
│  │   - Add from       │     │  │ - Source/Feed column                 │ │
│  │     Template       │     │  │ - Last sync indicator                │ │
│  │   - Sync Progress  │     │  └──────────────────────────────────────┘ │
│  └────────────────────┘     │                                           │
└─────────────────────────────┴───────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                              API Layer                                   │
│  /api/v1/ioc-feeds/*  (parallel to /api/v1/feeds/*)                     │
│  - CRUD, sync, enable/disable, templates, history                        │
└─────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          IOC Feed Manager                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │ STIX/TAXII   │  │    MISP      │  │  OTX/Pulse   │  │  CSV/JSON   │  │
│  │   Handler    │  │   Handler    │  │   Handler    │  │   Handler   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                      IOC Feed Scheduler                           │   │
│  │  - Cron-based scheduling (like Sigma feeds)                       │   │
│  │  - Per-feed sync locks                                            │   │
│  │  - Progress callbacks → WebSocket                                 │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          Storage Layer                                   │
│  ┌─────────────────┐  ┌────────────────────┐  ┌─────────────────────┐   │
│  │  ioc_feeds      │  │ ioc_feed_sync_hist │  │  iocs (extended)    │   │
│  │  (feed config)  │  │ (sync history)     │  │  + feed_id column   │   │
│  └─────────────────┘  └────────────────────┘  └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Core Backend Infrastructure

### 1.1 IOC Feed Data Models

**File: `threat/feeds/types.go`** (new package)

```go
// IOCFeedType represents supported feed source types
type IOCFeedType string

const (
    IOCFeedTypeSTIX       IOCFeedType = "stix"       // STIX/TAXII 2.x
    IOCFeedTypeMISP       IOCFeedType = "misp"       // MISP platform
    IOCFeedTypeOTX        IOCFeedType = "otx"        // AlienVault OTX
    IOCFeedTypeCSV        IOCFeedType = "csv"        // CSV file/URL
    IOCFeedTypeJSON       IOCFeedType = "json"       // JSON file/URL
    IOCFeedTypeHTTP       IOCFeedType = "http"       // Generic HTTP API
    IOCFeedTypeFilesystem IOCFeedType = "filesystem" // Local files
)

// IOCFeedStatus represents feed operational status
type IOCFeedStatus string

const (
    IOCFeedStatusActive   IOCFeedStatus = "active"
    IOCFeedStatusDisabled IOCFeedStatus = "disabled"
    IOCFeedStatusError    IOCFeedStatus = "error"
    IOCFeedStatusSyncing  IOCFeedStatus = "syncing"
)

// IOCFeed represents a threat intelligence feed configuration
type IOCFeed struct {
    ID          string            `json:"id"`
    Name        string            `json:"name"`
    Description string            `json:"description"`
    Type        IOCFeedType       `json:"type"`
    Status      IOCFeedStatus     `json:"status"`
    Enabled     bool              `json:"enabled"`

    // Connection
    URL        string                 `json:"url,omitempty"`
    AuthConfig map[string]interface{} `json:"auth_config,omitempty"`

    // STIX/TAXII specific
    CollectionID string `json:"collection_id,omitempty"`
    APIRoot      string `json:"api_root,omitempty"`

    // MISP specific
    OrgID        string `json:"org_id,omitempty"`
    EventFilters string `json:"event_filters,omitempty"` // JSON filter criteria

    // OTX specific
    PulseIDs []string `json:"pulse_ids,omitempty"` // Specific pulses or empty for subscribed

    // CSV/JSON specific
    FieldMapping map[string]string `json:"field_mapping,omitempty"` // Map source fields to IOC fields

    // Import Configuration
    IncludeTypes    []core.IOCType     `json:"include_types,omitempty"`    // Filter by IOC type
    ExcludeTypes    []core.IOCType     `json:"exclude_types,omitempty"`
    MinConfidence   float64            `json:"min_confidence,omitempty"`   // 0-100
    DefaultSeverity core.IOCSeverity   `json:"default_severity,omitempty"` // If not provided by feed
    DefaultStatus   core.IOCStatus     `json:"default_status,omitempty"`   // Usually "active"
    AutoExpireDays  int                `json:"auto_expire_days,omitempty"` // Auto-set expires_at
    Tags            []string           `json:"tags,omitempty"`             // Auto-apply tags
    Priority        int                `json:"priority"`                   // Conflict resolution (higher wins)

    // Update Configuration
    UpdateStrategy string    `json:"update_strategy"` // manual, startup, scheduled
    UpdateSchedule string    `json:"update_schedule"` // Cron expression
    LastSync       time.Time `json:"last_sync,omitempty"`
    NextSync       time.Time `json:"next_sync,omitempty"`

    // Statistics
    Stats     IOCFeedStats `json:"stats"`
    CreatedAt time.Time    `json:"created_at"`
    UpdatedAt time.Time    `json:"updated_at"`
    CreatedBy string       `json:"created_by"`
}

// IOCFeedStats tracks import statistics
type IOCFeedStats struct {
    TotalIOCs        int64   `json:"total_iocs"`         // IOCs in feed
    ImportedIOCs     int64   `json:"imported_iocs"`      // Successfully imported
    UpdatedIOCs      int64   `json:"updated_iocs"`       // Updated existing
    SkippedIOCs      int64   `json:"skipped_iocs"`       // Duplicates/filtered
    FailedIOCs       int64   `json:"failed_iocs"`        // Validation failures
    LastSyncDuration float64 `json:"last_sync_duration"` // Seconds
    LastError        string  `json:"last_error,omitempty"`
    SyncCount        int     `json:"sync_count"`
}

// IOCFeedSyncResult captures sync operation results
type IOCFeedSyncResult struct {
    ID         string        `json:"id"`
    FeedID     string        `json:"feed_id"`
    FeedName   string        `json:"feed_name"`
    StartTime  time.Time     `json:"start_time"`
    EndTime    time.Time     `json:"end_time"`
    Duration   float64       `json:"duration"`
    Success    bool          `json:"success"`
    Stats      IOCFeedStats  `json:"stats"`
    Errors     []string      `json:"errors,omitempty"`
    IOCResults []IOCImportResult `json:"ioc_results,omitempty"` // Detailed per-IOC results (limited)
}

// IOCImportResult tracks individual IOC import outcome
type IOCImportResult struct {
    IOCValue string `json:"ioc_value"`
    IOCType  string `json:"ioc_type"`
    Action   string `json:"action"` // imported, updated, skipped, failed
    Reason   string `json:"reason,omitempty"`
}

// IOCFeedTemplate for pre-configured feed sources
type IOCFeedTemplate struct {
    ID                 string      `json:"id"`
    Name               string      `json:"name"`
    Description        string      `json:"description"`
    Type               IOCFeedType `json:"type"`
    URL                string      `json:"url,omitempty"`
    RequiresAuth       bool        `json:"requires_auth"`
    AuthFields         []string    `json:"auth_fields,omitempty"` // Required auth fields
    DefaultConfig      map[string]interface{} `json:"default_config,omitempty"`
    RecommendedPriority int        `json:"recommended_priority"`
    EstimatedIOCCount  int         `json:"estimated_ioc_count"`
    Tags               []string    `json:"tags"`
}
```

### 1.2 Extend IOC Model

**File: `core/ioc.go`** (modify existing)

```go
// Add to IOC struct
type IOC struct {
    // ... existing fields ...

    // Feed Attribution (new fields)
    FeedID       string `json:"feed_id,omitempty"`       // Source feed ID (nil = manual)
    FeedName     string `json:"feed_name,omitempty"`     // Denormalized for display
    ExternalID   string `json:"external_id,omitempty"`   // ID in source system
    ImportedAt   *time.Time `json:"imported_at,omitempty"` // When imported from feed
    IsManual     bool   `json:"is_manual"`               // True if manually created
}
```

### 1.3 Storage Layer

**File: `storage/sqlite_ioc_feeds.go`** (new)

```go
// Tables:
// - ioc_feeds: Feed configuration (mirrors rule_feeds structure)
// - ioc_feed_sync_history: Sync operation history

// Modify iocs table:
// - Add feed_id column (nullable, FK to ioc_feeds)
// - Add external_id column
// - Add imported_at column
// - Add index on (feed_id, external_id) for deduplication

// Interface: IOCFeedStorage
type IOCFeedStorage interface {
    // Feed CRUD
    CreateFeed(ctx context.Context, feed *IOCFeed) error
    GetFeed(ctx context.Context, id string) (*IOCFeed, error)
    GetAllFeeds(ctx context.Context) ([]*IOCFeed, error)
    UpdateFeed(ctx context.Context, id string, feed *IOCFeed) error
    DeleteFeed(ctx context.Context, id string) error

    // Status & Stats
    UpdateFeedStatus(ctx context.Context, id string, status IOCFeedStatus) error
    UpdateFeedStats(ctx context.Context, id string, stats IOCFeedStats) error
    UpdateLastSync(ctx context.Context, id string, syncTime time.Time) error

    // Sync History
    SaveSyncResult(ctx context.Context, result *IOCFeedSyncResult) error
    GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*IOCFeedSyncResult, error)

    // Feed-specific IOC operations
    GetIOCsByFeed(ctx context.Context, feedID string, limit, offset int) ([]*core.IOC, int64, error)
    DeleteIOCsByFeed(ctx context.Context, feedID string) (int64, error) // Cascade delete
    FindFeedIOCByExternalID(ctx context.Context, feedID, externalID string) (*core.IOC, error)

    // Summary
    GetFeedsSummary(ctx context.Context) (*IOCFeedsSummary, error)
}
```

### 1.4 Feed Handlers

**File: `threat/feeds/handlers.go`** (new)

```go
// IOCFeedHandler interface for type-specific feed implementations
type IOCFeedHandler interface {
    // Connect establishes connection to feed source
    Connect(ctx context.Context, feed *IOCFeed) error

    // FetchIOCs retrieves IOCs from the feed
    FetchIOCs(ctx context.Context, feed *IOCFeed, since *time.Time) ([]*core.IOC, error)

    // Validate checks feed configuration
    Validate(feed *IOCFeed) error

    // Test verifies connectivity without full sync
    Test(ctx context.Context, feed *IOCFeed) error

    // Close releases resources
    Close() error
}
```

**Handlers to implement:**

| Handler | File | Description |
|---------|------|-------------|
| `STIXHandler` | `threat/feeds/stix_handler.go` | STIX/TAXII 2.x client |
| `MISPHandler` | `threat/feeds/misp_handler.go` | MISP REST API client |
| `OTXHandler` | `threat/feeds/otx_handler.go` | AlienVault OTX API |
| `CSVHandler` | `threat/feeds/csv_handler.go` | CSV parsing with field mapping |
| `JSONHandler` | `threat/feeds/json_handler.go` | JSON parsing with field mapping |
| `HTTPHandler` | `threat/feeds/http_handler.go` | Generic HTTP/REST API |

### 1.5 Feed Manager

**File: `threat/feeds/manager.go`** (new)

```go
type IOCFeedManager struct {
    storage     IOCFeedStorage
    iocStorage  core.IOCStorage
    handlers    map[IOCFeedType]IOCFeedHandler
    scheduler   *IOCFeedScheduler
    templates   []*IOCFeedTemplate
    syncLocks   map[string]*sync.Mutex
    mu          sync.RWMutex
    logger      *zap.SugaredLogger
}

// Key methods:
// - CreateFeed, GetFeed, ListFeeds, UpdateFeed, DeleteFeed
// - SyncFeed, SyncFeedWithProgress, SyncAllFeeds
// - EnableFeed, DisableFeed
// - TestFeedConnection
// - StartScheduler, StopScheduler
// - GetTemplates
```

### 1.6 Scheduler

**File: `threat/feeds/scheduler.go`** (new)

Reuse exact pattern from `sigma/feeds/scheduler.go`:
- 1-minute check interval
- Cron expression parsing
- Per-feed sync locks
- Timeout handling (30 min default)
- Progress callbacks for WebSocket

---

## Phase 2: API Layer

### 2.1 API Endpoints

**File: `api/ioc_feed_handlers.go`** (new)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/api/v1/ioc-feeds` | List all IOC feeds | `iocs:read` |
| POST | `/api/v1/ioc-feeds` | Create IOC feed | `iocs:admin` |
| GET | `/api/v1/ioc-feeds/summary` | Get feeds health summary | `iocs:read` |
| GET | `/api/v1/ioc-feeds/templates` | List feed templates | `iocs:read` |
| POST | `/api/v1/ioc-feeds/sync-all` | Sync all enabled feeds | `iocs:admin` |
| GET | `/api/v1/ioc-feeds/{id}` | Get feed details | `iocs:read` |
| PUT | `/api/v1/ioc-feeds/{id}` | Update feed | `iocs:admin` |
| DELETE | `/api/v1/ioc-feeds/{id}` | Delete feed (+ IOCs) | `iocs:admin` |
| POST | `/api/v1/ioc-feeds/{id}/sync` | Sync specific feed | `iocs:admin` |
| GET | `/api/v1/ioc-feeds/{id}/stats` | Get feed statistics | `iocs:read` |
| GET | `/api/v1/ioc-feeds/{id}/history` | Get sync history | `iocs:read` |
| POST | `/api/v1/ioc-feeds/{id}/test` | Test feed connection | `iocs:admin` |
| POST | `/api/v1/ioc-feeds/{id}/enable` | Enable feed | `iocs:admin` |
| POST | `/api/v1/ioc-feeds/{id}/disable` | Disable feed | `iocs:admin` |

### 2.2 Extend Existing IOC Endpoints

**Modify `api/ioc_handlers.go`:**

```go
// GET /api/v1/iocs - Add filter parameters:
// - feed_id: Filter by specific feed
// - source: "manual" | "feed" | "all"
// - feed_name: Filter by feed name (partial match)

// GET /api/v1/iocs/{id} - Include feed information in response

// Response includes:
// - is_manual: boolean
// - feed_id: string (if from feed)
// - feed_name: string (if from feed)
// - imported_at: timestamp (if from feed)
```

### 2.3 WebSocket Events

**Extend `api/websocket.go`:**

```go
type IOCFeedSyncEvent struct {
    Type     string           `json:"type"`      // "ioc-feed:sync:started|progress|completed|failed"
    FeedID   string           `json:"feed_id"`
    FeedName string           `json:"feed_name"`
    Progress int              `json:"progress"`  // 0-100
    Message  string           `json:"message"`
    Stats    *IOCFeedStats    `json:"stats,omitempty"`
    Error    string           `json:"error,omitempty"`
    Timestamp time.Time       `json:"timestamp"`
}
```

---

## Phase 3: Frontend Integration

### 3.1 Settings Page Enhancement

**File: `frontend/src/pages/Settings/index.tsx`** (modify)

Add new tab alongside existing tabs:
```
Settings
├── General
├── Sigma Feeds (existing)
├── IOC Feeds (NEW)
└── ...
```

**File: `frontend/src/pages/Settings/IOCFeedSettings.tsx`** (new)

```typescript
// Reuse patterns from FeedSettings.tsx:
// - Feed list with pagination
// - Create/Edit dialog
// - Template selector
// - Sync progress indicator
// - Enable/disable toggle
// - Delete confirmation
// - Sync history modal
```

### 3.2 IOC Feeds Components

**New files in `frontend/src/components/ioc-feeds/`:**

| Component | Description |
|-----------|-------------|
| `IOCFeedListView.tsx` | Table of IOC feeds with status, stats, actions |
| `IOCFeedFormDialog.tsx` | Create/edit feed form with type-specific fields |
| `IOCFeedDetailModal.tsx` | Feed details with sync history |
| `IOCFeedTemplateSelector.tsx` | Browse and select from templates |
| `IOCFeedSyncProgress.tsx` | Real-time sync progress indicator |

### 3.3 IOC Page Enhancement

**File: `frontend/src/pages/IOCs/index.tsx`** (modify or create)

Add source filtering and display:

```typescript
// New filter options
interface IOCFilters {
  // ... existing filters ...
  source?: 'all' | 'manual' | 'feed';
  feedId?: string;
}

// Table columns
const columns = [
  // ... existing columns ...
  {
    header: 'Source',
    cell: (ioc) => ioc.is_manual ? (
      <Chip label="Manual" color="primary" size="small" />
    ) : (
      <Chip
        label={ioc.feed_name}
        color="secondary"
        size="small"
        onClick={() => navigateToFeed(ioc.feed_id)}
      />
    )
  }
];

// Visual distinction for feed-imported IOCs:
// - Read-only badge for feed IOCs
// - Edit/delete disabled for feed IOCs
// - "View in Feed" action instead
```

### 3.4 Dashboard Widget

**File: `frontend/src/pages/Dashboard/components/IOCFeedStatsWidget.tsx`** (new)

```typescript
// Similar to FeedStatsWidget.tsx:
// - Total IOC feeds count
// - Active feeds count
// - Total imported IOCs
// - Last sync time
// - Health status indicator
// - Link to IOC Feeds settings
```

### 3.5 Frontend Types

**File: `frontend/src/types/iocFeeds.ts`** (new)

```typescript
export type IOCFeedType = 'stix' | 'misp' | 'otx' | 'csv' | 'json' | 'http' | 'filesystem';
export type IOCFeedStatus = 'active' | 'disabled' | 'error' | 'syncing';

export interface IOCFeed {
  id: string;
  name: string;
  description?: string;
  type: IOCFeedType;
  status: IOCFeedStatus;
  enabled: boolean;
  url?: string;
  auth_config?: Record<string, unknown>;

  // Type-specific
  collection_id?: string;  // STIX
  api_root?: string;       // STIX
  org_id?: string;         // MISP
  pulse_ids?: string[];    // OTX
  field_mapping?: Record<string, string>; // CSV/JSON

  // Import config
  include_types?: IOCType[];
  exclude_types?: IOCType[];
  min_confidence?: number;
  default_severity?: IOCSeverity;
  auto_expire_days?: number;
  tags?: string[];
  priority: number;

  // Schedule
  update_strategy: 'manual' | 'startup' | 'scheduled';
  update_schedule?: string;
  last_sync?: string;
  next_sync?: string;

  // Stats
  stats: IOCFeedStats;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface IOCFeedStats {
  total_iocs: number;
  imported_iocs: number;
  updated_iocs: number;
  skipped_iocs: number;
  failed_iocs: number;
  last_sync_duration: number;
  last_error?: string;
  sync_count: number;
}

export interface IOCFeedTemplate {
  id: string;
  name: string;
  description: string;
  type: IOCFeedType;
  url?: string;
  requires_auth: boolean;
  auth_fields?: string[];
  recommended_priority: number;
  estimated_ioc_count: number;
  tags: string[];
}

export interface IOCFeedsSummary {
  total_feeds: number;
  active_feeds: number;
  total_iocs: number;
  last_sync: string | null;
  health_status: 'healthy' | 'warning' | 'error';
  error_count: number;
}
```

### 3.6 Frontend Service

**File: `frontend/src/services/iocFeedsService.ts`** (new)

```typescript
export const iocFeedsService = {
  // CRUD
  getFeeds: (page: number, limit: number) => api.get<PaginatedResponse<IOCFeed>>('/ioc-feeds', { params: { page, limit } }),
  getFeed: (id: string) => api.get<IOCFeed>(`/ioc-feeds/${id}`),
  createFeed: (feed: CreateIOCFeedRequest) => api.post<IOCFeed>('/ioc-feeds', feed),
  updateFeed: (id: string, updates: UpdateIOCFeedRequest) => api.put<IOCFeed>(`/ioc-feeds/${id}`, updates),
  deleteFeed: (id: string) => api.delete(`/ioc-feeds/${id}`),

  // Sync
  syncFeed: (id: string) => api.post<SyncStatusResponse>(`/ioc-feeds/${id}/sync`),
  syncAllFeeds: () => api.post<SyncStatusResponse>('/ioc-feeds/sync-all'),

  // Operations
  enableFeed: (id: string) => api.post(`/ioc-feeds/${id}/enable`),
  disableFeed: (id: string) => api.post(`/ioc-feeds/${id}/disable`),
  testFeed: (id: string) => api.post<TestResult>(`/ioc-feeds/${id}/test`),

  // Info
  getStats: (id: string) => api.get<IOCFeedStats>(`/ioc-feeds/${id}/stats`),
  getHistory: (id: string, limit?: number) => api.get<IOCFeedSyncResult[]>(`/ioc-feeds/${id}/history`, { params: { limit } }),
  getTemplates: () => api.get<IOCFeedTemplate[]>('/ioc-feeds/templates'),
  getSummary: () => api.get<IOCFeedsSummary>('/ioc-feeds/summary'),
};
```

---

## Phase 4: Feed Templates

### 4.1 Pre-configured Templates

**File: `threat/feeds/config/ioc_feed_templates.yaml`** (new)

```yaml
templates:
  # STIX/TAXII Feeds
  - id: "abuse-ch-urlhaus"
    name: "abuse.ch URLhaus"
    description: "Malicious URL database from abuse.ch"
    type: "csv"
    url: "https://urlhaus.abuse.ch/downloads/csv_recent/"
    requires_auth: false
    field_mapping:
      url: "value"
      dateadded: "first_seen"
      threat: "description"
    default_config:
      include_types: ["url"]
      default_severity: "high"
      auto_expire_days: 30
    recommended_priority: 50
    estimated_ioc_count: 10000
    tags: ["malware", "urls", "abuse.ch"]

  - id: "abuse-ch-feodo"
    name: "abuse.ch Feodo Tracker"
    description: "Feodo/Emotet/Dridex C2 servers"
    type: "csv"
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    requires_auth: false
    field_mapping:
      dst_ip: "value"
      first_seen_utc: "first_seen"
      malware: "description"
    default_config:
      include_types: ["ip"]
      default_severity: "critical"
      auto_expire_days: 7
    recommended_priority: 90
    estimated_ioc_count: 500
    tags: ["malware", "c2", "emotet", "abuse.ch"]

  - id: "abuse-ch-sslbl"
    name: "abuse.ch SSL Blacklist"
    description: "Malicious SSL certificate fingerprints"
    type: "csv"
    url: "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
    requires_auth: false
    field_mapping:
      sha1: "value"
      listing_reason: "description"
    default_config:
      include_types: ["hash"]
      default_severity: "high"
    recommended_priority: 60
    estimated_ioc_count: 3000
    tags: ["ssl", "certificates", "abuse.ch"]

  - id: "otx-alienvault"
    name: "AlienVault OTX"
    description: "Open Threat Exchange community indicators"
    type: "otx"
    url: "https://otx.alienvault.com"
    requires_auth: true
    auth_fields: ["api_key"]
    default_config:
      min_confidence: 50
    recommended_priority: 40
    estimated_ioc_count: 100000
    tags: ["community", "multi-source"]

  - id: "misp-circl"
    name: "CIRCL MISP"
    description: "CIRCL public MISP instance"
    type: "misp"
    url: "https://www.circl.lu"
    requires_auth: true
    auth_fields: ["api_key"]
    recommended_priority: 70
    estimated_ioc_count: 50000
    tags: ["circl", "misp", "europe"]

  - id: "emergingthreats-compromised"
    name: "Emerging Threats Compromised IPs"
    description: "Known compromised hosts"
    type: "csv"
    url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    requires_auth: false
    field_mapping:
      line: "value"  # One IP per line
    default_config:
      include_types: ["ip"]
      default_severity: "medium"
    recommended_priority: 30
    estimated_ioc_count: 2000
    tags: ["compromised", "ips"]

  - id: "custom-filesystem"
    name: "Custom Local IOCs"
    description: "Local filesystem IOC files"
    type: "filesystem"
    requires_auth: false
    default_config:
      path: "./ioc_feeds/custom/"
      auto_enable: true
    recommended_priority: 1000
    estimated_ioc_count: 0
    tags: ["custom", "local"]
```

---

## Phase 5: Implementation Tasks

### Task Breakdown

| Phase | Task | Estimated Effort | Dependencies |
|-------|------|------------------|--------------|
| **1.1** | Create `threat/feeds/types.go` data models | 2h | None |
| **1.2** | Extend `core/ioc.go` with feed fields | 1h | None |
| **1.3** | Create `storage/sqlite_ioc_feeds.go` | 4h | 1.1, 1.2 |
| **1.3b** | Add migration for iocs table (feed columns) | 1h | 1.2 |
| **1.4** | Create handler interfaces | 1h | 1.1 |
| **1.4b** | Implement CSV/JSON handlers | 3h | 1.4 |
| **1.4c** | Implement OTX handler | 3h | 1.4 |
| **1.4d** | Implement MISP handler | 4h | 1.4 |
| **1.4e** | Implement STIX/TAXII handler | 6h | 1.4 |
| **1.5** | Create IOC Feed Manager | 4h | 1.3, 1.4 |
| **1.6** | Create IOC Feed Scheduler | 2h | 1.5 |
| **2.1** | Create `api/ioc_feed_handlers.go` | 4h | 1.5 |
| **2.2** | Extend existing IOC handlers | 2h | 1.2 |
| **2.3** | Add WebSocket events | 1h | 2.1 |
| **3.1** | Create IOCFeedSettings.tsx | 4h | 2.1 |
| **3.2** | Create feed components | 4h | 3.1 |
| **3.3** | Extend IOC page | 3h | 2.2 |
| **3.4** | Create dashboard widget | 2h | 2.1 |
| **3.5** | Create frontend types | 1h | None |
| **3.6** | Create frontend service | 1h | 3.5 |
| **4.1** | Create feed templates | 2h | 1.1 |
| **5.0** | Integration testing | 4h | All |
| **5.1** | Documentation | 2h | All |

**Total Estimated Effort: ~55-60 hours**

---

## Conflict Resolution Strategy

### Priority-Based Resolution

When an IOC exists in multiple sources (manual + feeds, or multiple feeds):

1. **Manual IOCs always win** - User-created IOCs are never overwritten
2. **Higher priority feed wins** - Feeds have configurable priority (0-1000)
3. **Newer data wins** (within same priority) - More recent sync updates existing

### Deduplication

- IOCs deduplicated by `(type, normalized_value)`
- Feed IOCs additionally tracked by `(feed_id, external_id)`
- Cross-feed duplicates handled by priority

### Update Behavior

| Scenario | Behavior |
|----------|----------|
| Feed IOC already exists (same feed) | Update metadata, refresh `last_seen` |
| Feed IOC exists from different feed | Compare priority, higher wins |
| Feed IOC exists as manual | Skip (manual preserved) |
| Manual IOC exists as feed | Manual untouched, feed version skipped |

---

## Security Considerations

1. **SSRF Protection** - Validate URLs, block private IP ranges (reuse existing)
2. **Credential Storage** - AuthConfig encrypted at rest, masked in responses
3. **Rate Limiting** - Respect feed provider rate limits
4. **Input Validation** - Validate all imported IOC values
5. **Size Limits** - Max IOCs per sync, max request body size
6. **Timeout Handling** - Feed connection and sync timeouts

---

## Configuration

### Environment Variables

```bash
# IOC Feeds
IOC_FEEDS_ENABLED=true
IOC_FEEDS_WORKING_DIR=./ioc_feeds
IOC_FEEDS_MAX_CONCURRENT_SYNCS=3
IOC_FEEDS_SYNC_TIMEOUT=1800  # 30 minutes
IOC_FEEDS_DEFAULT_EXPIRE_DAYS=90

# API Keys (for default feeds)
OTX_API_KEY=your_key_here
MISP_API_KEY=your_key_here
```

### Config File Section

```yaml
ioc_feeds:
  enabled: true
  working_dir: "./ioc_feeds"

  scheduler:
    enabled: true
    timezone: "UTC"
    max_concurrent_syncs: 3
    sync_timeout: 1800
    retry_failed_syncs: true
    retry_delay: 3600

  import_settings:
    batch_size: 500
    validate_before_import: true
    skip_duplicates: true
    default_expire_days: 90
```

---

## Success Metrics

1. **Functional**
   - Can create, edit, delete IOC feeds
   - Can sync feeds manually and on schedule
   - IOCs appear in IOC page with source attribution
   - WebSocket progress updates work

2. **Performance**
   - Sync of 10,000 IOCs completes in < 60 seconds
   - IOC page loads with 100k+ IOCs in < 2 seconds
   - No memory leaks during continuous syncing

3. **Reliability**
   - Failed syncs don't corrupt existing data
   - Scheduler recovers from crashes
   - Duplicate handling works correctly

---

## Future Enhancements

1. **Threat Intel Enrichment** - Auto-enrich IOCs with VirusTotal, Shodan, etc.
2. **Feed Health Alerts** - Notify on repeated sync failures
3. **IOC Sharing** - Export IOCs to STIX format
4. **Feed Recommendations** - Suggest feeds based on detected threats
5. **Confidence Scoring** - Multi-source confidence aggregation
6. **IOC Aging** - Auto-deprecate stale IOCs
