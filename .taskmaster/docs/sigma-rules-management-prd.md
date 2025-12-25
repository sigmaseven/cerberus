# SIGMA Rules Management & Refresh Feature PRD

## Overview

Cerberus has a fully implemented backend SIGMA feed management system (`sigma/feeds/`) that supports Git repositories, filesystem sources, scheduled syncs, and intelligent deduplication. However, this functionality is not exposed to end users through the UI or documented for operators. This PRD defines the user-facing features needed to manage and refresh SIGMA rules.

## Problem Statement

1. **No UI for Feed Management**: Users cannot view, add, edit, or remove SIGMA rule feeds through the frontend
2. **No Manual Refresh Capability**: No way to trigger on-demand feed synchronization from the UI
3. **No Visibility**: Users cannot see sync status, history, or rule import statistics
4. **No Setup Documentation**: New installations lack guidance on configuring SIGMA rule sources
5. **No CLI Tools**: Operators cannot manage feeds from command line for automation

## Goals

1. Provide a complete UI for SIGMA feed management in the Settings section
2. Enable manual feed refresh with real-time progress feedback
3. Display sync history, statistics, and rule import results
4. Create operator documentation for new installations and ongoing maintenance
5. Implement CLI commands for feed management automation

## Non-Goals

- Implementing new feed handler types (HTTP, S3, Webhook) - backend stubs exist for future
- Rule editing/customization UI - rules are read-only from feeds
- Multi-tenant feed isolation - single-tenant deployment assumed

---

## Feature Requirements

### 1. Feed Management API Endpoints

Expose the existing feed manager functionality via REST API.

**Required Endpoints:**

```
GET    /api/v1/feeds                    - List all configured feeds
POST   /api/v1/feeds                    - Create new feed
GET    /api/v1/feeds/{id}               - Get feed details
PUT    /api/v1/feeds/{id}               - Update feed configuration
DELETE /api/v1/feeds/{id}               - Delete feed
POST   /api/v1/feeds/{id}/sync          - Trigger manual sync
POST   /api/v1/feeds/sync-all           - Sync all enabled feeds
GET    /api/v1/feeds/{id}/history       - Get sync history
GET    /api/v1/feeds/{id}/stats         - Get feed statistics
GET    /api/v1/feeds/templates          - List available feed templates
POST   /api/v1/feeds/{id}/test          - Test feed connectivity
POST   /api/v1/feeds/{id}/enable        - Enable feed
POST   /api/v1/feeds/{id}/disable       - Disable feed
```

**Request/Response Models:**

Feed Create/Update:
```json
{
  "name": "SigmaHQ Community Rules",
  "type": "git",
  "enabled": true,
  "priority": 100,
  "url": "https://github.com/SigmaHQ/sigma.git",
  "branch": "master",
  "path": "rules",
  "include_paths": ["rules/windows/**", "rules/linux/**"],
  "exclude_paths": ["rules/deprecated/**"],
  "tags": ["attack.*"],
  "min_severity": "medium",
  "update_strategy": "scheduled",
  "schedule": "0 2 * * *"
}
```

Feed Response:
```json
{
  "id": "feed-123",
  "name": "SigmaHQ Community Rules",
  "type": "git",
  "enabled": true,
  "status": "active",
  "priority": 100,
  "url": "https://github.com/SigmaHQ/sigma.git",
  "branch": "master",
  "path": "rules",
  "stats": {
    "total_rules": 3200,
    "imported_rules": 2800,
    "updated_rules": 45,
    "skipped_rules": 400,
    "failed_rules": 0,
    "last_sync": "2025-01-15T02:00:00Z",
    "last_sync_duration": 45.2,
    "sync_count": 15
  },
  "next_sync": "2025-01-16T02:00:00Z",
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-15T02:00:00Z"
}
```

Sync Result (returned from POST /sync):
```json
{
  "feed_id": "feed-123",
  "feed_name": "SigmaHQ Community Rules",
  "success": true,
  "start_time": "2025-01-15T02:00:00Z",
  "end_time": "2025-01-15T02:00:45Z",
  "duration": 45.2,
  "stats": {
    "total_rules": 3200,
    "imported_rules": 50,
    "updated_rules": 12,
    "skipped_rules": 3138,
    "failed_rules": 0
  },
  "errors": []
}
```

### 2. Feed Management UI (Settings Page)

Add a "SIGMA Feeds" section to the Settings page.

**2.1 Feed List View**

- Display all configured feeds in a table/card layout
- Show for each feed:
  - Name and type icon (Git/Filesystem)
  - Status badge (Active/Disabled/Error/Syncing)
  - Rule count and last sync time
  - Enable/disable toggle
  - Quick actions: Sync, Edit, Delete
- "Add Feed" button opens feed creation dialog
- "Sync All" button triggers sync of all enabled feeds
- Filter by status (Active/Disabled/Error)

**2.2 Feed Creation/Edit Dialog**

- Form fields:
  - Name (required)
  - Type selector (Git Repository / Local Filesystem)
  - For Git: URL, Branch, Authentication (optional)
  - For Filesystem: Path
  - Rules Path (subdirectory within source)
  - Include Patterns (multi-input)
  - Exclude Patterns (multi-input)
  - Tag Filters (multi-input with autocomplete)
  - Minimum Severity dropdown
  - Priority number input
  - Update Strategy selector (Manual/Startup/Scheduled)
  - Schedule input (cron expression) if scheduled
  - Enable toggle
- "Test Connection" button validates configuration
- Save creates/updates feed
- Cancel discards changes

**2.3 Feed Templates**

- "Use Template" dropdown in feed creation
- Pre-populated templates from `feed_templates.yaml`:
  - SigmaHQ Full Repository
  - SigmaHQ Windows Only
  - SigmaHQ Linux Only
  - SigmaHQ Cloud
  - SigmaHQ Network
  - SigmaHQ Web Application
  - SigmaHQ Emerging Threats
  - Custom Organization Rules

**2.4 Feed Detail View**

- Accessed by clicking feed name or "View Details"
- Shows:
  - Full feed configuration
  - Statistics dashboard (pie charts for rule status)
  - Sync history table with pagination
  - Recent errors if any
  - "Sync Now" button with progress indicator

**2.5 Sync Progress Feedback**

- When sync is triggered:
  - Show spinner/progress on feed card
  - Status changes to "Syncing"
  - On completion: refresh stats, show success toast
  - On failure: show error toast, update status to "Error"
- Consider WebSocket for real-time progress updates

### 3. Feed Statistics Dashboard

Add a "Rule Sources" widget to the main Dashboard.

**Dashboard Widget:**
- Total feeds count
- Total rules imported
- Last sync time (most recent across all feeds)
- Quick health indicator (all feeds healthy / some errors)
- Link to full feed management

**Feed Detail Statistics:**
- Rules by severity pie chart
- Rules by source (MITRE tactic) bar chart
- Sync history timeline
- Import/update/skip trend over time

### 4. CLI Commands for Feed Management

Implement CLI subcommands for operator automation.

```bash
# List feeds
cerberus feeds list [--format=table|json]

# Show feed details
cerberus feeds show <feed-id>

# Create feed from template
cerberus feeds add --template=sigmahq-windows --name="Windows Rules"

# Create feed manually
cerberus feeds add --name="Custom" --type=git --url="https://..." --branch=main

# Update feed
cerberus feeds update <feed-id> --min-severity=high

# Delete feed
cerberus feeds delete <feed-id> [--force]

# Sync feed
cerberus feeds sync <feed-id>

# Sync all feeds
cerberus feeds sync-all

# Show sync history
cerberus feeds history <feed-id> [--limit=10]

# Test feed connectivity
cerberus feeds test <feed-id>

# Enable/disable feed
cerberus feeds enable <feed-id>
cerberus feeds disable <feed-id>

# Export feed configuration
cerberus feeds export [--output=feeds-backup.yaml]

# Import feed configuration
cerberus feeds import <file.yaml>
```

### 5. New Installation Setup

**5.1 First-Run Setup Wizard**

When Cerberus starts with no feeds configured:
- Display setup wizard modal
- Step 1: Welcome, explain SIGMA rules
- Step 2: Select feed templates (checkboxes)
- Step 3: Configure sync schedule
- Step 4: Initial sync with progress
- Step 5: Complete, show rule count

**5.2 Default Configuration**

If wizard is skipped, auto-create default feed:
- SigmaHQ Community Rules (already implemented in bootstrap)
- Medium+ severity filter
- Daily sync at 2 AM
- Auto-enable imported rules

### 6. Documentation

**6.1 Operator Guide** (`docs/operations/sigma-feeds.md`)

- Feed system architecture overview
- Supported feed types and configuration
- Setting up SigmaHQ feed
- Setting up custom organization feeds
- Configuring sync schedules
- Monitoring feed health
- Troubleshooting common issues
- Backup and restore feed configuration

**6.2 Quick Start Guide** (`docs/SIGMA_FEEDS_QUICKSTART.md`)

- Prerequisites
- Adding your first feed
- Manual sync walkthrough
- Verifying rules are imported
- Next steps

**6.3 API Reference** (Swagger/OpenAPI)

- Document all feed endpoints
- Request/response examples
- Error codes and handling

---

## Technical Implementation Notes

### Existing Backend Components to Leverage

1. **Feed Manager** (`sigma/feeds/manager.go`)
   - All CRUD operations implemented
   - SyncFeed, SyncAllFeeds implemented
   - GetFeedStats, GetFeedHealth implemented

2. **Feed Storage** (`storage/sqlite_feeds.go`)
   - Database tables exist (rule_feeds, feed_sync_history)
   - Persistence layer complete

3. **Git Handler** (`sigma/feeds/git_handler.go`)
   - Clone, fetch, parse implemented
   - Security validations in place

4. **Filesystem Handler** (`sigma/feeds/filesystem_handler.go`)
   - Directory validation, parsing implemented

5. **Scheduler** (`sigma/feeds/scheduler.go`)
   - Cron-based scheduling implemented

6. **Bootstrap** (`bootstrap/detection.go`)
   - Default feed creation on startup

### New Components Required

1. **API Handlers** (`api/feed_handlers.go`)
   - Wire feed manager to HTTP endpoints
   - Add proper authentication/authorization
   - Implement request validation

2. **Frontend Service** (`frontend/src/services/feedsService.ts`)
   - API client for all feed endpoints

3. **Frontend Types** (`frontend/src/types/index.ts`)
   - Feed, FeedStats, FeedSyncResult, FeedTemplate types

4. **Frontend Pages/Components**
   - Settings/Feeds section
   - FeedList, FeedCard, FeedForm components
   - FeedDetailModal, SyncHistoryTable components
   - SetupWizard component

5. **CLI Commands** (`cmd/feeds.go` or similar)
   - Implement cobra subcommands
   - Wire to feed manager

6. **Documentation Files**
   - Operator guide
   - Quick start
   - Swagger additions

### RBAC Permissions

- `feeds:read` - View feeds and stats
- `feeds:write` - Create, update, sync feeds
- `feeds:delete` - Delete feeds
- `feeds:admin` - Manage scheduler, global settings

### WebSocket Events (Optional Enhancement)

- `feed:sync:started` - Sync began
- `feed:sync:progress` - Progress update (rules processed)
- `feed:sync:completed` - Sync finished with stats
- `feed:sync:failed` - Sync failed with error

---

## Success Metrics

1. **Adoption**: >80% of installations have at least one active feed
2. **Freshness**: Average time since last sync < 24 hours
3. **Health**: <5% of feeds in error state
4. **User Satisfaction**: Operators can manage feeds without documentation

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Large repo sync times (SigmaHQ is 3000+ rules) | Progress feedback, background sync, depth=1 clone |
| Git rate limiting | Implement retry with backoff, cache clones |
| Disk space from clones | Configurable working directory, cleanup old clones |
| Conflicting rules from multiple feeds | Priority-based resolution, content hash dedup |
| Feed connectivity issues | Test connection before save, clear error display |

---

## Open Questions

1. Should we support private Git repos with SSH keys? (Backend supports it, need UI for key management)
2. Should sync run in background worker or inline? (Currently inline)
3. Should we implement feed "preview" to see rules before import?
4. Should deleted feeds auto-disable their imported rules?

---

## Appendix: Existing Feed Templates

From `sigma_feeds/config/feed_templates.yaml`:

| Template | Rules | Description |
|----------|-------|-------------|
| sigmahq-full | 3000+ | Complete SigmaHQ repository |
| sigmahq-windows | 1800+ | Windows-specific rules |
| sigmahq-linux | 400+ | Linux-specific rules |
| sigmahq-cloud | 300+ | Cloud platform rules (AWS, Azure, GCP) |
| sigmahq-network | 200+ | Network detection rules |
| sigmahq-web | 150+ | Web application rules |
| sigmahq-macos | 150+ | macOS-specific rules |
| sigmahq-emerging | 500+ | Emerging threat rules |
