# SIGMA Rule Feeds - Operator Guide

## Overview

This guide provides comprehensive documentation for operators managing SIGMA rule feeds in Cerberus SIEM. Feed management allows you to automatically import and synchronize detection rules from external sources, keeping your rule set current with emerging threats.

**Version**: 1.0
**Last Updated**: 2025-01-15
**Target Audience**: Security Operations, SIEM Administrators

---

## Table of Contents

1. [Feed System Architecture](#feed-system-architecture)
2. [Supported Feed Types](#supported-feed-types)
3. [Configuration](#configuration)
4. [Feed Operations](#feed-operations)
5. [Monitoring and Health](#monitoring-and-health)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)
8. [Backup and Recovery](#backup-and-recovery)

---

## Feed System Architecture

### Components

The feed system consists of several key components:

```
┌─────────────────────────────────────────────────────────────┐
│                     Feed Manager                            │
│  - Feed CRUD operations                                     │
│  - Synchronization orchestration                            │
│  - Scheduling and automation                                │
└─────────────────┬───────────────────────────────────────────┘
                  │
    ┌─────────────┼─────────────┬─────────────────────┐
    │             │             │                     │
┌───▼────┐  ┌────▼─────┐  ┌───▼────────┐  ┌────────▼─────┐
│  Git   │  │Filesystem│  │    HTTP    │  │   Future:    │
│Handler │  │ Handler  │  │  Handler   │  │  S3, API     │
└───┬────┘  └────┬─────┘  └───┬────────┘  └──────────────┘
    │            │            │
    └────────────┼────────────┘
                 │
       ┌─────────▼──────────┐
       │   Rule Storage     │
       │   (SQLite)         │
       └────────────────────┘
```

### Data Flow

1. **Feed Configuration**: Operator configures feed source and filters
2. **Synchronization**: Feed handler fetches rules from source
3. **Filtering**: Rules are filtered based on configured criteria
4. **Validation**: SIGMA rules are validated for correctness
5. **Import**: Valid rules are stored in rule database
6. **Tracking**: Sync history and statistics are recorded

### Storage

- **Feed Metadata**: SQLite table `rule_feeds`
- **Sync History**: SQLite table `feed_sync_history`
- **Rule Storage**: SQLite table `rules` (via RuleStorage interface)
- **Git Repositories**: Temporary working directory for cloned repos

---

## Supported Feed Types

### 1. Git Feeds

Pull SIGMA rules from Git repositories.

**Use Cases**:
- SigmaHQ official repository
- Organization-specific rule repositories
- Community threat detection repos
- Version-controlled rule sets

**Required Fields**:
- `url`: Git repository URL (https or git protocol)
- `branch`: Git branch to sync (e.g., `master`, `main`)

**Optional Fields**:
- `auth_config`: Authentication credentials
  - `username`: Git username
  - `password`: Git password or personal access token
  - `token`: OAuth token
  - `ssh_key`: SSH private key (for git:// URLs)

**Example**:
```json
{
  "name": "SigmaHQ Official Rules",
  "type": "git",
  "url": "https://github.com/SigmaHQ/sigma.git",
  "branch": "master",
  "include_paths": ["rules/"],
  "exclude_paths": ["rules/deprecated/"],
  "enabled": true
}
```

**Security Considerations**:
- HTTPS URLs are validated to prevent SSRF attacks
- Private IP ranges are blocked
- Credentials are encrypted at rest
- SSH keys must be properly secured

### 2. Filesystem Feeds

Load SIGMA rules from local filesystem paths.

**Use Cases**:
- Custom rules developed in-house
- Rules synchronized via external mechanisms (NFS, rsync)
- Development and testing scenarios
- Air-gapped environments

**Required Fields**:
- `path`: Absolute path to rule directory

**Optional Fields**:
- `include_paths`: Subdirectories to include (relative to `path`)
- `exclude_paths`: Subdirectories to exclude

**Example**:
```json
{
  "name": "Custom Internal Rules",
  "type": "filesystem",
  "path": "/opt/cerberus/custom-rules",
  "include_paths": ["production/"],
  "exclude_paths": ["testing/", "deprecated/"],
  "enabled": true
}
```

**Security Considerations**:
- Path traversal protection enforced (blocks `..` sequences)
- System directory access forbidden (`/etc`, `/sys`, `/proc`, etc.)
- Filesystem permissions must allow read access
- Symbolic links are followed (ensure safe targets)

### 3. HTTP Feeds (Future)

Fetch rules via HTTP/HTTPS endpoints.

**Planned Features**:
- REST API endpoints
- Archive downloads (ZIP, tar.gz)
- Authenticated endpoints
- Checksum verification

### 4. S3 Feeds (Future)

Load rules from AWS S3 buckets or S3-compatible storage.

**Planned Features**:
- IAM role-based authentication
- Versioning support
- Bucket-level filtering
- Cross-region replication

---

## Configuration

### Feed Properties

#### Core Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `id` | string | Auto-generated | Unique feed identifier (UUID) |
| `name` | string | Yes | Human-readable feed name |
| `description` | string | No | Detailed feed description |
| `type` | string | Yes | Feed type: `git`, `filesystem`, `http`, etc. |
| `enabled` | boolean | Yes | Enable/disable feed synchronization |
| `status` | string | Auto-set | Current status: `active`, `syncing`, `error` |

#### Source Configuration

| Property | Type | Description |
|----------|------|-------------|
| `url` | string | Repository URL (for `git`, `http` types) |
| `branch` | string | Git branch name (default: `master`) |
| `path` | string | Filesystem path (for `filesystem` type) |
| `auth_config` | object | Authentication credentials (encrypted) |

#### Filtering Configuration

| Property | Type | Description |
|----------|------|-------------|
| `include_paths` | array | Path patterns to include (glob syntax) |
| `exclude_paths` | array | Path patterns to exclude (glob syntax) |
| `include_tags` | array | Only import rules with these tags |
| `exclude_tags` | array | Skip rules with these tags |
| `min_severity` | string | Minimum severity: `low`, `medium`, `high`, `critical` |

#### Import Behavior

| Property | Type | Description |
|----------|------|-------------|
| `auto_enable_rules` | boolean | Automatically enable imported rules (default: `false`) |
| `priority` | integer | Feed priority for conflict resolution (higher = precedence) |
| `update_strategy` | string | Update strategy: `manual`, `startup`, `scheduled`, `webhook` |
| `update_schedule` | string | Cron expression for scheduled updates |

#### Metadata

| Property | Type | Description |
|----------|------|-------------|
| `tags` | array | Custom tags for organizing feeds |
| `metadata` | object | Additional key-value metadata |
| `created_at` | timestamp | Feed creation timestamp |
| `updated_at` | timestamp | Last modification timestamp |
| `created_by` | string | Username of feed creator |

### Update Strategies

#### 1. Manual (`manual`)

Feeds are synchronized only when explicitly triggered.

**Use When**:
- Testing new feed configurations
- Controlled change management required
- Infrequent rule updates

**Trigger Methods**:
- API: `POST /api/v1/feeds/{id}/sync`
- CLI: `cerberus feeds sync <id>`
- UI: Feed details page → "Sync Now" button

#### 2. Startup (`startup`)

Feeds synchronize automatically when Cerberus starts.

**Use When**:
- Ensuring latest rules after deployment
- Container/pod restart scenarios
- Development environments

**Configuration**:
```json
{
  "update_strategy": "startup"
}
```

#### 3. Scheduled (`scheduled`)

Feeds synchronize on a recurring schedule using cron syntax.

**Use When**:
- Regular automatic updates required
- Production continuous threat detection
- Minimizing manual intervention

**Configuration**:
```json
{
  "update_strategy": "scheduled",
  "update_schedule": "0 2 * * *"  // Daily at 2 AM
}
```

**Cron Syntax**:
```
┌───────────── minute (0 - 59)
│ ┌───────────── hour (0 - 23)
│ │ ┌───────────── day of month (1 - 31)
│ │ │ ┌───────────── month (1 - 12)
│ │ │ │ ┌───────────── day of week (0 - 6) (Sunday=0)
│ │ │ │ │
* * * * *
```

**Common Schedules**:
- `0 */6 * * *` - Every 6 hours
- `0 2 * * *` - Daily at 2 AM
- `0 0 * * 0` - Weekly on Sunday at midnight
- `0 0 1 * *` - Monthly on the 1st at midnight

#### 4. Webhook (`webhook`) - Future

Feeds synchronize when triggered by external webhook.

**Planned Features**:
- GitHub webhook integration
- GitLab webhook support
- Custom webhook endpoints
- Signature verification

---

## Feed Operations

### Creating a Feed

#### Via API

```bash
curl -X POST http://localhost:8081/api/v1/feeds \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SigmaHQ Main Feed",
    "description": "Official SIGMA rules from SigmaHQ repository",
    "type": "git",
    "url": "https://github.com/SigmaHQ/sigma.git",
    "branch": "master",
    "include_paths": ["rules/"],
    "exclude_paths": ["rules/deprecated/"],
    "auto_enable_rules": false,
    "priority": 100,
    "update_strategy": "scheduled",
    "update_schedule": "0 2 * * *",
    "enabled": true,
    "tags": ["official", "sigmahq"]
  }'
```

**Response**:
```json
{
  "feed": {
    "id": "feed-abc123",
    "name": "SigmaHQ Main Feed",
    "status": "active",
    "created_at": "2025-01-15T10:00:00Z",
    ...
  }
}
```

#### Via UI

1. Navigate to **Feeds** page
2. Click **"Create Feed"** button
3. Select feed type (Git, Filesystem, etc.)
4. Fill in required fields:
   - Feed name
   - Source URL or path
   - Branch (for Git)
5. Configure filters (optional):
   - Include/exclude paths
   - Tag filters
   - Minimum severity
6. Set update strategy
7. Click **"Create Feed"**
8. **Test connection** before enabling
9. Enable feed for synchronization

### Listing Feeds

#### Via API

```bash
# List all feeds
curl http://localhost:8081/api/v1/feeds \
  -H "Authorization: Bearer $TOKEN"

# With pagination
curl "http://localhost:8081/api/v1/feeds?page=1&limit=50" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "items": [
    {
      "id": "feed-abc123",
      "name": "SigmaHQ Main Feed",
      "type": "git",
      "enabled": true,
      "status": "active",
      "stats": {
        "total_rules": 3245,
        "imported_rules": 3200,
        "failed_rules": 45,
        "last_sync_duration": 45.3
      },
      "last_sync": "2025-01-15T02:00:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 50,
  "total_pages": 1
}
```

#### Via UI

Navigate to **Feeds** page to view all configured feeds with:
- Feed status indicators
- Last sync timestamp
- Rule counts
- Enable/disable toggles
- Quick actions (sync, edit, delete)

### Getting Feed Details

#### Via API

```bash
curl http://localhost:8081/api/v1/feeds/feed-abc123 \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "feed": {
    "id": "feed-abc123",
    "name": "SigmaHQ Main Feed",
    "description": "Official SIGMA rules from SigmaHQ repository",
    "type": "git",
    "status": "active",
    "enabled": true,
    "url": "https://github.com/SigmaHQ/sigma.git",
    "branch": "master",
    "auth_config": {
      "username": "***REDACTED***"
    },
    "include_paths": ["rules/"],
    "exclude_paths": ["rules/deprecated/"],
    "min_severity": "medium",
    "auto_enable_rules": false,
    "priority": 100,
    "update_strategy": "scheduled",
    "update_schedule": "0 2 * * *",
    "last_sync": "2025-01-15T02:00:00Z",
    "next_sync": "2025-01-16T02:00:00Z",
    "stats": {
      "total_rules": 3245,
      "imported_rules": 3200,
      "updated_rules": 15,
      "skipped_rules": 30,
      "failed_rules": 45,
      "last_sync_duration": 45.3,
      "sync_count": 42
    },
    "tags": ["official", "sigmahq"],
    "created_at": "2024-12-01T10:00:00Z",
    "updated_at": "2025-01-15T02:00:00Z",
    "created_by": "admin"
  }
}
```

**Note**: Sensitive fields in `auth_config` are automatically redacted in responses.

### Updating a Feed

#### Via API

```bash
curl -X PUT http://localhost:8081/api/v1/feeds/feed-abc123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description",
    "include_paths": ["rules/windows/", "rules/linux/"],
    "min_severity": "high",
    "update_schedule": "0 3 * * *"
  }'
```

**Note**: Only provided fields are updated (partial update supported).

#### Via UI

1. Navigate to **Feeds** page
2. Click on feed to view details
3. Click **"Edit Feed"** button
4. Modify desired fields
5. Click **"Save Changes"**
6. Optionally **"Test Connection"** to validate changes

### Deleting a Feed

#### Via API

```bash
curl -X DELETE http://localhost:8081/api/v1/feeds/feed-abc123 \
  -H "Authorization: Bearer $TOKEN"
```

**Response**: `204 No Content`

**Important**: Deleting a feed does NOT delete the rules that were previously imported from it. Rules remain in the system until manually deleted.

#### Via UI

1. Navigate to **Feeds** page
2. Click on feed to view details
3. Click **"Delete Feed"** button
4. Confirm deletion in dialog

### Synchronizing Feeds

#### Manual Sync (Single Feed)

**Via API**:
```bash
curl -X POST http://localhost:8081/api/v1/feeds/feed-abc123/sync \
  -H "Authorization: Bearer $TOKEN"
```

**Response** (202 Accepted - Async Operation):
```json
{
  "status": "accepted",
  "message": "Feed synchronization started in background. Poll the stats endpoint to check completion status.",
  "feed_id": "feed-abc123",
  "status_url": "/api/v1/feeds/feed-abc123/stats"
}
```

**Via UI**:
1. Navigate to feed details page
2. Click **"Sync Now"** button
3. Monitor progress indicator

**Note**: Synchronization is asynchronous. Poll the stats endpoint or view UI progress indicator to track completion.

#### Bulk Sync (All Enabled Feeds)

**Via API**:
```bash
curl -X POST http://localhost:8081/api/v1/feeds/sync-all \
  -H "Authorization: Bearer $TOKEN"
```

**Response** (202 Accepted):
```json
{
  "status": "accepted",
  "message": "Bulk feed synchronization started in background. Poll individual feed stats endpoints to check completion status.",
  "status_url": "/api/v1/feeds"
}
```

**Via UI**:
1. Navigate to **Feeds** page
2. Click **"Sync All Feeds"** button
3. Monitor progress for each feed

#### Checking Sync Status

Poll the feed stats endpoint to monitor synchronization progress:

```bash
# Check if sync is complete
curl http://localhost:8081/api/v1/feeds/feed-abc123/stats \
  -H "Authorization: Bearer $TOKEN"
```

**While Syncing**:
```json
{
  "status": "syncing",
  ...
}
```

**After Completion**:
```json
{
  "status": "active",
  "total_rules": 3245,
  "imported_rules": 3200,
  "updated_rules": 15,
  "skipped_rules": 30,
  "failed_rules": 45,
  "last_sync_duration": 45.3,
  "last_error": "",
  "sync_count": 43
}
```

### Enabling/Disabling Feeds

#### Enable Feed

**Via API**:
```bash
curl -X POST http://localhost:8081/api/v1/feeds/feed-abc123/enable \
  -H "Authorization: Bearer $TOKEN"
```

**Via UI**: Toggle the enable switch on the feed card

#### Disable Feed

**Via API**:
```bash
curl -X POST http://localhost:8081/api/v1/feeds/feed-abc123/disable \
  -H "Authorization: Bearer $TOKEN"
```

**Via UI**: Toggle the enable switch on the feed card

**Effect**: Disabled feeds are not synchronized (manual or scheduled).

### Testing Feed Connection

Test connectivity to a feed source before creating or after configuration changes.

#### Via API

```bash
curl -X POST http://localhost:8081/api/v1/feeds/feed-abc123/test \
  -H "Authorization: Bearer $TOKEN"
```

**Success Response**:
```json
{
  "status": "success",
  "message": "Connection test passed"
}
```

**Failure Response** (400 Bad Request):
```json
{
  "error": "Connection test failed: authentication failed"
}
```

#### Via UI

1. Navigate to feed details or create/edit form
2. Click **"Test Connection"** button
3. View success/failure message

**Tested Aspects**:
- Network connectivity
- Authentication credentials
- Repository/path accessibility
- Permission verification

### Viewing Sync History

#### Via API

```bash
# Get last 20 sync results
curl "http://localhost:8081/api/v1/feeds/feed-abc123/history?limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
[
  {
    "feed_id": "feed-abc123",
    "feed_name": "SigmaHQ Main Feed",
    "start_time": "2025-01-15T02:00:00Z",
    "end_time": "2025-01-15T02:00:45Z",
    "duration": 45.3,
    "success": true,
    "stats": {
      "total_rules": 3245,
      "imported_rules": 50,
      "updated_rules": 15,
      "skipped_rules": 3150,
      "failed_rules": 30
    },
    "errors": [],
    "rule_results": [
      {
        "rule_id": "rule-123",
        "rule_title": "Suspicious PowerShell",
        "file_path": "rules/windows/powershell/suspicious.yml",
        "action": "imported",
        "error": "",
        "reason": ""
      }
    ]
  }
]
```

#### Via UI

1. Navigate to feed details page
2. Click on **"Sync History"** tab
3. View chronological list of sync operations
4. Expand entries to see detailed rule import results

### Feed Templates

Use pre-configured templates for common feed sources.

#### Via API

```bash
curl http://localhost:8081/api/v1/feeds/templates \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
[
  {
    "id": "sigmahq-main",
    "name": "SigmaHQ Official Rules (Main)",
    "description": "Official SIGMA rules from SigmaHQ repository - main branch",
    "type": "git",
    "url": "https://github.com/SigmaHQ/sigma.git",
    "branch": "master",
    "include_paths": ["rules/"],
    "recommended_priority": 100,
    "estimated_rule_count": 3000,
    "tags": ["official", "community", "comprehensive"]
  },
  {
    "id": "sigmahq-emerging",
    "name": "SigmaHQ Emerging Threats",
    "description": "Emerging threat detection rules from SigmaHQ",
    "type": "git",
    "url": "https://github.com/SigmaHQ/sigma.git",
    "branch": "master",
    "include_paths": ["rules/emerging-threats/"],
    "recommended_priority": 90,
    "estimated_rule_count": 200,
    "tags": ["official", "emerging-threats"]
  }
]
```

#### Via UI

1. Navigate to **Feeds** page
2. Click **"Create Feed from Template"**
3. Select a template
4. Review and customize pre-filled configuration
5. Click **"Create Feed"**

---

## Monitoring and Health

### Feed Statistics

Monitor feed health and performance through statistics.

#### Key Metrics

| Metric | Description | Good Value |
|--------|-------------|------------|
| `total_rules` | Total rules discovered in feed | N/A |
| `imported_rules` | Successfully imported rules | High % of total |
| `updated_rules` | Rules updated in last sync | Expected churn |
| `skipped_rules` | Rules filtered by criteria | Expected based on filters |
| `failed_rules` | Rules that failed validation | <5% |
| `last_sync_duration` | Time taken for last sync (seconds) | <60s for most feeds |
| `sync_count` | Total number of syncs performed | Increments each sync |

#### Viewing Statistics

**Via API**:
```bash
curl http://localhost:8081/api/v1/feeds/feed-abc123/stats \
  -H "Authorization: Bearer $TOKEN"
```

**Via UI**:
- Feed list page: Summary statistics on each feed card
- Feed details page: Detailed statistics dashboard

### Feed Health Checks

#### Feed Status Values

| Status | Meaning | Action Required |
|--------|---------|-----------------|
| `active` | Feed is healthy and operational | None |
| `syncing` | Feed synchronization in progress | Monitor for completion |
| `error` | Last sync failed | Investigate `last_error` field |
| `disabled` | Feed manually disabled | Enable if needed |

#### Health Monitoring Endpoint

```bash
curl http://localhost:8081/api/v1/health/feeds \
  -H "Authorization: Bearer $TOKEN"
```

**Healthy Response**:
```json
{
  "status": "healthy",
  "total_feeds": 5,
  "enabled_feeds": 4,
  "failed_feeds": 0,
  "feeds": {
    "feed-abc123": "active",
    "feed-def456": "active",
    "feed-ghi789": "disabled",
    "feed-jkl012": "active"
  }
}
```

**Degraded Response** (if failures detected):
```json
{
  "status": "degraded",
  "total_feeds": 5,
  "enabled_feeds": 4,
  "failed_feeds": 1,
  "feeds": {
    "feed-abc123": "error"
  },
  "message": "1 feed(s) in error state"
}
```

### Logging

Feed operations are logged for audit and troubleshooting.

#### Log Locations

- **Application Logs**: Standard output (container) or `/var/log/cerberus/cerberus.log`
- **Audit Logs**: All feed CRUD operations logged with user context

#### Log Levels

- **INFO**: Feed sync start/completion, rule import summary
- **WARN**: Validation failures, skipped rules, retry attempts
- **ERROR**: Sync failures, authentication errors, critical issues

#### Example Log Entries

```
2025-01-15T02:00:00Z INFO  Feed sync started: SigmaHQ Main Feed (feed-abc123)
2025-01-15T02:00:15Z INFO  Importing 3245 rules from feed: SigmaHQ Main Feed
2025-01-15T02:00:45Z INFO  Feed sync completed: feed_id=feed-abc123 success=true imported=50 updated=15 failed=30 duration=45.3s
2025-01-15T02:00:45Z WARN  30 rules failed validation in feed feed-abc123
2025-01-15T10:30:00Z INFO  Feed created: feed_id=feed-def456 feed_name="Custom Rules" created_by=admin client_ip=192.168.1.50
```

### Alerting

Configure alerts for feed health issues.

#### Recommended Alerts

1. **Feed Sync Failure**
   - Condition: `status == "error"` for >1 hour
   - Severity: Medium
   - Action: Review `last_error` field, check connectivity

2. **High Failed Rule Rate**
   - Condition: `failed_rules / total_rules > 0.1` (>10% failure)
   - Severity: High
   - Action: Review rule validation errors, check SIGMA syntax

3. **Sync Duration Degradation**
   - Condition: `last_sync_duration > 300` (>5 minutes)
   - Severity: Low
   - Action: Investigate network latency, repository size

4. **No Successful Syncs**
   - Condition: Feed enabled but no successful sync in 7 days
   - Severity: High
   - Action: Check scheduler, test connection, review logs

---

## Troubleshooting

### Common Issues

#### 1. Feed Sync Fails with Authentication Error

**Symptoms**:
```json
{
  "status": "error",
  "last_error": "authentication failed: invalid credentials"
}
```

**Causes**:
- Incorrect username/password
- Expired access token
- Insufficient repository permissions

**Solutions**:

1. **Verify Credentials**:
   ```bash
   # Test Git credentials manually
   git clone https://username:token@github.com/org/repo.git
   ```

2. **Update Auth Config**:
   ```bash
   curl -X PUT http://localhost:8081/api/v1/feeds/feed-abc123 \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "auth_config": {
         "username": "new-username",
         "token": "ghp_newtoken123"
       }
     }'
   ```

3. **Check Token Scope** (for GitHub Personal Access Tokens):
   - Ensure `repo` scope is granted
   - Generate new token if expired

4. **Test Connection**:
   ```bash
   curl -X POST http://localhost:8081/api/v1/feeds/feed-abc123/test \
     -H "Authorization: Bearer $TOKEN"
   ```

#### 2. High Rule Validation Failure Rate

**Symptoms**:
```json
{
  "stats": {
    "total_rules": 1000,
    "imported_rules": 100,
    "failed_rules": 900
  }
}
```

**Causes**:
- Invalid SIGMA YAML syntax in upstream rules
- Unsupported SIGMA features
- Missing required fields
- Incompatible rule format version

**Solutions**:

1. **Review Sync History**:
   ```bash
   curl http://localhost:8081/api/v1/feeds/feed-abc123/history?limit=1 \
     -H "Authorization: Bearer $TOKEN" | jq '.[]rule_results[] | select(.action == "failed")'
   ```

2. **Check Application Logs**:
   ```bash
   grep "rule validation failed" /var/log/cerberus/cerberus.log
   ```

3. **Validate Individual Rules**:
   - Download failing rule file
   - Test with SIGMA validator: `sigmac --validation-only rule.yml`

4. **Exclude Problematic Paths**:
   ```bash
   curl -X PUT http://localhost:8081/api/v1/feeds/feed-abc123 \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "exclude_paths": ["rules/deprecated/", "rules/experimental/"]
     }'
   ```

5. **Adjust Quality Filters**:
   - Increase `min_severity` to exclude low-quality rules
   - Add tags to `exclude_tags` for experimental rules

#### 3. Feed Sync Timeout

**Symptoms**:
```json
{
  "status": "error",
  "last_error": "sync timeout: context deadline exceeded"
}
```

**Causes**:
- Large repository taking >10 minutes to clone
- Slow network connection
- High latency to upstream source

**Solutions**:

1. **Increase Sync Timeout** (requires config change):
   ```yaml
   # config.yaml
   feeds:
     sync_timeout: 1800  # 30 minutes
   ```

2. **Use Shallow Clone** (Git optimization - future feature):
   ```json
   {
     "metadata": {
       "git_depth": "1"
     }
   }
   ```

3. **Reduce Scope**:
   - Use more specific `include_paths` to reduce rule count
   - Exclude large directories with `exclude_paths`

4. **Check Network**:
   ```bash
   # Test connectivity
   curl -I https://github.com

   # Check DNS resolution
   nslookup github.com
   ```

#### 4. Duplicate Rules Across Feeds

**Symptoms**:
- Same rule imported multiple times
- Unexpected rule updates from lower-priority feeds

**Causes**:
- Multiple feeds containing same rules
- Overlapping `include_paths`
- Feed priority misconfiguration

**Solutions**:

1. **Review Feed Configuration**:
   ```bash
   curl http://localhost:8081/api/v1/feeds \
     -H "Authorization: Bearer $TOKEN" | jq '.items[] | {name, priority, include_paths}'
   ```

2. **Adjust Feed Priorities**:
   - Higher priority feed wins conflict resolution
   - Set official feeds (SigmaHQ) to priority 100
   - Set custom feeds to priority 50-90

3. **Use Exclusive Paths**:
   ```bash
   # Feed 1: Official Windows rules
   "include_paths": ["rules/windows/"]

   # Feed 2: Official Linux rules
   "include_paths": ["rules/linux/"]
   ```

4. **Enable Deduplication** (automatic):
   - Rules are deduplicated by content hash
   - Higher priority feed version is kept

#### 5. Filesystem Feed Path Not Found

**Symptoms**:
```json
{
  "status": "error",
  "last_error": "failed to read directory: no such file or directory"
}
```

**Causes**:
- Incorrect path specified
- Insufficient filesystem permissions
- Mount point not available (NFS, shared volumes)

**Solutions**:

1. **Verify Path Exists**:
   ```bash
   ls -la /opt/cerberus/custom-rules
   ```

2. **Check Permissions**:
   ```bash
   # Cerberus user must have read access
   sudo -u cerberus ls /opt/cerberus/custom-rules
   ```

3. **Verify Mount Points** (Docker/Kubernetes):
   ```bash
   # Check volume mounts
   docker inspect cerberus-siem | grep Mounts -A 10

   # Kubernetes
   kubectl describe pod cerberus-siem-xxx | grep Mounts -A 10
   ```

4. **Update Path**:
   ```bash
   curl -X PUT http://localhost:8081/api/v1/feeds/feed-abc123 \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "path": "/correct/path/to/rules"
     }'
   ```

#### 6. Scheduled Sync Not Running

**Symptoms**:
- Feed configured with `scheduled` strategy
- `next_sync` timestamp in the past
- No recent sync history entries

**Causes**:
- Scheduler not enabled in configuration
- Invalid cron expression
- Timezone mismatch
- Scheduler service not running

**Solutions**:

1. **Check Scheduler Configuration**:
   ```yaml
   # config.yaml
   feeds:
     scheduler:
       enabled: true
       timezone: "UTC"
   ```

2. **Validate Cron Expression**:
   ```bash
   # Use online cron validators or test locally
   # https://crontab.guru/
   ```

3. **Check Application Logs**:
   ```bash
   grep "feed scheduler" /var/log/cerberus/cerberus.log
   ```

4. **Verify Next Sync Timestamp**:
   ```bash
   curl http://localhost:8081/api/v1/feeds/feed-abc123 \
     -H "Authorization: Bearer $TOKEN" | jq '{next_sync, update_schedule}'
   ```

5. **Trigger Manual Sync to Test**:
   ```bash
   curl -X POST http://localhost:8081/api/v1/feeds/feed-abc123/sync \
     -H "Authorization: Bearer $TOKEN"
   ```

6. **Restart Service** (if scheduler is stuck):
   ```bash
   # Systemd
   sudo systemctl restart cerberus

   # Docker
   docker restart cerberus-siem

   # Kubernetes
   kubectl rollout restart deployment/cerberus-siem
   ```

### Diagnostic Commands

```bash
# Check feed health
curl http://localhost:8081/api/v1/health/feeds -H "Authorization: Bearer $TOKEN"

# List all feeds with status
curl http://localhost:8081/api/v1/feeds -H "Authorization: Bearer $TOKEN" | jq '.items[] | {name, status, enabled}'

# Get detailed stats for specific feed
curl http://localhost:8081/api/v1/feeds/feed-abc123/stats -H "Authorization: Bearer $TOKEN"

# View recent sync history
curl "http://localhost:8081/api/v1/feeds/feed-abc123/history?limit=5" -H "Authorization: Bearer $TOKEN"

# Test feed connection
curl -X POST http://localhost:8081/api/v1/feeds/feed-abc123/test -H "Authorization: Bearer $TOKEN"

# Check application logs for feed errors
grep -i "feed.*error" /var/log/cerberus/cerberus.log | tail -20

# View feed sync operations in audit log
grep "Feed sync" /var/log/cerberus/cerberus.log | tail -10
```

---

## Best Practices

### 1. Feed Organization

**Separate Feeds by Source and Purpose**:
```
✅ Good:
- SigmaHQ Windows Rules (priority: 100)
- SigmaHQ Linux Rules (priority: 100)
- Custom Internal Rules (priority: 90)
- Experimental Rules (priority: 50)

❌ Bad:
- All Rules Feed (single feed with all sources mixed)
```

**Benefits**:
- Easier troubleshooting
- Granular control over updates
- Clear priority hierarchy
- Better performance (smaller sync operations)

### 2. Priority Management

**Priority Hierarchy**:
```
100-110: Official/vendor rules (SigmaHQ, vendor-specific)
 80-99:  Community-contributed rules
 50-79:  Custom internal rules (production)
 20-49:  Custom internal rules (testing)
  1-19:  Experimental/development rules
```

**Rules**:
- Higher priority feeds override lower priority feeds for duplicate rules
- Use consistent priority ranges for similar feed types
- Document priority scheme for your organization

### 3. Scheduling Strategy

**Recommended Schedules by Feed Type**:

| Feed Type | Update Frequency | Schedule | Rationale |
|-----------|------------------|----------|-----------|
| Official (SigmaHQ) | Daily | `0 2 * * *` | Daily threat intelligence updates |
| Vendor Rules | Weekly | `0 3 * * 0` | Stable, less frequent changes |
| Custom Internal | On-demand | `manual` | Controlled change management |
| Experimental | Weekly | `0 4 * * 6` | Testing, non-critical |

**Avoid**:
- Syncing all feeds simultaneously (spreads load)
- Very frequent syncs (<6 hours) for stable feeds
- Syncing during peak hours (schedule for off-hours)

### 4. Resource Management

**Git Working Directory Cleanup**:
```bash
# Periodically clean up Git working directories
find /tmp/cerberus-feeds -type d -mtime +7 -exec rm -rf {} \;
```

**Monitor Disk Space**:
```bash
# Ensure adequate space for Git clones
df -h /tmp
df -h /var/lib/cerberus
```

**Resource Limits** (Kubernetes):
```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "250m"
  limits:
    memory: "2Gi"
    cpu: "1000m"
```

### 5. Security Hardening

**Credential Management**:
- Use personal access tokens instead of passwords
- Rotate credentials regularly (every 90 days)
- Use least-privilege access (read-only repository access)
- Store credentials in secure secret management (Vault, AWS Secrets Manager)

**Network Security**:
- Use HTTPS URLs for Git feeds (never HTTP)
- Validate TLS certificates
- Restrict egress network access to known sources
- Use private Git repositories for sensitive custom rules

**Audit Trail**:
- Enable audit logging for all feed operations
- Review feed modification logs regularly
- Monitor for unauthorized feed additions
- Alert on feed configuration changes

### 6. Change Management

**Feed Update Process**:

1. **Test in Staging**:
   - Create feed in staging environment first
   - Run manual sync to validate
   - Review imported rules
   - Test rule matching against sample events

2. **Staged Rollout**:
   - Create feed in production (disabled)
   - Test connection
   - Enable feed with `auto_enable_rules: false`
   - Manual sync and review
   - Gradually enable rules
   - Monitor for false positives

3. **Documentation**:
   - Document feed purpose and rationale
   - Record configuration decisions (filters, priority)
   - Maintain feed inventory spreadsheet
   - Document known issues or limitations

### 7. Monitoring and Alerting

**Configure Prometheus Metrics** (if available):
```yaml
# Sample Prometheus alerts
- alert: FeedSyncFailure
  expr: cerberus_feed_sync_failures_total > 0
  for: 1h
  annotations:
    summary: "Feed sync failing"

- alert: HighRuleFailureRate
  expr: (cerberus_feed_failed_rules / cerberus_feed_total_rules) > 0.1
  for: 30m
  annotations:
    summary: ">10% rule validation failures"
```

**Dashboard Widgets**:
- Feed health status grid
- Sync success rate over time
- Rule import trends
- Failed rule count by feed

### 8. Backup Strategy

**What to Backup**:
- Feed configurations (SQLite `rule_feeds` table)
- Sync history (SQLite `feed_sync_history` table)
- Imported rules (SQLite `rules` table)

**Backup Frequency**:
- Feed configurations: Daily
- Sync history: Weekly (retain 30 days)
- Imported rules: Daily

**Export Feed Configurations**:
```bash
# Export all feed configs
curl http://localhost:8081/api/v1/feeds \
  -H "Authorization: Bearer $TOKEN" > feeds-backup.json

# Import feed configs (manual process via API)
for feed in $(jq -c '.items[]' feeds-backup.json); do
  curl -X POST http://localhost:8081/api/v1/feeds \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$feed"
done
```

---

## Backup and Recovery

### Backup Procedures

#### 1. Feed Configuration Backup

**Manual Backup**:
```bash
# Backup feed configurations
curl http://localhost:8081/api/v1/feeds \
  -H "Authorization: Bearer $TOKEN" | jq '.items' > feeds-$(date +%Y%m%d).json

# Verify backup
jq '.' feeds-$(date +%Y%m%d).json
```

**Automated Backup Script**:
```bash
#!/bin/bash
# /opt/cerberus/scripts/backup-feeds.sh

BACKUP_DIR="/var/backups/cerberus/feeds"
DATE=$(date +%Y%m%d)
TOKEN="${CERBERUS_API_TOKEN}"

mkdir -p "$BACKUP_DIR"

# Backup feed configurations
curl -s http://localhost:8081/api/v1/feeds \
  -H "Authorization: Bearer $TOKEN" | jq '.items' > "$BACKUP_DIR/feeds-$DATE.json"

# Backup sync history for each feed
for feed_id in $(jq -r '.[].id' "$BACKUP_DIR/feeds-$DATE.json"); do
  curl -s "http://localhost:8081/api/v1/feeds/$feed_id/history?limit=100" \
    -H "Authorization: Bearer $TOKEN" > "$BACKUP_DIR/history-$feed_id-$DATE.json"
done

# Compress backups older than 7 days
find "$BACKUP_DIR" -name "*.json" -mtime +7 -exec gzip {} \;

# Delete backups older than 90 days
find "$BACKUP_DIR" -name "*.json.gz" -mtime +90 -delete

echo "Feed backup completed: $BACKUP_DIR/feeds-$DATE.json"
```

**Cron Schedule**:
```bash
# Daily at 3 AM
0 3 * * * /opt/cerberus/scripts/backup-feeds.sh >> /var/log/cerberus/feed-backup.log 2>&1
```

#### 2. Database Backup

**SQLite Database**:
```bash
# Backup entire SQLite database (includes feeds, rules, sync history)
sqlite3 /var/lib/cerberus/cerberus.db ".backup /var/backups/cerberus/db-$(date +%Y%m%d).db"

# Verify backup integrity
sqlite3 /var/backups/cerberus/db-$(date +%Y%m%d).db "PRAGMA integrity_check;"
```

**Table-Specific Exports**:
```bash
# Export feed tables only
sqlite3 /var/lib/cerberus/cerberus.db <<EOF
.mode csv
.output /var/backups/cerberus/rule_feeds-$(date +%Y%m%d).csv
SELECT * FROM rule_feeds;
.output /var/backups/cerberus/feed_sync_history-$(date +%Y%m%d).csv
SELECT * FROM feed_sync_history;
.quit
EOF
```

### Recovery Procedures

#### 1. Restore Feed Configuration

**From JSON Backup**:
```bash
# Restore all feeds from backup
jq -c '.[]' feeds-20250115.json | while read feed; do
  # Remove read-only fields
  feed_clean=$(echo "$feed" | jq 'del(.id, .created_at, .updated_at, .stats, .last_sync, .next_sync)')

  # Create feed
  curl -X POST http://localhost:8081/api/v1/feeds \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$feed_clean"
done
```

**Selective Restore**:
```bash
# Restore specific feed by name
FEED_NAME="SigmaHQ Main Feed"
jq -c ".[] | select(.name == \"$FEED_NAME\")" feeds-20250115.json | \
  jq 'del(.id, .created_at, .updated_at, .stats, .last_sync, .next_sync)' | \
  curl -X POST http://localhost:8081/api/v1/feeds \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d @-
```

#### 2. Restore from Database Backup

**Full Database Restore**:
```bash
# Stop Cerberus service
sudo systemctl stop cerberus

# Restore database
cp /var/backups/cerberus/db-20250115.db /var/lib/cerberus/cerberus.db

# Fix permissions
chown cerberus:cerberus /var/lib/cerberus/cerberus.db

# Start service
sudo systemctl start cerberus
```

**Verify Restoration**:
```bash
# Check feed count
curl http://localhost:8081/api/v1/feeds -H "Authorization: Bearer $TOKEN" | jq '.total'

# Verify specific feed
curl http://localhost:8081/api/v1/feeds/feed-abc123 -H "Authorization: Bearer $TOKEN"
```

#### 3. Disaster Recovery Scenarios

**Scenario 1: Accidental Feed Deletion**

```bash
# 1. Identify deleted feed from backup
jq '.[] | select(.id == "feed-abc123")' feeds-20250115.json

# 2. Restore feed (without ID to create new)
jq '.[] | select(.id == "feed-abc123") | del(.id, .created_at, .updated_at, .stats, .last_sync, .next_sync)' \
  feeds-20250115.json | \
  curl -X POST http://localhost:8081/api/v1/feeds \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d @-

# 3. Trigger sync to restore rules
NEW_FEED_ID=$(curl http://localhost:8081/api/v1/feeds -H "Authorization: Bearer $TOKEN" | \
  jq -r '.items[] | select(.name == "SigmaHQ Main Feed") | .id')

curl -X POST http://localhost:8081/api/v1/feeds/$NEW_FEED_ID/sync \
  -H "Authorization: Bearer $TOKEN"
```

**Scenario 2: Corrupted Feed Configuration**

```bash
# 1. Identify corrupted feed
curl http://localhost:8081/api/v1/feeds/feed-abc123 -H "Authorization: Bearer $TOKEN"

# 2. Delete corrupted feed
curl -X DELETE http://localhost:8081/api/v1/feeds/feed-abc123 \
  -H "Authorization: Bearer $TOKEN"

# 3. Restore from backup (see Scenario 1)
```

**Scenario 3: Lost Sync History**

```bash
# Sync history is maintained in database
# Restore from database backup to recover history

# If database backup not available, history is lost
# Trigger new sync to rebuild going forward
curl -X POST http://localhost:8081/api/v1/feeds/feed-abc123/sync \
  -H "Authorization: Bearer $TOKEN"
```

### High Availability Considerations

**For Production Deployments**:

1. **Database Replication**:
   - Use SQLite Write-Ahead Logging (WAL) mode
   - Regular automated backups to remote storage
   - Consider PostgreSQL/MySQL for HA deployments

2. **Feed Configuration as Code**:
   - Store feed configurations in Git repository
   - Use Infrastructure as Code (Terraform, Ansible)
   - Automated feed provisioning on deployment

3. **Monitoring and Alerting**:
   - Alert on backup failures
   - Monitor backup age (alert if >24 hours old)
   - Test restore procedures quarterly

---

## Additional Resources

### Documentation
- [SIGMA Feeds Quick Start Guide](../SIGMA_FEEDS_QUICKSTART.md)
- [SIGMA Rollout Guide](../SIGMA_ROLLOUT_GUIDE.md)
- [API Reference - Swagger](../swagger.yaml)
- [Production Deployment Runbook](./production-deployment-runbook.md)

### External Resources
- [SigmaHQ Official Repository](https://github.com/SigmaHQ/sigma)
- [SIGMA Specification](https://github.com/SigmaHQ/sigma/wiki/Specification)
- [Cron Expression Generator](https://crontab.guru/)

### Support
- **Issues**: GitHub Issues with `sigma-feeds` label
- **Documentation Updates**: Submit PRs to update this guide
- **Questions**: Community Slack/Discord channels

---

**Document Version**: 1.0
**Last Updated**: 2025-01-15
**Next Review**: 2025-04-15
