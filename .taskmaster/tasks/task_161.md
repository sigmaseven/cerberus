# Task ID: 161

**Title:** Create SIGMA Feeds Operator Documentation

**Status:** done

**Dependencies:** 154 ✓, 159 ✓

**Priority:** medium

**Description:** Write comprehensive operator guide for feed management and troubleshooting

**Details:**

Create docs/operations/sigma-feeds.md:

Table of Contents:
1. Feed System Architecture
   - Overview of components (manager, handlers, scheduler, storage)
   - Data flow diagram
   - Supported feed types (Git, Filesystem, future: HTTP/S3/Webhook)

2. Feed Configuration
   - Feed types explained:
     * Git repositories (clone, fetch, branch tracking)
     * Filesystem sources (local directory monitoring)
   - Configuration options reference:
     * URL/Path specification
     * Include/exclude patterns (glob syntax)
     * Tag filters (MITRE tactics)
     * Severity filtering
     * Priority and deduplication
     * Update strategies (manual, startup, scheduled)
     * Cron schedule syntax

3. Setting Up SigmaHQ Feed
   - Step-by-step guide with screenshots
   - Recommended configuration:
     * URL: https://github.com/SigmaHQ/sigma.git
     * Branch: master
     * Path: rules
     * Min Severity: medium
     * Auto-enable: true
   - Expected sync duration and resource usage

4. Setting Up Custom Organization Feeds
   - Private Git repository setup
   - SSH key authentication
   - File structure requirements
   - SIGMA rule format validation

5. Configuring Sync Schedules
   - Cron expression syntax guide
   - Best practices:
     * Off-peak scheduling
     * Stagger multiple feeds
   - Examples:
     * Daily: 0 2 * * *
     * Weekly: 0 2 * * 0
     * Hourly: 0 * * * *

6. Monitoring Feed Health
   - Dashboard widget overview
   - Feed status meanings (active, disabled, error, syncing)
   - Sync history interpretation
   - Common error messages and meanings
   - Metrics to monitor:
     * Import success rate
     * Sync duration trends
     * Failed rule count

7. Troubleshooting
   - Common issues:
     * Git authentication failures
     * Network timeouts
     * Disk space issues
     * Rule parsing errors
     * Conflicting rules from multiple feeds
   - Debug logging configuration
   - Manual sync testing
   - Feed connectivity testing
   - Database inspection queries

8. Backup and Restore
   - Exporting feed configuration
   - CLI command: cerberus feeds export
   - Importing on new instance
   - Version control for feed configs

9. Performance Tuning
   - Large repository optimization (shallow clone)
   - Working directory cleanup
   - Concurrent sync limits
   - Rate limiting considerations

10. Security Considerations
    - Private repository authentication
    - Credential storage (environment variables)
    - RBAC permissions for feed management
    - Audit logging of feed changes

Create docs/SIGMA_FEEDS_QUICKSTART.md:
- Quick reference for common tasks
- 5-minute setup guide
- CLI cheat sheet
- Troubleshooting checklist

Update README.md:
- Add SIGMA feeds section to features list
- Link to operator guide
- Add quick start example

**Test Strategy:**

Manual review: Technical writer review for clarity, operator testing with fresh Cerberus installation following guide, verify all commands and examples work, peer review by DevOps team.

## Subtasks

### 161.1. Write core operator documentation covering architecture, configuration, and setup guides

**Status:** pending  
**Dependencies:** None  

Create docs/operations/sigma-feeds.md with sections 1-7: Feed System Architecture (components, data flow, feed types), Feed Configuration (Git/Filesystem types, all configuration options with glob syntax, tag filters, cron schedules), Setting Up SigmaHQ Feed (step-by-step with recommended config), Setting Up Custom Organization Feeds (private repos, SSH keys, file structure), Configuring Sync Schedules (cron syntax, best practices, examples), Monitoring Feed Health (dashboard widgets, status meanings, metrics), and Troubleshooting (common issues, debug logging, connectivity testing)

**Details:**

Create docs/operations/sigma-feeds.md as comprehensive operator guide. Section 1 (Architecture): Document feed manager, handlers, scheduler, storage layer with data flow diagram showing Git/Filesystem sources -> Parser -> Storage -> Rule Engine. Section 2 (Configuration): Detail Git repo options (URL, branch, auth), Filesystem options (path, watch mode), glob patterns for include/exclude, MITRE tag filtering, severity levels, priority settings, update strategies (manual/startup/scheduled), cron syntax reference. Section 3 (SigmaHQ Setup): Provide step-by-step guide with URL https://github.com/SigmaHQ/sigma.git, branch master, path rules, min severity medium, auto-enable true, note expected 5-10 min initial sync. Section 4 (Custom Feeds): Cover private Git setup with SSH keys, required SIGMA YAML structure, validation requirements. Section 5 (Schedules): Explain cron expressions with examples (daily 0 2 * * *, weekly 0 2 * * 0), staggering strategy. Section 6 (Monitoring): Document dashboard widgets, status badges (active/disabled/error/syncing), sync history interpretation, key metrics (success rate, duration, failed rules). Section 7 (Troubleshooting): List common errors (auth failures, timeouts, disk space, parsing errors, conflicts), debug logging config, manual sync commands, connectivity tests, database queries for inspection

### 161.2. Add advanced sections covering performance, security, and backup/restore

**Status:** pending  
**Dependencies:** 161.1  

Complete docs/operations/sigma-feeds.md by adding sections 8-10: Performance Tuning (large repo optimization with shallow clone, working directory cleanup strategies, concurrent sync limits, rate limiting), Security Considerations (private repo authentication methods, credential storage best practices using environment variables, RBAC permissions for feed management operations, audit logging), and Backup and Restore (exporting feed configs, CLI commands for export/import, version control practices). Then create docs/SIGMA_FEEDS_QUICKSTART.md with quick reference for common tasks, 5-minute setup guide, CLI command cheat sheet, and troubleshooting checklist

**Details:**

Section 8 (Performance): Document shallow clone flag --depth=1 for large repos, scheduled cleanup of .git directories in working copies, max concurrent sync setting (recommend 3-5), rate limiting for API-based feeds. Section 9 (Security): Detail SSH key generation and deployment for private repos, environment variable storage for credentials (never in database), RBAC permission 'feeds:manage' requirement, audit log entries for create/update/delete/sync operations with user tracking. Section 10 (Backup/Restore): Document 'cerberus feeds export --output=feeds.json' command, import command 'cerberus feeds import --file=feeds.json', recommend version controlling feed configs in ops repo. Create SIGMA_FEEDS_QUICKSTART.md with: Quick Setup (3 steps to add SigmaHQ feed with curl/UI), Common Tasks table (sync feed, view status, add custom feed, troubleshoot errors), CLI Cheat Sheet (all cerberus feeds commands with examples), Troubleshooting Checklist (5 most common issues with one-line fixes)

### 161.3. Update README.md with SIGMA feeds section and conduct documentation review

**Status:** pending  
**Dependencies:** 161.1, 161.2  

Update main README.md to add SIGMA Feeds section under features list with overview, benefits, and links to detailed documentation. Include quick start example showing how to add SigmaHQ feed. Verify all code examples in both documentation files execute successfully. Conduct peer review with DevOps team and technical writer to validate clarity, accuracy, and completeness of operator documentation

**Details:**

Update README.md: Add new section 'SIGMA Rule Feeds' after existing features, include bullet points (automated SIGMA rule ingestion from Git repos, built-in SigmaHQ feed support, custom organization feed support, scheduled sync with cron, feed health monitoring). Add quick start code block showing API call or CLI command to add SigmaHQ feed with minimal config. Link to docs/operations/sigma-feeds.md for full guide and docs/SIGMA_FEEDS_QUICKSTART.md for quick reference. Verification: Test all curl examples in docs, execute all CLI commands, verify cron expressions, check Git URLs are valid, confirm dashboard screenshots match current UI. Peer Review: Submit docs to DevOps team member for operator perspective, submit to technical writer for clarity/formatting review, create checklist covering: terminology consistency, command accuracy, example validity, troubleshooting completeness, navigation/links work, formatting consistency
