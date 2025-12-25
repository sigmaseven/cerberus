# Legacy Rule Migration Guide

## Overview

This document provides comprehensive instructions for migrating legacy JSON condition-based rules to SIGMA YAML format in Cerberus. The migration is required as part of the transition to a unified SIGMA-based rule engine.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Pre-Migration Steps](#pre-migration-steps)
3. [Migration Procedure](#migration-procedure)
4. [Verification](#verification)
5. [Rollback Procedure](#rollback-procedure)
6. [Troubleshooting](#troubleshooting)
7. [FAQ](#faq)

## Prerequisites

### System Requirements

- **Cerberus Version:** v1.8.0 or later
- **Database:** SQLite 3.x with WAL mode enabled
- **Disk Space:** Minimum 2x database size for backups
- **Permissions:** Read/write access to database and backup directories

### Before You Begin

1. **Schedule Maintenance Window**
   - Recommended: 30-60 minutes for databases with <10,000 rules
   - Extended: 2-4 hours for databases with >10,000 rules
   - Consider off-peak hours to minimize impact

2. **Communication**
   - Notify all stakeholders of the maintenance window
   - Prepare rollback plan and approval process
   - Designate a point of contact for issues

3. **Environment Preparation**
   - Ensure sufficient disk space for backups
   - Verify backup script permissions: `chmod +x scripts/backup-before-migration.sh`
   - Test database connectivity
   - Review current rule count: `sqlite3 data/cerberus.db "SELECT COUNT(*) FROM rules;"`

## Pre-Migration Steps

### Step 1: Inventory Assessment

Run the pre-migration inventory script to assess the scope:

```bash
sqlite3 data/cerberus.db << EOF
SELECT
    COUNT(*) as total_rules,
    SUM(CASE WHEN conditions IS NOT NULL AND conditions != '[]' THEN 1 ELSE 0 END) as legacy_rules,
    SUM(CASE WHEN sigma_yaml IS NOT NULL AND sigma_yaml != '' THEN 1 ELSE 0 END) as sigma_rules
FROM rules;
EOF
```

**Expected Output:**
```
total_rules|legacy_rules|sigma_rules
150|45|105
```

If `legacy_rules` is 0, migration is not needed.

### Step 2: Create Database Backup

**CRITICAL:** Always create a verified backup before migration.

```bash
./scripts/backup-before-migration.sh \
    --db-path data/cerberus.db \
    --backup-dir backups \
    --verify
```

**Expected Output:**
```
[INFO] Cerberus Database Backup Utility
[INFO] =================================
[INFO] Database:   data/cerberus.db
[INFO] Backup dir: backups
[INFO] Database information:
[INFO]   Size: 256.45 MB
[INFO]   Rules: 150
[INFO] Creating backup...
[SUCCESS] Backup created successfully
[INFO] Verifying backup integrity...
[SUCCESS]   Size verification passed
[SUCCESS]   SQLite integrity check passed
[SUCCESS]   Rule count verification passed (150 rules)
[SUCCESS] Backup completed successfully
```

**Backup Location:**
The backup will be stored at: `backups/cerberus-pre-migration-YYYYMMDD-HHMMSS.db`

**IMPORTANT:** Record the backup file path for rollback procedures.

### Step 3: Stop Cerberus Service (Optional but Recommended)

To prevent concurrent modifications during migration:

```bash
# For systemd
sudo systemctl stop cerberus

# For Docker
docker-compose down

# Verify service is stopped
ps aux | grep cerberus
```

### Step 4: Dry Run Migration

Test the migration without committing changes:

```bash
cd cmd/migrate-legacy-rules
go run main.go \
    --db-path ../../data/cerberus.db \
    --dry-run \
    --backup-dir ../../backups
```

**Expected Output:**
```
Legacy Rules Migration Utility
Database: ../../data/cerberus.db
Dry Run:  true

Scanning for legacy rules...

========================================
MIGRATION SUMMARY
========================================
Total rules examined:     45
Rules migrated:           45
Rules skipped:            0
Rules failed:             0

========================================
DRY RUN - No changes committed
========================================

DRY RUN COMPLETE: Migration would succeed. Run without --dry-run to apply changes.
```

**Review the output carefully:**
- If `Rules failed` > 0, investigate errors before proceeding
- Review conversion logic for any edge cases
- Ensure `Total rules examined` matches your inventory

## Migration Procedure

### Step 1: Execute Migration

Run the migration tool to convert legacy rules to SIGMA format:

```bash
cd cmd/migrate-legacy-rules
go run main.go \
    --db-path ../../data/cerberus.db \
    --backup-dir ../../backups
```

**Expected Output:**
```
Legacy Rules Migration Utility
Database: ../../data/cerberus.db
Dry Run:  false

Creating backup in ../../backups...
Backup created: ../../backups/cerberus-pre-migration-20250116-143022.db
Scanning for legacy rules...

========================================
MIGRATION SUMMARY
========================================
Total rules examined:     45
Rules migrated:           45
Rules skipped:            0
Rules failed:             0

SUCCESS: All rules migrated to SIGMA format.
```

**Exit Codes:**
- `0`: Success (no legacy rules found or all migrated successfully)
- `1`: Operational error (database connection, permissions, etc.)
- `2`: Validation error (invalid rule data)
- `3`: Migration error (failed to convert one or more rules)

### Step 2: Verify Migration

Run the verification SQL script to confirm all rules are migrated:

```bash
sqlite3 data/cerberus.db < scripts/verify-sigma-migration.sql
```

**Expected Output:**
```
============================================================
1. RULE TYPE DISTRIBUTION
============================================================
type    count  percentage
sigma   150    100.0

============================================================
2. NON-SIGMA RULES (SHOULD BE EMPTY)
============================================================
(no results - expected)

============================================================
3. RULES WITH EMPTY SIGMA_YAML (SHOULD BE EMPTY)
============================================================
(no results - expected)

============================================================
4. RULES WITH LEGACY CONDITIONS (SHOULD BE EMPTY)
============================================================
(no results - expected)

============================================================
5. MIGRATION SUMMARY
============================================================
metric                        count
Total Rules                   150
SIGMA Rules                   150
Non-SIGMA Rules              0
Rules with sigma_yaml        150
Rules with empty sigma_yaml  0
Rules with legacy conditions 0
Rules with empty conditions  150

============================================================
7. VERIFICATION VERDICT
============================================================
verdict
PASS: All rules successfully migrated to SIGMA format
```

**Verification Checklist:**
- [ ] All rules have `type='sigma'`
- [ ] All rules have non-empty `sigma_yaml` field
- [ ] All rules have empty/null `conditions` field
- [ ] Verification verdict shows `PASS`

### Step 3: Restart Cerberus Service

```bash
# For systemd
sudo systemctl start cerberus
sudo systemctl status cerberus

# For Docker
docker-compose up -d

# Verify service health
curl http://localhost:8080/health
```

### Step 4: Post-Migration Testing

1. **Verify Rule Evaluation:**
   ```bash
   # Test a few migrated rules
   curl -X POST http://localhost:8080/api/rules/test \
       -H "Content-Type: application/json" \
       -d '{"rule_id": "your-rule-id", "event": {...}}'
   ```

2. **Monitor Logs:**
   ```bash
   tail -f logs/cerberus.log | grep -i "error\|warn"
   ```

3. **Check Alert Generation:**
   - Monitor alert dashboard for expected alerts
   - Verify alert rates are consistent with pre-migration levels

## Rollback Procedure

If migration fails or produces unexpected results, follow these steps to restore from backup:

### Emergency Rollback (Immediate)

```bash
# 1. Stop Cerberus service immediately
sudo systemctl stop cerberus

# 2. Restore from backup (use the backup file path from pre-migration)
cp backups/cerberus-pre-migration-YYYYMMDD-HHMMSS.db data/cerberus.db

# 3. Verify restored database integrity
sqlite3 data/cerberus.db "PRAGMA integrity_check;"
# Expected output: ok

# 4. Verify rule count matches pre-migration
sqlite3 data/cerberus.db "SELECT COUNT(*) FROM rules;"

# 5. Restart Cerberus service
sudo systemctl start cerberus
sudo systemctl status cerberus

# 6. Verify service health
curl http://localhost:8080/health
```

### Rollback Verification

After rollback, verify the system is in the pre-migration state:

```bash
# Check rule inventory
sqlite3 data/cerberus.db << EOF
SELECT
    COUNT(*) as total_rules,
    SUM(CASE WHEN conditions IS NOT NULL AND conditions != '[]' THEN 1 ELSE 0 END) as legacy_rules,
    SUM(CASE WHEN sigma_yaml IS NOT NULL AND sigma_yaml != '' THEN 1 ELSE 0 END) as sigma_rules
FROM rules;
EOF
```

**Expected:** Rule counts should match pre-migration inventory.

### Post-Rollback Actions

1. **Document the Issue:**
   - Capture error messages from migration logs
   - Note which rules failed to migrate
   - Record system state at time of failure

2. **Report to Development Team:**
   - Include migration logs
   - Provide database schema version
   - Share any custom rule configurations

3. **Plan Retry:**
   - Address identified issues
   - Test migration in staging environment
   - Schedule new maintenance window

## Troubleshooting

### Issue: Migration Tool Reports Failed Rules

**Symptoms:**
```
Rules failed:             3

========================================
MIGRATION ERRORS
========================================
[conversion] rule-123: rule must have at least one condition
[conversion] rule-456: failed to marshal SIGMA YAML: invalid character
[database_update] rule-789: constraint failed
```

**Resolution:**
1. Review the specific error messages for each failed rule
2. Manually inspect problematic rules:
   ```bash
   sqlite3 data/cerberus.db "SELECT * FROM rules WHERE id='rule-123';"
   ```
3. For data validation errors:
   - Fix invalid rule data manually
   - Re-run migration with `--dry-run` to verify
4. For conversion errors:
   - Check for special characters or malformed JSON in conditions
   - Contact development team if conversion logic needs adjustment

### Issue: Verification Shows Non-SIGMA Rules Exist

**Symptoms:**
```
2. NON-SIGMA RULES (SHOULD BE EMPTY)
id         type    name
cql-rule-1 cql     CQL Query Rule
```

**Resolution:**
This is expected. Only legacy condition-based rules are migrated. CQL rules are intentionally preserved:
- CQL rules use `query` field, not `conditions`
- CQL rules are a valid rule type alongside SIGMA
- No action needed unless the rule should have been migrated

### Issue: Backup Creation Fails

**Symptoms:**
```
[ERROR] Failed to write backup file: permission denied
```

**Resolution:**
1. Check backup directory permissions:
   ```bash
   ls -ld backups/
   chmod 755 backups/
   ```
2. Check disk space:
   ```bash
   df -h
   ```
3. Verify database file is not locked:
   ```bash
   lsof data/cerberus.db
   ```

### Issue: Service Won't Start After Migration

**Symptoms:**
- Service fails to start
- Logs show database schema errors
- Health endpoint returns 500

**Resolution:**
1. **Immediate:** Perform emergency rollback (see [Emergency Rollback](#emergency-rollback-immediate))
2. Check logs for specific error:
   ```bash
   journalctl -u cerberus -n 100
   ```
3. Verify database integrity:
   ```bash
   sqlite3 data/cerberus.db "PRAGMA integrity_check;"
   ```
4. If corruption detected, restore from backup

### Issue: Performance Degradation After Migration

**Symptoms:**
- Slow rule evaluation
- Increased memory usage
- High CPU utilization

**Resolution:**
1. Check SIGMA engine cache:
   ```bash
   curl http://localhost:8080/api/metrics | grep sigma_cache
   ```
2. Rebuild rule indexes:
   ```bash
   sqlite3 data/cerberus.db "REINDEX;"
   ```
3. Analyze SIGMA YAML size:
   ```bash
   sqlite3 data/cerberus.db "SELECT id, LENGTH(sigma_yaml) as yaml_size FROM rules ORDER BY yaml_size DESC LIMIT 10;"
   ```
4. Monitor for memory leaks:
   ```bash
   ps aux | grep cerberus
   ```

## FAQ

### Q: How long does migration take?

**A:** Migration duration depends on:
- Number of legacy rules
- Database size
- Disk I/O speed

**Typical times:**
- <100 rules: 1-2 minutes
- 100-1,000 rules: 5-10 minutes
- 1,000-10,000 rules: 15-30 minutes
- >10,000 rules: 30-60 minutes

### Q: Can I run migration on a live system?

**A:** Yes, but **not recommended**. Migration uses a single transaction, so concurrent rule modifications may cause:
- Lock contention
- Transaction rollback
- Data inconsistency

**Best practice:** Stop the service during migration.

### Q: What happens to custom rule fields?

**A:** All custom fields are preserved:
- `metadata`: Preserved as-is
- `tags`: Preserved as-is
- `mitre_*`: Preserved as-is
- `actions`: Preserved as-is
- Only `conditions` field is cleared and replaced with `sigma_yaml`

### Q: Can I migrate rules selectively?

**A:** The migration tool migrates ALL legacy rules in a single transaction. Selective migration is not supported. If you need to migrate specific rules:
1. Manually convert rules using SIGMA YAML editor in UI
2. Or modify the migration tool to filter by rule ID

### Q: What if I have CQL rules?

**A:** CQL rules are **not affected** by this migration:
- CQL rules use `query` field, not `conditions`
- They remain as `type='cql'`
- No conversion needed

### Q: Can I run migration multiple times?

**A:** Yes, the migration is **idempotent**:
- Already migrated rules are skipped
- Only rules with non-empty `conditions` field are processed
- Safe to re-run if interrupted

### Q: How do I verify a specific rule was migrated correctly?

**A:** Query the rule and inspect the SIGMA YAML:

```bash
sqlite3 data/cerberus.db << EOF
SELECT id, type, sigma_yaml
FROM rules
WHERE id = 'your-rule-id';
EOF
```

Compare the SIGMA YAML against the original conditions to ensure logical equivalence.

### Q: What if migration detects invalid rule data?

**A:** The migration tool fails fast by default:
- Transaction is rolled back
- Error details are logged
- No rules are modified

Fix the invalid rules and re-run migration.

## Additional Resources

- **SIGMA Specification:** https://github.com/SigmaHQ/sigma/wiki/Specification
- **Cerberus Rule Documentation:** `docs/SIGMA_ROLLOUT_GUIDE.md`
- **Migration Tool Source:** `cmd/migrate-legacy-rules/main.go`
- **Backup Script:** `scripts/backup-before-migration.sh`
- **Verification Script:** `scripts/verify-sigma-migration.sql`

## Support

For issues not covered in this guide:
1. Check Cerberus logs: `logs/cerberus.log`
2. Review GitHub issues: https://github.com/your-org/cerberus/issues
3. Contact the development team: devops@your-org.com

## Change Log

| Version | Date       | Changes                                    |
|---------|------------|--------------------------------------------|
| 1.0     | 2025-01-16 | Initial migration guide for Task #175      |
