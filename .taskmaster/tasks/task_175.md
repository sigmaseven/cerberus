# Task ID: 175

**Title:** Create data migration script and verify all rules are SIGMA format

**Status:** pending

**Dependencies:** None

**Priority:** high

**Description:** Implement SQL verification queries and optional migration utilities to ensure zero legacy JSON rules exist in production database before code removal begins

**Details:**

PHASE 0: PREREQUISITES - This is a BLOCKING task that MUST be completed first.

Implementation:
1. Create migration verification script in `scripts/verify-sigma-migration.sql`:
   ```sql
   -- Verify no legacy rules exist
   SELECT COUNT(*) as legacy_count FROM rules WHERE
       (type != 'sigma' OR type IS NULL)
       OR (sigma_yaml IS NULL OR sigma_yaml = '')
       OR (conditions IS NOT NULL AND conditions != '[]' AND conditions != '');
   
   -- Show any problematic rules
   SELECT id, name, type, 
          LENGTH(sigma_yaml) as yaml_length,
          LENGTH(conditions) as conditions_length
   FROM rules 
   WHERE (type != 'sigma' OR type IS NULL)
      OR (sigma_yaml IS NULL OR sigma_yaml = '')
      OR (conditions IS NOT NULL AND conditions != '[]' AND conditions != '');
   ```

2. Create Go migration utility in `cmd/migrate-legacy-rules/main.go`:
   - Read all rules with non-empty `conditions` field
   - Convert JSON conditions to basic SIGMA YAML format
   - Update rule type to 'sigma'
   - Clear conditions field
   - Provide dry-run mode

3. Create backup script `scripts/backup-before-migration.sh`:
   ```bash
   #!/bin/bash
   cp data/cerberus.db data/cerberus-backup-$(date +%Y%m%d-%H%M%S).db
   ```

4. Document rollback procedure in `docs/operations/legacy-rule-migration.md`

Success Criteria:
- Migration script exits with code 0 (zero legacy rules found)
- All rules have type='sigma'
- All rules have non-empty sigma_yaml field
- All rules have empty/null conditions field
- Database backup created and verified

**Test Strategy:**

1. Run verification query and assert COUNT = 0
2. Query random sample of 10 rules, verify sigma_yaml is populated
3. Verify conditions field is NULL or '[]' for all rules
4. Test migration script on copy of production DB with mock legacy rules
5. Verify rollback procedure by restoring backup and checking data integrity

## Subtasks

### 175.1. Create SQL verification queries with detailed reporting

**Status:** pending  
**Dependencies:** None  

Develop comprehensive SQL script to verify zero legacy JSON rules exist and provide detailed reporting on rule format status

**Details:**

Create scripts/verify-sigma-migration.sql with multiple verification queries:

1. Main verification query counting legacy rules with conditions:
   - Rules with type != 'sigma' or NULL
   - Rules with empty/null sigma_yaml
   - Rules with non-empty conditions field

2. Detailed problematic rules query showing:
   - Rule ID, name, type
   - Length of sigma_yaml and conditions fields
   - Created/updated timestamps

3. Summary statistics query:
   - Total rules count
   - Rules by type breakdown
   - Rules with populated sigma_yaml count
   - Rules with legacy conditions count

4. Add comments explaining each query and expected zero-count results

5. Include exit code logic (return 0 if legacy_count = 0, else return 1)

### 175.2. Build Go migration utility with dry-run mode and rollback support

**Status:** pending  
**Dependencies:** 175.1  

Implement Go command-line utility to migrate legacy JSON rules to SIGMA format with comprehensive safety features

**Details:**

Create cmd/migrate-legacy-rules/main.go with following features:

1. CLI flags:
   - --dry-run: Preview changes without applying
   - --db-path: Specify database path (default: data/cerberus.db)
   - --backup: Auto-create backup before migration
   - --verbose: Detailed logging

2. Migration logic:
   - Query all rules where conditions IS NOT NULL AND conditions != '[]'
   - For each legacy rule:
     * Parse JSON conditions field
     * Generate basic SIGMA YAML equivalent using template
     * Update type to 'sigma'
     * Populate sigma_yaml field
     * Clear conditions field to NULL
   - Use transactions for atomicity

3. Error handling:
   - Validate database connection
   - Check for parsing errors in conditions JSON
   - Rollback on any failure
   - Log all operations

4. Output detailed report of migrated rules

5. Call verification SQL after migration to confirm success

### 175.3. Implement backup script with verification

**Status:** pending  
**Dependencies:** None  

Create automated database backup script with integrity verification and retention management

**Details:**

Create scripts/backup-before-migration.sh with following features:

1. Backup creation:
   - Generate timestamped filename: cerberus-backup-YYYYMMDD-HHMMSS.db
   - Copy data/cerberus.db to backup location
   - Set appropriate file permissions (read-only for backup)

2. Integrity verification:
   - Run SQLite integrity_check on backup file
   - Verify file size > 0 and matches source approximately
   - Test backup is readable with sample query

3. Retention management:
   - Keep last 5 backups, delete older ones
   - Report disk space usage

4. Error handling:
   - Verify source database exists
   - Check sufficient disk space before backup
   - Exit with non-zero code on failure

5. Output summary:
   - Backup location and size
   - Verification status
   - Cleanup actions performed

6. Make script executable and cross-platform compatible (bash/sh)

### 175.4. Write comprehensive documentation and rollback procedures

**Status:** pending  
**Dependencies:** 175.1, 175.2, 175.3  

Create detailed operator documentation covering migration process, verification, and emergency rollback procedures

**Details:**

Create docs/operations/legacy-rule-migration.md with sections:

1. Overview:
   - Purpose of migration
   - Why legacy format is being removed
   - Timeline and prerequisites

2. Pre-Migration Checklist:
   - Backup procedures (reference backup script)
   - Verification steps (run SQL verification)
   - Maintenance window planning

3. Migration Procedure:
   - Step-by-step commands with examples
   - Expected output at each step
   - Progress monitoring
   - Dry-run testing instructions

4. Verification:
   - Post-migration SQL queries
   - Smoke tests to run
   - Performance validation

5. Rollback Procedures:
   - When to rollback (decision criteria)
   - Step-by-step restoration from backup
   - Verification after rollback
   - Incident reporting

6. Troubleshooting:
   - Common errors and solutions
   - Manual conversion examples
   - Emergency contacts

7. Appendix:
   - Command reference
   - SQL queries reference
   - Example migration logs
