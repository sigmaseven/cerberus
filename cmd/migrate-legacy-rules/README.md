# Legacy Rules Migration Tool

## Overview

This tool migrates legacy JSON condition-based rules to SIGMA YAML format in Cerberus. It provides a safe, atomic migration process with comprehensive error handling and rollback capabilities.

## Features

- **Atomic Migration**: All changes are made within a single database transaction
- **Dry-Run Mode**: Test migration without committing changes
- **Automatic Backups**: Creates database backup before migration
- **SIGMA Conversion**: Converts legacy conditions to SIGMA YAML format
- **OR Logic Support**: Handles both AND and OR logic in legacy conditions
- **Size Validation**: Prevents YAML bombs with 1MB size limit
- **Context Cancellation**: Graceful shutdown on interrupt signals
- **Comprehensive Testing**: >90% test coverage with unit and integration tests

## Installation

```bash
cd cmd/migrate-legacy-rules
go build -o migrate-legacy-rules
```

## Usage

### Command Line

```bash
# Basic usage
./migrate-legacy-rules --db-path=/path/to/cerberus.db

# With custom backup directory
./migrate-legacy-rules --db-path=/path/to/cerberus.db --backup-dir=/path/to/backups

# Dry-run mode (no changes committed)
./migrate-legacy-rules --db-path=/path/to/cerberus.db --dry-run
```

### Shell Script

The included `migrate.sh` script provides additional safety features:

```bash
# Basic usage
./migrate.sh /path/to/cerberus.db

# With custom backup directory
./migrate.sh /path/to/cerberus.db /path/to/backups
```

The shell script includes:
- Pre-migration validation
- Checksum verification
- SQLite integrity checks
- Atomic write guarantees
- Comprehensive error handling

## Migration Process

### What Gets Migrated

The tool migrates rules that:
- Have a non-empty `conditions` field
- Use the legacy JSON condition format
- Are not already in SIGMA format

### Migration Steps

1. **Validation**: Checks database path and permissions
2. **Backup**: Creates timestamped database backup (skipped in dry-run)
3. **Transaction Start**: Begins atomic database transaction
4. **Rule Retrieval**: Queries all legacy rules
5. **Conversion**: Converts each rule to SIGMA YAML format
6. **Update**: Updates database with SIGMA YAML and clears legacy conditions
7. **Commit/Rollback**: Commits changes (or rolls back in dry-run)
8. **Verification**: Verifies migration results

### SIGMA Conversion Details

The tool converts legacy conditions to SIGMA format:

**Operator Mappings:**
- `equals` → Direct field match
- `contains` → `field|contains`
- `starts_with` → `field|startswith`
- `ends_with` → `field|endswith`
- `regex` → `field|re`

**Logic Handling:**
- AND logic (default): All conditions in single selection block
- OR logic: Separate selection blocks combined with `or` condition

**Limitations:**
- Complex nested OR/AND logic is simplified
- Unsupported operators fall back to keyword matching
- Manual review recommended for complex rules

### Example Conversion

**Legacy Format:**
```json
{
  "id": "rule-123",
  "name": "Failed Login Attempt",
  "conditions": [
    {"field": "event_type", "operator": "equals", "value": "login"},
    {"field": "status", "operator": "equals", "value": "failure"}
  ]
}
```

**SIGMA Format:**
```yaml
title: Failed Login Attempt
id: rule-123
description: Detects failed login attempts
status: test
author: Cerberus Migration Tool
date: 2024/01/15
modified: 2024/01/15
logsource:
  category: application
  product: cerberus
detection:
  selection:
    event_type: login
    status: failure
  condition: selection
level: medium
```

## Exit Codes

- **0**: Success - no legacy rules found or all rules migrated
- **1**: Operational error - invalid arguments, database errors
- **2**: Validation error - invalid rules detected
- **3**: Migration error - failed to migrate one or more rules

## Safety Features

### Backup Creation

Backups are automatically created with timestamped filenames:
```
backups/cerberus-pre-migration-20240115-143022.db
```

Backups include:
- Full database snapshot
- Size verification
- Checksum validation (via shell script)

### Rollback Scenarios

The migration automatically rolls back in these cases:
- Context cancellation (Ctrl+C)
- Database query failures
- Transaction errors
- Panic recovery

### Security Considerations

- **Path Traversal Protection**: Validates and cleans all file paths
- **Symlink Resolution**: Resolves symlinks to prevent unintended writes
- **SQL Injection Prevention**: Uses prepared statements
- **YAML Bomb Protection**: Enforces 1MB size limit
- **Input Validation**: Validates all rule data before processing

## Error Handling

### Common Errors

**Database Not Found:**
```
Error: database file does not exist: /path/to/cerberus.db
```
**Solution**: Verify database path is correct

**Insufficient Permissions:**
```
Error: failed to create backup directory: permission denied
```
**Solution**: Ensure write permissions for backup directory

**Migration Failures:**
```
ERROR: Migration failed for 2 rules. See errors above.
[conversion] rule-123: rule ID cannot be empty
[database_update] rule-456: constraint violation
```
**Solution**: Review error details and fix invalid rules

### Failure Scenarios

**Scenario 1: Rule Conversion Failure**
- **Cause**: Invalid rule data (empty ID, name, or no conditions)
- **Behavior**: Rule is skipped, error logged, migration continues
- **Recovery**: Fix invalid rule data and re-run migration

**Scenario 2: Database Update Failure**
- **Cause**: Database constraint violations, disk space
- **Behavior**: Transaction rolled back, no changes committed
- **Recovery**: Fix database issues and retry

**Scenario 3: Transaction Commit Failure**
- **Cause**: Database lock, disk full, corruption
- **Behavior**: Automatic rollback attempted
- **Recovery**: Restore from backup, fix underlying issue

**Scenario 4: Context Cancellation**
- **Cause**: User interruption (Ctrl+C), timeout
- **Behavior**: Graceful rollback, partial changes discarded
- **Recovery**: Re-run migration when ready

**Scenario 5: Integrity Check Failure (Shell Script)**
- **Cause**: Database corruption after migration
- **Behavior**: Migration marked as failed
- **Recovery**: Restore from backup immediately

## Testing

### Run Unit Tests

```bash
go test -v -race -cover ./...
```

### Run Integration Tests

```bash
go test -v -run TestMigrateRulesIntegration
```

### Run Benchmarks

```bash
go test -bench=. -benchmem
```

### Test Coverage

Current test coverage: **>90%**

Covered areas:
- Flag parsing with custom FlagSet
- Database operations (queries, transactions)
- SIGMA YAML conversion (all operators, OR logic)
- Backup creation and verification
- Error handling (nil checks, invalid data)
- Context cancellation
- Migration integration (dry-run, commit)
- Rollback scenarios

## Monitoring and Verification

### Pre-Migration Checks

```bash
# Count legacy rules
sqlite3 cerberus.db "SELECT COUNT(*) FROM rules WHERE conditions IS NOT NULL AND TRIM(conditions) != '' AND conditions != '[]'"

# View sample legacy rule
sqlite3 cerberus.db "SELECT id, name, conditions FROM rules WHERE conditions IS NOT NULL LIMIT 1"
```

### Post-Migration Verification

```bash
# Count migrated rules
sqlite3 cerberus.db "SELECT COUNT(*) FROM rules WHERE type = 'sigma' AND sigma_yaml IS NOT NULL"

# Verify no legacy conditions remain
sqlite3 cerberus.db "SELECT COUNT(*) FROM rules WHERE type = 'sigma' AND conditions IS NOT NULL AND TRIM(conditions) != ''"

# View sample migrated rule
sqlite3 cerberus.db "SELECT id, name, sigma_yaml FROM rules WHERE type = 'sigma' LIMIT 1"

# Database integrity check
sqlite3 cerberus.db "PRAGMA integrity_check;"
```

## Performance

### Benchmarks

- **YAML Conversion**: ~50-100 µs per rule
- **Full Migration**: ~1-2 ms per rule (including database updates)
- **100 Rules**: ~200ms total
- **1000 Rules**: ~2s total

### Optimization Tips

- Run during low-traffic periods
- Use SSD storage for database
- Ensure adequate disk space (2x database size)
- Close other database connections during migration

## Troubleshooting

### Issue: Dry-run succeeds but actual migration fails

**Diagnosis:**
```bash
# Check disk space
df -h /path/to/database

# Check database locks
sqlite3 cerberus.db "PRAGMA locking_mode;"
```

**Solution**: Ensure adequate disk space and no competing database connections

### Issue: Migration is very slow

**Diagnosis:**
```bash
# Check database size
ls -lh cerberus.db

# Check rule count
sqlite3 cerberus.db "SELECT COUNT(*) FROM rules"
```

**Solution**: Consider running migration on a copy, then swap databases

### Issue: Backup creation fails

**Diagnosis:**
```bash
# Check backup directory permissions
ls -ld /path/to/backups

# Check disk space
df -h /path/to/backups
```

**Solution**: Ensure write permissions and adequate disk space

## Best Practices

1. **Always run dry-run first**: Verify migration before committing changes
2. **Use the shell script**: Provides additional safety checks
3. **Backup separately**: Create manual backup in addition to automatic backup
4. **Test on copy**: Test migration on database copy before production
5. **Monitor logs**: Review migration output for warnings or errors
6. **Verify results**: Use SQL queries to verify migration success
7. **Keep backups**: Retain backups until migration verified successful
8. **Review complex rules**: Manually review rules with OR logic after migration

## SQL Helper Queries

### Pre-Migration Analysis

```sql
-- Count rules by type
SELECT type, COUNT(*) FROM rules GROUP BY type;

-- Find rules with OR logic
SELECT id, name, conditions
FROM rules
WHERE conditions LIKE '%"logic"%"OR"%';

-- Identify large rules (potential issues)
SELECT id, name, LENGTH(conditions) as size
FROM rules
WHERE LENGTH(conditions) > 10000
ORDER BY size DESC;
```

### Post-Migration Verification

```sql
-- Verify all legacy rules migrated
SELECT
  (SELECT COUNT(*) FROM rules WHERE conditions IS NOT NULL AND TRIM(conditions) != '' AND conditions != '[]') as remaining_legacy,
  (SELECT COUNT(*) FROM rules WHERE type = 'sigma' AND sigma_yaml IS NOT NULL) as migrated_sigma;

-- Find rules with both conditions and sigma_yaml (should be 0)
SELECT id, name FROM rules WHERE conditions IS NOT NULL AND sigma_yaml IS NOT NULL;

-- Verify SIGMA YAML structure
SELECT id, name, SUBSTR(sigma_yaml, 1, 100) as yaml_preview
FROM rules
WHERE type = 'sigma'
LIMIT 5;
```

## Support

For issues or questions:
1. Review this documentation
2. Check test files for examples
3. Examine log files for error details
4. Run with `--dry-run` to diagnose issues
5. Restore from backup if needed

## License

Copyright (c) 2024 Cerberus SIEM. All rights reserved.
