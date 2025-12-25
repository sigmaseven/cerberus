# Task ID: 180

**Title:** Remove conditions field from storage layer and add database migration

**Status:** pending

**Dependencies:** 175, 179

**Priority:** high

**Description:** Remove conditions JSON serialization from SQLite storage, drop conditions column from database schema with migration script

**Details:**

PHASE 3: STORAGE LAYER REMOVAL - High risk, data layer changes

**CRITICAL: Ensure Task 175 (data migration) completed successfully before starting**

Files to modify:
1. `storage/sqlite_rules.go` (lines 868-872) - Remove conditions deserialization in scanRules()
2. `storage/sqlite_rules.go` (lines 516, 574) - Remove conditions from CreateRule()
3. `storage/sqlite_rules.go` (lines 657, 716) - Remove conditions from UpdateRule()
4. `storage/sqlite_correlation_rules.go` - Remove conditions handling

Database migration (`storage/migrations/migration_1_8_0.go`):
```go
package migrations

import (
    "database/sql"
    "fmt"
)

// Migration_1_8_0_RemoveLegacyConditions removes deprecated conditions columns
func Migration_1_8_0_RemoveLegacyConditions(tx *sql.Tx) error {
    // Step 1: Verify no legacy data exists
    var legacyCount int
    err := tx.QueryRow(`
        SELECT COUNT(*) FROM rules 
        WHERE conditions IS NOT NULL 
        AND conditions != '[]' 
        AND conditions != ''
    `).Scan(&legacyCount)
    
    if err != nil {
        return fmt.Errorf("failed to check legacy rules: %w", err)
    }
    
    if legacyCount > 0 {
        return fmt.Errorf("MIGRATION BLOCKED: %d rules still have legacy conditions field populated - run data migration first", legacyCount)
    }
    
    // Step 2: Drop deprecated columns
    migrations := []string{
        `ALTER TABLE rules DROP COLUMN conditions`,
        `ALTER TABLE rules DROP COLUMN detection`,  // Deprecated SIGMA field
        `ALTER TABLE rules DROP COLUMN logsource`,  // Deprecated SIGMA field
    }
    
    for _, migration := range migrations {
        if _, err := tx.Exec(migration); err != nil {
            return fmt.Errorf("migration failed: %w", err)
        }
    }
    
    // Step 3: Add constraint ensuring SIGMA rules have sigma_yaml
    _, err = tx.Exec(`
        CREATE TRIGGER enforce_sigma_yaml
        BEFORE INSERT ON rules
        WHEN NEW.type = 'sigma' AND (NEW.sigma_yaml IS NULL OR NEW.sigma_yaml = '')
        BEGIN
            SELECT RAISE(ABORT, 'SIGMA rules must have sigma_yaml field populated');
        END;
    `)
    
    return err
}
```

Storage layer changes:
- Remove all references to `conditions` in SQL queries
- Remove JSON marshaling/unmarshaling for conditions
- Update GetRules, GetAllRules, CreateRule, UpdateRule queries
- Keep sigma_yaml handling intact

**Test Strategy:**

1. **PRE-MIGRATION**: Backup database and verify Task 175 completed
2. Run migration on test database copy
3. Verify migration script blocks if legacy data exists (negative test)
4. Verify columns dropped: `PRAGMA table_info(rules)` should not list conditions/detection/logsource
5. Test CreateRule with SIGMA YAML - should succeed
6. Test CreateRule without sigma_yaml for SIGMA type - should fail (trigger)
7. Run `go test ./storage/... -v` - all tests must pass
8. Integration test: Create rule via API, verify it persists correctly
9. Verify GetAllRules returns rules without conditions field
10. Performance test: Measure query time before/after migration (should be faster)
