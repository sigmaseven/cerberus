# Task ID: 167

**Title:** Migrate Correlation Rules Data to Unified Rules Table

**Status:** done

**Dependencies:** 164 ✓

**Priority:** high

**Description:** Create data migration script to move all correlation_rules records to rules table with proper categorization and config transformation

**Details:**

Implementation: Create storage/migrations_correlation_unification.go:

1. Migration function:
   - SELECT all from correlation_rules
   - For each correlation rule:
     a. Create Rule with rule_category='correlation'
     b. Convert sequence field to correlation_config JSON
     c. Set lifecycle_status='stable' (existing rules are production)
     d. Preserve ID, name, description, severity, tags, actions
     e. INSERT into rules table
   - Verify count matches
   - Add verification flag: unification_migration_complete

2. Rollback function:
   - DELETE FROM rules WHERE rule_category='correlation' AND created_at >= migration_timestamp
   - Restore correlation_rules table

3. Use transaction for atomicity
4. Add dry-run mode for testing
5. Create backup before migration

**Test Strategy:**

Create storage/migrations_correlation_unification_test.go:
1. Test migration with sample correlation rules
2. Verify all fields mapped correctly
3. Test ID preservation (no duplicates)
4. Test rollback restores original state
5. Test migration idempotency (safe to re-run)
6. Test with empty correlation_rules table
7. Load test with 1000+ correlation rules

## Subtasks

### 167.1. Design data transformation logic for correlation_rules to rules migration

**Status:** pending  
**Dependencies:** None  

Design and document the complete data transformation logic to migrate correlation_rules records to the unified rules table with rule_category='correlation', including field mapping strategy and correlation_config JSON structure.

**Details:**

Create detailed design document for transformation logic:

1. Field mapping specification:
   - Direct mappings: id, name, description, severity, tags, actions, enabled, created_at, updated_at
   - New fields: rule_category='correlation', lifecycle_status='stable', rule_format='cerberus_correlation'
   - Transformation: sequence field → correlation_config JSON (preserve exact structure from sqlite_correlation_rules.go)

2. Define correlation_config JSON schema:
   - Map correlation.Sequence to correlation_config.sequence
   - Preserve type, timeWindow, groupBy, conditions arrays
   - Handle nested JSON serialization patterns

3. ID preservation strategy:
   - Document conflict resolution (correlation IDs vs existing rule IDs)
   - Define ID offset or namespace approach if needed

4. Edge case handling:
   - NULL/empty fields
   - Special characters in JSON
   - Large sequence arrays (1000+ conditions)
   - Malformed correlation data

5. Verification checkpoints:
   - Count validation
   - Data integrity checksums
   - Sample record validation

### 167.2. Implement migration function with transaction safety and verification

**Status:** pending  
**Dependencies:** 167.1  

Implement the core migration function in storage/migrations_correlation_unification.go with atomic transaction handling, progress tracking, and comprehensive verification steps.

**Details:**

Create storage/migrations_correlation_unification.go with MigrateCorrelationRulesToUnified() function:

1. Transaction setup:
   - Begin transaction with isolation level SERIALIZABLE
   - Set migration_timestamp for rollback tracking
   - Acquire exclusive lock on correlation_rules and rules tables

2. Migration implementation:
   - SELECT * FROM correlation_rules ORDER BY id
   - For each record:
     a. Transform to core.Rule with rule_category='correlation'
     b. Marshal sequence field to correlation_config JSON using json.Marshal
     c. Set lifecycle_status='stable', rule_format='cerberus_correlation'
     d. Preserve all original fields (id, name, description, severity, tags, actions, enabled, timestamps)
     e. INSERT into rules table with prepared statement
   - Handle batch processing for performance (100 records per batch)

3. Verification steps:
   - Count validation: SELECT COUNT(*) from both tables
   - Sample validation: Compare 10 random records field-by-field
   - JSON validation: Unmarshal correlation_config to verify structure
   - Foreign key validation: Verify all action IDs exist

4. Commit with verification flag:
   - INSERT INTO migrations (name, applied_at) VALUES ('correlation_unification', NOW())
   - Set unification_migration_complete flag
   - Log migration summary (records migrated, duration, errors)

5. Error handling:
   - Panic recovery with automatic rollback
   - Detailed error logging with record ID
   - Return structured error with failed record information

### 167.3. Create rollback function with timestamp-based restoration

**Status:** pending  
**Dependencies:** 167.2  

Implement a robust rollback function that can restore the original correlation_rules state by removing migrated records from the unified rules table based on migration timestamp and metadata.

**Details:**

Add RollbackCorrelationUnification() function to storage/migrations_correlation_unification.go:

1. Rollback logic:
   - Begin transaction with SERIALIZABLE isolation
   - Query migration timestamp: SELECT applied_at FROM migrations WHERE name='correlation_unification'
   - DELETE FROM rules WHERE rule_category='correlation' AND created_at >= migration_timestamp
   - Alternative: Use migration_id tracking if timestamps unreliable

2. Restoration verification:
   - Verify deleted count matches original migration count
   - Check correlation_rules table still intact (migration doesn't drop it)
   - Validate no orphaned foreign key references

3. Safety checks:
   - Prevent rollback if correlation_rules table was dropped
   - Check for manual edits to migrated rules (warn user)
   - Verify unification_migration_complete flag exists

4. Metadata cleanup:
   - DELETE FROM migrations WHERE name='correlation_unification'
   - Clear unification_migration_complete flag
   - Log rollback summary

5. Two-phase rollback:
   - Phase 1: Mark rules as deleted (soft delete)
   - Phase 2: Hard delete after verification window
   - Allow rollback cancellation between phases

6. Edge cases:
   - Partial migration rollback (if migration failed midway)
   - Concurrent rule modifications during rollback
   - Handle rules with active alerts/correlations

### 167.4. Add dry-run mode for testing without committing changes

**Status:** pending  
**Dependencies:** 167.2  

Implement a dry-run mode that simulates the entire migration process without committing changes, providing detailed reports of what would be migrated and potential issues.

**Details:**

Extend MigrateCorrelationRulesToUnified() with dryRun parameter:

1. Dry-run transaction handling:
   - Begin read-only transaction
   - Execute all SELECT queries
   - Perform all transformations in-memory
   - Simulate INSERTs without executing (validation only)
   - Automatic rollback at end

2. Report generation:
   - Total records to migrate
   - Estimated migration duration
   - List of potential ID conflicts
   - JSON transformation preview (first 5 records)
   - Estimated disk space requirements

3. Validation checks:
   - Check for NULL required fields
   - Validate JSON serialization for all records
   - Check for oversized correlation_config (>1MB)
   - Verify foreign key constraints
   - Check for duplicate IDs in target table

4. Issue detection:
   - Flag records that would fail migration
   - Categorize issues (critical/warning)
   - Suggest remediation steps
   - Estimate success rate percentage

5. Output formatting:
   - JSON report for programmatic access
   - Human-readable summary for CLI
   - Detailed CSV log of each record's transformation
   - Diff preview showing before/after for sample records

6. Performance estimation:
   - Benchmark transformation speed
   - Estimate production migration time
   - Recommend batch size based on record count

### 167.5. Write comprehensive tests including edge cases and performance validation

**Status:** pending  
**Dependencies:** 167.2, 167.3, 167.4  

Create a complete test suite covering normal operation, edge cases, performance benchmarks, and concurrent access scenarios for the correlation rules migration.

**Details:**

Create storage/migrations_correlation_unification_test.go with comprehensive test coverage:

1. Basic migration tests:
   - TestMigrationWithSampleRules: Migrate 10 diverse correlation rules, verify all fields
   - TestFieldMappingCorrectness: Assert each field maps to correct target column
   - TestIDPreservation: Verify original IDs maintained, no duplicates
   - TestRollbackRestoresOriginal: Migration → Rollback → Assert identical to pre-migration
   - TestMigrationIdempotency: Run migration twice, second run safely skips

2. Edge case tests:
   - TestEmptyCorrelationTable: Migration with 0 records completes successfully
   - TestLargeSequenceArray: Rule with 100+ sequence conditions
   - TestSpecialCharactersInJSON: Unicode, quotes, newlines in correlation config
   - TestNullOptionalFields: Handle NULL tags, actions gracefully
   - TestOversizedCorrelationConfig: 5MB+ correlation_config handling
   - TestMalformedSequenceJSON: Invalid JSON in sequence field recovery

3. Performance tests:
   - TestMigration1000PlusRules: Create 1500 correlation rules, migrate, verify <30s
   - BenchmarkTransformationSpeed: Benchmark single rule transformation
   - BenchmarkBatchInsertion: Test batch sizes (50, 100, 500)
   - TestMemoryUsage: Monitor memory during large migration (<500MB)

4. Concurrent access tests:
   - TestConcurrentMigrationPrevention: Two migrations blocked by lock
   - TestReadsDuringMigration: SELECT queries during migration behavior
   - TestCorrelationEngineActiveDuringMigration: Simulate active detection

5. Data integrity tests:
   - TestForeignKeyConstraints: Verify action IDs reference valid actions
   - TestJSONRoundTrip: correlation_config → unmarshal → matches original
   - TestCountVerification: Source count == target count enforced
   - TestNoDataLoss: Every field preserved bit-for-bit

6. Rollback edge cases:
   - TestPartialMigrationRollback: Migration fails at record 500/1000
   - TestRollbackWithModifiedRules: User edited migrated rule
   - TestRollbackTimestampEdgeCase: Rules created at exact migration_timestamp
