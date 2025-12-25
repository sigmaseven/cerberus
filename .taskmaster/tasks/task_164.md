# Task ID: 164

**Title:** Add Unified Rule Schema Columns to Rules Table

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Extend the rules table schema to support unified rule storage with correlation-specific fields, lifecycle states, and performance tracking

**Details:**

Implementation: Create migration 1.8.0 in storage/migrations_sqlite.go to add:
- rule_category TEXT NOT NULL DEFAULT 'detection' (values: 'detection', 'correlation')
- correlation_config TEXT (JSON blob for correlation-specific configuration)
- lifecycle_status TEXT NOT NULL DEFAULT 'active' (values: 'experimental', 'test', 'stable', 'deprecated', 'active')
- performance_stats TEXT (JSON: avg_eval_time_ms, match_count, false_positive_count)
- deprecated_at TIMESTAMP
- deprecated_reason TEXT

Create indexes:
- idx_rules_category on rule_category
- idx_rules_lifecycle_status on lifecycle_status
- idx_rules_deprecated_at on deprecated_at

Use existing migration infrastructure and helpers (addColumnIfNotExists, createIndexIfNotExists). Test with storage/migrations_integration_test.go pattern.

**Test Strategy:**

Create storage/migrations_unification_test.go:
1. Test migration applies cleanly on existing schema
2. Verify all columns and indexes created
3. Test default values applied correctly
4. Verify backward compatibility with existing rules
5. Test rollback capability
6. Verify foreign key constraints still enforced

## Subtasks

### 164.1. Create migration 1.8.0 with new unified rule schema columns

**Status:** pending  
**Dependencies:** None  

Implement the database migration in storage/migrations_sqlite.go to add six new columns to the rules table: rule_category (detection/correlation), correlation_config (JSON), lifecycle_status (experimental/test/stable/deprecated/active), performance_stats (JSON), deprecated_at (timestamp), and deprecated_reason (text)

**Details:**

Add migration function migrate_1_8_0() in storage/migrations_sqlite.go using existing helper functions. Add columns with addColumnIfNotExists: rule_category TEXT NOT NULL DEFAULT 'detection', correlation_config TEXT, lifecycle_status TEXT NOT NULL DEFAULT 'active', performance_stats TEXT, deprecated_at TIMESTAMP, deprecated_reason TEXT. Follow the pattern from migrate_1_7_0 for consistency. Ensure proper NULL/NOT NULL constraints and default values. Update the migration list in GetMigrations() to include version 1.8.0.

### 164.2. Create indexes for efficient querying of unified rule schema

**Status:** pending  
**Dependencies:** 164.1  

Add three database indexes to optimize queries on the new unified rule schema columns: idx_rules_category on rule_category, idx_rules_lifecycle_status on lifecycle_status, and idx_rules_deprecated_at on deprecated_at

**Details:**

In the same migrate_1_8_0() function, use createIndexIfNotExists helper to add three indexes: CREATE INDEX idx_rules_category ON rules(rule_category), CREATE INDEX idx_rules_lifecycle_status ON rules(lifecycle_status), CREATE INDEX idx_rules_deprecated_at ON rules(deprecated_at). These indexes will optimize filtering rules by category, lifecycle status, and finding deprecated rules. Follow existing index creation patterns from previous migrations.

### 164.3. Write comprehensive migration tests with rollback scenarios

**Status:** pending  
**Dependencies:** 164.1, 164.2  

Create storage/migrations_unification_test.go with comprehensive test coverage for migration 1.8.0 including clean migration, backward compatibility, default values, rollback capability, and foreign key integrity

**Details:**

Follow storage/migrations_integration_test.go pattern. Write tests: TestMigration_1_8_0_CleanApply (fresh database), TestMigration_1_8_0_ExistingData (verify existing rules get default values), TestMigration_1_8_0_ColumnTypes (verify TEXT/TIMESTAMP types), TestMigration_1_8_0_Indexes (verify all 3 indexes created), TestMigration_1_8_0_DefaultValues (verify 'detection' and 'active' defaults), TestMigration_1_8_0_BackwardCompatibility (existing queries still work), TestMigration_1_8_0_Rollback (if migration framework supports it). Use setupTestDB() helper and assert column existence with PRAGMA table_info queries.
