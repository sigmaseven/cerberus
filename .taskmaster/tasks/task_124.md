# Task ID: 124

**Title:** Implement safe SIGMA YAML migration script with validation

**Status:** done

**Dependencies:** 123 ✓

**Priority:** high

**Description:** Create production-safe migration tool to convert existing rules from JSON detection blocks to SIGMA YAML format with dry-run, validation-first approach, and rollback capability

**Details:**

Create storage/migrations_sigma_yaml.go:

1. MigrateToSigmaYAML function with config options:
   - DryRun bool (simulate without DB changes)
   - ValidateOnly bool (validate all rules, don't migrate)
   - ContinueOnError bool (skip invalid rules vs fail-fast)
   - BatchSize int (progress logging interval)

2. Three-phase execution:
   - Phase 1: Validate ALL rules BEFORE migration (validateAllRulesForMigration)
   - Phase 2: Load rules and convert to YAML (convertRuleToYAML)
   - Phase 3: Single-transaction update with rollback on error

3. Conversion logic (convertRuleToYAML):
   - Map core.Rule fields to SIGMA structure
   - Marshal detection/logsource from JSON to YAML
   - Validate generated YAML with ValidateSigmaYAML
   - Extract logsource fields for denormalized columns

4. RollbackSigmaYAMLMigration function:
   - Clear sigma_yaml and logsource columns
   - Preserve original detection_json/logsource_json

5. Tracking:
   - MigrationResult with stats (total, migrated, skipped, failed)
   - MigrationError list with rule ID and error details

See Phase 1.2 in PRD for complete implementation with error handling.

**Test Strategy:**

1. Unit tests:
   - convertRuleToYAML with valid/invalid rules
   - validateAllRulesForMigration with mixed valid/invalid rules
   - mapSeverityToLevel mapping correctness

2. Integration tests:
   - Dry-run mode (no DB changes)
   - ValidateOnly mode (only validation)
   - Full migration with rollback
   - ContinueOnError behavior
   - Transaction atomicity (partial failure rolls back)

3. Test with 100+ real SIGMA rules from detect/testdata/sigma_rules/

4. Performance test: Migrate 1000+ rules, measure throughput

## Subtasks

### 124.1. Create MigrateToSigmaYAML function with config struct

**Status:** pending  
**Dependencies:** None  

Implement the main migration function with configuration options including DryRun, ValidateOnly, ContinueOnError, and BatchSize fields to control migration behavior

**Details:**

Create storage/migrations_sigma_yaml.go file with MigrationConfig struct containing DryRun bool, ValidateOnly bool, ContinueOnError bool, and BatchSize int fields. Implement MigrateToSigmaYAML(db *sql.DB, config MigrationConfig) (*MigrationResult, error) function signature. Set up MigrationResult struct with fields: Total int, Migrated int, Skipped int, Failed int. Create MigrationError struct with RuleID string and Error string fields. Initialize logging with batch progress tracking based on BatchSize config.

### 124.2. Implement validateAllRulesForMigration pre-validation phase

**Status:** pending  
**Dependencies:** 124.1  

Create Phase 1 validation that checks all rules before any migration occurs to ensure fail-fast behavior and prevent partial migrations

**Details:**

Implement validateAllRulesForMigration(rules []core.Rule) error function that iterates through all rules and validates they can be converted to SIGMA YAML format. For each rule, attempt to parse detection_json and logsource_json fields. Check that required fields exist for SIGMA conversion (Name/Title, Severity/Level). Collect all validation errors and return aggregated error if any rule fails validation (unless ContinueOnError is true). If ValidateOnly mode is enabled, run validation and return results without proceeding to migration. Log validation progress every BatchSize rules.

### 124.3. Implement convertRuleToYAML function for SIGMA mapping

**Status:** pending  
**Dependencies:** 124.2  

Create conversion logic to map core.Rule fields to SIGMA YAML structure with proper field mapping, validation, and logsource extraction

**Details:**

Implement convertRuleToYAML(rule *core.Rule) (sigmaYAML string, logsourceCategory, logsourceProduct, logsourceService string, err error) function. Map core.Rule fields to SIGMA structure: Name->title, Description->description, Severity->level (using mapSeverityToLevel helper), Tags->tags array. Unmarshal detection_json to map and re-marshal to YAML format. Unmarshal logsource_json and extract category, product, service fields for denormalized columns. Use yaml.Marshal() to generate final SIGMA YAML string. Call core.ValidateSigmaYAML() on generated YAML to ensure validity. Implement mapSeverityToLevel(severity string) string helper to map critical->critical, high->high, medium->medium, low->low, info->informational.

### 124.4. Implement single-transaction update with rollback capability

**Status:** pending  
**Dependencies:** 124.3  

Create Phase 3 database update logic using SQL transaction to ensure atomic migration with automatic rollback on any error

**Details:**

Begin sql.Tx transaction using db.Begin(). For each validated rule, call convertRuleToYAML to generate SIGMA YAML and logsource fields. Execute UPDATE rules SET sigma_yaml=?, logsource_category=?, logsource_product=?, logsource_service=? WHERE id=? prepared statement. Track migration progress in MigrationResult counters. If any update fails and ContinueOnError is false, call tx.Rollback() and return error. If ContinueOnError is true, add error to MigrationError list and continue. After all updates, commit transaction with tx.Commit(). In DryRun mode, always call tx.Rollback() instead of Commit() to simulate migration without persisting changes. Log progress every BatchSize updates.

### 124.5. Create RollbackSigmaYAMLMigration function with result tracking

**Status:** pending  
**Dependencies:** 124.4  

Implement rollback functionality to revert SIGMA YAML migration by clearing sigma_yaml and logsource columns while preserving original JSON fields

**Details:**

Implement RollbackSigmaYAMLMigration(db *sql.DB) (*MigrationResult, error) function. Begin transaction with db.Begin(). Execute UPDATE rules SET sigma_yaml=NULL, logsource_category=NULL, logsource_product=NULL, logsource_service=NULL WHERE sigma_yaml IS NOT NULL to clear migrated columns. Count affected rows for MigrationResult.Total counter. Verify detection_json and logsource_json columns remain unchanged. Commit transaction if successful, rollback on error. Return MigrationResult with statistics. Add logging for rollback progress. Consider adding optional DryRun parameter to simulate rollback without changes.
