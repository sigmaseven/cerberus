# Task ID: 123

**Title:** Add sigma_yaml column to database schema and Rule struct

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Implement database migration to add sigma_yaml TEXT column to rules table and update core.Rule struct with SigmaYAML field, including denormalized logsource columns for filtering

**Details:**

1. Add migration 1.7.0 to storage/migrations_sqlite.go:
   - ALTER TABLE rules ADD COLUMN sigma_yaml TEXT
   - ALTER TABLE rules ADD COLUMN logsource_category TEXT
   - ALTER TABLE rules ADD COLUMN logsource_product TEXT  
   - ALTER TABLE rules ADD COLUMN logsource_service TEXT
   - CREATE INDEX idx_rules_logsource_category ON rules(logsource_category)
   - CREATE INDEX idx_rules_logsource_product ON rules(logsource_product)
   - CREATE INDEX idx_rules_logsource_service ON rules(logsource_service)

2. Update core/rule.go:
   - Add SigmaYAML string field with json/bson tags
   - Add LogsourceCategory, LogsourceProduct, LogsourceService string fields
   - Mark Detection and Logsource fields as DEPRECATED in comments

3. Implement Validate() method with mutual exclusion:
   - SIGMA rules MUST have sigma_yaml, cannot have query
   - CQL rules MUST have query, cannot have sigma_yaml
   - Correlation rules are NOT migrated (separate table)

4. Add ParsedSigmaRule() method to parse YAML on-demand

See Phase 1.1 in PRD for exact schema and Phase 2.1 for validation logic.

**Test Strategy:**

1. Unit tests for migration (create/rollback)
2. Unit tests for Rule.Validate() covering:
   - Valid SIGMA rule with sigma_yaml
   - Valid CQL rule with query
   - Invalid: SIGMA rule with query field
   - Invalid: CQL rule with sigma_yaml field
   - Invalid: correlation rule type
3. Integration test: Apply migration to test DB, verify columns exist
4. Test ParsedSigmaRule() with valid/invalid YAML

## Subtasks

### 123.1. Create migration 1.7.0 with ALTER TABLE statements and indexes

**Status:** done  
**Dependencies:** None  

Add migration 1.7.0 to storage/migrations_sqlite.go following existing migration patterns to add sigma_yaml and denormalized logsource columns with proper indexes

**Details:**

Add migration 1.7.0 in storage/migrations_sqlite.go following the existing pattern from migrations 1.0.0-1.6.0. Use helper functions addColumnIfNotExists and createIndexIfNotExists. Add columns: sigma_yaml TEXT, logsource_category TEXT, logsource_product TEXT, logsource_service TEXT. Create indexes: idx_rules_logsource_category, idx_rules_logsource_product, idx_rules_logsource_service. Ensure migration is idempotent and follows the established migration structure with version number, description, and rollback capability.

### 123.2. Update core.Rule struct with SigmaYAML and denormalized logsource fields

**Status:** done  
**Dependencies:** 123.1  

Modify core/rule.go to add SigmaYAML string field and LogsourceCategory, LogsourceProduct, LogsourceService fields with proper JSON/BSON tags, and mark Detection/Logsource as deprecated

**Details:**

Update core/rule.go struct definition. Add SigmaYAML string field with json:"sigma_yaml,omitempty" bson:"sigma_yaml,omitempty" tags. Add LogsourceCategory string with json:"logsource_category,omitempty" bson:"logsource_category,omitempty" tags. Add LogsourceProduct string with json:"logsource_product,omitempty" bson:"logsource_product,omitempty" tags. Add LogsourceService string with json:"logsource_service,omitempty" bson:"logsource_service,omitempty" tags. Add DEPRECATED comments above Detection and Logsource fields noting they are superseded by SigmaYAML for SIGMA rules.

### 123.3. Implement Validate() method with mutual exclusion logic

**Status:** done  
**Dependencies:** 123.2  

Add Validate() method to core.Rule that enforces mutual exclusion between SIGMA rules (must have sigma_yaml, cannot have query) and CQL rules (must have query, cannot have sigma_yaml)

**Details:**

Implement func (r *Rule) Validate() error in core/rule.go. Check rule Type field: For Type="SIGMA": return error if SigmaYAML is empty, return error if Query is not empty. For Type="CQL": return error if Query is empty, return error if SigmaYAML is not empty. For Type="CORRELATION": skip validation (correlation rules use separate table, not migrated). Return descriptive errors like "SIGMA rules must have sigma_yaml field and cannot have query field" or "CQL rules must have query field and cannot have sigma_yaml field".

### 123.4. Add ParsedSigmaRule() helper method for on-demand YAML parsing

**Status:** done  
**Dependencies:** 123.3  

Create ParsedSigmaRule() method that parses the SigmaYAML field on-demand using gopkg.in/yaml.v3 and returns a structured representation for detection engine use

**Details:**

Implement func (r *Rule) ParsedSigmaRule() (map[string]interface{}, error) in core/rule.go. Import gopkg.in/yaml.v3. Check if SigmaYAML is empty and return error if so. Use yaml.Unmarshal to parse r.SigmaYAML into map[string]interface{}. Return parsed structure and any YAML parsing errors. This provides on-demand parsing without storing parsed structure in memory, allowing detection engine to parse YAML when needed. Consider caching parsed result if performance becomes concern in future.
