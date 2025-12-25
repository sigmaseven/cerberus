# Task ID: 130

**Title:** Update storage layer for SIGMA YAML CRUD operations

**Status:** done

**Dependencies:** 123 ✓, 125 ✓

**Priority:** medium

**Description:** Modify SQLite storage functions to handle sigma_yaml field, extract metadata from YAML, and maintain denormalized logsource columns for efficient filtering

**Details:**

Update storage/sqlite_rules.go:

1. CreateRule:
   - Validate rule with core.Rule.Validate() (mutual exclusion check)
   - For SIGMA rules: Extract metadata from sigma_yaml
     * Parse YAML to map[string]interface{}
     * Extract logsource.category, .product, .service
     * Extract tags, mitre_tactics, mitre_techniques, references, etc.
   - Insert with sigma_yaml, logsource_category, logsource_product, logsource_service
   - For CQL rules: Validate query syntax

2. UpdateRule:
   - Same validation and extraction as CreateRule
   - Update sigma_yaml and denormalized fields atomically
   - Invalidate cache entry (call engine.cache.Invalidate(ruleID))

3. GetRule/ListRules:
   - SELECT includes sigma_yaml, logsource_* columns
   - Populate Rule.SigmaYAML, Rule.Logsource*, etc.
   - For backward compatibility: Still populate Detection/Logsource if sigma_yaml empty

4. extractMetadataFromYAML helper:
   - Parse sigma_yaml into map
   - Extract standard SIGMA fields (title, level, tags, references, etc.)
   - Handle missing optional fields gracefully
   - Map level to severity (critical→Critical, high→High, etc.)

5. Logsource filtering optimization:
   - Use denormalized columns in WHERE clause
   - Index usage: idx_rules_logsource_category, etc.
   - Example: WHERE logsource_category = 'process_creation' AND type = 'sigma'

6. Backward compatibility:
   - Rules without sigma_yaml still work (use Detection field)
   - Migration is optional (gradual rollout)
   - Both formats coexist during transition

See Phase 1.1 and Phase 6 for schema and migration strategy.

**Test Strategy:**

1. CRUD tests:
   - Create SIGMA rule with sigma_yaml
   - Create CQL rule with query
   - Update SIGMA rule (metadata changes)
   - Get SIGMA rule (verify all fields)
   - List rules with logsource filter

2. Validation tests:
   - Create SIGMA rule with query field (should fail)
   - Create CQL rule with sigma_yaml field (should fail)
   - Invalid SIGMA YAML (validation error)
   - Missing required fields

3. Metadata extraction tests:
   - Extract all optional fields
   - Handle missing fields
   - Level to severity mapping
   - Logsource extraction

4. Filtering tests:
   - Filter by logsource_category
   - Filter by logsource_product
   - Combined filters
   - Index usage verification (EXPLAIN QUERY PLAN)

5. Backward compatibility:
   - Create legacy rule (no sigma_yaml)
   - Retrieve legacy rule
   - Mixed query (sigma_yaml and legacy rules)

6. Concurrency tests:
   - Concurrent creates/updates
   - Cache invalidation during updates

## Subtasks

### 130.1. Update CreateRule in storage/sqlite_rules.go with validation and YAML metadata extraction

**Status:** done  
**Dependencies:** None  

Add core.Rule.Validate() call for mutual exclusion check, implement extractMetadataFromYAML helper to parse sigma_yaml and extract logsource fields (category, product, service), tags, MITRE tactics/techniques, references, and insert with sigma_yaml + logsource_* denormalized columns

**Details:**

Modify CreateRule function to:
1. Call core.Rule.Validate() before insertion to enforce mutual exclusion (SIGMA rules have sigma_yaml, CQL rules have query)
2. For SIGMA rules: Call extractMetadataFromYAML helper to parse sigma_yaml and extract metadata
3. Extract logsource.category, logsource.product, logsource.service from parsed YAML
4. Extract tags, mitre_tactics, mitre_techniques, references from YAML
5. Update INSERT statement to include sigma_yaml, logsource_category, logsource_product, logsource_service columns
6. For CQL rules: Validate query syntax as before
7. Maintain existing behavior for rules without sigma_yaml (backward compatibility)

### 130.2. Update UpdateRule with validation, extraction, and cache invalidation

**Status:** done  
**Dependencies:** 130.1  

Apply same validation and metadata extraction as CreateRule, implement atomic update of sigma_yaml + denormalized fields, and call engine.cache.Invalidate(ruleID) for proper cache invalidation

**Details:**

Modify UpdateRule function to:
1. Call core.Rule.Validate() to enforce mutual exclusion constraints
2. For SIGMA rules: Call extractMetadataFromYAML to re-extract metadata from updated sigma_yaml
3. Update sigma_yaml, logsource_category, logsource_product, logsource_service atomically in single UPDATE statement
4. Update tags, mitre_tactics, mitre_techniques, references, severity from extracted metadata
5. Call engine.cache.Invalidate(ruleID) after successful update to invalidate cached rule
6. Handle transaction rollback on validation or extraction errors
7. Maintain backward compatibility for rules without sigma_yaml

### 130.3. Update GetRule and ListRules to populate sigma_yaml and denormalized fields

**Status:** done  
**Dependencies:** 130.1  

Add sigma_yaml + logsource_* columns to SELECT statements, populate Rule.SigmaYAML and Rule.Logsource* fields in returned Rule objects, maintain backward compatibility by populating Detection/Logsource fields when sigma_yaml is empty

**Details:**

Modify GetRule and ListRules functions to:
1. Update SELECT statements to include: sigma_yaml, logsource_category, logsource_product, logsource_service columns
2. Scan results into Rule struct, populating Rule.SigmaYAML and denormalized logsource fields
3. For backward compatibility: If sigma_yaml is empty, still populate Rule.Detection and Rule.Logsource from legacy columns
4. If sigma_yaml is present, populate both sigma_yaml field AND legacy Detection/Logsource fields for gradual migration
5. Handle NULL values gracefully for optional logsource fields (product, service can be NULL)
6. Ensure all existing tests pass without modification (backward compatibility requirement)

### 130.4. Implement extractMetadataFromYAML helper function

**Status:** done  
**Dependencies:** None  

Create helper function to parse sigma_yaml YAML string to map[string]interface{}, extract title/level/tags/references/logsource fields, map SIGMA level to severity enum (critical→Critical, high→High, etc.), and handle missing optional fields gracefully

**Details:**

Implement extractMetadataFromYAML(sigmaYAML string) helper:
1. Parse sigmaYAML string using gopkg.in/yaml.v3 into map[string]interface{}
2. Extract required fields: title, level from root level
3. Extract logsource fields: logsource.category (required), logsource.product (optional), logsource.service (optional)
4. Extract optional arrays: tags, references as []string
5. Extract MITRE fields: extract mitre_tactics, mitre_techniques from tags with 'attack.t' or 'attack.tactic' prefixes
6. Map SIGMA level string to core.Severity enum: 'critical'→Critical, 'high'→High, 'medium'→Medium, 'low'→Low, 'informational'→Info
7. Handle missing optional fields by returning empty strings/nil for product, service, empty arrays for tags/references
8. Return extracted metadata as struct with all fields for easy insertion
9. Return validation errors if required fields missing or malformed YAML

### 130.5. Add logsource filtering optimization to ListRules using denormalized indexes

**Status:** done  
**Dependencies:** 130.3  

Implement WHERE clause filtering in ListRules using logsource_category, logsource_product, logsource_service denormalized columns with proper index usage (idx_rules_logsource_category, etc.) for efficient SIGMA rule filtering

**Details:**

Enhance ListRules function with logsource filtering:
1. Add optional filter parameters: logsourceCategory, logsourceProduct, logsourceService to ListRules function signature
2. Build WHERE clause dynamically: WHERE logsource_category = ? AND logsource_product = ? AND logsource_service = ?
3. Use indexes: idx_rules_logsource_category, idx_rules_logsource_product, idx_rules_logsource_service for efficient lookup
4. Support partial filtering: allow filtering by category only, category+product, or all three fields
5. Add type filter: WHERE type = 'sigma' to leverage idx_rules_type index
6. Example query: WHERE logsource_category = 'process_creation' AND type = 'sigma' ORDER BY created_at DESC
7. Ensure NULL handling for optional fields (product, service)
8. Document performance characteristics (indexed lookups vs full table scans)
