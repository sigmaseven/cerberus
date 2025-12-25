# Task ID: 172

**Title:** Implement CQL to SIGMA Conversion Tool

**Status:** done

**Dependencies:** 165 ✓

**Priority:** medium

**Description:** Build automated converter for migrating CQL rules to SIGMA format with dry-run and validation capabilities

**Details:**

Implementation: Create tools/cql_to_sigma_converter.go:

1. CQL Parser:
   - Tokenize CQL query
   - Parse SELECT, WHERE, JOIN clauses
   - Extract field names, operators, values

2. SIGMA Generator:
   func ConvertCQLToSigma(cqlRule *core.Rule) (*core.Rule, error) {
       // Parse CQL query
       // Map operators: = -> equals, LIKE -> contains, > -> gt
       // Build SIGMA detection block
       // Generate logsource from source tables
       // Convert correlation to SIGMA correlation block
       // Return new Rule with Type="sigma", SigmaYAML populated
   }

3. Mapping rules:
   CQL WHERE field='value' -> detection: selection: field: value
   CQL WHERE field LIKE '%pattern%' -> field|contains: pattern
   CQL GROUP BY -> correlation.group_by
   CQL HAVING COUNT(*) > 5 -> correlation.type: event_count, condition: {operator: ">", value: 5}

4. POST /api/v1/rules/migrate-cql handler:
   - Accept rule_ids or "all"
   - dry_run mode for preview
   - preserve_original flag
   - Return conversion results and errors

5. Handle unconvertible CQL:
   - Complex subqueries -> manual conversion required
   - Custom functions -> log warning
   - Return partial conversion with TODO comments

**Test Strategy:**

Create tools/cql_to_sigma_converter_test.go:
1. Test simple CQL conversion (single WHERE)
2. Test complex CQL with multiple conditions
3. Test correlation CQL conversion
4. Test unconvertible CQL error handling
5. Test dry-run mode (no database changes)
6. Test preserve_original flag
7. Integration test: convert 100 sample CQL rules

## Subtasks

### 172.1. Build CQL Parser with Tokenizer and AST Builder

**Status:** pending  
**Dependencies:** None  

Implement CQL parser infrastructure including tokenizer, lexer, and AST builder for SELECT, WHERE, JOIN, GROUP BY, and HAVING clauses

**Details:**

Create tools/cql_parser.go with:
1. Tokenizer: Scan CQL query string and produce tokens (KEYWORD, IDENTIFIER, OPERATOR, STRING, NUMBER)
2. Lexer: Convert token stream into semantic units
3. AST Builder: Build abstract syntax tree with nodes for:
   - SELECT clause (fields, aggregations)
   - FROM clause (source tables)
   - WHERE clause (field conditions, operators, values)
   - JOIN clause (join type, conditions)
   - GROUP BY clause (grouping fields)
   - HAVING clause (aggregate conditions)
4. Error handling for malformed CQL syntax
5. Helper functions: ExtractFields(), ExtractConditions(), ExtractAggregations()

### 172.2. Implement SIGMA Generator with Operator Mapping

**Status:** pending  
**Dependencies:** 172.1  

Build SIGMA YAML generator that maps CQL operators to SIGMA detection blocks and modifiers

**Details:**

Create tools/sigma_generator.go with:
1. ConvertCQLToSigma(cqlRule *core.Rule) (*core.Rule, error) function
2. Operator mapping logic:
   - CQL '=' → SIGMA 'equals' or direct value
   - CQL 'LIKE %pattern%' → SIGMA 'field|contains: pattern'
   - CQL 'LIKE pattern%' → SIGMA 'field|startswith: pattern'
   - CQL 'LIKE %pattern' → SIGMA 'field|endswith: pattern'
   - CQL '>' → SIGMA 'field|gt: value'
   - CQL '<' → SIGMA 'field|lt: value'
   - CQL 'IN (...)' → SIGMA list values
3. Detection block builder: Convert WHERE conditions to selection/filter blocks
4. Logsource generator: Extract from FROM/JOIN tables
5. Field normalization: Map CQL field names to SIGMA field conventions

### 172.3. Create Correlation Conversion Logic

**Status:** pending  
**Dependencies:** 172.1, 172.2  

Implement conversion of CQL GROUP BY and HAVING clauses to SIGMA correlation blocks with type and condition mapping

**Details:**

Extend tools/sigma_generator.go with correlation logic:
1. GROUP BY mapping:
   - Extract grouping fields from CQL GROUP BY
   - Map to SIGMA correlation.group_by array
   - Preserve field ordering
2. HAVING clause conversion:
   - Parse aggregate functions: COUNT(*), SUM(), AVG(), MAX(), MIN()
   - Map to SIGMA correlation.type:
     - COUNT(*) → event_count
     - COUNT(DISTINCT field) → value_count with field specification
   - Convert operators to correlation.condition:
     - '>' → {operator: "gt", value: N}
     - '>=' → {operator: "gte", value: N}
     - '<' → {operator: "lt", value: N}
     - '=' → {operator: "eq", value: N}
3. Timespan extraction: Parse time windows from WHERE clauses and map to correlation.timespan
4. Correlation rule ID generation and referenced_rules population

### 172.4. Add POST /api/v1/rules/migrate-cql Handler

**Status:** pending  
**Dependencies:** 172.2, 172.3  

Implement REST API endpoint for CQL to SIGMA migration with dry-run mode and preserve_original flag support

**Details:**

Create api/cql_migration_handlers.go:
1. Request structure:
   type MigrateCQLRequest struct {
       RuleIDs          []string `json:"rule_ids"` // or "all"
       DryRun           bool     `json:"dry_run"`
       PreserveOriginal bool     `json:"preserve_original"`
   }
2. Response structure:
   type MigrationResult struct {
       RuleID           string   `json:"rule_id"`
       OriginalName     string   `json:"original_name"`
       Success          bool     `json:"success"`
       ConvertedRule    *core.Rule `json:"converted_rule,omitempty"`
       Errors           []string `json:"errors,omitempty"`
       Warnings         []string `json:"warnings,omitempty"`
   }
3. Handler logic:
   - Fetch CQL rules from storage
   - Call ConvertCQLToSigma for each rule
   - If dry_run: return preview without saving
   - If preserve_original: keep CQL rule, create new SIGMA rule
   - If not preserve_original: update rule in place
   - Collect errors and warnings per rule
4. Transaction handling for batch operations
5. RBAC check: require rule:write permission

### 172.5. Implement Unconvertible Pattern Detection

**Status:** pending  
**Dependencies:** 172.1, 172.2, 172.3  

Add detection and handling for CQL patterns that cannot be automatically converted to SIGMA with partial conversion and TODO comment generation

**Details:**

Extend tools/cql_to_sigma_converter.go:
1. Unconvertible pattern detection:
   - Complex subqueries (nested SELECT)
   - Custom functions not in standard SQL
   - Window functions (ROW_NUMBER, RANK, etc.)
   - CASE statements
   - Complex JOIN logic (3+ tables, outer joins with conditions)
   - CQL-specific extensions
2. Partial conversion strategy:
   - Convert what's possible
   - Add TODO comments in SIGMA YAML for manual review
   - Flag rule as "requires_manual_review"
3. Warning generation:
   - Log detailed warnings for each unconvertible element
   - Include original CQL snippet in warning
   - Suggest manual conversion approach
4. Metadata preservation:
   - Add "converted_from_cql": true to rule metadata
   - Store original CQL query in rule.metadata.original_cql
   - Add conversion_warnings array to metadata

### 172.6. Write Comprehensive Test Suite for All CQL Patterns

**Status:** pending  
**Dependencies:** 172.1, 172.2, 172.3, 172.4, 172.5  

Create extensive test coverage for all CQL conversion scenarios including edge cases, complex queries, and integration tests

**Details:**

Create tools/cql_to_sigma_converter_test.go:
1. Unit tests:
   - Simple WHERE conversions (20+ operator combinations)
   - Complex multi-condition WHERE clauses
   - All JOIN types (INNER, LEFT, RIGHT, FULL)
   - All aggregate functions
   - All correlation patterns
2. Integration tests:
   - Convert 100 sample CQL rules from test dataset
   - Validate generated SIGMA YAML syntax
   - Test round-trip: CQL → SIGMA → detect/sigma_engine.go parsing
   - Verify converted rules match events correctly
3. Edge cases:
   - Empty WHERE clause
   - NULL handling
   - Special characters in field names and values
   - Very long queries (1000+ characters)
   - Malformed CQL syntax
4. Performance tests:
   - Benchmark conversion speed (target: 100 rules/second)
   - Memory usage monitoring
5. Create test fixtures:
   - testdata/cql_samples/ with 100+ sample queries
   - testdata/expected_sigma/ with expected SIGMA outputs
6. Test dry-run and preserve_original in realistic scenarios
