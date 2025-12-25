# Task ID: 166

**Title:** Implement SIGMA Correlation Parser Extension

**Status:** done

**Dependencies:** 165 ✓

**Priority:** high

**Description:** Extend detect/sigma_engine.go to parse and cache correlation blocks in SIGMA YAML rules

**Details:**

Implementation: Modify detect/sigma_engine.go getCachedRule():

1. After parsing SIGMA YAML, check for 'correlation' section:
if correlationRaw, ok := parsed["correlation"]; ok {
    var correlation core.SigmaCorrelation
    correlationBytes, _ := yaml.Marshal(correlationRaw)
    yaml.Unmarshal(correlationBytes, &correlation)
    cached.Correlation = &correlation
}

2. Add Correlation field to CachedSigmaRule in detect/sigma_cache.go:
type CachedSigmaRule struct {
    // ... existing fields ...
    Correlation *core.SigmaCorrelation
}

3. Validate correlation config matches rule_category in storage layer
4. Add correlation-aware cache invalidation
5. Update ParseSigmaYAML utility to handle correlation blocks

**Test Strategy:**

Create detect/sigma_correlation_parser_test.go:
1. Test parsing SIGMA rules with correlation blocks
2. Verify cache stores correlation config
3. Test detection+correlation hybrid rules
4. Test error handling for malformed correlation YAML
5. Test all 7 correlation type parsing
6. Benchmark correlation parsing overhead

## Subtasks

### 166.1. Modify detect/sigma_engine.go getCachedRule() to parse 'correlation' YAML blocks

**Status:** pending  
**Dependencies:** None  

Extend the getCachedRule() function in detect/sigma_engine.go to detect, parse, and extract correlation sections from SIGMA YAML rules into core.SigmaCorrelation structures

**Details:**

Implementation steps: 1) After parsing SIGMA YAML in getCachedRule(), check for 'correlation' section in parsed map. 2) If correlation block exists, marshal correlationRaw to YAML bytes and unmarshal into core.SigmaCorrelation struct. 3) Assign parsed correlation to cached.Correlation field. 4) Add error handling for malformed correlation YAML. 5) Ensure thread-safety with existing mutex patterns. 6) Validate correlation type field matches one of 7 supported types (event_count, value_count, temporal, sequence, etc.). 7) Log correlation parsing failures with context for debugging.

### 166.2. Extend CachedSigmaRule struct in detect/sigma_cache.go to include Correlation field

**Status:** pending  
**Dependencies:** 166.1  

Add Correlation field to CachedSigmaRule struct to store parsed correlation configuration alongside existing cached rule data

**Details:**

Implementation steps: 1) Open detect/sigma_cache.go and locate CachedSigmaRule struct definition. 2) Add new field: 'Correlation *core.SigmaCorrelation `json:"correlation,omitempty"`' after existing fields. 3) Update cache serialization/deserialization if needed. 4) Verify field is properly initialized to nil for rules without correlation. 5) Update any cache statistics or metrics to account for correlation field memory usage. 6) Ensure JSON tags support optional correlation field. 7) Document field purpose with inline comments.

### 166.3. Implement correlation-aware cache invalidation logic

**Status:** pending  
**Dependencies:** 166.2  

Add cache invalidation logic that detects when correlation configuration changes and invalidates affected cached rules to prevent stale correlation configs

**Details:**

Implementation steps: 1) In detect/sigma_cache.go, add CorrelationVersion or hash field to CachedSigmaRule for change detection. 2) Implement correlation comparison logic to detect config changes (type, timespan, group-by fields, conditions). 3) Extend existing cache invalidation mechanisms to check correlation field changes. 4) Add InvalidateByCorrelationChange(ruleID string) method. 5) Integrate with storage layer validation that checks correlation.rule_category matches SIGMA rule category. 6) Add metrics tracking correlation-triggered cache invalidations. 7) Ensure thread-safe invalidation with existing mutex patterns from TASK 144.4.

### 166.4. Add comprehensive parser tests for all 7 correlation types with error handling validation

**Status:** pending  
**Dependencies:** 166.1, 166.2, 166.3  

Create complete test suite validating parser handles all 7 SIGMA correlation types (event_count, value_count, temporal, temporal_ordered, sequence, process_creation, network) with robust error handling

**Details:**

Implementation steps: 1) Create detect/sigma_correlation_parser_comprehensive_test.go. 2) Write test fixtures for each correlation type with valid YAML examples. 3) Test event_count: verify count, timespan, group-by parsing. 4) Test value_count: verify distinct value counting logic. 5) Test temporal/temporal_ordered: verify time window and ordering. 6) Test sequence: verify ordered event sequence parsing. 7) Test process_creation and network: verify specialized field mappings. 8) Create negative tests for malformed YAML, invalid types, missing required fields, invalid timespan formats. 9) Test hybrid detection+correlation SIGMA rules. 10) Add benchmark tests for correlation parsing performance. 11) Verify error messages provide actionable debugging information.
