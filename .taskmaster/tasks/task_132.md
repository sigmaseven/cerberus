# Task ID: 132

**Title:** Create comprehensive test suite with 1000+ SIGMA rule tests

**Status:** done

**Dependencies:** 129 ✓

**Priority:** high

**Description:** Build extensive test coverage including 100+ real-world SIGMA rules, all modifiers, complex conditions, edge cases, security tests, and performance benchmarks

**Details:**

1. Create test data directory structure:
   - detect/testdata/sigma_rules/basic/ (50 simple rules)
   - detect/testdata/sigma_rules/complex/ (50 multi-block rules)
   - detect/testdata/sigma_rules/edge_cases/ (100 edge cases)
   - detect/testdata/sigma_rules/real_world/ (200+ from SigmaHQ)
   - detect/testdata/events/ (sample events: Windows, Linux, DNS, AWS, etc.)

2. Create detect/sigma_comprehensive_test.go:
   - TestSigmaEngine_AllRealWorldRules: Load all YAML files, evaluate against sample events
   - TestSigmaEngine_AllModifiers: Test each modifier individually
   - TestSigmaEngine_ComplexConditions: Nested expressions, parentheses, aggregations
   - TestSigmaEngine_EdgeCases: Empty values, null fields, type mismatches
   - TestSigmaEngine_SecurityTests: YAML bombs, ReDoS, large payloads
   - TestSigmaEngine_ConcurrentEvaluation: Thread-safety, race conditions

3. Benchmark tests (detect/sigma_benchmark_test.go):
   - BenchmarkSigmaEngine_SimpleRule (target: <5ms p95)
   - BenchmarkSigmaEngine_ComplexRule
   - BenchmarkSigmaEngine_RegexHeavy
   - BenchmarkSigmaEngine_CacheHit vs CacheMiss
   - BenchmarkSigmaEngine_HighLoad (1000 rules, 10k events/sec)

4. Modifier-specific tests (detect/sigma_modifiers_test.go):
   - 300+ tests covering all modifiers
   - Combination tests (base64 + contains, utf16 + regex)
   - Transform order validation
   - Error cases (invalid input)

5. Parser tests (detect/sigma_condition_parser_test.go):
   - 200+ tests for AST parser
   - Complex expressions from real SIGMA rules
   - Error cases (syntax errors, undefined identifiers)
   - Operator precedence validation

6. Field mapper tests (detect/sigma_field_mapper_test.go):
   - 100+ tests for mapping logic
   - All logsource types (windows_sysmon, dns, etc.)
   - Fallback chain validation
   - Missing field handling

7. Performance baseline measurement (detect/baseline_benchmark_test.go):
   - Measure current engine performance BEFORE migration
   - Compare native SIGMA vs legacy after implementation
   - Track regression: Latency, throughput, memory

See Phase 4 in PRD for complete testing strategy.

**Test Strategy:**

Test coverage targets:
- Line coverage: >90% for all SIGMA engine code
- Real-world rules: 100% pass rate on valid rules
- Security tests: 100% pass (no DoS vulnerabilities)
- Performance: <5ms p95 latency, >100 rules/sec import

Test execution:
1. Unit tests: go test ./detect/...
2. Integration tests: go test -tags=integration ./detect/...
3. Benchmarks: go test -bench=. ./detect/...
4. Race detector: go test -race ./detect/...
5. Coverage: go test -coverprofile=coverage.out ./detect/...

CI/CD integration:
- Run on every PR
- Block merge if coverage <90%
- Block merge if performance regresses >10%
- Nightly tests with full SIGMA rule corpus (1000+)

Test data sources:
- SigmaHQ official rules repository
- Windows Event Log samples
- Sysmon event samples
- Cloud provider audit logs (AWS, Azure, GCP)
- Network traffic samples (DNS, firewall)

## Subtasks

### 132.1. Create test data directory structure with sample SIGMA rules

**Status:** pending  
**Dependencies:** None  

Set up detect/testdata/ directory structure with subdirectories for basic (50 simple rules), complex (50 multi-block rules), edge_cases (100 edge cases), real_world (200+ rules from SigmaHQ), and events (sample events for Windows Sysmon, Linux, DNS, AWS CloudTrail, etc.)

**Details:**

Create directory structure: detect/testdata/sigma_rules/{basic,complex,edge_cases,real_world}/ and detect/testdata/events/. Populate basic/ with 50 simple SIGMA rules (single selection, basic modifiers). Add 50 complex rules to complex/ (multi-block conditions, nested logic). Create 100 edge case rules in edge_cases/ (empty values, null fields, type mismatches, malformed YAML). Download/curate 200+ real-world rules from SigmaHQ repository to real_world/. Create sample event JSON files in events/ directory covering Windows Sysmon (process creation, network, file events), Linux auditd, DNS queries, AWS CloudTrail, web proxy logs. Ensure events match rule expectations for positive/negative test cases.

### 132.2. Create detect/sigma_comprehensive_test.go with core engine tests

**Status:** pending  
**Dependencies:** 132.1  

Implement comprehensive test file with TestSigmaEngine_AllRealWorldRules (loads all YAML files, evaluates against sample events), TestSigmaEngine_AllModifiers (tests each modifier individually), TestSigmaEngine_ComplexConditions (nested expressions, parentheses, aggregations), TestSigmaEngine_EdgeCases, TestSigmaEngine_SecurityTests (YAML bombs, ReDoS), and TestSigmaEngine_ConcurrentEvaluation with race detector

**Details:**

Create detect/sigma_comprehensive_test.go with: 1) TestSigmaEngine_AllRealWorldRules - iterate through detect/testdata/sigma_rules/real_world/, load each YAML, parse to native SIGMA format, evaluate against corresponding events from testdata/events/, assert expected matches/non-matches. 2) TestSigmaEngine_AllModifiers - test contains, startswith, endswith, all, re, base64, utf16, wide, base64offset individually with positive/negative cases. 3) TestSigmaEngine_ComplexConditions - test nested AND/OR/NOT, parentheses grouping, 1/all of patterns, aggregation conditions. 4) TestSigmaEngine_EdgeCases - empty field values, null fields, type mismatches (string vs int), missing fields, malformed events. 5) TestSigmaEngine_SecurityTests - YAML bombs (deeply nested structures), ReDoS patterns (catastrophic backtracking), large payloads (10MB+ events). 6) TestSigmaEngine_ConcurrentEvaluation - run with -race flag, test parallel rule evaluation, shared state access, goroutine safety. Target: 200+ test cases total.

### 132.3. Create detect/sigma_benchmark_test.go with performance benchmarks

**Status:** pending  
**Dependencies:** 132.1  

Implement benchmark tests for simple/complex/regex-heavy rules, cache hit vs miss comparison, and high load scenarios (1000 rules, 10k events/sec). Measure p50/p95/p99 latency, throughput, and memory usage

**Details:**

Create detect/sigma_benchmark_test.go with: 1) BenchmarkSigmaEngine_SimpleRule - basic single-condition rule, target <5ms p95 latency. 2) BenchmarkSigmaEngine_ComplexRule - multi-block rule with 5+ conditions, nested logic. 3) BenchmarkSigmaEngine_RegexHeavy - rules with multiple regex patterns, measure compilation and evaluation overhead. 4) BenchmarkSigmaEngine_CacheHit vs BenchmarkSigmaEngine_CacheMiss - compare cached parsed rule vs fresh parse. 5) BenchmarkSigmaEngine_HighLoad - load 1000 rules, simulate 10k events/sec throughput, measure p50/p95/p99 latency using b.ReportMetric(). 6) BenchmarkSigmaEngine_MemoryUsage - track allocations, heap usage with b.ReportAllocs(). Use benchstat-compatible output format. Include b.RunParallel() tests for concurrent load.

### 132.4. Create detect/sigma_modifiers_test.go with 300+ modifier tests

**Status:** pending  
**Dependencies:** 132.1  

Implement comprehensive modifier tests covering all SIGMA modifiers individually, in combination (base64+contains, utf16+regex), transform order validation, and error cases with invalid input

**Details:**

Create detect/sigma_modifiers_test.go with 300+ test cases: 1) Individual modifier tests - contains (case-sensitive substring, wildcards), startswith/endswith (prefix/suffix matching), all (all values in list match), re (regex patterns, capturing groups, anchors), base64 (standard/URL encoding), utf16le/utf16be (little/big endian), wide (null-byte insertion), base64offset (shifted encoding). 2) Combination tests - base64|contains (decode then substring), utf16|re (transcode then regex), all|startswith (all values start with pattern), re|base64 (regex on encoded data). 3) Transform order validation - ensure modifiers apply left-to-right, test order sensitivity (base64|contains ≠ contains|base64). 4) Error cases - invalid regex syntax, malformed base64, unsupported encoding, null inputs, type mismatches. Use table-driven tests for parameterization. Include positive and negative assertions for each modifier.

### 132.5. Create detect/sigma_condition_parser_test.go with 200+ AST parser tests

**Status:** pending  
**Dependencies:** 132.1  

Implement comprehensive condition parser tests covering complex expressions from real SIGMA rules, error cases (syntax errors, undefined identifiers), and operator precedence validation

**Details:**

Create detect/sigma_condition_parser_test.go with 200+ test cases: 1) Basic expression parsing - simple AND/OR/NOT conditions, single identifiers, parentheses grouping. 2) Complex expressions from real rules - multi-level nesting '(A AND B) OR (C AND (D OR E))', 1 of patterns '1 of selection_*', all of patterns 'all of them', mixed quantifiers '1 of selection_* and all of filter_*'. 3) Operator precedence tests - NOT > AND > OR, verify '(A OR B AND C)' parses as '(A OR (B AND C))', test parentheses override. 4) AST structure validation - verify parse tree correctness, node types (BinaryOp, UnaryOp, Identifier), child relationships. 5) Error cases - syntax errors (unmatched parentheses, invalid operators), undefined identifiers (reference to non-existent selection), empty conditions, malformed quantifiers '2 of' without pattern. Use table-driven tests with expected AST structures. Test parser error messages for clarity.

### 132.6. Create detect/sigma_field_mapper_test.go with 100+ mapping tests

**Status:** pending  
**Dependencies:** 132.1  

Implement field mapper tests covering mapping logic for all logsource types (windows_sysmon, dns, aws_cloudtrail, etc.), fallback chain validation (logsource-specific → generic → FieldAliases → unmapped), and missing field handling

**Details:**

Create detect/sigma_field_mapper_test.go with 100+ test cases: 1) Logsource-specific mapping tests - windows_sysmon maps EventID→event_id, Image→process.executable; dns maps query→dns.question.name; aws_cloudtrail maps eventName→aws.cloudtrail.event_name. Test all logsource types defined in config/sigma_field_mappings.yaml. 2) Fallback chain tests - field not in logsource-specific mapping falls back to generic, generic not found falls back to core.FieldAliases, FieldAliases not found returns original field name. Verify 3-tier fallback works correctly. 3) Logsource key generation tests - product='windows' + service='sysmon' → 'windows_sysmon', product='aws' + service='cloudtrail' → 'aws_cloudtrail', product only → use product as key. 4) Missing field handling - unmapped fields pass through unchanged, nil logsource uses generic mapping only. 5) Edge cases - empty logsource, case sensitivity, special characters in field names. Use table-driven tests with mock mappings.

### 132.7. Create detect/baseline_benchmark_test.go for pre-migration performance baseline

**Status:** pending  
**Dependencies:** 132.2, 132.3  

Implement baseline benchmark tests to measure current engine performance before SIGMA migration, enabling regression comparison between native SIGMA and legacy engine. Track latency, throughput, and memory usage

**Details:**

Create detect/baseline_benchmark_test.go with: 1) BenchmarkLegacyEngine_SimpleRule - measure current engine performance on simple rule (pre-SIGMA), record p50/p95/p99 latency, throughput (events/sec), memory allocations. 2) BenchmarkLegacyEngine_ComplexRule - current engine with complex multi-condition rule. 3) BenchmarkLegacyEngine_HighLoad - current engine under 1000 rules, 10k events/sec load. 4) Comparison framework - save baseline results to JSON file (detect/testdata/baseline_metrics.json), include metadata (Go version, CPU, commit hash). 5) Regression detection - after SIGMA migration, run BenchmarkSigmaEngine_* vs baseline, calculate delta (%), flag regressions >20% latency increase or >50% memory increase. Use benchstat for statistical comparison. Document acceptable regression thresholds in comments. Generate comparison report showing native SIGMA vs legacy side-by-side.
