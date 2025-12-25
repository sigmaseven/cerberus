# Task ID: 129

**Title:** Build complete native SIGMA detection engine with caching

**Status:** done

**Dependencies:** 126 ✓, 127 ✓, 128 ✓

**Priority:** high

**Description:** Integrate parser, modifiers, and field mapper into production-ready SIGMA engine with parsed rule caching, metrics, and structured logging

**Details:**

Create detect/sigma_engine.go and detect/sigma_cache.go:

1. SigmaRuleCache (sigma_cache.go):
   - LRU cache with sync.RWMutex for thread-safety
   - CachedSigmaRule stores: ParsedYAML, DetectionAST, timestamps, access count
   - Get/Put/Invalidate/InvalidateAll methods
   - Background cleanup goroutine with context cancellation
   - evictLRU when cache is full
   - GetStats for observability

2. SigmaEngine (sigma_engine.go):
   - fieldMapper *FieldMapper
   - modifierEvaluator *ModifierEvaluator
   - cache *SigmaRuleCache
   - logger *zap.SugaredLogger
   - regexTimeout time.Duration

3. Evaluate function:
   - Check cache first (cache hit → use cached AST)
   - Cache miss → parse YAML, build AST, cache result
   - Call evaluateDetection with parsed rule and AST
   - Record metrics (evaluation duration, cache hits/misses)
   - Log matches and errors

4. evaluateDetection:
   - Build evaluation context (block_name → bool)
   - For each detection block: evaluateDetectionBlock
   - Evaluate condition AST with context
   - Return match result

5. evaluateDetectionBlock:
   - All field conditions in block are AND-ed
   - For each field|modifiers: value pair
   - Call evaluateFieldCondition
   - Short-circuit on first non-match

6. evaluateFieldCondition:
   - Parse field expression (field|modifier1|modifier2)
   - Map SIGMA field to event field (FieldMapper)
   - Get event value
   - Apply modifiers and compare (ModifierEvaluator)

7. Metrics integration (metrics/sigma_metrics.go):
   - cerberus_sigma_rule_evaluations_total (counter by rule_id, result)
   - cerberus_sigma_rule_evaluation_duration_seconds (histogram)
   - cerberus_sigma_cache_hits_total (counter)
   - cerberus_sigma_cache_misses_total (counter)
   - cerberus_sigma_modifier_evaluations_total (counter by modifier)
   - cerberus_sigma_parse_errors_total (counter by error_type)

See Phase 3.5 and Phase 5 in PRD for complete engine and metrics.

**Test Strategy:**

1. Engine tests:
   - Evaluate simple SIGMA rule (single condition)
   - Evaluate complex rule (multiple blocks, conditions)
   - Cache hit/miss behavior
   - Cache eviction under load
   - Concurrent evaluation (thread-safety)

2. Integration tests:
   - 100+ real SIGMA rules from testdata/
   - Windows Sysmon events
   - DNS query events
   - Linux auditd events
   - All modifiers exercised
   - All condition operators (and, or, not, all of, 1 of)

3. Performance tests:
   - Benchmark: Simple rule evaluation (<5ms p95)
   - Benchmark: Complex rule with regex
   - Benchmark: Cache hit vs miss overhead
   - Load test: 1000 rules, 10,000 events/sec
   - Memory profiling: Cache size limits

4. Error handling tests:
   - Invalid YAML in cache
   - Missing detection fields
   - Undefined condition identifiers
   - Field mapping failures
   - Modifier errors

5. Metrics validation:
   - All metrics incremented correctly
   - Histogram buckets appropriate
   - Labels applied correctly

## Subtasks

### 129.1. Create SigmaRuleCache struct with LRU eviction and thread-safety

**Status:** done  
**Dependencies:** None  

Implement detect/sigma_cache.go with SigmaRuleCache struct using LRU eviction policy, sync.RWMutex for concurrent access, CachedSigmaRule struct for storing parsed YAML and detection AST, and methods for cache operations

**Details:**

Create sigma_cache.go with: 1) SigmaRuleCache struct with map[string]*CachedSigmaRule, sync.RWMutex, maxSize int, evictionList (linked list for LRU). 2) CachedSigmaRule struct with ParsedYAML (map[string]interface{}), DetectionAST (*ConditionNode), CreatedAt/LastAccessedAt time.Time, AccessCount int64. 3) Get(ruleID string) method with RLock for reading, update LastAccessedAt and AccessCount. 4) Put(ruleID, ParsedYAML, DetectionAST) method with Lock for writing, call evictLRU if at capacity. 5) evictLRU() internal method to remove least recently used entry. 6) Invalidate(ruleID) and InvalidateAll() methods. 7) GetStats() returning CacheStats struct (size, hits, misses, evictions). Use container/list for LRU tracking.

### 129.2. Add background cleanup goroutine with context cancellation to SigmaRuleCache

**Status:** done  
**Dependencies:** 129.1  

Implement cache cleanup mechanism that runs periodically in a background goroutine to remove stale entries and handle graceful shutdown via context

**Details:**

Extend SigmaRuleCache with: 1) ctx context.Context and cancel context.CancelFunc fields. 2) cleanupInterval time.Duration (default 5 minutes). 3) maxIdleTime time.Duration (default 30 minutes). 4) StartCleanup(ctx) method that launches goroutine with ticker. 5) Cleanup goroutine: every cleanupInterval, iterate cache entries with RLock, collect stale entries (LastAccessedAt older than maxIdleTime), then Lock and delete them. 6) Stop() method calling cancel() and waiting for goroutine to exit. 7) Handle context.Done() for graceful shutdown. Increment eviction counter in GetStats for tracking.

### 129.3. Create SigmaEngine struct integrating all SIGMA components

**Status:** done  
**Dependencies:** 129.1  

Implement detect/sigma_engine.go with SigmaEngine struct that integrates FieldMapper, ModifierEvaluator, SigmaRuleCache, logger, and configuration for the complete detection engine

**Details:**

Create sigma_engine.go with: 1) SigmaEngine struct containing fieldMapper *FieldMapper, modifierEvaluator *ModifierEvaluator, cache *SigmaRuleCache, logger *zap.SugaredLogger, regexTimeout time.Duration (default 1s). 2) NewSigmaEngine(fieldMapper, logger, options) constructor accepting functional options for cache size, regex timeout, cleanup interval. 3) EngineOptions struct for configuration. 4) WithCacheSize(int), WithRegexTimeout(duration), WithCleanupInterval(duration) option functions. 5) Initialize cache with specified size, start background cleanup. 6) Close() method to stop cache cleanup and release resources. Follow existing patterns from detect/engine.go for consistency.

### 129.4. Implement Evaluate function with cache lookup and YAML parsing

**Status:** done  
**Dependencies:** 129.3  

Implement the main SigmaEngine.Evaluate function that checks cache, parses YAML on cache miss, builds detection AST, caches the result, and delegates to evaluateDetection

**Details:**

In sigma_engine.go, implement: 1) Evaluate(ruleID string, yamlContent []byte, event map[string]interface{}) (bool, error) function. 2) Check cache first: cached := engine.cache.Get(ruleID). If cache hit, record metric, use cached.ParsedYAML and cached.DetectionAST. 3) On cache miss: parse YAML with gopkg.in/yaml.v3, extract detection section, call buildDetectionAST (from Task 126), cache result with engine.cache.Put(ruleID, parsedYAML, ast). Record cache miss metric. 4) Call evaluateDetection(parsedRule, ast, event) for actual matching. 5) Wrap in timing for metrics (evaluation duration histogram). 6) Log match results and errors with structured logging (rule_id, match, duration). 7) Handle errors at each stage with appropriate error wrapping. Return (matched bool, error).

### 129.5. Implement evaluateDetection and evaluateDetectionBlock functions

**Status:** done  
**Dependencies:** 129.4  

Implement core detection logic that builds evaluation context from detection blocks, evaluates the condition AST, and processes individual detection blocks with AND logic for field conditions

**Details:**

In sigma_engine.go: 1) evaluateDetection(parsedRule map[string]interface{}, conditionAST *ConditionNode, event map[string]interface{}) (bool, error). Extract detection section from parsedRule. 2) Build context map[string]bool for each named detection block (e.g., 'selection', 'filter'): call evaluateDetectionBlock(blockName, blockContent, event), store result in context[blockName]. 3) Evaluate conditionAST with context using recursive AST walker (handle AND, OR, NOT nodes, leaf nodes look up context[blockName]). 4) evaluateDetectionBlock(blockName string, blockContent map[string]interface{}, event) bool: iterate each field|modifiers: value pair, call evaluateFieldCondition(field, value, event), AND all results with short-circuit (return false immediately on first non-match). 5) Handle edge cases: empty blocks, missing fields, invalid types.

### 129.6. Implement evaluateFieldCondition with field mapping and modifier application

**Status:** done  
**Dependencies:** 129.5  

Implement field-level condition evaluation that parses field|modifier expressions, maps SIGMA fields to event fields, retrieves event values, and applies modifiers for comparison

**Details:**

In sigma_engine.go: 1) evaluateFieldCondition(fieldExpr string, expectedValue interface{}, event map[string]interface{}) bool. 2) Parse fieldExpr to extract base field and modifiers (split by '|'): field|modifier1|modifier2 → baseField='field', modifiers=['modifier1', 'modifier2']. 3) Map SIGMA field to event field: mappedField := engine.fieldMapper.MapField(baseField). If no mapping, use baseField directly. 4) Get event value: eventValue := event[mappedField]. Handle nested fields (dot notation) with recursive lookup. 5) Call engine.modifierEvaluator.EvaluateWithModifiers(eventValue, expectedValue, modifiers) from Task 127. 6) Return comparison result. 7) Handle missing fields (nil eventValue), type mismatches. Log field mapping and comparison at debug level.

### 129.7. Create metrics/sigma_metrics.go with comprehensive Prometheus metrics

**Status:** done  
**Dependencies:** 129.4, 129.5, 129.6  

Implement Prometheus metrics for SIGMA engine observability including evaluation counters, duration histograms, cache performance, modifier usage, and parse error tracking

**Details:**

Create metrics/sigma_metrics.go: 1) cerberus_sigma_rule_evaluations_total: prometheus.CounterVec with labels [rule_id, result] (match/no_match/error). 2) cerberus_sigma_rule_evaluation_duration_seconds: prometheus.HistogramVec with labels [rule_id], buckets [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]. 3) cerberus_sigma_cache_hits_total and cerberus_sigma_cache_misses_total: prometheus.Counter. 4) cerberus_sigma_modifier_evaluations_total: prometheus.CounterVec with label [modifier]. 5) cerberus_sigma_parse_errors_total: prometheus.CounterVec with label [error_type]. 6) init() function to register all metrics with prometheus.MustRegister. 7) Helper functions: RecordEvaluation(ruleID, result, duration), RecordCacheHit(), RecordCacheMiss(), RecordModifierEval(modifier), RecordParseError(errorType). Integrate into existing metrics/metrics.go alongside existing rule metrics.
