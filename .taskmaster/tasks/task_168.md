# Task ID: 168

**Title:** Integrate Correlation Evaluation in Detection Engine

**Status:** done

**Dependencies:** 166 ✓, 167 ✓

**Priority:** high

**Description:** Modify detect/engine.go to evaluate correlation rules using SIGMA correlation blocks and existing enhanced correlation evaluators

**Details:**

Implementation: Modify detect/engine.go:

1. Add correlation rule loading:
func (e *Engine) LoadCorrelationRules(ctx context.Context) error {
    rules, err := e.ruleStorage.GetRulesByCategory(ctx, "correlation")
    // Parse SIGMA correlation blocks
    // Initialize correlation state managers
}

2. In ProcessEvent():
   - After detection rule evaluation
   - Check if event matches any correlation rule detection section
   - If match, extract correlation config from parsed SIGMA
   - Route to appropriate evaluator based on correlation.type
   - Use existing detect/correlation_evaluators.go functions

3. Add correlation state management:
   - Use detect/correlation_state.go CorrelationStateStore
   - Configure TTL based on correlation timespan
   - Implement state cleanup

4. Map SIGMA correlation types to evaluator functions:
   event_count -> EvaluateCountRule
   value_count -> EvaluateValueCountRule
   sequence -> EvaluateSequenceRule
   etc.

5. Generate correlation alerts when thresholds met

**Test Strategy:**

Create detect/engine_correlation_integration_test.go:
1. Test correlation rule loading from unified storage
2. Test event routing to correlation evaluators
3. Test each correlation type triggers alerts
4. Test correlation state persistence across events
5. Test correlation window expiration
6. Test mixed detection+correlation rule evaluation
7. Performance test: 10k events/sec with correlation

## Subtasks

### 168.1. Add LoadCorrelationRules() function to detect/engine.go with SIGMA parsing

**Status:** pending  
**Dependencies:** None  

Implement the LoadCorrelationRules() function that fetches correlation rules from storage, parses their SIGMA correlation blocks, and initializes correlation state managers for each rule type.

**Details:**

Add LoadCorrelationRules(ctx context.Context) error method to Engine struct. Use e.ruleStorage.GetRulesByCategory(ctx, "correlation") to fetch rules. Parse the sigma_yaml field to extract correlation configuration blocks (correlation.type, correlation.rules, correlation.timespan, etc.). Initialize CorrelationStateStore instances from detect/correlation_state.go for each correlation rule with appropriate TTL based on timespan. Store parsed correlation configs in a map[string]CorrelationConfig for quick lookup during event processing. Handle errors gracefully and log warnings for invalid correlation blocks.

### 168.2. Extend ProcessEvent() to route events to correlation evaluators after detection rule evaluation

**Status:** pending  
**Dependencies:** 168.1  

Modify the ProcessEvent() method in detect/engine.go to check events against correlation rules after standard detection rule evaluation, and route matching events to the appropriate correlation evaluator.

**Details:**

In ProcessEvent(ctx context.Context, event map[string]interface{}) method, after existing detection rule evaluation loop, add correlation rule matching phase. Iterate through loaded correlation rules and check if event matches the detection section criteria. For matches, extract the correlation configuration from parsed SIGMA blocks. Determine correlation type (event_count, value_count, sequence, etc.) and route to corresponding evaluator function. Pass event data, correlation config, and correlation state store to evaluator. Collect any generated correlation alerts and append to results. Ensure this additional processing doesn't block the main event processing pipeline.

### 168.3. Implement correlation state management using existing detect/correlation_state.go

**Status:** pending  
**Dependencies:** 168.1  

Integrate the CorrelationStateStore from detect/correlation_state.go into the Engine struct, implement proper initialization, TTL configuration, and cleanup mechanisms for correlation state across event streams.

**Details:**

Add correlationStates map[string]*CorrelationStateStore field to Engine struct to store state managers per correlation rule. In LoadCorrelationRules(), create CorrelationStateStore instances with TTL values extracted from SIGMA correlation.timespan field. Implement background cleanup goroutine that periodically calls CleanupExpiredStates() on each state store. Ensure thread-safe concurrent access using sync.RWMutex where needed. Add proper context cancellation handling for graceful shutdown. Store correlation state keys based on rule ID and grouping fields from correlation config.

### 168.4. Build routing logic mapping SIGMA correlation types to evaluator functions

**Status:** pending  
**Dependencies:** 168.2  

Create a type-safe routing mechanism that maps SIGMA correlation.type values to the appropriate evaluator functions from detect/correlation_evaluators.go, with proper parameter mapping and error handling.

**Details:**

Add correlationTypeRouter map[string]CorrelationEvaluatorFunc to Engine struct. Populate router in initialization with mappings: 'event_count' -> EvaluateCountRule, 'value_count' -> EvaluateValueCountRule, 'sequence' -> EvaluateSequenceRule, 'temporal' -> EvaluateTemporalRule. Create helper function routeToEvaluator(correlationType string, event map[string]interface{}, config CorrelationConfig, stateStore *CorrelationStateStore) that looks up the appropriate evaluator and invokes it with proper parameters. Handle unknown correlation types gracefully with logging and fallback behavior. Ensure evaluator function signatures are compatible with routing mechanism.

### 168.5. Add correlation alert generation with proper context

**Status:** pending  
**Dependencies:** 168.4  

Implement alert generation when correlation rule thresholds are met, including proper alert formatting, context enrichment, and integration with existing alert storage mechanisms.

**Details:**

When correlation evaluators return threshold-met results, create core.Alert objects with type='correlation'. Include all triggering event IDs in alert context. Populate alert fields: RuleID (correlation rule ID), RuleName, Severity (from SIGMA rule), Timestamp, and CorrelationContext (JSON with matched events, correlation window, threshold values). Add Tags field with correlation type and rule category. Ensure alerts include sufficient context for investigation (group-by field values, time window, matched conditions). Integrate with existing alert storage by calling e.alertStorage.CreateAlert(). Add metrics for correlation alerts generated by type.

### 168.6. Write integration tests for all correlation types with performance benchmarks (10k events/sec)

**Status:** pending  
**Dependencies:** 168.5  

Create comprehensive integration test suite in detect/engine_correlation_integration_test.go covering all correlation types, edge cases, and performance benchmarks validating 10k events/sec throughput.

**Details:**

Create detect/engine_correlation_integration_test.go with test cases for: 1) Each correlation type (event_count, value_count, sequence, temporal) generating alerts correctly, 2) Correlation state persistence across event batches, 3) TTL expiration and state cleanup, 4) Mixed detection and correlation rules processing same events, 5) Concurrent event processing with correlation evaluation, 6) Edge cases (zero threshold, single event correlation, overlapping windows). Add benchmark tests: BenchmarkProcessEventWithCorrelation measuring throughput with various correlation rule counts (1, 10, 100 rules). Target 10,000 events/sec minimum throughput. Use testing.B for accurate benchmarking. Include memory profiling to detect leaks.
