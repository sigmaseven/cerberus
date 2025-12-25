# Task ID: 170

**Title:** Implement Rule Testing Framework

**Status:** done

**Dependencies:** 168 ✓

**Priority:** medium

**Description:** Add API endpoints and engine support for testing rules against sample events before deployment with batch testing capability

**Details:**

Implementation: Create api/rule_testing.go (enhance existing):

1. POST /api/v1/rules/test handler:
type RuleTestRequest struct {
    Rule            *core.Rule   `json:"rule,omitempty"`
    RuleID          string       `json:"rule_id,omitempty"`
    Events          []core.Event `json:"events"`
    ExpectMatch     bool         `json:"expect_match,omitempty"`
    ExpectCorrelation bool       `json:"expect_correlation,omitempty"`
}

type RuleTestResponse struct {
    Matched             bool                   `json:"matched"`
    CorrelationTriggered bool                  `json:"correlation_triggered"`
    EvaluationTimeMs    float64               `json:"evaluation_time_ms"`
    MatchedEvents       []int                 `json:"matched_events"`
    CorrelationState    map[string]interface{} `json:"correlation_state,omitempty"`
    Errors              []string              `json:"errors"`
}

2. Create detect/test_engine.go:
   - Isolated engine instance for testing
   - No state persistence
   - Synchronous correlation evaluation
   - Detailed evaluation tracing

3. POST /api/v1/rules/{id}/test-batch:
   - Accept file upload or event array
   - Run rule against all events
   - Return aggregated results
   - Timeout protection (max 30s)

4. Add test event fixtures in testdata/

**Test Strategy:**

Create api/rule_testing_comprehensive_test.go:
1. Test single event rule testing
2. Test batch event testing
3. Test correlation rule testing with state
4. Test timeout enforcement
5. Test invalid rule rejection
6. Test expect_match validation
7. Performance: test 1000 events in <1s

## Subtasks

### 170.1. Enhance api/rule_testing.go with POST /api/v1/rules/test handler

**Status:** pending  
**Dependencies:** None  

Implement the core rule testing endpoint that accepts either a rule definition or rule ID along with sample events, and returns detailed evaluation results including match status, timing, and errors.

**Details:**

Create POST /api/v1/rules/test handler in api/rule_testing.go (enhance existing file). Implement RuleTestRequest struct with Rule, RuleID, Events, ExpectMatch, and ExpectCorrelation fields. Implement RuleTestResponse struct with Matched, CorrelationTriggered, EvaluationTimeMs, MatchedEvents, CorrelationState, and Errors fields. Add request validation to ensure either Rule or RuleID is provided. Integrate with detect/test_engine.go for rule evaluation. Add proper error handling for invalid rules, missing rule IDs, and evaluation failures. Include timing measurement using time.Now() before and after evaluation. Support both inline rule definitions and rule ID lookups from storage.

### 170.2. Create detect/test_engine.go with isolated synchronous evaluation

**Status:** pending  
**Dependencies:** 170.1  

Build a standalone test engine that provides isolated rule evaluation without state persistence, supporting both standard detection rules and correlation rules with synchronous evaluation and detailed tracing.

**Details:**

Create detect/test_engine.go with TestEngine struct containing isolated detector instance and temporary correlation state manager. Implement NewTestEngine() constructor that initializes engine without database connections. Implement TestRule() method that accepts rule and events, performs synchronous evaluation, and returns detailed results. For correlation rules, create temporary in-memory state that expires after test completion. Add detailed evaluation tracing that captures which conditions matched, field values evaluated, and correlation state transitions. Ensure no state persists to production storage. Implement synchronous correlation evaluation that processes all events in sequence and aggregates results. Add helper methods for extracting match details and correlation state snapshots.

### 170.3. Implement POST /api/v1/rules/{id}/test-batch for batch testing

**Status:** pending  
**Dependencies:** 170.1, 170.2  

Create batch testing endpoint that accepts multiple events via file upload or JSON array, evaluates a rule against all events, and returns aggregated results with timeout protection.

**Details:**

Implement POST /api/v1/rules/{id}/test-batch handler in api/rule_testing.go. Support multipart/form-data file upload (JSON, JSONL, CSV formats) and application/json array input. Parse uploaded files into []core.Event array with error handling for malformed data. Implement timeout protection using context.WithTimeout (max 30 seconds). Add goroutine-based processing with context cancellation on timeout. Aggregate results including total events, matched count, failed count, average evaluation time, and per-event results. Return BatchTestResponse with summary statistics and detailed per-event outcomes. Add progress tracking for large batches. Implement proper cleanup of uploaded files and temporary resources.

### 170.4. Add test event fixtures in testdata/ directory

**Status:** pending  
**Dependencies:** None  

Create comprehensive test event fixtures covering various log types, attack scenarios, and edge cases to support rule testing and validation.

**Details:**

Create testdata/rule_testing/ directory. Add sample_events.json with 50+ diverse events covering: Windows Security logs, Syslog events, web application logs, authentication events, network traffic logs, and cloud service logs. Create attack_scenarios.json with events for common attack patterns: brute force, privilege escalation, data exfiltration, lateral movement, and malware execution. Add edge_cases.json with unusual or boundary-condition events: empty fields, missing required fields, extremely long values, special characters, and Unicode. Create correlation_sequences.json with event sequences that should trigger correlation rules. Include benign_baseline.json with normal activity events. Add README.md documenting fixture structure and usage. Ensure all fixtures use valid core.Event schema with proper timestamps, fields, and metadata.

### 170.5. Write comprehensive tests with performance validation

**Status:** pending  
**Dependencies:** 170.1, 170.2, 170.3, 170.4  

Implement thorough test suite covering all rule testing functionality including timeout enforcement, correlation state management, and performance requirements (1000 events in under 1 second).

**Details:**

Create api/rule_testing_comprehensive_test.go. Implement TestSingleEventRuleTesting for basic rule evaluation with single events. Implement TestBatchEventTesting for batch processing with various sizes (10, 100, 1000 events). Implement TestCorrelationRuleTesting to validate correlation state tracking and sequence detection. Implement TestTimeoutEnforcement using events that sleep or infinite loops to trigger 30s timeout. Implement TestInvalidRuleRejection for malformed rules and missing required fields. Implement TestExpectMatchValidation to verify expect_match flag validation. Implement TestPerformance1000Events that evaluates 1000 events and asserts completion in <1s using testing.Benchmark or manual timing. Add table-driven tests for various rule types (SIGMA, CQL, correlation). Test error handling, edge cases, and concurrent batch requests. Verify resource cleanup and no memory leaks during batch processing.
