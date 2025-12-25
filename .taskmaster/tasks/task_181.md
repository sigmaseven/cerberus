# Task ID: 181

**Title:** Remove legacy condition evaluation from detection engine

**Status:** pending

**Dependencies:** 180

**Priority:** high

**Description:** Delete evaluateCondition() and all legacy evaluation functions, simplify evaluateRule() to only use SIGMA engine evaluation path

**Details:**

PHASE 4: DETECTION ENGINE REMOVAL - High risk, core logic changes

Files to modify:
1. `detect/engine.go` (lines 771-805) - Simplify evaluateRule(), remove conditions fallback
2. `detect/engine.go` (lines 920-1050) - DELETE evaluateCondition() function
3. `detect/engine.go` (lines 818-836) - DELETE evaluateStringOperator()
4. `detect/engine.go` (lines 841-844) - DELETE isActualNumericType()
5. `detect/engine.go` - DELETE compareNumbers(), compareFloat() helpers
6. `detect/test_engine.go` (line 403) - DELETE evaluateRuleConditions()
7. `detect/test_engine.go` (line 434) - DELETE evaluateCondition() (test version)
8. `detect/test_engine.go` (line 454) - DELETE matchValue()

Before/After for evaluateRule():
```go
// BEFORE (lines 771-805)
func (re *RuleEngine) evaluateRule(rule core.Rule, event *core.Event) bool {
    // SIGMA engine path
    if re.sigmaEngineEnabled && rule.Type == "sigma" && rule.SigmaYAML != "" {
        matched, err := re.sigmaEngine.Evaluate(&rule, event)
        if err != nil {
            re.logger.Errorw("SIGMA evaluation error", "rule_id", rule.ID, "error", err)
            return false
        }
        return matched
    }
    
    // LEGACY FALLBACK - REMOVE THIS ENTIRE BLOCK
    if len(rule.Conditions) == 0 {
        return false
    }
    
    for i, condition := range rule.Conditions {
        conditionMatched := re.evaluateCondition(condition, event) // DELETE
        // ... legacy logic ...
    }
    return false
}

// AFTER (simplified)
func (re *RuleEngine) evaluateRule(rule core.Rule, event *core.Event) bool {
    // Validate rule has SIGMA YAML
    if rule.SigmaYAML == "" {
        re.logger.Warnw("Rule has no SIGMA YAML, skipping evaluation", 
            "rule_id", rule.ID, "rule_type", rule.Type)
        return false
    }
    
    // Evaluate using SIGMA engine
    matched, err := re.sigmaEngine.Evaluate(&rule, event)
    if err != nil {
        re.logger.Errorw("SIGMA evaluation failed", 
            "rule_id", rule.ID, "error", err)
        return false
    }
    
    return matched
}
```

Functions to DELETE entirely (~400 lines):
- evaluateCondition()
- evaluateStringOperator()
- compareNumbers()
- compareFloat()
- isActualNumericType()
- All test engine equivalents

Ensure sigmaEngine field is always initialized in NewRuleEngine constructors.

**Test Strategy:**

1. Run `go test ./detect/... -v -race` - all tests must pass with race detection
2. Integration test: Send events through engine, verify SIGMA rules match correctly
3. Negative test: Create rule without sigma_yaml, verify it logs warning and doesn't match
4. Performance test: Benchmark rule evaluation, verify no regression
5. Use `git grep 'evaluateCondition' detect/` - should return 0 results (except in git history)
6. Verify engine successfully evaluates at least 10 different SIGMA rule patterns
7. Load test: Process 10,000 events with 100 SIGMA rules, verify memory doesn't leak
8. Check metrics: Verify prometheus metrics show SIGMA evaluation counts

## Subtasks

### 181.1. Simplify evaluateRule() to remove legacy conditions fallback

**Status:** pending  
**Dependencies:** None  

Remove the legacy conditions fallback block from evaluateRule() function (lines 771-805 in detect/engine.go), keeping only SIGMA engine evaluation path with proper validation and error handling

**Details:**

Modify detect/engine.go lines 771-805 to remove the entire legacy fallback block that checks len(rule.Conditions) and calls evaluateCondition(). Replace with simplified logic that validates rule.SigmaYAML is not empty, evaluates using sigmaEngine.Evaluate(), and returns the result with appropriate error logging. Add warning log for rules without SIGMA YAML. Ensure the function signature remains unchanged to maintain compatibility with existing callers.

### 181.2. Delete evaluateCondition() function from engine.go

**Status:** pending  
**Dependencies:** 181.1  

Remove the entire evaluateCondition() function (lines 920-1050 in detect/engine.go), which handles legacy condition evaluation logic including field extraction, operator matching, and type coercion

**Details:**

Delete the complete evaluateCondition() function from detect/engine.go spanning approximately 130 lines (920-1050). This function is no longer called after task 1 simplifies evaluateRule(). Verify no other functions in engine.go reference evaluateCondition() before deletion. Use git grep to confirm no imports or external references exist outside of test files.

### 181.3. Delete evaluateStringOperator() helper function

**Status:** pending  
**Dependencies:** 181.2  

Remove evaluateStringOperator() function (lines 818-836 in detect/engine.go) that performs string matching operations for legacy conditions including equals, contains, startswith, endswith, and regex operators

**Details:**

Delete evaluateStringOperator() function from detect/engine.go. This helper was called exclusively by evaluateCondition() which is removed in task 2. The function handles string comparison operators that are now fully managed by the SIGMA engine. Confirm the function is not referenced elsewhere in the codebase before deletion.

### 181.4. Delete numeric comparison helper functions

**Status:** pending  
**Dependencies:** 181.2  

Remove compareNumbers(), compareFloat(), and isActualNumericType() helper functions from detect/engine.go that were used for legacy numeric condition evaluation

**Details:**

Delete three numeric helper functions from detect/engine.go: compareNumbers() (handles int/float comparisons with operators like gt, lt, gte, lte), compareFloat() (float-specific comparison with epsilon tolerance), and isActualNumericType() (lines 841-844, type checking for numeric values). These functions were only used by evaluateCondition() which is removed in task 2. Verify no other code paths reference these helpers.

### 181.5. Delete legacy evaluation functions from test_engine.go

**Status:** pending  
**Dependencies:** 181.2, 181.3, 181.4  

Remove test engine equivalents of legacy evaluation functions from detect/test_engine.go including evaluateRuleConditions() (line 403), evaluateCondition() (line 434), and matchValue() (line 454)

**Details:**

Delete three legacy evaluation functions from detect/test_engine.go: evaluateRuleConditions() at line 403 (top-level test evaluation), evaluateCondition() at line 434 (test version of main evaluateCondition), and matchValue() at line 454 (value matching helper). These mirror the production functions removed in previous tasks and are no longer needed since test engine should only support SIGMA evaluation. Verify TestEngine struct and its methods remain functional after deletion.

### 181.6. Ensure sigmaEngine always initialized in NewRuleEngine constructors

**Status:** pending  
**Dependencies:** 181.1  

Verify and enforce that sigmaEngine field is always properly initialized in all NewRuleEngine constructor functions to prevent nil pointer panics after legacy fallback removal

**Details:**

Review all NewRuleEngine constructor functions in detect/engine.go and detect/test_engine.go. Ensure sigmaEngine is always initialized, never nil. Add validation that returns error if SIGMA engine initialization fails. Update constructor documentation to clarify SIGMA engine is mandatory. Check for any constructor variants or test helpers that might skip SIGMA engine initialization and fix them.

### 181.7. Comprehensive integration testing with race detection and load testing

**Status:** pending  
**Dependencies:** 181.1, 181.2, 181.3, 181.4, 181.5, 181.6  

Execute full integration test suite including race detection, memory leak checks, performance benchmarks, and load testing to validate the removal of legacy evaluation code under production-like conditions

**Details:**

Run comprehensive test suite: (1) go test ./detect/... -v -race to detect race conditions, (2) Integration test sending diverse events through engine with SIGMA rules to verify correct matching, (3) Negative test with rules lacking sigma_yaml to confirm warnings logged and no matches, (4) Performance benchmarks with go test ./detect/... -bench=. -benchmem to compare against baseline, (5) Load test with concurrent rule evaluation to stress test the simplified engine, (6) Memory profiling to detect leaks from removed code paths, (7) Verify metrics and observability still capture evaluation data correctly.
