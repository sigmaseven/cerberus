# Task ID: 177

**Title:** Remove legacy condition evaluation tests from detection engine

**Status:** pending

**Dependencies:** 176

**Priority:** medium

**Description:** Delete or rewrite all test functions that test evaluateCondition, evaluateRule with legacy conditions, and condition-based evaluation logic

**Details:**

PHASE 1: TEST CODE REMOVAL - Remove tests for legacy evaluation paths

Files to modify:
1. `detect/engine_test.go` (lines 312-400) - Remove evaluateCondition tests
2. `detect/engine_comprehensive_test.go` - Convert to SIGMA rule tests
3. `detect/performance_test.go` (lines 136-650) - Update benchmarks
4. `detect/loader_test.go` (lines 24-92) - Remove LoadRules() tests for JSON files

Implementation:
```go
// DELETE these test functions:
// - TestEvaluateCondition_Equals
// - TestEvaluateCondition_Contains
// - TestEvaluateCondition_Regex
// - TestEvaluateCondition_GreaterThan
// - TestEvaluateCondition_LessThan
// - TestEvaluateRule_WithConditions

// REPLACE with SIGMA equivalents:
func TestEvaluateRule_SigmaYAML(t *testing.T) {
    sigmaYAML := `title: Test Login Detection
detection:
  selection:
    event.type: login
    status: failed
  condition: selection
level: high`
    
    rule := core.Rule{
        ID: "test-1",
        Type: "sigma",
        SigmaYAML: sigmaYAML,
    }
    
    event := &core.Event{
        Type: "login",
        Fields: map[string]interface{}{
            "status": "failed",
        },
    }
    
    // Test SIGMA evaluation
    matched := engine.evaluateRule(rule, event)
    assert.True(t, matched)
}
```

Files to update:
- Remove ~200 lines of legacy condition tests
- Keep SIGMA engine tests
- Update benchmark tests to use SIGMA rules only

**Test Strategy:**

1. Run `go test ./detect/... -v` - all tests must pass
2. Verify test coverage remains above 70% for detect package
3. Run benchmarks: `go test ./detect/... -bench=. -benchmem`
4. Verify no test imports or uses evaluateCondition function
5. Use `git grep 'evaluateCondition' detect/*_test.go` - should return 0 results
