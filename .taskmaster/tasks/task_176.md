# Task ID: 176

**Title:** Remove legacy test helpers and update test fixtures to SIGMA format

**Status:** pending

**Dependencies:** 175

**Priority:** medium

**Description:** Update all test helper functions that create rules with Conditions to use SIGMA YAML format instead, ensuring tests use modern rule format

**Details:**

PHASE 1: TEST CODE REMOVAL - Low risk, tests are leaf nodes

Files to modify:
1. `api/test_helpers.go:459` - Update `NewTestRule()` function
2. `testing/mocks.go:489` - Update `CreateTestRule()` function
3. `tests/bdd/steps/security_steps.go:328` - Update `createRule()` function

Implementation pattern for each file:
```go
// BEFORE (legacy)
func NewTestRule() *core.Rule {
    return &core.Rule{
        ID: "test-rule-1",
        Name: "Test Rule",
        Type: "detection",
        Conditions: []core.Condition{
            {Field: "event.type", Operator: "equals", Value: "login"},
        },
    }
}

// AFTER (SIGMA YAML)
func NewTestRule() *core.Rule {
    sigmaYAML := `title: Test Rule
id: test-rule-1
status: experimental
logsource:
  category: authentication
detection:
  selection:
    event.type: login
  condition: selection
level: medium`
    
    return &core.Rule{
        ID: "test-rule-1",
        Name: "Test Rule",
        Type: "sigma",
        SigmaYAML: sigmaYAML,
        Severity: "medium",
    }
}
```

Steps:
1. Search codebase for all test helper functions creating rules
2. Update each to use SigmaYAML instead of Conditions
3. Ensure Type field is set to "sigma"
4. Remove any references to Conditions in test fixtures

**Test Strategy:**

1. Run `go test ./api/... -v` - all API tests must pass
2. Run `go test ./testing/... -v` - mock tests must pass
3. Run BDD tests if present - all scenarios must pass
4. Use `git grep 'Conditions.*\[\]core\.Condition'` in test files - should return 0 matches
5. Verify no test creates rules with empty SigmaYAML field
