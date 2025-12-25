# Task ID: 178

**Title:** Update storage layer tests to remove legacy conditions serialization tests

**Status:** pending

**Dependencies:** 176

**Priority:** medium

**Description:** Remove all tests that verify conditions field JSON marshaling/unmarshaling in SQLite storage layer

**Details:**

PHASE 1: TEST CODE REMOVAL - Update storage tests

Files to modify:
1. `storage/sqlite_rules_test.go` - Remove conditions field tests
2. `storage/sqlite_rules_comprehensive_test.go` - Update to SIGMA format
3. `storage/sqlite_correlation_rules_comprehensive_test.go` - Remove conditions tests

Implementation:
```go
// DELETE test cases like:
func TestCreateRule_WithConditions(t *testing.T) {
    rule := &core.Rule{
        ID: "test-1",
        Conditions: []core.Condition{
            {Field: "field", Operator: "equals", Value: "value"},
        },
    }
    // ... test conditions serialization
}

// REPLACE with:
func TestCreateRule_SigmaYAML(t *testing.T) {
    rule := &core.Rule{
        ID: "test-1",
        Type: "sigma",
        SigmaYAML: `title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection`,
    }
    
    err := storage.CreateRule(rule)
    assert.NoError(t, err)
    
    // Verify SIGMA YAML was persisted
    retrieved, err := storage.GetRule("test-1")
    assert.NoError(t, err)
    assert.Equal(t, rule.SigmaYAML, retrieved.SigmaYAML)
    assert.Empty(t, retrieved.Conditions) // Should be empty
}
```

Key changes:
- Remove all test cases that marshal/unmarshal Conditions
- Update assertions to check SigmaYAML field
- Verify Conditions field is always empty after retrieval
- Update test fixtures to use SIGMA format

**Test Strategy:**

1. Run `go test ./storage/... -v` - all tests must pass
2. Check test coverage: `go test ./storage/... -coverprofile=coverage.out`
3. Verify coverage for CreateRule, UpdateRule, GetRule remains above 80%
4. Ensure no test verifies conditions JSON structure
5. Use `git grep 'Conditions.*json' storage/*_test.go` - should return 0 results

## Subtasks

### 178.1. Update storage/sqlite_rules_test.go to remove conditions tests and add SIGMA YAML verification

**Status:** pending  
**Dependencies:** None  

Remove all test cases that verify conditions field JSON marshaling/unmarshaling, and replace with SIGMA YAML-based tests that verify the sigma_yaml field is properly persisted and retrieved.

**Details:**

1. Locate and delete test functions like TestCreateRule_WithConditions, TestUpdateRule_WithConditions that test conditions serialization
2. Add new test cases:
   - TestCreateRule_SigmaYAML: Verify SIGMA YAML is stored and retrieved correctly
   - TestUpdateRule_SigmaYAML: Verify SIGMA YAML updates work
   - TestGetRule_EmptyConditions: Verify Conditions field is empty after retrieval
3. Update test fixtures to use Type='sigma' and SigmaYAML field instead of Conditions
4. Add assertions: assert.Equal(t, rule.SigmaYAML, retrieved.SigmaYAML) and assert.Empty(t, retrieved.Conditions)
5. Run `go test ./storage/sqlite_rules_test.go -v -coverprofile=coverage.out`
6. Verify coverage remains >80% using `go tool cover -func=coverage.out`

### 178.2. Update storage/sqlite_rules_comprehensive_test.go test cases to SIGMA format

**Status:** pending  
**Dependencies:** 178.1  

Convert comprehensive test suite from legacy conditions-based tests to SIGMA YAML format, ensuring all rule creation, update, retrieval, and query operations work with sigma_yaml field.

**Details:**

1. Review all test cases in sqlite_rules_comprehensive_test.go and identify conditions-based tests
2. Replace test fixtures:
   - Change from: Conditions: []core.Condition{{Field: "x", Operator: "equals", Value: "y"}}
   - Change to: Type: "sigma", SigmaYAML: "title: Test\ndetection:\n  selection:\n    x: y\n  condition: selection"
3. Update test assertions to verify SigmaYAML field presence and Conditions emptiness
4. Ensure logsource extraction tests verify logsource_category, logsource_product, logsource_service fields
5. Update bulk operations tests (CreateMultipleRules, UpdateMultipleRules) to use SIGMA format
6. Run comprehensive test suite: `go test ./storage/sqlite_rules_comprehensive_test.go -v -race -coverprofile=coverage.out`
7. Verify no regressions in rule filtering, pagination, or search functionality

### 178.3. Update storage/sqlite_correlation_rules_comprehensive_test.go to remove conditions tests

**Status:** pending  
**Dependencies:** 178.1, 178.2  

Remove correlation rule tests that verify conditions field persistence and update to ensure correlation rules use SIGMA YAML format with correlation configuration.

**Details:**

1. Remove test cases that create correlation rules with Conditions field:
   - Delete TestCreateCorrelationRule_WithConditions
   - Delete TestUpdateCorrelationRule_ConditionsSerialization
2. Add/update correlation-specific SIGMA tests:
   - TestCreateCorrelationRule_SigmaYAML: Verify correlation rules with sigma_yaml and correlation_config
   - TestCorrelationRule_ConfigPersistence: Verify correlation_config JSON is properly stored/retrieved
3. Ensure correlation rule tests verify:
   - Type = "correlation"
   - SigmaYAML contains valid SIGMA YAML
   - CorrelationConfig contains time_window, count_threshold, group_by fields
   - Conditions field is always empty
4. Update test fixtures to include realistic correlation configurations
5. Run `go test ./storage/sqlite_correlation_rules_comprehensive_test.go -v -coverprofile=coverage.out`
6. Verify integration with correlation engine still works after changes
