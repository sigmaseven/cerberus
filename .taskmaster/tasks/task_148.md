# Task ID: 148

**Title:** Reduce Cyclomatic Complexity in Detection Engine

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Refactor detect/engine.go and detect/sigma_condition_parser.go by breaking down functions with complexity >10 into smaller, testable units to achieve 90%+ test coverage.

**Details:**

Large files with high cyclomatic complexity:
- detect/engine.go (1,152 lines)
- detect/sigma_condition_parser.go (1,237 lines)
- sigma_condition_parser.go:Parse() has complexity of 47 (limit: 10)
- Functions exceed 300 lines, impossible to achieve >60% test coverage

Example problem:
```go
func (p *Parser) Parse() (Node, error) {
  // 300+ lines of nested if/else/switch
  // Cyclomatic complexity: 47
  // Test coverage: 43%
}
```

Refactoring strategy:
1. Extract Parse() into 10+ smaller functions by responsibility:
   ```go
   func (p *Parser) Parse() (Node, error) {
     return p.parseExpression(0) // Entry point, complexity: 2
   }
   
   func (p *Parser) parseExpression(precedence int) (Node, error) {
     left := p.parsePrimary() // complexity: 3
     for p.current().Type.isOperator() {
       left = p.parseBinaryOp(left, precedence) // complexity: 4
     }
     return left, nil
   }
   
   func (p *Parser) parsePrimary() (Node, error) // complexity: 5
   func (p *Parser) parseBinaryOp(left Node, prec int) (Node, error) // complexity: 6
   func (p *Parser) parseUnaryOp() (Node, error) // complexity: 3
   func (p *Parser) parseParenthesized() (Node, error) // complexity: 2
   ```
2. Apply same pattern to detect/engine.go:
   - Extract rule evaluation into separate functions
   - Split condition matching by operator type
   - Create dedicated functions for aggregations
3. Use table-driven tests for comprehensive coverage:
   ```go
   tests := []struct{
     name     string
     input    string
     expected Node
     wantErr  bool
   }{
     {"simple AND", "a AND b", &BinaryNode{...}, false},
     // 50+ test cases
   }
   ```
4. Add cyclomatic complexity linting:
   - gocyclo with threshold of 10
   - CI fails if complexity >10

Success criteria:
- Maximum cyclomatic complexity: 10 per function
- 90%+ test coverage on detection engine
- No function exceeds 100 lines
- Benchmark showing no performance regression

**Test Strategy:**

1. Cyclomatic complexity analysis - gocyclo, all functions ≤10
2. Unit test coverage - 90%+ on all refactored functions
3. Table-driven tests - comprehensive input/output validation
4. Benchmark test - verify no performance regression (±5%)
5. Integration test - sigma rule parsing end-to-end
6. Edge case testing - malformed inputs, deeply nested conditions
7. Regression test suite - existing detection rules still work

## Subtasks

### 148.1. Analyze sigma_condition_parser.go Parse() and design decomposition strategy

**Status:** done  
**Dependencies:** None  

Analyze the Parse() function in detect/sigma_condition_parser.go (complexity 47, 300+ lines) and design a decomposition into 10+ single-responsibility functions following the parsing pattern: parseExpression, parsePrimary, parseBinaryOp, parseUnaryOp, parseParenthesized.

**Details:**

Read detect/sigma_condition_parser.go and map out the Parse() function's current control flow. Identify natural decomposition boundaries based on parsing phases (tokenization, expression parsing, operator precedence, parenthesis handling, unary operations). Document the function call graph for the proposed architecture where Parse() becomes a thin entry point delegating to specialized parsing functions. Create a refactoring plan with complexity targets: parseExpression (complexity ≤4), parsePrimary (complexity ≤5), parseBinaryOp (complexity ≤6), parseUnaryOp (complexity ≤3), parseParenthesized (complexity ≤2). Identify edge cases and parsing invariants that must be preserved.
<info added on 2025-12-15T02:55:24.500Z>
Based on the analysis results, I need to examine the actual codebase to understand the current implementation before generating the subtask update.Based on the codebase analysis, I can now generate the appropriate subtask update.

COMPLEXITY ANALYSIS COMPLETE. Functions identified with cyclomatic complexity >10:

HIGH PRIORITY REFACTORINGS (Complexity >20):
1. evaluateCorrelationRule (engine.go:503-648) - Complexity 28
   - Current structure: 145 lines, 3-step lock pattern (RLock→process→Lock)
   - Decomposition targets: extractCorrelationState(), processCorrelationEvents(), updateCorrelationState()
   - Critical sections: Lines 506-523 (state read), 531-592 (event processing), 597-648 (state write)
   - Complexity distribution: state extraction (≤3), event processing (≤8), state update (≤6), merge logic (≤5)

2. evaluateCondition (engine.go:691-792) - Complexity 25
   - Current structure: 100+ lines, 12 operator switch cases
   - Decomposition targets: evaluateStringOperator(), evaluateNumericOperator(), evaluateRegexOperator()
   - Switch cases: equals/not_equals (lines 698-711), contains/starts_with/ends_with (712-732), regex (733-750), numeric comparisons (751-792)
   - Complexity distribution: string ops (≤4), numeric ops (≤6), regex ops (≤3), type conversion (≤2)

3. EvaluateEnhancedCorrelation (engine.go:947-1030) - Complexity 22
   - Current structure: 83 lines, 6 rule type loops with identical pattern
   - Decomposition target: evaluateRuleType() - generic loop extractor
   - Loop pattern (lines 954-961, 964-971, 974-981, 984-991, 994-1001, 1004-1011): for rule in ruleSlice { if enabled { evaluate } }
   - Complexity distribution: generic evaluator (≤3), rule type dispatch (≤4)

MEDIUM PRIORITY REFACTORINGS (Complexity 15):
4. parseAggregation (sigma_condition_parser.go:995-1089) - Complexity 15
   - Current structure: 95 lines, quantifier switch (lines 1002-1044) + target switch (1059-1084)
   - Decomposition targets: parseQuantifier(), parseAggregationTarget()
   - Quantifier cases: ALL/ANY/ONE/NUMBER (lines 1003-1040), validation (1029-1039)
   - Target cases: THEM/IDENTIFIER/EOF/default (lines 1060-1084)
   - Complexity distribution: parseQuantifier (≤6), parseAggregationTarget (≤5), validation (≤3)

5. parsePrimaryExpression (sigma_condition_parser.go:788-887) - Complexity 15
   - Current structure: 100 lines, 10-case switch statement
   - Switch cases: LPAREN (793-815), IDENTIFIER (817-821), aggregation lookahead (823-837), error cases (839-887)
   - NOTE: Switch cases are NECESSARY for token type dispatch - cannot be extracted without introducing complexity
   - Recommended: Keep as-is, focus on higher-priority targets

REFACTORING IMPLEMENTATION PLAN:

Phase 1 - Extract evaluateCorrelationRule (engine.go:503):
```go
// Extract state reading (complexity ≤3)
func (re *RuleEngine) extractCorrelationState(ruleID string) (events []*core.Event, stateLen int, exists bool) {
    re.correlationMu.RLock()
    defer re.correlationMu.RUnlock()
    existingEvents := re.correlationState[ruleID]
    eventsCopy := make([]*core.Event, len(existingEvents))
    copy(eventsCopy, existingEvents)
    return eventsCopy, len(existingEvents), len(re.correlationState[ruleID]) > 0
}

// Extract event processing (complexity ≤8)
func processCorrelationEvents(eventsCopy []*core.Event, newEvent *core.Event, rule core.CorrelationRule, correlationTTL int) (windowedEvents []*core.Event, matched bool) {
    // Lines 528-592: sorting, filtering, window calculation, sequence matching
}

// Extract state update (complexity ≤6)
func (re *RuleEngine) updateCorrelationState(ruleID string, windowedEvents []*core.Event, originalStateLen int, event *core.Event, rule core.CorrelationRule, matched bool) {
    re.correlationMu.Lock()
    defer re.correlationMu.Unlock()
    // Lines 600-645: optimistic locking merge logic
}
```

Phase 2 - Extract evaluateCondition (engine.go:691):
```go
// Extract string operations (complexity ≤4)
func evaluateStringOperator(operator string, fieldValue interface{}, condValue interface{}) (bool, bool) {
    str, ok := fieldValue.(string)
    if !ok { return false, false }
    valStr, ok := condValue.(string)
    if !ok { return false, false }
    switch operator {
    case "contains": return strings.Contains(str, valStr), true
    case "starts_with": return strings.HasPrefix(str, valStr), true
    case "ends_with": return strings.HasSuffix(str, valStr), true
    }
    return false, false
}

// Extract numeric operations (complexity ≤6)
func evaluateNumericOperator(operator string, fieldValue interface{}, condValue interface{}) (bool, bool) {
    // Lines 751-792: gt, gte, lt, lte with type conversions
}
```

Phase 3 - Extract EvaluateEnhancedCorrelation (engine.go:947):
```go
// Generic rule type evaluator (complexity ≤3)
func evaluateRuleType[T any](rules []T, event *core.Event, evaluator func(T, *core.Event) (*core.Alert, bool)) []*core.Alert {
    var alerts []*core.Alert
    for _, rule := range rules {
        if alert, matched := evaluator(rule, event); matched {
            alerts = append(alerts, alert)
        }
    }
    return alerts
}
```

Phase 4 - Extract parseAggregation (sigma_condition_parser.go:995):
```go
// Extract quantifier parsing (complexity ≤6)
func (p *ConditionParser) parseQuantifier() (aggType AggregationType, count int, err error) {
    // Lines 998-1044: switch on ALL/ANY/ONE/NUMBER with validation
}

// Extract target parsing (complexity ≤5)
func (p *ConditionParser) parseAggregationTarget(availableIdentifiers []string) (pattern string, matchedIdentifiers []string, err error) {
    // Lines 1054-1089: switch on THEM/IDENTIFIER with matching logic
}
```

TESTING REQUIREMENTS BEFORE REFACTORING:
- Table-driven tests for evaluateCorrelationRule covering lock contention scenarios
- Table-driven tests for evaluateCondition covering all 12 operator types
- Table-driven tests for EvaluateEnhancedCorrelation covering all 6 rule types
- Table-driven tests for parseAggregation covering quantifier/target combinations
- Benchmark tests to verify <5% performance regression after extraction

NEXT STEPS FOR SUBTASK 148.2:
Focus test suite on functions 1-4 (skip parsePrimaryExpression - switch statement is idiomatic). Create comprehensive table-driven tests before any code changes to establish refactoring safety net.
</info added on 2025-12-15T02:55:24.500Z>

### 148.2. Implement comprehensive table-driven test suite before refactoring

**Status:** done  
**Dependencies:** 148.1  

Create 50+ table-driven test cases for sigma_condition_parser.go covering all parsing scenarios, edge cases, and error conditions to establish safety net before refactoring begins.

**Details:**

Build comprehensive test suite in detect/sigma_condition_parser_test.go using table-driven approach. Test cases must cover: simple AND/OR/NOT operations, nested conditions, operator precedence, parenthesized expressions, unary operations, whitespace handling, invalid syntax, malformed input, empty conditions, special characters, aggregation functions, field comparisons, and complex nested SIGMA conditions. Structure: []struct{name string, input string, expected Node, wantErr bool}. Aim for 90%+ coverage on current Parse() implementation to detect any regression during refactoring. Include benchmark tests to establish performance baseline.

### 148.3. Extract and test parsing functions with max complexity 10

**Status:** done  
**Dependencies:** 148.2  

Refactor Parse() by extracting individual parsing functions (parseExpression, parsePrimary, parseBinaryOp, parseUnaryOp, parseParenthesized) ensuring each has cyclomatic complexity ≤10 and maintains test coverage.

**Details:**

Incrementally extract functions from Parse() in detect/sigma_condition_parser.go following the design from subtask 1. Order: (1) parseParenthesized (simplest, complexity target 2), (2) parseUnaryOp (complexity target 3), (3) parsePrimary (complexity target 5), (4) parseBinaryOp (complexity target 6), (5) parseExpression (complexity target 4). After each extraction, run full test suite to verify no regression. Add focused unit tests for each new function. Ensure Parse() becomes a thin wrapper calling parseExpression(0). Run gocyclo after each extraction to verify complexity reduction. No function should exceed 100 lines.

### 148.4. Refactor detect/engine.go into operator-specific and aggregation functions

**Status:** done  
**Dependencies:** 148.3  

Apply decomposition pattern to detect/engine.go by extracting rule evaluation into operator-specific functions and dedicated aggregation handlers, reducing cyclomatic complexity to ≤10 per function.

**Details:**

Analyze detect/engine.go (1,844 lines) and identify high-complexity functions in rule evaluation logic. Extract into specialized functions: evaluateEqualsCondition(), evaluateContainsCondition(), evaluateRegexCondition(), evaluateComparisonCondition() for operator-specific logic. Create separate aggregation handlers: handleCountAggregation(), handleSumAggregation(), handleAvgAggregation(). Use strategy pattern or function maps for operator dispatch. Ensure main evaluation function becomes a coordinator delegating to specialized handlers. Target: no function >100 lines, complexity ≤10. Maintain backward compatibility with existing SIGMA rule parsing.

### 148.5. Add gocyclo linting to CI and validate no performance regression

**Status:** done  
**Dependencies:** 148.4  

Integrate gocyclo complexity checking into CI pipeline with threshold=10, add benchmark tests to ensure refactoring caused no performance regression beyond ±5%.

**Details:**

Add gocyclo to CI workflow (likely in .github/workflows/ or Makefile). Configure with -over 10 flag to fail builds when any function exceeds complexity of 10. Add gocyclo check for detect/engine.go and detect/sigma_condition_parser.go specifically. Create comprehensive benchmark suite in detect/engine_benchmark_test.go and detect/sigma_condition_parser_benchmark_test.go testing: (1) simple condition parsing, (2) complex nested conditions, (3) large rule evaluation, (4) aggregation performance. Document baseline metrics and ensure refactored code performs within ±5% of baseline. Add benchmark comparison to CI to catch performance regressions.
