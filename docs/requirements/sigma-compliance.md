# Sigma Specification Compliance Requirements

**Document Owner**: Security Engineering Team
**Created**: 2025-11-16
**Status**: DRAFT - Pending Technical Review
**Authoritative Source**: [Sigma Specification (SigmaHQ)](https://github.com/SigmaHQ/sigma-specification)
**Specification Version**: 1.0.0
**Purpose**: Define exact Sigma specification compliance requirements for Cerberus rule engine

---

## 1. EXECUTIVE SUMMARY

This document defines the REQUIRED behavior of the Cerberus Sigma rule engine based on the official Sigma specification. All tests MUST validate against these requirements, not against current implementation behavior.

**Critical Note**: If this document conflicts with current implementation, the implementation is WRONG and must be fixed.

---

## 2. SIGMA OPERATOR SEMANTICS

### 2.1 equals Operator

**Specification Reference**: [SigmaHQ Specification - Detection](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#detection)
**Semantic Requirement**: Exact string matching with case-sensitivity

**REQUIRED Behavior**:
1. **Exact Match**: Value must be identical to field value
2. **Case Sensitivity**: "Admin" ≠ "admin" (MUST be case-sensitive)
3. **No Substring Matching**: "Admin" ≠ "Administrator"
4. **Type Handling**: String "10" ≠ Number 10 (see Section 3)
5. **Whitespace**: Trailing/leading spaces are significant

**Test Requirements**:
```
MUST match:     field="Admin", condition="Admin"
MUST NOT match: field="Admin", condition="admin"
MUST NOT match: field="Administrator", condition="Admin"
MUST NOT match: field="Admin ", condition="Admin" (trailing space)
MUST match:     field="", condition="" (empty string equals empty string)
```

**Implementation Location**: `detect/engine.go:evaluateCondition()` line 382
**Current Implementation**: Uses `reflect.DeepEqual(fieldValue, cond.Value)`
**Compliance Status**: ⚠️ UNKNOWN - Needs verification with specification examples

**Validation Test Required**: `TestRuleEngine_EqualsOperator_SigmaCompliance`

---

### 2.2 not_equals Operator

**Specification Reference**: [SigmaHQ Specification - Detection Modifiers](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#detection)
**Semantic Requirement**: Logical negation of equals operator

**REQUIRED Behavior**:
1. Returns TRUE when equals would return FALSE
2. Returns FALSE when equals would return TRUE
3. Same case sensitivity as equals
4. Same type handling as equals

**Test Requirements**:
```
field="Admin", condition="admin" → TRUE (not equal, case-sensitive)
field="Admin", condition="Admin" → FALSE (equal)
field=nil → TRUE (missing field not equal to any value)
```

**Implementation Location**: `detect/engine.go:evaluateCondition()` line 385
**Current Implementation**: `!reflect.DeepEqual(fieldValue, cond.Value)`
**Compliance Status**: ⚠️ UNKNOWN - Needs verification against Sigma examples

**Validation Test Required**: `TestRuleEngine_NotEqualsOperator_SigmaCompliance`

---

### 2.3 contains Operator

**Specification Reference**: [SigmaHQ Specification - String Matching](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#string-matching)
**Semantic Requirement**: Substring matching with case-sensitivity by default

**REQUIRED Behavior**:
1. **Substring Match**: "error" in "an error occurred" → TRUE
2. **Case Sensitivity**: "error" in "ERROR occurred" → FALSE
3. **Position Independent**: Match anywhere in string
4. **Type Requirement**: Both field and value MUST be strings
5. **Non-String Fields**: Return FALSE (not error) if field is not string

**Test Requirements**:
```
MUST match:     field="an error occurred", value="error"
MUST match:     field="error", value="error" (full string is substring of itself)
MUST match:     field="error at end", value="end"
MUST NOT match: field="ERROR OCCURRED", value="error" (case-sensitive)
MUST NOT match: field=12345, value="123" (non-string field)
```

**Edge Cases**:
- Empty substring: `field="anything", value=""` → TRUE (empty string is substring of any string)
- Unicode: Must support UTF-8 substring matching
- Special characters: Must handle regex special chars as literals

**Implementation Location**: `detect/engine.go:evaluateCondition()` line 386-391
**Current Implementation**: Uses `strings.Contains(str, valStr)` with type checks
**Compliance Status**: ✅ LIKELY COMPLIANT - Verify empty string and unicode handling

**Validation Test Required**: `TestRuleEngine_ContainsOperator_SigmaCompliance`

---

### 2.4 startswith Operator

**Specification Reference**: [SigmaHQ Specification - String Matching](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#string-matching)
**Semantic Requirement**: Prefix matching with case-sensitivity

**REQUIRED Behavior**:
1. **Prefix Match**: Value must be at start of field value
2. **Case Sensitivity**: "Error" ≠ "error" at start
3. **Type Requirement**: Both MUST be strings
4. **Full Match**: "error" matches field "error" (equal strings)

**Test Requirements**:
```
MUST match:     field="error in system", value="error"
MUST match:     field="error", value="error" (equals case)
MUST NOT match: field="an error", value="error" (not at start)
MUST NOT match: field="Error", value="error" (case mismatch)
```

**Implementation Location**: `detect/engine.go:evaluateCondition()` line 393-399
**Current Implementation**: Uses `strings.HasPrefix(str, valStr)`
**Compliance Status**: ✅ LIKELY COMPLIANT - Verify case sensitivity

**Validation Test Required**: `TestRuleEngine_StartsWithOperator_SigmaCompliance`

---

### 2.5 endswith Operator

**Specification Reference**: [SigmaHQ Specification - String Matching](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#string-matching)
**Semantic Requirement**: Suffix matching with case-sensitivity

**REQUIRED Behavior**:
1. **Suffix Match**: Value must be at end of field value
2. **Case Sensitivity**: "Error" ≠ "error" at end
3. **Type Requirement**: Both MUST be strings
4. **Full Match**: "error" matches field "error" (equal strings)

**Test Requirements**:
```
MUST match:     field="system error", value="error"
MUST match:     field="error", value="error" (equals case)
MUST NOT match: field="error in system", value="error" (not at end)
MUST NOT match: field="ERROR", value="error" (case mismatch)
```

**Implementation Location**: `detect/engine.go:evaluateCondition()` line 400-406
**Current Implementation**: Uses `strings.HasSuffix(str, valStr)`
**Compliance Status**: ✅ LIKELY COMPLIANT - Verify case sensitivity

**Validation Test Required**: `TestRuleEngine_EndsWithOperator_SigmaCompliance`

---

### 2.6 regex Operator

**Specification Reference**: [SigmaHQ Specification - Regular Expressions](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#regular-expressions)
**Semantic Requirement**: Full regular expression matching per Go regexp syntax

**REQUIRED Behavior**:
1. **Regex Engine**: Go standard library `regexp` package
2. **Anchoring**: Patterns are NOT auto-anchored (user must use ^...$ for full match)
3. **Case Sensitivity**: Default case-sensitive, use `(?i)` flag for case-insensitive
4. **Type Requirement**: Field MUST be string
5. **Compilation**: Regex MUST be pre-compiled in Condition struct

**Test Requirements**:
```
MUST match:     field="user@example.com", pattern=".*@.*"
MUST match:     field="ERROR 404", pattern="(?i)error" (case-insensitive flag)
MUST NOT match: field="user@example.com", pattern="^example.com$" (not full match)
MUST handle:    field=12345, pattern=".*" → FALSE (non-string field)
```

**Security Considerations**:
- **ReDoS Protection**: Regex MUST have reasonable timeout (not currently implemented)
- **Complexity Limits**: Consider max pattern length and complexity (TBD)

**Implementation Location**: `detect/engine.go:evaluateCondition()` line 407-413
**Current Implementation**: Uses pre-compiled `cond.Regex.MatchString(str)`
**Compliance Status**: ⚠️ NEEDS VALIDATION - No ReDoS protection detected

**Validation Test Required**: `TestRuleEngine_RegexOperator_SigmaCompliance`

**TBD - Security Requirements**:
- [ ] **Decision Needed**: Regex timeout value (OWNER: Security Team, DEADLINE: Week 2)
- [ ] **Decision Needed**: Max regex pattern length (OWNER: Performance Team, DEADLINE: Week 2)
- [ ] **Decision Needed**: ReDoS detection strategy (OWNER: Security Team, DEADLINE: Week 3)

---

### 2.7 Comparison Operators (>, <, >=, <=)

**Specification Reference**: [SigmaHQ Specification - Numeric Comparison](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#numeric-comparison)
**Semantic Requirement**: Numeric comparison with type coercion

**REQUIRED Behavior**:

#### 2.7.1 Type Coercion Rules

**TBD - Critical Decision Required**:
```
Question: How should string "10" compare to number 10?

Option A: Strict typing (string ≠ number, comparison fails)
  - Pro: Type safety, predictable behavior
  - Con: Inflexible, may miss valid detections

Option B: Numeric coercion (parse string as number if possible)
  - Pro: Flexible, handles varied data sources
  - Con: May hide data quality issues

DECISION NEEDED:
  - Owner: Detection Engineering Team
  - Deadline: Week 1 (blocks all numeric comparison tests)
  - Recommendation: Review Sigma reference implementation
```

**Current Implementation Analysis**:
```go
// detect/engine.go:compareNumbers() line 427
// Attempts to parse strings as float64
if str, ok := a.(string); ok {
    if parsed, err := strconv.ParseFloat(str, 64); err == nil {
        fa = parsed
    } else {
        return false  // Parse failure = comparison fails
    }
}
```

**Observed Behavior**: Attempts type coercion (Option B)
**Compliance Status**: ⚠️ UNKNOWN - Need Sigma spec confirmation

#### 2.7.2 Operator Semantics

**greater_than (>)**:
```
MUST return TRUE:  10 > 5, 10.1 > 10, -5 > -10
MUST return FALSE: 10 > 10, 5 > 10, -10 > -5
```

**less_than (<)**:
```
MUST return TRUE:  5 < 10, -10 < -5
MUST return FALSE: 10 < 10, 10 < 5
```

**greater_than_or_equal (>=)**:
```
MUST return TRUE:  10 >= 10, 10 >= 5
MUST return FALSE: 5 >= 10
```

**less_than_or_equal (<=)**:
```
MUST return TRUE:  10 <= 10, 5 <= 10
MUST return FALSE: 10 <= 5
```

**Implementation Location**: `detect/engine.go:evaluateCondition()` lines 414-421
**Validation Test Required**: `TestRuleEngine_NumericComparisons_SigmaCompliance`

**TBD - Floating Point Precision**:
```
Question: How to handle floating point comparison precision?

Example: Is 0.1 + 0.2 == 0.3? (Actually 0.30000000000000004 in float64)

DECISION NEEDED:
  - Owner: Detection Engineering Team
  - Deadline: Week 1
  - Options:
    1. Exact comparison (current): May cause false negatives
    2. Epsilon comparison: Add small tolerance (e.g., 0.000001)
    3. Decimal type: Use precise decimal library
```

---

## 3. TYPE HANDLING REQUIREMENTS

### 3.1 String vs Number Comparison

**Specification Reference**: [SigmaHQ Sigma-Specification - Type System](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md)

**TBD - Needs Specification Review**:
```
The Sigma specification may or may not define explicit type handling.
If undefined in spec, we must define our own requirements.

RESEARCH NEEDED:
1. Review Sigma reference implementation (pySigma)
2. Test common Sigma rules against reference implementation
3. Document observed behavior
4. Make implementation decision

Owner: Detection Engineering Team
Deadline: Week 2
```

**Test Requirements** (pending decision):
- [ ] String "10" vs Number 10 comparison behavior
- [ ] String "10.5" vs Number 10.5 comparison behavior
- [ ] String "not a number" vs Number comparison behavior
- [ ] Boolean true/false handling
- [ ] Null/nil value handling

---

## 4. MISSING FIELD BEHAVIOR

### 4.1 Nil Field Values

**Specification Reference**: [SigmaHQ Detection Logic](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#detection)
**Requirement**: When field does not exist, condition evaluates to FALSE (not error)

**REQUIRED Behavior**:
1. **Top-Level Missing Field**: `event.nonexistent_field` → nil → condition returns FALSE
2. **Nested Missing Field**: `event.user.nonexistent` → nil → condition returns FALSE
3. **Not Equals Special Case**: `field not_equals "value"` when field=nil → TRUE (nil ≠ value)
4. **No Errors**: Missing fields MUST NOT cause errors or panics

**Test Requirements**:
```
MUST return FALSE: event={}, condition={field: "missing", operator: "equals", value: "anything"}
MUST return TRUE:  event={}, condition={field: "missing", operator: "not_equals", value: "anything"}
MUST return FALSE: event={user: {}}, condition={field: "user.missing", operator: "contains", value: "x"}
MUST NOT panic:    event={}, condition={field: "a.b.c.d.e.f", operator: "equals", value: "x"}
```

**Implementation Location**: `detect/engine.go:getFieldValue()` line 461
**Current Implementation**: Returns `nil` for missing fields
**Compliance Status**: ✅ APPEARS COMPLIANT - Verify in all edge cases

**Validation Test Required**: `TestRuleEngine_MissingFields_SigmaCompliance`

---

## 5. EDGE CASES MATRIX

| Scenario | Expected Behavior | Sigma Spec Reference | Test Name | Priority |
|----------|-------------------|---------------------|-----------|----------|
| **Null/Nil Values** |
| Field value is nil | FALSE (all operators except not_equals) | Detection section | TestEngine_NilValue | HIGH |
| Field value is Go nil interface | FALSE | Detection section | TestEngine_NilInterface | HIGH |
| Comparison with nil | FALSE | Detection section | TestEngine_NilComparison | HIGH |
| **Empty Strings** |
| Field="" equals "" | TRUE | String matching | TestEngine_EmptyStringEquals | HIGH |
| Field="" contains "" | TRUE | String matching | TestEngine_EmptyStringContains | HIGH |
| Field="" starts_with "" | TRUE | String matching | TestEngine_EmptyStringPrefix | MEDIUM |
| **Unicode & Encoding** |
| UTF-8 emoji matching | Full support | String matching | TestEngine_UnicodeEmoji | MEDIUM |
| Multi-byte characters | Full support | String matching | TestEngine_MultiByteChars | MEDIUM |
| Case folding (ä vs Ä) | Case-sensitive | String matching | TestEngine_UnicodeCaseFolding | MEDIUM |
| **Special Characters** |
| Regex special chars in contains | Treated as literals | String matching | TestEngine_RegexSpecialCharsLiteral | HIGH |
| Newline in field value | Supported | String matching | TestEngine_NewlineInField | MEDIUM |
| Null bytes | **SECURITY RISK** | N/A | TestEngine_NullByteRejection | CRITICAL |
| **Nested Structures** |
| Nested 10 levels deep | Should work | Detection | TestEngine_DeepNesting | MEDIUM |
| Nested field missing mid-path | FALSE | Detection | TestEngine_NestedMissingMidPath | HIGH |
| Array indexing | TBD (not in Sigma spec?) | TBD | TestEngine_ArrayIndexing | LOW |
| **Performance & Limits** |
| Field value 1MB string | Handle or reject gracefully | N/A | TestEngine_LargeFieldValue | MEDIUM |
| Regex ReDoS attack | MUST timeout | N/A | TestEngine_RegexReDoSProtection | CRITICAL |
| 1000 conditions in rule | Performance acceptable | N/A | TestEngine_ManyConditions | LOW |

---

## 6. LOGICAL OPERATORS (AND/OR)

### 6.1 AND Logic

**Specification Reference**: [SigmaHQ Detection Logic](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#detection)
**Requirement**: All conditions with AND logic must be TRUE

**REQUIRED Behavior**:
```
Condition1 AND Condition2:
  TRUE  AND TRUE  → TRUE
  TRUE  AND FALSE → FALSE
  FALSE AND TRUE  → FALSE
  FALSE AND FALSE → FALSE
```

**Short-Circuit Evaluation**:
- **TBD - Performance Decision**: Should evaluation stop at first FALSE?
- **Current Implementation**: No short-circuit (evaluates all conditions)
- **Decision Needed**: Performance vs. debugging (OWNER: Performance Team, DEADLINE: Week 2)

**Implementation Location**: `detect/engine.go:evaluateRule()` line 362-370
**Compliance Status**: ⚠️ VERIFY - Check if short-circuit expected by Sigma

---

### 6.2 OR Logic

**Specification Reference**: [SigmaHQ Detection Logic](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#detection)
**Requirement**: At least one condition with OR logic must be TRUE

**REQUIRED Behavior**:
```
Condition1 OR Condition2:
  TRUE  OR TRUE  → TRUE
  TRUE  OR FALSE → TRUE
  FALSE OR TRUE  → TRUE
  FALSE OR FALSE → FALSE
```

**Short-Circuit Evaluation**:
- **TBD - Performance Decision**: Should evaluation stop at first TRUE?
- **Current Implementation**: No short-circuit (evaluates all conditions)

**Implementation Location**: `detect/engine.go:evaluateRule()` line 362-370

---

## 7. COMPLIANCE VERIFICATION CHECKLIST

Before declaring Sigma compliance complete, ALL items must be checked:

### 7.1 Operator Compliance
- [ ] equals operator tested per spec (case sensitivity, exact match)
- [ ] not_equals operator tested per spec (negation semantics)
- [ ] contains operator tested per spec (substring, case-sensitive)
- [ ] startswith operator tested per spec (prefix matching)
- [ ] endswith operator tested per spec (suffix matching)
- [ ] regex operator tested per spec (Go regexp, no auto-anchor)
- [ ] greater_than operator tested per spec (numeric comparison)
- [ ] less_than operator tested per spec (numeric comparison)
- [ ] greater_than_or_equal tested per spec
- [ ] less_than_or_equal tested per spec

### 7.2 Type Handling Compliance
- [ ] String vs String comparison verified
- [ ] Number vs Number comparison verified
- [ ] String vs Number comparison behavior documented and tested
- [ ] Type coercion rules documented
- [ ] Float precision handling decided and tested
- [ ] Boolean handling (if applicable) documented and tested

### 7.3 Edge Case Compliance
- [ ] Missing field returns FALSE (not error)
- [ ] Nil value handling verified
- [ ] Empty string handling verified
- [ ] Unicode support verified (UTF-8)
- [ ] Special characters in strings verified
- [ ] Null byte rejection verified (SECURITY)
- [ ] Nested field navigation verified
- [ ] Deep nesting (10+ levels) verified

### 7.4 Logical Operator Compliance
- [ ] AND operator logic verified
- [ ] OR operator logic verified
- [ ] Multiple conditions with mixed AND/OR verified
- [ ] Short-circuit behavior documented (even if not implemented)

### 7.5 Performance Compliance
- [ ] Regex ReDoS protection implemented or documented as TBD
- [ ] Large field value handling verified
- [ ] Performance benchmarks within acceptable limits
- [ ] Memory usage tested with large rules

### 7.6 Security Compliance
- [ ] Regex ReDoS attack protection
- [ ] Null byte injection prevention
- [ ] No panic on malformed input
- [ ] No information disclosure in error messages

---

## 8. TEST REQUIREMENTS SUMMARY

### 8.1 Required Test Files

All tests MUST reference this document and specific section numbers.

1. **TestRuleEngine_EqualsOperator_SigmaCompliance**
   - Location: `detect/engine_test.go`
   - References: Section 2.1
   - Coverage: Case sensitivity, exact match, type handling

2. **TestRuleEngine_NotEqualsOperator_SigmaCompliance**
   - Location: `detect/engine_test.go`
   - References: Section 2.2
   - Coverage: Negation logic, nil handling

3. **TestRuleEngine_ContainsOperator_SigmaCompliance**
   - Location: `detect/engine_test.go`
   - References: Section 2.3
   - Coverage: Substring matching, case sensitivity, type checking

4. **TestRuleEngine_StringOperators_SigmaCompliance**
   - Location: `detect/engine_test.go`
   - References: Sections 2.4, 2.5
   - Coverage: startswith, endswith operators

5. **TestRuleEngine_RegexOperator_SigmaCompliance**
   - Location: `detect/engine_test.go`
   - References: Section 2.6
   - Coverage: Regex matching, ReDoS protection

6. **TestRuleEngine_NumericOperators_SigmaCompliance**
   - Location: `detect/engine_test.go`
   - References: Section 2.7
   - Coverage: All comparison operators, type coercion

7. **TestRuleEngine_MissingFields_SigmaCompliance**
   - Location: `detect/engine_test.go`
   - References: Section 4
   - Coverage: Nil handling, nested missing fields

8. **TestRuleEngine_EdgeCases_SigmaCompliance**
   - Location: `detect/engine_test.go`
   - References: Section 5
   - Coverage: All edge cases from matrix

9. **TestRuleEngine_LogicalOperators_SigmaCompliance**
   - Location: `detect/engine_test.go`
   - References: Section 6
   - Coverage: AND/OR logic

---

## 9. TBD TRACKER - DECISIONS NEEDED

All TBDs MUST be resolved before tests can be finalized.

| Item | Question | Owner | Deadline | Options | Status |
|------|----------|-------|----------|---------|--------|
| TBD-001 | Type coercion for string vs number | Detection Team | Week 1 | Strict / Coercion | OPEN |
| TBD-002 | Float comparison precision | Detection Team | Week 1 | Exact / Epsilon / Decimal | OPEN |
| TBD-003 | Regex timeout value | Security Team | Week 2 | 100ms / 1s / 10s | OPEN |
| TBD-004 | Max regex pattern length | Security Team | Week 2 | 1KB / 10KB / Unlimited | OPEN |
| TBD-005 | ReDoS detection strategy | Security Team | Week 3 | Timeout / Static analysis / Both | OPEN |
| TBD-006 | Short-circuit AND evaluation | Performance Team | Week 2 | Yes / No | OPEN |
| TBD-007 | Short-circuit OR evaluation | Performance Team | Week 2 | Yes / No | OPEN |
| TBD-008 | Array indexing support | Detection Team | Week 3 | Support / Not supported | OPEN |
| TBD-009 | Max field nesting depth | Performance Team | Week 2 | 10 / 20 / Unlimited | OPEN |
| TBD-010 | Max field value size | Security Team | Week 2 | 1MB / 10MB / Unlimited | OPEN |

---

## 10. REFERENCES

### 10.1 Authoritative Sources

1. **Sigma Specification**: https://github.com/SigmaHQ/sigma-specification
   - Primary authoritative source for all Sigma semantics
   - Version: 1.0.0 (verify current version)

2. **Sigma Reference Implementation** (pySigma): https://github.com/SigmaHQ/pySigma
   - Reference implementation for undefined specification areas
   - Use to verify type handling and edge cases

3. **Sigma Rule Collection**: https://github.com/SigmaHQ/sigma
   - Real-world examples to test compliance
   - Use for integration testing

### 10.2 Go Language References

1. **Go regexp Package**: https://pkg.go.dev/regexp
   - Regex engine used by Cerberus
   - RE2 syntax, guarantees linear time execution

2. **Go strings Package**: https://pkg.go.dev/strings
   - String manipulation functions
   - Contains, HasPrefix, HasSuffix semantics

### 10.3 Internal Documents

1. **BACKEND_TEST_REMEDIATIONS.md**: Master remediation plan
2. **detect/engine.go**: Implementation file
3. **detect/engine_test.go**: Test file (to be remediated)

---

## APPENDIX A: CURRENT IMPLEMENTATION GAPS

Based on code review of `detect/engine.go`:

### Confirmed Gaps:
1. **No ReDoS Protection**: Regex matching has no timeout
2. **No Input Size Limits**: Fields can be arbitrarily large
3. **No Type Validation**: No explicit type checking before operations
4. **No Float Precision Handling**: Direct float64 comparison
5. **No Short-Circuit Evaluation**: All conditions evaluated even if result known

### Potential Gaps (Need Specification Verification):
1. **Type Coercion**: Currently attempts to parse strings as numbers - is this correct?
2. **Case Insensitive Matching**: Not supported - is this required?
3. **Modifier Support**: No support for Sigma modifiers (|contains, |endswith, etc.)
4. **Null Byte Handling**: Not explicitly rejected - security risk?

---

**Document Status**: DRAFT
**Next Review Date**: Week 1 (after TBD decisions)
**Approver**: Technical Lead + Security Lead
**Version**: 1.0-DRAFT
