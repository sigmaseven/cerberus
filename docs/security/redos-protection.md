# ReDoS Protection: Implementation and Limitations

## Overview

Cerberus SIEM implements multiple layers of protection against Regular Expression Denial of Service (ReDoS) attacks. This document describes the protection mechanisms, their limitations, and recommendations for safe regex usage.

## Threat Model

**ReDoS (Regular Expression Denial of Service)** is a vulnerability where a malicious regular expression pattern causes exponential time complexity, leading to CPU exhaustion and service unavailability.

**CWE-1333**: Inefficient Regular Expression Complexity  
**OWASP ASVS V5.1.5**: Regular expression ReDoS vulnerability

### Attack Vector

An attacker could craft malicious regex patterns or provide malicious input that causes catastrophic backtracking, consuming excessive CPU resources.

**Example Attack Pattern**:
- Pattern: `(a+)+b`
- Malicious Input: `aaaaaaaaaaaaaaaaac` (many 'a' characters followed by 'c')
- Result: Exponential backtracking, CPU exhaustion

## Protection Layers

### Layer 1: Go RE2 Engine (Primary Protection)

**Location**: `regexp` package (standard library)

**Mechanism**: Go's `regexp` package uses the RE2 engine, which provides **linear time complexity guarantees**. RE2 does not support backtracking, which prevents exponential time complexity attacks.

**Limitations**:
- RE2 does not support all Perl-compatible regex features (e.g., backreferences, lookahead/lookbehind assertions)
- Some patterns may need to be rewritten for RE2 compatibility
- RE2's linear time guarantee applies to matching, but compilation still requires validation

**Status**: ✅ **ACTIVE** - Built into Go standard library

### Layer 2: Regex Timeout Wrapper (Defense-in-Depth)

**Location**: `detect/regex_timeout.go`, `util/saferegex.go`

**Mechanism**: Timeout wrapper using `context.WithTimeout()` and goroutines enforces a maximum execution time for regex matching operations.

**Implementation**:
```go
// Default timeout: 100ms (configurable via config.yaml)
RegexWithTimeout(pattern, input, timeout time.Duration) (bool, error)
```

**Configuration**:
- **Default timeout**: 100ms
- **Configurable**: `security.regex_timeout` in `config.yaml`
- **Range**: 10ms - 5000ms (validated in config)
- **Location**: `config/config.go` (Security struct)

**Limitations**:
1. **Goroutine Overhead**: Each regex evaluation spawns a goroutine, which adds ~1-5ms overhead
2. **Resource Leaks**: If goroutines do not complete before timeout, they may continue running until completion (mitigated by defer/cancel, but goroutine may still run)
3. **Timeout Precision**: Timeout is enforced at the goroutine level, not at the regex engine level - a runaway regex may still consume CPU until timeout
4. **Concurrent Execution**: Multiple concurrent regex evaluations may still consume CPU if all timeout simultaneously
5. **No Pattern Pre-Validation**: Timeout only catches issues at runtime, not at pattern compilation time

**Status**: ✅ **ACTIVE** - Implemented in `detect/regex_timeout.go` and `util/saferegex.go`

### Layer 3: Static Complexity Analysis (Prevention)

**Location**: `util/saferegex.go`

**Mechanism**: Static analysis of regex patterns to detect dangerous constructs before compilation and execution.

**Checks**:
1. **Nested Quantifiers**: Detects patterns like `(a*)*`, `(a+)+`, `(a?)?` which can cause catastrophic backtracking
2. **Excessive Nesting Depth**: Maximum nesting depth of 3 levels (configurable in code)
3. **Pattern Length**: Maximum pattern length of 200 characters (warning only)

**Functions**:
- `ValidateComplexity(pattern string) error`: Validates pattern complexity
- `CompileSafe(pattern string) (*regexp.Regexp, error)`: Compiles pattern with validation
- `AnalyzePattern(pattern string) ComplexityReport`: Provides complexity report

**Limitations**:
1. **Pattern Detection**: Static analysis may not catch all dangerous patterns - it uses pattern matching, not full AST analysis
2. **False Positives**: Some legitimate patterns may be flagged (e.g., `([0-9]*)?` for optional numbers)
3. **False Negatives**: Complex attack patterns may evade detection
4. **Not Enforced**: Complexity validation is not automatically applied - must be called explicitly via `CompileSafe()`
5. **Limited Scope**: Only checks for nested quantifiers and nesting depth - does not analyze alternation complexity or other attack vectors

**Status**: ⚠️ **PARTIAL** - Implemented but not automatically enforced everywhere

## Integration Points

### 1. Sigma Rule Engine

**Location**: `detect/engine.go`

**Integration**: Regex conditions in Sigma rules use `util.RegexWithTimeout()` with configurable timeout.

**Timeout**: Default 100ms (from config)

**Status**: ✅ **INTEGRATED**

### 2. CQL Query Evaluator

**Location**: `search/evaluator.go`

**Integration**: Regex operators (`=~`, `!~`) use `util.RegexWithTimeout()` with configurable timeout.

**Timeout**: Configurable (default 100ms)

**Status**: ✅ **INTEGRATED**

### 3. SOAR Playbook Executor

**Location**: `soar/executor.go`

**Integration**: Regex matching in conditional logic uses timeout wrapper.

**Timeout**: 500ms (hardcoded for playbook execution)

**Status**: ✅ **INTEGRATED**

## Limitations and Gaps

### Critical Limitations

1. **Not All Regex Operations Protected**: 
   - Direct `regexp.MatchString()` calls may bypass timeout wrapper
   - Third-party libraries may not use protected functions
   - Frontend regex validation (JavaScript) is not protected by backend timeouts

2. **Compilation-Time Attacks**:
   - Timeout wrapper only protects matching, not compilation
   - Malicious patterns may cause compilation to hang (rare, but possible)
   - Pattern compilation is not wrapped in timeout

3. **Goroutine Resource Leaks**:
   - Timed-out goroutines may continue running until completion
   - No cancellation mechanism for running regex operations
   - Potential for goroutine accumulation under attack

4. **No Rate Limiting**:
   - Multiple concurrent regex evaluations may still consume CPU
   - No per-user or per-IP rate limiting for regex operations
   - Attack could spawn many concurrent regex operations

5. **Pattern Validation Not Enforced**:
   - `ValidateComplexity()` must be called explicitly
   - Rule ingestion does not automatically validate patterns
   - Users can submit malicious patterns without validation

### Moderate Limitations

6. **Timeout Precision**:
   - Timeout is enforced at goroutine level, not regex engine level
   - Actual execution time may exceed timeout by goroutine scheduling overhead
   - No guarantee that regex stops immediately at timeout

7. **Complexity Analysis Gaps**:
   - Does not analyze alternation complexity (e.g., `(a|ab)*c`)
   - Does not detect overlapping alternatives
   - Does not analyze character class complexity

8. **Configuration**:
   - Timeout is global, not per-operation
   - Cannot set different timeouts for different operations (e.g., rules vs queries)
   - No way to disable timeout for trusted patterns

### Minor Limitations

9. **Performance Overhead**:
   - Goroutine creation adds ~1-5ms overhead per regex evaluation
   - Not suitable for high-frequency operations (>1000/sec per goroutine)
   - Context cancellation adds small overhead

10. **Error Handling**:
    - Timeout errors may be difficult to distinguish from other regex errors
    - No metrics for timeout frequency (would help detect attacks)

## Recommendations

### For Developers

1. **Always Use Protected Functions**:
   - Use `util.RegexWithTimeout()` for all regex matching operations
   - Use `util.CompileSafe()` for pattern compilation
   - Never call `regexp.MatchString()` directly

2. **Validate Patterns at Ingestion**:
   - Validate all user-provided patterns with `ValidateComplexity()`
   - Reject patterns with nested quantifiers
   - Limit pattern length and nesting depth

3. **Monitor Timeout Metrics**:
   - Track regex timeout frequency
   - Alert on high timeout rates (potential attack)
   - Log timeout occurrences for analysis

4. **Limit Concurrent Operations**:
   - Implement rate limiting for regex operations
   - Limit concurrent regex evaluations per user/IP
   - Use worker pools for regex evaluation

### For System Administrators

1. **Configure Appropriate Timeouts**:
   - Default 100ms is reasonable for most use cases
   - Adjust based on workload (higher for complex patterns, lower for simple)
   - Monitor timeout rates and adjust as needed

2. **Monitor System Resources**:
   - Monitor CPU usage for regex operations
   - Alert on sustained high CPU usage
   - Track goroutine counts for potential leaks

3. **Review Pattern Sources**:
   - Only accept patterns from trusted sources
   - Review all user-submitted patterns
   - Use allowlists for pattern sources if possible

### For Security Auditors

1. **Test ReDoS Protection**:
   - Test with known attack patterns (see examples below)
   - Verify timeout enforcement
   - Test concurrent regex operations

2. **Review Pattern Validation**:
   - Ensure all pattern ingestion points use validation
   - Verify complexity checks are applied
   - Test edge cases (long patterns, deep nesting)

3. **Assess Resource Limits**:
   - Verify timeout values are appropriate
   - Check for goroutine leaks under load
   - Test system behavior under attack

## Known Attack Patterns (Test Cases)

These patterns should be rejected or timeout when evaluated against malicious input:

1. **Nested Quantifiers**:
   - Pattern: `(a+)+b`
   - Input: `aaaaaaaaaaaaaaaaac` (many 'a' followed by 'c')
   - Expected: Timeout or rejection

2. **Alternation with Common Prefix**:
   - Pattern: `(a|ab)*c`
   - Input: `ababababababababababd` (repeated 'ab' followed by 'd')
   - Expected: Timeout or rejection

3. **Exponential Backtracking**:
   - Pattern: `(a|a)*b`
   - Input: `aaaaaaaaaaaaaaaaac` (many 'a' followed by 'c')
   - Expected: Timeout or rejection

4. **Deep Nesting**:
   - Pattern: `((((a*)*)*)*)*b`
   - Input: `ac`
   - Expected: Rejection (complexity validation)

## Configuration Reference

### config.yaml

```yaml
security:
  regex_timeout: 100ms  # Default: 100ms, Range: 10ms-5000ms
```

### Programmatic Configuration

```go
// In config/config.go
viper.SetDefault("security.regex_timeout", 100*time.Millisecond)
```

### Usage Examples

```go
// Safe regex compilation with validation
re, err := util.CompileSafe("pattern.*here")
if err != nil {
    // Handle complexity validation error
}

// Safe regex matching with timeout
match, err := util.RegexWithTimeout("pattern.*here", "input string", 100*time.Millisecond)
if err != nil {
    // Handle timeout or other error
}
```

## Related Documentation

- `TASK2_REDOS_PROTECTION_IMPLEMENTATION.md`: Implementation details
- `docs/requirements/security-threat-model.md`: Security threat model
- `docs/requirements/performance-sla-requirements.md`: Performance requirements

## Status

**Implementation Status**: ✅ **COMPLETE** (with known limitations)  
**Protection Level**: 🟡 **MODERATE** (multiple layers, but gaps exist)  
**Production Ready**: ✅ **YES** (with monitoring and configuration)

## Version History

- **2025-01-XX**: Initial implementation (Task 32)
- **2025-01-XX**: Documentation created (Task 49)

---

**Document Owner**: Security Team  
**Last Updated**: 2025-01-XX  
**Review Frequency**: Quarterly


