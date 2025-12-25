# ADR-002: Float Precision Handling

**Status**: ACCEPTED
**Date**: 2025-11-16
**Deciders**: Architecture Team
**Priority**: P0 (Blocker Resolution)

## Context

Floating-point arithmetic in modern computers follows the IEEE 754 standard, which has well-known precision limitations that can cause unexpected comparison failures.

### The Problem

```go
// Classic IEEE 754 precision issue
fmt.Println(0.1 + 0.2 == 0.3)  // Output: false
fmt.Println(0.1 + 0.2)          // Output: 0.30000000000000004
```

In SIEM rule evaluation, this causes **false negatives**:

```yaml
# Sigma Rule: Detect high CPU usage
detection:
  selection:
    cpu_usage_percent: 0.3  # Trigger on 30% CPU
  condition: selection
```

Without proper float handling:
- Event: `cpu_usage_percent: 0.30000000000000004` (from 0.1 + 0.2 calculation)
- Rule: `cpu_usage_percent: 0.3`
- Result: **NO MATCH** ❌ (False negative - critical alert missed!)

### Impact

This is a **P0 blocker** because:
1. **Security**: Critical alerts may be missed due to precision mismatches
2. **Usability**: Rules behave unpredictably with float comparisons
3. **Correctness**: Mathematical operations create non-matching values
4. **Production**: Blocks deployment of float-based detection rules

## Decision

**Use epsilon comparison with ε = 1e-9 for all float comparisons.**

Two floats `a` and `b` are considered "equal" if:
```
|a - b| < 1e-9
```

## Rationale

### Why Epsilon Comparison?

Epsilon comparison is the **industry standard** for handling IEEE 754 precision:

1. **Scientific Computing**: NumPy, MATLAB, and scientific libraries use epsilon
2. **Game Development**: Unity, Unreal Engine use epsilon for physics comparisons
3. **Financial Systems**: Trading platforms use epsilon for price comparisons
4. **Testing Frameworks**: JUnit, pytest use epsilon for float assertions

### Why ε = 1e-9?

| Epsilon | Too Small? | Too Large? | Use Case |
|---------|------------|------------|----------|
| 1e-15 | ✓ | | Double-precision limits |
| 1e-12 | | | High-precision science |
| **1e-9** | | | **SIEM metrics (CPU, memory, latency)** |
| 1e-6 | | | Engineering tolerances |
| 1e-3 | | ✓ | Too coarse for most uses |

**1e-9 is ideal for SIEM** because:
- **Small enough**: Distinguishes meaningful differences (1% = 0.01, well above epsilon)
- **Large enough**: Absorbs IEEE 754 rounding errors from arithmetic
- **Practical**: Handles metrics like CPU% (0.0-1.0), latency (ms), throughput

### Examples

```go
// ✓ CORRECT: Handles IEEE 754 rounding
floatEqual(0.1 + 0.2, 0.3) → true

// ✓ CORRECT: Detects real differences
floatEqual(0.1, 0.2) → false  // Diff: 0.1 >> 1e-9

// ✓ CORRECT: Epsilon-close values treated as equal
floatEqual(1.0, 1.0000000001) → true  // Diff: 1e-10 < 1e-9

// ✓ CORRECT: Values beyond epsilon are distinct
floatEqual(1.0, 1.00001) → false  // Diff: 1e-5 > 1e-9
```

## Implementation

### Core Functions

```go
// Float comparison epsilon (1e-9)
const floatEpsilon = 1e-9

// Equality with epsilon
func floatEqual(a, b float64) bool {
    return math.Abs(a - b) < floatEpsilon
}

// Comparison operators with epsilon
func compareFloat(a, b float64, op string) bool {
    switch op {
    case "=":
        return floatEqual(a, b)
    case "!=":
        return !floatEqual(a, b)
    case ">":
        return a > b && !floatEqual(a, b)
    case ">=":
        return a > b || floatEqual(a, b)
    case "<":
        return a < b && !floatEqual(a, b)
    case "<=":
        return a < b || floatEqual(a, b)
    }
}
```

### Comparison Semantics

| Operator | Semantics | Example |
|----------|-----------|---------|
| `=` | Equal within epsilon | `0.1+0.2 = 0.3` → TRUE |
| `!=` | Different beyond epsilon | `0.1 != 0.2` → TRUE |
| `>` | Strictly greater (not within epsilon) | `0.3 > 0.3` → FALSE |
| `>=` | Greater OR equal within epsilon | `0.3 >= 0.3` → TRUE |
| `<` | Strictly less (not within epsilon) | `0.3 < 0.3` → FALSE |
| `<=` | Less OR equal within epsilon | `0.3 <= 0.3` → TRUE |

### Integration Points

1. **Sigma Rule Evaluation** (`detect/engine.go`):
   - Use `compareFloat` for float field comparisons
   - Apply epsilon to threshold checks

2. **CQL Query Evaluation** (`detect/cql_correlation.go`):
   - Use `compareFloat` for numeric conditions
   - Handle aggregations (AVG, SUM) with epsilon

3. **Alert Thresholds** (`core/alert.go`):
   - Compare alert scores with epsilon
   - Prevent threshold boundary issues

## Consequences

### Positive

✓ **Correctness**: Float comparisons work as expected
✓ **Security**: No false negatives from precision issues
✓ **Usability**: Rules behave predictably with floats
✓ **Standard Practice**: Industry-standard solution
✓ **Performance**: Minimal overhead (single subtraction + comparison)

### Negative

❌ **Edge Case**: Values within epsilon are treated as equal
- **Example**: 1.0 and 1.0000000001 are "equal"
- **Mitigation**: 1e-9 is sufficiently small for SIEM use cases

❌ **Not Suitable for Exact Math**: Cryptography, financial cents, etc.
- **Mitigation**: Document that exact precision requires integer/decimal types

### Limitations

1. **Not for Cryptography**: Epsilon comparison is WRONG for cryptographic values
   - **Use Case**: Comparing hashes, signatures, keys
   - **Requirement**: Exact bit-for-bit equality
   - **Solution**: Use byte arrays, not floats

2. **Not for Financial Cents**: Money should use integers (cents)
   - **Example**: $0.10 + $0.20 = $0.30 (use cents: 10 + 20 = 30)
   - **Solution**: Store as integers, divide by 100 for display

3. **Epsilon is Absolute, Not Relative**: May be too large for very small numbers
   - **Example**: Comparing 1e-20 and 2e-20 (1e-9 epsilon is huge)
   - **SIEM Impact**: Negligible (metrics are typically 0-100 range)

## Alternatives Considered

### Option A: Exact Comparison (Rejected)

**Approach**: Use `a == b` directly (no epsilon)

**Rejected because**:
- ❌ Breaks for IEEE 754 arithmetic (`0.1 + 0.2 != 0.3`)
- ❌ Causes false negatives in rule matching
- ❌ Unpredictable behavior frustrates users

### Option B: Relative Epsilon (Rejected)

**Approach**: `|a - b| < epsilon * max(|a|, |b|)`

**Rejected because**:
- Fails at zero: `max(0, 0) = 0 → epsilon * 0 = 0` (no tolerance)
- More complex than needed for SIEM use cases
- Absolute epsilon suffices for typical metrics (0-100 range)

### Option C: Decimal Type (Rejected for v1.0)

**Approach**: Use arbitrary-precision decimal library

**Rejected because**:
- Performance overhead (10x-100x slower than float)
- Most SIEM metrics don't require exact precision
- Can add later if specific use case demands it

## Future Work

- **P2**: Add relative epsilon comparison if sub-1e-9 precision needed
- **P2**: Document field types requiring exact precision
- **P2**: Add linter warning for float comparison without epsilon
- **P3**: Consider decimal type for specific high-precision fields

## References

- **Issue**: TBD-002 (Float Precision Blocker)
- **Implementation**: `detect/engine.go` lines 753-837
- **Test Suite**: `detect/engine_float_precision_test.go`
- **Related**: ADR-001 (Type Coercion - specifies when to use epsilon)

## Review History

| Date | Reviewer | Decision |
|------|----------|----------|
| 2025-11-16 | golang-architect | Approved |

---

*This ADR resolves P0 blocker TBD-002 by establishing predictable, correct float comparison semantics for Cerberus v1.0.*
