# ADR-001: Sigma Rule Type Coercion Behavior

**Status**: ACCEPTED
**Date**: 2025-11-16
**Deciders**: Architecture Team
**Priority**: P0 (Blocker Resolution)

## Context

Sigma rules may compare event fields of different types (e.g., string "4624" vs integer 4624).
The Sigma specification does not mandate specific type coercion behavior, leading to ambiguity.

### Example Scenario
```yaml
# Sigma Rule
detection:
  selection:
    EventID: 4624  # Integer in YAML
  condition: selection
```

If the event contains `EventID: "4624"` (string), should it match the rule's integer 4624?

### Problem Statement
Without a clear decision, Cerberus behavior is undefined:
- Should string "4624" match integer 4624?
- Should string "01" match integer 1?
- What about float 4624.0 vs integer 4624?
- How do we handle type mismatches in comparisons (<, >, <=, >=)?

This ambiguity blocks production deployment and creates security risks:
1. **False Negatives**: Critical detections may fail due to type mismatches
2. **False Positives**: Unexpected coercions may trigger spurious alerts
3. **Unpredictability**: Rule behavior varies based on event source formatting

## Decision

**Cerberus v1.0 will use STRICT TYPING (no automatic type coercion):**
- String "4624" ≠ Integer 4624
- All comparisons require exact type match
- Rule authors must ensure correct field typing in rules

### Strict Typing Semantics

| Event Value | Rule Value | Operator | Result | Reason |
|-------------|------------|----------|--------|--------|
| "4624" (string) | 4624 (int) | = | **FALSE** | Type mismatch |
| 4624 (int) | 4624 (int) | = | **TRUE** | Exact match |
| "4624" (string) | "4624" (string) | = | **TRUE** | Exact match |
| 4624.0 (float) | 4624 (int) | = | **FALSE** | Type mismatch |
| "abc" (string) | 123 (int) | > | **FALSE** | Type mismatch (no comparison) |

## Rationale

### Technical Justification

1. **Predictability**
   - Behavior is unambiguous and easy to understand
   - No hidden conversion rules to memorize
   - Debugging is straightforward (types either match or don't)

2. **Performance**
   - Zero conversion overhead on every comparison
   - No type inference or reflection needed
   - Faster rule evaluation (critical for high-throughput SIEM)

3. **Correctness**
   - Prevents silent bugs from unexpected coercions
   - Example: "01" should NOT equal 1 in security contexts (leading zeros often significant)
   - No ambiguity in edge cases (0x10, "1e3", etc.)

4. **Spec Compliance**
   - Sigma specification does not mandate type coercion
   - Reference implementations (sigmac, pySigma) vary in behavior
   - Choosing strict typing is a valid interpretation

5. **Existing Implementation**
   - Current Cerberus codebase already uses strict typing (Go's native == operator)
   - No breaking changes to existing deployments
   - Codifies existing behavior as official policy

### Security Considerations

Type coercion can create security vulnerabilities:

```yaml
# DANGER: Lenient coercion could miss attacks
detection:
  selection:
    user_id: 0  # Intended to match integer 0 (admin account)
  condition: selection
```

With lenient coercion:
- Event: `user_id: "0000"` → Matches (coerced to 0) ✓ Expected
- Event: `user_id: ""` → **Matches** (empty string coerced to 0) ❌ VULNERABILITY
- Event: `user_id: "0x0"` → **Matches** (hex coerced to 0) ❌ UNEXPECTED

Strict typing prevents these false positives.

## Consequences

### Positive

✓ **Predictable**: No surprises, behavior is explicit
✓ **Performant**: No overhead from type conversion
✓ **Secure**: Prevents coercion-based bypasses
✓ **Debuggable**: Type mismatches are clearly visible
✓ **Spec-Compliant**: Valid Sigma interpretation

### Negative

❌ **Rule Author Burden**: Authors must use correct types
❌ **Migration Effort**: Users from lenient systems may need rule updates
❌ **False Negatives**: Type mismatches won't match (but this is explicit)

### Mitigation Strategies

1. **Documentation**: Clear guide on field type requirements
2. **Validation**: Rule validation warns about common type issues
3. **Field Normalization**: Ingest pipeline can normalize field types
4. **Future Enhancement**: Optional lenient mode (v2.0+) if user demand exists

## Alternatives Considered

### Option B: Lenient Coercion (Rejected)

**Approach**: Auto-convert types ("4624" == 4624)

**Pros**:
- More forgiving for rule authors
- Handles varied log formats automatically

**Cons**:
- Ambiguous edge cases ("01" == 1? "0x10" == 16?)
- Performance overhead on every comparison
- Security risks (see above)
- Harder to debug (hidden conversions)

**Decision**: Rejected due to complexity and security concerns

### Option C: Hybrid Coercion (Rejected)

**Approach**: Numeric strings coerce to numbers only

**Rules**:
- "123" == 123 → TRUE (numeric string)
- "abc" == 123 → FALSE (non-numeric)
- "01" == 1 → ? (ambiguous)

**Decision**: Too complex for v1.0. Can revisit post-launch if needed.

## Implementation

### Code Impact

No changes required. Current implementation already uses strict typing:

```go
// detect/engine.go (existing behavior)
func compareValues(field, value interface{}) bool {
    return field == value  // Go's == is strict by default
}
```

### Test Coverage

New test suite `detect/engine_sigma_type_test.go` documents and verifies behavior:
- String vs Int comparisons → FALSE
- Same-type comparisons → TRUE
- Float vs Int → FALSE
- Numeric strings → No coercion

## Future Work

- **P2 Enhancement**: Add optional `lenient_typing: true` config flag if user demand exists
- **Documentation**: Update rule authoring guide with type requirements
- **Tooling**: Add rule linter to warn about potential type mismatches
- **Field Mapping**: Enhance field mapping to specify expected types

## References

- **Issue**: TBD-001 (Type Coercion Ambiguity)
- **Sigma Spec**: https://github.com/SigmaHQ/sigma
- **Test Suite**: `detect/engine_sigma_type_test.go`
- **Related**: ADR-002 (Float Precision Handling)

## Review History

| Date | Reviewer | Decision |
|------|----------|----------|
| 2025-11-16 | golang-architect | Approved |

---

*This ADR resolves P0 blocker TBD-001 by establishing clear, predictable type coercion semantics for Cerberus v1.0.*
