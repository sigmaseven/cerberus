# Requirements Documentation - Phase 1 Complete

**Status**: ✅ DRAFT COMPLETE - Pending Technical Review
**Completion Date**: 2025-11-16
**Total Documents**: 7
**Total Size**: ~125,000 words

---

## Quick Navigation

### Requirement Documents (By Priority)

1. **[security-threat-model.md](security-threat-model.md)** ⚠️ **READ FIRST - CRITICAL SECURITY GAPS**
   - 2 CRITICAL vulnerabilities found (SSRF, ReDoS)
   - Blocks production deployment until fixed
   - ~25,000 words

2. **[sigma-compliance.md](sigma-compliance.md)** 📋 **Core Functionality**
   - Defines how rule engine MUST behave
   - Required for all rule evaluation tests
   - ~20,000 words

3. **[circuit-breaker-requirements.md](circuit-breaker-requirements.md)** 🔄 **Reliability**
   - State machine specification
   - Required for circuit breaker tests
   - ~18,000 words

4. **[storage-acid-requirements.md](storage-acid-requirements.md)** 💾 **Data Integrity**
   - SQLite ACID guarantees
   - ClickHouse limitations documented
   - Critical: Foreign keys not enabled!
   - ~16,000 words

5. **[performance-requirements.md](performance-requirements.md)** ⚡ **Performance (Mostly TBD)**
   - Framework for performance testing
   - Most SLAs undefined (needs benchmarking)
   - ~22,000 words

6. **[error-handling-requirements.md](error-handling-requirements.md)** 🚨 **Code Quality**
   - Error wrapping patterns
   - Testing requirements
   - ~15,000 words

7. **[PHASE1_COMPLETION_REPORT.md](PHASE1_COMPLETION_REPORT.md)** 📊 **Summary & Next Steps**
   - Complete gap analysis
   - TBD tracker
   - Timeline and recommendations
   - ~9,000 words

---

## Critical Findings Summary

### 🔴 CRITICAL - Production Blockers (Fix Immediately)

1. **SSRF Protection Missing** (`detect/actions.go`)
   - Can access AWS metadata service, steal credentials
   - Priority: CRITICAL
   - Estimated Fix: 2-3 days

2. **ReDoS Protection Missing** (`detect/engine.go`)
   - Malicious regex causes CPU exhaustion
   - Priority: CRITICAL
   - Estimated Fix: 1-2 days

### 🟡 HIGH - Should Fix Before Production

3. **SQLite Foreign Keys Not Enabled** (`storage/sqlite.go`)
   - Referential integrity not enforced
   - Fix: Add `?_foreign_keys=ON` parameter
   - Estimated Fix: 1 hour

4. **No Explicit Transactions** (`storage/sqlite_*.go`)
   - Multi-statement operations may be non-atomic
   - Estimated Fix: 3-5 days

5. **Path Traversal - Symlink Attack** (`detect/loader.go`)
   - Can read arbitrary files via symlink
   - Estimated Fix: 1 day

---

## TBD Summary - Decisions Needed

**Total TBDs**: 124 across all documents

### CRITICAL (Week 1) - Blocks Test Writing:
- Sigma type coercion (string "10" vs number 10)
- SSRF allowlist (safe domains for webhooks)
- Regex timeout (ReDoS prevention)
- SQLite foreign keys (enable by default?)
- Explicit transactions (use for multi-statement ops?)

### HIGH (Week 2) - Blocks Benchmarking:
- Event ingestion throughput SLA
- Query response time SLAs
- Circuit breaker default values rationale
- Float precision handling
- Memory usage limits

### MEDIUM (Week 3+) - Blocks Advanced Features:
- Short-circuit evaluation
- ClickHouse durability requirements
- Observability strategy
- Horizontal scaling support
- Data retention policy

**Full TBD Tracker**: See PHASE1_COMPLETION_REPORT.md Section 9

---

## Next Steps - Week by Week

### Week 1 (Nov 18-22): Review & Approve
- [ ] Technical review by all leads
- [ ] Security review by CISO
- [ ] Resolve CRITICAL TBDs
- [ ] Approve all requirement documents
- [ ] Assign owners to all TBDs

### Week 2 (Nov 25-29): Benchmarking
- [ ] Run benchmarking suite
- [ ] Define performance SLAs
- [ ] Research Sigma specification
- [ ] Update performance-requirements.md

### Week 3 (Dec 2-6): CRITICAL Security Fixes
- [ ] Implement SSRF protection
- [ ] Implement ReDoS protection
- [ ] Security testing
- [ ] ⚠️ **DEPLOYMENT UNBLOCKED** (if tests pass)

### Week 4 (Dec 9-13): Data Integrity Fixes
- [ ] Enable SQLite foreign keys
- [ ] Implement explicit transactions
- [ ] Data integrity testing

### Weeks 5-14: Test Remediation
- Fix tests against requirements
- Enable disabled tests
- Add missing tests

### Weeks 15-18: Enforcement
- CI/CD checks
- Pre-commit hooks
- Team training

---

## How to Use These Documents

### For Test Writers:

1. **Before Writing Any Test**:
   - Read relevant requirement document
   - Identify specific section with requirement
   - Reference section in test comment

2. **Test Template**:
```go
func TestRuleEngine_EqualsOperator_CaseSensitive(t *testing.T) {
    // REQUIREMENT: docs/requirements/sigma-compliance.md Section 2.1
    // Specification: Sigma spec requires case-sensitive exact matching
    // Test: "Admin" MUST NOT equal "admin"

    rule := core.Rule{
        Conditions: []core.Condition{
            {Field: "username", Operator: "equals", Value: "Admin"},
        },
    }

    event := &core.Event{Fields: map[string]interface{}{"username": "admin"}}

    matches := engine.Evaluate(event, rule)

    // VERIFY: No match (case-sensitive)
    assert.Empty(t, matches, "equals operator MUST be case-sensitive per Sigma spec")
}
```

3. **Don't Rubber-Stamp**:
   - ❌ WRONG: Test current behavior without verification
   - ✅ RIGHT: Test against documented requirement

### For Code Reviewers:

1. **Every Test Must Have**:
   - Reference to requirement document
   - Reference to specification (if applicable)
   - Clear assertion with rationale

2. **Reject Tests That**:
   - Have no requirement reference
   - Use magic numbers without rationale
   - Only test happy path (no error cases)
   - Would pass with buggy code

### For Security Reviews:

1. **Read**: security-threat-model.md
2. **Verify**: All CRITICAL and HIGH gaps are addressed
3. **Test**: Run security tests (once implemented)

### For Performance Engineering:

1. **Read**: performance-requirements.md
2. **Run**: Benchmarking suite (Week 2)
3. **Define**: SLAs based on benchmarks
4. **Update**: Document with SLAs

---

## Document Cross-References

### Security → Sigma:
- ReDoS protection (security-threat-model.md 6.1) requires regex timeout (sigma-compliance.md 2.6)

### Security → Storage:
- SQL injection (security-threat-model.md 2.1) requires parameterized queries (storage-acid-requirements.md 3.1.1)

### Performance → Circuit Breaker:
- Circuit breaker performance (performance-requirements.md 7.1) must be <10μs (circuit-breaker-requirements.md NFR-001)

### Error Handling → All:
- All components must follow error wrapping standards (error-handling-requirements.md 2.1)

---

## Statistics

### Documentation Coverage:
- **Functional Requirements**: 47
- **Non-Functional Requirements**: 23
- **Security Requirements**: 31
- **Test Requirements**: 89
- **TBD Items**: 124

### Implementation Gaps:
- **Critical Security**: 2
- **High Priority**: 5
- **Medium Priority**: 8
- **Code Fixes Needed**: 6 major items

### Test Coverage Gaps:
- **Missing Test Categories**: 12
- **Inadequate Categories**: 18
- **Tests Needing Rewrite**: 172+

---

## Contact / Ownership

| Document | Primary Owner | Reviewer | Status |
|----------|---------------|----------|--------|
| sigma-compliance.md | Detection Engineering | Security Lead | DRAFT |
| circuit-breaker-requirements.md | Reliability Engineering | Architect | DRAFT |
| security-threat-model.md | Security Team | CISO | DRAFT |
| storage-acid-requirements.md | Data Engineering | DBA | DRAFT |
| performance-requirements.md | Performance Engineering | Operations | DRAFT |
| error-handling-requirements.md | Engineering Standards | Tech Lead | DRAFT |
| PHASE1_COMPLETION_REPORT.md | Project Manager | All Leads | DRAFT |

---

## Questions?

**For Requirement Clarifications**: Contact document owner (see table above)
**For TBD Decisions**: See PHASE1_COMPLETION_REPORT.md Section 9
**For Security Questions**: security-threat-model.md + Security Team
**For Timeline Questions**: PHASE1_COMPLETION_REPORT.md Section 8

---

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0-DRAFT | 2025-11-16 | Initial creation (Phase 1 complete) | Principal Architect |
| 1.0-FINAL | TBD | After technical review and approval | TBD |

---

**Last Updated**: 2025-11-16
**Next Review**: Week 1 (technical review)
**Document Status**: DRAFT - Pending Approval
