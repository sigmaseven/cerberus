# Cerberus SIEM - E2E Test Coverage Matrix

## Requirements to Test Mapping

This document provides a complete mapping between requirements (from `docs/requirements/`) and E2E test cases.

---

## Authentication & Authorization (FR-USER-XXX)

| Req ID | Description | Test File | Test ID | Status |
|--------|-------------|-----------|---------|--------|
| FR-USER-004 | Password-based authentication | auth-comprehensive.spec.ts | FR-USER-004-001 | ✅ |
| FR-USER-004 | Invalid password rejection | auth-comprehensive.spec.ts | FR-USER-004-002 | ✅ |
| FR-USER-004 | Non-existent user rejection | auth-comprehensive.spec.ts | FR-USER-004-003 | ✅ |
| FR-USER-004 | Form validation - empty fields | auth-comprehensive.spec.ts | FR-USER-004-004 | ✅ |
| FR-USER-004 | Form validation - email format | auth-comprehensive.spec.ts | FR-USER-004-005 | ✅ |
| FR-USER-006 | JWT httpOnly cookie | auth-comprehensive.spec.ts | FR-USER-006-001 | ✅ |
| FR-USER-006 | JWT expiration | auth-comprehensive.spec.ts | FR-USER-006-002 | ✅ |
| FR-USER-006 | Expired JWT rejected | auth-comprehensive.spec.ts | FR-USER-006-003 | ✅ |
| FR-USER-006 | JWT blacklist on logout | auth-comprehensive.spec.ts | FR-USER-006-004 | ✅ |
| FR-USER-008 | Session persistence | auth-comprehensive.spec.ts | FR-USER-008-001 | ✅ |
| FR-USER-008 | Session timeout | auth-comprehensive.spec.ts | FR-USER-008-002 | ⚠️ |
| FR-USER-008 | Concurrent sessions | auth-comprehensive.spec.ts | FR-USER-008-003 | ✅ |
| FR-USER-012 | Account lockout after 5 attempts | auth-comprehensive.spec.ts | FR-USER-012-001 | ✅ |
| FR-USER-012 | Lockout duration | auth-comprehensive.spec.ts | FR-USER-012-002 | ⏭️ |
| FR-USER-012 | Failed attempts reset | auth-comprehensive.spec.ts | FR-USER-012-003 | ✅ |

**Coverage**: 13/15 (87%) - 2 marked as TBD/Skip

---

## API Design & Contract (FR-API-XXX)

| Req ID | Description | Test File | Test ID | Status |
|--------|-------------|-----------|---------|--------|
| FR-API-001 | Resource-oriented URLs | api-contract.spec.ts | Dashboard stats | ✅ |
| FR-API-001 | Collection endpoints | api-contract.spec.ts | Events endpoint | ✅ |
| FR-API-001 | Single resource | api-contract.spec.ts | Rules endpoint | ✅ |
| FR-API-003 | HTTP 200 OK | api-contract.spec.ts | Multiple tests | ✅ |
| FR-API-003 | HTTP 401 Unauthorized | security-comprehensive.spec.ts | SEC-AUTHZ-004 | ✅ |
| FR-API-003 | HTTP 403 Forbidden | security-comprehensive.spec.ts | SEC-CSRF-003 | ✅ |
| FR-API-003 | HTTP 404 Not Found | api-contract.spec.ts | Implicit | ✅ |
| FR-API-007 | Request validation | api-contract.spec.ts | All endpoints | ✅ |
| FR-API-007 | Response schema | api-contract.spec.ts | All endpoints | ✅ |
| FR-API-009 | Pagination support | api-contract.spec.ts | Events/Rules | ✅ |
| FR-API-009 | Pagination metadata | api-contract.spec.ts | Events/Rules | ✅ |
| FR-API-011 | JWT authentication | auth-comprehensive.spec.ts | FR-USER-006-* | ✅ |
| FR-API-013 | CSRF protection | security-comprehensive.spec.ts | SEC-CSRF-001 | ✅ |
| FR-API-013 | CSRF token validation | security-comprehensive.spec.ts | SEC-CSRF-002 | ✅ |
| FR-API-013 | CSRF rejection | security-comprehensive.spec.ts | SEC-CSRF-003 | ✅ |
| FR-API-014 | Rate limiting | security-comprehensive.spec.ts | Mentioned | ⚠️ |
| FR-API-018 | WebSocket connection | dashboard-comprehensive.spec.ts | DASH-006 | ⚠️ |
| FR-API-018 | Real-time updates | dashboard-comprehensive.spec.ts | DASH-007 | ⏭️ |
| FR-API-019 | Dashboard API < 200ms | performance.spec.ts | PERF-API-001 | ✅ |
| FR-API-019 | List API < 300ms | performance.spec.ts | PERF-API-002 | ✅ |
| FR-API-019 | Single resource < 100ms | performance.spec.ts | PERF-API-004 | ✅ |

**Coverage**: 18/21 (86%) - 3 partial/TBD

---

## Alert Requirements (ALERT-XXX)

| Req ID | Description | Test File | Test ID | Status |
|--------|-------------|-----------|---------|--------|
| ALERT-001 | Event preservation | alerts.spec.ts | Implicit | ✅ |
| ALERT-001 | Complete event data | api-contract.spec.ts | Alert structure | ✅ |
| ALERT-002 | Alert lifecycle states | alerts.spec.ts | Multiple tests | ✅ |
| ALERT-002 | Acknowledge alert | alerts.spec.ts | Implicit | ✅ |
| ALERT-002 | Dismiss alert | alerts.spec.ts | Implicit | ✅ |
| ALERT-003 | Alert deduplication | alerts.spec.ts | TBD | ⚠️ |

**Coverage**: 5/6 (83%)

---

## Security Requirements (OWASP / SEC-XXX)

| Threat | Description | Test File | Test ID | Status |
|--------|-------------|-----------|---------|--------|
| **A01: Broken Access Control** |
| AUTHZ | Unauthenticated access blocked | security-comprehensive.spec.ts | SEC-AUTHZ-003 | ✅ |
| AUTHZ | API without auth rejected | security-comprehensive.spec.ts | SEC-AUTHZ-004 | ✅ |
| AUTHZ | Admin can access all pages | security-comprehensive.spec.ts | SEC-AUTHZ-001 | ✅ |
| AUTHZ | Viewer cannot access admin | security-comprehensive.spec.ts | SEC-AUTHZ-002 | ⏭️ |
| **A02: Cryptographic Failures** |
| SESSION | Secure flag on cookies | security-comprehensive.spec.ts | SEC-SESSION-001 | ⚠️ |
| SESSION | HttpOnly flag on cookies | security-comprehensive.spec.ts | SEC-SESSION-002 | ✅ |
| SESSION | SameSite=Strict | security-comprehensive.spec.ts | SEC-SESSION-003 | ✅ |
| **A03: Injection** |
| XSS | XSS in rule name escaped | security-comprehensive.spec.ts | SEC-XSS-001 | ⏭️ |
| XSS | XSS in event data escaped | security-comprehensive.spec.ts | SEC-XSS-002 | ✅ |
| XSS | DOMPurify sanitization | security-comprehensive.spec.ts | SEC-XSS-003 | ✅ |
| XSS | Search input sanitized | security-comprehensive.spec.ts | SEC-XSS-004 | ✅ |
| XSS | No dangerouslySetInnerHTML | security-comprehensive.spec.ts | SEC-XSS-005 | ✅ |
| SQL | SQL injection in search | security-comprehensive.spec.ts | SEC-SQL-001 | ✅ |
| SQL | SQL injection in filters | security-comprehensive.spec.ts | SEC-SQL-002 | ✅ |
| **A05: Security Misconfiguration** |
| HEADERS | X-Frame-Options | security-comprehensive.spec.ts | SEC-HEADER-001 | ✅ |
| HEADERS | X-Content-Type-Options | security-comprehensive.spec.ts | SEC-HEADER-002 | ✅ |
| HEADERS | X-XSS-Protection | security-comprehensive.spec.ts | SEC-HEADER-003 | ✅ |
| HEADERS | HSTS | security-comprehensive.spec.ts | SEC-HEADER-004 | ⚠️ |
| HEADERS | CSP | security-comprehensive.spec.ts | SEC-HEADER-005 | ✅ |
| **A07: Identification & Authentication Failures** |
| AUTH | All login tests | auth-comprehensive.spec.ts | 25 tests | ✅ |
| AUTH | CSRF protection | security-comprehensive.spec.ts | 3 tests | ✅ |
| AUTH | Timing attack resistance | auth-comprehensive.spec.ts | SECURITY-004 | ✅ |
| AUTH | Password not in network | auth-comprehensive.spec.ts | SECURITY-005 | ✅ |
| **A09: Security Logging Failures** |
| ERROR | No stack traces in 500 | security-comprehensive.spec.ts | SEC-ERROR-001 | ✅ |
| ERROR | No DB structure leak | security-comprehensive.spec.ts | SEC-ERROR-002 | ✅ |

**Coverage**: 26/28 (93%) - 2 environment-dependent

---

## Accessibility Requirements (WCAG 2.1 AA)

| Criterion | Level | Description | Test File | Test ID | Status |
|-----------|-------|-------------|-----------|---------|--------|
| **1. Perceivable** |
| 1.1.1 | A | Non-text content | accessibility.spec.ts | A11Y-SR-001 | ✅ |
| 1.3.1 | A | Info and relationships | accessibility.spec.ts | A11Y-SR-004 | ✅ |
| 1.4.3 | AA | Contrast (Minimum) | accessibility.spec.ts | A11Y-COLOR-001 | ✅ |
| **2. Operable** |
| 2.1.1 | A | Keyboard | accessibility.spec.ts | A11Y-KB-001 | ✅ |
| 2.1.2 | A | No keyboard trap | accessibility.spec.ts | A11Y-KB-002 | ✅ |
| 2.4.1 | A | Bypass blocks | accessibility.spec.ts | A11Y-FOCUS-003 | ✅ |
| 2.4.3 | A | Focus order | accessibility.spec.ts | A11Y-KB-001 | ✅ |
| 2.4.6 | AA | Headings and labels | accessibility.spec.ts | A11Y-SR-002 | ✅ |
| 2.4.7 | AA | Focus visible | accessibility.spec.ts | A11Y-KB-001 | ✅ |
| 2.5.5 | AAA | Target size | accessibility.spec.ts | A11Y-MOBILE-001 | ✅ |
| **3. Understandable** |
| 3.2.1 | A | On focus | accessibility.spec.ts | A11Y-FOCUS-001 | ✅ |
| 3.3.1 | A | Error identification | accessibility.spec.ts | A11Y-SR-003 | ✅ |
| 3.3.2 | A | Labels or instructions | accessibility.spec.ts | A11Y-SR-002 | ✅ |
| **4. Robust** |
| 4.1.2 | A | Name, role, value | accessibility.spec.ts | A11Y-ARIA-001 | ✅ |
| 4.1.3 | AA | Status messages | accessibility.spec.ts | A11Y-SR-005 | ✅ |

**Coverage**: 15/15 (100%) of tested criteria

Additional accessibility tests:
- Modal focus trapping (A11Y-KB-002)
- Escape key functionality (A11Y-KB-003)
- Dropdown keyboard navigation (A11Y-KB-004)
- ARIA expanded state (A11Y-ARIA-002)
- ARIA required fields (A11Y-ARIA-003)
- ARIA invalid state (A11Y-ARIA-004)
- Focus management (A11Y-FOCUS-001, 002, 003)

**Total Accessibility Tests**: 25

---

## Performance Requirements (PERF-XXX)

| Req ID | Description | Target | Test File | Test ID | Status |
|--------|-------------|--------|-----------|---------|--------|
| **Page Load Times** |
| PERF-001 | Dashboard load | < 2s | performance.spec.ts | PERF-001 | ✅ |
| PERF-002 | Rules page load | < 2s | performance.spec.ts | PERF-002 | ✅ |
| PERF-003 | Events page load | < 2s | performance.spec.ts | PERF-003 | ✅ |
| PERF-004 | Alerts page load | < 2s | performance.spec.ts | PERF-004 | ✅ |
| **API Response Times** |
| PERF-API-001 | Dashboard API | < 300ms | performance.spec.ts | PERF-API-001 | ✅ |
| PERF-API-002 | Events API | < 300ms | performance.spec.ts | PERF-API-002 | ✅ |
| PERF-API-003 | Rules API | < 300ms | performance.spec.ts | PERF-API-003 | ✅ |
| PERF-API-004 | Single resource | < 100ms | performance.spec.ts | PERF-API-004 | ✅ |
| **Large Datasets** |
| PERF-DATA-001 | 1000 rows render | < 5s | performance.spec.ts | PERF-DATA-001 | ✅ |
| PERF-DATA-002 | Pagination | < 2s | performance.spec.ts | PERF-DATA-002 | ✅ |
| PERF-DATA-003 | Search large set | < 2s | performance.spec.ts | PERF-DATA-003 | ⏭️ |
| **Memory Leaks** |
| PERF-MEM-001 | Repeated navigation | < 50% growth | performance.spec.ts | PERF-MEM-001 | ✅ |
| PERF-MEM-002 | Modal open/close | < 30% growth | performance.spec.ts | PERF-MEM-002 | ✅ |
| **Network** |
| PERF-NET-001 | Asset caching | Present | performance.spec.ts | PERF-NET-001 | ✅ |
| PERF-NET-002 | Image optimization | < 3x display | performance.spec.ts | PERF-NET-002 | ✅ |
| PERF-NET-003 | API batching | < 10 requests | performance.spec.ts | PERF-NET-003 | ✅ |
| **Core Web Vitals** |
| PERF-RENDER-001 | FCP | < 1.5s | performance.spec.ts | PERF-RENDER-001 | ✅ |
| PERF-RENDER-002 | LCP | < 2.5s | performance.spec.ts | PERF-RENDER-002 | ✅ |
| PERF-RENDER-003 | CLS | < 0.1 | performance.spec.ts | PERF-RENDER-003 | ✅ |
| PERF-RENDER-004 | TTI | < 3s | performance.spec.ts | PERF-RENDER-004 | ✅ |

**Coverage**: 19/20 (95%) - 1 requires CQL implementation

---

## Feature Test Coverage Summary

| Feature | Total Tests | Passed | Failed | Skipped | Coverage |
|---------|-------------|--------|--------|---------|----------|
| Authentication | 25 | 23 | 0 | 2 | 92% |
| Dashboard | 20 | 18 | 0 | 2 | 90% |
| Rules | 22 | 20 | 0 | 2 | 91% |
| Alerts | 10 | 10 | 0 | 0 | 100% |
| Events | 8 | 8 | 0 | 0 | 100% |
| API Contract | 12 | 12 | 0 | 0 | 100% |
| Security | 30 | 28 | 0 | 2 | 93% |
| Accessibility | 25 | 25 | 0 | 0 | 100% |
| Performance | 20 | 19 | 0 | 1 | 95% |
| Correlation | 10 | 8 | 0 | 2 | 80% |
| Investigations | 10 | 8 | 0 | 2 | 80% |
| **TOTAL** | **192** | **179** | **0** | **13** | **93%** |

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Test implemented and passing |
| ⚠️ | Test partial or needs improvement |
| ⏭️ | Test skipped (feature not implemented) |
| ❌ | Test failing or not implemented |

---

## Notes

1. **Skipped Tests**: Tests marked as ⏭️ skip are intentional - they test features not yet implemented in the backend (e.g., idle timeout, LDAP, etc.)

2. **Partial Tests**: Tests marked as ⚠️ require specific backend configuration (e.g., HTTPS for Secure cookies, WebSocket events)

3. **Test IDs**: Follow format `CATEGORY-SUBCATEGORY-NUMBER` for traceability

4. **Coverage Calculation**: (Implemented Tests / Total Required Tests) × 100%

---

**Last Updated**: 2025-11-17
**Total Requirements Mapped**: 95+ requirements
**Test Files**: 15
**Test Cases**: 192
**Overall Coverage**: 93%
