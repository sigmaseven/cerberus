# Context.Background() Audit Report

**Date:** December 14, 2025
**Total Instances Found:** 803 occurrences across 114 files
**Production Code Instances:** ~60 occurrences across ~35 non-test files

## Executive Summary

This audit categorizes all `context.Background()` usage in the Cerberus SIEM codebase by severity level based on their impact on:
- Graceful shutdown capability
- Request timeout handling
- Distributed tracing continuity
- Resource cleanup

## Severity Categories

### CRITICAL (Immediate Attention Required) - 4 instances

These instances have no timeout/cancellation and could block graceful shutdown or cause resource leaks.

| File | Line | Function/Context | Issue | Remediation |
|------|------|-----------------|-------|-------------|
| `storage/retention.go` | 62 | Retention cleanup loop | No timeout, runs indefinitely | Add context from caller with cancellation |
| `storage/user.go` | 201 | GetRoleByID call | No timeout for DB lookup | Pass context from caller |
| `storage/sqlite_ml_models.go` | 210 | Background cleanup | No cancellation signal | Add shutdown context |
| `sigma/feeds/scheduler.go` | 85 | Scheduler operation | No cancellation support | Accept context parameter |

### HIGH (Goroutine Spawns - Affects Graceful Shutdown) - 7 instances

These create detached goroutines that may not respect shutdown signals.

| File | Line | Function/Context | Issue | Remediation |
|------|------|-----------------|-------|-------------|
| `detect/actions.go` | 83 | Action executor goroutine | Creates cancellable ctx but detached from parent | Wire to app shutdown context |
| `detect/engine.go` | 109 | Detection engine goroutine | Creates cancellable ctx but detached | Wire to app shutdown context |
| `detect/correlation_state.go` | 61 | Correlation state manager | Creates cancellable ctx but detached | Wire to app shutdown context |
| `detect/enhanced_correlation_state.go` | 138 | Enhanced state manager | Creates cancellable ctx but detached | Wire to app shutdown context |
| `detect/sigma_cache.go` | 170 | Cache cleanup goroutine | Creates cancellable ctx but detached | Wire to app shutdown context |
| `core/worker.go` | 45 | Worker pool | Creates cancellable ctx but detached | Wire to app shutdown context |
| `service/playbook_service.go` | 982 | Playbook deep copy | No timeout | Add timeout wrapper |

### MEDIUM (Has Timeout - Acceptable but Could Improve) - 23 instances

These have `WithTimeout` wrapping which is acceptable, but could benefit from accepting parent context.

| File | Line | Timeout | Notes |
|------|------|---------|-------|
| `api/api.go` | 250 | N/A | Health check ping, low risk |
| `api/feed_handlers.go` | 542, 610, 821, 1183 | 5s-5min | Has proper timeout wrapping |
| `api/playbook_handlers.go` | 377 | 5 min | Has timeout for execution |
| `storage/clickhouse_alerts.go` | 96, 130 | 30s | Flush operations |
| `storage/clickhouse_events.go` | 114, 188, 209 | 30s | Flush/batch operations |
| `storage/clickhouse_soar_audit.go` | 71 | 10s | Audit flush |
| `storage/clickhouse.go` | 82 | 5s | Connection check |
| `storage/migrations_clickhouse.go` | 37 | N/A | Init-only, acceptable |
| `storage/sqlite_password_history.go` | 52 | 5s | Pruning operation |
| `detect/regex_timeout.go` | 29 | configurable | Regex safety timeout |
| `soar/executor.go` | 648 | 500ms | Short timeout |
| `soar/ssrf_validation.go` | 129 | 5s | DNS resolution |
| `threat/enrichment.go` | 56 | 5s | External API call |
| `ingest/json.go` | 140 | 5s | Event enrichment |
| `core/worker.go` | 153 | configurable | Graceful stop |
| `service/playbook_service.go` | 727 | configurable | Execution timeout |
| `bootstrap/app.go` | 267, 367, 509 | 5-30s | Startup/shutdown ops |
| `ml/ensemble_engine.go` | 107 | N/A | Model loading (init) |
| `ml/training_pipeline.go` | 190 | N/A | Training context |

### LOW (Acceptable Uses) - 26+ instances

These are acceptable uses including:

#### Application Initialization (Acceptable)
| File | Line | Reason |
|------|------|--------|
| `main.go` | 39 | App entry point |
| `bootstrap/storage.go` | 72, 115 | Storage init |
| `ml/loader.go` | 26 | Model loading |
| `ml/system.go` | 77, 211 | System init |

#### CLI Commands (Acceptable - Short-lived processes)
| File | Lines | Count |
|------|-------|-------|
| `cmd/feeds.go` | 92, 137, 180, 270, 348, 402, 463, 538, 574, 613, 649, 685, 745 | 13 |

#### Test Files (Acceptable - ~750+ instances)
All `*_test.go` files - acceptable for testing.

## Remediation Plan

### Phase 1: Critical Fixes (Immediate)

1. **storage/retention.go:62**
   - Accept `context.Context` parameter
   - Wire to application shutdown context

2. **storage/user.go:201**
   - Accept `context.Context` parameter from caller

3. **storage/sqlite_ml_models.go:210**
   - Add shutdown context support

4. **sigma/feeds/scheduler.go:85**
   - Accept `context.Context` parameter

### Phase 2: High Severity (Week 2)

1. Create centralized shutdown context in `bootstrap/app.go`
2. Pass shutdown context to:
   - `detect/engine.go`
   - `detect/actions.go`
   - `detect/correlation_state.go`
   - `detect/enhanced_correlation_state.go`
   - `detect/sigma_cache.go`
   - `core/worker.go`

### Phase 3: Medium Severity (Optional Improvements)

Consider refactoring handlers to accept parent context from HTTP request:
- Allows request cancellation to propagate
- Enables distributed tracing
- Not strictly required if timeouts are appropriate

## Exceptions (Intentional Uses)

The following are intentional and should NOT be changed:

1. **CLI commands** (`cmd/feeds.go`) - Short-lived processes, no shutdown coordination needed
2. **Application init** (`main.go`, `bootstrap/*.go`) - Must create initial context
3. **Test files** - Test isolation requires fresh contexts
4. **Timeout-wrapped operations** - Already have appropriate safeguards

## Statistics Summary

| Category | Count | Action Required |
|----------|-------|-----------------|
| CRITICAL | 4 | Immediate |
| HIGH | 7 | Soon |
| MEDIUM | 23 | Optional |
| LOW (Init/CLI) | 26 | None |
| Test Files | ~750 | None |
| **Total** | **803** | **11 require action** |

## Validation Commands

```bash
# Count all instances
rg "context\.Background\(\)" --type go | wc -l

# Count in production code only
rg "context\.Background\(\)" --type go --glob "!*_test.go" | wc -l

# Find critical: no timeout in storage
rg "context\.Background\(\)" --type go --glob "!*_test.go" storage/ -A2 -B2

# Find goroutine spawns
rg "go func.*context\.Background" --type go --glob "!*_test.go"
```

## Peer Review Checklist

- [ ] Reviewed by team member 1
- [ ] Reviewed by team member 2
- [ ] Critical fixes validated
- [ ] Shutdown testing performed
