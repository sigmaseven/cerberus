# SIGMA-First Rules Unification PRD

## Overview

Cerberus currently has fragmented rule systems: SIGMA-based detection rules, legacy correlation rules with simple sequences, enhanced correlation types without storage, and CQL query-based rules. This PRD defines the architectural changes needed to make SIGMA the single, first-class format for ALL rules - both detection and correlation.

## Problem Statement

1. **Format Fragmentation**: 3 different rule formats (SIGMA, CQL, Legacy Correlation) with inconsistent APIs
2. **Storage Split**: Detection rules in `rules` table, correlation rules in `correlation_rules` table
3. **Missing Correlation Storage**: 7 enhanced correlation types (`core/correlation.go`) have no persistence layer
4. **Inconsistent Lifecycle**: Different CRUD patterns, validation, and lifecycle states per format
5. **Maintenance Burden**: Multiple code paths for similar functionality

## Goals

1. Make SIGMA YAML the **only** format for both detection and correlation rules
2. Unify storage into a single `rules` table with category discrimination
3. Implement SIGMA-compatible correlation syntax
4. Deprecate and migrate CQL format
5. Add missing lifecycle features (testing, deprecation states, performance tracking)

## Non-Goals

- Breaking backward compatibility immediately (migration path required)
- Removing CQL engine entirely (keep for query/search, not rules)
- Supporting non-SIGMA external rule formats

---

## Feature Requirements

### 1. Unified Rule Storage Schema

Consolidate all rules into a single table with clear category discrimination.

**Database Schema Changes:**

```sql
-- Modify rules table
ALTER TABLE rules ADD COLUMN rule_category TEXT NOT NULL DEFAULT 'detection';
-- Values: 'detection', 'correlation'

ALTER TABLE rules ADD COLUMN correlation_config TEXT;
-- JSON blob for correlation-specific configuration

ALTER TABLE rules ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'active';
-- Values: 'experimental', 'test', 'stable', 'deprecated', 'active'

ALTER TABLE rules ADD COLUMN performance_stats TEXT;
-- JSON blob: avg_eval_time_ms, match_count, false_positive_count

ALTER TABLE rules ADD COLUMN deprecated_at TIMESTAMP;
ALTER TABLE rules ADD COLUMN deprecated_reason TEXT;
```

**Migration Required:**
- Migrate all `correlation_rules` records to `rules` table
- Set `rule_category = 'correlation'` for migrated records
- Convert legacy `sequence` field to `correlation_config` JSON
- Drop `correlation_rules` table after verification

### 2. SIGMA Correlation Format Specification

Define a SIGMA-compatible YAML format for correlation rules that maps to the 7 enhanced correlation types.

**Correlation Block Specification:**

```yaml
title: Brute Force Login Detection
status: stable
logsource:
  category: authentication
  product: windows

detection:
  selection:
    EventID: 4625
  condition: selection

# NEW: Correlation block for correlation rules
correlation:
  type: event_count  # event_count | value_count | sequence | temporal | rare | statistical | chain

  # Grouping - which fields define a "session" for correlation
  group_by:
    - src_ip
    - target_user

  # Time window for correlation
  timespan: 5m

  # Type-specific configuration
  condition:
    field: "@count"      # For event_count
    operator: ">="
    value: 5

  # For sequence type
  ordered: true
  events:
    - selection_login_attempt
    - selection_login_success

  # For value_count type
  distinct_field: target_user

  # For statistical type
  baseline_window: 7d
  std_dev_threshold: 3

  # For chain type (multi-stage attacks)
  stages:
    - name: reconnaissance
      detection_ref: recon_rule_id
      timeout: 1h
    - name: exploitation
      detection_ref: exploit_rule_id
      timeout: 30m
```

**Correlation Types Mapping:**

| Enhanced Type | SIGMA correlation.type | Key Fields |
|--------------|----------------------|------------|
| CountCorrelationRule | event_count | condition.value, condition.operator |
| ValueCountCorrelationRule | value_count | distinct_field, condition |
| SequenceCorrelationRule | sequence | events[], ordered |
| TemporalCorrelationRule | temporal | time_pattern, recurrence |
| RareCorrelationRule | rare | baseline_window, rarity_threshold |
| StatisticalCorrelationRule | statistical | baseline_window, std_dev_threshold |
| ChainCorrelationRule | chain | stages[] |

### 3. SIGMA Correlation Parser

Extend the SIGMA parser to handle correlation blocks.

**Implementation in `sigma/parser.go`:**

```go
type SigmaCorrelation struct {
    Type           string            `yaml:"type"`
    GroupBy        []string          `yaml:"group_by"`
    Timespan       string            `yaml:"timespan"`
    Condition      *CorrelationCond  `yaml:"condition,omitempty"`
    Ordered        bool              `yaml:"ordered,omitempty"`
    Events         []string          `yaml:"events,omitempty"`
    DistinctField  string            `yaml:"distinct_field,omitempty"`
    BaselineWindow string            `yaml:"baseline_window,omitempty"`
    StdDevThreshold float64          `yaml:"std_dev_threshold,omitempty"`
    Stages         []ChainStage      `yaml:"stages,omitempty"`
}

type SigmaRule struct {
    // ... existing fields ...
    Correlation *SigmaCorrelation `yaml:"correlation,omitempty"`
}
```

### 4. Correlation Engine Integration

Modify the detection engine to evaluate correlation rules using the unified format.

**Changes to `detect/engine.go`:**

1. Add correlation evaluation pipeline
2. Integrate with existing enhanced correlation evaluators
3. Maintain correlation state per group_by key
4. Emit correlation alerts when conditions met

**State Management:**

```go
type CorrelationState struct {
    RuleID      string
    GroupKey    string                 // Hash of group_by field values
    EventCount  int64
    ValueSet    map[string]struct{}    // For distinct value tracking
    EventTimes  []time.Time            // For sequence/temporal
    Statistics  *StatisticalBaseline   // For statistical correlation
    LastUpdated time.Time
}
```

### 5. Rule Lifecycle Management

Add comprehensive lifecycle features to all rules.

**Lifecycle States:**

```
experimental → test → stable → deprecated → archived
                 ↓
              active (shortcut for production-ready)
```

**Lifecycle API Endpoints:**

```
POST /api/v1/rules/{id}/lifecycle
{
    "action": "promote",      // promote, deprecate, archive, activate
    "target_status": "stable",
    "reason": "Passed 30-day test period with <1% FP rate"
}

GET /api/v1/rules/{id}/lifecycle-history
// Returns audit trail of status changes
```

**Deprecation Flow:**
1. Mark rule as deprecated with reason and sunset date
2. Continue evaluating but flag alerts as "from deprecated rule"
3. After sunset date, auto-disable unless overridden
4. Archive removes from active evaluation entirely

### 6. Rule Testing Framework

Enable testing rules against sample events before deployment.

**Test API:**

```
POST /api/v1/rules/test
{
    "rule": { /* full rule object or ID */ },
    "events": [
        {"EventID": 4625, "src_ip": "10.0.0.1", ...},
        {"EventID": 4625, "src_ip": "10.0.0.1", ...}
    ],
    "expect_match": true,
    "expect_correlation": true
}

Response:
{
    "matched": true,
    "correlation_triggered": true,
    "evaluation_time_ms": 2.5,
    "matched_events": [0, 1],
    "correlation_state": { ... },
    "errors": []
}
```

**Batch Testing:**

```
POST /api/v1/rules/{id}/test-batch
{
    "event_file": "test-events.json",  // Or inline events array
    "expected_alerts": 5,
    "timeout_seconds": 30
}
```

### 7. Performance Tracking

Track and expose rule performance metrics.

**Metrics Collected:**

```go
type RulePerformanceStats struct {
    RuleID              string
    AvgEvalTimeMs       float64
    MaxEvalTimeMs       float64
    TotalEvaluations    int64
    TotalMatches        int64
    FalsePositiveCount  int64   // User-reported
    LastEvaluated       time.Time
    PercentileP99Ms     float64
}
```

**API Endpoint:**

```
GET /api/v1/rules/{id}/performance
GET /api/v1/rules/performance/slow?threshold_ms=100
```

### 8. CQL Deprecation and Migration

Provide tooling to migrate CQL rules to SIGMA format.

**Migration Tool:**

```
POST /api/v1/rules/migrate-cql
{
    "rule_ids": ["rule-1", "rule-2"],  // Or "all" for batch
    "dry_run": true,
    "preserve_original": true
}

Response:
{
    "migrated": 45,
    "failed": 2,
    "failures": [
        {"rule_id": "rule-x", "error": "Complex CQL not convertible"}
    ],
    "preview": [
        {"original": {...}, "sigma": "title: ...\ndetection:..."}
    ]
}
```

**CQL to SIGMA Converter:**

```go
func ConvertCQLToSigma(cqlRule *CQLRule) (*SigmaRule, error) {
    // Parse CQL query
    // Map operators to SIGMA detection syntax
    // Handle correlation config → SIGMA correlation block
    // Return converted rule or error if not convertible
}
```

### 9. Unified Rules API

Consolidate all rule operations under unified endpoints.

**Endpoints:**

```
# List all rules (detection + correlation)
GET /api/v1/rules?category=detection|correlation|all

# CRUD operations (unified)
POST /api/v1/rules
GET /api/v1/rules/{id}
PUT /api/v1/rules/{id}
DELETE /api/v1/rules/{id}

# Bulk operations
POST /api/v1/rules/bulk-enable
POST /api/v1/rules/bulk-disable
POST /api/v1/rules/bulk-delete

# Import/Export (SIGMA YAML)
POST /api/v1/rules/import
GET /api/v1/rules/export?format=sigma|json

# Validation
POST /api/v1/rules/validate
```

**Deprecate Old Endpoints:**
- `/api/v1/correlation-rules/*` → Redirect to `/api/v1/rules?category=correlation`

### 10. Frontend Updates

Update UI to handle unified rule management.

**Changes Required:**

1. **Rules Page**: Add category filter (Detection/Correlation/All)
2. **Rule Form**: Dynamic form based on category
   - Show correlation config fields when category=correlation
   - YAML editor with syntax highlighting for SIGMA
3. **Rule Testing Panel**: Test rules against sample events
4. **Performance Dashboard**: Show rule performance metrics
5. **Lifecycle Management**: Promote/deprecate actions in UI

---

## Technical Implementation Notes

### Database Migration Strategy

1. Create new columns with defaults (non-breaking)
2. Run background migration job for correlation_rules → rules
3. Verify data integrity
4. Update application to use unified table
5. Mark old table as deprecated
6. Drop old table in next major version

### Backward Compatibility

- Keep CQL evaluation engine for existing rules during transition
- Add `format` field to distinguish SIGMA vs CQL rules
- Provide 6-month deprecation window for CQL format
- Auto-convert CQL to SIGMA where possible

### Performance Considerations

- Correlation state stored in Redis for distributed deployments
- SQLite for single-node deployments (current default)
- Correlation state TTL based on rule timespan + buffer
- Batch correlation evaluation for high-volume events

---

## Success Metrics

1. **Unification**: 100% of rules in single `rules` table
2. **SIGMA Adoption**: 100% of new rules created in SIGMA format
3. **CQL Migration**: 95%+ of CQL rules successfully migrated
4. **Performance**: <5ms average rule evaluation time
5. **Testing Coverage**: 80%+ of rules have test cases

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Complex CQL rules can't convert to SIGMA | Manual conversion assistance, keep CQL engine as fallback |
| Correlation state memory pressure | TTL-based eviction, configurable retention |
| Migration data loss | Dry-run mode, backup before migration, rollback capability |
| API breaking changes | Versioned API, deprecation warnings, redirect old endpoints |

---

## Implementation Phases

### Phase 1: Foundation (Storage Unification)
- Add new columns to rules table
- Create migration scripts
- Implement unified storage layer
- Update API to support both categories

### Phase 2: SIGMA Correlation
- Define and implement correlation YAML spec
- Extend SIGMA parser for correlation blocks
- Integrate correlation evaluation in engine
- Add correlation state management

### Phase 3: Lifecycle & Testing
- Implement lifecycle state machine
- Build rule testing framework
- Add performance tracking
- Create lifecycle API endpoints

### Phase 4: Migration & Deprecation
- Build CQL to SIGMA converter
- Create migration tooling
- Deprecate old endpoints
- Update documentation

### Phase 5: Frontend Integration
- Update Rules page for unified view
- Add correlation rule form
- Implement testing UI
- Add performance dashboard
