# SIGMA Engine Gradual Rollout Guide

## Overview

This guide explains how to safely deploy the native SIGMA detection engine to production using gradual rollout (canary deployment).

**Task Reference:** Task #131.5 - Feature Flags for Gradual SIGMA Rollout

## Table of Contents

- [Architecture](#architecture)
- [Configuration Options](#configuration-options)
- [Rollout Strategy](#rollout-strategy)
- [Monitoring & Metrics](#monitoring--metrics)
- [Troubleshooting](#troubleshooting)
- [Rollback Procedures](#rollback-procedures)

## Architecture

### Decision Logic

The feature flag system uses a precedence-based decision model:

1. **Master Switch** (`enable_native_sigma_engine`): If `false`, all rules use legacy engine
2. **Blocklist** (`sigma_rollout_disabled_rules`): Explicitly blocked rules use legacy engine
3. **Whitelist** (`sigma_rollout_enabled_rules`): Explicitly enabled rules use native engine
4. **Hash-based Routing** (`sigma_rollout_percentage`): Deterministic canary rollout

### Deterministic Routing

- Uses SHA-256 hash of rule ID for stable, deterministic routing
- Same rule ID always routes to the same engine
- No randomness or time-based factors
- Even distribution across rule IDs

## Configuration Options

### Master Switch

```yaml
engine:
  enable_native_sigma_engine: true  # Enable native SIGMA engine globally
```

**When to disable:**
- Initial deployment testing
- Critical production issues with native engine
- Emergency rollback scenarios

### Rollout Percentage

```yaml
engine:
  sigma_rollout_percentage: 25  # 0-100, controls percentage of rules using native engine
```

**Valid range:** 0-100 (inclusive)

**Examples:**
- `0` = All rules use legacy engine (safe default)
- `5` = Canary deployment (5% of rules use native engine)
- `50` = Half of rules use native engine
- `100` = All rules use native engine (full migration)

### Whitelist (Explicit Enable)

```yaml
engine:
  sigma_rollout_enabled_rules:
    - "critical-rule-001"
    - "high-priority-detection"
    - "test-sigma-rule"
```

**Use cases:**
- Force specific high-priority rules to use native engine
- Test native engine with known-good rules
- Gradual expansion of rule coverage

### Blocklist (Explicit Disable)

```yaml
engine:
  sigma_rollout_disabled_rules:
    - "problematic-rule-123"
    - "slow-evaluation-rule"
    - "false-positive-rule"
```

**Use cases:**
- Prevent problematic rules from using native engine
- Emergency mitigation for rules with evaluation issues
- Performance isolation (keep slow rules on legacy engine)

## Rollout Strategy

### Phase 1: Pre-Deployment Validation (0% Rollout)

**Goal:** Validate configuration and metrics with engine enabled but not used

**Configuration:**
```yaml
engine:
  enable_native_sigma_engine: true
  sigma_rollout_percentage: 0
  sigma_rollout_enabled_rules: []
  sigma_rollout_disabled_rules: []
```

**Validation:**
1. Check application starts successfully
2. Verify metrics are exported:
   - `cerberus_sigma_engine_evaluations_total`
   - `cerberus_sigma_rollout_decisions_total`
3. Confirm all rules use legacy engine (expected behavior)

**Duration:** 1-2 hours

### Phase 2: Canary Deployment (5% Rollout)

**Goal:** Test native engine with small percentage of production traffic

**Configuration:**
```yaml
engine:
  enable_native_sigma_engine: true
  sigma_rollout_percentage: 5
```

**Monitoring checklist:**
- [ ] Error rate (target: <0.1%)
  - Metric: `cerberus_sigma_engine_errors_total`
- [ ] Evaluation latency (target: <100ms p99)
  - Compare native vs legacy performance
- [ ] Alert accuracy (no regression)
  - Manual validation of alerts from native engine rules
- [ ] Resource usage (CPU, memory)
  - Monitor for unexpected spikes

**Success criteria:**
- Error rate <0.1% for 24 hours
- No performance degradation
- No alert quality regression

**Duration:** 24-48 hours

### Phase 3: Expansion (25% Rollout)

**Goal:** Build confidence with larger traffic percentage

**Configuration:**
```yaml
engine:
  enable_native_sigma_engine: true
  sigma_rollout_percentage: 25
```

**Monitoring checklist:**
- [ ] Error rate remains <0.1%
- [ ] No memory leaks (stable memory usage over 72 hours)
- [ ] Cache hit rate >80% (metric: `cerberus_cache_hits_total{cache_type="sigma_engine"}`)
- [ ] Business metrics stable (no false positive spike)

**Success criteria:**
- All Phase 2 metrics stable
- No customer complaints about alert quality
- Engineering team confidence in native engine

**Duration:** 1 week

### Phase 4: Majority (75% Rollout)

**Goal:** Prepare for full migration with majority of traffic

**Configuration:**
```yaml
engine:
  enable_native_sigma_engine: true
  sigma_rollout_percentage: 75
```

**Monitoring checklist:**
- [ ] Error rate remains <0.1%
- [ ] Performance metrics stable at scale
- [ ] Legacy engine can be safely deprecated

**Success criteria:**
- 2 weeks of stable operation
- No outstanding issues with native engine
- Deprecated legacy code paths can be identified

**Duration:** 2 weeks

### Phase 5: Complete Migration (100% Rollout)

**Goal:** Full migration to native SIGMA engine

**Configuration:**
```yaml
engine:
  enable_native_sigma_engine: true
  sigma_rollout_percentage: 100
```

**Post-deployment:**
1. Monitor for 1 month
2. Plan deprecation of legacy engine code
3. Update documentation to reflect native-only deployment
4. Remove legacy engine code (future task)

## Monitoring & Metrics

### Key Metrics

#### Engine Usage Distribution

```promql
# Percentage of rules using native engine
sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
/
sum(rate(cerberus_sigma_engine_evaluations_total[5m]))
* 100
```

**Expected value:** Should match `sigma_rollout_percentage` (±5% variance acceptable)

#### Error Rate

```promql
# SIGMA engine error rate
sum(rate(cerberus_sigma_engine_errors_total[5m]))
/
sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
* 100
```

**Alert threshold:** >0.5% error rate for 10 minutes

#### Decision Breakdown

```promql
# Rollout decision reasons
sum by (reason) (cerberus_sigma_rollout_decisions_total)
```

**Reasons:**
- `master_switch_off`: Master flag disabled
- `explicit_blocklist`: Rule in blocklist
- `explicit_whitelist`: Rule in whitelist
- `hash_routing`: Hash-based percentage routing

### Grafana Dashboard

Recommended dashboard panels:

1. **Engine Usage Split** (Pie chart)
   - Native vs Legacy evaluations
2. **Error Rate Over Time** (Graph)
   - SIGMA engine errors by type
3. **Decision Breakdown** (Bar chart)
   - Decisions by reason
4. **Performance Comparison** (Heatmap)
   - Native vs Legacy evaluation latency
5. **Cache Performance** (Graph)
   - Cache hit/miss rate over time

### Alerting Rules

```yaml
groups:
  - name: sigma_rollout
    rules:
      # High error rate
      - alert: SigmaEngineHighErrorRate
        expr: |
          sum(rate(cerberus_sigma_engine_errors_total[5m]))
          /
          sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
          > 0.005
        for: 10m
        annotations:
          summary: "SIGMA engine error rate >0.5% for 10 minutes"
          description: "Consider rolling back or investigating errors"

      # Rollout percentage mismatch
      - alert: SigmaRolloutMismatch
        expr: |
          abs(
            sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
            /
            sum(rate(cerberus_sigma_engine_evaluations_total[5m]))
            * 100
            -
            cerberus_config_sigma_rollout_percentage
          ) > 10
        for: 30m
        annotations:
          summary: "Actual rollout percentage differs from configured by >10%"
          description: "Check hash distribution or configuration"
```

## Troubleshooting

### Issue: Rollout percentage doesn't match actual usage

**Symptom:** Prometheus shows 30% native engine usage but config says 25%

**Possible causes:**
1. Hash distribution variance (acceptable ±10%)
2. Whitelist/blocklist affecting distribution
3. Stale configuration (service not restarted)

**Resolution:**
1. Check whitelist/blocklist size: `len(enabled_rules) + len(disabled_rules)`
2. Verify config reload: restart service
3. If variance >15%, check hash distribution quality

### Issue: High error rate on native engine

**Symptom:** `cerberus_sigma_engine_errors_total` increasing rapidly

**Possible causes:**
1. Invalid SIGMA YAML in rules
2. Field mapping issues
3. Bug in native engine

**Resolution:**
1. Check error breakdown by `error_type` label:
   - `parse_error`: SIGMA YAML syntax issue
   - `evaluation_error`: Runtime evaluation failure
   - `field_mapping_error`: Field name not mapped
2. Identify problematic rules: check `rule_id` label
3. Add problematic rules to blocklist:
   ```yaml
   sigma_rollout_disabled_rules:
     - "problematic-rule-id"
   ```
4. File bug report with rule details

### Issue: Performance degradation

**Symptom:** Increased evaluation latency after rollout increase

**Possible causes:**
1. Cache not warmed up
2. Memory pressure (cache evictions)
3. Inefficient SIGMA rules

**Resolution:**
1. Check cache hit rate:
   ```promql
   sum(rate(cerberus_cache_hits_total{cache_type="sigma_engine"}[5m]))
   /
   sum(rate(cerberus_cache_hits_total{cache_type="sigma_engine"}[5m])
       + rate(cerberus_cache_misses_total{cache_type="sigma_engine"}[5m]))
   ```
2. If hit rate <80%, increase cache size:
   ```yaml
   engine:
     sigma_engine_cache_size: 2000  # Increase from 1000
   ```
3. If memory pressure, increase TTL to reduce evictions
4. Identify slow rules and add to blocklist

## Rollback Procedures

### Emergency Rollback (Complete)

**Use case:** Critical production issue with native engine

**Steps:**
1. Update configuration:
   ```yaml
   engine:
     enable_native_sigma_engine: false  # Master switch off
   ```
2. Reload configuration (restart service if needed)
3. Verify all rules use legacy engine:
   ```promql
   sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="legacy"}[1m]))
   ```
4. Monitor for stability
5. Investigate root cause offline

**Recovery time:** <5 minutes

### Partial Rollback (Reduce Percentage)

**Use case:** Issues with subset of rules, not all

**Steps:**
1. Reduce rollout percentage:
   ```yaml
   engine:
     sigma_rollout_percentage: 5  # Roll back to canary level
   ```
2. Add problematic rules to blocklist:
   ```yaml
   sigma_rollout_disabled_rules:
     - "rule-with-issue-1"
     - "rule-with-issue-2"
   ```
3. Monitor for stability
4. Investigate blocked rules offline

**Recovery time:** <10 minutes

### Targeted Rollback (Blocklist Only)

**Use case:** Specific rule(s) causing issues, rest working fine

**Steps:**
1. Identify problematic rule IDs from metrics:
   ```promql
   topk(10, sum by (rule_id) (rate(cerberus_sigma_engine_errors_total[5m])))
   ```
2. Add to blocklist:
   ```yaml
   sigma_rollout_disabled_rules:
     - "identified-rule-id"
   ```
3. Keep rollout percentage unchanged
4. Monitor for issue resolution

**Recovery time:** <5 minutes

## Best Practices

### Configuration Management

1. **Version control:** Always commit config changes
2. **Review process:** Peer review rollout percentage changes
3. **Change log:** Document reason for each rollout increase
4. **Automation:** Use CI/CD to deploy config changes

### Monitoring

1. **Dashboard:** Create dedicated Grafana dashboard
2. **Alerts:** Set up Prometheus alerts for error rates
3. **Logging:** Enable debug logging during initial rollouts
4. **Metrics retention:** Keep 30 days of rollout metrics

### Communication

1. **Stakeholders:** Notify team before rollout increases
2. **Documentation:** Update runbooks with lessons learned
3. **Incident response:** Define escalation path for issues
4. **Post-mortems:** Document any rollback events

## Appendix: Configuration Examples

### Conservative Rollout

```yaml
engine:
  enable_native_sigma_engine: true
  sigma_rollout_percentage: 10
  sigma_rollout_enabled_rules: []
  sigma_rollout_disabled_rules: []
```

### Aggressive Rollout (Not Recommended)

```yaml
engine:
  enable_native_sigma_engine: true
  sigma_rollout_percentage: 100  # ⚠️ Skip canary phases - risky!
```

### Hybrid Approach

```yaml
engine:
  enable_native_sigma_engine: true
  sigma_rollout_percentage: 50
  sigma_rollout_enabled_rules:
    # Force high-confidence rules to native
    - "sigma-rule-brute-force"
    - "sigma-rule-privilege-escalation"
  sigma_rollout_disabled_rules:
    # Keep known problematic rules on legacy
    - "legacy-rule-with-complex-regex"
    - "rule-with-field-mapping-issues"
```

## Support

**Questions or issues?**
- File GitHub issue with `sigma-rollout` label
- Tag on-call engineer in Slack #cerberus-alerts
- Escalate to engineering lead if production impact

**Documentation feedback?**
- Submit PR to improve this guide
- Add troubleshooting scenarios from your experience
