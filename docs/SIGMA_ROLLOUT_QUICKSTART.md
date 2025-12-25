# SIGMA Engine Rollout - Quick Start Guide

## 5-Minute Quick Start

### Step 1: Enable SIGMA Engine (0% Rollout)

```yaml
# config.yaml
engine:
  enable_native_sigma_engine: true   # Master switch ON
  sigma_rollout_percentage: 0        # 0% rollout (validate metrics only)
```

**Validation:**
```bash
# Check logs for successful initialization
grep "SIGMA rollout configuration initialized" cerberus.log

# Check Prometheus metrics are exported
curl localhost:9090/metrics | grep cerberus_sigma_
```

**Expected:** All rules use legacy engine, metrics are being collected.

---

### Step 2: Canary Deployment (5% Rollout)

```yaml
engine:
  sigma_rollout_percentage: 5  # 5% of rules use native engine
```

**Monitor for 24 hours:**
```promql
# Error rate (should be <0.1%)
sum(rate(cerberus_sigma_engine_errors_total[5m]))
/
sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
* 100
```

**Alert if:** Error rate >0.5% for 10 minutes → **ROLLBACK**

---

### Step 3: Gradual Expansion

Increase percentage gradually:
- Day 3: 10%
- Week 1: 25%
- Week 2: 50%
- Week 4: 75%
- Week 6: 100%

**Monitor at each step:**
- Error rate <0.1%
- Alert quality unchanged
- Performance stable

---

## Emergency Rollback

### Complete Rollback (<5 minutes)

```yaml
engine:
  enable_native_sigma_engine: false  # Master switch OFF
```

Restart service. All rules immediately use legacy engine.

---

### Partial Rollback (Specific Rules)

```yaml
engine:
  sigma_rollout_percentage: 5  # Roll back to canary
  sigma_rollout_disabled_rules:
    - "problematic-rule-id-1"
    - "problematic-rule-id-2"
```

Find problematic rules:
```promql
topk(10, sum by (rule_id) (rate(cerberus_sigma_engine_errors_total[5m])))
```

---

## Key Metrics

### Engine Usage Distribution
```promql
sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
/
sum(rate(cerberus_sigma_engine_evaluations_total[5m]))
* 100
```
**Expected:** Should match configured percentage ±10%

### Error Rate
```promql
sum(rate(cerberus_sigma_engine_errors_total[5m]))
/
sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
* 100
```
**Alert if:** >0.5%

### Decision Breakdown
```promql
sum by (reason) (cerberus_sigma_rollout_decisions_total)
```
**Reasons:** master_switch_off, explicit_blocklist, explicit_whitelist, hash_routing

---

## Configuration Options

### Master Switch
```yaml
enable_native_sigma_engine: true/false
```
**When false:** All rules use legacy engine (overrides everything)

### Rollout Percentage
```yaml
sigma_rollout_percentage: 0-100
```
**Hash-based routing:** Deterministic distribution across rules

### Whitelist (Force Native)
```yaml
sigma_rollout_enabled_rules:
  - "critical-rule-001"
  - "high-priority-detection"
```
**Use for:** Specific high-confidence rules

### Blocklist (Force Legacy)
```yaml
sigma_rollout_disabled_rules:
  - "problematic-rule-123"
  - "slow-evaluation-rule"
```
**Use for:** Emergency mitigation of broken rules

---

## Decision Precedence

1. **Master Switch OFF** → All rules use legacy
2. **Blocklist** → Blocked rules use legacy (highest priority)
3. **Whitelist** → Whitelisted rules use native
4. **Hash-based Routing** → Percentage-based distribution

---

## Grafana Dashboard Queries

### Panel 1: Engine Usage Split (Pie Chart)
```promql
sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="legacy"}[5m]))
```

### Panel 2: Error Rate Over Time (Graph)
```promql
sum(rate(cerberus_sigma_engine_errors_total[5m]))
/
sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
* 100
```

### Panel 3: Top 10 Failing Rules (Table)
```promql
topk(10, sum by (rule_id) (rate(cerberus_sigma_engine_errors_total[5m])))
```

---

## Alert Rules

### High Error Rate
```yaml
- alert: SigmaEngineHighErrorRate
  expr: |
    sum(rate(cerberus_sigma_engine_errors_total[5m]))
    /
    sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
    > 0.005
  for: 10m
  annotations:
    summary: "SIGMA engine error rate >0.5%"
    action: "Consider rolling back or investigating errors"
```

### Rollout Percentage Mismatch
```yaml
- alert: SigmaRolloutMismatch
  expr: |
    abs(
      sum(rate(cerberus_sigma_engine_evaluations_total{engine_type="native"}[5m]))
      /
      sum(rate(cerberus_sigma_engine_evaluations_total[5m]))
      * 100
      -
      cerberus_config_sigma_rollout_percentage
    ) > 15
  for: 30m
  annotations:
    summary: "Actual vs configured rollout differs by >15%"
```

---

## Troubleshooting

### Issue: High Error Rate

**Check error types:**
```promql
sum by (error_type) (rate(cerberus_sigma_engine_errors_total[5m]))
```

**Error types:**
- `parse_error`: Invalid SIGMA YAML syntax
- `evaluation_error`: Runtime evaluation failure
- `field_mapping_error`: Field name not mapped

**Solution:**
1. Identify problematic rules (see Top 10 query)
2. Add to blocklist
3. File bug report with rule details

### Issue: Percentage Mismatch

**Acceptable variance:** ±10% (due to hash distribution)
**Unacceptable variance:** >15%

**Check:**
1. Whitelist/blocklist size affecting distribution
2. Configuration reload (restart service)
3. Hash distribution quality

### Issue: Performance Degradation

**Check cache hit rate:**
```promql
sum(rate(cerberus_cache_hits_total{cache_type="sigma_engine"}[5m]))
/
sum(rate(cerberus_cache_hits_total{cache_type="sigma_engine"}[5m])
    + rate(cerberus_cache_misses_total{cache_type="sigma_engine"}[5m]))
```

**If hit rate <80%:**
```yaml
engine:
  sigma_engine_cache_size: 2000  # Increase cache size
```

---

## Common Rollout Scenarios

### Scenario 1: Test Specific Rules First

```yaml
engine:
  enable_native_sigma_engine: true
  sigma_rollout_percentage: 0  # No hash routing
  sigma_rollout_enabled_rules:
    - "well-tested-rule-001"
    - "high-confidence-rule-002"
```

**Monitor for 48 hours, then expand to 5%**

### Scenario 2: Exclude Known Problematic Rules

```yaml
engine:
  enable_native_sigma_engine: true
  sigma_rollout_percentage: 25
  sigma_rollout_disabled_rules:
    - "complex-regex-rule"
    - "field-mapping-issue-rule"
```

**Gradually remove from blocklist as issues are fixed**

### Scenario 3: Emergency Mitigation

```yaml
engine:
  sigma_rollout_percentage: 5  # Roll back from 25% to 5%
  sigma_rollout_disabled_rules:
    - "newly-identified-problem-rule"
```

**Keep percentage low, add to blocklist, investigate offline**

---

## Health Check Endpoint

```bash
curl localhost:8080/api/v1/health/sigma-rollout
```

**Expected response:**
```json
{
  "status": "healthy",
  "rollout": {
    "enabled": true,
    "rollout_percentage": 25,
    "whitelist_count": 2,
    "blocklist_count": 1
  },
  "message": "Native SIGMA engine partially deployed"
}
```

---

## Support

**Questions?**
- See full documentation: `docs/SIGMA_ROLLOUT_GUIDE.md`
- File issue: GitHub with `sigma-rollout` label
- Escalate: On-call engineer via PagerDuty

**Production incident?**
1. Execute emergency rollback (master switch OFF)
2. Monitor error rates return to normal
3. File post-incident report
4. Schedule post-mortem
