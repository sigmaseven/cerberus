# Correlation Rule Requirements

**Document Owner**: Detection Engineering Team
**Created**: 2025-01-16
**Status**: DRAFT
**Last Updated**: 2025-01-16
**Version**: 1.0
**Authoritative Sources**:
- SIGMA Detection Rule Specification (Correlation Extensions)
- Elastic Security Detection Rule Guide
- Splunk Correlation Searches Best Practices
- Gartner SIEM Correlation Design Patterns

---

## 1. Executive Summary

Correlation rules enable multi-event detection of complex attack patterns that single-event rules cannot detect. This document defines comprehensive requirements for correlation rule evaluation, state management, performance optimization, and memory constraints to ensure reliable real-time threat detection without resource exhaustion.

**Critical Requirements**:
- Multiple correlation pattern types (count, value_count, sequence, rare, statistical, cross_entity, chain)
- Stateful event aggregation with time windows
- Memory-bounded state management (max 10,000 events per rule)
- Real-time evaluation with <1s latency
- Concurrent rule execution
- State cleanup and garbage collection
- Alert generation with correlation context

**Known Gaps**:
- Statistical correlation baseline calculation TBD
- Cross-entity correlation testing incomplete
- Chain correlation implementation pending
- Performance benchmarks under high load TBD

---

## 2. Functional Requirements

### 2.1 Correlation Rule Types

#### FR-CORR-001: Count-Based Correlation
**Requirement**: System MUST support count-based correlation to detect events exceeding a threshold within a time window.

**Rationale**: Count-based correlation is the most common pattern for brute force attacks, scanning activity, and failed authentication detection.

**Specification**:

**Use Cases**:
- Brute force authentication: 10+ failed logins within 5 minutes
- Port scanning: 50+ connection attempts to different ports within 1 minute
- DDoS detection: 10,000+ requests from single IP within 1 minute

**Rule Structure**:
```json
{
  "id": "brute_force_detection",
  "type": "count",
  "name": "SSH Brute Force Detection",
  "description": "Detects 10+ failed SSH logins from same IP within 5 minutes",
  "severity": "High",
  "enabled": true,
  "window": "5m",
  "selection": {
    "event_type": "auth_failure",
    "service": "ssh"
  },
  "group_by": ["source_ip"],
  "threshold": {
    "operator": ">",
    "value": 10
  },
  "actions": ["alert", "block_ip"]
}
```

**Evaluation Logic**:
1. Event matches `selection` criteria
2. Compute `group_key` from `group_by` fields (e.g., `source_ip=192.168.1.100`)
3. Increment event count for `group_key` within `window`
4. If count exceeds `threshold`, generate alert with all correlated events
5. Reset state for `group_key` after alert

**Threshold Operators**:
- `>`: Greater than
- `>=`: Greater than or equal
- `<`: Less than (rare events)
- `<=`: Less than or equal
- `==`: Exactly equal
- `!=`: Not equal

**Acceptance Criteria**:
- [x] Count-based correlation implemented
- [x] Time window enforcement (events outside window excluded)
- [x] Group_by field extraction supports nested fields (e.g., `user.name`)
- [x] Threshold comparison with all operators
- [x] Alert includes all correlated events
- [x] State reset after alert generation
- [ ] Count-based correlation supports multiple group_by fields

**Current Implementation**: ✅ COMPLIANT (detect/correlation_evaluators.go:10-45)

**Test Cases**:
```
TEST-CORR-001: Count threshold exceeded
GIVEN: Count rule with threshold > 5, window 5m
WHEN: 6 events matching selection arrive within 5 minutes
THEN: Alert generated with all 6 correlated events

TEST-CORR-002: Count threshold not exceeded
GIVEN: Count rule with threshold > 5, window 5m
WHEN: 4 events matching selection arrive within 5 minutes
THEN: No alert generated, state preserved

TEST-CORR-003: Events outside window excluded
GIVEN: Count rule with threshold > 5, window 5m
WHEN: 6 events arrive, but 2 are older than 5 minutes
THEN: Only 4 events counted, no alert
```

---

#### FR-CORR-002: Value Count Correlation
**Requirement**: System MUST support value count correlation to detect distinct value thresholds.

**Rationale**: Detects lateral movement, password spray attacks, and enumeration activities involving multiple distinct targets.

**Specification**:

**Use Cases**:
- Lateral movement: Same user authenticates to 10+ distinct hosts within 10 minutes
- Password spray: Same IP attempts authentication with 20+ distinct usernames
- Enumeration: Single IP queries 50+ distinct DNS names

**Rule Structure**:
```json
{
  "id": "lateral_movement",
  "type": "value_count",
  "name": "Lateral Movement Detection",
  "description": "Detects user authenticating to 10+ hosts within 10 minutes",
  "severity": "Critical",
  "window": "10m",
  "selection": {
    "event_type": "auth_success"
  },
  "count_field": "dest_hostname",
  "group_by": ["username"],
  "threshold": {
    "operator": ">=",
    "value": 10
  }
}
```

**Evaluation Logic**:
1. Event matches `selection` criteria
2. Extract `count_field` value (e.g., `dest_hostname=web01`)
3. Compute `group_key` from `group_by` fields (e.g., `username=admin`)
4. Add `count_field` value to set of distinct values for `group_key`
5. If distinct count exceeds `threshold`, generate alert

**Acceptance Criteria**:
- [x] Value count correlation implemented
- [x] Distinct value tracking (set-based, not count)
- [x] Count_field extraction from nested paths
- [x] Alert includes distinct value list
- [ ] Memory limit for distinct value sets (max 10,000 values)

**Current Implementation**: ✅ PARTIAL (detect/correlation_evaluators.go:48-87, memory limit TBD)

**Test Cases**:
```
TEST-CORR-004: Distinct value threshold exceeded
GIVEN: Value_count rule with count_field=username, threshold > 5
WHEN: 6 events with distinct usernames arrive
THEN: Alert generated with list of 6 distinct usernames

TEST-CORR-005: Duplicate values not counted
GIVEN: Value_count rule with count_field=username, threshold > 5
WHEN: 10 events arrive but only 3 distinct usernames
THEN: No alert, distinct count = 3
```

---

#### FR-CORR-003: Sequence Correlation
**Requirement**: System MUST support sequence correlation to detect ordered or unordered multi-stage attack patterns.

**Rationale**: Advanced attacks follow predictable multi-stage patterns (reconnaissance → exploitation → privilege escalation → lateral movement).

**Specification**:

**Use Cases**:
- Web attack chain: SQL injection → command execution → data exfiltration
- Malware infection: phishing email → macro execution → C2 beacon
- Insider threat: privilege escalation → credential access → data exfiltration

**Rule Structure** (Ordered Sequence):
```json
{
  "id": "web_attack_chain",
  "type": "sequence",
  "name": "Web Attack Chain Detection",
  "description": "Detects SQL injection followed by command execution",
  "severity": "Critical",
  "window": "1h",
  "sequence": [
    {
      "name": "sqli",
      "selection": {"event_type": "sql_injection"},
      "required": true
    },
    {
      "name": "rce",
      "selection": {"event_type": "command_execution"},
      "required": true
    }
  ],
  "ordered": true,
  "group_by": ["source_ip", "dest_host"],
  "max_span": "15m"
}
```

**Rule Structure** (Unordered Sequence):
```json
{
  "id": "suspicious_process_activity",
  "type": "sequence",
  "name": "Suspicious Process Activity",
  "description": "Detects PowerShell and network activity (any order)",
  "window": "5m",
  "sequence": [
    {"name": "powershell", "selection": {"process": "powershell.exe"}},
    {"name": "network", "selection": {"event_type": "network_connection"}}
  ],
  "ordered": false,
  "group_by": ["hostname"]
}
```

**Sequence Properties**:
- `ordered`: If `true`, events must occur in defined order
- `required`: If `true`, stage must be present for match
- `max_span`: Maximum time between first and last event (optional)
- Events can repeat (e.g., multiple SQL injection attempts before RCE)

**Evaluation Logic** (Ordered):
1. Event matches one of the sequence stage `selection` criteria
2. Compute `group_key` from `group_by` fields
3. Add event to sequence for `group_key`
4. Check if all `required` stages are present
5. Check if stages appear in correct order
6. Check if `max_span` constraint satisfied
7. If all conditions met, generate alert

**Evaluation Logic** (Unordered):
- Same as ordered, but skip order check

**Acceptance Criteria**:
- [x] Ordered sequence correlation implemented
- [x] Unordered sequence correlation implemented
- [x] Required vs optional stages enforced
- [x] Max_span time constraint enforced
- [x] Repeating events in sequence supported
- [x] Alert includes all sequence events
- [ ] Partial sequence timeout (emit alert for partial match after window expires)

**Current Implementation**: ✅ COMPLIANT (detect/correlation_evaluators.go:89-203)

**Test Cases**:
```
TEST-CORR-006: Ordered sequence matched
GIVEN: Ordered sequence rule [A, B, C]
WHEN: Events arrive in order A → B → C within window
THEN: Alert generated with all 3 events

TEST-CORR-007: Ordered sequence violated
GIVEN: Ordered sequence rule [A, B, C]
WHEN: Events arrive out of order B → A → C
THEN: No alert generated

TEST-CORR-008: Unordered sequence matched
GIVEN: Unordered sequence rule [A, B]
WHEN: Events arrive B → A within window
THEN: Alert generated

TEST-CORR-009: Max_span exceeded
GIVEN: Sequence rule with max_span=5m
WHEN: Events A and B are 6 minutes apart
THEN: No alert generated
```

---

#### FR-CORR-004: Rare Event Detection
**Requirement**: System MUST support rare event detection for anomalous low-frequency events.

**Rationale**: Rare events indicate unusual activity such as first-time process execution, rare port access, or unusual user behavior.

**Specification**:

**Use Cases**:
- Rare process execution: Process seen ≤ 2 times in 24 hours
- Rare port access: Port accessed ≤ 1 time in 7 days
- Rare domain access: Domain queried ≤ 3 times in 30 days

**Rule Structure**:
```json
{
  "id": "rare_process",
  "type": "rare",
  "name": "Rare Process Execution",
  "description": "Detects processes executed ≤2 times in 24h",
  "severity": "Medium",
  "window": "24h",
  "selection": {
    "event_type": "process_creation"
  },
  "count_field": "process_name",
  "threshold": {
    "operator": "<=",
    "value": 2
  }
}
```

**Evaluation Logic**:
1. Event matches `selection` criteria
2. Extract `count_field` value (e.g., `process_name=malware.exe`)
3. Use `count_field` value as `group_key` (track per unique value)
4. Increment count for `count_field` value within `window`
5. If count ≤ `threshold`, generate alert (note: **low** count triggers alert)

**Baseline Considerations**:
- Rare detection requires baseline period (e.g., 7 days)
- New processes in environment trigger alerts
- Whitelist common processes to reduce noise

**Acceptance Criteria**:
- [x] Rare event correlation implemented
- [x] Low count threshold triggers alert
- [ ] Baseline learning period configurable
- [ ] Whitelist/blacklist for rare detection
- [ ] Rare event count persisted across restarts

**Current Implementation**: ✅ PARTIAL (detect/correlation_evaluators.go:206-244, baseline TBD)

**Test Cases**:
```
TEST-CORR-010: Rare event detected
GIVEN: Rare rule with threshold <= 2, window 24h
WHEN: Process executed 2 times in 24h
THEN: Alert generated on 2nd occurrence

TEST-CORR-011: Event not rare
GIVEN: Rare rule with threshold <= 2, window 24h
WHEN: Process executed 5 times in 24h
THEN: No alert after 3rd occurrence
```

---

#### FR-CORR-005: Statistical Anomaly Detection
**Requirement**: System MUST support statistical correlation to detect anomalies based on baseline metrics.

**Rationale**: Detects data exfiltration, bandwidth spikes, process memory anomalies using statistical deviation.

**Specification**:

**Use Cases**:
- Data exfiltration: Network bytes sent > 3 standard deviations above mean
- CPU spike: Process CPU usage > 2 standard deviations above baseline
- Authentication spike: Logins > 3 standard deviations above normal

**Rule Structure**:
```json
{
  "id": "data_exfil",
  "type": "statistical",
  "name": "Data Exfiltration Detection",
  "description": "Detects network traffic > 3 std dev above baseline",
  "severity": "High",
  "window": "1h",
  "baseline_window": "7d",
  "selection": {
    "event_type": "network_traffic"
  },
  "metric_field": "bytes_sent",
  "group_by": ["source_ip"],
  "threshold": {
    "operator": "std_dev",
    "value": 3
  }
}
```

**Evaluation Logic**:
1. Event matches `selection` criteria
2. Extract numeric `metric_field` value (e.g., `bytes_sent=1048576`)
3. Compute `group_key` from `group_by` fields
4. Add metric to running statistics (mean, std dev) for `group_key`
5. Calculate current value's deviation: `(value - mean) / std_dev`
6. If deviation > `threshold`, generate alert

**Statistical Metrics**:
- **Mean (μ)**: Average value over baseline window
- **Standard Deviation (σ)**: Measure of value dispersion
- **Z-Score**: Number of standard deviations from mean: `(x - μ) / σ`

**Baseline Requirements**:
- Minimum data points: 10 events (configurable)
- Baseline window: 7 days default (configurable 1h - 30d)
- Baseline recalculation: Rolling window, updated with each event

**Threshold Operators**:
- `std_dev`: Absolute Z-score (e.g., `> 3` means >3σ above mean)
- `std_dev_above`: Z-score above mean only (positive deviation)
- `std_dev_below`: Z-score below mean only (negative deviation)

**Acceptance Criteria**:
- [x] Statistical correlation implemented
- [x] Running mean and standard deviation calculation
- [x] Z-score threshold evaluation
- [ ] Minimum data points enforced (10 events)
- [ ] Baseline window configurable
- [ ] Statistical state persisted across restarts
- [ ] Anomaly detection supports absolute, above, below thresholds

**Current Implementation**: ✅ PARTIAL (detect/correlation_evaluators.go:246-299, persistence TBD)

**Test Cases**:
```
TEST-CORR-012: Statistical anomaly detected
GIVEN: Statistical rule with threshold std_dev > 3
WHEN: Baseline mean=100, std_dev=10, new value=140
THEN: Alert generated (Z-score = 4.0)

TEST-CORR-013: Within normal range
GIVEN: Statistical rule with threshold std_dev > 3
WHEN: Baseline mean=100, std_dev=10, new value=120
THEN: No alert (Z-score = 2.0)

TEST-CORR-014: Insufficient baseline data
GIVEN: Statistical rule with min_data_points=10
WHEN: Only 5 events in baseline
THEN: No alert, continue collecting baseline
```

---

#### FR-CORR-006: Cross-Entity Correlation
**Requirement**: System SHOULD support cross-entity correlation to track entities across multiple targets.

**Rationale**: Detects lateral movement, account compromise, and distributed attacks involving one entity interacting with many targets.

**Specification**:

**Use Cases**:
- Lateral movement: Single user accesses 10+ distinct hosts
- Account compromise: Single IP authenticates as 20+ distinct users
- Data staging: Single host connects to 50+ distinct external IPs

**Rule Structure**:
```json
{
  "id": "cross_host_access",
  "type": "cross_entity",
  "name": "Cross-Host Access Detection",
  "description": "Detects user accessing 10+ hosts within 15 minutes",
  "severity": "High",
  "window": "15m",
  "selection": {
    "event_type": "auth_success"
  },
  "track_field": "username",
  "count_distinct": "dest_host",
  "threshold": {
    "operator": ">=",
    "value": 10
  }
}
```

**Evaluation Logic**:
1. Event matches `selection` criteria
2. Extract `track_field` value (e.g., `username=admin`)
3. Extract `count_distinct` value (e.g., `dest_host=web01`)
4. Track distinct `count_distinct` values per `track_field` value
5. If distinct count exceeds `threshold`, generate alert

**Difference from Value Count**:
- **Value Count**: Groups by entity, counts distinct values of another field
- **Cross-Entity**: Tracks single entity, counts distinct targets

**Acceptance Criteria**:
- [ ] Cross-entity correlation implemented
- [ ] Track_field extraction
- [ ] Count_distinct field tracking
- [ ] Distinct target list in alert
- [ ] Memory limit for distinct targets (max 10,000)

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] Cross-entity vs value_count implementation comparison
- [ ] Performance impact of tracking many entities

---

#### FR-CORR-007: Chain Correlation (Multi-Stage Attack)
**Requirement**: System SHOULD support chain correlation to detect multi-stage attacks with flexible ordering and time constraints.

**Rationale**: Advanced Persistent Threats (APTs) execute complex, multi-stage attack chains over extended periods.

**Specification**:

**Use Cases**:
- APT kill chain: Reconnaissance → Exploitation → C2 → Lateral Movement → Exfiltration
- Ransomware chain: Phishing → Execution → Credential Access → Encryption
- Insider threat: Access escalation → Credential theft → Data access → Exfiltration

**Rule Structure**:
```json
{
  "id": "apt_kill_chain",
  "type": "chain",
  "name": "APT Kill Chain Detection",
  "description": "Detects multi-stage APT attack chain",
  "severity": "Critical",
  "max_duration": "24h",
  "stages": [
    {
      "name": "recon",
      "selection": {"tactic": "reconnaissance"},
      "required": false
    },
    {
      "name": "exploit",
      "selection": {"tactic": "exploitation"},
      "required": true
    },
    {
      "name": "c2",
      "selection": {"tactic": "command_and_control"},
      "required": true
    },
    {
      "name": "lateral",
      "selection": {"tactic": "lateral_movement"},
      "required": false
    },
    {
      "name": "exfil",
      "selection": {"tactic": "exfiltration"},
      "required": true
    }
  ],
  "min_stages": 3,
  "group_by": ["source_ip", "dest_network"]
}
```

**Chain Properties**:
- `max_duration`: Maximum time from first to last stage
- `min_stages`: Minimum stages required for alert (subset matching)
- `required`: Stage must be present
- Stages can occur in any order (flexible sequencing)

**Evaluation Logic**:
1. Event matches one of the chain stage `selection` criteria
2. Compute `group_key` from `group_by` fields
3. Add event to chain for `group_key`
4. Count matched stages (distinct stage names)
5. Check if all `required` stages present
6. Check if `min_stages` threshold met
7. Check if `max_duration` not exceeded
8. If all conditions met, generate alert

**Acceptance Criteria**:
- [ ] Chain correlation implemented
- [ ] Min_stages threshold enforcement
- [ ] Max_duration enforcement
- [ ] Flexible stage ordering (stages can occur in any order)
- [ ] Required vs optional stages
- [ ] Subset matching (partial chains trigger alerts)

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] Chain vs sequence differentiation validation
- [ ] Chain state memory management for long durations (24h+)

---

### 2.2 State Management

#### FR-CORR-008: Time-Windowed State Management
**Requirement**: System MUST manage correlation state within defined time windows and automatically expire old events.

**Rationale**: Correlation rules evaluate events within sliding time windows. Expired events must be removed to conserve memory and prevent incorrect matches.

**Specification**:

**Window Semantics**:
- **Sliding window**: Last N time units from current event (e.g., last 5 minutes)
- **Tumbling window** (future): Fixed windows (00:00-00:05, 00:05-00:10)

**State Expiration**:
- Events older than `window` duration are excluded from correlation
- State cleanup runs periodically (every 30 seconds default)
- Expired events removed from memory

**Window Syntax**:
- `5s`: 5 seconds
- `10m`: 10 minutes
- `1h`: 1 hour
- `24h`: 24 hours
- `7d`: 7 days

**State Storage**:
- Per-rule, per-group_key state buckets
- Events stored in sorted order (by timestamp)
- Binary search for window filtering

**Acceptance Criteria**:
- [x] Sliding window implementation
- [x] Event expiration based on window
- [x] Periodic state cleanup (every 30s)
- [x] Sorted event storage for efficient window queries
- [ ] Tumbling window support (future)
- [ ] Configurable cleanup interval

**Current Implementation**: ✅ COMPLIANT (detect/correlation_state.go:197-232)

**Test Cases**:
```
TEST-CORR-015: Events outside window excluded
GIVEN: Correlation rule with window=5m
WHEN: Event arrives at T+6m (6 minutes after first event)
THEN: First event excluded from window, not counted

TEST-CORR-016: State cleanup removes expired events
GIVEN: Correlation state with events older than window
WHEN: Cleanup runs
THEN: Expired events removed from memory
```

---

#### FR-CORR-009: Memory-Bounded State Management
**Requirement**: System MUST enforce memory limits to prevent unbounded state growth and OOM errors.

**Rationale**: High-volume event sources can accumulate millions of events in state, exhausting memory. Bounded state prevents resource exhaustion DoS.

**Specification**:

**Memory Limits**:
- **Per-rule limit**: 10,000 events maximum (configurable via `MaxCorrelationEventsPerWindow`)
- **Global limit**: 1 million events total across all correlation rules (TBD)
- **Per-group_key limit**: 1,000 events (prevents single group_key from exhausting rule limit)

**Eviction Policy**:
- **FIFO (First-In-First-Out)**: Oldest events evicted first
- When limit reached, discard oldest event before inserting new event
- Evicted events logged with warning

**Memory Monitoring**:
- Metrics: `correlation_state_events_total`, `correlation_state_memory_bytes`
- Alert when >80% of memory limit consumed
- Alert when eviction rate >10%

**Acceptance Criteria**:
- [x] Per-rule event limit enforced (10,000 events)
- [x] FIFO eviction policy implemented
- [x] Eviction logged with warning
- [ ] Per-group_key event limit enforced
- [ ] Global event limit enforced
- [ ] Memory usage metrics tracked
- [ ] Eviction rate metrics tracked

**Current Implementation**: ✅ PARTIAL (detect/correlation_state.go:92-105, global limit TBD)

**Test Cases**:
```
TEST-CORR-017: Per-rule event limit enforced
GIVEN: Correlation rule with max events = 10,000
WHEN: 10,001st event arrives
THEN: Oldest event evicted, new event inserted, warning logged

TEST-CORR-018: Memory limit prevents OOM
GIVEN: Correlation rules consuming 1GB RAM
WHEN: More events arrive
THEN: Eviction prevents memory growth beyond limit
```

---

#### FR-CORR-010: State Cleanup and Garbage Collection
**Requirement**: System MUST periodically clean up idle and expired correlation state to prevent memory leaks.

**Rationale**: Long-lived correlation state (e.g., 24h windows) can accumulate if not actively cleaned. Periodic GC prevents memory leaks.

**Specification**:

**Cleanup Triggers**:
- **Periodic**: Every 30 seconds (default, configurable)
- **Idle state**: Correlation state with no activity for 2x TTL
- **Empty state**: Correlation state with 0 events

**Cleanup Logic**:
1. Iterate all correlation rules' state buckets
2. For each state bucket:
   - Remove events older than window
   - If no events remain, delete state bucket
   - If no activity for 2x TTL, delete state bucket
3. Log cleanup statistics (rules cleaned, events removed)

**Cleanup Performance**:
- Cleanup runs in background goroutine
- Cleanup cancellable via context (graceful shutdown)
- Cleanup checks context every 100 rules (prevents blocking shutdown)

**Acceptance Criteria**:
- [x] Periodic cleanup every 30 seconds
- [x] Idle state removal (2x TTL)
- [x] Empty state removal (0 events)
- [x] Cleanup runs in background goroutine
- [x] Cleanup cancellable for graceful shutdown
- [x] Cleanup statistics logged
- [ ] Cleanup interval configurable

**Current Implementation**: ✅ COMPLIANT (detect/correlation_state.go:234-300)

---

### 2.3 Correlation Evaluation

#### FR-CORR-011: Event Selection Matching
**Requirement**: System MUST match events against correlation rule selection criteria using SIGMA-like field matching.

**Rationale**: Selection criteria filter events eligible for correlation. Matching logic must be consistent with SIGMA rule semantics.

**Specification**:

**Selection Syntax** (SIGMA-compatible):
```json
{
  "selection": {
    "event_type": "auth_failure",
    "service": "ssh",
    "source_ip": "192.168.1.*"
  }
}
```

**Matching Operators**:
- **Equals**: `"field": "value"` (exact match)
- **OR**: `"field": ["value1", "value2"]` (any value matches)
- **Wildcard**: `"field": "*value*"` (glob pattern)
- **Regex**: `"field": "/^regex$/"` (regex pattern, future)

**Nested Field Access**:
- Dot notation: `"user.name": "admin"`
- Nested selection: `"fields": {"user": {"name": "admin"}}`

**Acceptance Criteria**:
- [x] Exact match selection implemented
- [x] OR selection (array of values) implemented
- [ ] Wildcard selection implemented
- [ ] Regex selection implemented (future)
- [x] Nested field access supported

**Current Implementation**: ✅ PARTIAL (selection matching in evaluators, wildcard/regex TBD)

---

#### FR-CORR-012: Group Key Computation
**Requirement**: System MUST compute group keys from event fields to partition correlation state.

**Rationale**: Correlation rules group events by entity (e.g., source IP, username) to detect per-entity patterns.

**Specification**:

**Group Key Syntax**:
- Single field: `"group_by": ["source_ip"]` → `source_ip=192.168.1.100`
- Multiple fields: `"group_by": ["source_ip", "username"]` → `source_ip=192.168.1.100,username=admin`

**Group Key Computation**:
1. Extract each `group_by` field from event
2. Concatenate field values with delimiters
3. Use group key as state bucket identifier

**Nested Field Extraction**:
- Support dot notation: `group_by: ["user.name"]`
- Handle missing fields: Empty string if field not present

**Acceptance Criteria**:
- [x] Single field group_by implemented
- [x] Multiple field group_by implemented
- [x] Nested field extraction supported
- [x] Missing field handling (empty string)
- [ ] Field value escaping (commas, equals in values)

**Current Implementation**: ✅ COMPLIANT (detect/correlation_evaluators.go, ComputeGroupKey function)

---

#### FR-CORR-013: Threshold Evaluation
**Requirement**: System MUST evaluate correlation thresholds using comparison operators.

**Rationale**: Thresholds determine when correlation patterns trigger alerts.

**Specification**:

**Numeric Thresholds**:
```json
{
  "threshold": {
    "operator": ">",
    "value": 10
  }
}
```

**Operators**:
- `>`: Greater than
- `>=`: Greater than or equal
- `<`: Less than
- `<=`: Less than or equal
- `==`: Equal
- `!=`: Not equal

**Statistical Thresholds**:
```json
{
  "threshold": {
    "operator": "std_dev",
    "value": 3
  }
}
```

**Operators**:
- `std_dev`: Absolute Z-score (distance from mean)
- `std_dev_above`: Z-score above mean
- `std_dev_below`: Z-score below mean

**Acceptance Criteria**:
- [x] Numeric comparison operators implemented
- [x] Statistical threshold operators implemented
- [ ] Statistical above/below variants implemented
- [x] Type coercion (string "10" → int 10)

**Current Implementation**: ✅ PARTIAL (numeric operators complete, statistical variants TBD)

---

### 2.4 Alert Generation

#### FR-CORR-014: Correlation Alert Metadata
**Requirement**: System MUST generate alerts with comprehensive correlation context.

**Rationale**: Correlation alerts require additional context beyond single-event alerts (correlated events, group keys, statistics).

**Specification**:

**Alert Structure**:
```json
{
  "id": "alert_123",
  "rule_id": "brute_force_detection",
  "rule_name": "SSH Brute Force Detection",
  "severity": "High",
  "timestamp": "2025-01-16T12:00:00Z",
  "correlation_type": "count",
  "correlation_context": {
    "group_key": "source_ip=192.168.1.100",
    "count": 15,
    "threshold": {"operator": ">", "value": 10},
    "window": "5m",
    "group_by": ["source_ip"],
    "correlated_events": [...], // Array of events that triggered correlation
    "first_event_time": "2025-01-16T11:55:00Z",
    "last_event_time": "2025-01-16T12:00:00Z"
  },
  "event": {...} // Triggering event
}
```

**Correlation-Specific Fields**:
- `correlation_type`: count, value_count, sequence, rare, statistical, cross_entity, chain
- `group_key`: Entity grouping key
- `correlated_events`: All events in correlation window
- `first_event_time`: Timestamp of first correlated event
- `last_event_time`: Timestamp of last (triggering) event
- Type-specific: `distinct_count`, `matched_sequence`, `deviation`, `rare_value`, etc.

**Acceptance Criteria**:
- [x] Alert includes correlation_type
- [x] Alert includes group_key
- [x] Alert includes correlated_events array
- [x] Alert includes correlation context (count, threshold, etc.)
- [ ] Alert includes first/last event timestamps
- [ ] Alert size limit enforced (max 100KB)

**Current Implementation**: ✅ PARTIAL (correlation context present, timestamps TBD)

---

## 3. Non-Functional Requirements

### 3.1 Performance

**NFR-CORR-001: Real-Time Evaluation Latency**
- Correlation rule evaluation MUST complete within 1 second (p95)
- State lookup MUST complete within 10ms (p95)
- Group key computation MUST complete within 1ms

**NFR-CORR-002: Concurrent Evaluation**
- System MUST support 100 concurrent correlation rules
- System MUST evaluate 10,000 events/second against all correlation rules
- Each rule evaluated independently (parallel evaluation)

**NFR-CORR-003: State Access Performance**
- State insert/update: < 1ms (p95)
- State retrieval: < 10ms (p95)
- State cleanup: < 100ms per cleanup cycle

### 3.2 Memory

**NFR-CORR-004: Memory Constraints**
- Per-rule event limit: 10,000 events (50-100 MB)
- Total correlation state: < 1 GB
- Memory growth MUST be bounded (eviction prevents unbounded growth)

**NFR-CORR-005: Memory Efficiency**
- Event storage SHOULD use pointers (avoid duplication)
- State buckets SHOULD use compact data structures (maps, slices)
- Cleanup SHOULD reclaim memory aggressively

### 3.3 Reliability

**NFR-CORR-006: Fault Tolerance**
- Correlation state MUST be isolated per rule (one rule failure doesn't affect others)
- State corruption MUST NOT cause system crash
- State cleanup MUST handle concurrent modifications (thread-safe)

**NFR-CORR-007: Consistency**
- Correlation matching MUST be deterministic (same events → same result)
- Time window calculations MUST be consistent across evaluations
- State expiration MUST be eventual (within cleanup interval)

### 3.4 Scalability

**NFR-CORR-008: Horizontal Scaling**
- Correlation state SHOULD be shareable across multiple instances (future)
- State synchronization SHOULD use distributed cache (Redis, future)
- Correlation rules SHOULD be partitionable by group_key (future)

---

## 4. Test Requirements

### 4.1 Functional Tests

**TEST-CORR-019: Count correlation threshold**
- GIVEN: Count rule with threshold > 5, window 5m
- WHEN: 6 events arrive within 5m
- THEN: Alert generated with all 6 events

**TEST-CORR-020: Value count distinct values**
- GIVEN: Value_count rule counting distinct usernames
- WHEN: 10 events with 3 distinct usernames
- THEN: No alert (threshold not met)

**TEST-CORR-021: Ordered sequence matching**
- GIVEN: Sequence rule [A, B, C], ordered=true
- WHEN: Events arrive A → B → C
- THEN: Alert generated

**TEST-CORR-022: Statistical anomaly detection**
- GIVEN: Statistical rule with threshold std_dev > 3
- WHEN: Value 4 std dev above mean
- THEN: Alert generated

### 4.2 Performance Tests

**TEST-CORR-023: Correlation latency under load**
- GIVEN: 100 correlation rules, 10K EPS
- WHEN: Events evaluated against all rules
- THEN: p95 latency < 1s, no events dropped

**TEST-CORR-024: State memory limit**
- GIVEN: Correlation rule with 10,000 event limit
- WHEN: 20,000 events arrive
- THEN: Oldest 10,000 events evicted, memory stable

### 4.3 Reliability Tests

**TEST-CORR-025: Graceful state cleanup shutdown**
- GIVEN: Correlation state cleanup running
- WHEN: System shutdown signal (SIGTERM)
- THEN: Cleanup cancels within 5 seconds, no data loss

**TEST-CORR-026: State isolation**
- GIVEN: Multiple correlation rules
- WHEN: One rule's state corrupted
- THEN: Other rules unaffected, continue operating

---

## 5. TBD Tracker

| ID | Description | Owner | Target Date | Status |
|----|-------------|-------|-------------|--------|
| TBD-CORR-001 | Statistical baseline persistence across restarts | Detection Team | 2025-03-15 | Open |
| TBD-CORR-002 | Cross-entity correlation implementation | Detection Team | 2025-03-01 | Open |
| TBD-CORR-003 | Chain correlation implementation | Detection Team | 2025-04-01 | Open |
| TBD-CORR-004 | Global memory limit enforcement | Detection Team | 2025-02-15 | Open |
| TBD-CORR-005 | Per-group_key event limit | Detection Team | 2025-02-15 | Open |
| TBD-CORR-006 | Wildcard selection matching | Detection Team | 2025-03-01 | Open |
| TBD-CORR-007 | Regex selection matching | Detection Team | 2025-04-01 | Open |
| TBD-CORR-008 | Distributed correlation state (Redis) | Architecture Team | 2025-06-01 | Open |
| TBD-CORR-009 | Performance benchmarks for 100 rules | QA Team | 2025-02-28 | Open |
| TBD-CORR-010 | Correlation rule testing framework | Detection Team | 2025-03-15 | Open |

---

## 6. Compliance Verification Checklist

### Correlation Types
- [x] Count-based correlation
- [x] Value count correlation
- [x] Sequence correlation (ordered/unordered)
- [x] Rare event detection
- [x] Statistical anomaly detection
- [ ] Cross-entity correlation
- [ ] Chain correlation

### State Management
- [x] Time-windowed state management
- [x] Memory-bounded state (per-rule limit)
- [ ] Memory-bounded state (global limit)
- [x] State cleanup and garbage collection
- [x] Event expiration
- [x] Idle state removal

### Evaluation
- [x] Selection matching (equals, OR)
- [ ] Selection matching (wildcard, regex)
- [x] Group key computation
- [x] Threshold evaluation (numeric)
- [x] Threshold evaluation (statistical)

### Alert Generation
- [x] Correlation alert metadata
- [x] Correlated events array
- [x] Correlation context
- [ ] Alert size limits

### Performance
- [ ] Real-time evaluation latency validated
- [ ] Concurrent rule evaluation tested
- [x] State access performance optimized

### Reliability
- [x] Rule isolation implemented
- [x] Thread-safe state management
- [x] Graceful shutdown

---

## 7. References

### Industry Standards
- [SIGMA Detection Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Elastic Detection Rule Guide](https://www.elastic.co/guide/en/security/current/rules-ui-create.html)
- [Splunk Correlation Searches](https://docs.splunk.com/Documentation/ES/latest/User/Howtocreateacorrelationsearch)

### Internal Documents
- `docs/requirements/performance-requirements.md`: Performance SLAs
- `docs/requirements/sigma-compliance.md`: SIGMA operator semantics

### Related Code
- `core/correlation.go`: Correlation rule data structures
- `detect/correlation_evaluators.go`: Correlation evaluation logic
- `detect/correlation_state.go`: State management
- `detect/correlation_state_test.go`: State management tests
- `detect/enhanced_correlation_evaluator.go`: Evaluator implementation

---

## 8. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-16 | Requirements Team | Initial draft based on codebase analysis |

---

**Document Status**: DRAFT - Awaiting technical review and stakeholder approval

**Next Steps**:
1. Technical review by detection engineering team (target: 2025-01-23)
2. Performance validation via load testing (target: 2025-02-28)
3. Statistical correlation baseline design review (target: 2025-02-15)
4. Stakeholder approval (target: 2025-02-06)
