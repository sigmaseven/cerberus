# Alert Requirements

## Purpose
This document defines the requirements for security alert generation, management, and preservation in the Cerberus SIEM system.

## Table of Contents
1. [ALERT-001: Event Preservation](#alert-001-event-preservation)
2. [ALERT-002: Alert Lifecycle](#alert-002-alert-lifecycle)
3. [ALERT-003: Alert Deduplication](#alert-003-alert-deduplication)

---

## ALERT-001: Event Preservation

### Requirement Statement
**Every alert MUST preserve the complete event that triggered it.**

### Rationale
1. **Forensic Investigation**: Incident responders need the exact event data to understand what happened
2. **Compliance Requirements**:
   - PCI-DSS 10.6: Requires retention of audit log history for at least one year
   - HIPAA Security Rule: Requires complete audit trails for security incidents
   - SOC 2: Requires evidence of security events for audit purposes
3. **False Positive Analysis**: Security analysts need event context to tune rules and reduce noise
4. **Incident Response**: Complete event data is required for:
   - Root cause analysis
   - Impact assessment
   - Evidence collection
   - Timeline reconstruction

### Business Rule
**If event data is unavailable, alert creation MUST fail** rather than create an incomplete alert.

### Design Decision: Nil Events

**Question**: Should `NewAlert()` accept `nil` event pointers?

**Decision**: **NO** - Nil events are rejected.

**Justification**:
- **Data Integrity**: Alerts without events violate the fundamental requirement of preserving forensic context
- **Operational Risk**: Incomplete alerts create gaps in the audit trail
- **Investigation Impact**: Analysts cannot investigate alerts without event details
- **Compliance Violation**: Missing event data fails regulatory requirements

**Alternative Considered**: Allow nil events for "manual alerts" created by analysts

**Rejected Because**:
- Manual alerts should use an empty `Event{}` struct with metadata fields populated
- Empty struct is semantically different from nil (present but empty vs. absent)
- API consistency: all alerts have the same structure regardless of source

### Implementation Requirements

1. **Constructor Validation**:
   ```go
   func NewAlert(ruleID, eventID string, severity string, event *Event) *Alert {
       if event == nil {
           panic("event cannot be nil: violates ALERT-001 requirement")
       }
       // ... rest of implementation
   }
   ```

2. **Event Data Completeness**:
   - Minimum required fields in Event:
     - `EventID`: Unique identifier
     - `Timestamp`: When the event occurred
     - `RawData`: Original log line or data
     - `Fields`: Parsed field data

3. **Storage Requirements**:
   - Alerts MUST be stored with complete event data
   - Event data MUST NOT be deleted while alert exists
   - Retention period: Follow regulatory requirements (minimum 1 year)

### Test Requirements

**ALERT-001-TEST-1**: NewAlert rejects nil events
```go
func TestNewAlert_RejectsNilEvent(t *testing.T) {
    assert.Panics(t, func() {
        NewAlert("rule-1", "event-1", "high", nil)
    }, "NewAlert MUST reject nil events per ALERT-001")
}
```

**ALERT-001-TEST-2**: NewAlert preserves complete event data
```go
func TestNewAlert_PreservesEventData(t *testing.T) {
    event := &Event{
        EventID: "evt-123",
        Timestamp: time.Now(),
        RawData: "test log line",
        Fields: map[string]interface{}{
            "source_ip": "192.168.1.1",
            "action": "login_failed",
        },
    }

    alert := NewAlert("rule-1", "evt-123", "high", event)

    require.NotNil(t, alert.Event)
    assert.Equal(t, event.EventID, alert.Event.EventID)
    assert.Equal(t, event.RawData, alert.Event.RawData)
    assert.Equal(t, event.Fields["source_ip"], alert.Event.Fields["source_ip"])
}
```

**ALERT-001-TEST-3**: Alert retrieval includes event data
```go
func TestAlertStorage_RetrievesEventData(t *testing.T) {
    // Verify that loading alerts from storage includes event data
    // This ensures the complete audit trail is preserved
}
```

### Acceptance Criteria
- [ ] NewAlert panics if event is nil
- [ ] NewAlert preserves all event fields
- [ ] Alert storage persists complete event data
- [ ] Alert retrieval includes complete event data
- [ ] Tests verify requirement is enforced
- [ ] Tests would fail if requirement violated

---

## ALERT-002: Alert Lifecycle

### Requirement Statement
**Alerts MUST transition through defined states with audit trail.**

### States
1. **Pending**: Initial state when alert is created
2. **Acknowledged**: Analyst has seen the alert
3. **Investigating**: Active investigation in progress
4. **Resolved**: Alert handled, no action needed
5. **Escalated**: Requires higher-level response

### Audit Requirements
- All state transitions MUST be logged
- State changes MUST record:
  - Timestamp
  - User who made the change
  - Reason/comments
  - Previous state

### Implementation
See `core/alert_lifecycle.go` for lifecycle management.

---

## ALERT-003: Alert Deduplication

### Requirement Statement
**Similar alerts MUST be deduplicated to reduce noise.**

### Deduplication Strategy
1. **Fingerprinting**: Generate fingerprint from event fields
2. **Time Window**: Group alerts within configurable time window (default: 5 minutes)
3. **Counter**: Increment duplicate count instead of creating new alert
4. **Event IDs**: Preserve list of all deduplicated event IDs

### Fingerprint Algorithm
```
fingerprint = SHA256(rule_id + sorted_key_fields)
```

### Key Fields (Rule-Specific)
- Rule can specify which fields are significant for deduplication
- Example: For failed login alerts, key fields might be `[username, source_ip]`
- Same username + IP failing repeatedly = single alert with counter

### Implementation
See `core/deduplication.go` for deduplication logic.

---

## References

1. **PCI-DSS v4.0**: Requirement 10 - Log and Monitor All Access
2. **HIPAA Security Rule**: 45 CFR § 164.312(b) - Audit Controls
3. **SOC 2 Trust Service Criteria**: CC7.2 - Monitoring Activities
4. **NIST SP 800-53**: AU-6 - Audit Review, Analysis, and Reporting
5. **ISO 27001:2022**: A.8.15 - Logging

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-16 | System | Initial requirements document |

