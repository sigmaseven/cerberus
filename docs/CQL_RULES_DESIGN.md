# CQL Rules: Query-Based Detection System

## Overview

CQL Rules allow you to define detection rules using Cerberus Query Language (CQL) instead of traditional SIGMA YAML syntax. This provides a unified, powerful, and intuitive way to create detection rules.

**Example CQL Rule:**
```yaml
name: "Failed SSH Login Attempts"
query: 'event_type:"auth" AND message contains "Failed password" AND user!="root"'
severity: medium
```

## Benefits

1. **Unified Language**: Use the same CQL syntax for both searching and detection
2. **Simpler Syntax**: No complex YAML conditions - just write a query
3. **Testable**: Test rules by running the query in the search UI
4. **Powerful**: Leverage full CQL capabilities (regex, ranges, logical operators)
5. **Familiar**: If you know how to search, you know how to write rules

## Architecture

### Components Created

```
core/cql_rule.go         - CQL rule schema and data structures
search/evaluator.go      - Single-event CQL evaluator
storage/cqlrulestorage.go - CQL rule persistence
detect/cql_detector.go   - CQL rule detection engine
api/cql_handlers.go      - REST API endpoints
frontend/src/pages/CQLRules/ - UI components
```

### Data Flow

```
Event → Detector → CQL Evaluator → Match? → Alert
                      ↓
                 Parse CQL Query
                      ↓
                 Evaluate AST
                      ↓
                Check Conditions
```

## CQL Rule Schema

```go
type CQLRule struct {
    ID              string            // Unique identifier
    Name            string            // Rule name
    Description     string            // Detailed description
    Query           string            // CQL query string
    Severity        string            // low, medium, high, critical
    Enabled         bool              // Rule enabled/disabled
    Tags            []string          // Tags for categorization
    MITRE           []string          // MITRE ATT&CK techniques
    Actions         []string          // Actions to trigger
    Metadata        map[string]string // Custom metadata
    CreatedAt       time.Time
    UpdatedAt       time.Time
    Author          string
    References      []string          // External references
    FalsePositives  string            // Known false positive info
}
```

## CQL Query Examples

### Authentication Failures

**Failed Login Attempts:**
```
event_type:"auth" AND message contains "failed" AND user exists
```

**Brute Force Detection:**
```
event_type:"auth" AND message contains "failed" AND source_ip exists
```

### Network Security

**Port Scanning:**
```
dest_port > 1024 AND dest_port < 65535 AND protocol:"tcp"
```

**Suspicious Outbound:**
```
source_ip startswith "192.168" AND dest_port in [4444, 5555, 6666, 7777]
```

### File Activity

**Suspicious File Access:**
```
event_type:"file" AND filename endswith ".exe" AND path contains "temp"
```

**Ransomware Indicators:**
```
event_type:"file" AND filename matches ".*\\.encrypted$" OR filename contains "README"
```

### Process Execution

**PowerShell Obfuscation:**
```
process:"powershell.exe" AND (command contains "-enc" OR command contains "IEX")
```

**Suspicious Parent Process:**
```
parent_process:"winword.exe" AND process:"powershell.exe"
```

### Web Application

**SQL Injection Attempts:**
```
http_path contains "'" OR http_path contains "UNION SELECT"
```

**Admin Panel Access:**
```
http_path contains "/admin" AND http_status:403
```

### Cloud/Kubernetes

**Pod Creation:**
```
event_source:"kubernetes" AND event_type:"pod" AND action:"create"
```

**Privileged Container:**
```
event_source:"kubernetes" AND container_privileged:true
```

## CQL Evaluator Implementation

The evaluator works by:

1. **Parsing**: Convert CQL query string to AST (Abstract Syntax Tree)
2. **Validation**: Validate AST structure and syntax
3. **Evaluation**: Walk AST and check conditions against event
4. **Matching**: Return boolean match result + matched fields

```go
// Example usage
evaluator := search.NewEvaluator()
matched, fields, err := evaluator.Evaluate(rule.Query, event)
if matched {
    // Create alert
    alert, err := &CQLRuleMatch{
        Rule:          rule,
        Event:         event,
        MatchedFields: fields,
    }.ToAlert()
    if err != nil {
        // Handle error
        return err
    }
}
```

### Supported Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `=` or `equals` | Exact match | `user="admin"` |
| `!=` or `not_equals` | Not equal | `status!="success"` |
| `>`, `<`, `>=`, `<=` | Comparison | `count > 100` |
| `contains` | Substring | `message contains "error"` |
| `startswith` | Prefix | `filename startswith "/tmp"` |
| `endswith` | Suffix | `filename endswith ".exe"` |
| `matches` or `~=` | Regex | `email matches ".*@evil\.com"` |
| `in` | In array | `port in [80, 443, 8080]` |
| `not in` | Not in array | `user not in ["admin", "root"]` |
| `exists` | Field exists | `user exists` |
| `not exists` | Field missing | `password not exists` |

### Logical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `AND` | Both conditions | `A AND B` |
| `OR` | Either condition | `A OR B` |
| `NOT` | Negation | `NOT (A OR B)` |
| `( )` | Grouping | `(A OR B) AND C` |

## Storage Interface

```go
type CQLRuleStorage interface {
    // CRUD operations
    CreateRule(rule *core.CQLRule) error
    GetRule(id string) (*core.CQLRule, error)
    UpdateRule(rule *core.CQLRule) error
    DeleteRule(id string) error
    ListRules(filters map[string]interface{}) ([]*core.CQLRule, error)

    // Query operations
    GetEnabledRules() ([]*core.CQLRule, error)
    GetRulesByTag(tag string) ([]*core.CQLRule, error)
    GetRulesBySeverity(severity string) ([]*core.CQLRule, error)

    // Bulk operations
    EnableRule(id string) error
    DisableRule(id string) error
    BulkEnable(ids []string) error
    BulkDisable(ids []string) error

    // Testing
    TestRule(query string, event *core.Event) (bool, map[string]interface{}, error)
}
```

## Detection Engine Integration

### CQL Detector

```go
type CQLDetector struct {
    rules     []*core.CQLRule
    evaluator *search.Evaluator
    storage   CQLRuleStorage
    logger    *zap.SugaredLogger
}

func (d *CQLDetector) Detect(event *core.Event) []*core.Alert {
    alerts := []*core.Alert{}

    for _, rule := range d.rules {
        if !rule.Enabled {
            continue
        }

        matched, fields, err := d.evaluator.Evaluate(rule.Query, event)
        if err != nil {
            d.logger.Errorw("CQL evaluation error", "rule", rule.ID, "error", err)
            continue
        }

        if matched {
            alert, err := &core.CQLRuleMatch{
                Rule:          rule,
                Event:         event,
                Timestamp:     time.Now(),
                MatchedFields: fields,
            }.ToAlert()
            if err != nil {
                d.logger.Errorw("Failed to convert match to alert", "rule", rule.ID, "error", err)
                continue
            }

            alerts = append(alerts, alert)
        }
    }

    return alerts
}
```

### Integration with Existing Detector

```go
// In detect/detector.go
type Detector struct {
    ruleEngine   *RuleEngine    // Existing SIGMA rules
    cqlDetector  *CQLDetector   // New CQL rules
    mlDetector   MLAnomalyDetector
    // ...
}

func (d *Detector) processEvent(event *core.Event) {
    // Check traditional SIGMA rules
    sigmaAlerts := d.ruleEngine.Evaluate(event)

    // Check CQL rules
    cqlAlerts := d.cqlDetector.Detect(event)

    // Check ML rules
    mlAlerts := d.mlDetector.Detect(event)

    // Send all alerts
    for _, alert := range append(append(sigmaAlerts, cqlAlerts...), mlAlerts...) {
        d.alertCh <- alert
    }
}
```

## REST API Endpoints

### CQL Rule Management

```
POST   /api/v1/cql-rules              Create CQL rule
GET    /api/v1/cql-rules              List all CQL rules
GET    /api/v1/cql-rules/:id          Get specific rule
PUT    /api/v1/cql-rules/:id          Update rule
DELETE /api/v1/cql-rules/:id          Delete rule

POST   /api/v1/cql-rules/:id/enable   Enable rule
POST   /api/v1/cql-rules/:id/disable  Disable rule

POST   /api/v1/cql-rules/test         Test rule against sample event
POST   /api/v1/cql-rules/validate     Validate CQL query syntax

GET    /api/v1/cql-rules/tags         Get all tags
GET    /api/v1/cql-rules/search       Search rules
```

### Example Request/Response

**Create Rule:**
```json
POST /api/v1/cql-rules
{
  "name": "Failed Admin Login",
  "description": "Detects failed login attempts to admin accounts",
  "query": "event_type:\"auth\" AND message contains \"failed\" AND user:\"admin\"",
  "severity": "high",
  "enabled": true,
  "tags": ["authentication", "brute-force"],
  "mitre": ["T1110"],
  "actions": ["email-soc", "slack-security"]
}
```

**Response:**
```json
{
  "id": "cql_rule_123abc",
  "name": "Failed Admin Login",
  "query": "event_type:\"auth\" AND message contains \"failed\" AND user:\"admin\"",
  "severity": "high",
  "enabled": true,
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T10:30:00Z"
}
```

**Test Rule:**
```json
POST /api/v1/cql-rules/test
{
  "query": "event_type:\"auth\" AND message contains \"failed\"",
  "event": {
    "event_type": "auth",
    "message": "Failed password for admin",
    "user": "admin",
    "source_ip": "192.168.1.100"
  }
}
```

**Response:**
```json
{
  "matched": true,
  "matched_fields": {
    "event_type": "auth",
    "message": "Failed password for admin"
  },
  "explanation": "Query matched: event_type=\"auth\" (matched) AND message contains \"failed\" (matched)"
}
```

## Frontend UI

### Pages and Components

```
frontend/src/pages/CQLRules/
├── index.tsx                 # CQL Rules list page
├── CreateCQLRule.tsx         # Create new rule
├── EditCQLRule.tsx           # Edit existing rule
├── CQLRuleDetails.tsx        # View rule details
└── TestCQLRule.tsx           # Test rule UI

frontend/src/components/CQLRules/
├── CQLQueryEditor.tsx        # CQL query editor with syntax highlighting
├── CQLRuleForm.tsx           # Rule creation/edit form
├── CQLRuleCard.tsx           # Rule display card
├── CQLTestPanel.tsx          # Rule testing panel
└── CQLQueryBuilder.tsx       # Visual query builder (optional)
```

### CQL Query Editor Features

- **Syntax Highlighting**: Color-coded CQL syntax
- **Auto-completion**: Field name suggestions
- **Validation**: Real-time syntax checking
- **Examples**: Pre-built query templates
- **Test Mode**: Test against historical events

### CQL Rule Form

```tsx
<CQLRuleForm>
  <TextField name="name" required />
  <TextField name="description" multiline />

  <CQLQueryEditor
    value={query}
    onChange={setQuery}
    onValidate={handleValidate}
    placeholder='event_type:"auth" AND message contains "failed"'
  />

  <Select name="severity" options={["low", "medium", "high", "critical"]} />
  <TagInput name="tags" />
  <MITRESelector name="mitre" />
  <ActionSelector name="actions" />

  <TestPanel
    query={query}
    onTest={handleTest}
    results={testResults}
  />
</CQLRuleForm>
```

## Testing

### Unit Tests

```go
// search/evaluator_test.go
func TestEvaluator_SimpleCondition(t *testing.T) {
    evaluator := NewEvaluator()
    event := &core.Event{
        EventType: "auth",
        Message:   "Failed password for admin",
        UserName:  "admin",
    }

    matched, fields, err := evaluator.Evaluate(
        `event_type:"auth" AND message contains "failed"`,
        event,
    )

    assert.NoError(t, err)
    assert.True(t, matched)
    assert.Equal(t, "auth", fields["event_type"])
}

func TestEvaluator_ComplexQuery(t *testing.T) {
    evaluator := NewEvaluator()
    event := &core.Event{
        EventType: "network",
        DestPort:  22,
        Protocol:  "tcp",
    }

    matched, _, err := evaluator.Evaluate(
        `(dest_port:22 OR dest_port:3389) AND protocol:"tcp"`,
        event,
    )

    assert.NoError(t, err)
    assert.True(t, matched)
}
```

### Integration Tests

```go
// detect/cql_detector_test.go
func TestCQLDetector_Integration(t *testing.T) {
    // Create detector with test rules
    rules := []*core.CQLRule{
        {
            ID:       "rule1",
            Name:     "Failed Auth",
            Query:    `event_type:"auth" AND message contains "failed"`,
            Severity: "medium",
            Enabled:  true,
        },
    }

    detector := NewCQLDetector(rules, logger)

    // Test with matching event
    event := &core.Event{
        EventType: "auth",
        Message:   "Failed login attempt",
    }

    alerts := detector.Detect(event)
    assert.Len(t, alerts, 1)
    assert.Equal(t, "Failed Auth", alerts[0].RuleName)
}
```

## Performance Considerations

### Optimization Strategies

1. **Query Caching**: Cache parsed CQL AST to avoid re-parsing
2. **Rule Indexing**: Index rules by field names for faster matching
3. **Lazy Evaluation**: Short-circuit AND/OR operators
4. **Regex Caching**: Cache compiled regexes in evaluator
5. **Parallel Evaluation**: Evaluate multiple rules concurrently

### Performance Benchmarks

Expected performance (1000 rules):
- Simple condition: ~0.1ms per event
- Complex query (5+ conditions): ~0.5ms per event
- Regex matching: ~1ms per event
- Overall throughput: 10,000-50,000 events/second

## Migration Path

### From SIGMA Rules to CQL Rules

**SIGMA Rule:**
```yaml
title: Failed SSH Login
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event_type: auth
    message|contains: 'Failed password'
  condition: selection
```

**Equivalent CQL Rule:**
```yaml
name: "Failed SSH Login"
query: 'event_type:"auth" AND message contains "Failed password"'
severity: medium
```

### Conversion Script

```python
# tools/sigma_to_cql.py
def convert_sigma_to_cql(sigma_rule):
    """Convert SIGMA rule to CQL rule"""
    conditions = []

    for field, value in sigma_rule['detection']['selection'].items():
        if '|contains' in field:
            field = field.replace('|contains', '')
            conditions.append(f'{field} contains "{value}"')
        else:
            conditions.append(f'{field}:"{value}"')

    query = ' AND '.join(conditions)

    return {
        'name': sigma_rule['title'],
        'query': query,
        'severity': sigma_rule.get('level', 'medium'),
    }
```

## Example Rule Library

### Authentication

```
# Brute Force Detection
query: 'event_type:"auth" AND message contains "failed" AND source_ip exists'
severity: high

# Successful Login After Failures
query: 'event_type:"auth" AND message contains "Accepted" AND user:"admin"'
severity: medium

# SSH Key Authentication
query: 'event_type:"auth" AND message contains "Accepted publickey"'
severity: low
```

### Network

```
# Port Scan Detection
query: 'dest_port > 1000 AND protocol:"tcp" AND dest_port < 65535'
severity: medium

# Outbound to Suspicious Ports
query: 'dest_port in [4444, 5555, 6666, 7777] AND protocol:"tcp"'
severity: high

# Large Data Transfer
query: 'bytes_sent > 10000000'
severity: low
```

### File Activity

```
# Suspicious File Creation
query: 'event_type:"file" AND action:"create" AND filename endswith ".exe" AND path contains "temp"'
severity: medium

# File Encryption
query: 'event_type:"file" AND filename matches ".*\\.encrypted$"'
severity: critical

# System File Modification
query: 'event_type:"file" AND path startswith "C:\\Windows\\System32"'
severity: high
```

## Documentation

### User Guide

**Creating Your First CQL Rule:**

1. Navigate to **CQL Rules** page
2. Click **Create Rule**
3. Fill in rule details:
   - Name: "Failed Admin Login"
   - Description: "Detects failed admin authentication"
   - Query: `event_type:"auth" AND message contains "failed" AND user:"admin"`
   - Severity: High
4. Click **Test Rule** to validate
5. Click **Create** to save

**Testing Rules:**

1. Go to rule details page
2. Click **Test** tab
3. Enter sample event JSON or select from recent events
4. Click **Test Query**
5. View match results and matched fields

**Best Practices:**

- Start with simple queries and add complexity
- Test rules against historical data before enabling
- Use descriptive names and documentation
- Tag rules for easy organization
- Set appropriate severity levels
- Document false positive scenarios

## Roadmap

### Phase 1: Core Implementation ✅
- [x] CQL rule schema
- [x] CQL evaluator
- [x] Storage interface

### Phase 2: Integration (In Progress)
- [ ] Detection engine integration
- [ ] API endpoints
- [ ] Frontend UI

### Phase 3: Advanced Features
- [ ] Visual query builder
- [ ] Rule templates library
- [ ] SIGMA → CQL converter
- [ ] Performance dashboard
- [ ] Rule testing automation

### Phase 4: Enterprise Features
- [ ] Rule versioning
- [ ] Approval workflows
- [ ] Multi-tenancy support
- [ ] Rule marketplace
- [ ] Advanced analytics

## Conclusion

CQL Rules provide a powerful, intuitive way to define detection logic using the same query language you use for searching. This unification simplifies rule creation, testing, and maintenance while providing the full expressiveness of CQL.

**Key Advantages:**
- ✅ Unified query language
- ✅ Simple syntax
- ✅ Easy to test
- ✅ Powerful matching
- ✅ Familiar to users

**Next Steps:**
1. Complete storage implementation
2. Integrate with detection engine
3. Build API endpoints
4. Create frontend UI
5. Write comprehensive tests
6. Document migration path
