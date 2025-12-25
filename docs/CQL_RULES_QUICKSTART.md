# CQL Rules Quick Start Guide

## What are CQL Rules?

CQL Rules allow you to define detection rules using **Cerberus Query Language** instead of traditional SIGMA YAML syntax. This means you can use the same query language you already know from searching events to create powerful detection rules!

## Quick Comparison

### Traditional SIGMA Rule ❌
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
level: medium
```

### CQL Rule ✅
```json
{
  "name": "Failed SSH Login",
  "query": "event_type:\"auth\" AND message contains \"Failed password\"",
  "severity": "medium"
}
```

**Much simpler, right?** 🎉

## Core Concepts

### 1. Query Syntax

CQL Rules use the exact same syntax as the search bar:

```
field:value                    # Exact match
field contains "text"          # Contains
field startswith "prefix"      # Starts with
field endswith "suffix"        # Ends with
field matches "regex.*"        # Regex
field > 100                    # Comparison
field in [value1, value2]      # In array
field exists                   # Field exists
```

### 2. Logical Operators

Combine conditions with AND, OR, NOT:

```
A AND B                        # Both must match
A OR B                         # Either matches
NOT A                          # Negation
(A OR B) AND C                 # Grouping
```

### 3. Rule Structure

```json
{
  "name": "Rule Name",
  "description": "What this rule detects",
  "query": "CQL query here",
  "severity": "low|medium|high|critical",
  "enabled": true,
  "tags": ["category1", "category2"],
  "mitre": ["T1110"],
  "actions": ["email-soc", "slack-security"]
}
```

## Example Rules

### 1. Failed Authentication ⚠️

**Detect failed login attempts:**
```json
{
  "name": "Failed Login Attempts",
  "query": "event_type:\"auth\" AND message contains \"failed\"",
  "severity": "medium"
}
```

### 2. Brute Force Attack 🔴

**Detect multiple failures from same IP:**
```json
{
  "name": "Brute Force Detection",
  "query": "event_type:\"auth\" AND message contains \"failed\" AND source_ip exists",
  "severity": "high",
  "tags": ["brute-force", "authentication"]
}
```

### 3. Suspicious PowerShell 💀

**Detect encoded PowerShell commands:**
```json
{
  "name": "Suspicious PowerShell",
  "query": "process:\"powershell.exe\" AND (command contains \"-enc\" OR command contains \"IEX\")",
  "severity": "high",
  "tags": ["execution", "obfuscation"],
  "mitre": ["T1059.001", "T1027"]
}
```

### 4. Port Scanning 🔍

**Detect port scan activity:**
```json
{
  "name": "Port Scan Detection",
  "query": "dest_port > 1024 AND dest_port < 65535 AND protocol:\"tcp\"",
  "severity": "medium",
  "tags": ["network", "reconnaissance"]
}
```

### 5. Ransomware Indicators 🚨

**Detect ransomware file extensions:**
```json
{
  "name": "Ransomware File Extensions",
  "query": "event_type:\"file\" AND (filename endswith \".encrypted\" OR filename endswith \".locked\")",
  "severity": "critical",
  "tags": ["malware", "ransomware"],
  "mitre": ["T1486"],
  "actions": ["email-soc", "slack-security", "pagerduty-oncall"]
}
```

### 6. SQL Injection 💉

**Detect SQL injection attempts:**
```json
{
  "name": "SQL Injection Attempt",
  "query": "http_path contains \"'\" OR http_path contains \"UNION SELECT\" OR http_path contains \"OR 1=1\"",
  "severity": "high",
  "tags": ["web", "injection"]
}
```

### 7. Kubernetes Privileged Container 🐳

**Detect privileged pods:**
```json
{
  "name": "Privileged Pod Creation",
  "query": "event_source:\"kubernetes\" AND privileged:true AND action:\"create\"",
  "severity": "high",
  "tags": ["kubernetes", "container"]
}
```

## Testing Rules

Before enabling a rule, test it:

### Via API
```bash
curl -X POST http://localhost:8080/api/v1/cql-rules/test \
  -H "Content-Type: application/json" \
  -d '{
    "query": "event_type:\"auth\" AND message contains \"failed\"",
    "event": {
      "event_type": "auth",
      "message": "Failed password for admin",
      "user": "admin"
    }
  }'
```

### Via UI
1. Go to **CQL Rules** page
2. Click **Create Rule**
3. Enter your query
4. Click **Test Query**
5. Select sample events to test against
6. Review match results

## Advanced Queries

### Complex Conditions

**Multiple conditions with grouping:**
```
(user:"admin" OR user:"root") AND event_type:"auth" AND NOT message contains "Accepted"
```

**Regex matching:**
```
email matches ".*@evil\\.com" AND event_type:"email"
```

**Range queries:**
```
bytes_sent > 1000000 AND bytes_sent < 10000000
```

**Array membership:**
```
dest_port in [80, 443, 8080, 8443] AND protocol:"tcp"
```

### Field References

You can reference any field in the event:

**Standard Fields:**
- `event_type`, `message`, `timestamp`
- `source_ip`, `dest_ip`, `hostname`
- `username`, `process`, `filename`
- `protocol`, `port`, `severity`

**Nested Fields:**
- `user.name`, `process.parent`, `kubernetes.pod_name`

**Custom Fields:**
- Any field in `AdditionalFields` can be queried

## Performance Tips

### ✅ Good Practices

1. **Use specific fields:**
   ```
   event_type:"auth" AND user:"admin"  # Fast
   ```

2. **Avoid wildcards at start:**
   ```
   filename endswith ".exe"   # Fast
   filename contains "evil"   # OK
   filename startswith "C:\\" # Fast
   ```

3. **Cache-friendly:**
   - Simple equality checks are fastest
   - Contains is fast for short strings
   - Regex is slower but cached

### ❌ Avoid

1. **Too broad queries:**
   ```
   message contains "error"  # Too many matches
   ```

2. **Complex regex:**
   ```
   message matches "^.*very.*complex.*regex.*$"
   ```

3. **Many OR conditions:**
   ```
   field:"a" OR field:"b" OR field:"c" ...  # Use 'in' instead
   field in ["a", "b", "c"]  # Better
   ```

## Migration from SIGMA

### Step 1: Identify Simple Rules

Start with simple SIGMA rules that have straightforward conditions.

### Step 2: Convert Detection to Query

**SIGMA:**
```yaml
detection:
  selection:
    event_type: auth
    message|contains: 'failed'
  condition: selection
```

**CQL:**
```
event_type:"auth" AND message contains "failed"
```

### Step 3: Test

Test the converted rule against historical data to ensure it matches as expected.

### Step 4: Enable

Once validated, enable the CQL rule and disable the old SIGMA rule.

## Common Patterns

### Authentication

```
# Failed logins
event_type:"auth" AND message contains "failed"

# Successful login after failures
event_type:"auth" AND message contains "Accepted" AND user:"admin"

# Login from new location
event_type:"auth" AND geo_location not in ["US", "GB", "DE"]
```

### Network

```
# Suspicious ports
dest_port in [4444, 5555, 6666]

# Large transfers
bytes_sent > 100000000

# External connections
dest_ip not startswith "192.168" AND dest_ip not startswith "10."
```

### File Activity

```
# Executable in temp
filename endswith ".exe" AND path contains "temp"

# System file modified
path startswith "C:\\Windows\\System32"

# Multiple file operations
event_type:"file" AND action:"create" AND count > 100
```

### Web

```
# Admin access attempts
http_path contains "/admin" AND http_status:403

# SQL injection
http_path contains "'" OR http_path contains "UNION"

# XSS attempts
http_params contains "<script"
```

## Best Practices

### 1. Descriptive Names
✅ "Failed Admin SSH Login"
❌ "Rule 123"

### 2. Clear Descriptions
```json
{
  "name": "Failed SSH Login",
  "description": "Detects failed SSH authentication attempts that could indicate brute force attacks. Triggers on any failed password attempt to SSH service.",
  "query": "..."
}
```

### 3. Appropriate Severity

- **Low**: Informational, rarely actionable
- **Medium**: Worth investigating, potential threat
- **High**: Likely threat, requires action
- **Critical**: Active threat, immediate response

### 4. Use Tags

Organize rules with tags:
```json
{
  "tags": ["authentication", "ssh", "brute-force", "linux"]
}
```

### 5. Document False Positives

```json
{
  "false_positives": "Users with forgotten passwords may trigger this rule. Consider excluding service accounts."
}
```

### 6. Link to MITRE ATT&CK

```json
{
  "mitre": ["T1110.001"]  // Brute Force: Password Guessing
}
```

### 7. Configure Actions

```json
{
  "actions": ["email-soc", "slack-security"]
}
```

## Troubleshooting

### Query Not Matching

**Problem**: Rule doesn't trigger on expected events

**Solutions**:
1. Test query in search bar first
2. Check field names (use exact names from event)
3. Verify field values (case-sensitive)
4. Test with sample event using `/test` endpoint

### Too Many Matches

**Problem**: Rule triggers too frequently

**Solutions**:
1. Add more specific conditions
2. Use exact matches instead of contains
3. Add NOT conditions to exclude known good
4. Increase severity threshold

### Performance Issues

**Problem**: Rule is slow to evaluate

**Solutions**:
1. Simplify regex patterns
2. Use equality instead of contains when possible
3. Add field existence checks first
4. Split complex rules into multiple simpler ones

## Next Steps

1. **Try It Out**: Copy examples and test them
2. **Create Your First Rule**: Start with simple query
3. **Test Thoroughly**: Use test endpoint before enabling
4. **Monitor**: Check alert volume after enabling
5. **Iterate**: Refine queries based on results

## Resources

- **Full Documentation**: `docs/CQL_RULES_DESIGN.md`
- **Example Library**: `cql_rules_examples.json`
- **CQL Syntax Guide**: See search documentation
- **API Reference**: See API docs for endpoints

## Questions?

Common questions:

**Q: Can I use both SIGMA and CQL rules?**
A: Yes! They work side-by-side. Use CQL for simpler rules, SIGMA for complex correlation.

**Q: How do I convert existing SIGMA rules?**
A: See migration section above. Start with simple rules first.

**Q: What's the performance impact?**
A: CQL rules are evaluated in ~0.1-1ms per event. 1000 rules can still process 10k-50k events/second.

**Q: Can I test rules before enabling?**
A: Yes! Use the `/test` API endpoint or UI test feature.

**Q: How do I debug a rule?**
A: Test with sample events and check which fields matched using the `matched_fields` response.

---

**Happy rule writing!** 🚀
