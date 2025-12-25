# SOAR (Security Orchestration, Automation, and Response) Requirements

**Document Owner**: Security Automation Team & SOC Operations
**Created**: 2025-11-16
**Status**: DRAFT - Pending Security Review & Stakeholder Approval
**Last Updated**: 2025-11-16
**Version**: 1.0
**Authoritative Sources**:
- NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide
- OWASP Automated Threat Handbook
- "Security Orchestration, Automation and Response (SOAR) Implementation Guide" - Gartner
- ISO/IEC 27035 - Information Security Incident Management
- MITRE ATT&CK Framework - Mitigation Strategies
- "The Practice of Network Security Monitoring" by Richard Bejtlich

---

## 1. Executive Summary

Security Orchestration, Automation, and Response (SOAR) capabilities enable Cerberus to automatically respond to security threats through orchestrated workflows (playbooks) that execute predefined actions. SOAR reduces mean time to respond (MTTR), improves consistency, and scales SOC operations.

**Critical Capabilities**:
- Playbook-driven workflow automation
- Action integration (webhooks, email, ticketing, blocking, isolation)
- Conditional logic and decision trees
- Human-in-the-loop approval gates
- Security-hardened action execution (SSRF protection, sandbox isolation)
- Enrichment and threat intelligence lookups
- Audit logging and compliance tracking

**Business Value**:
- **Reduce MTTR**: Automated response reduces incident response time from minutes/hours to seconds
- **Consistency**: Playbooks ensure consistent response to similar threats (eliminate human error)
- **Scalability**: Automation handles high alert volumes without increasing headcount
- **Compliance**: Audit logs provide evidence of timely response for compliance requirements

**Known Gaps** (Current Implementation):
- Playbook engine not yet implemented (types defined in `soar/types.go`, execution logic pending)
- Limited action types (webhook, notify, block IP implemented; enrichment, scripting pending)
- No approval workflow mechanism (all actions execute automatically)
- No playbook versioning or rollback
- Limited error handling and retry logic

---

## 2. Playbook Execution Requirements

### FR-SOAR-001: Playbook Definition Format (CRITICAL)

**Specification**:
Playbooks SHALL be defined in JSON format conforming to the Cerberus Playbook Schema with the following required fields:

```json
{
  "id": "string (UUID or unique identifier)",
  "name": "string (human-readable playbook name)",
  "description": "string (what the playbook does)",
  "enabled": boolean,
  "priority": integer (1-100, higher = executes first),
  "triggers": [PlaybookTrigger],
  "steps": [PlaybookStep],
  "created_by": "string (username)",
  "created_at": "ISO 8601 timestamp",
  "updated_at": "ISO 8601 timestamp",
  "tags": ["string"]
}
```

**PlaybookTrigger Schema**:
```json
{
  "type": "string (alert, severity, rule_id, ioc_type)",
  "conditions": [
    {
      "field": "string (alert field path, e.g., severity, rule_id)",
      "operator": "string (eq, ne, gt, lt, gte, lte, in, contains, matches)",
      "value": "any (value or array of values)"
    }
  ]
}
```

**PlaybookStep Schema**:
```json
{
  "id": "string (step identifier within playbook)",
  "name": "string (human-readable step name)",
  "action_type": "ActionType enum",
  "parameters": {object (action-specific parameters)},
  "continue_on_error": boolean,
  "timeout": "duration string (e.g., 30s, 1m, 5m)",
  "conditions": [PlaybookCondition] (optional step-level conditions)
}
```

**Acceptance Criteria**:
- [ ] Playbook JSON schema validated on load (JSON Schema validator)
- [ ] Required fields enforced (id, name, enabled, triggers, steps)
- [ ] Invalid playbooks rejected with clear error messages
- [ ] Playbooks loaded from file (`playbooks.json`) at startup
- [ ] Playbook hot-reload supported (update without restart)
- [ ] Maximum playbook size: 1 MB (prevent DoS via large playbooks)
- [ ] Maximum steps per playbook: 50 (prevent infinite loops)

**Rationale**:
JSON format is human-readable, widely supported, and integrates with version control. Schema validation prevents configuration errors.

**Test Method**:
1. Create valid playbook JSON
2. Verify playbook loads successfully
3. Create invalid playbook (missing required fields)
4. Verify playbook rejected with error
5. Test hot-reload (update file, verify changes applied)

**Priority**: CRITICAL

---

### FR-SOAR-002: Step Execution Orchestration (CRITICAL)

**Specification**:
Playbook steps SHALL execute in sequential order (step 1, step 2, ..., step N) unless parallel execution is explicitly configured.

**Execution Logic**:
1. Trigger evaluation: Check if alert matches playbook triggers
2. For each triggered playbook (ordered by priority):
   a. Evaluate playbook-level conditions (if any)
   b. For each step in sequence:
      - Evaluate step-level conditions (if any)
      - Execute action with configured parameters
      - Record result (success/failure, output, duration)
      - If `continue_on_error = false` and step fails: abort playbook
      - If `continue_on_error = true` and step fails: log error, continue to next step
   c. Record playbook execution result

**Acceptance Criteria**:
- [ ] Steps execute in defined order (1, 2, 3, ...)
- [ ] Step execution waits for previous step completion (sequential, not parallel by default)
- [ ] Step timeout enforced (execution aborted if exceeds timeout)
- [ ] `continue_on_error` flag controls failure behavior
- [ ] Playbook execution state persisted (can resume after crash)
- [ ] Execution context passed between steps (output of step N available to step N+1)

**Rationale**:
Sequential execution simplifies reasoning about playbook behavior and prevents race conditions. Most SOAR workflows are sequential by nature (investigate → notify → remediate).

**Test Method**:
1. Create playbook with 5 steps
2. Execute playbook
3. Verify steps execute in order (log timestamps verify sequence)
4. Test `continue_on_error = false`: verify playbook aborts on first failure
5. Test `continue_on_error = true`: verify playbook continues after failure

**Priority**: CRITICAL

---

### FR-SOAR-003: Conditional Logic Support (HIGH)

**Specification**:
Playbook steps SHALL support conditional execution based on alert fields or previous step outputs using the following operators:

**Supported Operators**:
- `eq` (equals): `field == value`
- `ne` (not equals): `field != value`
- `gt` (greater than): `field > value` (numeric only)
- `lt` (less than): `field < value` (numeric only)
- `gte` (greater than or equal): `field >= value`
- `lte` (less than or equal): `field <= value`
- `in` (value in array): `field in [value1, value2, ...]`
- `contains` (string contains): `field contains substring`
- `matches` (regex match): `field matches pattern`

**Condition Evaluation**:
- All conditions in array are AND-ed (all must be true)
- If any condition is false: skip step
- If all conditions are true: execute step

**Acceptance Criteria**:
- [ ] All operators implemented and tested
- [ ] Field paths support nested access (e.g., `event.source_ip`, `alert.severity`)
- [ ] Regex patterns validated on playbook load (prevent ReDoS)
- [ ] Type checking enforced (numeric operators reject string values)
- [ ] Conditions evaluated before step execution (skip if false)
- [ ] Condition evaluation latency ≤ 1ms (no significant overhead)

**Rationale**:
Conditional logic enables playbooks to adapt to context (e.g., only isolate host if severity is Critical, only block IP if confidence > 0.8).

**Example**:
```json
{
  "id": "step-2",
  "name": "Isolate Host (Critical Only)",
  "action_type": "isolate_host",
  "conditions": [
    {"field": "alert.severity", "operator": "eq", "value": "Critical"},
    {"field": "event.hostname", "operator": "ne", "value": null}
  ],
  "parameters": {"hostname": "{{event.hostname}}"}
}
```

**Test Method**:
1. Create playbook with conditional step
2. Execute with alert matching conditions: verify step executes
3. Execute with alert not matching conditions: verify step skipped
4. Test all operators with representative data

**Priority**: HIGH

---

### FR-SOAR-004: Error Handling and Retry Logic (HIGH)

**Specification**:
Playbook step failures SHALL be handled according to the following retry and error handling strategy:

**Retry Configuration** (per step):
- `max_retries`: Number of retry attempts (default: 0, max: 5)
- `retry_delay`: Delay between retries (default: 5s, supports exponential backoff)
- `retry_on`: List of error types to retry (e.g., `["network_timeout", "rate_limit"]`)

**Error Classification**:
- **Transient Errors**: Retry (network timeout, rate limit, service unavailable)
- **Permanent Errors**: Do not retry (invalid parameters, authentication failure, not found)

**Acceptance Criteria**:
- [ ] Retry logic implemented for transient errors
- [ ] Exponential backoff supported (retry_delay × 2^attempt)
- [ ] Permanent errors do not trigger retries
- [ ] Maximum 5 retry attempts enforced (prevent infinite loops)
- [ ] Retry attempts logged with attempt number and error
- [ ] After max retries exhausted: record failure, apply `continue_on_error` logic

**Rationale**:
Transient failures are common in distributed systems (network blips, service restarts). Retry logic improves reliability without manual intervention.

**Retry Strategy Example**:
```
Attempt 1: Execute → Timeout (retry after 5s)
Attempt 2: Execute → Timeout (retry after 10s, exponential backoff)
Attempt 3: Execute → Success (stop retrying)
```

**Test Method**:
1. Simulate transient failure (network timeout)
2. Configure step with max_retries = 3
3. Verify 3 retry attempts before failure
4. Simulate permanent failure (invalid parameter)
5. Verify no retries (immediate failure)

**Priority**: HIGH

---

### FR-SOAR-005: Step Timeout Configuration (MEDIUM)

**Specification**:
Each playbook step SHALL enforce a timeout to prevent infinite execution:

- **Default timeout**: 60 seconds (configurable per step)
- **Minimum timeout**: 5 seconds
- **Maximum timeout**: 600 seconds (10 minutes)
- **Timeout behavior**: Abort step execution, record timeout error, apply `continue_on_error` logic

**Acceptance Criteria**:
- [ ] Step timeout enforced using context.Context with deadline
- [ ] Timeout error distinct from other errors (identifiable in logs)
- [ ] Long-running actions (enrichment, ticket creation) support longer timeouts
- [ ] Short-running actions (update alert) use shorter timeouts
- [ ] Timeout expiration logged with step ID and duration

**Rationale**:
Timeout protection prevents playbook execution from hanging indefinitely due to unresponsive external services.

**Test Method**:
1. Create step with 5-second timeout
2. Simulate slow action (sleep 10 seconds)
3. Verify step aborted after 5 seconds
4. Verify timeout error logged

**Priority**: MEDIUM

---

### FR-SOAR-006: Parallel vs Sequential Execution (LOW)

**Specification**:
Playbooks SHALL support parallel execution of independent steps to improve performance:

**Parallel Execution Configuration**:
```json
{
  "parallel_groups": [
    {
      "steps": ["step-1", "step-2", "step-3"],
      "wait_for_all": true
    }
  ]
}
```

**Execution Logic**:
- Steps in `parallel_groups` execute concurrently
- If `wait_for_all = true`: Wait for all steps to complete before continuing
- If `wait_for_all = false`: Continue after first successful step

**Acceptance Criteria**:
- [ ] Parallel groups execute steps concurrently
- [ ] wait_for_all flag controls synchronization
- [ ] Parallel execution faster than sequential (benchmark)
- [ ] Error handling works in parallel (one failure does not block others)
- [ ] Maximum 10 concurrent steps (prevent resource exhaustion)

**Rationale**:
Independent actions (send email, create ticket, call webhook) can execute in parallel to reduce total playbook execution time.

**Current Status**: NOT IMPLEMENTED (future enhancement)

**Priority**: LOW (future enhancement)

---

## 3. Action Integration Requirements

### FR-SOAR-007: Webhook Action Execution (HIGH)

**Specification**:
The system SHALL support webhook actions to call external HTTP/HTTPS endpoints with alert data.

**Webhook Parameters**:
- `url` (required): HTTP/HTTPS endpoint URL
- `method` (optional): HTTP method (GET, POST, PUT, PATCH, DELETE, default: POST)
- `headers` (optional): Custom HTTP headers (map[string]string)
- `payload` (optional): Custom payload (overrides default alert payload)
- `timeout` (optional): Request timeout (default: 30s, max: 60s)
- `verify_tls` (optional): Verify TLS certificates (default: true)

**Security Requirements**:
- **SSRF Protection**: URL MUST be validated against allowlist (prevent internal network access)
- **Credential Management**: API keys/tokens stored securely (not in playbook JSON)
- **TLS Enforcement**: HTTP URLs upgraded to HTTPS, TLS 1.2+ required
- **Timeout Protection**: Request timeout enforced (prevent indefinite blocking)
- **Circuit Breaker**: Webhook failures trigger circuit breaker (fail fast after repeated failures)

**Acceptance Criteria**:
- [ ] Webhook action executes HTTP/HTTPS requests
- [ ] All HTTP methods supported
- [ ] Custom headers included in request
- [ ] Alert data serialized to JSON payload
- [ ] SSRF protection implemented (URL allowlist validated)
- [ ] TLS certificate verification enforced (unless explicitly disabled for testing)
- [ ] Circuit breaker protects against repeated failures (see FR-SOAR-007)
- [ ] Response status code and body logged
- [ ] Webhook timeout enforced (default 30s)

**Rationale**:
Webhooks enable integration with external systems (SIEM, SOAR, ticketing, notification services). SSRF protection is critical security requirement.

**SSRF Protection Implementation**:
```go
// Allowlist of permitted webhook domains
var webhookAllowlist = []string{
  "hooks.slack.com",
  "api.pagerduty.com",
  "your-company.atlassian.net",
  // Internal domains explicitly allowed
}

func validateWebhookURL(url string) error {
  parsed, _ := url.Parse(url)

  // Block private IP ranges (RFC 1918, RFC 4193)
  if isPrivateIP(parsed.Hostname()) {
    return errors.New("webhook URL must not target private IP ranges")
  }

  // Block localhost/loopback
  if isLocalhost(parsed.Hostname()) {
    return errors.New("webhook URL must not target localhost")
  }

  // Check allowlist
  if !isAllowlisted(parsed.Hostname(), webhookAllowlist) {
    return errors.New("webhook URL not in allowlist")
  }

  return nil
}
```

**Test Method**:
1. Create webhook action with valid URL
2. Execute action, verify HTTP request sent
3. Verify response logged
4. Test SSRF protection: attempt internal IP (127.0.0.1, 192.168.x.x, 169.254.x.x)
5. Verify request rejected

**Priority**: HIGH

---

### FR-SOAR-008: Email Notification Action (MEDIUM)

**Specification**:
The system SHALL support email notification actions to send alerts via SMTP.

**Email Parameters**:
- `to` (required): Recipient email address(es) (array)
- `cc` (optional): CC recipients
- `subject` (required): Email subject (supports template variables)
- `body` (required): Email body (supports HTML and template variables)
- `attachments` (optional): File attachments (PDF reports, CSV exports)
- `smtp_server` (required): SMTP server configuration (from config)

**Template Variables**:
- `{{alert.id}}`: Alert ID
- `{{alert.severity}}`: Alert severity
- `{{alert.rule_id}}`: Triggering rule ID
- `{{event.source_ip}}`: Event source IP
- `{{event.timestamp}}`: Event timestamp
- Template engine: Go `text/template` or simple string replacement

**Acceptance Criteria**:
- [ ] Email action sends via SMTP
- [ ] Template variables replaced with actual values
- [ ] HTML email body supported
- [ ] Multiple recipients supported (to, cc, bcc)
- [ ] Attachments supported (base64 encoded)
- [ ] SMTP authentication supported (PLAIN, LOGIN, CRAM-MD5)
- [ ] TLS/STARTTLS encryption enforced
- [ ] Email sending errors logged (SMTP errors)
- [ ] Rate limiting: max 100 emails/minute (prevent spam)

**Rationale**:
Email notifications are standard alerting mechanism for security teams. Template support enables customized messages.

**Test Method**:
1. Configure SMTP server (use test SMTP service like Mailtrap)
2. Create email action with template
3. Execute action, verify email received
4. Verify template variables replaced
5. Test HTML email rendering

**Priority**: MEDIUM

---

### FR-SOAR-009: Ticket Creation Action (HIGH)

**Specification**:
The system SHALL support ticket creation in external ticketing systems (Jira, ServiceNow, GitHub Issues).

**Ticket Parameters** (Jira Example):
- `system` (required): Ticketing system type (jira, servicenow, github)
- `project_key` (required): Jira project key (e.g., "SEC")
- `issue_type` (required): Issue type (Bug, Task, Story, Incident)
- `summary` (required): Ticket title/summary
- `description` (required): Ticket description (supports Markdown/Jira markup)
- `priority` (optional): Ticket priority (Highest, High, Medium, Low, Lowest)
- `assignee` (optional): Assignee username
- `labels` (optional): Ticket labels/tags

**Integration Configuration** (stored in config, not playbook):
```yaml
integrations:
  jira:
    url: "https://your-company.atlassian.net"
    username: "automation@company.com"
    api_token: "${JIRA_API_TOKEN}" # From secret manager
  servicenow:
    instance: "yourcompany.service-now.com"
    username: "cerberus_integration"
    password: "${SERVICENOW_PASSWORD}"
```

**Acceptance Criteria**:
- [ ] Jira ticket creation implemented (via Jira REST API)
- [ ] ServiceNow incident creation implemented (via ServiceNow API)
- [ ] GitHub issue creation implemented (via GitHub API)
- [ ] API credentials stored securely (environment variables or secret manager)
- [ ] Ticket ID returned and logged
- [ ] Ticket creation errors handled gracefully (log, retry transient failures)
- [ ] Rate limiting respected (Jira: 10 requests/second, ServiceNow: varies)
- [ ] Ticket URL included in action result (for SOC reference)

**Rationale**:
Ticket creation automates case management workflow. Ensures every critical alert has corresponding ticket for tracking and compliance.

**Test Method**:
1. Configure Jira/ServiceNow integration
2. Create ticket creation action
3. Execute action, verify ticket created
4. Verify ticket ID and URL logged
5. Test error handling (invalid project key)

**Priority**: HIGH

---

### FR-SOAR-010: Incident Response Actions (HIGH)

**Specification**:
The system SHALL support automated incident response actions including IP blocking and host isolation.

**Block IP Action Parameters**:
- `ip_address` (optional): IP to block (defaults to `event.source_ip`)
- `duration` (optional): Block duration (default: 24h, max: 30 days)
- `firewall_api` (required): Firewall API endpoint (from config)
- `action` (required): Block action (block, unblock)

**Isolate Host Action Parameters**:
- `hostname` (required): Host to isolate
- `edr_api` (required): EDR/XDR API endpoint (from config)
- `action` (required): Isolation action (isolate, restore)

**Security Considerations**:
- **Approval Workflow**: Destructive actions (block, isolate) SHOULD require approval (see FR-SOAR-021)
- **Allowlist Protection**: Prevent blocking critical infrastructure IPs (DNS servers, domain controllers)
- **Audit Logging**: All blocking/isolation actions logged with username, timestamp, reason
- **Automatic Expiration**: Blocks expire automatically (prevent permanent blocks from forgotten incidents)

**Acceptance Criteria**:
- [ ] Block IP action integrates with firewall API (Palo Alto, Fortinet, generic REST API)
- [ ] Isolate host action integrates with EDR/XDR (CrowdStrike, SentinelOne, Microsoft Defender)
- [ ] IP allowlist enforced (prevent blocking critical IPs)
- [ ] Block duration enforced (automatic unblock after expiration)
- [ ] Approval workflow supported (manual approval required for production)
- [ ] Rollback supported (unblock IP, restore host connectivity)
- [ ] Action status queryable (is IP still blocked? is host still isolated?)

**Rationale**:
Automated blocking and isolation are critical incident response capabilities. Contain threats before manual analysis completes (reduce dwell time).

**Implementation Note**: Current implementation (`soar/actions.go`) includes simulation mode (logs action without executing). Production deployment requires integration with actual firewall/EDR APIs.

**Test Method**:
1. Create block IP action
2. Execute in simulation mode, verify log entry
3. (Production) Execute with firewall integration, verify IP blocked
4. Verify automatic unblock after duration
5. Test allowlist protection (attempt to block DNS server IP)

**Priority**: HIGH

---

### FR-SOAR-011: Custom Script Execution (MEDIUM)

**Specification**:
The system SHALL support execution of custom scripts (Python, Bash, PowerShell) for specialized response actions.

**Script Parameters**:
- `script_path` (required): Path to script file (relative to scripts directory)
- `interpreter` (required): Script interpreter (python3, bash, powershell)
- `arguments` (optional): Command-line arguments (array)
- `environment` (optional): Environment variables (map[string]string)
- `timeout` (optional): Script execution timeout (default: 60s, max: 300s)
- `working_directory` (optional): Script working directory

**Security Requirements** (CRITICAL):
- **Sandbox Execution**: Scripts MUST run in isolated sandbox (container, chroot, restricted user)
- **Path Validation**: Script paths MUST be validated (prevent path traversal)
- **Argument Sanitization**: Arguments sanitized to prevent command injection
- **Resource Limits**: CPU, memory, disk I/O limits enforced
- **Network Restrictions**: Sandbox has limited network access (allowlist)
- **Approval Required**: Script execution MUST require explicit approval (manual or pre-approved script allowlist)

**Acceptance Criteria**:
- [ ] Script execution implemented with sandbox isolation
- [ ] Supported interpreters: Python 3, Bash, PowerShell
- [ ] Script output captured (stdout, stderr)
- [ ] Script exit code checked (0 = success, non-zero = failure)
- [ ] Timeout enforced (script killed if exceeds timeout)
- [ ] Resource limits enforced (CPU, memory caps)
- [ ] Command injection prevented (argument sanitization)
- [ ] Path traversal prevented (script path validation)
- [ ] Audit logging (script executed, arguments, output, exit code)

**Rationale**:
Custom scripts enable complex response actions not covered by built-in action types (parse malware samples, query threat intel APIs, update firewall rules).

**Security Warning**: Script execution is high-risk feature. Sandbox isolation is MANDATORY. Consider disabling in production until sandbox implementation is hardened and audited.

**Test Method**:
1. Create safe test script (echo "Hello World")
2. Execute script action, verify output captured
3. Test timeout (script that sleeps 120 seconds, timeout 30s)
4. Test command injection protection (attempt to inject shell metacharacters)
5. Test path traversal protection (attempt ../../../etc/passwd)

**Priority**: MEDIUM (implement only after sandbox hardening)

---

## 4. Enrichment Requirements

### FR-SOAR-012: Threat Intelligence Lookups (HIGH)

**Specification**:
The system SHALL support threat intelligence enrichment actions to query external threat intel feeds and enrich alerts with context.

**Enrichment Sources**:
- **VirusTotal**: File hash, IP, domain, URL lookups
- **AbuseIPDB**: IP reputation lookups
- **AlienVault OTX**: IOC reputation and context
- **Custom Threat Intel Feeds**: Generic HTTP API integration

**Enrichment Action Parameters**:
- `source` (required): Threat intel source (virustotal, abuseipdb, otx, custom)
- `ioc_type` (required): Indicator type (ip, domain, url, file_hash)
- `ioc_value` (optional): IOC value (defaults to alert field, e.g., `event.source_ip`)
- `api_key` (required): API key (from secret manager, not playbook)
- `timeout` (optional): Lookup timeout (default: 10s, max: 30s)

**Enrichment Result**:
- Store enrichment data in alert metadata: `alert.enrichment[source] = result`
- Enrichment fields: reputation score, categories, malware families, related IOCs
- Cache enrichment results (TTL: 1 hour) to reduce API calls and cost

**Acceptance Criteria**:
- [ ] VirusTotal API integration implemented
- [ ] AbuseIPDB API integration implemented
- [ ] AlienVault OTX API integration implemented
- [ ] Enrichment results stored in alert metadata
- [ ] Cache implemented (reduce duplicate lookups)
- [ ] Rate limiting respected (VirusTotal: 4 requests/minute free tier)
- [ ] API errors handled gracefully (log, continue playbook)
- [ ] Enrichment timeout enforced (prevent slow lookups from blocking playbook)

**Rationale**:
Threat intelligence enrichment provides context for alert triage (is this IP known malicious? has this file hash been seen before?). Enables faster, more informed decisions.

**Test Method**:
1. Configure VirusTotal API key
2. Create enrichment action for malicious IP
3. Execute action, verify enrichment data retrieved
4. Verify enrichment stored in alert metadata
5. Test caching (second lookup returns cached result)

**Priority**: HIGH

---

### FR-SOAR-013: GeoIP Enrichment (MEDIUM)

**Specification**:
The system SHALL support GeoIP enrichment to determine geographic location of IP addresses.

**GeoIP Parameters**:
- `ip_address` (optional): IP to lookup (defaults to `event.source_ip`)
- `database` (required): GeoIP database (MaxMind GeoLite2, IP2Location)

**Enrichment Fields**:
- Country (ISO code, full name)
- City
- Latitude/Longitude
- ASN (Autonomous System Number)
- Organization
- Connection type (residential, business, hosting)

**Acceptance Criteria**:
- [ ] MaxMind GeoLite2 database integration
- [ ] GeoIP lookup latency ≤ 5ms (local database)
- [ ] Enrichment results stored in alert metadata
- [ ] IPv4 and IPv6 support
- [ ] Database updates automated (weekly download)
- [ ] Missing/invalid IPs handled gracefully (log, skip enrichment)

**Rationale**:
GeoIP context helps identify anomalous access (login from unexpected country, access from high-risk regions).

**Test Method**:
1. Load MaxMind GeoLite2 database
2. Create GeoIP enrichment action
3. Execute with known IP (e.g., 8.8.8.8)
4. Verify country, city, ASN enriched
5. Benchmark lookup latency (should be <5ms)

**Priority**: MEDIUM

---

### FR-SOAR-014: DNS Resolution and WHOIS Lookup (LOW)

**Specification**:
The system SHALL support DNS resolution (forward/reverse) and WHOIS lookups for domain enrichment.

**DNS Resolution Parameters**:
- `hostname` (required): Hostname to resolve
- `record_type` (optional): DNS record type (A, AAAA, MX, TXT, default: A)

**WHOIS Lookup Parameters**:
- `domain` (required): Domain to query
- `whois_server` (optional): WHOIS server (defaults to appropriate server for TLD)

**Acceptance Criteria**:
- [ ] Forward DNS resolution (hostname → IP)
- [ ] Reverse DNS resolution (IP → hostname)
- [ ] WHOIS lookup for domain registration info
- [ ] DNS timeout enforced (5 seconds)
- [ ] DNS caching (reduce redundant lookups)
- [ ] WHOIS rate limiting (prevent abuse)

**Rationale**:
DNS and WHOIS data provide context for domain-based threats (newly registered domains, suspicious TLDs, hosting provider).

**Priority**: LOW (future enhancement)

---

### FR-SOAR-015: User and Asset Context Enrichment (MEDIUM)

**Specification**:
The system SHALL support enrichment with internal user and asset databases (CMDB, LDAP, Active Directory).

**User Enrichment** (from LDAP/AD):
- Username → Full name, email, department, manager, account status
- Identify privileged accounts (admin, service accounts)

**Asset Enrichment** (from CMDB):
- Hostname → Owner, location, criticality, OS version, patch level
- Identify critical assets (domain controllers, databases, production servers)

**Acceptance Criteria**:
- [ ] LDAP/Active Directory integration for user lookups
- [ ] CMDB integration for asset lookups
- [ ] Enrichment results stored in alert metadata
- [ ] Cache implemented (TTL: 1 hour for user data, 24 hours for asset data)
- [ ] Missing users/assets handled gracefully (unknown user/asset logged)
- [ ] LDAP bind credentials stored securely

**Rationale**:
User and asset context enables risk-based alerting (alert on privileged user anomalies, prioritize critical asset alerts).

**Test Method**:
1. Configure LDAP connection
2. Create user enrichment action
3. Execute with username, verify user details retrieved
4. Test asset enrichment with hostname

**Priority**: MEDIUM

---

### FR-SOAR-016: Caching Strategy for Enrichments (MEDIUM)

**Specification**:
Enrichment actions SHALL implement caching to reduce API calls, costs, and latency.

**Cache Configuration**:
- **Cache Backend**: Redis (recommended) or in-memory (fallback)
- **Cache TTL**: Configurable per enrichment type (default: 1 hour)
- **Cache Key**: Hash of enrichment source + IOC type + IOC value
- **Cache Invalidation**: TTL-based expiration, manual invalidation API

**TTL Recommendations**:
- IP reputation: 1 hour (reputation changes frequently)
- Domain reputation: 6 hours
- File hash: 24 hours (file hash reputation stable)
- GeoIP: 7 days (location rarely changes)
- User/asset: 1 hour (user status changes)

**Acceptance Criteria**:
- [ ] Cache implemented (Redis or in-memory)
- [ ] Cache hit/miss metrics exposed (Prometheus)
- [ ] Cache TTL configurable per enrichment type
- [ ] Cache invalidation API (manual purge)
- [ ] Enrichment latency: <5ms cache hit, <500ms cache miss
- [ ] Cache hit rate >80% (indicates effective caching)

**Rationale**:
Caching reduces API costs (VirusTotal charges per lookup), improves performance, and reduces dependency on external services.

**Test Method**:
1. Execute enrichment action (cache miss, API call)
2. Execute same enrichment (cache hit, no API call)
3. Verify cache hit latency <5ms
4. Verify cache expiration after TTL

**Priority**: MEDIUM

---

## 5. Security Requirements

### FR-SOAR-017: Command Injection Prevention (CRITICAL)

<!-- GATEKEEPER FIX: BLOCKING-001
Issue: "Block or escape" is NOT a specification - developers will implement differently
Fix: Specify EXACT approach - shell metacharacters SHALL be rejected (return error), not escaped
Provide allowlist regex, specify allowlist vs blocklist
Justification: Escaping is error-prone (different shells, different escaping rules). Rejection is unambiguous.
-->

**Specification**:
All action parameters that are passed to external commands or scripts SHALL use allowlist validation and REJECT (not escape) any input containing shell metacharacters.

**Vulnerable Scenarios**:
- Script execution with user-controlled arguments
- Webhook URLs with user-controlled parameters
- Shell commands constructed from alert fields

**Protection Mechanisms (MANDATORY)**:

1. **Allowlist Validation** (REQUIRED for all external inputs):
   - **Script paths**: SHALL match regex `^[a-zA-Z0-9._/-]+$`
   - **Script arguments**: SHALL match regex `^[a-zA-Z0-9._:/@-]+$`
   - **File paths**: SHALL match regex `^[a-zA-Z0-9._/-]+$` AND prevent path traversal (no `..`)
   - **URLs**: SHALL be validated against allowlist (see FR-SOAR-018 SSRF protection)

2. **Shell Metacharacter Rejection** (NOT escaping):
   **Blocklisted characters** (input containing ANY of these SHALL be rejected with error):
   ```
   ; | & $ ` \ " ' < > ( ) { } [ ] * ? ~ ! # \n \r
   ```
   **Error behavior**: Return `400 Bad Request` with message "Invalid input: shell metacharacters not permitted"

3. **Parameterized API Usage** (MANDATORY):
   - All external commands SHALL use `os/exec.Cmd` with Args array
   - Shell invocation (`sh -c`, `bash -c`, `cmd.exe /c`) is **PROHIBITED**
   - Direct execution only (no shell interpretation layer)

4. **Sandboxing**: Execute scripts in isolated sandbox (see FR-SOAR-019)

**Acceptance Criteria**:
- [ ] Allowlist regex enforced for script paths: `^[a-zA-Z0-9._/-]+$`
- [ ] Allowlist regex enforced for script arguments: `^[a-zA-Z0-9._:/@-]+$`
- [ ] Shell metacharacters REJECTED (return error), not escaped
- [ ] All external command invocations use `os/exec.Cmd` with Args array (never shell string)
- [ ] Shell invocation (`sh -c`, `bash -c`) disabled (code audit confirms no usage)
- [ ] Path traversal prevention (reject `..` in file paths)
- [ ] Automated security tests verify command injection protection
- [ ] Security audit performed by external reviewer before production

**Rationale**:
Command injection is critical vulnerability (RCE). Malicious alert data could execute arbitrary commands on SOAR server. Rejection is safer than escaping (no ambiguity about escaping rules for different shells).

**Why Rejection Instead of Escaping**:
- Escaping is shell-dependent (Bash vs Zsh vs cmd.exe have different rules)
- Escaping failures are common (forgotten characters, double-escaping bugs)
- Allowlist + rejection is unambiguous: "only alphanumeric + limited special chars allowed"

**Secure Implementation** (MANDATORY pattern):
```go
// SECURE CODE - MANDATORY PATTERN
func executeScript(scriptPath string, args []string) error {
  // 1. Validate script path (allowlist)
  if !regexp.MustCompile(`^[a-zA-Z0-9._/-]+$`).MatchString(scriptPath) {
    return errors.New("invalid script path: only alphanumeric, dots, underscores, slashes allowed")
  }

  // 2. Prevent path traversal
  if strings.Contains(scriptPath, "..") {
    return errors.New("invalid script path: parent directory traversal not allowed")
  }

  // 3. Validate each argument (allowlist)
  for _, arg := range args {
    if !regexp.MustCompile(`^[a-zA-Z0-9._:/@-]+$`).MatchString(arg) {
      return errors.New("invalid argument: shell metacharacters not permitted")
    }
  }

  // 4. Use parameterized execution (NO shell)
  cmd := exec.Command(scriptPath, args...) // Args array, not shell string

  // 5. Execute in sandbox (see FR-SOAR-019)
  return executeSandboxed(cmd)
}
```

**PROHIBITED Pattern** (will fail security audit):
```go
// VULNERABLE CODE - PROHIBITED
cmd := exec.Command("sh", "-c", "script.sh " + arg) // NEVER DO THIS
cmd := exec.Command("bash", "-c", command) // PROHIBITED
```

**Test Method**:
1. Attempt command injection in script path: `../../etc/passwd; cat /etc/passwd`
2. Attempt command injection in script args: `"; rm -rf /"`
3. Attempt path traversal: `../../../etc/passwd`
4. Attempt shell metacharacters in URL: `http://example.com; curl evil.com`
5. Verify all attempts REJECTED with 400 Bad Request
6. Verify security tests in CI/CD catch injection attempts

**Priority**: CRITICAL

---

### FR-SOAR-018: SSRF Protection in Webhook Actions (CRITICAL)

<!-- GATEKEEPER FIX: BLOCKING-002
Issue: Missing DNS rebinding protection, incomplete IPv6 blocklist, vague redirect handling
Attack Scenario: DNS changes during execution (evil.com → 169.254.169.254)
Fix:
1. DNS rebinding: Resolve hostname ONCE before AND after connection, verify both match
2. Redirects: HTTP redirects SHALL be disabled (do not follow 301/302)
3. Complete IPv6 blocklist: Add ff00::/8 (multicast), fd00::/8 (ULA)
Justification: DNS rebinding is time-of-check-time-of-use (TOCTOU) vulnerability.
-->

**Specification**:
Webhook actions SHALL prevent Server-Side Request Forgery (SSRF) attacks by validating destination URLs with DNS rebinding protection, redirect blocking, and comprehensive IP blocklists.

**SSRF Threats**:
- Access internal network (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- Access cloud metadata services (169.254.169.254 - AWS, GCP, Azure metadata)
- Access localhost services (127.0.0.1, localhost)
- **DNS rebinding attacks** (TOCTOU: lookup returns public IP during validation, then resolves to private IP during request)
- HTTP redirects to internal IPs (initial URL public, redirect to 127.0.0.1)

**Protection Mechanisms (MANDATORY)**:

1. **URL Allowlist** (REQUIRED):
   - Only permit HTTPS URLs to explicitly allowlisted domains
   - Allowlist stored in `webhook_allowlist.yaml` (example domains: `hooks.slack.com`, `api.pagerduty.com`)
   - HTTP URLs **PROHIBITED** (HTTPS only)
   - Wildcard subdomains **PROHIBITED** (must list each subdomain explicitly)

2. **IP Blocklist (IPv4 and IPv6)**:
   **IPv4 Blocklisted Ranges**:
   ```
   127.0.0.0/8       (loopback)
   10.0.0.0/8        (RFC 1918 private)
   172.16.0.0/12     (RFC 1918 private)
   192.168.0.0/16    (RFC 1918 private)
   169.254.0.0/16    (link-local, AWS/Azure/GCP metadata)
   224.0.0.0/4       (multicast)
   240.0.0.0/4       (reserved)
   255.255.255.255   (broadcast)
   0.0.0.0/8         (current network)
   ```

   **IPv6 Blocklisted Ranges** (COMPLETE list):
   ```
   ::1/128           (loopback)
   ::/128            (unspecified)
   fc00::/7          (unique local addresses - private)
   fd00::/8          (ULA - private, GATEKEEPER FIX)
   fe80::/10         (link-local)
   ff00::/8          (multicast, GATEKEEPER FIX)
   fd00:ec2::/32     (AWS metadata IPv6)
   ```

3. **DNS Rebinding Protection** (MANDATORY):
   <!-- GATEKEEPER FIX: DNS rebinding protection -->
   **Attack Prevention**: Resolve hostname TWICE (before and after connection), verify both resolve to same public IP

   **Implementation**:
   ```
   Step 1: Parse URL, extract hostname
   Step 2: Resolve hostname → IP_INITIAL
   Step 3: Verify IP_INITIAL is public (not in blocklist)
   Step 4: Establish TCP connection to IP_INITIAL
   Step 5: Resolve hostname AGAIN → IP_FINAL
   Step 6: Verify IP_INITIAL == IP_FINAL (prevent DNS rebinding)
   Step 7: Verify IP_FINAL still public (not in blocklist)
   Step 8: If all checks pass, send HTTP request
   ```

   **Timeout**: DNS resolution timeout = 5 seconds (prevent DNS delay attacks)

4. **HTTP Redirect Blocking** (MANDATORY):
   <!-- GATEKEEPER FIX: Redirects SHALL be disabled, not validated -->
   - HTTP redirects (301, 302, 307, 308) **SHALL BE DISABLED**
   - HTTP client configured with `CheckRedirect: func(req, via) error { return http.ErrUseLastResponse }`
   - Rationale: Redirect validation is complex and error-prone. Blocking is safer.
   - If redirect detected: Return error "HTTP redirects not allowed for security reasons"

5. **Timeout Protection**: Request timeout = 30 seconds (prevent long-running SSRF probes)

**Acceptance Criteria**:
- [ ] Webhook URL allowlist enforced (configuration file: `webhook_allowlist.yaml`)
- [ ] HTTP URLs rejected (HTTPS only)
- [ ] Private IPv4 ranges blocked (all 9 ranges above)
- [ ] Private IPv6 ranges blocked (all 7 ranges above, including ff00::/8 and fd00::/8)
- [ ] DNS rebinding protection: Resolve hostname BEFORE and AFTER connection, verify match
- [ ] HTTP redirects DISABLED (301/302/307/308 return error, not followed)
- [ ] Cloud metadata IPs explicitly blocked (169.254.169.254, fd00:ec2::/32)
- [ ] DNS resolution timeout enforced (5 seconds)
- [ ] Security tests verify SSRF protection (attempt internal IPs, metadata IP, DNS rebinding, redirects)
- [ ] SSRF protection cannot be disabled (no "insecure mode" flag)

**Rationale**:
SSRF enables attacker to access internal services, steal cloud credentials (AWS keys from metadata service), scan internal network. DNS rebinding bypasses initial IP validation (TOCTOU vulnerability). HTTP redirects can redirect to internal IPs.

**DNS Rebinding Attack Scenario** (BLOCKED by this fix):
1. Attacker controls DNS for `evil.com`
2. Initial DNS lookup: `evil.com` → `1.2.3.4` (public IP, passes validation)
3. Attacker changes DNS: `evil.com` → `169.254.169.254` (metadata service)
4. Request sent to `evil.com` resolves to metadata IP
5. **Mitigation**: Resolve hostname AFTER connection, verify IP unchanged

**Secure Implementation** (MANDATORY pattern):
```go
func validateWebhookURL(urlStr string) error {
  // 1. Parse URL
  u, err := url.Parse(urlStr)
  if err != nil {
    return errors.New("invalid URL")
  }

  // 2. HTTPS only
  if u.Scheme != "https" {
    return errors.New("HTTP URLs not allowed, HTTPS required")
  }

  // 3. Check allowlist
  if !isAllowlisted(u.Hostname()) {
    return errors.New("URL not in allowlist")
  }

  // 4. Resolve hostname (initial)
  ipsInitial, err := net.LookupIP(u.Hostname())
  if err != nil {
    return errors.New("DNS resolution failed")
  }

  // 5. Verify initial IP is public (not blocklisted)
  for _, ip := range ipsInitial {
    if isBlocklistedIP(ip) {
      return errors.New("URL resolves to private/reserved IP")
    }
  }

  // 6. Establish connection
  conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
  if err != nil {
    return err
  }
  defer conn.Close()

  // 7. Resolve hostname AGAIN (DNS rebinding protection)
  ipsFinal, err := net.LookupIP(u.Hostname())
  if err != nil {
    return errors.New("DNS re-resolution failed")
  }

  // 8. Verify IP unchanged
  if !ipSlicesEqual(ipsInitial, ipsFinal) {
    return errors.New("DNS rebinding detected: IP changed during connection")
  }

  // 9. Verify final IP still public
  for _, ip := range ipsFinal {
    if isBlocklistedIP(ip) {
      return errors.New("DNS rebinding detected: IP now resolves to private IP")
    }
  }

  return nil
}

// HTTP client with redirects DISABLED
httpClient := &http.Client{
  Timeout: 30 * time.Second,
  CheckRedirect: func(req *http.Request, via []*http.Request) error {
    return http.ErrUseLastResponse // DO NOT follow redirects
  },
}
```

**Test Method**:
1. Create webhook action with internal IP (192.168.1.1) → Verify blocked
2. Attempt AWS metadata IP (169.254.169.254) → Verify blocked
3. Attempt IPv6 metadata (fd00:ec2::254) → Verify blocked
4. Attempt localhost (127.0.0.1, ::1) → Verify blocked
5. Attempt multicast IPv6 (ff00::1) → Verify blocked
6. Test DNS rebinding: Domain resolves to public IP initially, then private IP → Verify blocked
7. Test HTTP redirect: URL redirects to 127.0.0.1 → Verify redirect blocked (not followed)
8. Test HTTP (not HTTPS) URL → Verify rejected

**Priority**: CRITICAL

---

### FR-SOAR-019: Sandbox Execution for Custom Scripts (CRITICAL)

**Specification**:
Custom script execution SHALL occur in isolated sandbox with restricted capabilities.

**Sandbox Requirements**:
- **Process Isolation**: Scripts run in separate process/container
- **Filesystem Isolation**: Read-only filesystem, write access only to /tmp
- **Network Restrictions**: Limited outbound network (allowlist), no inbound
- **Resource Limits**: CPU (1 core max), memory (512 MB max), disk I/O (10 MB/s max)
- **Execution Time Limit**: 300 seconds (5 minutes) maximum
- **Capability Dropping**: Drop all Linux capabilities (CAP_*)
- **User Isolation**: Run as unprivileged user (not root)

**Recommended Sandbox Technologies**:
- **Docker**: Run scripts in ephemeral container (limited resources, no network)
- **gVisor**: Lightweight application kernel for additional isolation
- **Firecracker**: Lightweight VM (maximum isolation, higher overhead)
- **Seccomp**: Restrict system calls (block dangerous syscalls like `execve`, `fork`)

**Acceptance Criteria**:
- [ ] Scripts execute in isolated sandbox (Docker/gVisor/Firecracker)
- [ ] Filesystem read-only (except /tmp)
- [ ] Network access limited (allowlist)
- [ ] Resource limits enforced (CPU, memory, disk)
- [ ] Execution timeout enforced (5 minutes max)
- [ ] Sandbox escape attempts detected and blocked
- [ ] Security audit confirms sandbox isolation

**Rationale**:
Custom scripts are high-risk attack surface. Sandbox prevents malicious scripts from compromising SOAR server, accessing sensitive data, or pivoting to internal network.

**Security Warning**: Do not enable script execution in production until sandbox implementation is audited by security team.

**Test Method**:
1. Create test script attempting to access /etc/passwd
2. Verify access denied (read-only filesystem)
3. Create script attempting network access (curl http://internal-server)
4. Verify network blocked (or allowlist enforced)
5. Create script attempting to exhaust memory (allocate 10 GB)
6. Verify resource limit enforced (killed after 512 MB)

**Priority**: CRITICAL

---

### FR-SOAR-020: Approval Workflows for Destructive Actions (HIGH)

**Specification**:
Destructive actions (block IP, isolate host, delete data, run custom script) SHALL require manual approval before execution.

**Approval Workflow**:
1. Playbook execution pauses at approval step
2. Notification sent to approver (email, Slack, in-app notification)
3. Approver reviews action details and context
4. Approver approves or rejects action
5. If approved: action executes, playbook continues
6. If rejected: action skipped, playbook continues (or aborts based on config)
7. Timeout: If no response within timeout (default: 1 hour), action auto-rejects

**Approval Configuration** (per step):
```json
{
  "id": "step-3",
  "name": "Block Attacker IP",
  "action_type": "block_ip",
  "approval_required": true,
  "approvers": ["security-admin@company.com", "soc-lead@company.com"],
  "approval_timeout": "1h",
  "auto_reject_on_timeout": true,
  "parameters": {"ip_address": "{{event.source_ip}}"}
}
```

**Acceptance Criteria**:
- [ ] Approval workflow implemented (pause execution, send notification)
- [ ] Approvers notified via configured channel (email, Slack)
- [ ] Approval UI provided (web interface or API)
- [ ] Approval decision logged (who approved/rejected, timestamp, reason)
- [ ] Timeout enforced (auto-reject or auto-approve based on config)
- [ ] Approved actions execute normally
- [ ] Rejected actions skipped (logged, do not execute)

**Rationale**:
Automated blocking and isolation are high-impact actions. Approval workflow prevents false positives from causing business disruption (blocking legitimate user, isolating production server).

**Current Status**: NOT IMPLEMENTED (future enhancement)

**Priority**: HIGH

---

### FR-SOAR-021: Audit Logging for All SOAR Actions (CRITICAL)

**Specification**:
All playbook executions and action executions SHALL be logged to immutable audit log for compliance and forensics.

**Audit Log Fields**:
- Timestamp (ISO 8601, UTC)
- Playbook ID and name
- Alert ID (triggering alert)
- Step ID and action type
- Action parameters (sanitized, no secrets)
- Execution result (success, failure, error message)
- Execution duration
- User context (who triggered playbook, who approved action)
- IP address (source of API call)

**Audit Log Storage**:
- **Primary**: ClickHouse (searchable, queryable)
- **Secondary**: Append-only file (immutable, compliance)
- **Retention**: 90 days minimum (configurable, compliance requirement)

**Acceptance Criteria**:
- [ ] All playbook executions logged
- [ ] All action executions logged (including approval decisions)
- [ ] Secrets redacted from logs (API keys, passwords masked as `***`)
- [ ] Audit logs immutable (append-only, tamper-evident)
- [ ] Audit log search API provided (query by playbook, alert, time range)
- [ ] Audit log retention enforced (90 days minimum)
- [ ] Audit log exported for external SIEM (syslog, JSON)

**Rationale**:
Audit logs provide forensic evidence, compliance proof (SOC 2, PCI-DSS, HIPAA), and incident investigation trail.

**Test Method**:
1. Execute playbook with multiple steps
2. Query audit log for playbook execution
3. Verify all steps logged
4. Verify secrets redacted (API keys not visible)
5. Test audit log search (query by alert ID)

**Priority**: CRITICAL

---

### FR-SOAR-022: Rate Limiting for External API Calls (MEDIUM)

**Specification**:
External API calls (webhooks, threat intel, ticketing) SHALL enforce rate limiting to prevent abuse and respect API quotas.

**Rate Limiting Strategy**:
- **Per-Action Rate Limits**: Webhook (100 requests/minute), VirusTotal (4 requests/minute), Jira (10 requests/second)
- **Global Rate Limit**: 1,000 external API calls/minute (system-wide)
- **Rate Limit Enforcement**: Token bucket or sliding window algorithm
- **Rate Limit Exceeded Behavior**: Queue request (if queueing enabled) or return 429 error

**Acceptance Criteria**:
- [ ] Rate limits configured per action type
- [ ] Rate limit enforcement implemented (token bucket algorithm)
- [ ] Rate limit exceeded: request queued or rejected (configurable)
- [ ] Rate limit metrics exposed (Prometheus: requests allowed, requests rejected)
- [ ] Rate limits configurable (per action, per integration)
- [ ] Rate limit headers respected (HTTP Retry-After, X-RateLimit-*)

**Rationale**:
API rate limits prevent abuse (API bill shock, account suspension) and ensure fair usage of external services.

**Test Method**:
1. Configure VirusTotal rate limit (4 requests/minute)
2. Execute 10 enrichment actions rapidly
3. Verify 4 requests allowed, 6 queued or rejected
4. Wait 1 minute, verify remaining requests execute

**Priority**: MEDIUM

---

## 6. Performance Requirements

### FR-SOAR-023: Playbook Execution Latency (HIGH)

**Specification**:
Playbook execution SHALL complete within the following latency targets:

- **Simple playbook** (3 steps, no external calls): P99 ≤ 100ms
- **Moderate playbook** (5 steps, 2 external API calls): P99 ≤ 2000ms (2 seconds)
- **Complex playbook** (10 steps, 5 external API calls, enrichment): P99 ≤ 10000ms (10 seconds)

**Acceptance Criteria**:
- [ ] Playbook execution latency measured and logged
- [ ] P99 latency targets met for each playbook complexity tier
- [ ] Execution latency does not degrade with system load (concurrent playbooks)
- [ ] Slow actions (enrichment, ticket creation) do not block other steps
- [ ] Timeout enforcement prevents infinite execution

**Rationale**:
Fast playbook execution reduces mean time to respond (MTTR). Automated blocking should complete in seconds, not minutes.

**Test Method**:
1. Create simple 3-step playbook
2. Execute 100 times, measure latency distribution
3. Verify P99 ≤ 100ms
4. Repeat for moderate and complex playbooks

**Priority**: HIGH

---

### FR-SOAR-024: Concurrent Playbook Execution Limit (MEDIUM)

**Specification**:
The system SHALL support at least 50 concurrent playbook executions without latency degradation exceeding 20%.

**Acceptance Criteria**:
- [ ] 50 concurrent playbooks: P99 latency ≤ 120ms (100ms + 20%)
- [ ] Worker pool manages concurrency (limit concurrent goroutines)
- [ ] Queue depth monitored (playbooks waiting for execution)
- [ ] Queueing delay included in total latency metric
- [ ] Resource usage (CPU, memory) within limits during concurrent execution

**Rationale**:
Alert storms generate many concurrent playbook executions. System must handle concurrency without performance collapse.

**Test Method**:
1. Trigger 50 alerts simultaneously (50 playbook executions)
2. Measure per-playbook latency
3. Verify P99 latency ≤ 120ms
4. Monitor system resources

**Priority**: MEDIUM

---

### FR-SOAR-025: Action Timeout Thresholds (MEDIUM)

**Specification**:
Action timeout thresholds SHALL be enforced to prevent slow external services from blocking playbook execution:

- **Webhook**: 30 seconds default, 60 seconds maximum
- **Email**: 30 seconds
- **Ticket creation**: 60 seconds
- **Enrichment (API call)**: 10 seconds
- **Script execution**: 60 seconds default, 300 seconds maximum
- **Block IP / Isolate host**: 120 seconds

**Acceptance Criteria**:
- [ ] Timeout enforced for all action types
- [ ] Timeout configurable per action step
- [ ] Timeout expiration logged (distinct error type)
- [ ] Circuit breaker triggered by repeated timeouts
- [ ] Timeout does not leak resources (goroutines, connections)

**Rationale**:
Timeout protection prevents slow external services from causing playbook execution to hang indefinitely.

**Test Method**:
1. Create webhook action with 5-second timeout
2. Call endpoint that delays 10 seconds
3. Verify action aborted after 5 seconds
4. Verify timeout error logged

**Priority**: MEDIUM

---

### FR-SOAR-026: Queue Depth for Pending Actions (LOW)

**Specification**:
Playbook execution queue SHALL support up to 1,000 pending playbook executions without dropping requests.

**Acceptance Criteria**:
- [ ] Queue implemented (buffered channel or external queue)
- [ ] Queue capacity: 1,000 pending playbooks
- [ ] Queue overflow: reject new playbooks with error (503 Service Unavailable)
- [ ] Queue depth metric exposed (Prometheus)
- [ ] Alert triggered when queue depth > 800 (80% full)

**Rationale**:
Alert storms generate temporary spikes in playbook execution requests. Queue buffers spikes, prevents dropped executions.

**Test Method**:
1. Submit 1,500 playbook executions rapidly
2. Verify 1,000 queued, 500 rejected
3. Verify all 1,000 queued playbooks execute

**Priority**: LOW

---

### FR-SOAR-027: Memory Usage Per Playbook Execution (MEDIUM)

**Specification**:
Each playbook execution SHALL consume ≤ 10 MB memory (average) to support concurrent executions.

**Acceptance Criteria**:
- [ ] Average memory per playbook execution ≤ 10 MB
- [ ] 50 concurrent playbooks: total memory ≤ 500 MB
- [ ] No memory leaks (memory released after playbook completion)
- [ ] Large payloads (enrichment data) do not exhaust memory
- [ ] Memory profiling confirms memory usage within limits

**Rationale**:
Memory-efficient playbook execution enables high concurrency without exhausting system memory.

**Test Method**:
1. Profile memory usage during playbook execution
2. Verify average memory ≤ 10 MB per execution
3. Execute 50 concurrent playbooks, verify total memory ≤ 500 MB

**Priority**: MEDIUM

---

## 7. Reliability Requirements

### FR-SOAR-028: Playbook Execution Failure Rate (HIGH)

**Specification**:
Playbook execution failure rate SHALL NOT exceed 1% (excluding external service failures).

**Failure Classification**:
- **Internal Failures**: SOAR engine bugs, resource exhaustion, panics (target: 0%)
- **External Failures**: Webhook timeout, API rate limit, service unavailable (target: <5%)
- **Configuration Failures**: Invalid playbook, missing credentials (target: 0% after validation)

**Acceptance Criteria**:
- [ ] Internal failure rate ≤ 0.1% (1 failure per 1,000 executions)
- [ ] External failure rate ≤ 5% (acceptable, external services unreliable)
- [ ] Failures logged with stack trace and context
- [ ] Failure rate monitored (Prometheus alert if exceeds threshold)
- [ ] Automatic retry reduces external failure impact

**Rationale**:
High reliability ensures automated response is dependable. Low failure rate builds trust in automation.

**Test Method**:
1. Execute 10,000 playbooks
2. Measure failure rate (internal vs external)
3. Verify internal failure rate ≤ 0.1%

**Priority**: HIGH

---

### FR-SOAR-029: Automatic Retry on Transient Failures (MEDIUM)

**Specification**:
Transient failures (network timeout, 503 Service Unavailable, rate limit) SHALL trigger automatic retry with exponential backoff.

**Retry Strategy**:
- **Max Retries**: 3 (configurable, max 5)
- **Initial Delay**: 5 seconds
- **Backoff Multiplier**: 2x (exponential backoff: 5s, 10s, 20s)
- **Max Delay**: 60 seconds (cap exponential growth)
- **Jitter**: ±20% (randomize delay to prevent thundering herd)

**Acceptance Criteria**:
- [ ] Retry logic implemented for transient errors
- [ ] Exponential backoff with jitter
- [ ] Max retry attempts enforced
- [ ] Retry attempts logged (attempt number, delay)
- [ ] Permanent errors do not trigger retries
- [ ] Retry logic does not violate rate limits

**Rationale**:
Transient failures are common in distributed systems. Retry logic improves success rate without manual intervention.

**Test Method**:
1. Simulate transient failure (503 Service Unavailable)
2. Configure max_retries = 3
3. Verify 3 retry attempts with exponential backoff
4. Verify success after retry

**Priority**: MEDIUM

---

### FR-SOAR-030: Dead Letter Queue for Failed Actions (MEDIUM)

**Specification**:
Actions that fail after maximum retries SHALL be moved to dead letter queue for manual review.

**Dead Letter Queue (DLQ)**:
- **Storage**: SQLite table `dlq_actions` or ClickHouse table
- **Fields**: Playbook ID, step ID, action type, parameters, error, timestamp, retry count
- **Retention**: 30 days (configurable)
- **Processing**: Manual review UI, resubmit API

**Acceptance Criteria**:
- [ ] Failed actions moved to DLQ after max retries
- [ ] DLQ queryable (API: list failed actions, filter by date/type)
- [ ] DLQ UI displays failed actions with context
- [ ] Resubmit API allows retry of DLQ actions
- [ ] DLQ retention enforced (auto-delete after 30 days)
- [ ] DLQ metrics exposed (count of failed actions)

**Rationale**:
DLQ prevents silent failures. Failed actions are visible for debugging and manual retry.

**Test Method**:
1. Simulate permanent failure (invalid API key)
2. Verify action fails after 3 retries
3. Verify action added to DLQ
4. Query DLQ, verify action present

**Priority**: MEDIUM

---

### FR-SOAR-031: Playbook State Recovery After Crash (MEDIUM)

**Specification**:
In-progress playbook executions SHALL be recoverable after system crash or restart.

**State Persistence**:
- **Storage**: SQLite table `playbook_executions` or ClickHouse table
- **Fields**: Execution ID, playbook ID, alert ID, current step, status, started_at, updated_at
- **Update Frequency**: After each step completion

**Recovery Logic**:
1. On startup, query for in-progress playbook executions (status = "running")
2. For each in-progress execution:
   - If execution age > 1 hour: mark as failed (stale execution)
   - If execution age < 1 hour: resume from last completed step

**Acceptance Criteria**:
- [ ] Playbook execution state persisted after each step
- [ ] On restart, in-progress executions recovered
- [ ] Stale executions (>1 hour) marked as failed
- [ ] Recent executions (<1 hour) resumed from last completed step
- [ ] Idempotency: Resuming execution does not duplicate actions
- [ ] Recovery logged (execution ID, resumed from step X)

**Rationale**:
Crash recovery prevents data loss and ensures critical playbooks complete even after system failures.

**Current Status**: NOT IMPLEMENTED (future enhancement)

**Priority**: MEDIUM

---

### FR-SOAR-032: Idempotency Guarantees (LOW)

**Specification**:
Actions SHALL be idempotent where possible (executing same action twice produces same result, no duplicate side effects).

**Idempotent Actions**:
- **Update Alert**: Set status to "investigating" (idempotent, safe to repeat)
- **Block IP**: Block IP 192.168.1.100 (idempotent, blocking twice is same as blocking once)
- **Send Email**: NOT idempotent (sends duplicate email)
- **Create Ticket**: NOT idempotent (creates duplicate ticket)

**Idempotency Strategy**:
- **Execution ID**: Each playbook execution has unique ID
- **Deduplication**: Store execution ID in action metadata (e.g., Jira ticket custom field)
- **Retry Detection**: Before creating ticket, check if ticket with execution ID already exists

**Acceptance Criteria**:
- [ ] Idempotent actions identified and documented
- [ ] Non-idempotent actions implement deduplication (execution ID tracking)
- [ ] Retry does not create duplicate tickets/emails (deduplication works)
- [ ] Idempotency documented in action specification

**Rationale**:
Idempotency enables safe retries without fear of duplicate actions (duplicate tickets, duplicate blocks).

**Current Status**: NOT IMPLEMENTED (future enhancement)

**Priority**: LOW

---

## 8. Observability and Monitoring

### FR-SOAR-033: SOAR Metrics Exposure (HIGH)

**Specification**:
The system SHALL expose the following SOAR metrics via Prometheus `/metrics` endpoint:

**Playbook Metrics**:
- `cerberus_playbook_executions_total` (counter): Total playbook executions by playbook ID, status
- `cerberus_playbook_execution_duration_seconds` (histogram): Playbook execution latency
- `cerberus_playbook_execution_errors_total` (counter): Playbook execution failures

**Action Metrics**:
- `cerberus_action_executions_total` (counter): Total action executions by action type, status
- `cerberus_action_execution_duration_seconds` (histogram): Action execution latency
- `cerberus_action_execution_errors_total` (counter): Action execution failures

**Queue Metrics**:
- `cerberus_playbook_queue_depth` (gauge): Current playbook execution queue depth
- `cerberus_dlq_actions_total` (gauge): Current dead letter queue size

**Approval Metrics**:
- `cerberus_approval_requests_total` (counter): Total approval requests
- `cerberus_approval_latency_seconds` (histogram): Time from request to approval decision

**Acceptance Criteria**:
- [ ] All metrics exposed at `/metrics` endpoint
- [ ] Metrics updated in real-time
- [ ] Histogram buckets appropriate for SOAR latencies (0.1, 1, 10, 60 seconds)
- [ ] Metrics compatible with Prometheus scraping

**Rationale**:
Metrics enable monitoring, alerting, and capacity planning for SOAR operations.

**Priority**: HIGH

---

### FR-SOAR-034: SOAR Dashboards and Alerting (MEDIUM)

**Specification**:
Pre-built Grafana dashboards and Prometheus alerting rules SHALL be provided for SOAR monitoring.

**Dashboards**:
- **SOAR Overview**: Playbook execution rate, success rate, average latency
- **Action Performance**: Action execution latency by type, error rate
- **Queue Monitoring**: Queue depth, queueing delay, DLQ size

**Alerting Rules**:
- Playbook execution failure rate > 5% for 5 minutes
- Playbook execution latency P99 > 30 seconds for 5 minutes
- Queue depth > 800 (80% full) for 2 minutes
- DLQ size > 100 (indicates systemic issue)

**Acceptance Criteria**:
- [ ] Grafana dashboard JSON provided
- [ ] Prometheus alerting rules provided
- [ ] Dashboards and alerts tested and functional

**Priority**: MEDIUM

---

## 9. Compliance and Governance

### FR-SOAR-035: Playbook Versioning (LOW)

**Specification**:
Playbooks SHALL support versioning to enable rollback and change tracking.

**Versioning Strategy**:
- **Version Field**: Playbook schema includes `version` field (semantic versioning: 1.0.0)
- **Change History**: Store playbook change history (who changed, when, what changed)
- **Rollback**: API to rollback to previous playbook version

**Acceptance Criteria**:
- [ ] Playbook version field enforced
- [ ] Change history stored (SQLite table: playbook_versions)
- [ ] Rollback API implemented
- [ ] Version displayed in UI (current version, available versions)

**Current Status**: NOT IMPLEMENTED (future enhancement)

**Priority**: LOW

---

### FR-SOAR-036: RBAC for Playbook Management (MEDIUM)

**Specification**:
Playbook management operations SHALL enforce role-based access control (RBAC):

**Roles**:
- **Viewer**: View playbooks, view execution history
- **Operator**: Execute playbooks manually, approve actions
- **Editor**: Create, update playbooks (cannot delete)
- **Admin**: Full access (create, update, delete, enable/disable)

**Acceptance Criteria**:
- [ ] RBAC enforced for all playbook APIs
- [ ] Unauthorized operations return 403 Forbidden
- [ ] Role assignments managed via user management API
- [ ] RBAC audit logged (who accessed what)

**Priority**: MEDIUM

---

## 10. Testing and Validation

### 10.1 Functional Testing

**Test Scenarios**:
1. **Playbook Execution**: Trigger playbook, verify all steps execute in order
2. **Conditional Logic**: Test all operators (eq, ne, gt, lt, in, contains, matches)
3. **Error Handling**: Test continue_on_error true/false, verify behavior
4. **Timeout**: Test step timeout, verify execution aborted
5. **Retry Logic**: Test retry on transient failure, verify exponential backoff
6. **Approval Workflow**: Test approval required, verify execution pauses

**Acceptance Criteria**:
- [ ] All functional tests pass
- [ ] Test coverage >80% for SOAR code
- [ ] Integration tests with actual external services (test accounts)

---

### 10.2 Security Testing

**Test Scenarios**:
1. **Command Injection**: Attempt injection in script args, webhook params
2. **SSRF**: Attempt internal IP, metadata IP in webhook URL
3. **Path Traversal**: Attempt ../../../etc/passwd in script path
4. **Sandbox Escape**: Attempt to break out of script sandbox
5. **Audit Log Tampering**: Verify audit logs immutable

**Acceptance Criteria**:
- [ ] All security tests pass
- [ ] Penetration testing performed by external security firm
- [ ] Security findings remediated before production

---

### 10.3 Performance Testing

**Test Scenarios**:
1. **Playbook Latency**: Execute 1,000 playbooks, verify P99 latency
2. **Concurrent Execution**: Execute 50 concurrent playbooks, verify latency degradation <20%
3. **Queue Depth**: Submit 1,500 playbooks, verify queue handles overflow
4. **Memory Usage**: Verify memory usage per playbook <10 MB

**Acceptance Criteria**:
- [ ] All performance SLAs met
- [ ] Benchmark results documented

---

## 11. Compliance Verification Checklist

### 11.1 Playbook Execution
- [ ] FR-SOAR-001: Playbook JSON schema validated
- [ ] FR-SOAR-002: Sequential step execution verified
- [ ] FR-SOAR-003: Conditional logic tested (all operators)
- [ ] FR-SOAR-004: Retry logic verified (exponential backoff)
- [ ] FR-SOAR-005: Timeout enforcement verified
- [ ] FR-SOAR-006: Parallel execution implemented (future)

### 11.2 Action Integration
- [ ] FR-SOAR-007: Webhook action tested (SSRF protection verified)
- [ ] FR-SOAR-008: Email notification tested
- [ ] FR-SOAR-009: Ticket creation tested (Jira, ServiceNow)
- [ ] FR-SOAR-010: Block IP / Isolate host tested
- [ ] FR-SOAR-011: Script execution tested (sandbox verified)

### 11.3 Enrichment
- [ ] FR-SOAR-012: Threat intel lookups tested (VirusTotal, AbuseIPDB)
- [ ] FR-SOAR-013: GeoIP enrichment tested
- [ ] FR-SOAR-014: DNS/WHOIS tested (future)
- [ ] FR-SOAR-015: User/asset enrichment tested
- [ ] FR-SOAR-016: Caching verified (hit rate >80%)

### 11.4 Security
- [ ] FR-SOAR-017: Command injection protection verified
- [ ] FR-SOAR-018: SSRF protection verified
- [ ] FR-SOAR-019: Sandbox isolation verified
- [ ] FR-SOAR-020: Approval workflow implemented (future)
- [ ] FR-SOAR-021: Audit logging verified
- [ ] FR-SOAR-022: Rate limiting verified

### 11.5 Performance
- [ ] FR-SOAR-023: Playbook latency SLAs met
- [ ] FR-SOAR-024: Concurrent execution (50 playbooks) verified
- [ ] FR-SOAR-025: Action timeouts enforced
- [ ] FR-SOAR-026: Queue depth (1,000 pending) verified
- [ ] FR-SOAR-027: Memory usage per playbook <10 MB verified

### 11.6 Reliability
- [ ] FR-SOAR-028: Failure rate <1% verified
- [ ] FR-SOAR-029: Automatic retry verified
- [ ] FR-SOAR-030: Dead letter queue implemented
- [ ] FR-SOAR-031: State recovery tested (future)
- [ ] FR-SOAR-032: Idempotency implemented (future)

### 11.7 Observability
- [ ] FR-SOAR-033: SOAR metrics exposed
- [ ] FR-SOAR-034: Dashboards and alerts provided

### 11.8 Governance
- [ ] FR-SOAR-035: Playbook versioning implemented (future)
- [ ] FR-SOAR-036: RBAC enforced

---

## 12. Open Questions and Decisions Needed

| ID | Question | Owner | Deadline | Priority | Status |
|----|----------|-------|----------|----------|--------|
| OQ-SOAR-001 | Finalize webhook URL allowlist for production | Security Team | Week 1 | CRITICAL | OPEN |
| OQ-SOAR-002 | Select sandbox technology (Docker, gVisor, Firecracker) | Infrastructure Team | Week 2 | CRITICAL | OPEN |
| OQ-SOAR-003 | Define approval workflow UI/UX | UX Team | Week 3 | HIGH | OPEN |
| OQ-SOAR-004 | Integrate with production firewall API (Palo Alto, Fortinet) | Network Team | Week 4 | HIGH | OPEN |
| OQ-SOAR-005 | Integrate with EDR/XDR (CrowdStrike, SentinelOne) | Endpoint Team | Week 4 | HIGH | OPEN |
| OQ-SOAR-006 | Define playbook versioning strategy | Architecture Team | Week 3 | MEDIUM | OPEN |
| OQ-SOAR-007 | Benchmark playbook execution performance | Performance Team | Week 2 | HIGH | OPEN |

---

## 13. Assumptions

1. **External Services**: Production integrations (Jira, ServiceNow, VirusTotal) require valid API credentials
2. **Network Access**: SOAR server has outbound HTTPS access to external services (allowlisted domains)
3. **Sandbox Infrastructure**: Docker or equivalent container runtime available for script execution
4. **Approval Workflow**: Manual approval initially via API, UI in future release
5. **Playbook Storage**: Playbooks stored in JSON file (initial), migrate to database for versioning
6. **Secret Management**: API keys stored in environment variables (initial), migrate to HashiCorp Vault or AWS Secrets Manager

---

## 14. Stakeholder Sign-Off

**SOAR Requirements Approved By**:
- [ ] Security Automation Lead: _____________________ Date: _____
- [ ] SOC Operations Manager: _____________________ Date: _____
- [ ] Security Architect: _____________________ Date: _____
- [ ] Compliance Officer: _____________________ Date: _____
- [ ] CTO: _____________________ Date: _____

---

**Document Status**: DRAFT - Pending Security Review & Implementation
**Next Review**: After Week 2 (security hardening review)
**Version**: 1.0
**Last Updated**: 2025-11-16
