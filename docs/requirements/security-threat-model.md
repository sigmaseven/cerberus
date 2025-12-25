# Security Threat Model & Test Requirements

**Document Owner**: Security Engineering Team
**Created**: 2025-11-16
**Status**: DRAFT - Pending Security Review
**Classification**: INTERNAL - Security Requirements
**Authoritative Sources**:
- OWASP Application Security Verification Standard (ASVS) v4.0
- OWASP Top 10 2021
- CWE/SANS Top 25 Most Dangerous Software Errors
- NIST SP 800-53 Rev. 5

**Purpose**: Define security threat model and test requirements for Cerberus SIEM

---

## 1. EXECUTIVE SUMMARY

This document defines security threats, attack vectors, and REQUIRED defensive controls for Cerberus. All security controls MUST be tested with both positive and negative test cases.

**Security Posture**: Cerberus is a security product (SIEM) and MUST meet higher security standards than typical applications.

**Critical Principle**: Security tests MUST verify controls work correctly, not just that current code doesn't crash.

---

## 2. INJECTION ATTACKS

### 2.1 SQL Injection (CWE-89)

**OWASP ASVS Reference**: V5.3.4 "Verify that all SQL queries, HQL, OSQL, NOSQL and stored procedures, calling of stored procedures are protected by the use of prepared statements or query parameterization"

**Threat**: Attacker manipulates SQL queries to access/modify unauthorized data or execute arbitrary database commands.

**Attack Surface in Cerberus**:
1. **ClickHouse Queries**: Event/alert searches, aggregations
2. **SQLite Queries**: Rule/action/user CRUD operations
3. **Database Name Creation**: `storage/clickhouse.go:ensureDatabase()`

---

#### 2.1.1 ClickHouse SQL Injection

**Vulnerable Code Pattern**:
```go
// WRONG: String concatenation
query := "SELECT * FROM events WHERE user = '" + userInput + "'"
conn.Query(ctx, query)
```

**Required Defense**: Parameterized queries
```go
// CORRECT: Parameterized query
query := "SELECT * FROM events WHERE user = ?"
conn.Query(ctx, query, userInput)
```

**Test Requirements**:

```go
func TestClickHouse_SQLInjection_ParamterizedQueries(t *testing.T) {
    // Test Case 1: UNION-based injection
    maliciousUser := "admin' UNION SELECT password FROM users --"
    events, err := storage.SearchEvents(maliciousUser)

    // MUST: Query returns 0 results (not password data)
    // MUST: No syntax error (proves parameterization)
    assert.NoError(t, err)
    assert.Empty(t, events)

    // Verify query was parameterized (inspect logs or use mock)
    // MUST: Parameter passed as-is, not interpreted as SQL

    // Test Case 2: Boolean-based blind injection
    maliciousUser = "admin' OR '1'='1"
    events, err = storage.SearchEvents(maliciousUser)
    assert.NoError(t, err)
    // MUST NOT return all events (proves OR not executed)

    // Test Case 3: Time-based blind injection
    maliciousUser = "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 1 END --"
    start := time.Now()
    events, err = storage.SearchEvents(maliciousUser)
    elapsed := time.Since(start)
    // MUST: Complete in <1s (not 5s), proves injection failed
    assert.Less(t, elapsed, 1*time.Second)
}
```

**Current Implementation Analysis**:
- File: `storage/clickhouse_events.go`, `clickhouse_alerts.go`
- Status: ⚠️ NEEDS AUDIT - Verify all queries use parameterization
- Known Safe: Uses ClickHouse Go driver's parameterized query interface

**Validation Method**:
1. **Code Review**: Grep for string concatenation in SQL queries
2. **Black-Box Testing**: Inject SQL payloads, verify no SQL errors returned
3. **Instrumentation**: Log actual queries sent to database, verify parameters escaped

---

#### 2.1.2 Database Identifier Injection

**Threat**: Attacker injects malicious database/table/column names

**Vulnerable Code**:
```go
// storage/clickhouse.go:ensureDatabase() line 125
query := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", database)
```

**Attack Vector**:
```go
database := "valid_name`; DROP DATABASE production; --"
// Results in: CREATE DATABASE IF NOT EXISTS `valid_name`; DROP DATABASE production; --`
```

**Current Defense** (line 102-114):
```go
func validateDatabaseName(database string) error {
    if !validDatabaseNameRegex.MatchString(database) {
        return fmt.Errorf("database name contains invalid characters")
    }
}
```

**Required Defense**: Input validation + identifier quoting

**Test Requirements**:
```go
func TestClickHouse_DatabaseNameInjection_ValidationAndQuoting(t *testing.T) {
    // Test Case 1: SQL injection attempt via backtick escape
    maliciousDB := "valid`; DROP DATABASE production; --"
    err := storage.EnsureDatabase(maliciousDB)
    // MUST: Reject invalid database name
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "invalid characters")

    // Test Case 2: Path traversal attempt
    maliciousDB = "../../../etc/passwd"
    err = storage.EnsureDatabase(maliciousDB)
    assert.Error(t, err)

    // Test Case 3: Null byte injection
    maliciousDB = "valid\x00DROP"
    err = storage.EnsureDatabase(maliciousDB)
    assert.Error(t, err)

    // Test Case 4: Valid database name (positive test)
    validDB := "cerberus_events_2024"
    err = storage.EnsureDatabase(validDB)
    assert.NoError(t, err)
}
```

**Current Implementation**: ✅ APPEARS SECURE
- Validation regex: `^[a-zA-Z0-9_]+$` (line 20)
- Backtick quoting as defense-in-depth (line 125)

**OWASP ASVS Compliance**: V5.3.4 ✅ (input validation + safe API)

---

### 2.2 NoSQL Injection

**Threat**: Manipulation of NoSQL query logic (if Cerberus uses NoSQL in future)

**Current Status**: NOT APPLICABLE (MongoDB removed from codebase)

**Test Requirements**: N/A (but document for future MongoDB reintegration)

---

### 2.3 Command Injection (CWE-78)

**OWASP ASVS Reference**: V5.3.8 "Verify that the application protects against OS command injection"

**Attack Surface in Cerberus**:
1. **Alert Actions**: Executing external scripts/commands for notifications
2. **Rule Testing**: Potential exec of external tools
3. **Listener Management**: Starting/stopping listener processes

---

#### 2.3.1 Alert Action Command Injection

**Threat**: Attacker crafts alert that causes malicious command execution

**Vulnerable Code Pattern**:
```go
// WRONG: Shell command with unsanitized input
cmd := exec.Command("sh", "-c", "curl -X POST " + webhookURL + " -d '" + alertData + "'")
```

**Attack Vector**:
```go
alertData := "normal data'; rm -rf / #"
// Results in: curl -X POST http://example.com -d 'normal data'; rm -rf / #'
```

**Required Defense**:
1. **No Shell Invocation**: Use exec.Command() with separate args (no "sh -c")
2. **Input Validation**: Validate/sanitize all inputs
3. **Principle of Least Privilege**: Run with minimal permissions

**Correct Code Pattern**:
```go
// CORRECT: Direct command invocation with separate arguments
cmd := exec.Command("curl", "-X", "POST", webhookURL, "-d", alertData)
// Arguments are NOT interpreted by shell
```

**Test Requirements**:
```go
func TestAlertActions_CommandInjection_NoShellInterpretation(t *testing.T) {
    // Test Case 1: Shell metacharacters in webhook URL
    maliciousURL := "http://example.com; cat /etc/passwd"
    action := core.Action{
        Type: "webhook",
        Config: map[string]interface{}{
            "url": maliciousURL,
        },
    }

    // Execute action
    err := actions.ExecuteAction(action, testAlert)

    // MUST: Either reject URL (validation) or treat entire string as URL
    // MUST NOT: Execute 'cat /etc/passwd'
    // Verification: Check process list, file access logs

    // Test Case 2: Command injection in alert data
    testAlert.Data = "data'; touch /tmp/pwned; #"
    err = actions.ExecuteAction(validAction, testAlert)

    // MUST NOT: Create /tmp/pwned file
    _, err = os.Stat("/tmp/pwned")
    assert.True(t, os.IsNotExist(err), "Command injection succeeded - file created!")
}
```

**Current Implementation**:
- File: `detect/actions.go`
- Status: ⚠️ NEEDS SECURITY AUDIT
- Known Issue: Code review required to verify no "sh -c" usage

---

### 2.4 LDAP Injection (CWE-90)

**OWASP ASVS Reference**: V5.3.6
**Current Status**: NOT APPLICABLE (no LDAP integration)
**Future Consideration**: If adding LDAP authentication, implement LDAP escaping

---

### 2.5 Template Injection (CWE-94)

**Threat**: Attacker injects code into template engines

**Attack Surface**: Alert email templates, notification message templates

**TBD - DECISION NEEDED**:
```
Question: Does Cerberus use any template engines (html/template, text/template)?

Owner: Development Team
Deadline: Week 1

If YES: Implement template injection defenses
If NO: Document as not applicable
```

---

## 3. PATH TRAVERSAL & FILE ATTACKS

### 3.1 Path Traversal (CWE-22)

**OWASP ASVS Reference**: V12.2.1 "Verify that files obtained from untrusted sources are validated and scanned"

**Attack Surface**:
1. **Rule File Loading**: `detect/loader.go`
2. **Configuration File Loading**: `config/config.go`
3. **SQLite Database Paths**: `storage/sqlite.go`

---

#### 3.1.1 Rule File Path Traversal

**Threat**: Attacker loads rules from unauthorized file paths to read sensitive files

**Vulnerable Code Pattern**:
```go
// WRONG: User-controlled file path
filePath := userInput + ".yaml"
content, _ := os.ReadFile(filePath)
```

**Attack Vector**:
```go
ruleFile := "../../../../etc/passwd"
// Reads /etc/passwd instead of rule file
```

**Current Implementation Analysis**:
- File: `detect/loader.go`
- Method: `LoadRulesFromDirectory()`
- Status: ⚠️ NEEDS SECURITY AUDIT

**Test Requirements**:
```go
func TestRuleLoader_PathTraversal_DirectoryEscape(t *testing.T) {
    loader := detect.NewRuleLoader()

    // Test Case 1: Parent directory traversal
    maliciousPath := "/etc/passwd"
    _, err := loader.LoadRuleFromFile(maliciousPath)
    // MUST: Reject file outside allowed directory
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "path traversal")

    // Test Case 2: Relative path escape
    maliciousPath = "../../../../etc/passwd"
    _, err = loader.LoadRuleFromFile(maliciousPath)
    assert.Error(t, err)

    // Test Case 3: Symlink attack (CRITICAL)
    // Create symlink: ln -s /etc/passwd ./rules/malicious.yaml
    symlinkPath := filepath.Join(rulesDir, "malicious.yaml")
    os.Symlink("/etc/passwd", symlinkPath)
    defer os.Remove(symlinkPath)

    _, err = loader.LoadRuleFromFile(symlinkPath)
    // MUST: Detect and reject symlink to file outside rules directory
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "symlink")
}
```

**Required Defenses**:
1. **Path Normalization**: Use `filepath.Clean()` and `filepath.Abs()`
2. **Base Directory Check**: Verify resolved path starts with allowed base directory
3. **Symlink Detection**: Use `os.Lstat()` to detect symlinks before reading
4. **Reject Absolute Paths**: Only accept relative paths within base directory

**Defense-in-Depth Code**:
```go
func validateFilePath(basePath, requestedPath string) (string, error) {
    // Resolve to absolute path
    absBase, _ := filepath.Abs(basePath)
    absRequested, _ := filepath.Abs(filepath.Join(basePath, requestedPath))

    // Verify within base directory
    if !strings.HasPrefix(absRequested, absBase) {
        return "", errors.New("path traversal detected")
    }

    // Check for symlinks
    info, err := os.Lstat(absRequested)
    if err != nil {
        return "", err
    }
    if info.Mode()&os.ModeSymlink != 0 {
        // Resolve symlink and re-check base directory
        realPath, _ := filepath.EvalSymlinks(absRequested)
        if !strings.HasPrefix(realPath, absBase) {
            return "", errors.New("symlink escape detected")
        }
    }

    return absRequested, nil
}
```

---

#### 3.1.2 Null Byte Injection in Paths

**Threat**: Null byte truncates path, bypassing extension checks

**Attack Vector**:
```go
filename := "malicious.sh\x00.yaml"
// OS may truncate at null byte, reading "malicious.sh" instead of "malicious.sh\x00.yaml"
```

**Test Requirements**:
```go
func TestFileOperations_NullByteInjection_Rejection(t *testing.T) {
    // Test Case 1: Null byte in filename
    maliciousPath := "rule\x00.sh"
    err := loader.LoadRuleFromFile(maliciousPath)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "null byte")

    // Test Case 2: Null byte in directory path
    maliciousPath = "rules\x00/../../etc/passwd"
    err = loader.LoadRuleFromFile(maliciousPath)
    assert.Error(t, err)
}
```

**Required Defense**:
```go
if strings.Contains(path, "\x00") {
    return errors.New("null byte in path")
}
```

---

### 3.2 Arbitrary File Write (CWE-434)

**Threat**: Attacker writes files to unauthorized locations

**Attack Surface**: Export functionality, log files, temp files

**Test Requirements**:
```go
func TestExport_FileWrite_PathValidation(t *testing.T) {
    // Verify export functionality doesn't allow writing to arbitrary paths
    // Test with: ../../etc/cron.d/malicious
}
```

**Current Status**: TBD - Audit export/file-writing code paths

---

## 4. SERVER-SIDE REQUEST FORGERY (SSRF)

### 4.1 SSRF via Webhook URLs (CWE-918)

**OWASP ASVS Reference**: V12.6.1 "Verify that the web or application server is configured with an allow list of resources or systems to which the server can send requests"

**Threat**: Attacker uses Cerberus to make HTTP requests to internal services

**Attack Vector**:
```go
// Attacker creates alert action with webhook URL
webhookURL := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
// Cerberus makes request to AWS metadata service, leaking credentials
```

**Attack Surface**:
1. **Webhook Actions**: HTTP POST to user-specified URL
2. **Threat Intel Feeds**: Fetching external threat data
3. **SIEM Integrations**: Connecting to external SIEMs

**Required Defenses**:
1. **URL Allowlist**: Only allow known-safe domains
2. **Blocklist Private IPs**: Reject RFC 1918, link-local, loopback addresses
3. **DNS Rebinding Protection**: Re-resolve DNS after initial check
4. **Timeout & Size Limits**: Prevent slowloris and data exfiltration

**Test Requirements**:
```go
func TestWebhookAction_SSRF_PrivateIPBlocking(t *testing.T) {
    // Test Case 1: AWS metadata service
    maliciousURL := "http://169.254.169.254/latest/meta-data/"
    err := actions.ExecuteWebhook(maliciousURL, alertData)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "private IP")

    // Test Case 2: Internal network (RFC 1918)
    maliciousURL = "http://192.168.1.1/admin"
    err = actions.ExecuteWebhook(maliciousURL, alertData)
    assert.Error(t, err)

    // Test Case 3: Localhost
    maliciousURL = "http://localhost:5432/postgres"
    err = actions.ExecuteWebhook(maliciousURL, alertData)
    assert.Error(t, err)

    // Test Case 4: Loopback IP
    maliciousURL = "http://127.0.0.1:8081/admin"
    err = actions.ExecuteWebhook(maliciousURL, alertData)
    assert.Error(t, err)

    // Test Case 5: DNS rebinding (resolve to public IP, then private)
    // This is complex - use test server that changes DNS response

    // Test Case 6: IPv6 loopback
    maliciousURL = "http://[::1]:8081/admin"
    err = actions.ExecuteWebhook(maliciousURL, alertData)
    assert.Error(t, err)

    // Test Case 7: Redirect to private IP
    // Webhook returns 302 redirect to http://192.168.1.1
    // MUST: Reject redirect to private IP
}
```

**Blocked IP Ranges** (MUST be rejected):
```
10.0.0.0/8          (RFC 1918 - Private)
172.16.0.0/12       (RFC 1918 - Private)
192.168.0.0/16      (RFC 1918 - Private)
127.0.0.0/8         (Loopback)
169.254.0.0/16      (Link-local)
::1/128             (IPv6 loopback)
fc00::/7            (IPv6 private)
fe80::/10           (IPv6 link-local)
```

**Current Implementation**:
- File: `detect/actions.go`
- Status: ❌ CRITICAL SECURITY GAP - No SSRF protection detected

**Priority**: CRITICAL - Must be fixed before production deployment

---

## 5. AUTHENTICATION & AUTHORIZATION

### 5.1 JWT Token Security (CWE-287)

**OWASP ASVS Reference**: V2.1.1 "Verify that user passwords are stored with a cryptographic hash"

**Attack Surface**: JWT authentication system

**Test Requirements**:
```go
func TestJWT_TokenSecurity_SignatureValidation(t *testing.T) {
    // Test Case 1: Tampered token (modified claims)
    validToken := auth.GenerateToken("user@example.com")
    tamperedToken := modifyTokenClaims(validToken, map[string]interface{}{
        "role": "admin", // Escalate to admin
    })

    claims, err := auth.ValidateToken(tamperedToken)
    // MUST: Reject tampered token (signature invalid)
    assert.Error(t, err)
    assert.Nil(t, claims)

    // Test Case 2: None algorithm attack (CVE-2015-9235)
    noneToken := createNoneAlgorithmToken(map[string]interface{}{
        "email": "attacker@example.com",
        "role": "admin",
    })

    claims, err = auth.ValidateToken(noneToken)
    // MUST: Reject tokens with "alg": "none"
    assert.Error(t, err)

    // Test Case 3: Weak secret brute-force
    // Generate token with known weak secret
    weakSecretToken := generateTokenWithSecret("password123", userClaims)

    // Verify our token validation uses strong secret
    claims, err = auth.ValidateToken(weakSecretToken)
    assert.Error(t, err) // Must fail (different secret)
}
```

**Current Implementation**:
- File: `api/jwt.go`
- Status: ⚠️ NEEDS SECURITY AUDIT
- Required Checks:
  - [ ] Secret key strength (minimum 256 bits)
  - [ ] Algorithm allowlist (only HS256/RS256, no "none")
  - [ ] Token expiration enforced
  - [ ] Token revocation (blacklist) implemented

---

### 5.2 Password Storage (CWE-759)

**OWASP ASVS Reference**: V2.4.1 "Verify that passwords are stored with bcrypt, scrypt, or Argon2"

**Test Requirements**:
```go
func TestUserStorage_PasswordSecurity_BcryptHashing(t *testing.T) {
    // Test Case 1: Verify bcrypt is used (not MD5/SHA1)
    password := "SecurePassword123!"
    user := &core.User{Username: "test", Password: password}

    err := storage.CreateUser(user)
    assert.NoError(t, err)

    // Retrieve user from DB
    storedUser, _ := storage.GetUser("test")

    // MUST: Password is hashed, not plaintext
    assert.NotEqual(t, password, storedUser.PasswordHash)

    // MUST: Hash starts with bcrypt prefix ($2a$ or $2b$)
    assert.True(t, strings.HasPrefix(storedUser.PasswordHash, "$2a$") ||
                 strings.HasPrefix(storedUser.PasswordHash, "$2b$"))

    // Test Case 2: Verify bcrypt cost factor (minimum 10)
    // Extract cost from hash: $2a$COST$...
    cost, _ := strconv.Atoi(storedUser.PasswordHash[4:6])
    assert.GreaterOrEqual(t, cost, 10, "Bcrypt cost too low (vulnerable to brute-force)")
}
```

**Current Implementation**:
- File: `storage/user.go` or `storage/sqlite_users.go`
- Status: ⚠️ NEEDS VERIFICATION
- Required: Bcrypt with cost ≥ 10

---

## 6. DENIAL OF SERVICE (DoS)

### 6.1 Regex ReDoS (CWE-1333)

**Threat**: Malicious regex causes exponential backtracking, CPU exhaustion

**Attack Vector**:
```go
// Vulnerable regex: (a+)+$
maliciousInput := strings.Repeat("a", 50) + "X"
// Causes exponential backtracking: O(2^n) time complexity
```

**Attack Surface**:
1. **Sigma Rules**: User-provided regex in rule conditions
2. **Event Search**: Regex search queries
3. **Field Extraction**: Regex-based field parsing

**Test Requirements**:
```go
func TestRuleEngine_RegexReDoS_TimeoutProtection(t *testing.T) {
    // Test Case 1: Exponential backtracking pattern
    maliciousRegex := regexp.MustCompile("(a+)+$")
    maliciousInput := strings.Repeat("a", 30) + "X"

    start := time.Now()
    // Execute regex matching with timeout
    result := evaluateRegexWithTimeout(maliciousRegex, maliciousInput, 100*time.Millisecond)
    elapsed := time.Since(start)

    // MUST: Complete within timeout (100ms)
    assert.Less(t, elapsed, 200*time.Millisecond)
    // MUST: Return timeout error (not crash)
    assert.False(t, result)

    // Test Case 2: Nested quantifiers
    maliciousRegex = regexp.MustCompile("(a*)*b")
    maliciousInput = strings.Repeat("a", 25)
    // Similar test...
}
```

**Required Defense**:
```go
// Use context with timeout for regex matching
func evaluateRegexWithTimeout(re *regexp.Regexp, input string, timeout time.Duration) bool {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    resultChan := make(chan bool, 1)
    go func() {
        resultChan <- re.MatchString(input)
    }()

    select {
    case result := <-resultChan:
        return result
    case <-ctx.Done():
        return false // Timeout
    }
}
```

**Current Implementation**:
- File: `detect/engine.go:evaluateCondition()`
- Status: ❌ CRITICAL - No ReDoS protection detected
- Priority: HIGH (blocks regex operator testing)

**TBD - DECISION NEEDED**:
- Regex timeout value: 100ms? 1s? (OWNER: Security Team, DEADLINE: Week 2)

---

### 6.2 Billion Laughs / XML Bomb

**Current Status**: NOT APPLICABLE (no XML parsing detected)

---

### 6.3 Resource Exhaustion via Large Inputs

**Threat**: Attacker sends huge events/rules to exhaust memory

**Test Requirements**:
```go
func TestEventIngestion_ResourceExhaustion_SizeLimits(t *testing.T) {
    // Test Case 1: Huge event payload
    hugeEvent := &core.Event{
        Fields: map[string]interface{}{
            "data": strings.Repeat("A", 100*1024*1024), // 100 MB
        },
    }

    err := ingest.ProcessEvent(hugeEvent)
    // MUST: Reject event exceeding size limit
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "too large")
}
```

**Current Implementation**:
- File: `api/api.go` line 37
- Limit: `maxRequestBodySize = 10 * 1024 * 1024` (10 MB)
- Status: ✅ APPEARS ADEQUATE

---

## 7. INFORMATION DISCLOSURE

### 7.1 Error Message Information Leakage (CWE-209)

**OWASP ASVS Reference**: V7.4.1 "Verify that a generic message is shown when an unexpected error occurs"

**Threat**: Error messages reveal sensitive information (database structure, file paths, internal IPs)

**Test Requirements**:
```go
func TestAPI_ErrorHandling_NoInformationLeakage(t *testing.T) {
    // Test Case 1: Database error should not reveal schema
    resp := makeRequest("GET", "/api/v1/rules/nonexistent-id")
    assert.Equal(t, 404, resp.StatusCode)

    body := readBody(resp)
    // MUST NOT contain: SQL queries, table names, column names
    assert.NotContains(t, body, "SELECT")
    assert.NotContains(t, body, "FROM rules")

    // MUST contain: Generic error message
    assert.Contains(t, body, "not found")

    // Test Case 2: File system error should not reveal paths
    // Trigger file system error (e.g., permission denied)
    // MUST NOT contain: Full file paths (/home/user/cerberus/...)
}
```

**Current Implementation**:
- File: `api/middleware.go` line 174 `errorSanitizationMiddleware`
- Status: ✅ EXISTS - Verify effectiveness

---

### 7.2 Sensitive Data in Logs

**Threat**: Passwords, tokens, PII logged in plaintext

**Test Requirements**:
```go
func TestLogging_SensitiveData_Redaction(t *testing.T) {
    // Capture log output
    logBuffer := &bytes.Buffer{}
    logger := zap.New(zapcore.NewCore(
        zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
        zapcore.AddSync(logBuffer),
        zapcore.InfoLevel,
    ))

    // Trigger login with password
    auth.Login("user", "SecretPassword123!", logger)

    logs := logBuffer.String()
    // MUST NOT contain password
    assert.NotContains(t, logs, "SecretPassword123!")

    // Test JWT tokens, API keys, etc.
}
```

---

## 8. SECURITY TESTING STRATEGY

### 8.1 Test Classification

All security tests MUST be classified:

1. **Positive Security Tests**: Verify security control works
   - Example: Parameterized query prevents SQL injection

2. **Negative Security Tests**: Verify attack is blocked
   - Example: Path traversal attempt is rejected

3. **Boundary Tests**: Verify edge cases in security controls
   - Example: Null byte at position 0, middle, end of string

---

### 8.2 Test Evidence Requirements

Security tests MUST provide evidence the control works:

**BAD Test** (no evidence):
```go
func TestSQLInjection(t *testing.T) {
    // Just verify no error - doesn't prove injection failed
    err := storage.Query("malicious' OR '1'='1")
    assert.NoError(t, err)
}
```

**GOOD Test** (with evidence):
```go
func TestSQLInjection_WithEvidence(t *testing.T) {
    // Setup: Create user "admin"
    storage.CreateUser("admin")

    // Attack: Try to dump all users with SQL injection
    maliciousInput := "admin' OR '1'='1 --"
    users, err := storage.GetUser(maliciousInput)

    // Verify: Returns 0 or 1 user (not all users)
    assert.NoError(t, err)
    assert.LessOrEqual(t, len(users), 1)

    // Additional verification: Inspect database query log
    // (if available) to confirm parameterization
}
```

---

## 9. COMPLIANCE VERIFICATION CHECKLIST

### 9.1 Injection Attacks
- [ ] SQL injection tests (ClickHouse parameterized queries)
- [ ] SQL injection tests (SQLite parameterized queries)
- [ ] Database identifier injection tests
- [ ] Command injection tests (alert actions)
- [ ] Null byte injection tests (all file operations)
- [ ] SSRF tests (webhook URLs, threat intel feeds)

### 9.2 Path Traversal
- [ ] File path validation tests (rule loading)
- [ ] Symlink attack tests
- [ ] Null byte in path tests
- [ ] Absolute path rejection tests

### 9.3 Authentication
- [ ] JWT signature validation tests
- [ ] JWT algorithm allowlist tests (block "none")
- [ ] Password hashing tests (bcrypt verification)
- [ ] Password hashing cost factor tests (≥10)
- [ ] Token expiration tests
- [ ] Token revocation tests

### 9.4 Denial of Service
- [ ] Regex ReDoS protection tests
- [ ] Large input rejection tests (events, rules, requests)
- [ ] Rate limiting tests

### 9.5 Information Disclosure
- [ ] Error message sanitization tests
- [ ] Sensitive data in logs tests (passwords, tokens)
- [ ] Stack trace removal in production

---

## 10. TBD TRACKER - SECURITY DECISIONS NEEDED

| Item | Question | Owner | Deadline | Risk | Status |
|------|----------|-------|----------|------|--------|
| TBD-SEC-001 | Regex timeout value | Security Team | Week 2 | HIGH | OPEN |
| TBD-SEC-002 | SSRF allowlist domains | Security Team | Week 1 | CRITICAL | OPEN |
| TBD-SEC-003 | Max event size limit | Security Team | Week 1 | MEDIUM | OPEN |
| TBD-SEC-004 | JWT secret key rotation | Security Team | Week 3 | MEDIUM | OPEN |
| TBD-SEC-005 | Audit logging requirements | Compliance Team | Week 2 | MEDIUM | OPEN |
| TBD-SEC-006 | File upload allowed extensions | Security Team | Week 2 | HIGH | OPEN |

---

## 11. REFERENCES

### 11.1 OWASP Resources

1. **OWASP ASVS v4.0**: https://owasp.org/www-project-application-security-verification-standard/
2. **OWASP Top 10 2021**: https://owasp.org/Top10/
3. **OWASP Testing Guide v4**: https://owasp.org/www-project-web-security-testing-guide/

### 11.2 CWE References

1. **CWE-89** (SQL Injection): https://cwe.mitre.org/data/definitions/89.html
2. **CWE-78** (OS Command Injection): https://cwe.mitre.org/data/definitions/78.html
3. **CWE-22** (Path Traversal): https://cwe.mitre.org/data/definitions/22.html
4. **CWE-918** (SSRF): https://cwe.mitre.org/data/definitions/918.html

### 11.3 Internal Documents

1. **BACKEND_TEST_REMEDIATIONS.md**: Section on security vulnerabilities
2. **storage/clickhouse.go**: Database security implementation
3. **api/jwt.go**: Authentication implementation
4. **detect/actions.go**: Alert action execution

---

**Document Status**: DRAFT - SECURITY REVIEW REQUIRED
**Next Review Date**: Week 1 (CRITICAL security gaps identified)
**Approver**: CISO + Security Lead + Architect
**Classification**: INTERNAL
**Version**: 1.0-DRAFT

---

## APPENDIX A: CRITICAL SECURITY GAPS FOUND

During requirements documentation, these CRITICAL gaps were identified:

1. **SSRF Protection**: ❌ NOT IMPLEMENTED
   - File: `detect/actions.go`
   - Risk: CRITICAL
   - Impact: Internal network access, metadata service credential theft

2. **ReDoS Protection**: ❌ NOT IMPLEMENTED
   - File: `detect/engine.go`
   - Risk: HIGH
   - Impact: CPU exhaustion, denial of service

3. **Path Traversal Testing**: ⚠️ INCOMPLETE
   - File: `detect/loader_test.go`
   - Risk: HIGH
   - Impact: Arbitrary file read

**RECOMMENDATION**: Block production deployment until items 1 & 2 are fixed.
