# Task ID: 149

**Title:** Add Comprehensive SQL Injection Protection

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Implement gosec static analysis in CI pipeline and add database query audit logging to prevent SQL injection vulnerabilities and enable forensic analysis.

**Details:**

No SQL injection found currently (all queries use placeholders correctly), but NO STATIC ANALYSIS preventing future vulnerabilities.

Good example:
```go
db.Exec("INSERT INTO rules (id, name) VALUES (?, ?)", id, name)
```

Need protection against:
```go
// DANGEROUS - No protection
db.Exec(fmt.Sprintf("SELECT * FROM rules WHERE id = '%s'", id))
```

Implementation:
1. Add gosec to CI pipeline:
   ```yaml
   # .github/workflows/security.yml
   - name: Run gosec security scanner
     run: |
       go install github.com/securego/gosec/v2/cmd/gosec@latest
       gosec -fmt=json -out=gosec-report.json -exclude-dir=tests ./...
   ```
2. Configure gosec to flag SQL issues (gosec.json):
   ```json
   {
     "global": {
       "exclude": {},
       "include": ["G201", "G202"],  // SQL string concatenation
       "severity": "medium"
     }
   }
   ```
3. Add database query audit logging:
   ```go
   type AuditLogger struct {
     logger *zap.SugaredLogger
   }
   
   func (al *AuditLogger) LogQuery(ctx context.Context, query string, args ...interface{}) {
     al.logger.Infow("database_query",
       "query", query,
       "args_count", len(args),
       "request_id", ctx.Value("request_id"),
       "user", ctx.Value("user_id"))
   }
   ```
4. Wrap all database operations with audit logging:
   ```go
   func (s *SQLite) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
     s.auditLogger.LogQuery(ctx, query, args...)
     return s.DB.QueryContext(ctx, query, args...)
   }
   ```
5. Document safe query patterns in CONTRIBUTING.md:
   - Always use parameterized queries (?, $1, etc.)
   - Never concatenate user input into SQL strings
   - Use query builders or ORMs for complex queries
   - Examples of safe and unsafe patterns
6. Add pre-commit hook running gosec

Files to audit:
- storage/sqlite_*.go (50+ query methods)
- storage/clickhouse_*.go (30+ query methods)

**Test Strategy:**

1. Static analysis - gosec CI check, zero G201/G202 violations
2. SQL injection test - attempt injection via API endpoints
3. Audit log test - verify all queries logged with context
4. Pre-commit hook test - verify gosec runs before commit
5. Code review checklist - manual SQL query audit
6. Penetration test - OWASP SQL injection test suite
7. Query pattern validation - grep for string concatenation in SQL

## Subtasks

### 149.1. Configure gosec in CI pipeline with G201/G202 rules enabled

**Status:** done  
**Dependencies:** None  

Add gosec static analysis security scanner to GitHub Actions CI pipeline with SQL injection detection rules (G201, G202) and JSON output reporting.

**Details:**

Create .github/workflows/security.yml with gosec installation and execution. Configure gosec.json to include G201 (SQL string formatting) and G202 (SQL string concatenation) rules with medium severity threshold. Set up JSON output format for integration with GitHub Security tab. Ensure pipeline fails on any SQL injection vulnerabilities detected. Add workflow badge to README.md.

### 149.2. Audit all database query methods in storage layer for parameterized queries

**Status:** done  
**Dependencies:** 149.1  

Comprehensive audit of 50+ methods in storage/sqlite_*.go and 30+ methods in storage/clickhouse_*.go to verify all queries use parameterized placeholders (?, $1) instead of string concatenation.

**Details:**

Systematically review every database query method across storage/sqlite_actions.go, sqlite_alerts.go, sqlite_rules.go, sqlite_correlation_rules.go, sqlite_investigations.go, sqlite_users.go, sqlite_evidence.go, sqlite_exceptions.go, clickhouse_alerts.go, clickhouse_events.go, clickhouse_soar_audit.go, and all other storage files. Document each query method's safety status. Create audit report listing all methods with their query patterns. Verify no string interpolation (fmt.Sprintf, string concatenation with +) is used with user input. Flag any potential issues for remediation.

### 149.3. Implement database query audit logger with context propagation

**Status:** deferred  
**Dependencies:** 149.2  

Create audit logging wrapper for all database operations capturing query text, parameters count, request_id, user_id, and timestamps for forensic analysis and security monitoring.

**Details:**

Implement storage/audit_logger.go with AuditLogger struct using zap.SugaredLogger. Create LogQuery method extracting request_id and user_id from context. Wrap all SQLite and ClickHouse QueryContext, ExecContext, QueryRowContext methods to invoke audit logger before execution. Ensure context propagation works correctly (depends on Task 144 context propagation work). Add structured logging fields: query_hash, args_count, timestamp, duration, affected_rows. Configure log rotation and retention policy. Set up alerts for suspicious query patterns (multiple failed queries, unusual table access).

### 149.4. Add pre-commit hook and document safe query patterns

**Status:** deferred  
**Dependencies:** 149.1  

Create pre-commit hook running gosec on changed Go files and document comprehensive SQL injection prevention guidelines in CONTRIBUTING.md with safe/unsafe examples.

**Details:**

Create .git/hooks/pre-commit script running gosec only on staged .go files for fast feedback. Add pre-commit hook installation instructions to CONTRIBUTING.md. Document safe query patterns: (1) Always use parameterized queries with ? or $1 placeholders, (2) Never use fmt.Sprintf or + concatenation with user input in SQL, (3) Use query builders (squirrel) for complex dynamic queries, (4) Escape identifiers separately from values. Provide 10+ code examples showing safe patterns (prepared statements, named parameters) vs unsafe patterns (string interpolation, concatenation). Add SQL injection prevention section to security documentation. Include gosec integration with IDE (VSCode, GoLand) for real-time feedback.

### 149.5. Run OWASP SQL injection penetration testing suite against API

**Status:** done  
**Dependencies:** 149.2, 149.3  

Execute comprehensive SQL injection attack vectors against all API endpoints using OWASP testing methodology to validate protection mechanisms and identify any bypasses.

**Details:**

Set up OWASP ZAP or sqlmap for automated SQL injection testing. Test all API endpoints accepting user input: /api/rules, /api/events, /api/alerts, /api/users, /api/search, /api/correlation-rules, /api/investigations. Attack vectors: (1) Classic SQLi (OR 1=1, UNION SELECT), (2) Blind SQLi (time-based, boolean-based), (3) Second-order SQLi, (4) NoSQL injection (for any NoSQL queries), (5) ORM injection. Test GET/POST parameters, headers, JSON body fields, path parameters. Verify all attempts are logged by audit logger. Document all test cases and results. Create security test report. Add automated SQL injection regression tests to CI pipeline using sqlmap in safe mode.
