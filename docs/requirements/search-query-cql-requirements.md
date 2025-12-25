# Search and Query (CQL) Requirements

**Document Owner**: Search Team
**Created**: 2025-01-16
**Status**: DRAFT
**Last Updated**: 2025-01-16
**Version**: 1.0
**Authoritative Sources**:
- Elasticsearch Query DSL
- Kibana Query Language (KQL)
- Splunk Search Processing Language (SPL)
- SQL-92 Standard

---

## 1. Executive Summary

The Cerberus Query Language (CQL) is the primary interface for analysts to search, filter, and analyze security events. This document defines comprehensive requirements for CQL syntax, semantics, query parsing, optimization, and performance to enable efficient threat hunting and investigation workflows.

**Critical Requirements**:
- SQL-like query syntax for familiarity
- Field-based filtering with rich operators
- Logical operators (AND, OR, NOT)
- Time range filtering
- Full-text search capabilities
- Query validation and sanitization
- Query performance optimization
- Sub-second query response times

**Known Gaps**:
- Aggregation and grouping syntax TBD
- Join operations not specified
- Query result ranking algorithm TBD
- Query optimization heuristics TBD

---

## 2. Functional Requirements

### 2.1 CQL Syntax

#### FR-CQL-001: Basic Field Queries
**Requirement**: CQL MUST support field-based equality queries.

**Specification**:
```
source_ip = "192.168.1.100"
event_type equals "auth_failure"
severity = "High"
```

**Operators**:
- `=`, `equals`: Exact match
- `!=`, `not_equals`: Not equal
- Case-sensitive by default

**Acceptance Criteria**:
- [x] Equality operator implemented
- [x] Not equals operator implemented
- [x] String value matching
- [x] Numeric value matching
- [x] Boolean value matching

**Current Implementation**: ✅ COMPLIANT (search/parser.go:350-388)

---

#### FR-CQL-002: Comparison Operators
**Requirement**: CQL MUST support numeric and date comparison operators.

**Specification**:
```
port > 1024
port >= 443
timestamp < "2025-01-16T12:00:00Z"
bytes_sent <= 1000000
```

**Operators**:
- `>`, `gt`: Greater than
- `>=`, `gte`: Greater than or equal
- `<`, `lt`: Less than
- `<=`, `lte`: Less than or equal

**Acceptance Criteria**:
- [x] Comparison operators implemented
- [x] Numeric comparison
- [x] Date/timestamp comparison
- [x] Type coercion (string "100" → int 100)

**Current Implementation**: ✅ COMPLIANT (search/parser.go:142-148)

---

#### FR-CQL-003: String Matching Operators
**Requirement**: CQL MUST support string pattern matching operators.

**Specification**:
```
message contains "failed"
username startswith "admin"
filename endswith ".exe"
command_line matches "^powershell.*-enc"
```

**Operators**:
- `contains`: Substring match (case-insensitive)
- `startswith`: Prefix match
- `endswith`: Suffix match
- `matches`, `~=`: Regex match

**Acceptance Criteria**:
- [x] Contains operator implemented
- [x] Starts with operator implemented
- [x] Ends with operator implemented
- [x] Regex operator implemented
- [ ] Case-insensitive option for all operators

**Current Implementation**: ✅ PARTIAL (search/parser.go:142-148, case-insensitive TBD)

---

#### FR-CQL-004: Array and List Operators
**Requirement**: CQL MUST support array membership and existence operators.

**Specification**:
```
source_ip in ["192.168.1.100", "10.0.0.50"]
event_type not in ["info", "debug"]
tags exists
optional_field not exists
```

**Operators**:
- `in`: Value in array
- `not in`: Value not in array
- `exists`: Field present (any value including null)
- `not exists`: Field absent

**Acceptance Criteria**:
- [x] In operator implemented
- [x] Not in operator implemented
- [x] Exists operator implemented
- [x] Not exists operator implemented
- [x] Array values parsed correctly

**Current Implementation**: ✅ COMPLIANT (search/parser.go:142-148, 186-204)

---

#### FR-CQL-005: Logical Operators
**Requirement**: CQL MUST support logical operators for combining conditions.

**Specification**:
```
source_ip = "192.168.1.100" AND event_type = "auth_failure"
severity = "High" OR severity = "Critical"
NOT user = "admin"
(source_ip = "192.168.1.100" OR source_ip = "10.0.0.50") AND event_type = "login"
```

**Operators**:
- `AND`, `&&`: Logical AND
- `OR`, `||`: Logical OR
- `NOT`, `!`: Logical NOT

**Precedence**: NOT > AND > OR (parentheses override)

**Acceptance Criteria**:
- [x] AND operator implemented
- [x] OR operator implemented
- [x] NOT operator implemented
- [x] Operator precedence enforced
- [x] Parentheses grouping supported

**Current Implementation**: ✅ COMPLIANT (search/parser.go:263-313)

---

#### FR-CQL-006: Nested Field Access
**Requirement**: CQL MUST support nested field access using dot notation.

**Specification**:
```
user.name = "admin"
process.parent.command_line contains "cmd.exe"
network.destination.ip = "8.8.8.8"
```

**Acceptance Criteria**:
- [x] Dot notation field access
- [x] Multi-level nesting (a.b.c)
- [x] Missing nested field handling (null)

**Current Implementation**: ✅ COMPLIANT (search/parser.go:209)

---

### 2.2 Query Parsing

#### FR-CQL-007: Lexical Analysis (Tokenization)
**Requirement**: CQL parser MUST tokenize queries into structured tokens.

**Specification**:

**Token Types**:
- Field names: `source_ip`, `event_type`
- Operators: `=`, `>=`, `contains`, `AND`
- Values: `"192.168.1.100"`, `443`, `true`, `["a", "b"]`
- Parentheses: `(`, `)`
- EOF: End of input

**Tokenization Rules**:
- Quoted strings: `"value with spaces"`
- Escaped quotes: `"value with \" quote"`
- Arrays: `["val1", "val2"]`
- Numbers: `123`, `45.67`
- Booleans: `true`, `false`

**Acceptance Criteria**:
- [x] Tokenizer implemented
- [x] Quoted string parsing
- [x] Escaped character handling
- [x] Array parsing
- [x] Number parsing
- [x] Boolean parsing
- [x] Unterminated string error handling

**Current Implementation**: ✅ COMPLIANT (search/parser.go:84-234)

---

#### FR-CQL-008: Syntax Analysis (Parsing)
**Requirement**: CQL parser MUST build Abstract Syntax Tree (AST) from tokens.

**Specification**:

**AST Node Types**:
- `Condition`: Field operator value (e.g., `source_ip = "1.2.3.4"`)
- `Logical`: AND, OR, NOT operations
- `Group`: Parenthesized expressions

**Parsing Algorithm**:
- Recursive descent parser
- Operator precedence: NOT > AND > OR
- Expression grammar:
  ```
  Expression  → OrExpr
  OrExpr      → AndExpr ( "OR" AndExpr )*
  AndExpr     → Primary ( "AND" Primary )*
  Primary     → "(" Expression ")" | "NOT" Primary | Condition
  Condition   → Field Operator Value
  ```

**Acceptance Criteria**:
- [x] AST construction implemented
- [x] Operator precedence enforced
- [x] Parentheses grouping
- [x] Syntax error detection
- [x] Error position reporting

**Current Implementation**: ✅ COMPLIANT (search/parser.go:263-347)

---

#### FR-CQL-009: Semantic Validation
**Requirement**: CQL parser MUST perform semantic validation on AST.

**Specification**:

**Validation Rules**:
- Field names not empty
- Operators valid for field types
- Values match operator expectations (e.g., `in` requires array)
- `exists`/`not exists` don't require values

**Error Examples**:
```
✗ "" = "value"           // Empty field name
✗ field invalid_op value // Invalid operator
✗ field in "value"       // 'in' requires array, not string
✗ field exists "value"   // 'exists' doesn't take value
```

**Acceptance Criteria**:
- [x] Empty field name validation
- [x] Invalid operator detection
- [x] Operator/value type checking
- [x] Exists operator validation
- [x] Validation error messages

**Current Implementation**: ✅ COMPLIANT (search/parser.go:533-584)

---

### 2.3 Query Execution

#### FR-CQL-010: Query Evaluation Engine
**Requirement**: System MUST evaluate CQL queries against event collections efficiently.

**Specification**:

**Evaluation Strategy**:
1. Parse CQL to AST
2. Traverse AST depth-first
3. Evaluate leaf nodes (conditions) against events
4. Combine results using logical operators
5. Return matching events

**Field Value Extraction**:
- Extract field value from event
- Handle nested fields (dot notation)
- Handle missing fields (return null)

**Operator Evaluation**:
- String operators: Case-insensitive comparison
- Numeric operators: Type coercion if needed
- Array operators: Membership check
- Regex operators: Compiled regex matching

**Acceptance Criteria**:
- [ ] Query evaluator implemented
- [ ] Field extraction for nested fields
- [ ] All operators evaluated correctly
- [ ] Missing field handling
- [ ] Type coercion for comparisons

**Current Implementation**: ⚠️ PARTIAL (AST built, executor implementation TBD)

**TBD**:
- [ ] Query executor implementation
- [ ] Integration with ClickHouse
- [ ] Query translation to SQL

---

#### FR-CQL-011: Query Translation to SQL
**Requirement**: System SHOULD translate CQL queries to ClickHouse SQL for efficient execution.

**Specification**:

**Translation Examples**:
```
CQL:  source_ip = "192.168.1.100" AND port > 1024
SQL:  SELECT * FROM events
      WHERE source_ip = '192.168.1.100' AND port > 1024

CQL:  message contains "error"
SQL:  SELECT * FROM events
      WHERE lower(message) LIKE '%error%'

CQL:  source_ip in ["1.2.3.4", "5.6.7.8"]
SQL:  SELECT * FROM events
      WHERE source_ip IN ('1.2.3.4', '5.6.7.8')
```

**SQL Injection Prevention**:
- Use parameterized queries
- Escape special characters
- Validate field names against whitelist
- Sanitize user input

**Acceptance Criteria**:
- [ ] CQL to SQL translator implemented
- [ ] Parameterized queries used
- [ ] SQL injection prevention validated
- [ ] All CQL operators translated

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] SQL translation layer design
- [ ] ClickHouse-specific optimizations

---

### 2.4 Advanced Search Features

#### FR-CQL-012: Time Range Filtering
**Requirement**: CQL MUST support time range filtering for temporal analysis.

**Specification**:

**Time Syntax**:
```
@timestamp > "2025-01-16T12:00:00Z"
@timestamp >= "last 24h"
@timestamp between "2025-01-15" and "2025-01-16"
```

**Relative Time**:
- `last 1h`: Last hour
- `last 24h`, `last 1d`: Last 24 hours
- `last 7d`: Last 7 days
- `last 30d`: Last 30 days

**Absolute Time**:
- ISO 8601 format: `2025-01-16T12:00:00Z`
- Date only: `2025-01-16` (implies 00:00:00)

**Acceptance Criteria**:
- [x] Timestamp comparison operators
- [x] Relative time parsing (last Xh/d)
- [ ] Between operator for ranges
- [ ] Date-only format (implied time)

**Current Implementation**: ✅ PARTIAL (search/parser.go:438-477, between operator TBD)

---

#### FR-CQL-013: Full-Text Search
**Requirement**: CQL SHOULD support full-text search across all indexed fields.

**Specification**:

**Syntax**:
```
"failed login attempt"           // Search all fields
message:"failed" AND severity:High // Field-specific + full-text
```

**Search Behavior**:
- Search all string fields by default
- Tokenize query into words
- Match any word (OR logic)
- Case-insensitive matching

**Ranking**:
- TF-IDF scoring (term frequency × inverse document frequency)
- Field boosting (title > body)
- Recency boosting (recent events ranked higher)

**Acceptance Criteria**:
- [ ] Full-text search implemented
- [ ] Multi-field search
- [ ] Tokenization and matching
- [ ] Result ranking by relevance

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] Full-text search index design
- [ ] Ranking algorithm selection

---

#### FR-CQL-014: Aggregation and Grouping
**Requirement**: CQL SHOULD support aggregation and grouping for statistical analysis.

**Specification**:

**Syntax** (SQL-like):
```
SELECT COUNT(*) FROM events WHERE severity = "High"
SELECT source_ip, COUNT(*) FROM events GROUP BY source_ip
SELECT AVG(bytes_sent) FROM events WHERE event_type = "network"
```

**Aggregation Functions**:
- `COUNT(*)`: Count events
- `COUNT(field)`: Count non-null values
- `SUM(field)`: Sum numeric values
- `AVG(field)`: Average
- `MIN(field)`, `MAX(field)`: Min/max
- `DISTINCT(field)`: Unique values

**Group By**:
- Group by single field
- Group by multiple fields
- Order by aggregation result

**Acceptance Criteria**:
- [ ] Aggregation syntax defined
- [ ] COUNT, SUM, AVG, MIN, MAX implemented
- [ ] GROUP BY implemented
- [ ] ORDER BY aggregation results

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] Aggregation syntax finalization
- [ ] Integration with ClickHouse aggregation

---

### 2.5 Query Performance

#### FR-CQL-015: Query Optimization
**Requirement**: System SHOULD optimize CQL queries for performance.

**Specification**:

**Optimization Techniques**:
1. **Index Usage**: Use indexed fields in WHERE clause
2. **Filter Pushdown**: Apply filters early in execution
3. **Short-Circuit Evaluation**: Stop evaluation when result determined
4. **Query Rewriting**: Transform queries to equivalent but faster forms

**Examples**:
```
// Inefficient
NOT (a OR b)

// Optimized (De Morgan's Law)
(NOT a) AND (NOT b)
```

**Acceptance Criteria**:
- [ ] Index-based filtering
- [ ] Filter pushdown to storage layer
- [ ] Short-circuit AND/OR evaluation
- [ ] Query plan optimization

**Current Implementation**: ❌ NOT IMPLEMENTED

---

#### FR-CQL-016: Query Performance SLAs
**Requirement**: CQL queries MUST meet defined performance targets.

**Specification**:

**Response Time Targets** (p95):
- Simple queries (1-3 conditions): < 100ms
- Complex queries (5+ conditions, joins): < 1000ms
- Aggregation queries: < 2000ms
- Full-text search: < 500ms

**Throughput Targets**:
- 100 concurrent queries
- 1000 queries/minute sustained

**Timeout**:
- Query timeout: 30 seconds (configurable)
- Queries exceeding timeout canceled
- Timeout error returned to client

**Acceptance Criteria**:
- [ ] Response time SLAs validated via load testing
- [ ] Query timeout enforced
- [ ] Slow query logging (>1s)
- [ ] Query performance metrics tracked

**Current Implementation**: ⚠️ PARTIAL (timeout TBD, SLAs TBD)

---

### 2.6 Query Security

#### FR-CQL-017: Query Sanitization
**Requirement**: System MUST sanitize CQL queries to prevent injection attacks.

**Rationale**: Unsanitized queries can enable SQL injection, NoSQL injection, or command injection.

**Specification**:

**Sanitization Steps**:
1. Parse query using formal grammar (prevents injection)
2. Validate field names against whitelist
3. Use parameterized queries for storage layer
4. Escape special characters in values
5. Limit query complexity (max conditions, depth)

**Rejected Queries**:
```
✗ '); DROP TABLE events; --
✗ field = "value" OR 1=1
✗ field = "'; system('rm -rf /'); '"
```

**Acceptance Criteria**:
- [x] Formal grammar-based parsing (prevents injection)
- [ ] Field name whitelist validation
- [ ] Parameterized query generation
- [ ] Query complexity limits (max 100 conditions)

**Current Implementation**: ✅ PARTIAL (parser prevents injection, whitelist TBD)

---

#### FR-CQL-018: Query Validation
**Requirement**: System MUST validate CQL queries before execution.

**Specification**:

**Validation Checks**:
- Syntax validation (valid CQL)
- Semantic validation (valid operators, types)
- Field name validation (fields exist in schema)
- Value validation (valid data types)
- Complexity validation (query not too complex)

**Validation API**:
```
POST /api/v1/events/search/validate
{
  "query": "source_ip = '192.168.1.100' AND port > 1024"
}

Response:
{
  "valid": true,
  "errors": [],
  "warnings": ["Field 'port' not indexed, query may be slow"]
}
```

**Acceptance Criteria**:
- [x] Syntax validation implemented
- [x] Semantic validation implemented
- [ ] Field schema validation
- [ ] Validation API endpoint implemented

**Current Implementation**: ✅ PARTIAL (parser validation exists, API TBD)

---

## 3. Non-Functional Requirements

### 3.1 Performance
- Query response time: p95 < 1000ms
- Query throughput: 100 concurrent queries
- Query timeout: 30 seconds
- Index utilization: >90% of queries use indexes

### 3.2 Usability
- CQL syntax familiar to SQL users
- Syntax error messages clear and actionable
- Query suggestions/autocomplete (future)
- Query history and saved searches

### 3.3 Security
- Query injection prevention (formal parser)
- Field access control (RBAC, future)
- Query audit logging
- Query complexity limits

### 3.4 Scalability
- Query execution scales with storage layer
- Distributed query execution (future)
- Query result pagination required for large result sets

---

## 4. Test Requirements

**TEST-CQL-001: Parse valid query**
- GIVEN: `source_ip = "192.168.1.100" AND port > 1024`
- WHEN: Parser invoked
- THEN: AST created with 2 conditions joined by AND

**TEST-CQL-002: Reject invalid syntax**
- GIVEN: `source_ip = ` (incomplete query)
- WHEN: Parser invoked
- THEN: Syntax error returned with position

**TEST-CQL-003: Evaluate query against events**
- GIVEN: Query `severity = "High"` and 100 events (10 High severity)
- WHEN: Query executed
- THEN: 10 matching events returned

**TEST-CQL-004: Query performance SLA**
- GIVEN: 1 million events in storage
- WHEN: Simple query executed
- THEN: Response time < 100ms (p95)

---

## 5. TBD Tracker

| ID | Description | Owner | Target Date | Status |
|----|-------------|-------|-------------|--------|
| TBD-CQL-001 | Query executor implementation | Search Team | 2025-02-15 | Open |
| TBD-CQL-002 | CQL to SQL translation layer | Search Team | 2025-02-28 | Open |
| TBD-CQL-003 | Full-text search implementation | Search Team | 2025-03-15 | Open |
| TBD-CQL-004 | Aggregation syntax finalization | Search Team | 2025-03-01 | Open |
| TBD-CQL-005 | Query optimization heuristics | Search Team | 2025-03-15 | Open |
| TBD-CQL-006 | Performance SLA validation | QA Team | 2025-02-28 | Open |
| TBD-CQL-007 | Field schema validation | Search Team | 2025-02-15 | Open |
| TBD-CQL-008 | Query autocomplete/suggestions | Frontend Team | 2025-04-01 | Open |

---

## 6. References

- `search/parser.go`: CQL parser implementation
- `search/evaluator.go`: Query evaluation engine (TBD)
- Elasticsearch Query DSL
- Splunk SPL Documentation
- SQL-92 Standard

---

**Document Status**: DRAFT

**Next Steps**:
1. Technical review by search team (2025-01-23)
2. Query executor implementation (2025-02-15)
3. Performance validation (2025-02-28)
