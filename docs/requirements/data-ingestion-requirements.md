# Data Ingestion Requirements

**Document Owner**: Ingestion Team
**Created**: 2025-01-16
**Status**: DRAFT
**Last Updated**: 2025-01-16
**Version**: 1.0
**Authoritative Sources**:
- RFC 5424 (Syslog Protocol)
- RFC 3164 (BSD Syslog Protocol)
- Common Event Format (CEF) Specification v25
- SIGMA Taxonomy Standard
- Fluentd/Fluent Bit Forward Protocol
- MessagePack Specification

---

## 1. Executive Summary

Data ingestion is the foundational capability of the Cerberus SIEM system. The system must reliably collect, parse, normalize, and forward security events from diverse log sources using multiple protocols. This document defines comprehensive requirements for event ingestion to ensure data quality, system reliability, and SIGMA compliance.

**Critical Requirements**:
- Multi-protocol support (Syslog, CEF, JSON, Fluentd/Fluent Bit)
- Field normalization to SIGMA taxonomy
- Event validation and quality assurance
- High-throughput ingestion (10,000+ EPS)
- Malformed event handling
- Back-pressure and flow control
- Ingestion monitoring and metrics

**Known Gaps**:
- Fluentd/Fluent Bit integration tests incomplete
- Multi-line event handling not fully specified
- Dead-letter queue fully implemented (ingest/dlq.go, api/dlq_handlers.go)
- Ingestion performance benchmarks TBD

---

## 2. Functional Requirements

### 2.1 Supported Ingestion Protocols

#### FR-ING-001: Syslog Protocol Support
**Requirement**: System MUST support Syslog ingestion via RFC 5424 (modern) and RFC 3164 (legacy BSD syslog).

**Rationale**: Syslog is the most widely-deployed log protocol, used by network devices, servers, and applications.

**Specification**:

**Supported Transports**:
- UDP (port 514 default): Best-effort delivery, suitable for high-volume non-critical logs
- TCP (port 514 default): Reliable delivery with connection-oriented semantics

**RFC 5424 Format** (Structured Syslog):
```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MESSAGE
```

Example:
```
<134>1 2025-01-16T12:00:00.000Z firewall.example.com firewalld 1234 ID47 [meta sequenceId="123"] Connection denied
```

**RFC 3164 Format** (Legacy BSD Syslog):
```
<PRI>TIMESTAMP HOSTNAME MESSAGE
```

Example:
```
<134>Jan 16 12:00:00 firewall.example.com firewalld[1234]: Connection denied
```

**Priority Decoding**:
- PRI = Facility * 8 + Severity
- Facility: 0-23 (kernel, user, mail, daemon, auth, syslog, etc.)
- Severity: 0-7 (emergency, alert, critical, error, warning, notice, info, debug)

**Acceptance Criteria**:
- [x] RFC 5424 structured syslog parsing implemented
- [x] RFC 3164 legacy syslog parsing implemented
- [x] UDP and TCP transports supported
- [x] Priority field correctly decoded to facility and severity
- [ ] Structured data extraction (RFC 5424 [SD-ID]) implemented
- [ ] Multiple concurrent syslog sources supported
- [x] Malformed syslog events logged and dropped

**Current Implementation**: ✅ PARTIAL (ingest/syslog.go, parser needs structured data extraction)

**Test Cases**:
```
TEST-ING-001: Parse valid RFC 5424 message
GIVEN: <134>1 2025-01-16T12:00:00Z host app 123 ID [meta x="y"] msg
WHEN: Syslog parser invoked
THEN: Event created with facility=16, severity=6, timestamp parsed, structured data extracted

TEST-ING-002: Parse valid RFC 3164 message
GIVEN: <134>Jan 16 12:00:00 host message
WHEN: Syslog parser invoked
THEN: Event created with facility=16, severity=6, timestamp parsed

TEST-ING-003: Handle malformed syslog
GIVEN: Invalid syslog message with missing PRI
WHEN: Syslog parser invoked
THEN: Parsing error logged, event dropped, metric incremented
```

---

#### FR-ING-002: Common Event Format (CEF) Support
**Requirement**: System MUST support CEF format ingestion as defined in CEF specification v25.

**Rationale**: CEF is industry-standard format used by security devices (firewalls, IDS/IPS, proxies, SIEM agents).

**Specification**:

**CEF Format**:
```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

**Example**:
```
CEF:0|Palo Alto Networks|PAN-OS|9.0|TRAFFIC|Denied Connection|5|src=192.168.1.100 dst=10.0.0.50 spt=54321 dpt=443 proto=TCP act=blocked
```

**CEF Components**:
- **Version**: CEF format version (0 for v25)
- **Device Vendor**: Device manufacturer
- **Device Product**: Product name
- **Device Version**: Product version
- **Signature ID**: Event classification ID
- **Name**: Human-readable event name
- **Severity**: 0-10 (0=low, 10=critical)
- **Extension**: Key-value pairs (space-separated, values with spaces must be escaped)

**Standard CEF Fields** (Extension):
| Field | Description | Example |
|-------|-------------|---------|
| src | Source IP | 192.168.1.100 |
| dst | Destination IP | 10.0.0.50 |
| spt | Source port | 54321 |
| dpt | Destination port | 443 |
| proto | Protocol | TCP |
| act | Action taken | blocked |
| app | Application protocol | HTTPS |
| msg | Event message | Connection denied |
| cn1-cn3 | Custom numbers | cn1=5 |
| cs1-cs6 | Custom strings | cs1=Internal |

**Supported Transports**:
- UDP (port 514 default)
- TCP (port 514 default)

**Acceptance Criteria**:
- [x] CEF header parsing implemented
- [x] CEF extension parsing implemented (key-value pairs)
- [x] Escaped values handled correctly (pipes, equals, backslashes)
- [ ] All standard CEF fields mapped to SIGMA taxonomy
- [x] Custom fields (cn1-cn3, cs1-cs6) preserved
- [x] UDP and TCP transports supported
- [x] Malformed CEF events logged and dropped

**Current Implementation**: ✅ PARTIAL (ingest/cef.go, field mapping TBD)

**Test Cases**:
```
TEST-ING-004: Parse valid CEF message
GIVEN: CEF:0|Vendor|Product|1.0|100|Test|5|src=1.2.3.4 dst=5.6.7.8
WHEN: CEF parser invoked
THEN: Event created with all fields extracted correctly

TEST-ING-005: Handle escaped values in CEF
GIVEN: CEF message with escaped pipe and equals in msg field
WHEN: CEF parser invoked
THEN: Escaped characters correctly unescaped

TEST-ING-006: Handle malformed CEF
GIVEN: CEF message with missing required header fields
WHEN: CEF parser invoked
THEN: Parsing error logged, event dropped
```

---

#### FR-ING-003: JSON Protocol Support
**Requirement**: System MUST support JSON event ingestion via HTTP POST and UDP.

**Rationale**: JSON is ubiquitous format for modern applications, APIs, and cloud services.

**Specification**:

**Supported Transports**:
- HTTP POST: `POST /api/v1/ingest/json` with JSON body
- UDP (port 5140 default): Newline-delimited JSON

**JSON Schema** (flexible, any valid JSON object):
```json
{
  "timestamp": "2025-01-16T12:00:00Z",
  "level": "error",
  "message": "Authentication failed",
  "user": "admin",
  "source_ip": "192.168.1.100",
  "event_type": "auth_failure",
  "custom_field": "custom_value"
}
```

**Field Handling**:
- All fields preserved as-is
- Fields mapped to SIGMA taxonomy via field normalizer
- Nested objects flattened with dot notation: `user.name` → `user.name`
- Arrays preserved as JSON arrays

**HTTP Ingestion**:
- Request: `POST /api/v1/ingest/json`
- Content-Type: `application/json`
- Body: Single JSON object or array of objects
- Response: `202 Accepted` on success, `400 Bad Request` on invalid JSON

**HTTP Headers**:
- `X-Source`: Optional source identifier
- `X-Timestamp`: Optional override timestamp (ISO 8601)

**Size Limits**:
- Single event: 1 MB (configurable)
- Batch: 10 MB (configurable)

**Acceptance Criteria**:
- [x] JSON parsing via HTTP POST implemented
- [x] JSON parsing via UDP implemented
- [x] Nested objects preserved
- [x] Arrays preserved
- [x] Size limits enforced (413 Payload Too Large)
- [x] Invalid JSON returns 400 with error details
- [ ] Batch ingestion supported (array of events)
- [ ] Custom headers extracted (X-Source, X-Timestamp)

**Current Implementation**: ✅ PARTIAL (ingest/json.go, batch TBD)

**Test Cases**:
```
TEST-ING-007: Ingest valid JSON via HTTP
GIVEN: POST /api/v1/ingest/json with valid JSON body
WHEN: JSON ingestion handler invoked
THEN: 202 Accepted returned, event forwarded to pipeline

TEST-ING-008: Reject invalid JSON
GIVEN: POST /api/v1/ingest/json with malformed JSON
WHEN: JSON ingestion handler invoked
THEN: 400 Bad Request returned with error details

TEST-ING-009: Enforce size limit
GIVEN: POST /api/v1/ingest/json with 2MB body
WHEN: JSON ingestion handler invoked
THEN: 413 Payload Too Large returned
```

---

#### FR-ING-004: Fluentd/Fluent Bit Support
**Requirement**: System MUST support event ingestion from Fluentd and Fluent Bit using Forward protocol.

**Rationale**: Fluentd/Fluent Bit are popular log collectors used in Kubernetes, cloud environments, and distributed systems.

**Specification**:

**Forward Protocol**:
- Transport: TCP (port 24224 default)
- Encoding: MessagePack (binary format)
- Modes:
  - Forward mode: Simple tag + timestamp + record
  - PackedForward mode: Optimized packed format for high throughput
  - CompressedPackedForward mode: Gzip-compressed packed format

**Message Format** (Forward mode):
```
[tag, timestamp, record, options]
```

Example:
```
["app.logs", 1705401600, {"level":"error", "msg":"Failed"}, {"chunk":"abc"}]
```

**Message Format** (PackedForward mode):
```
[tag, [[timestamp, record], [timestamp, record], ...], options]
```

**Field Mapping**:
- Fluentd tag → `fluentd.tag`
- Fluentd timestamp → `@timestamp`
- Record fields → Preserve as-is, map via field normalizer

**Acceptance Criteria**:
- [x] Forward protocol parser implemented
- [x] MessagePack decoding implemented
- [x] Forward mode supported
- [ ] PackedForward mode supported (future)
- [ ] CompressedPackedForward mode supported (future)
- [x] Fluentd tag preserved
- [ ] TLS/mutual TLS support for encrypted transport
- [ ] Acknowledgment mode for guaranteed delivery

**Current Implementation**: ✅ PARTIAL (ingest/fluentd.go, packed mode TBD)

**Test Cases**:
```
TEST-ING-010: Parse Fluentd Forward message
GIVEN: Valid MessagePack-encoded Forward message
WHEN: Fluentd parser invoked
THEN: Event created with tag, timestamp, and record fields

TEST-ING-011: Handle MessagePack decode error
GIVEN: Invalid MessagePack data
WHEN: Fluentd parser invoked
THEN: Decoding error logged, message dropped
```

---

### 2.2 Field Normalization

#### FR-ING-005: SIGMA Field Normalization
**Requirement**: All ingested events MUST be normalized to SIGMA taxonomy for consistent rule matching.

**Rationale**: SIGMA rules assume standardized field names. Normalization enables vendor-agnostic rule portability.

**Specification**:

**SIGMA Field Taxonomy** (subset):
| Category | SIGMA Field | Description | Examples |
|----------|------------|-------------|----------|
| Process | `CommandLine` | Full command line | `powershell.exe -enc ABC` |
| Process | `Image` | Process executable path | `C:\Windows\System32\cmd.exe` |
| Process | `User` | User running process | `DOMAIN\user` |
| Network | `SourceIp` | Source IP address | `192.168.1.100` |
| Network | `DestinationIp` | Destination IP address | `10.0.0.50` |
| Network | `DestinationPort` | Destination port | `443` |
| File | `TargetFilename` | File path | `C:\temp\malware.exe` |
| File | `Hashes` | File hashes | `MD5=abc, SHA256=def` |
| Auth | `TargetUserName` | Authentication target user | `admin` |
| Auth | `LogonType` | Windows logon type | `3` (Network) |

**Field Mapping Configuration**:
- YAML-based field mappings per log source
- Mappings loaded at startup from `config/sigma_field_mappings.yaml`
- Generic fallback mapping for unmapped sources

**Example Mapping** (Windows Security):
```yaml
windows_security:
  EventID: "EventID"
  TargetUserName: "User"
  SourceAddress: "SourceIp"
  TargetFileName: "TargetFilename"
  CommandLine: "CommandLine"
```

**Normalization Behavior**:
- Original fields preserved in `_raw` namespace
- SIGMA fields added to root namespace
- Original and normalized fields coexist
- Unmapped fields pass through unchanged

**Special Field Handling**:
- **Hashes**: Normalize to `MD5=...,SHA256=...` format
- **Timestamps**: Convert to ISO 8601 UTC (`2025-01-16T12:00:00Z`)
- **IP Addresses**: Validate format, convert to string
- **Ports**: Validate range (1-65535)

**Acceptance Criteria**:
- [x] Field normalizer implemented
- [x] YAML field mapping configuration loaded
- [x] Original fields preserved in _raw namespace
- [x] SIGMA fields added to root namespace
- [x] Nested field extraction supported (dot notation)
- [x] Hash normalization implemented
- [x] Timestamp normalization implemented
- [ ] Per-source field mappings configurable via UI
- [ ] Field mapping validation on startup

**Current Implementation**: ✅ COMPLIANT (core/field_normalizer.go, config/sigma_field_mappings.yaml)

**Test Cases**:
```
TEST-ING-012: Normalize Windows Security event
GIVEN: Event with EventID=4625, TargetUserName=admin
WHEN: Field normalizer applied with windows_security mapping
THEN: Event contains EventID=4625, User=admin, _raw.EventID=4625

TEST-ING-013: Preserve unmapped fields
GIVEN: Event with custom_field=value
WHEN: Field normalizer applied
THEN: custom_field preserved in output

TEST-ING-014: Normalize hash format
GIVEN: Event with hash=abc123 (32 chars)
WHEN: Field normalizer applied
THEN: Hashes=MD5=ABC123
```

---

#### FR-ING-006: Event Enrichment
**Requirement**: System SHOULD enrich events with additional context during ingestion.

**Rationale**: Enrichment adds value to raw events by providing threat intelligence, geolocation, and metadata.

**Specification**:

**Enrichment Types**:

**1. GeoIP Lookup**:
- Source/Destination IP → Country, City, ASN, Organization
- Uses MaxMind GeoLite2 database (free) or commercial GeoIP
- Fields added: `src_geo.country`, `src_geo.city`, `src_geo.asn`, `src_geo.org`

**2. DNS Reverse Lookup** (optional, performance impact):
- IP address → Hostname
- Cached with TTL to reduce latency
- Field added: `src_hostname`, `dst_hostname`

**3. Threat Intelligence Lookup** (future):
- IP/Domain/Hash → Threat score, category, feeds
- Integration with MISP, STIX/TAXII, vendor feeds
- Fields added: `threat.score`, `threat.category`, `threat.feeds`

**4. Asset Inventory Correlation** (future):
- IP/Hostname → Asset metadata (owner, criticality, location)
- Integration with CMDB
- Fields added: `asset.owner`, `asset.criticality`, `asset.tags`

**Configuration**:
```yaml
enrichment:
  geoip:
    enabled: true
    database_path: "/data/GeoLite2-City.mmdb"
    cache_ttl: 3600s
  dns:
    enabled: false  # High latency, disabled by default
    timeout: 100ms
  threat_intel:
    enabled: false
    sources: ["misp", "otx"]
```

**Acceptance Criteria**:
- [ ] GeoIP enrichment implemented
- [ ] GeoIP database auto-update mechanism
- [ ] DNS reverse lookup implemented with caching
- [ ] Enrichment toggle per source/field
- [ ] Enrichment metrics tracked (lookup time, cache hit rate)
- [ ] Enrichment errors logged but don't fail ingestion

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] GeoIP library selection (MaxMind vs alternatives)
- [ ] Enrichment performance impact analysis
- [ ] Threat intel feed integration priorities

---

### 2.3 Event Validation

#### FR-ING-007: Event Schema Validation
**Requirement**: System MUST validate event structure and data types during ingestion.

**Rationale**: Invalid events cause downstream pipeline failures. Early validation prevents bad data propagation.

**Specification**:

**Required Fields**:
- `@timestamp`: Event timestamp (ISO 8601 UTC)
- `source`: Log source identifier (hostname, IP, application)
- `message` OR `raw_event`: Event content

**Validation Rules**:

**Timestamp Validation**:
- Format: ISO 8601 with timezone (e.g., `2025-01-16T12:00:00Z`)
- Range: Within 7 days past or 1 hour future (clock skew tolerance)
- Default: Current time if missing or invalid

**IP Address Validation**:
- IPv4: Dotted quad format (e.g., `192.168.1.100`)
- IPv6: Colon-separated format (e.g., `2001:db8::1`)
- Invalid IPs logged, field set to null

**Port Validation**:
- Range: 1-65535
- Type: Integer
- Invalid ports logged, field set to null

**String Length Limits**:
- `message`: 64 KB max
- Field names: 256 chars max
- String values: 32 KB max (configurable)

**Malformed Event Handling**:
1. Log malformed event details (correlation ID, raw content, error)
2. Increment malformed event metric
3. Optionally send to dead-letter queue (DLQ) for manual review
4. Drop event from normal pipeline

**Acceptance Criteria**:
- [ ] Required field validation implemented
- [x] Timestamp validation and parsing implemented
- [ ] IP address validation implemented
- [ ] Port range validation implemented
- [ ] String length limits enforced
- [ ] Malformed events logged with details
- [ ] Malformed event metrics tracked
- [ ] Dead-letter queue implemented (optional)

**Current Implementation**: ⚠️ PARTIAL (basic parsing, formal validation TBD)

**Test Cases**:
```
TEST-ING-015: Accept valid event
GIVEN: Event with @timestamp, source, message
WHEN: Event validator invoked
THEN: Event passes validation

TEST-ING-016: Reject event with invalid timestamp
GIVEN: Event with @timestamp="invalid"
WHEN: Event validator invoked
THEN: Event rejected, default timestamp applied, warning logged

TEST-ING-017: Enforce string length limit
GIVEN: Event with message=65KB string
WHEN: Event validator invoked
THEN: Event rejected or truncated, error logged
```

---

### 2.4 Ingestion Performance and Reliability

#### FR-ING-008: High-Throughput Ingestion
**Requirement**: System MUST sustain 10,000 events per second (EPS) ingestion rate with <500ms latency (p95).

**Rationale**: Enterprise SIEM requires high throughput to keep pace with log volume without data loss.

**Specification**:

**Throughput Targets**:
- Sustained throughput: 10,000 EPS
- Burst throughput: 50,000 EPS for 60 seconds
- Total daily ingestion: 864 million events (10K EPS × 86,400 sec)

**Latency Targets** (event received → available for search):
- p50 latency: < 100ms
- p95 latency: < 500ms
- p99 latency: < 2 seconds

**Scalability**:
- Horizontal scaling: Multiple ingestion nodes with load balancer
- Partitioning: Distribute events across storage partitions
- Batching: Batch writes to storage (100-1000 events per batch)

**Performance Optimizations**:
- Connection pooling for database writes
- Async I/O for network operations
- Worker pool for event processing (CPU-bound)
- Buffered channels for event pipeline (backpressure)

**Acceptance Criteria**:
- [ ] Sustained 10,000 EPS validated via load testing
- [ ] Burst 50,000 EPS validated via load testing
- [ ] p95 latency < 500ms under normal load
- [ ] Horizontal scaling tested with 2+ nodes
- [ ] Zero data loss under normal operating conditions
- [ ] Graceful degradation under overload (backpressure)

**Current Implementation**: ⚠️ PARTIAL (architecture supports, benchmarks TBD)

**TBD**:
- [ ] Load testing with realistic event mix
- [ ] Storage write batching implementation
- [ ] Horizontal scaling testing
- [ ] Throughput/latency metrics dashboard

---

#### FR-ING-009: Connection Management
**Requirement**: System MUST implement bounded connection pools to prevent resource exhaustion.

**Rationale**: Unbounded connections enable DoS attacks and exhaust server resources (memory, file descriptors).

**Specification**:

**TCP Connection Limits**:
- Global limit: 1,000 concurrent connections (configurable)
- Per-IP limit: 10 concurrent connections (prevents single source from exhausting pool)
- Connection timeout: 5 minutes idle timeout
- Backlog: 128 pending connections (OS TCP backlog)

**Connection Pool Behavior**:
- Semaphore-based admission control (token bucket)
- Connection rejected when pool full (graceful backpressure)
- Rejected connections logged with source IP
- Metrics tracked: active connections, rejected connections, per-IP connections

**UDP Packet Handling**:
- UDP is stateless, no connection limit
- Rate limiting prevents UDP packet floods
- Oversized packets dropped (max 64KB)

**HTTP Ingestion**:
- HTTP server connection limits (default: 1,000)
- Idle timeout: 60 seconds
- Header read timeout: 5 seconds
- Request read timeout: 15 seconds

**Acceptance Criteria**:
- [x] TCP connection pool implemented with semaphore
- [x] Per-IP connection tracking implemented
- [x] Per-IP connection limit enforced (10 connections)
- [x] Global connection limit enforced (1,000 connections)
- [x] Connection timeouts configured
- [x] Rejected connections logged and counted
- [x] Metrics tracked for connection pool

**Current Implementation**: ✅ COMPLIANT (ingest/base.go:19-99, 169-243)

---

#### FR-ING-010: Rate Limiting
**Requirement**: System MUST implement rate limiting to prevent ingestion pipeline overload.

**Rationale**: Rate limiting protects downstream components (parser, normalizer, storage) from overload.

**Specification**:

**Rate Limiting Strategy**:
- Algorithm: Token bucket (allows bursts, smooths traffic)
- Scope: Per listener (Syslog, CEF, JSON, Fluentd)
- Default rate: 1,000 events/second per listener
- Burst capacity: 2x rate limit (2,000 events)

**Rate Limit Exceeded Behavior**:
- Event dropped (not queued)
- Warning logged with source IP and listener type
- Metric incremented: `ingestion_rate_limit_exceeded`
- No response sent (UDP) or 429 returned (HTTP)

**Dynamic Rate Limiting** (future):
- Auto-adjust based on downstream capacity (backpressure)
- Per-source rate limits (e.g., noisy source gets limited)
- Priority-based rate limiting (critical sources bypass limit)

**Acceptance Criteria**:
- [x] Rate limiting implemented per listener
- [x] Token bucket algorithm used
- [x] Rate limit exceeded events logged
- [x] Metrics tracked for rate limit violations
- [ ] Dynamic rate limiting based on backpressure
- [ ] Per-source rate limits configurable

**Current Implementation**: ✅ PARTIAL (ingest/base.go:91, needs dynamic adjustment)

---

#### FR-ING-011: Backpressure and Flow Control
**Requirement**: System MUST implement backpressure to prevent event loss when downstream pipeline is overloaded.

**Rationale**: When storage or rule engine is slow, ingestion must slow down gracefully rather than dropping events.

**Specification**:

**Backpressure Mechanism**:
- Buffered event channel: 10,000 event buffer
- Channel full behavior:
  - TCP: Slow down reading (TCP backpressure to client)
  - UDP: Drop packets (log warning)
  - HTTP: Return 503 Service Unavailable

**Backpressure Signals**:
- Event channel utilization: Track % full
- Alert when >80% full (warning)
- Alert when >95% full (critical)
- Auto-scale or throttle when full

**Graceful Degradation**:
- Priority: Critical events bypassed
- Rate limiting tightened when backpressure detected
- Temporary suspension of non-critical sources

**Acceptance Criteria**:
- [x] Buffered event channel implemented (capacity: 10,000)
- [x] Channel full behavior defined per protocol
- [x] HTTP returns 503 when buffer full
- [ ] Channel utilization metrics tracked
- [ ] Backpressure alerts configured (>80%, >95%)
- [ ] Priority-based event handling implemented

**Current Implementation**: ✅ PARTIAL (buffered channel in place, monitoring TBD)

---

#### FR-ING-012: Dead Letter Queue (DLQ)
**Requirement**: System MUST implement a dead-letter queue for malformed events.

**Rationale**: Malformed events contain valuable context for debugging and may become parseable after mapping updates.

**Specification**:

**DLQ Behavior**:
- Malformed events written to DLQ automatically on parse/validation failure
- DLQ storage: SQLite table `dead_letter_queue`
- Retention: Configurable (default: 30 days)
- Fields: ID, timestamp, protocol, raw_event, error_reason, error_details, source_ip, retries, status, created_at

**DLQ Event Status**:
- `pending`: New event, not yet replayed
- `replayed`: Event successfully re-ingested after replay
- `discarded`: Event manually discarded or expired

**DLQ Management**:
- REST API endpoints for DLQ operations:
  - `GET /api/v1/dlq`: List DLQ events (with pagination and filtering)
  - `GET /api/v1/dlq/{id}`: Get single DLQ event
  - `POST /api/v1/dlq/{id}/replay`: Replay DLQ event (retry parsing)
  - `DELETE /api/v1/dlq/{id}`: Discard DLQ event
- Filtering by status (pending, replayed, discarded) and protocol
- Pagination support (default: 50, max: 100 per page)

**DLQ Replay Mechanism**:
- Manual replay via API endpoint
- Replay attempts re-parse event through original ingestion handler
- Retry counter tracks replay attempts
- Successful replay updates status to `replayed`
- Failed replay increments retry counter

**DLQ Metrics** (Prometheus):
- `cerberus_dlq_events_total`: Total DLQ events written
- `cerberus_dlq_events_by_reason`: DLQ events by error reason (parse_failure, validation_error, etc.)
- `cerberus_dlq_events_by_protocol`: DLQ events by protocol (syslog, cef, json, fluentd)

**DLQ Retention Policies**:
- Automatic cleanup of expired events (based on `created_at`)
- Retention period configurable (default: 30 days)
- Cleanup job runs periodically

**Acceptance Criteria**:
- [x] DLQ storage implemented (SQLite table)
- [x] Malformed events written to DLQ automatically
- [x] DLQ API endpoints implemented (list, get, replay, delete)
- [x] Retry parsing mechanism implemented (replay endpoint)
- [x] DLQ retention policy enforced (cleanup method)
- [x] DLQ metrics tracked (Prometheus metrics)

**Current Implementation**: ✅ FULLY IMPLEMENTED (ingest/dlq.go, api/dlq_handlers.go)

**Implementation Details**:
- Storage: SQLite `dead_letter_queue` table
- Metrics: Prometheus metrics integration via `metrics` package
- API: RESTful endpoints with RBAC enforcement
- Error tracking: Categorizes errors by reason (parse_failure, validation_error, etc.)
- Replay: Re-ingests events through original ingestion pipeline

#### FR-DLQ-001: Dead Letter Queue for Failed Event Parsing
**Requirement**: System MUST automatically write malformed events to dead-letter queue.

**Specification**:
- Events that fail parsing or validation are automatically written to DLQ
- DLQ entry includes: raw event, protocol, error reason, error details, source IP, timestamp
- DLQ write operations are non-blocking (failures don't block ingestion pipeline)
- DLQ write operations are logged for debugging

**Implementation**: `ingest/dlq.go:42-69` (DLQ.Add)

**Acceptance Criteria**:
- [x] Malformed events automatically written to DLQ
- [x] DLQ entries include all required fields
- [x] DLQ writes are non-blocking

---

#### FR-DLQ-002: DLQ Event Retention and Expiry
**Requirement**: System MUST support configurable DLQ event retention policies.

**Specification**:
- Default retention: 30 days
- Retention configurable via configuration
- Expired events are automatically cleaned up
- Cleanup job runs periodically (configurable interval)
- Cleanup operations are logged

**Implementation**: `ingest/dlq.go:220-238` (DLQ.Cleanup)

**Acceptance Criteria**:
- [x] Retention policy is configurable
- [x] Expired events are cleaned up automatically
- [x] Cleanup operations are logged

---

#### FR-DLQ-003: DLQ Event Replay Mechanism
**Requirement**: System MUST support replaying DLQ events to retry parsing.

**Specification**:
- Manual replay via API endpoint: `POST /api/v1/dlq/{id}/replay`
- Replay re-ingests event through original ingestion handler
- Retry counter tracks number of replay attempts
- Successful replay updates status to `replayed`
- Failed replay increments retry counter

**Implementation**: `api/dlq_handlers.go:96-161` (replayDLQEvent)

**Acceptance Criteria**:
- [x] Replay endpoint exists
- [x] Replay re-ingests through original handler
- [x] Retry counter is tracked
- [x] Status is updated on success/failure

---

#### FR-DLQ-004: DLQ Metrics and Monitoring
**Requirement**: System MUST expose DLQ metrics via Prometheus.

**Specification**:
- `cerberus_dlq_events_total`: Total DLQ events written (counter)
- `cerberus_dlq_events_by_reason`: DLQ events by error reason (counter with label `reason`)
- `cerberus_dlq_events_by_protocol`: DLQ events by protocol (counter with label `protocol`)
- Metrics are updated on DLQ write operations

**Implementation**: `ingest/dlq.go:62-65` (metrics integration)

**Acceptance Criteria**:
- [x] DLQ metrics are exposed
- [x] Metrics are updated on DLQ operations
- [x] Metrics include required labels

---

#### FR-DLQ-005: DLQ API Endpoints
**Requirement**: System MUST provide REST API endpoints for DLQ management.

**Specification**:
- `GET /api/v1/dlq`: List DLQ events (with pagination and filtering)
  - Query params: `page`, `limit`, `status`, `protocol`
  - Response: Paginated list of DLQ events
- `GET /api/v1/dlq/{id}`: Get single DLQ event by ID
  - Response: DLQ event details
- `POST /api/v1/dlq/{id}/replay`: Replay DLQ event (retry parsing)
  - Response: Replay result (success/failure)
- `DELETE /api/v1/dlq/{id}`: Discard DLQ event
  - Response: 204 No Content
- All endpoints require RBAC permissions (admin:system or write:events)

**Implementation**: `api/dlq_handlers.go` (all endpoints)

**Acceptance Criteria**:
- [x] All DLQ endpoints are implemented
- [x] Endpoints support pagination and filtering
- [x] RBAC is enforced

---

#### FR-DLQ-006: DLQ Retention Policies
**Requirement**: System MUST enforce DLQ retention policies automatically.

**Specification**:
- Automatic cleanup of expired events (based on `created_at` timestamp)
- Retention period: Configurable (default: 30 days)
- Cleanup job: Runs periodically (configurable interval, default: daily)
- Cleanup operations: Batch delete expired events
- Cleanup logging: All cleanup operations are logged

**Implementation**: `ingest/dlq.go:220-238` (DLQ.Cleanup)

**Acceptance Criteria**:
- [x] Retention policies are enforced
- [x] Cleanup job runs periodically
- [x] Cleanup operations are logged

---

### 2.5 Multi-line Event Handling

#### FR-ING-013: Multi-line Event Aggregation
**Requirement**: System SHOULD support multi-line event aggregation for logs spanning multiple lines.

**Rationale**: Stack traces, JSON logs, and multi-line syslog messages require aggregation before parsing.

**Specification**:

**Aggregation Strategies**:

**1. Pattern-based**:
- Start pattern: Regex matching first line of event (e.g., `^\d{4}-\d{2}-\d{2}`)
- Continuation pattern: Lines not matching start pattern
- Timeout: 5 seconds (emit incomplete event)

**2. Delimiter-based**:
- End delimiter: Empty line, special character
- Example: JSON logs separated by blank lines

**3. Count-based**:
- Fixed number of lines per event
- Example: 3-line events

**Configuration Example**:
```yaml
listeners:
  syslog:
    multiline:
      enabled: true
      pattern: '^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'  # Syslog timestamp
      negate: false
      match: after
      timeout: 5s
```

**Acceptance Criteria**:
- [ ] Pattern-based aggregation implemented
- [ ] Delimiter-based aggregation implemented
- [ ] Count-based aggregation implemented
- [ ] Timeout enforcement (incomplete events emitted)
- [ ] Configurable per listener
- [ ] Metrics tracked (multi-line events aggregated)

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] Multi-line aggregation requirements validation
- [ ] Common log format patterns library
- [ ] Performance impact analysis

---

### 2.6 Ingestion Monitoring

#### FR-ING-014: Ingestion Metrics
**Requirement**: System MUST expose comprehensive ingestion metrics via Prometheus.

**Rationale**: Metrics enable capacity planning, performance monitoring, and anomaly detection.

**Specification**:

**Metrics to Track**:

**Throughput Metrics**:
- `ingestion_events_total` (counter): Total events ingested, labeled by protocol
- `ingestion_events_per_second` (gauge): Current ingestion rate
- `ingestion_bytes_total` (counter): Total bytes ingested

**Latency Metrics**:
- `ingestion_latency_seconds` (histogram): End-to-end ingestion latency (p50, p95, p99)
- `ingestion_parse_duration_seconds` (histogram): Parse time per protocol

**Error Metrics**:
- `ingestion_errors_total` (counter): Parse errors, labeled by protocol and error type
- `ingestion_dropped_events_total` (counter): Events dropped due to errors
- `ingestion_rate_limit_exceeded_total` (counter): Rate limit violations

**Connection Metrics**:
- `ingestion_active_connections` (gauge): Current active TCP connections
- `ingestion_rejected_connections_total` (counter): Connections rejected (pool full)
- `ingestion_connections_per_ip` (gauge): Connections per IP address

**Resource Metrics**:
- `ingestion_channel_utilization` (gauge): Event channel buffer % full
- `ingestion_memory_bytes` (gauge): Memory usage

**Acceptance Criteria**:
- [ ] All metrics implemented and exposed via `/metrics`
- [ ] Metrics labeled appropriately (protocol, error_type, source)
- [ ] Prometheus dashboard created
- [ ] Alerting rules configured (high error rate, high latency, channel full)
- [ ] Metrics documented

**Current Implementation**: ⚠️ PARTIAL (some metrics exist, comprehensive set TBD)

**TBD**:
- [ ] Complete metrics implementation
- [ ] Grafana dashboard design
- [ ] Alert thresholds configuration

---

## 3. Non-Functional Requirements

### 3.1 Performance

**NFR-ING-001: Ingestion Throughput**
- MUST sustain 10,000 EPS continuously
- MUST handle 50,000 EPS bursts for 60 seconds
- MUST NOT drop events under normal load (<80% capacity)

**NFR-ING-002: Ingestion Latency**
- p50: < 100ms
- p95: < 500ms
- p99: < 2 seconds
- Measured from event received to available in storage

**NFR-ING-003: CPU Utilization**
- MUST NOT exceed 80% CPU under normal load (10K EPS)
- SHOULD NOT exceed 95% CPU under burst load (50K EPS)

**NFR-ING-004: Memory Usage**
- Event channel buffer: 10,000 events × ~5KB/event = ~50MB
- Connection tracking: 1,000 connections × ~10KB = ~10MB
- Total ingestion memory: < 200MB under normal load

### 3.2 Reliability

**NFR-ING-005: Availability**
- Ingestion service MUST achieve 99.9% uptime
- MUST recover from crashes within 30 seconds
- MUST NOT lose in-flight events on graceful shutdown

**NFR-ING-006: Data Integrity**
- Zero data loss under normal operating conditions
- MUST detect and log data corruption (checksum validation)
- MUST preserve original event in _raw field

**NFR-ING-007: Fault Tolerance**
- MUST continue ingesting when storage is unavailable (buffer to disk)
- MUST continue ingesting when one protocol fails
- MUST isolate listener failures (TCP failure doesn't affect UDP)

### 3.3 Security

**NFR-ING-008: Transport Security**
- MUST support TLS for TCP-based protocols (Syslog TCP, Fluentd, HTTP)
- SHOULD support mutual TLS for client authentication
- MUST enforce TLS 1.2+ (reject TLS 1.0, TLS 1.1, SSLv3)

**NFR-ING-009: Input Validation**
- MUST validate all input to prevent injection attacks
- MUST limit input size to prevent DoS (10MB max per event)
- MUST sanitize log output to prevent log injection

**NFR-ING-010: Resource Limits**
- MUST enforce connection limits (1,000 global, 10 per-IP)
- MUST enforce rate limits (1,000 EPS per listener)
- MUST enforce request size limits (1MB for JSON, 64KB for Syslog)

### 3.4 Scalability

**NFR-ING-011: Horizontal Scaling**
- Ingestion tier MUST scale horizontally (stateless)
- MUST support multiple ingestion nodes behind load balancer
- MUST distribute load evenly across nodes

**NFR-ING-012: Storage Scalability**
- MUST support partitioned storage writes (ClickHouse distributed tables)
- MUST batch storage writes for efficiency (100-1000 events per batch)
- MUST NOT overwhelm storage with write rate

---

## 4. Test Requirements

### 4.1 Functional Tests

**TEST-ING-018: Syslog RFC 5424 Parsing**
- GIVEN: Valid RFC 5424 syslog message
- WHEN: Syslog parser invoked
- THEN: All fields extracted correctly (facility, severity, timestamp, hostname, message, structured data)

**TEST-ING-019: CEF Parsing with Escaped Characters**
- GIVEN: CEF message with escaped pipes, equals, backslashes
- WHEN: CEF parser invoked
- THEN: Escaped characters correctly unescaped in output

**TEST-ING-020: JSON Nested Object Preservation**
- GIVEN: JSON event with nested objects
- WHEN: JSON parser invoked
- THEN: Nested objects preserved in event structure

**TEST-ING-021: Field Normalization**
- GIVEN: Windows Security event with EventID=4625
- WHEN: Field normalizer applied
- THEN: SIGMA field User created, original field preserved in _raw

### 4.2 Performance Tests

**TEST-ING-022: Sustained Throughput Test**
- GIVEN: Continuous stream of 10,000 EPS for 10 minutes
- WHEN: Ingestion pipeline runs
- THEN: All events ingested successfully, p95 latency < 500ms, 0% drop rate

**TEST-ING-023: Burst Throughput Test**
- GIVEN: Burst of 50,000 EPS for 60 seconds
- WHEN: Ingestion pipeline runs
- THEN: All events buffered and processed, recovery within 2 minutes

**TEST-ING-024: Connection Pool Exhaustion Test**
- GIVEN: 1,100 concurrent TCP connections attempted
- WHEN: Connection pool limit is 1,000
- THEN: 100 connections rejected, existing connections unaffected

### 4.3 Reliability Tests

**TEST-ING-025: Graceful Shutdown Test**
- GIVEN: Ingestion service processing events
- WHEN: SIGTERM sent to service
- THEN: Service stops accepting new connections, drains buffer, exits cleanly

**TEST-ING-026: Storage Failure Resilience**
- GIVEN: Storage becomes unavailable
- WHEN: Events continue arriving
- THEN: Events buffered to disk, no data loss, recovery when storage returns

### 4.4 Security Tests

**TEST-ING-027: Oversized Event Rejection**
- GIVEN: JSON event with 15MB body
- WHEN: HTTP ingestion receives event
- THEN: 413 Payload Too Large returned, event dropped

**TEST-ING-028: Per-IP Connection Limit**
- GIVEN: Single IP attempts 15 concurrent TCP connections
- WHEN: Per-IP limit is 10
- THEN: First 10 connections accepted, subsequent 5 rejected

---

## 5. TBD Tracker

| ID | Description | Owner | Target Date | Status |
|----|-------------|-------|-------------|--------|
| TBD-ING-001 | Fluentd PackedForward mode implementation | Ingestion Team | 2025-03-15 | Open |
| TBD-ING-002 | Dead-letter queue storage backend selection | Ingestion Team | 2025-02-15 | ✅ COMPLETE (SQLite) |
| TBD-ING-003 | Multi-line event aggregation requirements | Ingestion Team | 2025-03-01 | Open |
| TBD-ING-004 | GeoIP enrichment integration | Ingestion Team | 2025-04-01 | Open |
| TBD-ING-005 | Load testing with 10K EPS | QA Team | 2025-02-28 | Open |
| TBD-ING-006 | Horizontal scaling testing | Infra Team | 2025-03-15 | Open |
| TBD-ING-007 | TLS/mutual TLS for ingestion protocols | Security Team | 2025-03-01 | Open |
| TBD-ING-008 | Prometheus metrics dashboard design | Observability Team | 2025-02-15 | Open |
| TBD-ING-009 | Event validation schema formalization | Ingestion Team | 2025-02-01 | Open |
| TBD-ING-010 | Storage write batching optimization | Storage Team | 2025-03-01 | Open |

---

## 6. Compliance Verification Checklist

### Protocol Support
- [x] Syslog RFC 5424 implemented
- [x] Syslog RFC 3164 implemented
- [x] CEF parsing implemented
- [x] JSON ingestion implemented
- [x] Fluentd Forward protocol implemented
- [ ] Fluentd PackedForward implemented

### Field Normalization
- [x] SIGMA field mapping implemented
- [x] Original field preservation (_raw)
- [x] Hash normalization
- [x] Timestamp normalization
- [ ] Configurable field mappings

### Validation
- [ ] Required field validation
- [x] Timestamp validation
- [ ] IP address validation
- [ ] String length limits
- [ ] Malformed event logging

### Performance
- [x] Connection pool limits enforced
- [x] Rate limiting implemented
- [x] Backpressure mechanism implemented
- [ ] 10K EPS sustained throughput validated
- [ ] Latency SLAs validated

### Reliability
- [x] Graceful shutdown implemented
- [ ] Dead-letter queue implemented
- [ ] Storage failure resilience tested

### Security
- [x] Request size limits enforced
- [x] Per-IP connection limits enforced
- [ ] TLS support for TCP protocols
- [x] Input sanitization

### Monitoring
- [ ] Comprehensive metrics implemented
- [ ] Prometheus dashboard created
- [ ] Alerting rules configured

---

## 7. References

### Industry Standards
- [RFC 5424: Syslog Protocol](https://tools.ietf.org/html/rfc5424)
- [RFC 3164: BSD Syslog Protocol](https://tools.ietf.org/html/rfc3164)
- [Common Event Format (CEF) v25](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf)
- [SIGMA Detection Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [Fluentd Forward Protocol](https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1)
- [MessagePack Specification](https://msgpack.org/)

### Internal Documents
- `docs/requirements/performance-requirements.md`: Performance SLAs
- `docs/requirements/security-threat-model.md`: Security requirements
- `config/sigma_field_mappings.yaml`: Field mapping configuration

### Related Code
- `ingest/base.go`: Base listener implementation
- `ingest/syslog.go`: Syslog listener
- `ingest/cef.go`: CEF listener
- `ingest/json.go`: JSON listener
- `ingest/fluentd.go`: Fluentd listener
- `core/field_normalizer.go`: SIGMA field normalization
- `metrics/metrics.go`: Ingestion metrics

---

## 8. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-16 | Requirements Team | Initial draft based on codebase analysis |

---

**Document Status**: DRAFT - Awaiting technical review and stakeholder approval

**Next Steps**:
1. Technical review by ingestion team (target: 2025-01-23)
2. Performance validation via load testing (target: 2025-02-28)
3. Security review by security team (target: 2025-01-30)
4. Stakeholder approval (target: 2025-02-06)
