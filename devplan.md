# **Cerberus SIEM Development Plan**

## **Project Overview**

Product Name: Cerberus (Golang-based Security Information and Event Management)  
Core Technology Stack: Golang, MongoDB  
Architectural Metaphor: The three heads of Cerberus represent the core functions of the SIEM:

1. **Event Ingestion:** Listening, normalizing, and storing raw security data.  
2. **Alerting/Detection:** Applying real-time rules and logic to identify threats.  
3. **Orchestration/Response:** Automating actions and driving external security systems.

## **Combined Phase 0-1: Foundation & Ingestion**

This combined phase establishes the core architecture, data model, and ingestion capabilities, ensuring a solid foundation for event processing. The architecture follows a modular, concurrent design using Golang's strengths in goroutines and channels for high-performance event handling.

### **Architectural Overview**
- **Modular Structure**: Service divided into packages: `ingest` (listeners and parsers), `core` (common schema and utilities), `config` (configuration management), `storage` (MongoDB interactions).
- **Concurrency Model**: Extensive use of goroutines and channels for non-blocking I/O. Listeners run in separate goroutines, feeding events into a buffered channel for processing.
- **Data Flow**: Raw events → Listener Goroutines → Parser (transformation) → Validation → Buffered Channel → Batch Writer Goroutines → MongoDB.
- **Error Handling**: Dead-letter queues (MongoDB collection) for failed events; structured logging with zap for observability.
- **Security**: TLS for all listeners; secrets managed via environment variables; input validation to prevent injection attacks.
- **Scalability**: Connection pooling for MongoDB; rate limiting with token bucket algorithm; horizontal scaling via Kubernetes pods.

### **0.1 Common Event Schema Definition**

All incoming events, regardless of their source format (Syslog, CEF, JSON), MUST be transformed into a standardized Golang struct and corresponding MongoDB document structure for uniform processing and querying. The schema uses a flexible map for custom fields while enforcing core fields.

**Architectural Details**:
- Struct defined in `core/schema.go` with JSON/BSON tags.
- Validation using Go's `validator` library for required fields.
- Indexing strategy: Compound indexes on `timestamp` and `event_type` for efficient queries.

| Field Name | Type (Go) | Description |
| :---- | :---- | :---- |
| event\_id | string | Unique identifier (e.g., UUID v4 generated upon ingestion). |
| timestamp | time.Time | Event creation time, standardized to UTC. |
| source\_format | string | Original format (syslog, cef, json) for reference. |
| source\_ip | string | IP address of the device/system that sent the log. |
| event\_type | string | Categorization of the event (e.g., user\_login, file\_access). |
| severity | string | Normalized severity (e.g., Info, Warning, Critical). |
| raw\_data | string | The complete original log line/payload (for forensic purposes). |
| fields | map\[string\]interface{} | A flexible JSON BSON structure for all parsed, normalized key-value pairs (e.g., user: "john.doe", action: "failed\_auth"). |

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-0.1.1** | Define and implement the Common Event Schema as a Golang struct with JSON/BSON tags for MongoDB compatibility. | The struct compiles without errors and can be marshaled/unmarshaled to/from JSON and BSON. |
| **FR-0.1.2** | Ensure schema flexibility for custom fields while maintaining core fields. | Custom fields are stored in the 'fields' map without breaking core field access. |
| **FR-0.1.3** | Implement UUID generation using crypto/rand for event_id uniqueness. | Generated IDs are unique across 1M events with <0.01% collision probability. |

### **0.2 Core Services & Configuration**

**Architectural Details**:
- Configuration loaded via Viper from YAML/JSON files and env vars.
- Dependency injection pattern for services (e.g., MongoDB client injected into storage layer).
- Health checks using Gorilla Mux for HTTP endpoints.
- CI/CD with GitHub Actions: build, test, lint (golangci-lint), and security scans (gosec).

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-0.2.1** | Initialize a Golang service structure with clear modules (ingest, detect, orchestrate). | Project scaffolded; go run main.go compiles and starts the core service without error. |
| **FR-0.2.2** | Implement robust configuration loading (e.g., using viper or standard JSON/YAML file). | All service parameters (ports, DB connection strings, rule file paths) are loaded at startup. |
| **FR-0.2.3** | Establish connection and persistence with a MongoDB instance. | A health check endpoint or startup message confirms a successful connection to the MongoDB instance. |
| **FR-0.2.4** | Set up API versioning strategy (e.g., /api/v1/) and initial CI/CD pipeline (e.g., GitHub Actions for build/test). | API endpoints are versioned; CI/CD runs on pushes, ensuring builds pass. |
| **FR-0.2.5** | Implement dependency management (Go modules) and MongoDB indexing for common schema fields (e.g., timestamp, event_type). | Dependencies are locked; indexes improve query performance by 50% in benchmarks. |
| **FR-0.2.6** | Add health check endpoints (/health) and basic metrics (e.g., uptime, connection status). | Health endpoint returns 200 OK with JSON status; metrics are exposed for monitoring. |
| **FR-0.2.7** | Implement graceful shutdown with context cancellation for all goroutines. | Service shuts down cleanly on SIGTERM, closing connections and flushing buffers. |

### **1.1 Listener Implementation (Syslog, CEF, JSON)**

**Architectural Details**:
- Factory pattern for listener creation (e.g., `ListenerFactory` interface with implementations for Syslog, CEF, JSON).
- Observer pattern: Listeners notify a central event channel.
- Rate limiting using golang.org/x/time/rate with token bucket algorithm.
- Parsing algorithms: Regex for Syslog (RFC 5424), string splitting for CEF, JSON unmarshaling for raw JSON.
- Concurrency: Each listener spawns goroutines per connection; channels prevent blocking.
- Protocols: All listeners support both TCP and UDP for maximum compatibility (e.g., Syslog UDP/TCP, CEF UDP/TCP, JSON HTTP POST and UDP raw).

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-1.1.1** | Implement a listener for standard Syslog (RFC 5424) events over TCP/UDP on a user-defined port. | The service successfully receives and processes Syslog messages from a test utility (e.g., logger) over both TCP and UDP. |
| **FR-1.1.2** | Implement a listener for CEF (Common Event Format) events over TCP/UDP. | The service correctly parses the pipe-separated fields and extension dictionary of a sample CEF event received via TCP or UDP. |
| **FR-1.1.3** | Implement a listener for raw JSON log data over HTTP POST endpoints and UDP. | A POST request with a JSON body to the /api/v1/ingest/json endpoint results in a 202 Accepted response; UDP JSON messages are also accepted and parsed. |
| **FR-1.1.4** | Add rate limiting for listeners (e.g., 1000 EPS per source) and support for additional formats like Windows Event Logs. | Rate-limited sources are throttled; Windows events are parsed and ingested correctly. |
| **FR-1.1.5** | Implement TLS support for secure listeners (e.g., HTTPS for JSON, TLS for Syslog/CEF TCP). | Listeners accept encrypted connections; certificates are configurable. |
| **FR-1.1.6** | Add listener concurrency with Goroutines for handling multiple simultaneous connections. | System handles 100 concurrent connections without errors. |
| **FR-1.1.7** | Implement input sanitization and validation to prevent malformed data injection. | Invalid inputs are rejected with 400 Bad Request; logs detail validation failures. |

### **1.2 Event Transformation and Persistence**

**Architectural Details**:
- Pipeline pattern: Raw input → Parser → Validator → Normalizer → Channel → Writer.
- Deduplication using SHA-256 hashing of raw_data; Bloom filter for fast checks.
- Batching with worker pool pattern: Goroutines consume from channel, batch writes to MongoDB.
- Error handling: Circuit breaker pattern for MongoDB failures; exponential backoff for retries.

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-1.2.1** | The ingestion pipeline must transform raw Syslog, CEF, and JSON into the Common Event Schema (FR-0.1.1). | A test event from each format is logged to the console, showing correct field mapping and timestamp normalization. |
| **FR-1.2.2** | Every normalized event must be immediately written to the MongoDB instance. | The MongoDB collection for events successfully receives and stores 1,000 test events per minute without errors. |
| **FR-1.2.3** | Implement robust error handling for malformed events (e.g., logging the raw data to a dead-letter queue/file and dropping the event, rather than crashing). | When a malformed event is sent, the service logs an error, but continues to process subsequent valid events. |
| **FR-1.2.4** | Implement batching for MongoDB writes (e.g., 100 events per batch) and custom parsers for edge cases. | Batched writes reduce latency; custom parsers handle 95% of malformed events. |
| **FR-1.2.5** | Add event deduplication based on event_id or hash of raw_data. | Duplicate events are detected and not stored redundantly. |
| **FR-1.2.6** | Implement event buffering/queueing for high-throughput scenarios. | System buffers events during peak loads, processing them without loss. |
| **FR-1.2.7** | Use connection pooling for MongoDB with configurable max connections. | Pool reuses connections efficiently; no connection leaks under load. |

## **Phase 2: Head 2 - Detection & Alerting (The Sentinel)**

This phase implements the Rule Engine, which processes events in real-time immediately after normalization (pre-persistence) to look for threats.

### **2.1 Rule Engine Definition**

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-2.1.1** | Define a rule schema (e.g., YAML) that supports defining: Rule ID, Name, Description, Severity, and **Match Conditions**. | A rule file is successfully loaded at startup, and rule configuration errors are clearly reported. |
| **FR-2.1.2** | Match Conditions must support simple logical operators (AND, OR) and field comparisons (equals, contains, not equals, starts with) against the Common Event Schema's fields map. | The rule engine correctly evaluates a test rule like: (event\_type equals 'user\_login' AND fields.status equals 'failure') OR (fields.user contains 'admin'). |
| **FR-2.1.3** | Implement a real-time detection function that executes the Rule Engine against **every incoming normalized event**. | The execution time of the rule engine against a single event must be less than 5ms (P99 latency). |
| **FR-2.1.4** | Add rule versioning and correlation across events (e.g., multi-event rules for sequences). | Rules are versioned; correlated alerts trigger for event patterns within 10 minutes. |

### **2.2 Alert Generation**

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-2.2.1** | Upon a rule match, an **Alert Object** must be generated, linking back to the Rule ID and embedding the triggering Event Object. | A successful rule match creates a new object containing the rule details and the event data. |
| **FR-2.2.2** | The Alert Object must be stored in a separate MongoDB collection (alerts). | A test event matching a rule is successfully stored as an Alert in the alerts collection. |
| **FR-2.2.3** | The Alert Object must include fields for Status (New, In Progress, Closed) and an optional Jira\_Ticket\_ID. | The initial Alert Object is created with the Status set to New and Jira\_Ticket\_ID set to null/empty. |
| **FR-2.2.4** | Implement alert deduplication/throttling (e.g., suppress duplicates within 5 minutes). | Duplicate alerts are merged; no spam during high-volume events. |

## **Phase 3: Head 3 - Orchestration & Response (The Automator)**

This phase defines how Cerberus integrates with and controls external systems to automate security workflows (SOAR capabilities).

### **3.1 Webhook & External System Calling**

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-3.1.1** | Implement a **Response Action** schema in the rule definition that allows associating a rule match with an automation step (e.g., calling a Webhook). | The system successfully loads a rule that specifies a Webhook URL and the HTTP method (POST). |
| **FR-3.1.2** | Implement a Golang function to execute an HTTP POST request to a user-configured Webhook URL when an alert is triggered. | An alert correctly triggers an HTTP POST to a mock testing server (e.g., RequestBin), and the payload contains relevant Alert and Event details. |
| **FR-3.1.3** | Implement retry logic (e.g., exponential backoff) for failed webhook calls to ensure reliable communication. | A webhook configured to initially fail eventually succeeds after the defined retry interval and limit. |
| **FR-3.1.4** | Extend integrations to Slack notifications and email alerts with conditional logic. | Alerts trigger Slack messages/emails based on severity; conditions prevent false positives. |

### **3.2 Jira Ticketing Integration**

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-3.2.1** | Implement a configuration block for Jira connection details (API URL, Username/Token, Default Project Key). | The service successfully connects and authenticates with the Jira API at startup. |
| **FR-3.2.2** | Allow a rule's Response Action to automatically create a Jira ticket when an alert is generated. | A high-severity alert correctly creates a new issue in the configured Jira project, with the summary/description populated by the Alert details and the original raw log. |
| **FR-3.2.3** | Automatically update the corresponding Alert Object in MongoDB with the newly created Jira\_Ticket\_ID. | After ticket creation, the MongoDB alerts collection is updated with the Jira ID within 500ms. |
| **FR-3.2.4** | Add alert lifecycle management (e.g., auto-close alerts after Jira resolution). | Resolved Jira tickets update alert status to Closed in MongoDB. |

## **Phase 4: Non-Functional Requirements (NFR)**

This phase ensures the application is robust, performant, and maintainable.

### **4.1 Performance & Scalability**

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-4.1.1** | Utilize Golang Goroutines extensively across all listeners, the Rule Engine, and Webhook dispatching to ensure high concurrency. | System is capable of processing 5,000 events per second (EPS) on commodity hardware without dropping events. |
| **FR-4.1.2** | Implement connection pooling for the MongoDB client to efficiently manage database connections. | Monitoring confirms that MongoDB connections are reused efficiently under high load. |
| **FR-4.1.3** | Add monitoring/metrics integration (e.g., Prometheus) for EPS, latency, and error rates. | Metrics dashboard shows real-time performance; alerts trigger on thresholds. |

### **4.2 Security & Maintainability**

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-4.2.1** | Ensure all configuration secrets (DB credentials, Jira tokens) are loaded securely via environment variables or encrypted configuration files. | Secrets are not hardcoded in the source code. |
| **FR-4.2.2** | Implement comprehensive structured logging (e.g., using logr or zap) for all critical operations (startup, ingest failures, rule matches, webhook errors). | Logs contain structured key-value pairs ({"level": "info", "component": "ingest", "status": "success", "processed\_events": 100}). |
| **FR-4.2.3** | Establish unit tests for all core functions (ingestion parsers, rule engine logic, MongoDB connection). | All unit tests pass with a minimum of 80% code coverage. |
| **FR-4.2.4** | Implement disaster recovery (e.g., event replay from MongoDB) and compliance (e.g., GDPR data retention policies). | Events are replayable after outage; data is retained per policy without breaches. |

## **Phase 5: UI/Dashboard & Deployment**

### **5.1 User Interface**

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-5.1.1** | Develop a React-based dashboard for viewing alerts, events, and rules. | Dashboard loads alerts/events in <2s; supports filtering/search. |
| **FR-5.1.2** | Include real-time updates (e.g., WebSockets) and alert management (acknowledge/close). | Alerts update live; users can manage statuses via UI. |

### **5.2 Deployment & Testing**

**Functional Requirements (FR)**

| FR ID | Requirement | Acceptance Criteria (AC) |
| :---- | :---- | :---- |
| **FR-5.2.1** | Create deployment guides (Docker, Kubernetes) and end-to-end testing phases. | System deploys successfully; E2E tests cover full ingestion-to-response flow. |
| **FR-5.2.2** | Define timelines (e.g., 6 months total), risk assessments, and team roles. | Project completes on time; risks mitigated (e.g., MongoDB scaling). |
