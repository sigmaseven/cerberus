# Cerberus SIEM End-to-End Functional QA Testing Plan

## 1. Introduction

### 1.1 Purpose
This document outlines a comprehensive functional QA testing plan for end-to-end (E2E) testing of the Cerberus SIEM system. The plan ensures that all critical user workflows are validated, from event ingestion to alert response, across the backend API, detection engine, and frontend UI.

### 1.2 Scope
- **In Scope**: Functional E2E testing of core features including event ingestion, rule-based detection, alert generation, orchestration actions, data management, and UI interactions.
- **Out of Scope**: Unit testing, performance/load testing (separate plan), security penetration testing, third-party integrations (e.g., Jira, Slack) unless mocked.

### 1.3 Objectives
- Validate complete user journeys from event ingestion to alert resolution.
- Ensure data integrity across ingestion, processing, storage, and UI display.
- Verify rule matching, correlation, and action execution.
- Confirm system reliability under normal operations.

## 2. Test Environment

### 2.1 Setup Requirements
- **Hardware/Software**:
  - Docker and Docker Compose for containerized deployment.
  - MongoDB instance (via Docker Compose).
  - Node.js for frontend testing.
  - Go environment for backend if needed.
- **Test Data**:
  - Sample event logs in Syslog, CEF, and JSON formats.
  - Pre-configured rules.json and correlation_rules.json.
  - Mock webhooks for action testing.
- **Tools**:
  - Postman or curl for API testing.
  - Browser (Chrome/Firefox) for UI testing.
  - Syslog/CEF generators (e.g., logger command, custom scripts).
  - Test management tool (e.g., TestRail, Jira) for tracking.

### 2.2 Environment Configuration
- Deploy Cerberus using `docker-compose.yml`.
- Configure listeners: Syslog (UDP 514), CEF (TCP 515), JSON (HTTP 8080).
- Enable MongoDB storage.
- Load sample rules and correlation rules.
- Access UI at http://localhost:8081.

## 3. Test Data Preparation

### 3.1 Event Samples
- **Syslog Events**: Failed login attempts, successful logins, admin access.
- **CEF Events**: Security events like firewall blocks, malware detections.
- **JSON Events**: Custom structured events for rule testing.
- **Volume**: 100-500 events per test cycle, including duplicates for deduplication testing.

### 3.2 Rules and Configurations
- Detection rules for common scenarios (e.g., failed logins, admin access).
- Correlation rules for multi-event patterns (e.g., brute force attacks).
- Action configurations: Webhook URLs pointing to mock servers.

## 4. Test Scenarios and Cases

### 4.1 High-Level Scenarios
1. **Event Ingestion and Processing**
2. **Rule-Based Alert Generation**
3. **Correlation Alert Generation**
4. **Alert Management via UI**
5. **Action Execution**
6. **Data Retention and Cleanup**
7. **System Health and Monitoring**

### 4.2 Detailed Test Cases

#### Scenario 1: Event Ingestion and Processing
- **TC1.1**: Ingest Syslog events via UDP. Verify events appear in UI and API.
- **TC1.2**: Ingest CEF events via TCP. Check parsing and storage.
- **TC1.3**: Ingest JSON events via HTTP POST. Validate fields and deduplication.
- **TC1.4**: Test rate limiting (send >1000 EPS). Ensure graceful handling.
- **TC1.5**: Send malformed events. Verify error handling and dead-letter queue.

#### Scenario 2: Rule-Based Alert Generation
- **TC2.1**: Trigger single-event rule (e.g., failed login). Verify alert creation.
- **TC2.2**: Test rule conditions with AND/OR logic.
- **TC2.3**: Disable/enable rules. Confirm no alerts when disabled.
- **TC2.4**: Update rule via API/UI. Verify changes take effect without restart.

#### Scenario 3: Correlation Alert Generation
- **TC3.1**: Send sequence of events matching correlation rule. Verify alert.
- **TC3.2**: Test time window constraints (events outside window should not trigger).
- **TC3.3**: Partial sequence matching. Ensure no false positives.

#### Scenario 4: Alert Management via UI
- **TC4.1**: View alerts list. Check sorting, filtering by severity/status.
- **TC4.2**: Acknowledge alert. Verify status update in UI and API.
- **TC4.3**: Dismiss alert. Confirm removal or archiving.
- **TC4.4**: Auto-refresh UI. Ensure real-time updates.

#### Scenario 5: Action Execution
- **TC5.1**: Trigger rule with webhook action. Verify HTTP POST to configured URL.
- **TC5.2**: Test action failure (invalid URL). Check retry logic and logging.
- **TC5.3**: Multiple actions per rule. Ensure all execute asynchronously.

#### Scenario 6: Data Retention and Cleanup
- **TC6.1**: Configure retention (e.g., 1 day). Verify old events/alerts are cleaned up.
- **TC6.2**: Test event replay for disaster recovery.

#### Scenario 7: System Health and Monitoring
- **TC7.1**: Check /health endpoint. Verify system status.
- **TC7.2**: Access /metrics. Confirm Prometheus metrics exposure.
- **TC7.3**: Simulate DB disconnection. Ensure graceful degradation to in-memory mode.

### 4.3 Edge Cases and Negative Testing
- Invalid configurations (e.g., bad JSON in rules).
- Network interruptions during ingestion.
- Concurrent rule updates and event processing.
- Large event payloads.

## 5. Execution Strategy

### 5.1 Test Execution Phases
1. **Setup Phase**: Deploy environment, load test data.
2. **Smoke Testing**: Basic ingestion and UI access.
3. **Regression Testing**: Full E2E cycles.
4. **Exploratory Testing**: Unscripted scenarios for usability.

### 5.2 Roles and Responsibilities
- **QA Testers**: Execute test cases, log defects.
- **Developers**: Provide environment support, fix issues.
- **Product Owner**: Validate business logic.

### 5.3 Entry/Exit Criteria
- **Entry**: Environment stable, test data ready.
- **Exit**: All critical test cases pass, no open blockers.

## 6. Defect Management
- Use Jira/TestRail for tracking.
- Severity levels: Critical (system down), High (major feature broken), Medium (minor issues), Low (cosmetic).
- Re-test after fixes.

## 7. Reporting
- Daily status reports: Pass/fail rates, open defects.
- Final report: Test summary, coverage, recommendations.

## 8. Risks and Mitigations
- **Risk**: Environment instability. Mitigation: Use Docker for consistency.
- **Risk**: Data dependencies. Mitigation: Scripted data setup.
- **Risk**: Time constraints. Mitigation: Prioritize critical paths.

## 9. Appendices
- Test Case Templates
- Sample Test Data
- Environment Setup Scripts