# Feature: Event Ingestion Throughput
# Requirement: FR-ING-008 - High-Throughput Ingestion
# Requirement: NFR-ING-001 - Ingestion Throughput
# Source: docs/requirements/data-ingestion-requirements.md
# Source: docs/requirements/performance-requirements.md
#
# The ingestion pipeline MUST sustain 10,000 events per second with
# sub-second latency and zero data loss under normal conditions.

@performance @critical @ingestion @throughput
Feature: Event Ingestion Throughput
  As a SIEM operator
  I want high-throughput event ingestion
  So that all security events are captured without data loss

  Background:
    Given the Cerberus ingestion service is running
    And the storage backend is ready
    And ingestion metrics are being collected

  @happy-path @sustained-load
  Scenario: Sustained 10,000 EPS for 10 minutes
    Given the ingestion service is idle
    When I send 10,000 events per second for 10 minutes
    Then all 6,000,000 events should be ingested
    And the data loss rate should be 0%
    And the p95 latency should be less than 500 milliseconds
    And the p99 latency should be less than 2 seconds

  @burst-load
  Scenario: Burst load of 50,000 EPS for 60 seconds
    Given the ingestion service is idle
    When I send 50,000 events per second for 60 seconds
    Then all 3,000,000 events should be buffered
    And the events should be processed successfully
    And the system should recover to normal state within 2 minutes
    And no events should be dropped

  @backpressure
  Scenario: Backpressure when event buffer is full
    Given the event buffer capacity is 10,000 events
    And the storage backend is slow
    When I send events faster than they can be processed
    Then the event buffer should fill up
    And ingestion should slow down gracefully
    And HTTP clients should receive 503 Service Unavailable
    And TCP clients should experience backpressure
    And no events should be lost

  @protocol-throughput @syslog
  Scenario: Syslog ingestion meets throughput target
    Given the Syslog listener is active on port 514
    When I send 10,000 Syslog messages per second via UDP
    Then all messages should be parsed successfully
    And the parse error rate should be less than 0.1%
    And the ingestion latency should be less than 100ms (p95)

  @protocol-throughput @json
  Scenario: JSON HTTP ingestion meets throughput target
    Given the JSON HTTP endpoint is active
    When I POST 1,000 JSON events per second to "/api/v1/ingest/json"
    Then all events should be accepted (202 Accepted)
    And the HTTP response time should be less than 50ms (p95)
    And all events should be persisted to storage

  @protocol-throughput @cef
  Scenario: CEF ingestion meets throughput target
    Given the CEF listener is active on port 514
    When I send 10,000 CEF messages per second via TCP
    Then all messages should be parsed correctly
    And CEF extension fields should be extracted
    And the throughput should be sustained without packet loss

  @latency @end-to-end
  Scenario: End-to-end ingestion latency meets SLA
    When I send an event to the ingestion pipeline
    Then the event should be available for search within 500ms (p95)
    And the latency should be measured from receipt to queryable

  @resource-utilization
  Scenario: CPU utilization under normal load
    When ingesting 10,000 events per second
    Then the CPU utilization should not exceed 80%
    And CPU spikes should be temporary
    And the system should remain responsive

  @resource-utilization
  Scenario: Memory utilization under load
    When ingesting 50,000 events per second for 5 minutes
    Then the memory usage should not exceed 200 MB for ingestion buffers
    And memory should not grow unbounded
    And no memory leaks should occur

  @connection-management
  Scenario: Connection pool limits prevent resource exhaustion
    Given the TCP connection limit is 1,000
    When 1,100 clients attempt to connect simultaneously
    Then the first 1,000 connections should be accepted
    And 100 connections should be rejected
    And rejected connections should be logged
    And existing connections should not be affected

  @per-ip-limit
  Scenario: Per-IP connection limit prevents single source from exhausting pool
    Given the per-IP connection limit is 10
    When a single IP attempts 15 concurrent TCP connections
    Then the first 10 connections should be accepted
    And 5 connections should be rejected
    And other IPs should still be able to connect

  @rate-limiting
  Scenario: Rate limiting prevents ingestion overload
    Given the rate limit is 1,000 events per second per listener
    When I send 2,000 events per second to a single listener
    Then 1,000 events per second should be accepted
    And excess events should be dropped
    And a rate limit exceeded metric should be incremented
    And a warning should be logged

  @field-normalization @performance
  Scenario: Field normalization does not impact throughput
    Given field normalization is enabled
    When I send 10,000 events per second with various source formats
    Then all events should be normalized to SIGMA taxonomy
    And the throughput should not degrade below 10,000 EPS
    And the normalization latency should be less than 10ms per event

  @malformed-events
  Scenario: Malformed events do not impact throughput
    When I send a mix of 90% valid and 10% malformed events at 10,000 EPS
    Then valid events should be ingested successfully
    And malformed events should be logged
    And malformed events should be sent to dead-letter queue
    And the valid event throughput should remain 9,000 EPS

  @graceful-degradation
  Scenario: Graceful degradation under overload
    When the system is at 120% capacity
    Then low-priority events should be queued or dropped
    And high-priority events should be processed first
    And the system should not crash
    And metrics should reflect the degraded state
