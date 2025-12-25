# Feature: Correlation Rule Evaluation
# Requirement: FR-CORR-001 - Count-Based Correlation
# Requirement: FR-CORR-002 - Value Count Correlation
# Requirement: FR-CORR-003 - Sequence Correlation
# Source: docs/requirements/correlation-rule-requirements.md
#
# The detection engine MUST support multiple correlation patterns including
# count-based, value count, and sequence correlation with proper state management.

@detection @critical @correlation
Feature: Correlation Rule Evaluation
  As a detection engineer
  I want to detect complex multi-event attack patterns
  So that advanced threats can be identified

  Background:
    Given the Cerberus detection engine is running
    And correlation state is initialized

  @count-based @brute-force
  Scenario: Count-based correlation detects brute force attack
    Given a count-based correlation rule:
      | field       | value                                   |
      | type        | count                                   |
      | window      | 5m                                      |
      | selection   | event_type: auth_failure, service: ssh  |
      | group_by    | source_ip                               |
      | threshold   | operator: >, value: 5                   |
    When I send 6 failed SSH login events from IP "192.168.1.100" within 5 minutes
    Then a correlation alert should be generated
    And the alert should contain all 6 correlated events
    And the alert correlation_type should be "count"
    And the alert group_key should be "source_ip=192.168.1.100"

  @count-based @no-match
  Scenario: Count threshold not exceeded does not generate alert
    Given a count-based correlation rule with threshold > 5 and window 5m
    When I send 4 matching events within 5 minutes
    Then no correlation alert should be generated
    And the correlation state should preserve the 4 events

  @count-based @time-window
  Scenario: Events outside time window are excluded from count
    Given a count-based correlation rule with threshold > 5 and window 5m
    When I send 6 events with the following timestamps:
      | event | timestamp_offset |
      | 1     | -7 minutes       |
      | 2     | -6 minutes       |
      | 3     | -3 minutes       |
      | 4     | -2 minutes       |
      | 5     | -1 minute        |
      | 6     | now              |
    Then only 4 events should be counted (events outside 5m window excluded)
    And no correlation alert should be generated

  @value-count @lateral-movement
  Scenario: Value count correlation detects lateral movement
    Given a value count correlation rule:
      | field        | value                        |
      | type         | value_count                  |
      | window       | 10m                          |
      | selection    | event_type: auth_success     |
      | count_field  | dest_hostname                |
      | group_by     | username                     |
      | threshold    | operator: >=, value: 10      |
    When I send 10 successful auth events for user "admin" to 10 distinct hosts within 10 minutes
    Then a correlation alert should be generated
    And the alert should list all 10 distinct hostnames
    And the alert correlation_type should be "value_count"

  @value-count @duplicate-values
  Scenario: Value count ignores duplicate values
    Given a value count correlation rule with count_field "username" and threshold > 5
    When I send 10 events with only 3 distinct usernames
    Then the distinct count should be 3
    And no correlation alert should be generated

  @sequence @ordered
  Scenario: Ordered sequence correlation detects multi-stage attack
    Given an ordered sequence correlation rule:
      | stage | selection                       | required |
      | sqli  | event_type: sql_injection       | true     |
      | rce   | event_type: command_execution   | true     |
      | exfil | event_type: data_exfiltration   | true     |
    And the sequence window is 1 hour
    And the sequence is ordered
    When I send events in order: sqli → rce → exfil within 1 hour
    And all events have the same source_ip
    Then a sequence correlation alert should be generated
    And the alert should contain all 3 sequence events

  @sequence @ordered @violation
  Scenario: Out-of-order sequence does not match ordered rule
    Given an ordered sequence correlation rule [A, B, C]
    When I send events in order: B → A → C
    Then no sequence correlation alert should be generated

  @sequence @unordered
  Scenario: Unordered sequence matches regardless of event order
    Given an unordered sequence correlation rule:
      | stage      | selection                      |
      | powershell | process: powershell.exe        |
      | network    | event_type: network_connection |
    And the sequence window is 5 minutes
    When I send events in order: network → powershell within 5 minutes
    Then a sequence correlation alert should be generated

  @sequence @max-span
  Scenario: Sequence max_span constraint is enforced
    Given a sequence correlation rule with max_span = 5 minutes
    When event A occurs at time T
    And event B occurs at time T+6 minutes
    Then no sequence alert should be generated
    And the max_span violation should be logged

  @rare-event
  Scenario: Rare event detection triggers on low frequency
    Given a rare event correlation rule:
      | field        | value                     |
      | type         | rare                      |
      | window       | 24h                       |
      | selection    | event_type: process_start |
      | count_field  | process_name              |
      | threshold    | operator: <=, value: 2    |
    When a process "malware.exe" is executed 2 times in 24 hours
    Then a rare event alert should be generated on the 2nd occurrence

  @rare-event @not-rare
  Scenario: Frequent events do not trigger rare detection
    Given a rare event correlation rule with threshold <= 2
    When a process "chrome.exe" is executed 10 times in 24 hours
    Then no rare event alert should be generated after the 3rd occurrence

  @state-management @memory-limit
  Scenario: Correlation state enforces memory limit
    Given a correlation rule with max events per window = 10000
    When I send 10001 matching events
    Then the oldest event should be evicted
    And the correlation state should contain exactly 10000 events
    And an eviction warning should be logged

  @state-management @cleanup
  Scenario: Expired correlation state is cleaned up
    Given a correlation rule with window = 5 minutes
    And correlation state contains events from 10 minutes ago
    When the state cleanup runs
    Then expired events should be removed from memory
    And cleanup statistics should be logged

  @group-by @multiple-fields
  Scenario: Correlation groups by multiple fields
    Given a correlation rule with group_by ["source_ip", "username"]
    When I send events from IP "1.2.3.4" with username "admin"
    And I send events from IP "1.2.3.4" with username "user"
    Then two separate correlation state buckets should exist
    And each bucket should track events independently

  @alert-context
  Scenario: Correlation alert includes comprehensive context
    Given a count-based correlation rule
    When a correlation threshold is exceeded
    Then the generated alert should include:
      | field                | description                        |
      | correlation_type     | Type of correlation (count)        |
      | group_key            | Entity grouping key                |
      | correlated_events    | Array of all matching events       |
      | first_event_time     | Timestamp of first event           |
      | last_event_time      | Timestamp of triggering event      |
      | threshold            | Threshold configuration            |
      | window               | Time window configuration          |
