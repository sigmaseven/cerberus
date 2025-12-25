Feature: Alert Lifecycle Management
  As an analyst
  I want to manage alerts through their lifecycle
  So that I can track and respond to security events

  @alert @lifecycle
  Scenario: Create new alert
    Given an alert exists with severity "high"
    When the analyst views the alert
    Then the alert status is "new"
    And the alert is visible in the alert list

  @alert @lifecycle
  Scenario: Assign alert to analyst
    Given an alert exists with severity "high"
    And an analyst user "analyst1" exists
    When the analyst assigns the alert to "analyst1"
    Then the alert status is "assigned"
    And the alert assignee is "analyst1"
    And an audit log entry is created

  @alert @lifecycle
  Scenario: Investigate alert
    Given an alert exists with severity "high"
    And the alert status is "assigned"
    When the analyst starts investigating the alert
    Then the alert status is "investigating"
    And the investigation timestamp is recorded

  @alert @lifecycle
  Scenario: Resolve alert
    Given an alert exists with severity "high"
    And the alert status is "investigating"
    When the analyst resolves the alert
    Then the alert status is "resolved"
    And the resolution timestamp is recorded

  @alert @lifecycle
  Scenario: Escalate alert
    Given an alert exists with severity "high"
    And the alert status is "investigating"
    When the analyst escalates the alert
    Then the alert status is "escalated"
    And the alert severity is increased

  @alert @lifecycle
  Scenario: Suppress alert
    Given an alert exists with severity "low"
    When the analyst suppresses the alert
    Then the alert status is "suppressed"
    And the alert is hidden from default views

  @alert @lifecycle
  Scenario: Bulk close alerts
    Given 5 alerts exist with status "resolved"
    When the analyst performs bulk close operation
    Then all 5 alerts status is "closed"
    And audit log entries are created for each alert

  @alert @lifecycle
  Scenario: Alert deduplication
    Given an alert exists with fingerprint "abc123"
    When a duplicate alert is created with fingerprint "abc123"
    Then the duplicate alert is merged
    And the original alert duplicate count is incremented

