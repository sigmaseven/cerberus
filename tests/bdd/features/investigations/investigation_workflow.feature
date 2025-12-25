Feature: Investigation Workflow Management
  As an analyst
  I want to manage investigations and link evidence
  So that I can track security incidents comprehensively

  @investigation @workflow
  Scenario: Create investigation
    Given an analyst user "analyst1" exists
    When the analyst creates an investigation with title "Suspicious Activity"
    Then an investigation is created with status "open"
    And the investigation title is "Suspicious Activity"
    And the investigation created_by is "analyst1"

  @investigation @workflow
  Scenario: Link alerts to investigation
    Given an investigation exists with status "open"
    And an alert exists with severity "high"
    When the analyst links the alert to the investigation
    Then the alert is linked to the investigation
    And the investigation alert count is incremented
    And the timeline entry is created

  @investigation @workflow
  Scenario: Add evidence to investigation
    Given an investigation exists with status "open"
    When the analyst adds evidence "suspicious_file.txt" to the investigation
    Then the evidence is linked to the investigation
    And the investigation evidence count is incremented
    And the timeline entry is created

  @investigation @workflow
  Scenario: Investigation timeline
    Given an investigation exists
    And 3 timeline events exist for the investigation
    When the analyst views the investigation timeline
    Then the timeline contains 3 events
    And the events are ordered chronologically

  @investigation @workflow
  Scenario: Close investigation
    Given an investigation exists with status "open"
    And the investigation has linked alerts
    When the analyst closes the investigation
    Then the investigation status is "closed"
    And the closure timestamp is recorded
    And the closure reason is recorded

  @investigation @workflow
  Scenario: Investigation collaboration
    Given an investigation exists
    And analyst users "analyst1" and "analyst2" exist
    When "analyst1" adds a note to the investigation
    And "analyst2" views the investigation
    Then both analysts can see all notes
    And the timeline shows contributions from both analysts

