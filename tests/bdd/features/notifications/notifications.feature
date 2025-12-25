Feature: Notification Delivery
  As the system
  I want to send notifications when alerts are triggered
  So that analysts are informed of security events

  @notification @email
  Scenario: Send email notification
    Given an alert exists with severity "high"
    And email notification channel is configured
    When the alert triggers notification
    Then an email notification is sent
    And the notification contains alert details
    And the delivery status is recorded

  @notification @webhook
  Scenario: Send webhook notification
    Given an alert exists with severity "high"
    And webhook notification channel is configured
    When the alert triggers notification
    Then a webhook notification is sent
    And the webhook receives the alert payload
    And the delivery status is recorded

  @notification @slack
  Scenario: Send Slack notification
    Given an alert exists with severity "high"
    And Slack notification channel is configured
    When the alert triggers notification
    Then a Slack notification is sent
    And the Slack message contains alert details
    And the delivery status is recorded

  @notification @rate-limiting
  Scenario: Notification rate limiting
    Given 100 alerts exist
    And notification rate limit is 10 per minute
    When all alerts trigger notifications simultaneously
    Then only 10 notifications are sent immediately
    And remaining notifications are queued
    And queued notifications are sent when rate limit resets

  @notification @failure-handling
  Scenario: Notification failure handling
    Given an alert exists with severity "high"
    And notification channel is misconfigured
    When the alert triggers notification
    Then notification delivery fails
    And a retry is attempted after backoff delay
    And failure is logged for review

