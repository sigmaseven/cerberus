# Feature: Rule Management API
# Requirement: API-001 through API-013 - API Contracts
# Source: docs/requirements/api-design-requirements.md
#
# The API MUST provide complete CRUD operations for detection rules with
# proper validation, error handling, and response formats.

@api @critical @rules
Feature: Rule Management API
  As a detection engineer
  I want to manage detection rules via API
  So that I can automate rule deployment and updates

  Background:
    Given the Cerberus API is running
    And I am authenticated as an admin user

  @happy-path @create
  Scenario: Create a new detection rule
    When I POST to "/api/v1/rules" with:
      """json
      {
        "id": "test-rule-001",
        "name": "Test Rule",
        "description": "Test detection rule",
        "severity": "High",
        "enabled": true,
        "detection": {
          "selection": {
            "EventID": 4625
          }
        }
      }
      """
    Then the response status should be 201 Created
    And the response should contain the created rule with id "test-rule-001"
    And the Location header should be "/api/v1/rules/test-rule-001"
    And the rule should exist in the database

  @validation @create
  Scenario: Create rule fails with missing required fields
    When I POST to "/api/v1/rules" with:
      """json
      {
        "name": "Incomplete Rule"
      }
      """
    Then the response status should be 400 Bad Request
    And the error message should indicate missing required field "id"

  @validation @create
  Scenario: Create rule fails with invalid severity
    When I POST to "/api/v1/rules" with:
      """json
      {
        "id": "rule-002",
        "name": "Bad Severity Rule",
        "severity": "InvalidSeverity"
      }
      """
    Then the response status should be 400 Bad Request
    And the error message should indicate invalid severity value
    And valid severity values should be listed: Low, Medium, High, Critical

  @happy-path @read
  Scenario: Get rule by ID
    Given a rule exists with id "existing-rule-001"
    When I GET "/api/v1/rules/existing-rule-001"
    Then the response status should be 200 OK
    And the response should contain the rule details
    And the rule id should be "existing-rule-001"

  @error-handling @read
  Scenario: Get non-existent rule returns 404
    When I GET "/api/v1/rules/nonexistent-rule"
    Then the response status should be 404 Not Found
    And the error message should indicate "rule not found"

  @happy-path @list
  Scenario: List all rules with pagination
    Given 25 rules exist in the database
    When I GET "/api/v1/rules?limit=10&offset=0"
    Then the response status should be 200 OK
    And the response should contain 10 rules
    And the response should include pagination metadata:
      | field  | value |
      | total  | 25    |
      | limit  | 10    |
      | offset | 0     |

  @filtering @list
  Scenario: Filter rules by severity
    Given rules exist with various severities
    When I GET "/api/v1/rules?severity=Critical"
    Then the response status should be 200 OK
    And all returned rules should have severity "Critical"

  @filtering @list
  Scenario: Filter rules by enabled status
    Given 10 enabled rules and 5 disabled rules exist
    When I GET "/api/v1/rules?enabled=true"
    Then the response status should be 200 OK
    And all returned rules should have enabled = true
    And the count should be 10

  @happy-path @update
  Scenario: Update existing rule
    Given a rule exists with id "rule-to-update"
    When I PUT "/api/v1/rules/rule-to-update" with:
      """json
      {
        "name": "Updated Rule Name",
        "severity": "Critical",
        "enabled": false
      }
      """
    Then the response status should be 200 OK
    And the rule name should be updated to "Updated Rule Name"
    And the rule severity should be updated to "Critical"
    And the rule enabled status should be false

  @validation @update
  Scenario: Update rule fails with invalid data
    Given a rule exists with id "rule-001"
    When I PUT "/api/v1/rules/rule-001" with invalid detection syntax
    Then the response status should be 400 Bad Request
    And the error message should indicate the validation failure
    And the original rule should remain unchanged

  @happy-path @delete
  Scenario: Delete existing rule
    Given a rule exists with id "rule-to-delete"
    When I DELETE "/api/v1/rules/rule-to-delete"
    Then the response status should be 200 OK
    And the rule should no longer exist in the database
    When I GET "/api/v1/rules/rule-to-delete"
    Then the response status should be 404 Not Found

  @error-handling @delete
  Scenario: Delete non-existent rule returns 404
    When I DELETE "/api/v1/rules/nonexistent-rule"
    Then the response status should be 404 Not Found

  @referential-integrity @delete
  Scenario: Cannot delete rule with active alerts
    Given a rule exists with id "rule-with-alerts"
    And 5 active alerts reference this rule
    When I DELETE "/api/v1/rules/rule-with-alerts"
    Then the response status should be 409 Conflict
    And the error message should indicate "rule has active alerts"
    And the rule should still exist

  @validation @id-format
  Scenario Outline: Rule ID validation
    When I POST to "/api/v1/rules" with id "<rule_id>"
    Then the response status should be <status>
    And the validation should <result>

    Examples:
      | rule_id                    | status | result                            |
      | valid-rule-123             | 201    | succeed                           |
      | rule_with_underscores      | 201    | succeed                           |
      | "invalid id with spaces"   | 400    | fail with invalid characters      |
      | rule-with-ñ-unicode        | 400    | fail with non-ASCII               |
      | a                          | 400    | fail with too short (min 3 chars) |
      | [65 character string]      | 400    | fail with too long (max 64 chars) |

  @content-negotiation
  Scenario: API supports JSON content type
    When I POST to "/api/v1/rules" with Content-Type "application/json"
    Then the request should be processed
    When I POST to "/api/v1/rules" with Content-Type "text/plain"
    Then the response status should be 415 Unsupported Media Type

  @performance
  Scenario: List rules completes within performance SLA
    Given 1000 rules exist in the database
    When I GET "/api/v1/rules?limit=100"
    Then the response should be returned within 200 milliseconds
    And the response status should be 200 OK
