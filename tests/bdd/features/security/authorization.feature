# Feature: Role-Based Access Control (RBAC)
# Requirement: SEC-002 - Authorization
# Source: docs/requirements/security-threat-model.md
# Source: docs/requirements/user-management-authentication-requirements.md
#
# The system MUST enforce role-based access control to ensure users can only
# perform actions authorized by their assigned roles.

@security @critical @authorization @rbac
Feature: Role-Based Access Control
  As a security administrator
  I want to control user access based on roles
  So that users can only perform authorized actions

  Background:
    Given the Cerberus API is running
    And the database is initialized
    And the following roles exist:
      | role       | permissions                                    |
      | admin      | read_rules, write_rules, delete_rules, manage_users |
      | analyst    | read_rules, read_alerts, read_events          |
      | viewer     | read_rules, read_alerts                        |
    And the following users exist:
      | username | role    | password       |
      | admin1   | admin   | AdminPass123!  |
      | analyst1 | analyst | AnalystPass123! |
      | viewer1  | viewer  | ViewerPass123!  |

  @happy-path
  Scenario: Admin can create rules
    Given I am logged in as "admin1"
    When I attempt to create a rule via POST "/api/v1/rules"
    Then the request should succeed
    And I should receive a "201 Created" response
    And the rule should be created in the database

  @authorization-check
  Scenario: Analyst cannot create rules
    Given I am logged in as "analyst1"
    When I attempt to create a rule via POST "/api/v1/rules"
    Then the request should fail
    And I should receive a "403 Forbidden" response
    And the error message should indicate insufficient permissions

  @authorization-check
  Scenario: Viewer cannot create rules
    Given I am logged in as "viewer1"
    When I attempt to create a rule via POST "/api/v1/rules"
    Then the request should fail
    And I should receive a "403 Forbidden" response

  @authorization-check
  Scenario: Admin can delete rules
    Given I am logged in as "admin1"
    And a rule exists with id "test-rule-1"
    When I attempt to delete the rule via DELETE "/api/v1/rules/test-rule-1"
    Then the request should succeed
    And I should receive a "200 OK" response
    And the rule should be deleted from the database

  @authorization-check
  Scenario: Analyst cannot delete rules
    Given I am logged in as "analyst1"
    And a rule exists with id "test-rule-1"
    When I attempt to delete the rule via DELETE "/api/v1/rules/test-rule-1"
    Then the request should fail
    And I should receive a "403 Forbidden" response
    And the rule should still exist in the database

  @authorization-check
  Scenario: Analyst can read rules
    Given I am logged in as "analyst1"
    And a rule exists with id "test-rule-1"
    When I attempt to read the rule via GET "/api/v1/rules/test-rule-1"
    Then the request should succeed
    And I should receive a "200 OK" response
    And the rule details should be returned

  @authorization-check
  Scenario: Viewer can read rules
    Given I am logged in as "viewer1"
    And a rule exists with id "test-rule-1"
    When I attempt to read the rule via GET "/api/v1/rules/test-rule-1"
    Then the request should succeed
    And I should receive a "200 OK" response

  @authorization-check
  Scenario: Admin can manage users
    Given I am logged in as "admin1"
    When I attempt to create a user via POST "/api/v1/users"
    Then the request should succeed
    And I should receive a "201 Created" response

  @authorization-check
  Scenario: Analyst cannot manage users
    Given I am logged in as "analyst1"
    When I attempt to create a user via POST "/api/v1/users"
    Then the request should fail
    And I should receive a "403 Forbidden" response

  @authorization-check
  Scenario: Unauthenticated requests are rejected
    When I attempt to access "/api/v1/rules" without authentication
    Then the request should fail
    And I should receive a "401 Unauthorized" response

  @authorization-check @privilege-escalation
  Scenario: User cannot escalate their own privileges
    Given I am logged in as "analyst1"
    And my user ID is "analyst1-id"
    When I attempt to update my role to "admin" via PUT "/api/v1/users/analyst1-id"
    Then the request should fail
    And I should receive a "403 Forbidden" response
    And my role should remain "analyst"

  @authorization-check @horizontal-access
  Scenario: User cannot access another user's private data
    Given I am logged in as "analyst1"
    And a user "analyst2" exists with private API key
    When I attempt to read analyst2's API key via GET "/api/v1/users/analyst2-id/api-key"
    Then the request should fail
    And I should receive a "403 Forbidden" response
