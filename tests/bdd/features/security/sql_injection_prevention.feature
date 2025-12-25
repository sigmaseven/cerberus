# Feature: SQL Injection Prevention
# Requirement: SEC-003 - SQL Injection Prevention
# Source: docs/requirements/security-threat-model.md
#
# All database queries MUST use parameterized queries to prevent SQL injection.
# This feature tests that various SQL injection attack vectors are prevented.

@security @critical @sql-injection
Feature: SQL Injection Prevention
  As a security engineer
  I want all database queries to use parameterized statements
  So that SQL injection attacks are prevented

  Background:
    Given the Cerberus API is running
    And the database is initialized
    And I am authenticated as an admin user

  @happy-path
  Scenario: Normal search query with special characters
    Given a rule exists with name "Test Rule (Special)"
    When I search for rules with query "Test Rule (Special)"
    Then the search should succeed
    And the rule "Test Rule (Special)" should be in the results

  @attack-vector @union-injection
  Scenario: UNION-based SQL injection attempt is blocked
    Given a rule exists with id "legitimate-rule"
    When I search for rules with query "' UNION SELECT username, password FROM users --"
    Then the search should succeed
    And no user data should be in the results
    And only valid rule data should be returned

  @attack-vector @time-based-injection
  Scenario: Time-based blind SQL injection is prevented
    When I search for rules with query "'; SELECT SLEEP(5) --"
    Then the search should complete in under 1 second
    And no database timeout should occur

  @attack-vector @error-based-injection
  Scenario: Error-based SQL injection is prevented
    When I search for rules with query "' AND 1=CONVERT(int, (SELECT @@version)) --"
    Then the search should succeed
    And no database error should be exposed in the response

  @attack-vector @encoding-bypass
  Scenario Outline: Encoding-based SQL injection bypasses are prevented
    When I search for rules with query "<attack_payload>"
    Then the search should succeed
    And the attack should not execute

    Examples:
      | attack_payload                |
      | %27 OR 1=1--                 |
      | \\x27 OR 1=1--               |
      | ' OR '1'='1                  |
      | '; DROP TABLE rules; --      |
      | ' OR 1=1 UNION SELECT * FROM users-- |

  @code-inspection
  Scenario: Database queries use parameterized statements
    When I inspect the storage layer source code
    Then all SQL queries should use parameterized statements
    And no string concatenation should be used in queries
    And no fmt.Sprintf should be used for query building

  @attack-vector @second-order-injection
  Scenario: Second-order SQL injection is prevented
    Given I create a rule with name "admin'; DROP TABLE rules; --"
    When I search for rules with name "admin'; DROP TABLE rules; --"
    Then the search should succeed
    And the rule name should be stored exactly as provided
    And the rules table should still exist

  @attack-vector @boolean-injection
  Scenario: Boolean-based blind SQL injection is prevented
    When I search for rules with query "' OR '1'='1"
    Then the search should succeed
    And only rules matching the actual query should be returned
    And authentication should not be bypassed
