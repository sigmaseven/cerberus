# Feature: User Authentication
# Requirement: SEC-001 - Authentication
# Source: docs/requirements/user-management-authentication-requirements.md
# Source: docs/requirements/security-threat-model.md
#
# The system MUST implement secure JWT-based authentication with proper
# password hashing, session management, and brute force protection.

@security @critical @authentication
Feature: User Authentication
  As a security-conscious organization
  I want secure user authentication
  So that only authorized users can access the SIEM system

  Background:
    Given the Cerberus API is running
    And the database is initialized

  @happy-path
  Scenario: Successful login with valid credentials
    Given a user exists with username "analyst1" and password "SecurePass123!"
    When I attempt to login with username "analyst1" and password "SecurePass123!"
    Then the login should succeed
    And I should receive a valid JWT token
    And the JWT token should contain the user ID
    And the JWT token should have an expiration time

  @security @password-validation
  Scenario: Login fails with incorrect password
    Given a user exists with username "analyst1" and password "SecurePass123!"
    When I attempt to login with username "analyst1" and password "WrongPassword"
    Then the login should fail
    And I should receive a "401 Unauthorized" response
    And no JWT token should be returned
    And the error message should not reveal that the username exists

  @security @user-validation
  Scenario: Login fails with non-existent user
    When I attempt to login with username "nonexistent" and password "AnyPassword123!"
    Then the login should fail
    And I should receive a "401 Unauthorized" response
    And the error message should be identical to wrong password error

  @security @brute-force-protection
  Scenario: Account lockout after multiple failed login attempts
    Given a user exists with username "analyst1" and password "SecurePass123!"
    When I attempt to login 5 times with username "analyst1" and incorrect passwords
    Then all 5 login attempts should fail
    When I attempt to login again with username "analyst1" and password "SecurePass123!"
    Then the login should fail with "account locked" error
    And the account should be locked for at least 15 minutes

  @security @brute-force-protection
  Scenario: Account lockout resets after successful login
    Given a user exists with username "analyst1" and password "SecurePass123!"
    And the user has 3 failed login attempts
    When I attempt to login with username "analyst1" and password "SecurePass123!"
    Then the login should succeed
    And the failed login counter should be reset to 0

  @security @jwt-validation
  Scenario: Valid JWT token grants access to protected endpoints
    Given I am logged in as user "analyst1"
    When I access a protected endpoint "/api/v1/rules" with my JWT token
    Then the request should succeed
    And I should receive a "200 OK" response

  @security @jwt-validation
  Scenario: Invalid JWT token is rejected
    When I access a protected endpoint "/api/v1/rules" with an invalid JWT token
    Then the request should fail
    And I should receive a "401 Unauthorized" response

  @security @jwt-validation
  Scenario: Expired JWT token is rejected
    Given I have an expired JWT token
    When I access a protected endpoint "/api/v1/rules" with the expired token
    Then the request should fail
    And I should receive a "401 Unauthorized" response
    And the error message should indicate the token has expired

  @security @jwt-validation
  Scenario: Tampered JWT token is rejected
    Given I am logged in as user "analyst1"
    When I modify the JWT token payload to claim admin role
    And I access a protected endpoint "/api/v1/rules" with the tampered token
    Then the request should fail
    And I should receive a "401 Unauthorized" response

  @security @session-management
  Scenario: Logout invalidates JWT token
    Given I am logged in as user "analyst1"
    When I logout
    And I attempt to use the same JWT token to access "/api/v1/rules"
    Then the request should fail
    And I should receive a "401 Unauthorized" response

  @security @password-complexity
  Scenario Outline: Password complexity requirements are enforced
    When I attempt to create a user with password "<password>"
    Then the creation should <result>
    And the error message should indicate "<reason>"

    Examples:
      | password      | result | reason                     |
      | Short1!       | fail   | minimum 12 characters      |
      | nouppercase1! | fail   | requires uppercase letter  |
      | NOLOWERCASE1! | fail   | requires lowercase letter  |
      | NoNumbers!    | fail   | requires numeric digit     |
      | NoSpecials123 | fail   | requires special character |
      | SecurePass123! | succeed | meets all requirements    |

  @security @timing-attack
  Scenario: Login timing is constant for valid and invalid users
    When I measure login time for 100 attempts with invalid users
    And I measure login time for 100 attempts with valid users but wrong passwords
    Then the average time difference should be less than 10 milliseconds
