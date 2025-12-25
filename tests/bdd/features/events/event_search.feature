Feature: Event Search and Query
  As an analyst
  I want to search events using CQL queries
  So that I can find relevant security events

  @search @cql
  Scenario: Search events by CQL query
    Given 100 events exist in the database
    When the analyst executes CQL query "src_ip = '192.168.1.100'"
    Then results are returned
    And the results match the query criteria
    And the results contain only matching events

  @search @cql
  Scenario: Search with time range
    Given events exist from the last 24 hours
    When the analyst searches with time range "last 1h"
    Then results contain only events from the last hour
    And the results are ordered by timestamp descending

  @search @cql
  Scenario: Search with pagination
    Given 1000 events exist in the database
    When the analyst searches with page size 50
    Then the first page contains 50 events
    When the analyst requests the next page
    Then the next page contains the next 50 events
    And no duplicate events are returned

  @search @cql
  Scenario: Save search query
    Given an analyst user "analyst1" exists
    When the analyst saves search query "src_ip = '192.168.1.100'" as "Suspicious IP"
    Then the saved search is created
    And the saved search can be retrieved by name
    And the saved search belongs to "analyst1"

  @search @cql
  Scenario: Export search results
    Given search results exist with 100 events
    When the analyst exports results as "CSV"
    Then a CSV file is generated
    And the file contains all result events
    And the file format is valid

  @search @cql
  Scenario: Invalid query handling
    When the analyst executes invalid CQL query "invalid syntax"
    Then an error is returned
    And the error message describes the syntax issue
    And no results are returned

