# Feature: ACID Transaction Guarantees
# Requirement: DATA-001 - ACID Transactions
# Source: docs/requirements/storage-acid-requirements.md
#
# The storage layer MUST provide ACID (Atomicity, Consistency, Isolation, Durability)
# guarantees for critical operations to ensure data integrity.

@data @critical @acid @transactions
Feature: ACID Transaction Guarantees
  As a database administrator
  I want ACID transaction guarantees
  So that data integrity is maintained even under failure conditions

  Background:
    Given the Cerberus storage layer is initialized
    And the database is empty

  @atomicity
  Scenario: Transaction atomicity - all or nothing rule creation
    Given I start a transaction
    When I create a rule with id "rule-1" in the transaction
    And I create a rule with id "rule-2" in the transaction
    And I create a rule with invalid data causing an error
    And I rollback the transaction
    Then no rules should exist in the database
    And rule "rule-1" should not exist
    And rule "rule-2" should not exist

  @atomicity
  Scenario: Successful transaction commits all changes
    Given I start a transaction
    When I create a rule with id "rule-1" in the transaction
    And I create a rule with id "rule-2" in the transaction
    And I commit the transaction
    Then both rules should exist in the database
    And rule "rule-1" should be retrievable
    And rule "rule-2" should be retrievable

  @consistency
  Scenario: Foreign key constraints maintain consistency
    Given a rule with id "parent-rule" exists
    When I create an alert referencing rule id "parent-rule"
    Then the alert should be created successfully
    When I attempt to delete the rule "parent-rule"
    Then the deletion should fail with a foreign key constraint error
    And the rule "parent-rule" should still exist
    And the alert should still exist

  @consistency
  Scenario: Unique constraint prevents duplicate rule IDs
    Given a rule exists with id "unique-rule"
    When I attempt to create another rule with id "unique-rule"
    Then the creation should fail with a unique constraint violation
    And only one rule with id "unique-rule" should exist

  @isolation @dirty-read
  Scenario: Read committed isolation prevents dirty reads
    Given I start transaction T1
    And I create a rule with id "test-rule" in transaction T1
    When I query for rule "test-rule" in a separate transaction T2
    Then transaction T2 should not see the uncommitted rule
    When I commit transaction T1
    And I query for rule "test-rule" in transaction T2
    Then transaction T2 should now see the committed rule

  @isolation @non-repeatable-read
  Scenario: Repeatable read isolation prevents non-repeatable reads
    Given a rule exists with id "rule-1" and name "Original Name"
    And I start transaction T1 with repeatable read isolation
    And I read rule "rule-1" in transaction T1
    When another transaction T2 updates rule "rule-1" name to "Modified Name"
    And I read rule "rule-1" again in transaction T1
    Then I should still see the name as "Original Name"
    And the read should be repeatable within the transaction

  @isolation @phantom-read
  Scenario: Serializable isolation prevents phantom reads
    Given I start transaction T1 with serializable isolation
    And I count rules matching criteria "severity=High"
    And the count is 5
    When another transaction T2 inserts a rule with severity "High"
    And I count rules matching criteria "severity=High" again in transaction T1
    Then I should still see a count of 5
    And no phantom rows should appear

  @durability @crash-recovery
  Scenario: Committed transactions survive system crash
    Given I create a rule with id "durable-rule"
    And the transaction is committed
    When I simulate a system crash
    And I restart the database
    Then rule "durable-rule" should still exist
    And the rule data should be intact

  @durability @wal
  Scenario: Write-ahead logging ensures durability
    Given write-ahead logging is enabled
    When I create 100 rules in rapid succession
    And each create operation returns success
    Then all 100 rules should be retrievable after restart
    And no data loss should occur

  @atomicity @batch-operations
  Scenario: Batch alert creation is atomic
    Given I start a transaction
    When I attempt to create 10 alerts in a batch
    And alert number 7 has invalid data
    And I rollback the transaction
    Then zero alerts should be created
    And the database should remain in a consistent state

  @consistency @referential-integrity
  Scenario: Cascade delete maintains referential integrity
    Given a correlation rule with id "corr-rule-1" exists
    And the rule references 3 sub-rules
    When I delete the correlation rule "corr-rule-1" with cascade
    Then the correlation rule should be deleted
    And all 3 sub-rule references should be cleaned up
    And no orphaned references should remain
