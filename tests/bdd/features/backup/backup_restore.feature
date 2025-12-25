Feature: Backup and Restore Operations
  As an administrator
  I want to backup and restore system data
  So that I can recover from data loss

  @backup @restore
  Scenario: Create backup
    Given the database contains rules, alerts, and investigations
    When the administrator creates a backup
    Then a backup file is created
    And the backup file contains all data
    And the backup file integrity is verified

  @backup @restore
  Scenario: List backups
    Given 5 backups exist
    When the administrator lists backups
    Then 5 backups are returned
    And each backup shows creation time and size
    And backups are ordered by creation time descending

  @backup @restore
  Scenario: Restore backup
    Given a backup file exists
    And the current database is empty
    When the administrator restores the backup
    Then all data from backup is restored
    And data integrity is verified
    And the system operates normally

  @backup @restore
  Scenario: Delete backup
    Given a backup file exists
    When the administrator deletes the backup
    Then the backup file is removed
    And the backup is no longer in the list

  @backup @restore
  Scenario: Incremental backup
    Given a full backup exists
    And new data has been added since backup
    When the administrator creates an incremental backup
    Then only changed data is backed up
    And backup size is smaller than full backup
    And incremental backup references the full backup

  @backup @restore
  Scenario: Backup integrity verification
    Given a backup file exists
    When the administrator verifies backup integrity
    Then backup checksum is validated
    And backup format is validated
    And all required data is present

