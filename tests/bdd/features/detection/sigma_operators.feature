# Feature: SIGMA Operator Compliance
# Requirement: SIGMA-002 - Operator Case Sensitivity
# Requirement: SIGMA-005 - Field Path Resolution
# Source: docs/requirements/sigma-compliance.md
#
# The detection engine MUST correctly implement all SIGMA operators with
# proper case sensitivity handling and field path resolution.

@detection @critical @sigma @operators
Feature: SIGMA Operator Compliance
  As a detection engineer
  I want SIGMA operators to work correctly
  So that detection rules match events as expected

  Background:
    Given the Cerberus detection engine is running
    And the database contains sample events

  @sigma-operator @equals
  Scenario: Equals operator with exact case match
    Given a SIGMA rule with condition "EventID equals 4625"
    And an event exists with EventID "4625"
    When I evaluate the rule against the event
    Then the rule should match
    And an alert should be generated

  @sigma-operator @equals @case-sensitivity
  Scenario: Equals operator is case-sensitive for strings
    Given a SIGMA rule with condition "ProcessName equals 'cmd.exe'"
    And an event exists with ProcessName "CMD.EXE"
    When I evaluate the rule against the event
    Then the rule should not match
    And no alert should be generated

  @sigma-operator @contains
  Scenario: Contains operator matches substring
    Given a SIGMA rule with condition "CommandLine contains 'powershell'"
    And an event exists with CommandLine "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc ABC"
    When I evaluate the rule against the event
    Then the rule should match

  @sigma-operator @contains @case-insensitive
  Scenario: Contains operator is case-insensitive
    Given a SIGMA rule with condition "CommandLine contains 'powershell'"
    And an event exists with CommandLine "C:\Windows\POWERSHELL\powershell.exe"
    When I evaluate the rule against the event
    Then the rule should match

  @sigma-operator @startswith
  Scenario: Startswith operator matches prefix
    Given a SIGMA rule with condition "TargetFilename startswith 'C:\Windows\Temp\'"
    And an event exists with TargetFilename "C:\Windows\Temp\malware.exe"
    When I evaluate the rule against the event
    Then the rule should match

  @sigma-operator @startswith @negative
  Scenario: Startswith operator does not match if prefix differs
    Given a SIGMA rule with condition "TargetFilename startswith 'C:\Windows\Temp\'"
    And an event exists with TargetFilename "C:\Users\Public\file.exe"
    When I evaluate the rule against the event
    Then the rule should not match

  @sigma-operator @endswith
  Scenario: Endswith operator matches suffix
    Given a SIGMA rule with condition "TargetFilename endswith '.exe'"
    And an event exists with TargetFilename "C:\Windows\System32\calc.exe"
    When I evaluate the rule against the event
    Then the rule should match

  @sigma-operator @all-of
  Scenario: All-of operator requires all conditions
    Given a SIGMA rule with condition "all of: ProcessName equals 'powershell.exe' AND CommandLine contains '-enc'"
    And an event exists with ProcessName "powershell.exe" and CommandLine "powershell.exe -enc ABCD"
    When I evaluate the rule against the event
    Then the rule should match

  @sigma-operator @all-of @negative
  Scenario: All-of operator fails if any condition fails
    Given a SIGMA rule with condition "all of: ProcessName equals 'powershell.exe' AND CommandLine contains '-enc'"
    And an event exists with ProcessName "cmd.exe" and CommandLine "powershell.exe -enc ABCD"
    When I evaluate the rule against the event
    Then the rule should not match

  @sigma-operator @any-of
  Scenario: Any-of operator matches if any condition matches
    Given a SIGMA rule with condition "any of: ProcessName equals 'powershell.exe' OR ProcessName equals 'cmd.exe'"
    And an event exists with ProcessName "cmd.exe"
    When I evaluate the rule against the event
    Then the rule should match

  @sigma-operator @regex
  Scenario: Regex operator matches pattern
    Given a SIGMA rule with condition "CommandLine matches '.*-enc[oded]{0,4}\\s+[A-Za-z0-9+/=]{50,}'"
    And an event exists with CommandLine "powershell.exe -encoded QQBCAEMARAAuAC4ALgA="
    When I evaluate the rule against the event
    Then the rule should match

  @sigma-operator @field-path
  Scenario: Nested field path resolution with dot notation
    Given a SIGMA rule with condition "user.name equals 'admin'"
    And an event exists with nested field user.name = "admin"
    When I evaluate the rule against the event
    Then the rule should match

  @sigma-operator @field-path @deep-nesting
  Scenario: Deep nested field path resolution
    Given a SIGMA rule with condition "process.parent.command_line contains 'cmd.exe'"
    And an event exists with deeply nested field process.parent.command_line = "C:\Windows\System32\cmd.exe /c malware.bat"
    When I evaluate the rule against the event
    Then the rule should match

  @sigma-operator @field-path @missing-field
  Scenario: Missing field in event does not match
    Given a SIGMA rule with condition "optional_field equals 'value'"
    And an event exists without the field "optional_field"
    When I evaluate the rule against the event
    Then the rule should not match

  @sigma-operator @null-value
  Scenario: Null field value does not match non-null condition
    Given a SIGMA rule with condition "field1 equals 'value'"
    And an event exists with field1 = null
    When I evaluate the rule against the event
    Then the rule should not match

  @sigma-operator @wildcard
  Scenario Outline: Wildcard matching with asterisks
    Given a SIGMA rule with condition "TargetFilename wildcard '<pattern>'"
    And an event exists with TargetFilename "<filename>"
    Then the rule should <result>

    Examples:
      | pattern                  | filename                      | result     |
      | C:\Windows\*.exe         | C:\Windows\calc.exe           | match      |
      | C:\Windows\*.exe         | C:\Windows\System32\cmd.exe   | not match  |
      | C:\Windows\*\*.exe       | C:\Windows\System32\cmd.exe   | match      |
      | *.bat                    | malware.bat                   | match      |
      | *.bat                    | malware.exe                   | not match  |

  @sigma-operator @modifiers @case-insensitive
  Scenario: Case-insensitive modifier overrides default behavior
    Given a SIGMA rule with condition "ProcessName|caseinsensitive equals 'cmd.exe'"
    And an event exists with ProcessName "CMD.EXE"
    When I evaluate the rule against the event
    Then the rule should match

  @sigma-operator @modifiers @base64
  Scenario: Base64 modifier decodes values before matching
    Given a SIGMA rule with condition "Data|base64 contains 'powershell'"
    And an event exists with Data = base64("powershell -enc ABC")
    When I evaluate the rule against the event
    Then the rule should match
