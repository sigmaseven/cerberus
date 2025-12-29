# Feature: Visual Correlation Builder End-to-End Testing
# Requirement: FR-VCB-001 - Visual Correlation Builder API
# Requirement: FR-VCB-002 - Template-Based Correlation Creation
# Requirement: FR-VCB-003 - Multi-Node Graph Execution
# Requirement: FR-VCB-004 - RBAC Enforcement
# Source: docs/requirements/visual-builder-requirements.md
#
# The visual correlation builder MUST support template-based creation,
# multi-node graph building, Sigma import, and comprehensive audit trails.

@visual-builder @integration @critical
Feature: Visual Correlation Builder End-to-End
  As a security engineer
  I want to build correlation rules visually
  So that complex detection logic can be created and managed intuitively

  Background:
    Given the Cerberus API server is running
    And I am authenticated as user "admin" with role "admin"
    And the correlation storage is initialized
    And the audit logging is enabled

  # ============================================
  # Scenario 1: Create Correlation from Template
  # ============================================

  @template @happy-path
  Scenario: Create correlation rule from template
    Given the following correlation templates exist:
      | name                | type     | description                         |
      | brute-force-ssh     | count    | Detect SSH brute force attempts     |
      | lateral-movement    | sequence | Detect lateral movement patterns    |
      | rare-process        | rare     | Detect rare process executions      |
    When I create a correlation from template "brute-force-ssh" with parameters:
      | parameter    | value           |
      | threshold    | 5               |
      | window       | 5m              |
      | group_by     | source_ip       |
      | severity     | high            |
    Then the response status should be 201
    And a new correlation rule should be created
    And the correlation should have type "count"
    And the correlation should have visual metadata
    And an audit log entry should be created for "correlation.created"

  @template @missing-parameters
  Scenario: Template instantiation fails with missing required parameters
    Given a correlation template "brute-force-ssh" with required parameters ["threshold", "window"]
    When I create a correlation from template without "threshold" parameter
    Then the response status should be 400
    And the error should indicate "missing required parameter: threshold"

  # ============================================
  # Scenario 2: Build Graph with Multiple Nodes
  # ============================================

  @graph @multi-node @happy-path
  Scenario: Build correlation graph with multiple node types
    When I create a visual correlation with the following nodes:
      | id     | type        | config                                          |
      | input  | input       | selection: event_type = "auth_failure"          |
      | filter | filter      | condition: severity = "high"                    |
      | agg    | aggregation | function: count, group_by: source_ip, window: 5m|
      | alert  | alert       | severity: high, name: "High Severity Auth Fail" |
    And I connect the nodes:
      | from   | to     |
      | input  | filter |
      | filter | agg    |
      | agg    | alert  |
    And I validate the correlation graph
    Then the validation should pass
    And the graph should have 4 nodes
    And the graph should have 3 edges
    And the execution order should be "input → filter → agg → alert"

  @graph @join-node
  Scenario: Build correlation graph with join node
    When I create a visual correlation with a join node:
      | left_input   | right_input  | join_type | join_key   |
      | auth_events  | network_conn | inner     | source_ip  |
    And I configure the join window as "10m"
    Then the correlation should be created with join configuration
    And the join node should accept events from both inputs

  @graph @debounce-node
  Scenario: Build correlation graph with debounce node
    When I create a visual correlation with nodes:
      | id       | type     | config                         |
      | input    | input    | selection: event_type = "scan" |
      | debounce | debounce | window: 1m, count: 1           |
      | alert    | alert    | severity: medium               |
    And I connect input → debounce → alert
    Then the correlation should suppress duplicate alerts within 1 minute

  @graph @enrichment-node
  Scenario: Build correlation graph with enrichment node
    When I create a visual correlation with enrichment node:
      | enrichment_type | lookup_table    | match_field | output_fields       |
      | lookup          | ip_reputation   | source_ip   | risk_score, country |
    Then the correlation should enrich events with lookup data
    And the enriched fields should be available for downstream processing

  @graph @validation-error
  Scenario: Graph validation fails for disconnected nodes
    When I create a visual correlation with nodes:
      | id     | type   |
      | input1 | input  |
      | input2 | input  |
      | alert  | alert  |
    And I only connect input1 → alert
    And I validate the correlation graph
    Then the validation should fail
    And the error should indicate "node 'input2' is not connected to the graph"

  @graph @cyclic-detection
  Scenario: Graph validation fails for cyclic dependencies
    When I create a visual correlation with a cycle:
      | from   | to     |
      | nodeA  | nodeB  |
      | nodeB  | nodeC  |
      | nodeC  | nodeA  |
    And I validate the correlation graph
    Then the validation should fail
    And the error should indicate "cyclic dependency detected"

  # ============================================
  # Scenario 3: Test Correlation with Sample Events
  # ============================================

  @testing @dry-run @happy-path
  Scenario: Test correlation with sample events
    Given a visual correlation rule for brute force detection
    When I test the correlation with sample events:
      | event_type   | source_ip    | username | timestamp          |
      | auth_failure | 192.168.1.50 | admin    | 2024-01-15T10:00:00|
      | auth_failure | 192.168.1.50 | admin    | 2024-01-15T10:01:00|
      | auth_failure | 192.168.1.50 | admin    | 2024-01-15T10:02:00|
      | auth_failure | 192.168.1.50 | admin    | 2024-01-15T10:03:00|
      | auth_failure | 192.168.1.50 | admin    | 2024-01-15T10:04:00|
      | auth_failure | 192.168.1.50 | admin    | 2024-01-15T10:05:00|
    Then the dry-run results should show:
      | field          | value |
      | alerts_count   | 1     |
      | events_matched | 6     |
    And the dry-run should not persist any alerts
    And the node execution trace should be available

  @testing @no-match
  Scenario: Test correlation that does not trigger alert
    Given a visual correlation rule with threshold > 10
    When I test the correlation with 5 matching events
    Then the dry-run results should show alerts_count = 0
    And the results should show events_matched = 5
    And no alert should be generated

  @testing @validation-mode
  Scenario: Test correlation in validation mode shows node-by-node results
    Given a visual correlation with nodes: input → filter → aggregation → alert
    When I test the correlation in validation mode
    Then the results should show processing stats for each node:
      | node        | events_in | events_out | duration_ms |
      | input       | 10        | 10         | < 100       |
      | filter      | 10        | 6          | < 100       |
      | aggregation | 6         | 1          | < 100       |
      | alert       | 1         | 1          | < 100       |

  # ============================================
  # Scenario 4: Import Sigma Rule to Visual Format
  # ============================================

  @sigma-import @happy-path
  Scenario: Import Sigma rule and convert to visual format
    Given a valid Sigma rule:
      """
      title: SSH Brute Force Attempt
      status: test
      logsource:
        product: linux
        service: sshd
      detection:
        selection:
          event_type: auth_failure
        condition: selection | count() by source_ip > 5
      level: high
      """
    When I import the Sigma rule as a visual correlation
    Then the response status should be 201
    And a visual correlation should be created with:
      | field      | value                     |
      | type       | count                     |
      | threshold  | 5                         |
      | group_by   | source_ip                 |
      | severity   | high                      |
    And the visual graph should have nodes:
      | type        | count |
      | input       | 1     |
      | aggregation | 1     |
      | alert       | 1     |
    And the original Sigma YAML should be preserved in metadata

  @sigma-import @complex-rule
  Scenario: Import complex Sigma rule with multiple conditions
    Given a Sigma rule with selection and filter conditions
    When I import the Sigma rule as a visual correlation
    Then the visual graph should include filter nodes for each condition
    And the CQL query should be correctly generated

  @sigma-import @invalid-rule
  Scenario: Import fails for invalid Sigma syntax
    Given an invalid Sigma rule with syntax errors
    When I attempt to import the Sigma rule
    Then the response status should be 400
    And the error should describe the Sigma parsing failure

  # ============================================
  # Scenario 5: Execute Correlation and Verify Alert
  # ============================================

  @execution @alert-generation @happy-path
  Scenario: Execute correlation and verify alert generation
    Given a visual correlation rule "brute-force-detection" is active
    And the detection engine is running
    When I send 6 failed SSH login events from IP "10.0.0.50" within 5 minutes
    Then an alert should be generated within 30 seconds
    And the alert should have:
      | field            | value                              |
      | rule_id          | brute-force-detection              |
      | severity         | high                               |
      | source_ip        | 10.0.0.50                          |
      | correlated_count | 6                                  |
    And the alert should contain references to all 6 triggering events

  @execution @alert-context
  Scenario: Alert includes enriched context from processing nodes
    Given a visual correlation with enrichment node adding geo-location
    And the correlation is active
    When triggering events are processed
    Then the generated alert should include geo-location data
    And the alert metadata should show enrichment was applied

  @execution @suppression
  Scenario: Alert suppression prevents duplicate alerts
    Given a visual correlation with debounce node (window: 5m)
    When I send 10 triggering event sequences within 5 minutes
    Then only 1 alert should be generated
    And subsequent triggering events should be suppressed

  # ============================================
  # Scenario 6: Verify Audit Trail
  # ============================================

  @audit @create-operation
  Scenario: Audit trail captures correlation creation
    When I create a new visual correlation
    Then an audit log entry should exist with:
      | field         | value               |
      | operation     | correlation.created |
      | user          | admin               |
      | correlation_id| <created_id>        |
    And the audit entry should include the full correlation configuration

  @audit @update-operation
  Scenario: Audit trail captures correlation updates
    Given an existing visual correlation "test-rule"
    When I update the correlation threshold to 10
    Then an audit log entry should exist with:
      | field     | value               |
      | operation | correlation.updated |
      | changes   | threshold: 5 → 10   |

  @audit @delete-operation
  Scenario: Audit trail captures correlation deletion
    Given an existing visual correlation "to-be-deleted"
    When I delete the correlation
    Then an audit log entry should exist with:
      | field     | value               |
      | operation | correlation.deleted |
    And the audit entry should include the deleted correlation's configuration

  @audit @activation-toggle
  Scenario: Audit trail captures enable/disable operations
    Given an active visual correlation "test-rule"
    When I disable the correlation
    Then an audit log entry should exist with:
      | field     | value                  |
      | operation | correlation.disabled   |
    When I enable the correlation
    Then an audit log entry should exist with:
      | field     | value                 |
      | operation | correlation.enabled   |

  @audit @query
  Scenario: Query audit logs for correlation changes
    Given multiple audit entries for correlation "rule-123"
    When I query audit logs for correlation_id = "rule-123"
    Then I should receive a paginated list of all operations
    And the entries should be ordered by timestamp descending
    And the response should include operation counts by type

  # ============================================
  # Scenario 7: Impact Analysis Before Deletion
  # ============================================

  @impact-analysis @happy-path
  Scenario: Impact analysis shows dependencies before deletion
    Given a visual correlation "base-rule" that is referenced by:
      | type         | name              |
      | playbook     | incident-response |
      | dashboard    | soc-overview      |
      | nested-rule  | advanced-threat   |
    When I request impact analysis for "base-rule"
    Then the response should show:
      | dependency_type | count | names                  |
      | playbooks       | 1     | incident-response      |
      | dashboards      | 1     | soc-overview           |
      | correlations    | 1     | advanced-threat        |
    And the response should recommend "resolve dependencies before deletion"

  @impact-analysis @no-dependencies
  Scenario: Impact analysis for rule with no dependencies
    Given a visual correlation with no external references
    When I request impact analysis
    Then the response should indicate no dependencies
    And deletion should be safe to proceed

  @impact-analysis @block-delete
  Scenario: Deletion blocked when dependencies exist and force=false
    Given a visual correlation with active dependencies
    When I attempt to delete without force=true
    Then the response status should be 409 Conflict
    And the error should list all blocking dependencies

  @impact-analysis @force-delete
  Scenario: Force deletion removes rule despite dependencies
    Given a visual correlation with dependencies
    When I delete with force=true
    Then the correlation should be deleted
    And dependent playbooks should be marked as "broken"
    And a warning audit log should be created

  # ============================================
  # Scenario 8: RBAC Permission Enforcement
  # ============================================

  @rbac @viewer-restrictions
  Scenario: Viewer role can only read correlations
    Given I am authenticated as user "analyst" with role "viewer"
    When I attempt to read correlation "test-rule"
    Then the response status should be 200
    When I attempt to create a new correlation
    Then the response status should be 403 Forbidden
    When I attempt to update correlation "test-rule"
    Then the response status should be 403 Forbidden
    When I attempt to delete correlation "test-rule"
    Then the response status should be 403 Forbidden

  @rbac @analyst-permissions
  Scenario: Analyst role can create and update but not delete
    Given I am authenticated as user "analyst" with role "analyst"
    When I create a new correlation
    Then the response status should be 201
    When I update my created correlation
    Then the response status should be 200
    When I attempt to delete a correlation
    Then the response status should be 403 Forbidden

  @rbac @engineer-permissions
  Scenario: Engineer role has full correlation management access
    Given I am authenticated as user "engineer" with role "engineer"
    When I create a new correlation
    Then the response status should be 201
    When I update the correlation
    Then the response status should be 200
    When I delete the correlation
    Then the response status should be 200

  @rbac @admin-override
  Scenario: Admin role can manage all correlations
    Given I am authenticated as user "admin" with role "admin"
    And a correlation owned by user "other-user"
    When I update the correlation
    Then the response status should be 200
    When I delete the correlation
    Then the response status should be 200

  @rbac @ownership
  Scenario: Users can only modify their own correlations unless admin
    Given I am authenticated as user "analyst1" with role "analyst"
    And a correlation owned by user "analyst2"
    When I attempt to update the correlation
    Then the response status should be 403 Forbidden
    And the error should indicate "insufficient permissions"

  # ============================================
  # Error Handling Scenarios
  # ============================================

  @error-handling @not-found
  Scenario: Appropriate error for non-existent correlation
    When I request correlation with id "non-existent-id"
    Then the response status should be 404 Not Found
    And the error message should be "correlation not found"

  @error-handling @invalid-config
  Scenario: Validation error for invalid correlation configuration
    When I create a correlation with invalid window value "-5m"
    Then the response status should be 400 Bad Request
    And the error should indicate "invalid time window: must be positive"

  @error-handling @concurrent-modification
  Scenario: Optimistic locking prevents lost updates
    Given a visual correlation with version 1
    When user A reads the correlation
    And user B updates the correlation (version becomes 2)
    And user A attempts to update with version 1
    Then user A should receive status 409 Conflict
    And the error should indicate "concurrent modification detected"

  @error-handling @storage-failure
  Scenario: Graceful handling of storage failures
    Given a simulated storage failure
    When I attempt to create a correlation
    Then the response status should be 503 Service Unavailable
    And the error should indicate storage unavailability
    And no partial data should be persisted
