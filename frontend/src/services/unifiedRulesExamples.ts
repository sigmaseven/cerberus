/**
 * Unified Rules API Usage Examples
 * TASK 174.7: Demonstrates all new unified rules endpoints
 *
 * This file shows practical examples of using the unified rules API client.
 * It is not imported anywhere - it serves as documentation and reference.
 */

import apiService from './api';
import type {
  UnifiedRulesListRequest,
  BulkOperationRequest,
  ValidateRuleRequest,
  RuleTestRequest,
  ImportRulesFormData,
  ExportRulesRequest,
  LifecycleTransitionRequest,
  FalsePositiveReportRequest,
  MigrateCQLRequest,
} from '../types';

// =============================================================================
// Example 1: Listing Rules with Advanced Filtering
// =============================================================================

export async function exampleListRules() {
  // Get all rules (detection + correlation)
  const allRules = await apiService.getUnifiedRules();
  console.log(`Total rules: ${allRules.total}`);

  // Get only detection rules
  const detectionRules = await apiService.getUnifiedRules({
    category: 'detection',
  });

  // Get only correlation rules
  const correlationRules = await apiService.getUnifiedRules({
    category: 'correlation',
  });

  // Advanced filtering: Windows authentication rules in experimental stage
  const windowsAuthExperimental = await apiService.getUnifiedRules({
    category: 'detection',
    lifecycle_status: 'experimental',
    logsource_category: 'authentication',
    logsource_product: 'windows',
    enabled: true,
    page: 1,
    limit: 100,
  });

  // Pagination with offset
  const page2 = await apiService.getUnifiedRules({
    offset: 50,
    limit: 50,
  });

  return { allRules, detectionRules, correlationRules, windowsAuthExperimental };
}

// =============================================================================
// Example 2: CRUD Operations
// =============================================================================

export async function exampleCRUDOperations() {
  // Create a new SIGMA rule
  const newRule = await apiService.createUnifiedRule({
    name: 'Suspicious PowerShell Execution',
    description: 'Detects encoded PowerShell commands',
    severity: 'high',
    enabled: true,
    sigma_yaml: `
title: Suspicious PowerShell Execution
description: Detects encoded PowerShell commands
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-encodedcommand'
  condition: selection
level: high
    `.trim(),
    type: 'sigma',
    conditions: [],
    actions: [],
  });

  console.log(`Created rule: ${newRule.rule.id}`);

  // Get the rule
  const fetchedRule = await apiService.getUnifiedRule(newRule.rule.id);
  console.log(`Fetched rule category: ${fetchedRule.category}`);

  // Update the rule
  const updatedRule = await apiService.updateUnifiedRule(newRule.rule.id, {
    enabled: false,
    description: 'Updated description',
  });

  // Delete the rule
  await apiService.deleteUnifiedRule(newRule.rule.id);
  console.log('Rule deleted');

  return { newRule, fetchedRule, updatedRule };
}

// =============================================================================
// Example 3: Bulk Operations
// =============================================================================

export async function exampleBulkOperations() {
  const ruleIds = ['rule-1', 'rule-2', 'rule-3', 'rule-4', 'rule-5'];

  // Enable multiple rules
  const enableResult = await apiService.bulkEnableRules(ruleIds);
  console.log(
    `Bulk enable: ${enableResult.processed} succeeded, ${enableResult.failed} failed`
  );
  if (enableResult.errors && enableResult.errors.length > 0) {
    console.error('Errors:', enableResult.errors);
  }

  // Disable multiple rules
  const disableResult = await apiService.bulkDisableRules(ruleIds);
  console.log(
    `Bulk disable: ${disableResult.processed} succeeded, ${disableResult.failed} failed`
  );

  // Delete multiple rules
  const deleteResult = await apiService.bulkDeleteRules(ruleIds);
  console.log(
    `Bulk delete: ${deleteResult.processed} succeeded, ${deleteResult.failed} failed`
  );

  return { enableResult, disableResult, deleteResult };
}

// =============================================================================
// Example 4: Import/Export
// =============================================================================

export async function exampleImportExport() {
  // Import SIGMA rules from files
  const fileInput = document.getElementById('file-input') as HTMLInputElement;
  const files = Array.from(fileInput?.files || []);

  const importResult = await apiService.importUnifiedRules({
    files,
    overwrite_existing: true,
    dry_run: false,
  });

  console.log(
    `Import: ${importResult.imported} imported, ${importResult.updated} updated, ${importResult.skipped} skipped, ${importResult.failed} failed`
  );

  // Show detailed results
  importResult.results.forEach((result) => {
    console.log(
      `${result.filename}: ${result.status}${result.message ? ` - ${result.message}` : ''}`
    );
  });

  // Export all SIGMA rules as ZIP
  const sigmaZip = await apiService.exportUnifiedRules({
    format: 'sigma',
    category: 'all',
  });

  // Download the ZIP file
  const url = window.URL.createObjectURL(sigmaZip);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sigma-rules-${Date.now()}.zip`;
  a.click();
  window.URL.revokeObjectURL(url);

  // Export specific rules as JSON
  const jsonZip = await apiService.exportUnifiedRules({
    format: 'json',
    category: 'detection',
    rule_ids: ['rule-1', 'rule-2'],
  });

  return { importResult, sigmaZip, jsonZip };
}

// =============================================================================
// Example 5: Validation
// =============================================================================

export async function exampleValidation() {
  const sigmaYaml = `
title: Test Rule
description: Testing validation
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'test'
  condition: selection
level: medium
  `.trim();

  const validation = await apiService.validateRule({ sigma_yaml: sigmaYaml });

  if (validation.valid) {
    console.log('✓ Rule is valid');
    console.log(`  Category: ${validation.category}`);
  } else {
    console.error('✗ Rule validation failed');
    validation.errors?.forEach((error) => console.error(`  Error: ${error}`));
  }

  if (validation.warnings && validation.warnings.length > 0) {
    console.warn('⚠ Warnings:');
    validation.warnings.forEach((warning) => console.warn(`  ${warning}`));
  }

  return validation;
}

// =============================================================================
// Example 6: Lifecycle Management
// =============================================================================

export async function exampleLifecycleManagement(ruleId: string) {
  // Transition from experimental to test
  const transitioned = await apiService.transitionRuleLifecycle(ruleId, {
    status: 'test',
    comment: 'Moved to testing after initial validation',
  });

  console.log(`Rule status changed to: ${transitioned.category}`);

  // Get lifecycle history
  const history = await apiService.getRuleLifecycleHistory(ruleId);
  console.log(`Lifecycle history (${history.length} entries):`);
  history.forEach((entry) => {
    console.log(
      `  ${entry.timestamp}: ${entry.from_status} -> ${entry.to_status} by ${entry.changed_by}`
    );
    if (entry.comment) {
      console.log(`    Comment: ${entry.comment}`);
    }
  });

  return { transitioned, history };
}

// =============================================================================
// Example 7: Rule Testing
// =============================================================================

export async function exampleRuleTesting() {
  // Test rule with sample events
  const testResult = await apiService.testRule({
    rule_id: 'my-rule-id',
    events: [
      {
        Image: 'C:\\Windows\\System32\\powershell.exe',
        CommandLine: 'powershell.exe -encodedcommand abc123',
      },
      {
        Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'cmd.exe /c echo hello',
      },
      {
        Image: 'C:\\Windows\\System32\\powershell.exe',
        CommandLine: 'powershell.exe Get-Process',
      },
    ],
  });

  console.log(`Test results: ${testResult.match_count}/${testResult.events_tested} matched`);
  console.log(`Overall match: ${testResult.matched}`);

  testResult.matches.forEach((match) => {
    console.log(`  Event ${match.event_index} matched:`);
    match.matched_conditions.forEach((condition) => {
      console.log(`    - ${condition}`);
    });
  });

  if (testResult.errors && testResult.errors.length > 0) {
    console.error('Test errors:', testResult.errors);
  }

  // Batch test against stored events
  const batchTest = await apiService.batchTestRule({
    rule_id: 'my-rule-id',
    event_ids: ['event-1', 'event-2', 'event-3'],
  });

  return { testResult, batchTest };
}

// =============================================================================
// Example 8: Performance Monitoring
// =============================================================================

export async function examplePerformanceMonitoring() {
  // Get performance stats for a specific rule
  const perf = await apiService.getRulePerformance('my-rule-id', {
    start: '2025-01-01T00:00:00Z',
    end: '2025-01-31T23:59:59Z',
  });

  console.log(`Rule Performance: ${perf.rule_name}`);
  console.log(`  Total executions: ${perf.total_executions}`);
  console.log(`  Total matches: ${perf.total_matches}`);
  console.log(`  Avg execution time: ${perf.avg_execution_time_ms}ms`);
  console.log(`  Max execution time: ${perf.max_execution_time_ms}ms`);
  console.log(`  Min execution time: ${perf.min_execution_time_ms}ms`);
  console.log(`  False positives: ${perf.false_positive_count}`);

  // Find slow rules
  const slowRules = await apiService.getSlowRules(10, 100); // Top 10 rules >100ms
  console.log('\nSlow Rules (>100ms):');
  slowRules.forEach((rule, index) => {
    console.log(
      `  ${index + 1}. ${rule.rule_name}: ${rule.avg_execution_time_ms}ms (${rule.executions_count} executions)`
    );
  });

  return { perf, slowRules };
}

// =============================================================================
// Example 9: False Positive Reporting
// =============================================================================

export async function exampleFalsePositiveReporting() {
  const report = await apiService.reportFalsePositive({
    rule_id: 'my-rule-id',
    event_id: 'event-123',
    alert_id: 'alert-456',
    reason: 'Legitimate PowerShell script execution by system administrator',
    suggested_fix:
      'Add exclusion for scripts in C:\\AdminScripts\\ directory',
  });

  console.log(`False positive reported: ${report.report_id}`);
  console.log(`Status: ${report.reported ? 'Success' : 'Failed'}`);
  console.log(`Message: ${report.message}`);

  return report;
}

// =============================================================================
// Example 10: CQL Migration
// =============================================================================

export async function exampleCQLMigration() {
  // Migrate all CQL rules
  const migrationAll = await apiService.migrateCQLRules({
    auto_enable: false,
    preserve_originals: true,
  });

  console.log(
    `Migration: ${migrationAll.migrated}/${migrationAll.total} succeeded, ${migrationAll.failed} failed`
  );

  migrationAll.results.forEach((result) => {
    if (result.success) {
      console.log(
        `✓ ${result.rule_name}: migrated to ${result.sigma_rule_id}`
      );
      if (result.warnings && result.warnings.length > 0) {
        result.warnings.forEach((warning) => console.warn(`  ⚠ ${warning}`));
      }
    } else {
      console.error(`✗ ${result.rule_name}: ${result.error}`);
    }
  });

  // Migrate specific rules
  const migrationSpecific = await apiService.migrateCQLRules({
    rule_ids: ['cql-rule-1', 'cql-rule-2'],
    auto_enable: true,
    preserve_originals: false,
  });

  return { migrationAll, migrationSpecific };
}

// =============================================================================
// Example 11: Complete Workflow - Create, Test, Deploy
// =============================================================================

export async function exampleCompleteWorkflow() {
  // Step 1: Validate SIGMA YAML
  const sigmaYaml = `
title: Suspicious Network Connection
description: Detects suspicious outbound connections
status: experimental
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationPort:
      - 4444
      - 5555
    Initiated: 'true'
  filter:
    Image|endswith:
      - '\\chrome.exe'
      - '\\firefox.exe'
  condition: selection and not filter
level: high
  `.trim();

  const validation = await apiService.validateRule({ sigma_yaml: sigmaYaml });
  if (!validation.valid) {
    console.error('Validation failed:', validation.errors);
    return null;
  }

  // Step 2: Create rule
  const newRule = await apiService.createUnifiedRule({
    name: 'Suspicious Network Connection',
    description: 'Detects suspicious outbound connections',
    severity: 'high',
    enabled: false, // Start disabled for testing
    sigma_yaml: sigmaYaml,
    type: 'sigma',
    conditions: [],
    actions: [],
  });

  console.log(`Created rule: ${newRule.rule.id}`);

  // Step 3: Test rule with sample events
  const testResult = await apiService.testRule({
    rule_id: newRule.rule.id,
    events: [
      { DestinationPort: 4444, Initiated: 'true', Image: 'C:\\malware.exe' },
      {
        DestinationPort: 4444,
        Initiated: 'true',
        Image: 'C:\\Program Files\\Google\\Chrome\\chrome.exe',
      },
      { DestinationPort: 80, Initiated: 'true', Image: 'C:\\malware.exe' },
    ],
  });

  console.log(`Test: ${testResult.match_count}/${testResult.events_tested} matched`);

  // Step 4: If tests pass, enable the rule
  if (testResult.matched && testResult.match_count > 0) {
    const enabled = await apiService.updateUnifiedRule(newRule.rule.id, {
      enabled: true,
    });
    console.log('Rule enabled');

    // Step 5: Transition to test status
    await apiService.transitionRuleLifecycle(newRule.rule.id, {
      status: 'test',
      comment: 'Passed initial testing, moving to test phase',
    });
  }

  // Step 6: Monitor performance
  setTimeout(async () => {
    const perf = await apiService.getRulePerformance(newRule.rule.id);
    console.log(
      `Performance after deployment: ${perf.avg_execution_time_ms}ms avg`
    );
  }, 60000); // Check after 1 minute

  return { validation, newRule, testResult };
}
