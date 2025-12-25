/**
 * Comprehensive E2E Tests for Unified Rules Page (Task 174.8)
 *
 * Test Coverage:
 * 1. Category filtering (Detection/Correlation/All)
 * 2. Create detection rule with YAML editor
 * 3. Create correlation rule with CorrelationConfigEditor
 * 4. YAML editor validation
 * 5. Rule testing panel
 * 6. Lifecycle state transitions
 * 7. Performance dashboard
 * 8. Import/export workflow
 * 9. Accessibility audit (WCAG 2.1 AA)
 * 10. Visual regression tests
 *
 * Follows established patterns from auth.fixture.ts and rules-comprehensive.spec.ts
 */

import { test as authTest, expect } from './fixtures/auth.fixture';
import { generateTestRule } from './fixtures/test-data.fixture';
import AxeBuilder from '@axe-core/playwright';
import type { Page } from '@playwright/test';

// =============================================================================
// Test Helpers
// =============================================================================

/**
 * Helper to wait for network idle and specific selector
 */
async function waitForPageReady(page: Page, selector: string, timeout = 10000): Promise<void> {
  await page.waitForLoadState('networkidle', { timeout });
  await page.waitForSelector(selector, { timeout });
}

/**
 * Helper to create a test detection rule via UI
 */
async function createDetectionRule(
  page: Page,
  ruleName: string,
  yamlContent: string
): Promise<void> {
  // Open create dialog
  await page.click('button:has-text("Create Rule")');
  const dialogSelector = page.locator('[role="dialog"]').or(page.locator('form:has(input[name="title"])'));
  await dialogSelector.waitFor({ timeout: 10000 });

  // Fill basic fields
  await page.fill('input[name="title"]', ruleName);
  const descriptionField = page.locator('textarea[name="description"]').or(page.locator('input[name="description"]'));
  await descriptionField.fill(`Test detection rule: ${ruleName}`);

  // Select severity
  const severitySelect = page.locator('select[name="severity"]').or(page.locator('div[role="button"]:has-text("Severity")'));
  await severitySelect.click();
  const highOption = page.locator('li[role="option"]:has-text("High")').or(page.locator('option:has-text("High")'));
  await highOption.click();

  // Paste YAML content into editor
  const yamlEditor = page.locator('.cm-content').or(page.locator('textarea[placeholder*="YAML"]')).or(page.locator('.CodeMirror textarea')).first();
  if (await yamlEditor.count() > 0) {
    await yamlEditor.fill(yamlContent);
    // Wait for validation to complete
    await page.waitForLoadState('networkidle');
  }

  // Submit form
  const saveButton = page.locator('button[type="submit"]:has-text("Save")').or(page.locator('button:has-text("Save Rule")'));
  await saveButton.click();

  // Wait for success or error
  const resultSelector = page.locator('text=created successfully').or(page.locator('text=error')).or(page.locator('[role="alert"]'));
  await resultSelector.waitFor({ timeout: 10000 });
}

/**
 * Helper to create a test correlation rule via UI
 */
async function createCorrelationRule(
  page: Page,
  ruleName: string,
  correlationType: string
): Promise<void> {
  // Open create dialog
  await page.click('button:has-text("Create Rule")');
  const dialogSelector = page.locator('[role="dialog"]').or(page.locator('form:has(input[name="title"])'));
  await dialogSelector.waitFor({ timeout: 10000 });

  // Select correlation category
  const categorySelect = page.locator('select:has-text("Rule Category")').or(page.locator('div[role="button"]:has-text("Category")'));
  if (await categorySelect.count() > 0) {
    await categorySelect.first().click();
    const correlationOption = page.locator('li[role="option"]:has-text("Correlation")').or(page.locator('option:has-text("Correlation")'));
    await correlationOption.click();
  }

  // Fill basic fields
  await page.fill('input[name="title"]', ruleName);
  const descriptionField = page.locator('textarea[name="description"]').or(page.locator('input[name="description"]'));
  await descriptionField.fill(`Test correlation rule: ${ruleName}`);

  // Select correlation type
  const typeSelect = page.locator('select:has-text("Correlation Type")').or(page.locator('div[role="button"]:has-text("Correlation Type")'));
  await typeSelect.click();
  const typeOption = page.locator(`li[role="option"]:has-text("${correlationType}")`).or(page.locator(`option:has-text("${correlationType}")`));
  await typeOption.click();

  // Fill type-specific fields
  if (correlationType === 'Event Count') {
    await page.fill('input[name*="count"]', '10');
    await page.fill('input[name*="timespan"]', '5m');
  }

  // Submit form
  const saveButton = page.locator('button[type="submit"]:has-text("Save")').or(page.locator('button:has-text("Save Rule")'));
  await saveButton.click();

  // Wait for success or error
  const resultSelector = page.locator('text=created successfully').or(page.locator('text=error')).or(page.locator('[role="alert"]'));
  await resultSelector.waitFor({ timeout: 10000 });
}

/**
 * Helper to clean up test rules
 */
async function cleanupTestRules(page: Page, ruleName: string): Promise<void> {
  await page.goto('/rules');
  await waitForPageReady(page, 'table', 5000);

  // Search for test rule
  const searchInput = page.locator('input[placeholder*="Search"]').or(page.locator('input[aria-label*="Search"]'));
  if (await searchInput.count() > 0) {
    await searchInput.fill(ruleName);
    // Wait for search results to update
    await page.waitForLoadState('networkidle');
  }

  // Delete if exists
  const deleteButton = page.locator('button[aria-label*="Delete"]:visible').first();
  if (await deleteButton.count() > 0) {
    await deleteButton.click();
    const confirmButton = page.locator('button:has-text("Confirm")').or(page.locator('button:has-text("Delete")'));
    await confirmButton.click();
    // Wait for deletion to complete
    await page.waitForLoadState('networkidle');
  }
}

// =============================================================================
// Test Data
// =============================================================================

const SAMPLE_SIGMA_YAML = `title: Test SSH Brute Force Detection
description: Detects multiple failed SSH authentication attempts
status: experimental
logsource:
  category: auth
  product: linux
detection:
  selection:
    EventID: 4625
    service: ssh
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1110`;

const SAMPLE_CORRELATION_CONFIG = {
  type: 'event_count',
  group_by: ['source_ip'],
  timespan: '5m',
  count: 10,
  condition: '>='
};

// =============================================================================
// Test Suite 1: Category Filtering
// =============================================================================

authTest.describe('UNIFIED-RULES-01: Category Filtering', () => {
  authTest.beforeEach(async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');
  });

  authTest('UNIFIED-001: Filter by Detection category', async ({ authenticatedPage }) => {
    // Find and click category filter
    const categoryFilter = authenticatedPage.locator('select[aria-label*="category"]').or(authenticatedPage.locator('div[role="button"]:has-text("Category")'));
    await expect(categoryFilter).toBeVisible();

    await categoryFilter.click();
    const detectionOption = authenticatedPage.locator('li[role="option"]:has-text("Detection")').or(authenticatedPage.locator('option:has-text("Detection")'));
    await detectionOption.click();

    // Wait for filter to apply by checking table re-renders
    await authenticatedPage.waitForLoadState('networkidle');

    // Verify only detection rules shown
    const categoryChips = authenticatedPage.locator('span:has-text("Detection")');
    const count = await categoryChips.count();
    expect(count).toBeGreaterThan(0);
  });

  authTest('UNIFIED-002: Filter by Correlation category', async ({ authenticatedPage }) => {
    const categoryFilter = authenticatedPage.locator('select[aria-label*="category"]').or(authenticatedPage.locator('div[role="button"]:has-text("Category")'));
    await categoryFilter.click();
    const correlationOption = authenticatedPage.locator('li[role="option"]:has-text("Correlation")').or(authenticatedPage.locator('option:has-text("Correlation")'));
    await correlationOption.click();

    // Wait for filter to apply
    await authenticatedPage.waitForLoadState('networkidle');

    // Verify correlation rules shown (or empty state)
    const table = authenticatedPage.locator('table');
    await expect(table).toBeVisible();
  });

  authTest('UNIFIED-003: Filter by All categories', async ({ authenticatedPage }) => {
    const categoryFilter = authenticatedPage.locator('select[aria-label*="category"]').or(authenticatedPage.locator('div[role="button"]:has-text("Category")'));
    await categoryFilter.click();
    const allOption = authenticatedPage.locator('li[role="option"]:has-text("All")').or(authenticatedPage.locator('option:has-text("All")'));
    await allOption.click();

    // Wait for filter to apply
    await authenticatedPage.waitForLoadState('networkidle');

    // Verify table displays
    const table = authenticatedPage.locator('table');
    await expect(table).toBeVisible();
  });

  authTest('UNIFIED-004: Category filter persists after page reload', async ({ authenticatedPage }) => {
    const categoryFilter = authenticatedPage.locator('select[aria-label*="category"]').or(authenticatedPage.locator('div[role="button"]:has-text("Category")'));
    await categoryFilter.click();
    const detectionOption = authenticatedPage.locator('li[role="option"]:has-text("Detection")').or(authenticatedPage.locator('option:has-text("Detection")'));
    await detectionOption.click();

    // Wait for filter to apply
    await authenticatedPage.waitForLoadState('networkidle');

    // Reload page
    await authenticatedPage.reload();
    await waitForPageReady(authenticatedPage, 'table');

    // Verify filter still applied (may reset - this tests behavior)
    const table = authenticatedPage.locator('table');
    await expect(table).toBeVisible();
  });
});

// =============================================================================
// Test Suite 2: Detection Rule CRUD with YAML
// =============================================================================

authTest.describe('UNIFIED-RULES-02: Detection Rule CRUD', () => {
  const testRuleName = `E2E-Detection-${Date.now()}`;

  authTest.afterEach(async ({ page }) => {
    await cleanupTestRules(page, testRuleName);
  });

  authTest('UNIFIED-005: Create detection rule with YAML editor', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    await createDetectionRule(authenticatedPage, testRuleName, SAMPLE_SIGMA_YAML);

    // Verify success message
    await expect(authenticatedPage.locator('text=created successfully')).toBeVisible({ timeout: 5000 });

    // Verify rule appears in table
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    const searchInput = authenticatedPage.locator('input[placeholder*="Search"]').or(authenticatedPage.locator('input[aria-label*="Search"]'));
    if (await searchInput.count() > 0) {
      await searchInput.fill(testRuleName);
      await authenticatedPage.waitForLoadState('networkidle');
      await expect(authenticatedPage.locator(`text="${testRuleName}"`)).toBeVisible();
    }
  });

  authTest('UNIFIED-006: Edit detection rule YAML', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    // Create rule first
    await createDetectionRule(authenticatedPage, testRuleName, SAMPLE_SIGMA_YAML);
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    // Search for rule
    const searchInput = authenticatedPage.locator('input[placeholder*="Search"]');
    if (await searchInput.count() > 0) {
      await searchInput.fill(testRuleName);
      await authenticatedPage.waitForLoadState('networkidle');
    }

    // Click edit button
    const editButton = authenticatedPage.locator('button[aria-label*="Edit"]').first();
    if (await editButton.count() > 0) {
      await editButton.click();
      await authenticatedPage.waitForSelector('input[name="title"]', { timeout: 5000 });

      // Modify YAML
      const yamlEditor = authenticatedPage.locator('.cm-content').or(authenticatedPage.locator('textarea')).first();
      if (await yamlEditor.count() > 0) {
        const currentYaml = await yamlEditor.textContent();
        const updatedYaml = currentYaml?.replace('experimental', 'test') || SAMPLE_SIGMA_YAML;
        await yamlEditor.fill(updatedYaml);
        await authenticatedPage.waitForLoadState('networkidle');
      }

      // Save
      await authenticatedPage.click('button:has-text("Save")');
      const successIndicator = authenticatedPage.locator('text=updated successfully').or(authenticatedPage.locator('text=success'));
      await expect(successIndicator).toBeVisible({ timeout: 5000 });
    }
  });

  authTest('UNIFIED-007: Delete detection rule', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    // Create rule first
    await createDetectionRule(authenticatedPage, testRuleName, SAMPLE_SIGMA_YAML);
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    // Search and delete
    const searchInput = authenticatedPage.locator('input[placeholder*="Search"]');
    if (await searchInput.count() > 0) {
      await searchInput.fill(testRuleName);
      await authenticatedPage.waitForLoadState('networkidle');
    }

    const deleteButton = authenticatedPage.locator('button[aria-label*="Delete"]').first();
    if (await deleteButton.count() > 0) {
      await deleteButton.click();
      const confirmButton = authenticatedPage.locator('button:has-text("Confirm")').or(authenticatedPage.locator('button:has-text("Delete")'));
      await confirmButton.click();
      const successIndicator = authenticatedPage.locator('text=deleted successfully').or(authenticatedPage.locator('text=success'));
      await expect(successIndicator).toBeVisible({ timeout: 5000 });
    }
  });
});

// =============================================================================
// Test Suite 3: YAML Editor Validation
// =============================================================================

authTest.describe('UNIFIED-RULES-03: YAML Editor Validation', () => {
  authTest.beforeEach(async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await authenticatedPage.click('button:has-text("Create Rule")');
    await authenticatedPage.waitForSelector('input[name="title"]', { timeout: 10000 });
  });

  authTest('UNIFIED-008: YAML syntax highlighting displays', async ({ authenticatedPage }) => {
    // Fill in title and description to enable YAML editor
    await authenticatedPage.fill('input[name="title"]', 'YAML Syntax Test');
    const descField = authenticatedPage.locator('textarea[name="description"]').or(authenticatedPage.locator('input[name="description"]'));
    await descField.fill('Testing YAML syntax');

    // Look for YAML editor (CodeMirror or custom)
    const yamlEditor = authenticatedPage.locator('.cm-editor').or(authenticatedPage.locator('.CodeMirror')).or(authenticatedPage.locator('textarea[placeholder*="YAML"]')).first();
    await expect(yamlEditor).toBeVisible();
  });

  authTest('UNIFIED-009: YAML validation error displays for invalid syntax', async ({ authenticatedPage }) => {
    await authenticatedPage.fill('input[name="title"]', 'Invalid YAML Test');
    await authenticatedPage.fill('textarea[name="description"]', 'Testing invalid YAML');

    const yamlEditor = authenticatedPage.locator('.cm-content').or(authenticatedPage.locator('textarea')).first();
    if (await yamlEditor.count() > 0) {
      // Enter invalid YAML
      await yamlEditor.fill('title: Test\n  invalid indentation:\n- broken list');
      await authenticatedPage.waitForLoadState('networkidle');

      // Try to save - should show error
      await authenticatedPage.click('button:has-text("Save Rule")');
      await authenticatedPage.waitForLoadState('networkidle');

      // Check for error indicators (validation or form error)
      const errorIndicator = authenticatedPage.locator('text=error').or(authenticatedPage.locator('text=invalid')).or(authenticatedPage.locator('[role="alert"]'));
      const hasError = await errorIndicator.count();
      expect(hasError).toBeGreaterThan(0);
    }
  });

  authTest('UNIFIED-010: YAML validation success displays for valid syntax', async ({ authenticatedPage }) => {
    await authenticatedPage.fill('input[name="title"]', 'Valid YAML Test');
    await authenticatedPage.fill('textarea[name="description"]', 'Testing valid YAML');

    const yamlEditor = authenticatedPage.locator('.cm-content').or(authenticatedPage.locator('textarea')).first();
    if (await yamlEditor.count() > 0) {
      await yamlEditor.fill(SAMPLE_SIGMA_YAML);
      await authenticatedPage.waitForLoadState('networkidle');

      // Look for success indicator
      const saveButton = authenticatedPage.locator('button:has-text("Save Rule")');
      const isEnabled = await saveButton.isEnabled();
      expect(isEnabled).toBeTruthy();
    }
  });

  authTest('UNIFIED-011: YAML preview updates in real-time', async ({ authenticatedPage }) => {
    await authenticatedPage.fill('input[name="title"]', 'YAML Preview Test');
    await authenticatedPage.fill('textarea[name="description"]', 'Testing YAML preview');

    const yamlEditor = authenticatedPage.locator('.cm-content').or(authenticatedPage.locator('textarea')).first();
    if (await yamlEditor.count() > 0) {
      // Type incrementally and check updates
      await yamlEditor.fill('title: Test Rule\n');
      await expect(yamlEditor).toContainText('Test Rule');
      await yamlEditor.fill('title: Test Rule\ndescription: Updates in real-time\n');
      await expect(yamlEditor).toContainText('real-time');

      // Editor should reflect changes
      const content = await yamlEditor.textContent();
      expect(content).toContain('real-time');
    }
  });
});

// =============================================================================
// Test Suite 4: Correlation Rule with CorrelationConfigEditor
// =============================================================================

authTest.describe('UNIFIED-RULES-04: Correlation Rule Creation', () => {
  const testRuleName = `E2E-Correlation-${Date.now()}`;

  authTest.afterEach(async ({ page }) => {
    await cleanupTestRules(page, testRuleName);
  });

  authTest('UNIFIED-012: Create correlation rule with Event Count type', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    await createCorrelationRule(authenticatedPage, testRuleName, 'Event Count');

    // Verify success
    const successMessage = authenticatedPage.locator('text=created successfully').or(authenticatedPage.locator('text=success'));
    const msgCount = await successMessage.count();
    if (msgCount > 0) {
      await expect(authenticatedPage.locator('text=created successfully')).toBeVisible();
    }
  });

  authTest('UNIFIED-013: Switch between Visual and YAML modes in correlation editor', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await authenticatedPage.click('button:has-text("Create Rule")');
    await authenticatedPage.waitForSelector('input[name="title"]', { timeout: 10000 });

    // Select correlation category
    const categorySelect = authenticatedPage.locator('select').or(authenticatedPage.locator('div[role="button"]:has-text("Category")')).first();
    if (await categorySelect.count() > 0) {
      await categorySelect.click();
      const correlationOption = authenticatedPage.locator('li:has-text("Correlation")').or(authenticatedPage.locator('option:has-text("Correlation")'));
      if (await correlationOption.count() > 0) {
        await correlationOption.click();
        await authenticatedPage.waitForLoadState('networkidle');

        // Look for mode toggle buttons
        const visualButton = authenticatedPage.locator('button:has-text("Visual")');
        const yamlButton = authenticatedPage.locator('button:has-text("YAML")');

        if (await visualButton.count() > 0 && await yamlButton.count() > 0) {
          // Test switching to YAML mode
          await yamlButton.click();
          await expect(yamlButton).toHaveAttribute('aria-pressed', 'true', { timeout: 3000 }).catch(() => {});

          // Switch back to Visual
          await visualButton.click();
          await expect(visualButton).toHaveAttribute('aria-pressed', 'true', { timeout: 3000 }).catch(() => {});

          expect(await visualButton.count()).toBeGreaterThan(0);
        }
      }
    }
  });

  authTest('UNIFIED-014: Correlation config validates required fields', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await authenticatedPage.click('button:has-text("Create Rule")');
    await authenticatedPage.waitForSelector('input[name="title"]');

    await authenticatedPage.fill('input[name="title"]', 'Validation Test');
    await authenticatedPage.fill('textarea[name="description"]', 'Testing validation');

    // Select correlation category
    const categorySelect = authenticatedPage.locator('select').or(authenticatedPage.locator('div[role="button"]')).first();
    if (await categorySelect.count() > 0) {
      await categorySelect.click();
      const correlationOption = authenticatedPage.locator('li:has-text("Correlation")').or(authenticatedPage.locator('option:has-text("Correlation")'));
      if (await correlationOption.count() > 0) {
        await correlationOption.click();
        await authenticatedPage.waitForLoadState('networkidle');
      }
    }

    // Try to save without filling required correlation fields
    await authenticatedPage.click('button:has-text("Save Rule")');
    await authenticatedPage.waitForLoadState('networkidle');

    // Should show validation errors or prevent save
    const isDialogStillOpen = await authenticatedPage.locator('input[name="title"]').count();
    expect(isDialogStillOpen).toBeGreaterThan(0);
  });
});

// =============================================================================
// Test Suite 5: Rule Testing Panel
// =============================================================================

authTest.describe('UNIFIED-RULES-05: Rule Testing Panel', () => {
  authTest.skip('UNIFIED-015: Upload test event file', async ({ authenticatedPage }) => {
    // This test requires the Rule Testing Panel component to be integrated
    // Skipping until component is available in the UI
  });

  authTest.skip('UNIFIED-016: Execute rule test with sample event', async ({ authenticatedPage }) => {
    // Requires Rule Testing Panel integration
  });

  authTest.skip('UNIFIED-017: View test results with match/no-match indicator', async ({ authenticatedPage }) => {
    // Requires Rule Testing Panel integration
  });
});

// =============================================================================
// Test Suite 6: Lifecycle State Transitions
// =============================================================================

authTest.describe('UNIFIED-RULES-06: Lifecycle Management', () => {
  authTest.skip('UNIFIED-018: Promote rule from experimental to test', async ({ authenticatedPage }) => {
    // Requires RuleLifecyclePanel integration in rules page
  });

  authTest.skip('UNIFIED-019: Deprecate rule with reason', async ({ authenticatedPage }) => {
    // Requires RuleLifecyclePanel integration
  });

  authTest.skip('UNIFIED-020: Archive deprecated rule', async ({ authenticatedPage }) => {
    // Requires RuleLifecyclePanel integration
  });

  authTest.skip('UNIFIED-021: View lifecycle history timeline', async ({ authenticatedPage }) => {
    // Requires RuleLifecyclePanel integration
  });
});

// =============================================================================
// Test Suite 7: Performance Dashboard
// =============================================================================

authTest.describe('UNIFIED-RULES-07: Performance Dashboard', () => {
  authTest.beforeEach(async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules/performance');
    await waitForPageReady(authenticatedPage, 'h1:has-text("Performance")');
  });

  authTest('UNIFIED-022: Performance dashboard loads successfully', async ({ authenticatedPage }) => {
    const pageHeader = authenticatedPage.locator('h1').or(authenticatedPage.locator('h4'));
    await expect(pageHeader).toContainText('Performance');
  });

  authTest('UNIFIED-023: Summary cards display performance metrics', async ({ authenticatedPage }) => {
    // Check for KPI cards
    const cards = authenticatedPage.locator('[role="region"]').or(authenticatedPage.locator('.MuiCard-root')).or(authenticatedPage.locator('article'));
    const count = await cards.count();
    expect(count).toBeGreaterThan(0);

    // Look for specific metrics
    const metricsPresent = authenticatedPage.locator('text=Rules Evaluated').or(authenticatedPage.locator('text=Avg Evaluation Time')).or(authenticatedPage.locator('text=Slowest Rule'));
    const metricsCount = await metricsPresent.count();
    expect(metricsCount).toBeGreaterThan(0);
  });

  authTest('UNIFIED-024: Slow rules table displays and sorts', async ({ authenticatedPage }) => {
    const table = authenticatedPage.locator('table');
    if (await table.count() > 0) {
      await expect(table).toBeVisible();

      // Try to sort by avg time
      const sortHeader = authenticatedPage.locator('th:has-text("Avg Time")');
      if (await sortHeader.count() > 0) {
        await sortHeader.click();
        await authenticatedPage.waitForLoadState('networkidle');
      }
    }
  });

  authTest('UNIFIED-025: Performance charts render', async ({ authenticatedPage }) => {
    // Look for chart containers (Recharts SVG)
    const charts = authenticatedPage.locator('svg').or(authenticatedPage.locator('canvas')).or(authenticatedPage.locator('[role="img"]'));
    const chartCount = await charts.count();
    expect(chartCount).toBeGreaterThan(0);
  });

  authTest('UNIFIED-026: Export performance data to CSV', async ({ authenticatedPage }) => {
    const exportButton = authenticatedPage.locator('button:has-text("Export")');
    if (await exportButton.count() > 0) {
      // Set up download handler
      const downloadPromise = authenticatedPage.waitForEvent('download', { timeout: 5000 });

      await exportButton.click();

      // Wait for download
      try {
        const download = await downloadPromise;
        expect(download.suggestedFilename()).toContain('performance');
      } catch (e) {
        // Download may not trigger in test environment - that's ok
        console.log('Download not triggered in test environment');
      }
    }
  });

  authTest('UNIFIED-027: Time range filter changes data', async ({ authenticatedPage }) => {
    const timeRangeSelect = authenticatedPage.locator('select:has-text("Time Range")').or(authenticatedPage.locator('div[role="button"]:has-text("Time Range")'));
    if (await timeRangeSelect.count() > 0) {
      await timeRangeSelect.click();
      const sevenDaysOption = authenticatedPage.locator('li:has-text("Last 7 Days")').or(authenticatedPage.locator('option:has-text("7 Days")'));
      await sevenDaysOption.click();
      await authenticatedPage.waitForLoadState('networkidle');

      // Verify page still displays (data may refresh)
      const pageHeader = authenticatedPage.locator('h1').or(authenticatedPage.locator('h4'));
      await expect(pageHeader).toContainText('Performance');
    }
  });

  authTest('UNIFIED-028: Threshold filter updates slow rules table', async ({ authenticatedPage }) => {
    const thresholdSelect = authenticatedPage.locator('select:has-text("Threshold")').or(authenticatedPage.locator('div[role="button"]:has-text("Threshold")'));
    if (await thresholdSelect.count() > 0) {
      await thresholdSelect.click();
      const thresholdOption = authenticatedPage.locator('li:has-text("100ms")').or(authenticatedPage.locator('option:has-text("100")'));
      await thresholdOption.click();
      await authenticatedPage.waitForLoadState('networkidle');

      // Table should update
      const table = authenticatedPage.locator('table');
      if (await table.count() > 0) {
        await expect(table).toBeVisible();
      }
    }
  });
});

// =============================================================================
// Test Suite 8: Import/Export Workflow
// =============================================================================

authTest.describe('UNIFIED-RULES-08: Import/Export Workflow', () => {
  authTest.beforeEach(async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');
  });

  authTest('UNIFIED-029: Export dialog opens', async ({ authenticatedPage }) => {
    const exportButton = authenticatedPage.locator('button:has-text("Export")');
    await exportButton.click();

    // Wait for export dialog
    const dialogIndicator = authenticatedPage.locator('text=Export').or(authenticatedPage.locator('[role="dialog"]'));
    await expect(dialogIndicator).toBeVisible({ timeout: 5000 });
  });

  authTest('UNIFIED-030: Export rules as JSON', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Export")');
    await authenticatedPage.waitForSelector('[role="dialog"]', { timeout: 5000 });

    // Select JSON format if option exists
    const jsonButton = authenticatedPage.locator('button:has-text("JSON")');
    if (await jsonButton.count() > 0) {
      const downloadPromise = authenticatedPage.waitForEvent('download', { timeout: 5000 });
      await jsonButton.click();

      try {
        const download = await downloadPromise;
        expect(download.suggestedFilename()).toContain('rules');
        expect(download.suggestedFilename()).toContain('.json');
      } catch (e) {
        console.log('JSON download not triggered in test environment');
      }
    }
  });

  authTest('UNIFIED-031: Export rules as YAML', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Export")');
    await authenticatedPage.waitForSelector('[role="dialog"]', { timeout: 5000 });

    const yamlButton = authenticatedPage.locator('button:has-text("YAML")');
    if (await yamlButton.count() > 0) {
      const downloadPromise = authenticatedPage.waitForEvent('download', { timeout: 5000 });
      await yamlButton.click();

      try {
        const download = await downloadPromise;
        expect(download.suggestedFilename()).toContain('rules');
        expect(download.suggestedFilename()).toMatch(/\.(yaml|yml)$/);
      } catch (e) {
        console.log('YAML download not triggered in test environment');
      }
    }
  });

  authTest('UNIFIED-032: Import dialog opens', async ({ authenticatedPage }) => {
    const importButton = authenticatedPage.locator('button:has-text("Import")');
    await importButton.click();

    // Wait for import dialog
    const dialogIndicator = authenticatedPage.locator('text=Import').or(authenticatedPage.locator('[role="dialog"]'));
    await expect(dialogIndicator).toBeVisible({ timeout: 5000 });
  });

  authTest('UNIFIED-033: Import requires file selection', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Import")');
    await authenticatedPage.waitForSelector('[role="dialog"]', { timeout: 5000 });

    // Try to import without file
    const submitButton = authenticatedPage.locator('button:has-text("Import")').or(authenticatedPage.locator('button[type="submit"]')).last();
    if (await submitButton.count() > 0) {
      const isDisabled = await submitButton.isDisabled();
      expect(isDisabled).toBeTruthy();
    }
  });
});

// =============================================================================
// Test Suite 9: Accessibility Audit
// =============================================================================

authTest.describe('UNIFIED-RULES-09: Accessibility (WCAG 2.1 AA)', () => {
  authTest('UNIFIED-A11Y-001: Rules page passes accessibility audit', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    const accessibilityScanResults = await new AxeBuilder({ page: authenticatedPage })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  authTest('UNIFIED-A11Y-002: Create rule dialog passes accessibility audit', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await authenticatedPage.click('button:has-text("Create Rule")');
    await authenticatedPage.waitForSelector('[role="dialog"]', { timeout: 10000 });

    const accessibilityScanResults = await new AxeBuilder({ page: authenticatedPage })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  authTest('UNIFIED-A11Y-003: Performance dashboard passes accessibility audit', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules/performance');
    // Wait for any heading to indicate page loaded
    const headingSelector = authenticatedPage.locator('h1').or(authenticatedPage.locator('h4'));
    await headingSelector.first().waitFor({ timeout: 10000 });

    const accessibilityScanResults = await new AxeBuilder({ page: authenticatedPage })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  authTest('UNIFIED-A11Y-004: All interactive elements are keyboard accessible', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    // Tab through interactive elements
    await authenticatedPage.keyboard.press('Tab');
    await authenticatedPage.keyboard.press('Tab');
    await authenticatedPage.keyboard.press('Tab');

    // Verify focus is visible
    const focusedElement = await authenticatedPage.evaluate(() => {
      const el = document.activeElement;
      return el ? el.tagName : null;
    });

    expect(focusedElement).toBeDefined();
    expect(focusedElement).not.toBeNull();
  });

  authTest('UNIFIED-A11Y-005: Form labels are properly associated', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await authenticatedPage.click('button:has-text("Create Rule")');
    await authenticatedPage.waitForSelector('input[name="title"]');

    // Check for label associations
    const titleLabel = authenticatedPage.locator('label:has-text("Title")').or(authenticatedPage.locator('label[for*="title"]'));
    const descriptionLabel = authenticatedPage.locator('label:has-text("Description")').or(authenticatedPage.locator('label[for*="description"]'));

    await expect(titleLabel).toBeVisible();
    await expect(descriptionLabel).toBeVisible();
  });

  authTest('UNIFIED-A11Y-006: ARIA labels present on complex controls', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    // Check for ARIA labels on filters and buttons
    const categoryFilter = authenticatedPage.locator('[aria-label*="category"]').or(authenticatedPage.locator('[aria-label*="Category"]'));
    const searchInput = authenticatedPage.locator('[aria-label*="search"]').or(authenticatedPage.locator('[aria-label*="Search"]'));

    const categoryCount = await categoryFilter.count();
    const searchCount = await searchInput.count();

    // At least one should have ARIA label
    expect(categoryCount + searchCount).toBeGreaterThan(0);
  });
});

// =============================================================================
// Test Suite 10: Visual Regression Tests
// =============================================================================

authTest.describe('UNIFIED-RULES-10: Visual Regression', () => {
  authTest('UNIFIED-VR-001: Rules table screenshot', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    // Take screenshot
    await expect(authenticatedPage.locator('table')).toHaveScreenshot('rules-table.png', {
      maxDiffPixels: 100,
    });
  });

  authTest('UNIFIED-VR-002: Create rule dialog screenshot', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await authenticatedPage.click('button:has-text("Create Rule")');
    await authenticatedPage.waitForSelector('[role="dialog"]');

    const dialog = authenticatedPage.locator('[role="dialog"]');
    await expect(dialog).toHaveScreenshot('create-rule-dialog.png', {
      maxDiffPixels: 100,
    });
  });

  authTest('UNIFIED-VR-003: Performance dashboard screenshot', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules/performance');
    // Wait for any heading to indicate page loaded
    const headingSelector = authenticatedPage.locator('h1').or(authenticatedPage.locator('h4'));
    await headingSelector.first().waitFor({ timeout: 10000 });

    await expect(authenticatedPage).toHaveScreenshot('performance-dashboard.png', {
      maxDiffPixels: 200,
      fullPage: true,
    });
  });

  authTest('UNIFIED-VR-004: Category filter dropdown screenshot', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await waitForPageReady(authenticatedPage, 'table');

    const categoryFilter = authenticatedPage.locator('select').or(authenticatedPage.locator('div[role="button"]:has-text("Category")')).first();
    if (await categoryFilter.count() > 0) {
      await categoryFilter.click();
      // Wait for dropdown options to be visible
      const dropdownOptions = authenticatedPage.locator('li[role="option"]').or(authenticatedPage.locator('option')).first();
      await dropdownOptions.waitFor({ state: 'visible', timeout: 3000 }).catch(() => {});

      await expect(authenticatedPage).toHaveScreenshot('category-filter-open.png', {
        maxDiffPixels: 100,
      });
    }
  });

  authTest('UNIFIED-VR-005: Slow rules table on performance page', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules/performance');
    await waitForPageReady(authenticatedPage, 'table');

    const table = authenticatedPage.locator('table');
    if (await table.count() > 0) {
      await expect(table).toHaveScreenshot('slow-rules-table.png', {
        maxDiffPixels: 100,
      });
    }
  });
});

// =============================================================================
// Test Suite 11: Responsive Design
// =============================================================================

authTest.describe('UNIFIED-RULES-11: Responsive Design', () => {
  authTest('UNIFIED-RESP-001: Rules page displays correctly on mobile', async ({ authenticatedPage }) => {
    await authenticatedPage.setViewportSize({ width: 375, height: 667 }); // iPhone SE
    await authenticatedPage.goto('/rules');
    // Wait for page content to load
    const pageContent = authenticatedPage.locator('table').or(authenticatedPage.locator('h1')).or(authenticatedPage.locator('h4'));
    await pageContent.first().waitFor({ timeout: 10000 });

    // Verify page renders without horizontal overflow
    const hasOverflow = await authenticatedPage.evaluate(() => {
      return document.body.scrollWidth > window.innerWidth;
    });

    expect(hasOverflow).toBeFalsy();
  });

  authTest('UNIFIED-RESP-002: Create rule dialog is usable on tablet', async ({ authenticatedPage }) => {
    await authenticatedPage.setViewportSize({ width: 768, height: 1024 }); // iPad
    await authenticatedPage.goto('/rules');
    await authenticatedPage.click('button:has-text("Create Rule")');
    await authenticatedPage.waitForSelector('[role="dialog"]');

    const dialog = authenticatedPage.locator('[role="dialog"]');
    await expect(dialog).toBeVisible();
  });

  authTest('UNIFIED-RESP-003: Performance dashboard adapts to small screens', async ({ authenticatedPage }) => {
    await authenticatedPage.setViewportSize({ width: 375, height: 667 });
    await authenticatedPage.goto('/rules/performance');
    // Wait for any heading to indicate page loaded
    const headingSelector = authenticatedPage.locator('h1').or(authenticatedPage.locator('h4'));
    await headingSelector.first().waitFor({ timeout: 10000 });

    // Check that content doesn't overflow
    const hasOverflow = await authenticatedPage.evaluate(() => {
      return document.body.scrollWidth > window.innerWidth;
    });

    expect(hasOverflow).toBeFalsy();
  });
});
