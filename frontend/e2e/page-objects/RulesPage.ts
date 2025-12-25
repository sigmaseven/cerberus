/**
 * Rules Page Object Model
 *
 * Encapsulates all Rules page interactions.
 * Uses data-testid selectors exclusively for stability.
 * Tests against real backend - no mocks.
 */

import { Page, expect, Locator } from '@playwright/test';
import { BasePage } from './BasePage';

export interface RuleData {
  name: string;
  description: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  enabled: boolean;
}

export class RulesPage extends BasePage {
  private readonly TEST_IDS = {
    // Page elements
    pageTitle: 'rules-page-title',
    createRuleButton: 'create-rule-button',
    searchInput: 'rules-search-input',
    filterSeverity: 'filter-severity',
    filterEnabled: 'filter-enabled',

    // Table
    rulesTable: 'rules-table',
    ruleRow: 'rule-row',
    ruleNameCell: 'rule-name-cell',
    ruleSeverityCell: 'rule-severity-cell',
    ruleEnabledCell: 'rule-enabled-cell',

    // Actions
    editRuleButton: 'edit-rule-button',
    deleteRuleButton: 'delete-rule-button',
    toggleRuleButton: 'toggle-rule-button',
    duplicateRuleButton: 'duplicate-rule-button',

    // Dialog/Modal
    ruleDialog: 'rule-dialog',
    ruleDialogTitle: 'rule-dialog-title',
    ruleNameInput: 'rule-name-input',
    ruleDescriptionInput: 'rule-description-input',
    ruleSeveritySelect: 'rule-severity-select',
    ruleEnabledToggle: 'rule-enabled-toggle',
    addConditionButton: 'add-condition-button',
    saveRuleButton: 'save-rule-button',
    cancelButton: 'cancel-button',

    // Delete confirmation
    deleteDialog: 'delete-confirmation-dialog',
    confirmDeleteButton: 'confirm-delete-button',
    cancelDeleteButton: 'cancel-delete-button',

    // Empty state
    emptyState: 'rules-empty-state',
    emptyStateMessage: 'rules-empty-state-message',

    // Error state
    errorAlert: 'rules-error-alert',
    errorMessage: 'rules-error-message',
  };

  constructor(page: Page) {
    super(page, '/rules');
  }

  /**
   * Verify rules page is loaded
   */
  async verifyPageLoaded(): Promise<void> {
    await this.waitForTestId(this.TEST_IDS.pageTitle);
    await expect(this.page).toHaveURL(/\/rules/);
  }

  /**
   * Click create rule button
   */
  async clickCreateRule(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.createRuleButton);
    await this.waitForTestId(this.TEST_IDS.ruleDialog);
  }

  /**
   * Search for rules
   */
  async searchRules(query: string): Promise<void> {
    await this.fillByTestId(this.TEST_IDS.searchInput, query);
    await this.waitForLoadingComplete();
  }

  /**
   * Filter by severity
   */
  async filterBySeverity(severity: string): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.filterSeverity);
    await this.page.locator(`[data-value="${severity}"]`).click();
    await this.waitForLoadingComplete();
  }

  /**
   * Filter by enabled status
   */
  async filterByEnabled(enabled: boolean): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.filterEnabled);
    await this.page.locator(`[data-value="${enabled}"]`).click();
    await this.waitForLoadingComplete();
  }

  /**
   * Get rule row by name
   */
  getRuleRow(ruleName: string): Locator {
    return this.page.locator(`[data-testid="${this.TEST_IDS.ruleRow}"][data-rule-name="${ruleName}"]`);
  }

  /**
   * Verify rule exists in table
   */
  async verifyRuleExists(ruleName: string): Promise<void> {
    const row = this.getRuleRow(ruleName);
    await expect(row).toBeVisible();
  }

  /**
   * Verify rule does not exist in table
   */
  async verifyRuleNotExists(ruleName: string): Promise<void> {
    const row = this.getRuleRow(ruleName);
    await expect(row).not.toBeVisible();
  }

  /**
   * Get number of rules in table
   */
  async getRuleCount(): Promise<number> {
    const rows = this.page.locator(`[data-testid="${this.TEST_IDS.ruleRow}"]`);
    return await rows.count();
  }

  /**
   * Click edit button for specific rule
   */
  async clickEditRule(ruleName: string): Promise<void> {
    const row = this.getRuleRow(ruleName);
    await row.locator(`[data-testid="${this.TEST_IDS.editRuleButton}"]`).click();
    await this.waitForTestId(this.TEST_IDS.ruleDialog);
  }

  /**
   * Click delete button for specific rule
   */
  async clickDeleteRule(ruleName: string): Promise<void> {
    const row = this.getRuleRow(ruleName);
    await row.locator(`[data-testid="${this.TEST_IDS.deleteRuleButton}"]`).click();
    await this.waitForTestId(this.TEST_IDS.deleteDialog);
  }

  /**
   * Confirm delete in dialog
   */
  async confirmDelete(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.confirmDeleteButton);
    await this.waitForLoadingComplete();
  }

  /**
   * Cancel delete in dialog
   */
  async cancelDelete(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.cancelDeleteButton);
    const deleteDialog = this.getByTestId(this.TEST_IDS.deleteDialog);
    await expect(deleteDialog).not.toBeVisible();
  }

  /**
   * Toggle rule enabled/disabled
   */
  async toggleRule(ruleName: string): Promise<void> {
    const row = this.getRuleRow(ruleName);
    await row.locator(`[data-testid="${this.TEST_IDS.toggleRuleButton}"]`).click();
    await this.waitForLoadingComplete();
  }

  /**
   * Duplicate rule
   */
  async duplicateRule(ruleName: string): Promise<void> {
    const row = this.getRuleRow(ruleName);
    await row.locator(`[data-testid="${this.TEST_IDS.duplicateRuleButton}"]`).click();
    await this.waitForTestId(this.TEST_IDS.ruleDialog);
  }

  /**
   * Fill rule form
   */
  async fillRuleForm(ruleData: RuleData): Promise<void> {
    await this.fillByTestId(this.TEST_IDS.ruleNameInput, ruleData.name);
    await this.fillByTestId(this.TEST_IDS.ruleDescriptionInput, ruleData.description);

    // Select severity
    await this.clickByTestId(this.TEST_IDS.ruleSeveritySelect);
    await this.page.locator(`[data-value="${ruleData.severity}"]`).click();

    // Toggle enabled if needed
    const enabledToggle = this.getByTestId(this.TEST_IDS.ruleEnabledToggle);
    const isChecked = await enabledToggle.isChecked();
    if (isChecked !== ruleData.enabled) {
      await this.clickByTestId(this.TEST_IDS.ruleEnabledToggle);
    }
  }

  /**
   * Save rule form
   */
  async saveRule(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.saveRuleButton);
    await this.waitForLoadingComplete();

    // Wait for dialog to close
    const dialog = this.getByTestId(this.TEST_IDS.ruleDialog);
    await expect(dialog).not.toBeVisible({ timeout: 5000 });
  }

  /**
   * Cancel rule form
   */
  async cancelRuleForm(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.cancelButton);
    const dialog = this.getByTestId(this.TEST_IDS.ruleDialog);
    await expect(dialog).not.toBeVisible();
  }

  /**
   * Create a new rule (full flow)
   */
  async createRule(ruleData: RuleData): Promise<void> {
    await this.clickCreateRule();
    await this.fillRuleForm(ruleData);
    await this.saveRule();
    await this.verifyNotification('Rule created successfully');
  }

  /**
   * Edit an existing rule (full flow)
   */
  async editRule(ruleName: string, newData: Partial<RuleData>): Promise<void> {
    await this.clickEditRule(ruleName);

    if (newData.name) {
      await this.fillByTestId(this.TEST_IDS.ruleNameInput, newData.name);
    }
    if (newData.description) {
      await this.fillByTestId(this.TEST_IDS.ruleDescriptionInput, newData.description);
    }
    if (newData.severity) {
      await this.clickByTestId(this.TEST_IDS.ruleSeveritySelect);
      await this.page.locator(`[data-value="${newData.severity}"]`).click();
    }

    await this.saveRule();
    await this.verifyNotification('Rule updated successfully');
  }

  /**
   * Delete a rule (full flow)
   */
  async deleteRule(ruleName: string): Promise<void> {
    await this.clickDeleteRule(ruleName);
    await this.confirmDelete();
    await this.verifyNotification('Rule deleted successfully');
    await this.verifyRuleNotExists(ruleName);
  }

  /**
   * Verify empty state is shown
   */
  async verifyEmptyState(): Promise<void> {
    await expect(this.getByTestId(this.TEST_IDS.emptyState)).toBeVisible();
    await expect(this.getByTestId(this.TEST_IDS.emptyStateMessage)).toBeVisible();
  }

  /**
   * Verify error is shown
   */
  async verifyErrorShown(message?: string): Promise<void> {
    await expect(this.getByTestId(this.TEST_IDS.errorAlert)).toBeVisible();

    if (message) {
      const errorText = await this.getTextByTestId(this.TEST_IDS.errorMessage);
      expect(errorText).toContain(message);
    }
  }

  /**
   * Verify form validation errors
   */
  async verifyFormValidation(): Promise<void> {
    await this.clickCreateRule();
    await this.clickByTestId(this.TEST_IDS.saveRuleButton);

    // Should show validation errors for required fields
    const nameInput = this.getByTestId(this.TEST_IDS.ruleNameInput);
    const hasError = await nameInput.evaluate((el) => {
      return el.getAttribute('aria-invalid') === 'true' ||
             el.closest('.Mui-error') !== null;
    });

    expect(hasError).toBe(true);
  }

  /**
   * Verify accessibility
   */
  async verifyAccessibility(): Promise<void> {
    await super.verifyAccessibility();

    // Verify table has proper ARIA labels
    const table = this.getByTestId(this.TEST_IDS.rulesTable);
    const ariaLabel = await table.getAttribute('aria-label');
    expect(ariaLabel || await table.getAttribute('aria-labelledby')).toBeTruthy();

    // Verify action buttons have labels
    const createButton = this.getByTestId(this.TEST_IDS.createRuleButton);
    const buttonLabel = await createButton.getAttribute('aria-label');
    expect(buttonLabel || await createButton.textContent()).toBeTruthy();
  }
}
