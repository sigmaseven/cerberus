/**
 * Correlation Rules Page Object Model
 * Uses data-testid selectors exclusively.
 */

import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export class CorrelationRulesPage extends BasePage {
  private readonly TEST_IDS = {
    pageTitle: 'correlation-rules-page-title',
    createButton: 'create-correlation-rule-button',
    searchInput: 'correlation-rules-search-input',
    ruleRow: 'correlation-rule-row',
    editButton: 'edit-correlation-rule-button',
    deleteButton: 'delete-correlation-rule-button',
    toggleButton: 'toggle-correlation-rule-button',
    ruleDialog: 'correlation-rule-dialog',
    ruleNameInput: 'correlation-rule-name-input',
    ruleDescriptionInput: 'correlation-rule-description-input',
    windowInput: 'correlation-window-input',
    saveButton: 'save-correlation-rule-button',
    cancelButton: 'cancel-button',
    deleteDialog: 'delete-confirmation-dialog',
    confirmDeleteButton: 'confirm-delete-button',
    emptyState: 'correlation-rules-empty-state',
    errorAlert: 'correlation-rules-error-alert',
  };

  constructor(page: Page) {
    super(page, '/correlation-rules');
  }

  async verifyPageLoaded(): Promise<void> {
    await this.waitForTestId(this.TEST_IDS.pageTitle);
    await expect(this.page).toHaveURL(/\/correlation-rules/);
  }

  async clickCreateRule(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.createButton);
    await this.waitForTestId(this.TEST_IDS.ruleDialog);
  }

  async getRuleCount(): Promise<number> {
    const rows = this.page.locator(`[data-testid="${this.TEST_IDS.ruleRow}"]`);
    return await rows.count();
  }

  async editRule(ruleId: string): Promise<void> {
    const row = this.page.locator(`[data-testid="${this.TEST_IDS.ruleRow}"][data-rule-id="${ruleId}"]`);
    await row.locator(`[data-testid="${this.TEST_IDS.editButton}"]`).click();
    await this.waitForTestId(this.TEST_IDS.ruleDialog);
  }

  async deleteRule(ruleId: string): Promise<void> {
    const row = this.page.locator(`[data-testid="${this.TEST_IDS.ruleRow}"][data-rule-id="${ruleId}"]`);
    await row.locator(`[data-testid="${this.TEST_IDS.deleteButton}"]`).click();
    await this.waitForTestId(this.TEST_IDS.deleteDialog);
    await this.clickByTestId(this.TEST_IDS.confirmDeleteButton);
    await this.waitForLoadingComplete();
  }
}
