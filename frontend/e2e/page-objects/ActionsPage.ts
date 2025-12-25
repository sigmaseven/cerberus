/**
 * Actions Page Object Model
 * Uses data-testid selectors exclusively.
 */

import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export class ActionsPage extends BasePage {
  private readonly TEST_IDS = {
    pageTitle: 'actions-page-title',
    createActionButton: 'create-action-button',
    searchInput: 'actions-search-input',
    actionCard: 'action-card',
    configureButton: 'configure-action-button',
    deleteButton: 'delete-action-button',
    testButton: 'test-action-button',
    actionDialog: 'action-dialog',
    actionTypeSelect: 'action-type-select',
    actionConfigInput: 'action-config-input',
    saveButton: 'save-action-button',
    cancelButton: 'cancel-button',
    deleteDialog: 'delete-confirmation-dialog',
    confirmDeleteButton: 'confirm-delete-button',
    emptyState: 'actions-empty-state',
    errorAlert: 'actions-error-alert',
  };

  constructor(page: Page) {
    super(page, '/actions');
  }

  async verifyPageLoaded(): Promise<void> {
    await this.waitForTestId(this.TEST_IDS.pageTitle);
    await expect(this.page).toHaveURL(/\/actions/);
  }

  async clickCreateAction(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.createActionButton);
    await this.waitForTestId(this.TEST_IDS.actionDialog);
  }

  async searchActions(query: string): Promise<void> {
    await this.fillByTestId(this.TEST_IDS.searchInput, query);
    await this.waitForLoadingComplete();
  }

  async getActionCount(): Promise<number> {
    const cards = this.page.locator(`[data-testid="${this.TEST_IDS.actionCard}"]`);
    return await cards.count();
  }

  async configureAction(actionId: string): Promise<void> {
    const card = this.page.locator(`[data-testid="${this.TEST_IDS.actionCard}"][data-action-id="${actionId}"]`);
    await card.locator(`[data-testid="${this.TEST_IDS.configureButton}"]`).click();
    await this.waitForTestId(this.TEST_IDS.actionDialog);
  }

  async deleteAction(actionId: string): Promise<void> {
    const card = this.page.locator(`[data-testid="${this.TEST_IDS.actionCard}"][data-action-id="${actionId}"]`);
    await card.locator(`[data-testid="${this.TEST_IDS.deleteButton}"]`).click();
    await this.waitForTestId(this.TEST_IDS.deleteDialog);
    await this.clickByTestId(this.TEST_IDS.confirmDeleteButton);
    await this.waitForLoadingComplete();
  }
}
