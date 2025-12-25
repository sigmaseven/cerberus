/**
 * Investigations Page Object Model
 * Uses data-testid selectors exclusively.
 */

import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export class InvestigationsPage extends BasePage {
  private readonly TEST_IDS = {
    pageTitle: 'investigations-page-title',
    createButton: 'create-investigation-button',
    searchInput: 'investigations-search-input',
    filterStatus: 'filter-status',
    filterPriority: 'filter-priority',
    investigationCard: 'investigation-card',
    viewButton: 'view-investigation-button',
    updateStatusButton: 'update-status-button',
    addNoteButton: 'add-note-button',
    investigationDialog: 'investigation-dialog',
    titleInput: 'investigation-title-input',
    descriptionInput: 'investigation-description-input',
    prioritySelect: 'investigation-priority-select',
    saveButton: 'save-investigation-button',
    cancelButton: 'cancel-button',
    emptyState: 'investigations-empty-state',
    errorAlert: 'investigations-error-alert',
  };

  constructor(page: Page) {
    super(page, '/investigations');
  }

  async verifyPageLoaded(): Promise<void> {
    await this.waitForTestId(this.TEST_IDS.pageTitle);
    await expect(this.page).toHaveURL(/\/investigations/);
  }

  async clickCreateInvestigation(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.createButton);
    await this.waitForTestId(this.TEST_IDS.investigationDialog);
  }

  async getInvestigationCount(): Promise<number> {
    const cards = this.page.locator(`[data-testid="${this.TEST_IDS.investigationCard}"]`);
    return await cards.count();
  }

  async viewInvestigation(investigationId: string): Promise<void> {
    const card = this.page.locator(`[data-testid="${this.TEST_IDS.investigationCard}"][data-investigation-id="${investigationId}"]`);
    await card.locator(`[data-testid="${this.TEST_IDS.viewButton}"]`).click();
    await this.page.waitForURL(new RegExp(`/investigations/${investigationId}`));
  }

  async filterByStatus(status: string): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.filterStatus);
    await this.page.locator(`[data-value="${status}"]`).click();
    await this.waitForLoadingComplete();
  }
}
