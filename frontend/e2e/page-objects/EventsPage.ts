/**
 * Events Page Object Model
 * Uses data-testid selectors exclusively.
 */

import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export class EventsPage extends BasePage {
  private readonly TEST_IDS = {
    pageTitle: 'events-page-title',
    searchInput: 'events-search-input',
    cqlQueryInput: 'cql-query-input',
    searchButton: 'search-button',
    eventsTable: 'events-table',
    eventRow: 'event-row',
    viewEventButton: 'view-event-button',
    exportButton: 'export-events-button',
    timeRangeSelector: 'time-range-selector',
    fromDateInput: 'from-date-input',
    toDateInput: 'to-date-input',
    eventDialog: 'event-detail-dialog',
    closeDialog: 'close-dialog-button',
    emptyState: 'events-empty-state',
    errorAlert: 'events-error-alert',
    paginationNext: 'pagination-next',
    paginationPrev: 'pagination-prev',
  };

  constructor(page: Page) {
    super(page, '/events');
  }

  async verifyPageLoaded(): Promise<void> {
    await this.waitForTestId(this.TEST_IDS.pageTitle);
    await expect(this.page).toHaveURL(/\/events/);
  }

  async searchByCQL(query: string): Promise<void> {
    await this.fillByTestId(this.TEST_IDS.cqlQueryInput, query);
    await this.clickByTestId(this.TEST_IDS.searchButton);
    await this.waitForLoadingComplete();
  }

  async getEventCount(): Promise<number> {
    const rows = this.page.locator(`[data-testid="${this.TEST_IDS.eventRow}"]`);
    return await rows.count();
  }

  async viewEvent(eventId: string): Promise<void> {
    const row = this.page.locator(`[data-testid="${this.TEST_IDS.eventRow}"][data-event-id="${eventId}"]`);
    await row.locator(`[data-testid="${this.TEST_IDS.viewEventButton}"]`).click();
    await this.waitForTestId(this.TEST_IDS.eventDialog);
  }

  async setTimeRange(from: string, to: string): Promise<void> {
    await this.fillByTestId(this.TEST_IDS.fromDateInput, from);
    await this.fillByTestId(this.TEST_IDS.toDateInput, to);
  }

  async exportEvents(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.exportButton);
  }

  async nextPage(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.paginationNext);
    await this.waitForLoadingComplete();
  }

  async previousPage(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.paginationPrev);
    await this.waitForLoadingComplete();
  }
}
