/**
 * Alerts Page Object Model
 *
 * Uses data-testid selectors exclusively.
 * Tests against real backend - no mocks.
 */

import { Page, expect, Locator } from '@playwright/test';
import { BasePage } from './BasePage';

export class AlertsPage extends BasePage {
  private readonly TEST_IDS = {
    pageTitle: 'alerts-page-title',
    searchInput: 'alerts-search-input',
    filterSeverity: 'filter-severity',
    filterStatus: 'filter-status',
    alertsTable: 'alerts-table',
    alertRow: 'alert-row',
    viewAlertButton: 'view-alert-button',
    ackAlertButton: 'acknowledge-alert-button',
    dismissAlertButton: 'dismiss-alert-button',
    bulkAckButton: 'bulk-acknowledge-button',
    bulkDismissButton: 'bulk-dismiss-button',
    exportButton: 'export-csv-button',
    alertDialog: 'alert-detail-dialog',
    closeDialog: 'close-dialog-button',
    emptyState: 'alerts-empty-state',
    errorAlert: 'alerts-error-alert',
  };

  constructor(page: Page) {
    super(page, '/alerts');
  }

  async verifyPageLoaded(): Promise<void> {
    await this.waitForTestId(this.TEST_IDS.pageTitle);
    await expect(this.page).toHaveURL(/\/alerts/);
  }

  async searchAlerts(query: string): Promise<void> {
    await this.fillByTestId(this.TEST_IDS.searchInput, query);
    await this.waitForLoadingComplete();
  }

  async filterBySeverity(severity: string): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.filterSeverity);
    await this.page.locator(`[data-value="${severity}"]`).click();
    await this.waitForLoadingComplete();
  }

  async filterByStatus(status: string): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.filterStatus);
    await this.page.locator(`[data-value="${status}"]`).click();
    await this.waitForLoadingComplete();
  }

  getAlertRow(alertId: string): Locator {
    return this.page.locator(`[data-testid="${this.TEST_IDS.alertRow}"][data-alert-id="${alertId}"]`);
  }

  async getAlertCount(): Promise<number> {
    const rows = this.page.locator(`[data-testid="${this.TEST_IDS.alertRow}"]`);
    return await rows.count();
  }

  async viewAlert(alertId: string): Promise<void> {
    const row = this.getAlertRow(alertId);
    await row.locator(`[data-testid="${this.TEST_IDS.viewAlertButton}"]`).click();
    await this.waitForTestId(this.TEST_IDS.alertDialog);
  }

  async acknowledgeAlert(alertId: string): Promise<void> {
    const row = this.getAlertRow(alertId);
    await row.locator(`[data-testid="${this.TEST_IDS.ackAlertButton}"]`).click();
    await this.waitForLoadingComplete();
  }

  async dismissAlert(alertId: string): Promise<void> {
    const row = this.getAlertRow(alertId);
    await row.locator(`[data-testid="${this.TEST_IDS.dismissAlertButton}"]`).click();
    await this.waitForLoadingComplete();
  }

  async closeAlertDialog(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.closeDialog);
    const dialog = this.getByTestId(this.TEST_IDS.alertDialog);
    await expect(dialog).not.toBeVisible();
  }

  async bulkAcknowledge(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.bulkAckButton);
    await this.waitForLoadingComplete();
  }

  async bulkDismiss(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.bulkDismissButton);
    await this.waitForLoadingComplete();
  }

  async exportCSV(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.exportButton);
  }

  async verifyEmptyState(): Promise<void> {
    await expect(this.getByTestId(this.TEST_IDS.emptyState)).toBeVisible();
  }

  async verifyErrorShown(): Promise<void> {
    await expect(this.getByTestId(this.TEST_IDS.errorAlert)).toBeVisible();
  }
}
