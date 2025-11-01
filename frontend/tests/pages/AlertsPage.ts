import { Page, Locator } from '@playwright/test';

export class AlertsPage {
  readonly page: Page;
  readonly title: Locator;
  readonly searchInput: Locator;
  readonly severityFilter: Locator;
  readonly alertsTable: Locator;
  readonly viewDetailsButtons: Locator;
  readonly acknowledgeButtons: Locator;
  readonly dismissButtons: Locator;
  readonly alertDetailsModal: Locator;
  readonly alertIdText: Locator;
  readonly alertRuleIdText: Locator;
  readonly alertTimestampText: Locator;
  readonly alertSeverityText: Locator;
  readonly alertStatusText: Locator;
  readonly alertJiraTicketText: Locator;
  readonly alertEventIdText: Locator;
  readonly alertEventTypeText: Locator;
  readonly alertEventSourceIpText: Locator;
  readonly alertEventRawDataText: Locator;

  constructor(page: Page) {
    this.page = page;
    this.title = page.locator('h2').filter({ hasText: 'Alerts' });
    this.searchInput = page.locator('input[placeholder="Search alerts..."]');
    this.severityFilter = page.locator('select').filter({ hasText: 'Filter by severity' });
    this.alertsTable = page.locator('table');
    this.viewDetailsButtons = page.locator('button').filter({ hasText: 'View Details' });
    this.acknowledgeButtons = page.locator('button').filter({ hasText: 'Acknowledge' });
    this.dismissButtons = page.locator('button').filter({ hasText: 'Dismiss' });
    this.alertDetailsModal = page.locator('div[role="dialog"]').filter({ hasText: 'Alert Details' });
    this.alertIdText = page.locator('text=Alert ID:').locator('xpath=following-sibling::*');
    this.alertRuleIdText = page.locator('text=Rule ID:').locator('xpath=following-sibling::*');
    this.alertTimestampText = page.locator('text=Timestamp:').locator('xpath=following-sibling::*');
    this.alertSeverityText = page.locator('text=Severity:').locator('xpath=following-sibling::*');
    this.alertStatusText = page.locator('text=Status:').locator('xpath=following-sibling::*');
    this.alertJiraTicketText = page.locator('text=Jira Ticket:').locator('xpath=following-sibling::*');
    this.alertEventIdText = page.locator('text=Event ID:').locator('xpath=following-sibling::*').first();
    this.alertEventTypeText = page.locator('text=Type:').locator('xpath=following-sibling::*').first();
    this.alertEventSourceIpText = page.locator('text=Source IP:').locator('xpath=following-sibling::*').first();
    this.alertEventRawDataText = page.locator('pre').first();
  }

  async goto() {
    await this.page.goto('/alerts');
  }

  async searchAlerts(query: string) {
    await this.searchInput.fill(query);
  }

  async filterBySeverity(severity: string | null) {
    if (severity) {
      await this.severityFilter.selectOption(severity);
    } else {
      await this.severityFilter.selectOption('');
    }
  }

  async getAlertCount() {
    return await this.alertsTable.locator('tbody tr').count();
  }

  async viewAlertDetails(index: number = 0) {
    await this.viewDetailsButtons.nth(index).click();
  }

  async acknowledgeAlert(index: number = 0) {
    await this.acknowledgeButtons.nth(index).click();
  }

  async dismissAlert(index: number = 0) {
    await this.dismissButtons.nth(index).click();
  }

  async closeAlertDetailsModal() {
    await this.alertDetailsModal.locator('button').filter({ hasText: 'Close' }).click();
  }

  async getAlertId() {
    return await this.alertIdText.textContent();
  }

  async getAlertRuleId() {
    return await this.alertRuleIdText.textContent();
  }

  async getAlertTimestamp() {
    return await this.alertTimestampText.textContent();
  }

  async getAlertSeverity() {
    return await this.alertSeverityText.textContent();
  }

  async getAlertStatus() {
    return await this.alertStatusText.textContent();
  }

  async getAlertJiraTicket() {
    return await this.alertJiraTicketText.textContent();
  }

  async getAlertEventId() {
    return await this.alertEventIdText.textContent();
  }

  async getAlertEventType() {
    return await this.alertEventTypeText.textContent();
  }

  async getAlertEventSourceIp() {
    return await this.alertEventSourceIpText.textContent();
  }

  async getAlertEventRawData() {
    return await this.alertEventRawDataText.textContent();
  }
}