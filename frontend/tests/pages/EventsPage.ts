import { Page, Locator } from '@playwright/test';

export class EventsPage {
  readonly page: Page;
  readonly title: Locator;
  readonly searchInput: Locator;
  readonly severityFilter: Locator;
  readonly eventsTable: Locator;
  readonly viewDetailsButtons: Locator;
  readonly eventDetailsModal: Locator;
  readonly eventIdText: Locator;
  readonly eventTimestampText: Locator;
  readonly eventTypeText: Locator;
  readonly eventSeverityText: Locator;
  readonly eventSourceIpText: Locator;
  readonly eventRawDataText: Locator;

  constructor(page: Page) {
    this.page = page;
    this.title = page.locator('h2').filter({ hasText: 'Events' });
    this.searchInput = page.locator('input[placeholder="Search events..."]');
    this.severityFilter = page.locator('select').filter({ hasText: 'Filter by severity' });
    this.eventsTable = page.locator('table');
    this.viewDetailsButtons = page.locator('button[aria-label="View event details"]');
    this.eventDetailsModal = page.locator('div[role="dialog"]').filter({ hasText: 'Event Details' });
    this.eventIdText = page.locator('text=Event ID:').locator('xpath=following-sibling::*');
    this.eventTimestampText = page.locator('text=Timestamp:').locator('xpath=following-sibling::*');
    this.eventTypeText = page.locator('text=Type:').locator('xpath=following-sibling::*');
    this.eventSeverityText = page.locator('text=Severity:').locator('xpath=following-sibling::*');
    this.eventSourceIpText = page.locator('text=Source IP:').locator('xpath=following-sibling::*');
    this.eventRawDataText = page.locator('pre');
  }

  async goto() {
    await this.page.goto('/events');
  }

  async searchEvents(query: string) {
    await this.searchInput.fill(query);
  }

  async filterBySeverity(severity: string | null) {
    if (severity) {
      await this.severityFilter.selectOption(severity);
    } else {
      await this.severityFilter.selectOption('');
    }
  }

  async getEventCount() {
    return await this.eventsTable.locator('tbody tr').count();
  }

  async viewEventDetails(index: number = 0) {
    await this.viewDetailsButtons.nth(index).click();
  }

  async closeEventDetailsModal() {
    await this.eventDetailsModal.locator('button').filter({ hasText: 'Close' }).click();
  }

  async getEventId() {
    return await this.eventIdText.textContent();
  }

  async getEventTimestamp() {
    return await this.eventTimestampText.textContent();
  }

  async getEventType() {
    return await this.eventTypeText.textContent();
  }

  async getEventSeverity() {
    return await this.eventSeverityText.textContent();
  }

  async getEventSourceIp() {
    return await this.eventSourceIpText.textContent();
  }

  async getEventRawData() {
    return await this.eventRawDataText.textContent();
  }
}