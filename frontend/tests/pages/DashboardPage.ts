import { Page, Locator } from '@playwright/test';

export class DashboardPage {
  readonly page: Page;
  readonly title: Locator;
  readonly refreshButton: Locator;
  readonly totalEventsCard: Locator;
  readonly totalAlertsCard: Locator;
  readonly chart: Locator;
  readonly recentEventsList: Locator;
  readonly totalEventsValue: Locator;
  readonly totalAlertsValue: Locator;

  constructor(page: Page) {
    this.page = page;
    this.title = page.locator('h2').filter({ hasText: 'Dashboard' });
    this.refreshButton = page.locator('button').filter({ hasText: 'Refresh' });
    this.totalEventsCard = page.locator('text=Total Events');
    this.totalAlertsCard = page.locator('text=Total Alerts');
    this.chart = page.locator('[aria-label="Events and alerts over time chart"]');
    this.recentEventsList = page.locator('text=Recent Events');
    this.totalEventsValue = page.locator('text=Total Events').locator('xpath=following-sibling::*[2]');
    this.totalAlertsValue = page.locator('text=Total Alerts').locator('xpath=following-sibling::*[2]');
  }

  async goto() {
    await this.page.goto('/');
  }

  async refresh() {
    await this.refreshButton.click();
  }

  async getTotalEvents() {
    return await this.totalEventsValue.textContent();
  }

  async getTotalAlerts() {
    return await this.totalAlertsValue.textContent();
  }

  async isChartVisible() {
    return await this.chart.isVisible();
  }

  async getRecentEventsCount() {
    return await this.recentEventsList.locator('xpath=following-sibling::div//li').count();
  }

  async waitForDataLoad() {
    await this.page.waitForSelector('text=Total Events');
    await this.page.waitForSelector('text=Total Alerts');
  }
}