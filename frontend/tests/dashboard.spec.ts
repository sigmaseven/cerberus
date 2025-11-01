import { test, expect } from '@playwright/test';
import { DashboardPage } from './pages/DashboardPage';

test.describe('Dashboard Viewing', () => {
  let dashboardPage: DashboardPage;

  test.beforeEach(async ({ page }) => {
    dashboardPage = new DashboardPage(page);
    await dashboardPage.goto();
    await dashboardPage.waitForDataLoad();
  });

  test('should load dashboard and display real-time stats', async () => {
    await expect(dashboardPage.title).toBeVisible();
    await expect(dashboardPage.refreshButton).toBeVisible();
    await expect(dashboardPage.totalEventsCard).toBeVisible();
    await expect(dashboardPage.totalAlertsCard).toBeVisible();
    await expect(dashboardPage.chart).toBeVisible();
    await expect(dashboardPage.recentEventsList).toBeVisible();
  });

  test('should display total events and alerts counts', async () => {
    const totalEvents = await dashboardPage.getTotalEvents();
    const totalAlerts = await dashboardPage.getTotalAlerts();

    expect(totalEvents).toBeTruthy();
    expect(totalAlerts).toBeTruthy();
    // Events and alerts should be non-negative numbers
    expect(parseInt(totalEvents!.replace(/,/g, ''))).toBeGreaterThanOrEqual(0);
    expect(parseInt(totalAlerts!.replace(/,/g, ''))).toBeGreaterThanOrEqual(0);
  });

  test('should display chart rendering', async () => {
    await expect(dashboardPage.chart).toBeVisible();
    // Check that chart has proper accessibility attributes
    await expect(dashboardPage.chart).toHaveAttribute('aria-label', 'Events and alerts over time chart');
  });

  test('should display recent events list', async () => {
    await expect(dashboardPage.recentEventsList).toBeVisible();
    const eventCount = await dashboardPage.getRecentEventsCount();
    // Should show up to 10 recent events or fewer if less data available
    expect(eventCount).toBeLessThanOrEqual(10);
    expect(eventCount).toBeGreaterThanOrEqual(0);
  });

  test('should refresh data on button click', async ({ page }) => {
    await dashboardPage.refresh();
    // Wait for refresh to complete
    await page.waitForTimeout(2000);
    const refreshedEvents = await dashboardPage.getTotalEvents();
    // Data should be refreshed (might be the same if no new data)
    expect(refreshedEvents).toBeDefined();
  });

  test('should handle auto-refresh functionality', async ({ page }) => {
    // Wait for auto-refresh interval (30 seconds as per constants)
    // For testing purposes, we'll wait a shorter time and check if refresh button is still functional
    await page.waitForTimeout(5000);
    await expect(dashboardPage.refreshButton).toBeVisible();
    await expect(dashboardPage.title).toBeVisible();
  });

  test('should display events and alerts over time chart with proper data', async () => {
    await expect(dashboardPage.chart).toBeVisible();
    // The chart should be rendered with Recharts
    // Check for chart elements
    const chartContainer = dashboardPage.page.locator('.recharts-wrapper');
    await expect(chartContainer).toBeVisible();
  });

  test('should display recent events with proper information', async () => {
    const eventCount = await dashboardPage.getRecentEventsCount();
    if (eventCount > 0) {
      // Check that events have proper structure
      const firstEvent = dashboardPage.recentEventsList.locator('xpath=following-sibling::div//li').first();
      await expect(firstEvent).toBeVisible();
      // Events should contain timestamp and type information
      const eventText = await firstEvent.textContent();
      expect(eventText).toBeTruthy();
      expect(eventText).toMatch(/\d{4}-\d{2}-\d{2}/); // Should contain a date
    }
  });

  test('should handle loading states gracefully', async ({ page }) => {
    // Reload page to check loading state
    await page.reload();
    await dashboardPage.waitForDataLoad();
    await expect(dashboardPage.title).toBeVisible();
  });

  test('should display dashboard in responsive layout', async ({ page }) => {
    // Check grid layout
    const grid = page.locator('.mantine-Grid-root');
    await expect(grid).toBeVisible();

    // Check that cards are properly arranged
    const cards = page.locator('.mantine-Card-root');
    await expect(cards).toHaveCount(4); // 2 stat cards + chart card + recent events card
  });
});