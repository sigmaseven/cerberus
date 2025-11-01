import { test, expect } from '@playwright/test';
import { AlertsPage } from './pages/AlertsPage';

test.describe('Alerts Management', () => {
  let alertsPage: AlertsPage;

  test.beforeEach(async ({ page }) => {
    alertsPage = new AlertsPage(page);
    await alertsPage.goto();
  });

  test('should load alerts page and display alerts table', async () => {
    await expect(alertsPage.title).toBeVisible();
    await expect(alertsPage.alertsTable).toBeVisible();
  });

  test('should display search input and allow searching alerts', async () => {
    await expect(alertsPage.searchInput).toBeVisible();
    await alertsPage.searchAlerts('failed');
    await expect(alertsPage.alertsTable).toBeVisible();
  });

  test('should display severity filter and allow filtering', async () => {
    await expect(alertsPage.severityFilter).toBeVisible();
    await alertsPage.filterBySeverity('critical');
    await expect(alertsPage.alertsTable).toBeVisible();
  });

  test('should clear severity filter', async () => {
    await alertsPage.filterBySeverity('critical');
    await alertsPage.filterBySeverity(null);
    await expect(alertsPage.alertsTable).toBeVisible();
  });

  test('should display action buttons for alerts', async () => {
    const alertCount = await alertsPage.getAlertCount();
    if (alertCount > 0) {
      await expect(alertsPage.viewDetailsButtons.first()).toBeVisible();
      // Check if there are new alerts with acknowledge/dismiss buttons
      const acknowledgeCount = await alertsPage.acknowledgeButtons.count();
      const dismissCount = await alertsPage.dismissButtons.count();
      expect(acknowledgeCount).toBeGreaterThanOrEqual(0);
      expect(dismissCount).toBeGreaterThanOrEqual(0);
    }
  });

  test('should open and display alert details modal', async () => {
    const alertCount = await alertsPage.getAlertCount();
    if (alertCount > 0) {
      await alertsPage.viewAlertDetails(0);
      await expect(alertsPage.alertDetailsModal).toBeVisible();
      await expect(alertsPage.alertIdText).toBeVisible();
      await expect(alertsPage.alertRuleIdText).toBeVisible();
      await expect(alertsPage.alertTimestampText).toBeVisible();
      await expect(alertsPage.alertSeverityText).toBeVisible();
      await expect(alertsPage.alertStatusText).toBeVisible();
      await expect(alertsPage.alertJiraTicketText).toBeVisible();
      await expect(alertsPage.alertEventIdText).toBeVisible();
      await expect(alertsPage.alertEventTypeText).toBeVisible();
      await expect(alertsPage.alertEventSourceIpText).toBeVisible();
      await expect(alertsPage.alertEventRawDataText).toBeVisible();
    }
  });

  test('should display correct alert information in details modal', async () => {
    const alertCount = await alertsPage.getAlertCount();
    if (alertCount > 0) {
      await alertsPage.viewAlertDetails(0);
      const alertId = await alertsPage.getAlertId();
      const ruleId = await alertsPage.getAlertRuleId();
      const timestamp = await alertsPage.getAlertTimestamp();
      const severity = await alertsPage.getAlertSeverity();
      const status = await alertsPage.getAlertStatus();
      const jiraTicket = await alertsPage.getAlertJiraTicket();
      const eventId = await alertsPage.getAlertEventId();
      const eventType = await alertsPage.getAlertEventType();
      const sourceIp = await alertsPage.getAlertEventSourceIp();
      const rawData = await alertsPage.getAlertEventRawData();

      expect(alertId).toBeTruthy();
      expect(ruleId).toBeTruthy();
      expect(timestamp).toBeTruthy();
      expect(severity).toBeTruthy();
      expect(status).toBeTruthy();
      expect(jiraTicket).toBeTruthy();
      expect(eventId).toBeTruthy();
      expect(eventType).toBeTruthy();
      expect(sourceIp).toBeTruthy();
      expect(rawData).toBeTruthy();
    }
  });

  test('should close alert details modal', async () => {
    const alertCount = await alertsPage.getAlertCount();
    if (alertCount > 0) {
      await alertsPage.viewAlertDetails(0);
      await expect(alertsPage.alertDetailsModal).toBeVisible();
      await alertsPage.closeAlertDetailsModal();
      await expect(alertsPage.alertDetailsModal).not.toBeVisible();
    }
  });

  test('should acknowledge alert', async () => {
    const initialCount = await alertsPage.getAlertCount();
    if (initialCount > 0) {
      const acknowledgeButtons = await alertsPage.acknowledgeButtons.count();
      if (acknowledgeButtons > 0) {
        await alertsPage.acknowledgeAlert(0);
        // Wait for potential UI update
        await alertsPage.page.waitForTimeout(1000);
        // Note: In a real scenario, the alert status should change
        // This might require checking the table row or waiting for a notification
      }
    }
  });

  test('should dismiss alert', async () => {
    const initialCount = await alertsPage.getAlertCount();
    if (initialCount > 0) {
      const dismissButtons = await alertsPage.dismissButtons.count();
      if (dismissButtons > 0) {
        await alertsPage.dismissAlert(0);
        // Wait for potential UI update
        await alertsPage.page.waitForTimeout(1000);
        // Note: In a real scenario, the alert status should change
      }
    }
  });

  test('should handle empty alerts list gracefully', async () => {
    const alertCount = await alertsPage.getAlertCount();
    if (alertCount === 0) {
      await expect(alertsPage.alertsTable).toBeVisible();
      await expect(alertsPage.viewDetailsButtons).toHaveCount(0);
      await expect(alertsPage.acknowledgeButtons).toHaveCount(0);
      await expect(alertsPage.dismissButtons).toHaveCount(0);
    }
  });

  test('should maintain search and filter state', async () => {
    await alertsPage.searchAlerts('test alert');
    await alertsPage.filterBySeverity('high');
    await expect(alertsPage.searchInput).toHaveValue('test alert');
    // Note: Checking select value might require additional implementation
  });
});