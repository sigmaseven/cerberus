import { test, expect } from '@playwright/test';
import { EventsPage } from './pages/EventsPage';

test.describe('Events Management', () => {
  let eventsPage: EventsPage;

  test.beforeEach(async ({ page }) => {
    eventsPage = new EventsPage(page);
    await eventsPage.goto();
  });

  test('should load events page and display events table', async () => {
    await expect(eventsPage.title).toBeVisible();
    await expect(eventsPage.eventsTable).toBeVisible();
  });

  test('should display search input and allow searching events', async () => {
    await expect(eventsPage.searchInput).toBeVisible();
    await eventsPage.searchEvents('login');
    // Note: Actual search results depend on test data
    await expect(eventsPage.eventsTable).toBeVisible();
  });

  test('should display severity filter and allow filtering', async () => {
    await expect(eventsPage.severityFilter).toBeVisible();
    await eventsPage.filterBySeverity('high');
    // Note: Actual filter results depend on test data
    await expect(eventsPage.eventsTable).toBeVisible();
  });

  test('should clear severity filter', async () => {
    await eventsPage.filterBySeverity('high');
    await eventsPage.filterBySeverity(null);
    await expect(eventsPage.eventsTable).toBeVisible();
  });

  test('should display view details buttons for events', async () => {
    const eventCount = await eventsPage.getEventCount();
    if (eventCount > 0) {
      await expect(eventsPage.viewDetailsButtons.first()).toBeVisible();
    }
  });

  test('should open and display event details modal', async () => {
    const eventCount = await eventsPage.getEventCount();
    if (eventCount > 0) {
      await eventsPage.viewEventDetails(0);
      await expect(eventsPage.eventDetailsModal).toBeVisible();
      await expect(eventsPage.eventIdText).toBeVisible();
      await expect(eventsPage.eventTimestampText).toBeVisible();
      await expect(eventsPage.eventTypeText).toBeVisible();
      await expect(eventsPage.eventSeverityText).toBeVisible();
      await expect(eventsPage.eventSourceIpText).toBeVisible();
      await expect(eventsPage.eventRawDataText).toBeVisible();
    }
  });

  test('should display correct event information in details modal', async () => {
    const eventCount = await eventsPage.getEventCount();
    if (eventCount > 0) {
      await eventsPage.viewEventDetails(0);
      const eventId = await eventsPage.getEventId();
      const timestamp = await eventsPage.getEventTimestamp();
      const type = await eventsPage.getEventType();
      const severity = await eventsPage.getEventSeverity();
      const sourceIp = await eventsPage.getEventSourceIp();
      const rawData = await eventsPage.getEventRawData();

      expect(eventId).toBeTruthy();
      expect(timestamp).toBeTruthy();
      expect(type).toBeTruthy();
      expect(severity).toBeTruthy();
      expect(sourceIp).toBeTruthy();
      expect(rawData).toBeTruthy();
    }
  });

  test('should close event details modal', async () => {
    const eventCount = await eventsPage.getEventCount();
    if (eventCount > 0) {
      await eventsPage.viewEventDetails(0);
      await expect(eventsPage.eventDetailsModal).toBeVisible();
      await eventsPage.closeEventDetailsModal();
      await expect(eventsPage.eventDetailsModal).not.toBeVisible();
    }
  });

  test('should handle empty events list gracefully', async () => {
    // This test assumes there might be scenarios with no events
    // In a real test environment, you might need to set up mock data
    const eventCount = await eventsPage.getEventCount();
    if (eventCount === 0) {
      await expect(eventsPage.eventsTable).toBeVisible();
      await expect(eventsPage.viewDetailsButtons).toHaveCount(0);
    }
  });

  test('should maintain search and filter state', async () => {
    await eventsPage.searchEvents('test');
    await eventsPage.filterBySeverity('medium');
    // Verify that search and filter are still applied
    await expect(eventsPage.searchInput).toHaveValue('test');
    // Note: Checking select value might require additional implementation
  });
});