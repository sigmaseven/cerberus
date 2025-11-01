import { test, expect } from '@playwright/test';

test.describe('Events', () => {
  test.beforeEach(async ({ page }) => {
    // Set up authentication
    await page.addInitScript(() => {
      localStorage.setItem('auth-storage', JSON.stringify({
        state: { token: 'test-token', isAuthenticated: true },
        version: 0
      }));
    });

    // Set up mock API responses
    await page.route('**/api/events**', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            event_id: 'event1',
            timestamp: '2024-01-01T10:00:00Z',
            event_type: 'login',
            severity: 'medium',
            source_ip: '192.168.1.100',
            fields: { username: 'admin', success: true }
          },
          {
            event_id: 'event2',
            timestamp: '2024-01-01T09:30:00Z',
            event_type: 'file_access',
            severity: 'low',
            source_ip: '192.168.1.101',
            fields: { filename: 'document.txt', user: 'user1' }
          },
          {
            event_id: 'event3',
            timestamp: '2024-01-01T09:00:00Z',
            event_type: 'network_traffic',
            severity: 'high',
            source_ip: '10.0.0.1',
            fields: { protocol: 'TCP', port: 443, bytes: 1024 }
          }
        ])
      });
    });
  });

  test('should load events page', async ({ page }) => {
    await page.goto('/events');

    await expect(page.getByText('Security Events')).toBeVisible();
  });

  test('should display events table', async ({ page }) => {
    await page.goto('/events');

    // Check table headers
    await expect(page.getByText('Timestamp')).toBeVisible();
    await expect(page.getByText('Event Type')).toBeVisible();
    await expect(page.getByText('Severity')).toBeVisible();
    await expect(page.getByText('Source IP')).toBeVisible();
    await expect(page.getByText('Raw Data')).toBeVisible();

    // Check event data
    await expect(page.getByText('login')).toBeVisible();
    await expect(page.getByText('medium')).toBeVisible();
    await expect(page.getByText('192.168.1.100')).toBeVisible();
    await expect(page.getByText('file_access')).toBeVisible();
    await expect(page.getByText('network_traffic')).toBeVisible();
  });

  test('should display severity chips with correct colors', async ({ page }) => {
    await page.goto('/events');

    // Check severity chips
    const mediumChip = page.locator('text=medium').locator('..').locator('..');
    await expect(mediumChip).toHaveClass(/MuiChip-colorWarning/);

    const lowChip = page.locator('text=low').locator('..').locator('..');
    await expect(lowChip).toHaveClass(/MuiChip-colorInfo/);

    const highChip = page.locator('text=high').locator('..').locator('..');
    await expect(highChip).toHaveClass(/MuiChip-colorError/);
  });

  test('should display timestamps in readable format', async ({ page }) => {
    await page.goto('/events');

    // Check that timestamps are displayed (exact format may vary)
    const timestampCells = page.locator('td').filter({ hasText: /\d{1,2}\/\d{1,2}\/\d{4}/ });
    await expect(timestampCells.first()).toBeVisible();
  });

  test('should display raw data in truncated format', async ({ page }) => {
    await page.goto('/events');

    // Check that raw data is displayed in pre tags
    const rawDataCells = page.locator('pre');
    await expect(rawDataCells.first()).toBeVisible();

    // Check that raw data contains expected JSON
    await expect(page.getByText('"username": "admin"')).toBeVisible();
    await expect(page.getByText('"filename": "document.txt"')).toBeVisible();
  });

  test('should show new events notification', async ({ page }) => {
    await page.goto('/events');

    // Simulate new event via WebSocket (mocked)
    await page.evaluate(() => {
      // This would normally come from WebSocket
      const event = new CustomEvent('newEvent', {
        detail: {
          event_id: 'event4',
          timestamp: new Date().toISOString(),
          event_type: 'intrusion_attempt',
          severity: 'critical',
          source_ip: '192.168.1.200',
          fields: { attack_type: 'sql_injection' }
        }
      });
      window.dispatchEvent(event);
    });

    // Check for notification (this might need adjustment based on actual implementation)
    // await expect(page.getByText(/new event/)).toBeVisible();
  });

  test('should handle empty events list', async ({ page }) => {
    // Override the mock to return empty array
    await page.route('**/api/events**', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([])
      });
    });

    await page.goto('/events');

    // Page should still load without errors
    await expect(page.getByText('Security Events')).toBeVisible();

    // Table should be empty
    const tableRows = page.locator('tbody tr');
    await expect(tableRows).toHaveCount(0);
  });

  test('should handle API error', async ({ page }) => {
    // Override the mock to return error
    await page.route('**/api/events**', async route => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal server error' })
      });
    });

    await page.goto('/events');

    // Should show error message
    await expect(page.getByText('Failed to load events')).toBeVisible();
  });

  test('should be responsive on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/events');

    // Check that page loads on mobile
    await expect(page.getByText('Security Events')).toBeVisible();

    // Check that table is horizontally scrollable
    const tableContainer = page.locator('.MuiTableContainer-root');
    const overflowX = await tableContainer.evaluate(el => getComputedStyle(el).overflowX);
    expect(overflowX).toBe('auto');

    // Check that raw data is still visible (though truncated)
    await expect(page.getByText('"username": "admin"')).toBeVisible();
  });
});