import { test, expect } from '@playwright/test';

test.describe('Alerts Management', () => {
  test.beforeEach(async ({ page }) => {
    // Set up authentication
    await page.addInitScript(() => {
      localStorage.setItem('auth-storage', JSON.stringify({
        state: { token: 'test-token', isAuthenticated: true },
        version: 0
      }));
    });

    // Set up mock API responses
    await page.route('**/api/alerts', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              alert_id: 'alert1',
              rule_id: 'rule1',
              severity: 'High',
              status: 'Pending',
              timestamp: '2024-01-01T10:00:00Z',
              event: {
                event_type: 'login',
                source_ip: '192.168.1.100',
                fields: { username: 'admin', success: false }
              }
            },
            {
              alert_id: 'alert2',
              rule_id: 'rule2',
              severity: 'Medium',
              status: 'Acknowledged',
              timestamp: '2024-01-01T09:30:00Z',
              event: {
                event_type: 'file_access',
                source_ip: '192.168.1.101',
                fields: { filename: 'sensitive.txt', user: 'user1' }
              }
            }
          ])
        });
      } else if (route.request().method() === 'PUT') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ success: true })
        });
      }
    });
  });

  test('should load alerts page', async ({ page }) => {
    await page.goto('/alerts');

    await expect(page.getByText('Alerts Management')).toBeVisible();
  });

  test('should display alerts table', async ({ page }) => {
    await page.goto('/alerts');

    // Check table headers
    await expect(page.getByText('ID')).toBeVisible();
    await expect(page.getByText('Severity')).toBeVisible();
    await expect(page.getByText('Status')).toBeVisible();
    await expect(page.getByText('Timestamp')).toBeVisible();
    await expect(page.getByText('Rule')).toBeVisible();
    await expect(page.getByText('Source')).toBeVisible();
    await expect(page.getByText('Actions')).toBeVisible();

    // Check alert data
    await expect(page.getByText('alert1')).toBeVisible();
    await expect(page.getByText('High')).toBeVisible();
    await expect(page.getByText('Pending')).toBeVisible();
    await expect(page.getByText('rule1')).toBeVisible();
    await expect(page.getByText('192.168.1.100')).toBeVisible();
  });

  test('should filter alerts by severity', async ({ page }) => {
    await page.goto('/alerts');

    // Filter by High severity
    await page.getByLabel('Severity').click();
    await page.getByText('High').click();

    // Should show only high severity alerts
    await expect(page.getByText('alert1')).toBeVisible();
    await expect(page.getByText('alert2')).not.toBeVisible();
  });

  test('should filter alerts by status', async ({ page }) => {
    await page.goto('/alerts');

    // Filter by Pending status
    await page.getByLabel('Status').click();
    await page.getByText('Pending').click();

    // Should show only pending alerts
    await expect(page.getByText('alert1')).toBeVisible();
    await expect(page.getByText('alert2')).not.toBeVisible();
  });

  test('should search alerts', async ({ page }) => {
    await page.goto('/alerts');

    const searchInput = page.getByLabel('Search');
    await searchInput.fill('rule1');

    // Should show matching alert
    await expect(page.getByText('alert1')).toBeVisible();
    await expect(page.getByText('alert2')).not.toBeVisible();

    // Search for non-existent alert
    await searchInput.fill('nonexistent');

    // Should show no results (table should be empty or show no data message)
    await expect(page.getByText('alert1')).not.toBeVisible();
    await expect(page.getByText('alert2')).not.toBeVisible();
  });

  test('should acknowledge alert', async ({ page }) => {
    await page.goto('/alerts');

    // Click acknowledge button for first alert
    await page.getByText('Ack').first().click();

    // Should trigger API call (mocked)
    // In real scenario, alert status would change
  });

  test('should dismiss alert', async ({ page }) => {
    await page.goto('/alerts');

    // Click dismiss button for first alert
    await page.getByText('Dismiss').first().click();

    // Should trigger API call (mocked)
    // In real scenario, alert status would change
  });

  test('should open alert details dialog', async ({ page }) => {
    await page.goto('/alerts');

    // Click view button for first alert
    await page.getByText('View').first().click();

    // Check dialog opens
    await expect(page.getByText('Alert Details')).toBeVisible();
    await expect(page.getByText('Alert Information')).toBeVisible();
    await expect(page.getByText('alert1')).toBeVisible();
    await expect(page.getByText('High')).toBeVisible();
    await expect(page.getByText('Event Data')).toBeVisible();
    await expect(page.getByText('login')).toBeVisible();
  });

  test('should close alert details dialog', async ({ page }) => {
    await page.goto('/alerts');

    // Open dialog
    await page.getByText('View').first().click();
    await expect(page.getByText('Alert Details')).toBeVisible();

    // Close dialog
    await page.getByText('Close').click();
    await expect(page.getByText('Alert Details')).not.toBeVisible();
  });

  test('should show bulk action buttons', async ({ page }) => {
    await page.goto('/alerts');

    await expect(page.getByText('Bulk Acknowledge')).toBeVisible();
    await expect(page.getByText('Bulk Dismiss')).toBeVisible();
    await expect(page.getByText('Export CSV')).toBeVisible();
  });

  test('should show new alerts notification', async ({ page }) => {
    await page.goto('/alerts');

    // Simulate new alert via WebSocket (mocked)
    await page.evaluate(() => {
      // This would normally come from WebSocket
      const event = new CustomEvent('newAlert', {
        detail: {
          alert_id: 'alert3',
          rule_id: 'rule3',
          severity: 'Critical',
          status: 'Pending',
          timestamp: new Date().toISOString(),
          event: { event_type: 'intrusion', source_ip: '10.0.0.1', fields: {} }
        }
      });
      window.dispatchEvent(event);
    });

    // Check for notification (this might need adjustment based on actual implementation)
    // await expect(page.getByText(/new alert/)).toBeVisible();
  });

  test('should be responsive on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/alerts');

    // Check that page loads on mobile
    await expect(page.getByText('Alerts Management')).toBeVisible();

    // Check that filters are accessible
    await expect(page.getByLabel('Search')).toBeVisible();

    // Check that table is horizontally scrollable
    const tableContainer = page.locator('.MuiTableContainer-root');
    const overflowX = await tableContainer.evaluate(el => getComputedStyle(el).overflowX);
    expect(overflowX).toBe('auto');
  });
});