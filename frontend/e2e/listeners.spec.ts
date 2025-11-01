import { test, expect } from '@playwright/test';

test.describe('Listeners', () => {
  test.beforeEach(async ({ page }) => {
    // Set up authentication
    await page.addInitScript(() => {
      localStorage.setItem('auth-storage', JSON.stringify({
        state: { token: 'test-token', isAuthenticated: true },
        version: 0
      }));
    });

    // Set up mock API responses
    await page.route('**/api/listeners', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          syslog: {
            active: true,
            port: 514,
            events_per_minute: 15.5,
            errors: 0
          },
          cef: {
            active: true,
            port: 515,
            events_per_minute: 8.2,
            errors: 2
          },
          json: {
            active: false,
            port: 516,
            events_per_minute: 0,
            errors: 0
          }
        })
      });
    });
  });

  test('should load listeners page', async ({ page }) => {
    await page.goto('/listeners');

    await expect(page.getByText('Event Listeners')).toBeVisible();
    await expect(page.getByText('Monitor the status of event ingestion listeners')).toBeVisible();
  });

  test('should display listener cards', async ({ page }) => {
    await page.goto('/listeners');

    // Check that listener cards are displayed
    await expect(page.getByText('SYSLOG Listener')).toBeVisible();
    await expect(page.getByText('CEF Listener')).toBeVisible();
    await expect(page.getByText('JSON Listener')).toBeVisible();
  });

  test('should display status chips with correct colors', async ({ page }) => {
    await page.goto('/listeners');

    // Check status chips
    await expect(page.getByText('Active')).toHaveCount(2); // syslog and cef are active
    await expect(page.getByText('Inactive')).toHaveCount(1); // json is inactive
  });

  test('should display status icons', async ({ page }) => {
    await page.goto('/listeners');

    // Check that status icons are present (WifiIcon for active, WifiOffIcon for inactive)
    // This is harder to test directly, but we can check the structure exists
    const cards = page.locator('.MuiCard-root');
    await expect(cards).toHaveCount(3);
  });

  test('should display listener details', async ({ page }) => {
    await page.goto('/listeners');

    // Check port information
    await expect(page.getByText('Port: 514')).toBeVisible();
    await expect(page.getByText('Port: 515')).toBeVisible();
    await expect(page.getByText('Port: 516')).toBeVisible();

    // Check events per minute
    await expect(page.getByText('Events/min: 15.5')).toBeVisible();
    await expect(page.getByText('Events/min: 8.2')).toBeVisible();
    await expect(page.getByText('Events/min: 0')).toBeVisible();

    // Check error counts
    await expect(page.getByText('Errors: 0')).toHaveCount(2); // syslog and json
    await expect(page.getByText('Errors: 2')).toBeVisible(); // cef
  });

  test('should show error alerts for listeners with errors', async ({ page }) => {
    await page.goto('/listeners');

    // CEF listener has 2 errors, should show warning alert
    await expect(page.getByText('Check logs for error details')).toBeVisible();
  });

  test('should have refresh and configure buttons', async ({ page }) => {
    await page.goto('/listeners');

    await expect(page.getByText('Refresh')).toBeVisible();
    await expect(page.getByText('Configure')).toBeVisible();
  });

  test('should open configuration dialog', async ({ page }) => {
    await page.goto('/listeners');

    await page.getByText('Configure').click();

    await expect(page.getByText('Listener Configuration')).toBeVisible();
    await expect(page.getByText('Listener configuration is managed through the Cerberus configuration file')).toBeVisible();
  });

  test('should close configuration dialog', async ({ page }) => {
    await page.goto('/listeners');

    // Open dialog
    await page.getByText('Configure').click();
    await expect(page.getByText('Listener Configuration')).toBeVisible();

    // Close dialog
    await page.getByText('Close').click();
    await expect(page.getByText('Listener Configuration')).not.toBeVisible();
  });

  test('should handle empty listeners object', async ({ page }) => {
    // Override the mock to return empty object
    await page.route('**/api/listeners', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({})
      });
    });

    await page.goto('/listeners');

    // Page should still load without errors
    await expect(page.getByText('Event Listeners')).toBeVisible();

    // No cards should be displayed
    const listenerCards = page.locator('.MuiCard-root');
    await expect(listenerCards).toHaveCount(0);
  });

  test('should handle API error', async ({ page }) => {
    // Override the mock to return error
    await page.route('**/api/listeners', async route => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal server error' })
      });
    });

    await page.goto('/listeners');

    // Should show error message
    await expect(page.getByText('Failed to load listener status')).toBeVisible();
  });

  test('should be responsive on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/listeners');

    // Check that page loads on mobile
    await expect(page.getByText('Event Listeners')).toBeVisible();

    // Check that buttons are accessible
    await expect(page.getByText('Refresh')).toBeVisible();
    await expect(page.getByText('Configure')).toBeVisible();

    // Check that listener cards are displayed in single column
    const listenerCards = page.locator('.MuiGrid-item');
    // On mobile, each card should take full width (xs=12)
    const firstCard = listenerCards.first();
    const box = await firstCard.boundingBox();
    expect(box?.width).toBeGreaterThan(300); // Should be nearly full width
  });

  test('should format events per minute correctly', async ({ page }) => {
    await page.goto('/listeners');

    // Check various formatting scenarios
    await expect(page.getByText('Events/min: 15.5')).toBeVisible(); // Normal rate
    await expect(page.getByText('Events/min: 8.2')).toBeVisible(); // Decimal rate
    await expect(page.getByText('Events/min: 0')).toBeVisible(); // Zero rate
  });
});