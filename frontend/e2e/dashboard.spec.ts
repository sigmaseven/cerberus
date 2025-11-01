import { test, expect } from '@playwright/test';

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Set up authentication
    await page.addInitScript(() => {
      localStorage.setItem('auth-storage', JSON.stringify({
        state: { token: 'test-token', isAuthenticated: true },
        version: 0
      }));
    });

    // Set up mock API responses
    await page.route('**/api/dashboard', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_events: 1250,
          active_alerts: 3,
          rules_fired: 15,
          system_health: 'OK'
        })
      });
    });

    await page.route('**/api/dashboard/chart', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { timestamp: '2024-01-01T00:00:00Z', events: 100, alerts: 2 },
          { timestamp: '2024-01-01T01:00:00Z', events: 150, alerts: 1 }
        ])
      });
    });
  });

  test('should load dashboard page', async ({ page }) => {
    await page.goto('/');

    // Should redirect to dashboard
    await expect(page).toHaveURL('/dashboard');

    // Check if dashboard title is visible
    await expect(page.getByText('Dashboard')).toBeVisible();
  });

  test('should display KPI cards with data', async ({ page }) => {
    await page.goto('/dashboard');

    // Check for KPI card titles and values
    await expect(page.getByText('Total Events')).toBeVisible();
    await expect(page.getByText('1250')).toBeVisible();

    await expect(page.getByText('Active Alerts')).toBeVisible();
    await expect(page.getByText('3')).toBeVisible();

    await expect(page.getByText('Rules Fired')).toBeVisible();
    await expect(page.getByText('15')).toBeVisible();

    await expect(page.getByText('System Health')).toBeVisible();
    await expect(page.getByText('OK')).toBeVisible();
  });

  test('should display chart section', async ({ page }) => {
    await page.goto('/dashboard');

    // Check for chart title
    await expect(page.getByText('Events Over Time')).toBeVisible();

    // Check for system status section
    await expect(page.getByText('System Status')).toBeVisible();
    await expect(page.getByText('Events Ingest: 95%')).toBeVisible();
    await expect(page.getByText('Rules Engine: 100%')).toBeVisible();
    await expect(page.getByText('Database: OK')).toBeVisible();
  });

  test('should have functional navigation menu', async ({ page }) => {
    await page.goto('/dashboard');

    // Check navigation items are visible
    await expect(page.getByText('Dashboard')).toBeVisible();
    await expect(page.getByText('Alerts')).toBeVisible();
    await expect(page.getByText('Events')).toBeVisible();
    await expect(page.getByText('Rules')).toBeVisible();
    await expect(page.getByText('Correlation Rules')).toBeVisible();
    await expect(page.getByText('Actions')).toBeVisible();
    await expect(page.getByText('Listeners')).toBeVisible();
  });

  test('should navigate to different pages', async ({ page }) => {
    await page.goto('/dashboard');

    // Click on Alerts navigation
    await page.getByText('Alerts').click();
    await expect(page).toHaveURL('/alerts');
    await expect(page.getByText('Alerts Management')).toBeVisible();

    // Navigate back to dashboard
    await page.getByText('Dashboard').click();
    await expect(page).toHaveURL('/dashboard');

    // Click on Rules navigation
    await page.getByText('Rules').click();
    await expect(page).toHaveURL('/rules');
    await expect(page.getByText('Detection Rules')).toBeVisible();
  });

  test('should be responsive on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 }); // iPhone SE size
    await page.goto('/dashboard');

    // Check that dashboard loads on mobile
    await expect(page.getByText('Dashboard')).toBeVisible();

    // Check that KPI cards are arranged in 2x2 grid on mobile
    const kpiCards = page.locator('[data-testid="kpi-card"]');
    await expect(kpiCards).toHaveCount(4);

    // Check that navigation is accessible via hamburger menu
    const menuButton = page.locator('button[aria-label="open drawer"]');
    await expect(menuButton).toBeVisible();
  });

  test('should show WebSocket connection status', async ({ page }) => {
    await page.goto('/dashboard');

    // Check for connection status indicator
    const connectionChip = page.locator('text=/Live|Offline/');
    await expect(connectionChip).toBeVisible();
  });
});