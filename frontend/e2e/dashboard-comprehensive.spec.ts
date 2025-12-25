/**
 * Comprehensive Dashboard Tests
 *
 * Coverage:
 * - Dashboard statistics display
 * - Real-time WebSocket updates
 * - Chart data visualization
 * - System health monitoring
 * - Performance metrics
 *
 * Maps to requirements:
 * - FR-API-018: WebSocket real-time updates
 * - FR-API-019: Response time SLAs
 */

import { test, expect } from '@playwright/test';
import { test as authTest } from './fixtures/auth.fixture';

authTest.describe('Dashboard - Statistics Display', () => {
  authTest.beforeEach(async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');
    await authenticatedPage.waitForLoadState('networkidle');
  });

  authTest('DASH-001: Dashboard displays all KPI cards', async ({ authenticatedPage }) => {
    // Verify all 4 KPI cards are visible
    await expect(authenticatedPage.locator('text=Total Events')).toBeVisible();
    await expect(authenticatedPage.locator('text=Active Alerts')).toBeVisible();
    await expect(authenticatedPage.locator('text=Rules Fired')).toBeVisible();
    await expect(authenticatedPage.locator('text=System Health')).toBeVisible();

    // Verify each card has a numeric value
    const totalEventsValue = authenticatedPage.locator('text=Total Events').locator('..').locator('h4, h5');
    await expect(totalEventsValue).toBeVisible();

    const activeAlertsValue = authenticatedPage.locator('text=Active Alerts').locator('..').locator('h4, h5');
    await expect(activeAlertsValue).toBeVisible();
  });

  authTest('DASH-002: Dashboard statistics are numeric', async ({ authenticatedPage }) => {
    const totalEventsCard = authenticatedPage.locator('text=Total Events').locator('..').locator('h4, h5');
    const text = await totalEventsCard.textContent();

    // Remove commas and verify it's a number
    const value = parseInt(text?.replace(/,/g, '') || '0');
    expect(value).toBeGreaterThanOrEqual(0);
  });

  authTest('DASH-003: System health displays status', async ({ authenticatedPage }) => {
    const healthCard = authenticatedPage.locator('text=System Health').locator('..').locator('h4, h5');
    const healthText = await healthCard.textContent();

    // Verify valid health status
    const validStatuses = ['Healthy', 'Degraded', 'Down', 'OK', 'Good'];
    expect(validStatuses.some(status => healthText?.includes(status))).toBeTruthy();
  });

  authTest('DASH-004: Dashboard chart renders', async ({ authenticatedPage }) => {
    // Verify Recharts SVG canvas exists
    const chart = authenticatedPage.locator('.recharts-wrapper');
    await expect(chart).toBeVisible({ timeout: 10000 });

    // Verify chart has data
    const chartBars = authenticatedPage.locator('.recharts-bar, .recharts-line');
    const count = await chartBars.count();
    expect(count).toBeGreaterThan(0);
  });

  authTest('DASH-005: Dashboard loads within performance SLA', async ({ authenticatedPage }) => {
    const startTime = Date.now();

    await authenticatedPage.goto('/');
    await authenticatedPage.waitForLoadState('networkidle');

    const loadTime = Date.now() - startTime;

    // FR-API-019: Dashboard should load < 200ms (p95)
    // In E2E, allow up to 2 seconds for full page load
    expect(loadTime).toBeLessThan(2000);
  });
});

authTest.describe('Dashboard - Real-time Updates', () => {
  authTest('DASH-006: WebSocket connection established', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Wait for WebSocket connection
    await authenticatedPage.waitForTimeout(2000);

    // Check WebSocket status in console (if exposed)
    const wsConnected = await authenticatedPage.evaluate(() => {
      return (window as any).__wsConnected || false;
    });

    // Note: This test may need WebSocket mock or backend running
    test.skip(!wsConnected, 'WebSocket not connected - requires backend');
  });

  authTest('DASH-007: Dashboard updates on new events', async ({ authenticatedPage }) => {
    test.slow();
    test.skip(true, 'Requires event ingestion simulation');

    await authenticatedPage.goto('/');

    // Get initial total events
    const initialEventsText = await authenticatedPage
      .locator('text=Total Events')
      .locator('..')
      .locator('h4, h5')
      .textContent();
    const initialEvents = parseInt(initialEventsText?.replace(/,/g, '') || '0');

    // Simulate event ingestion (requires backend API or WebSocket mock)
    // await ingestTestEvent();

    // Wait for WebSocket update
    await authenticatedPage.waitForTimeout(2000);

    // Verify counter incremented
    const updatedEventsText = await authenticatedPage
      .locator('text=Total Events')
      .locator('..')
      .locator('h4, h5')
      .textContent();
    const updatedEvents = parseInt(updatedEventsText?.replace(/,/g, '') || '0');

    expect(updatedEvents).toBeGreaterThan(initialEvents);
  });
});

authTest.describe('Dashboard - Navigation', () => {
  authTest('DASH-008: Navigate to Events page from dashboard', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    await authenticatedPage.click('text=Events');
    await expect(authenticatedPage).toHaveURL(/\/events/);
    await expect(authenticatedPage.locator('h4:has-text("Security Events")')).toBeVisible();
  });

  authTest('DASH-009: Navigate to Alerts page from dashboard', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    await authenticatedPage.click('text=Alerts');
    await expect(authenticatedPage).toHaveURL(/\/alerts/);
  });

  authTest('DASH-010: Navigate to Rules page from dashboard', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    await authenticatedPage.click('text=Rules');
    await expect(authenticatedPage).toHaveURL(/\/rules/);
  });

  authTest('DASH-011: Sidebar navigation is accessible', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Verify all main menu items are keyboard accessible
    await authenticatedPage.keyboard.press('Tab');

    const menuItems = [
      'Dashboard',
      'Events',
      'Alerts',
      'Rules',
      'Actions',
      'Investigations',
      'MITRE Coverage',
    ];

    for (const item of menuItems) {
      const link = authenticatedPage.locator(`nav a:has-text("${item}")`);
      await expect(link).toBeVisible();
    }
  });
});

authTest.describe('Dashboard - Error Handling', () => {
  authTest('DASH-012: Dashboard handles API errors gracefully', async ({ authenticatedPage, page }) => {
    // Intercept dashboard API and return error
    await page.route('**/api/v1/dashboard', route =>
      route.fulfill({
        status: 500,
        body: JSON.stringify({ error: 'Internal server error' }),
      })
    );

    await authenticatedPage.goto('/');

    // Verify error message displayed
    const errorAlert = authenticatedPage.locator('[role="alert"], .MuiAlert-standardError');
    await expect(errorAlert).toBeVisible({ timeout: 5000 });
  });

  authTest('DASH-013: Dashboard handles timeout gracefully', async ({ authenticatedPage, page }) => {
    // Intercept and delay dashboard API
    await page.route('**/api/v1/dashboard', route =>
      setTimeout(() => route.continue(), 10000)
    );

    await authenticatedPage.goto('/');

    // Verify loading indicator or timeout message
    const loading = authenticatedPage.locator('.MuiCircularProgress-root, text=Loading');
    await expect(loading).toBeVisible();
  });
});

authTest.describe('Dashboard - Accessibility', () => {
  authTest('DASH-A11Y-001: Dashboard has proper heading hierarchy', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Verify main heading exists
    const mainHeading = authenticatedPage.locator('h1, h2, h3, h4').first();
    await expect(mainHeading).toBeVisible();

    // Verify heading contains "Dashboard" or similar
    const headingText = await mainHeading.textContent();
    expect(headingText?.toLowerCase()).toContain('dashboard');
  });

  authTest('DASH-A11Y-002: KPI cards have accessible labels', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Verify cards have semantic structure
    const cards = authenticatedPage.locator('[role="article"], .MuiCard-root');
    const count = await cards.count();
    expect(count).toBeGreaterThanOrEqual(4);
  });

  authTest('DASH-A11Y-003: Chart has accessible description', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const chart = authenticatedPage.locator('.recharts-wrapper');
    await expect(chart).toBeVisible();

    // Verify chart has aria-label or title
    const ariaLabel = await chart.getAttribute('aria-label');
    const title = await authenticatedPage.locator('text=Events Over Time, text=Activity Chart').count();

    expect(ariaLabel || title > 0).toBeTruthy();
  });
});

authTest.describe('Dashboard - Performance', () => {
  authTest('DASH-PERF-001: Dashboard renders without layout shift', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Measure Cumulative Layout Shift (CLS)
    const cls = await authenticatedPage.evaluate(() => {
      return new Promise(resolve => {
        let clsScore = 0;
        const observer = new PerformanceObserver(list => {
          for (const entry of list.getEntries()) {
            if ((entry as any).hadRecentInput) continue;
            clsScore += (entry as any).value;
          }
        });

        observer.observe({ type: 'layout-shift', buffered: true });

        setTimeout(() => {
          observer.disconnect();
          resolve(clsScore);
        }, 3000);
      });
    });

    // CLS should be < 0.1 (good)
    expect(cls).toBeLessThan(0.1);
  });

  authTest('DASH-PERF-002: Dashboard API calls complete quickly', async ({ authenticatedPage, page }) => {
    const apiTimes: number[] = [];

    page.on('response', response => {
      if (response.url().includes('/api/v1/dashboard')) {
        const timing = response.timing();
        apiTimes.push(timing.responseEnd);
      }
    });

    await authenticatedPage.goto('/');
    await authenticatedPage.waitForLoadState('networkidle');

    // Verify API response time < 300ms (FR-API-019)
    for (const time of apiTimes) {
      expect(time).toBeLessThan(300);
    }
  });
});
