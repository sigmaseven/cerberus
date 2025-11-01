import { test, expect } from '@playwright/test';

test.describe('Dashboard', () => {
  test('should load dashboard page', async ({ page }) => {
    await page.goto('/');

    // Should redirect to dashboard
    await expect(page).toHaveURL('/dashboard');

    // Check if dashboard title is visible
    await expect(page.getByText('Dashboard')).toBeVisible();
  });

  test('should display KPI cards', async ({ page }) => {
    await page.goto('/dashboard');

    // Check for KPI card titles
    await expect(page.getByText('Total Events')).toBeVisible();
    await expect(page.getByText('Active Alerts')).toBeVisible();
    await expect(page.getByText('Rules Fired')).toBeVisible();
    await expect(page.getByText('System Health')).toBeVisible();
  });

  test('should have navigation menu', async ({ page }) => {
    await page.goto('/dashboard');

    // Check navigation items
    await expect(page.getByText('Dashboard')).toBeVisible();
    await expect(page.getByText('Alerts')).toBeVisible();
    await expect(page.getByText('Events')).toBeVisible();
    await expect(page.getByText('Rules')).toBeVisible();
  });
});