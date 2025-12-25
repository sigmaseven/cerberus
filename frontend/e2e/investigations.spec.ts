import { test, expect } from '@playwright/test';

test.describe('Investigations', () => {
  test.beforeEach(async ({ page }) => {
    // Login before each test
    await page.goto('/login');
    await page.fill('input[name="username"]', 'admin');
    await page.fill('input[name="password"]', 'admin');
    await page.click('button[type="submit"]');
    await page.waitForURL('/dashboard');
  });

  test('should display investigations page', async ({ page }) => {
    await page.goto('/investigations');
    await expect(page.locator('h4', { hasText: 'Investigations' })).toBeVisible();
    await expect(page.locator('text=Manage and track security incident investigations')).toBeVisible();
  });

  test('should display statistics cards', async ({ page }) => {
    await page.goto('/investigations');

    // Check for statistics cards
    await expect(page.locator('text=Total Investigations')).toBeVisible();
    await expect(page.locator('text=Open')).toBeVisible();
    await expect(page.locator('text=Closed')).toBeVisible();
    await expect(page.locator('text=Avg Resolution Time')).toBeVisible();
  });

  test('should display tabs for different statuses', async ({ page }) => {
    await page.goto('/investigations');

    await expect(page.locator('button[role="tab"]', { hasText: 'All' })).toBeVisible();
    await expect(page.locator('button[role="tab"]', { hasText: 'Open' })).toBeVisible();
    await expect(page.locator('button[role="tab"]', { hasText: 'In Progress' })).toBeVisible();
    await expect(page.locator('button[role="tab"]', { hasText: 'Awaiting Review' })).toBeVisible();
    await expect(page.locator('button[role="tab"]', { hasText: 'Closed' })).toBeVisible();
  });

  test('should filter investigations by priority', async ({ page }) => {
    await page.goto('/investigations');

    // Open priority filter
    await page.click('label:has-text("Priority")');
    await page.click('text=High');

    // Verify filter is applied
    await expect(page.locator('input[value="high"]')).toBeVisible();
  });

  test('should search investigations', async ({ page }) => {
    await page.goto('/investigations');

    const searchInput = page.locator('input[placeholder*="Search"]');
    await searchInput.fill('suspicious');

    // Results should update (implementation dependent)
    await page.waitForTimeout(500);
  });

  test('should navigate to create investigation page', async ({ page }) => {
    await page.goto('/investigations');

    await page.click('button:has-text("New Investigation")');
    await expect(page).toHaveURL('/investigations/new');
    await expect(page.locator('h4', { hasText: 'Create New Investigation' })).toBeVisible();
  });

  test('should create a new investigation', async ({ page }) => {
    await page.goto('/investigations/new');

    // Fill in the form
    await page.fill('input[label="Title *"]', 'Test Investigation');
    await page.fill('textarea[label="Description *"]', 'This is a test investigation for E2E testing');

    // Select priority
    await page.click('text=High');

    // Submit the form
    await page.click('button:has-text("Create Investigation")');

    // Should redirect to the investigation workspace
    await page.waitForURL(/\/investigations\/inv-/);
    await expect(page.locator('h4', { hasText: 'Test Investigation' })).toBeVisible();
  });

  test('should display investigation workspace', async ({ page }) => {
    // Assuming there's at least one investigation
    await page.goto('/investigations');

    // Click on the first investigation card
    const firstCard = page.locator('[role="button"]').first();
    await firstCard.click();

    // Should be on the investigation workspace
    await expect(page).toHaveURL(/\/investigations\/inv-/);

    // Check for tabs
    await expect(page.locator('button[role="tab"]', { hasText: 'Overview' })).toBeVisible();
    await expect(page.locator('button[role="tab"]', { hasText: 'Alerts' })).toBeVisible();
    await expect(page.locator('button[role="tab"]', { hasText: 'Notes' })).toBeVisible();
    await expect(page.locator('button[role="tab"]', { hasText: 'Timeline' })).toBeVisible();
    await expect(page.locator('button[role="tab"]', { hasText: 'MITRE ATT&CK' })).toBeVisible();
  });

  test('should add a note to investigation', async ({ page }) => {
    await page.goto('/investigations');

    // Open first investigation
    const firstCard = page.locator('[role="button"]').first();
    await firstCard.click();

    // Navigate to Notes tab
    await page.click('button[role="tab"]:has-text("Notes")');

    // Add a note
    const noteInput = page.locator('textarea[placeholder*="note"]');
    await noteInput.fill('This is a test note from E2E testing');

    await page.click('button:has-text("Add Note")');

    // Verify note appears
    await expect(page.locator('text=This is a test note from E2E testing')).toBeVisible();
  });

  test('should open verdict modal when closing investigation', async ({ page }) => {
    await page.goto('/investigations');

    // Open first investigation
    const firstCard = page.locator('[role="button"]').first();
    await firstCard.click();

    // Click close button
    await page.click('button:has-text("Close Investigation")');

    // Verdict modal should open
    await expect(page.locator('text=Close Investigation')).toBeVisible();
    await expect(page.locator('text=Investigation Verdict')).toBeVisible();
    await expect(page.locator('text=True Positive')).toBeVisible();
    await expect(page.locator('text=False Positive')).toBeVisible();
    await expect(page.locator('text=Inconclusive')).toBeVisible();
  });

  test('should close investigation with verdict', async ({ page }) => {
    await page.goto('/investigations');

    // Open first investigation
    const firstCard = page.locator('[role="button"]').first();
    await firstCard.click();

    // Open verdict modal
    await page.click('button:has-text("Close Investigation")');

    // Select verdict
    await page.click('text=True Positive');

    // Select resolution category
    await page.click('text=Malware Infection');

    // Fill summary
    await page.fill('textarea[label*="Summary"]', 'Investigation completed. Threat was confirmed and mitigated.');

    // Submit
    await page.click('button:has-text("Close Investigation")');

    // Should return to investigations list or show closed status
    await page.waitForTimeout(1000);
  });

  test('should refresh investigations list', async ({ page }) => {
    await page.goto('/investigations');

    // Click refresh button
    const refreshButton = page.locator('button[aria-label="Refresh"]');
    await refreshButton.click();

    // Should show loading state briefly
    await page.waitForTimeout(500);
  });

  test('should navigate between tabs', async ({ page }) => {
    await page.goto('/investigations');

    // Click on each tab
    await page.click('button[role="tab"]:has-text("Open")');
    await page.waitForTimeout(300);

    await page.click('button[role="tab"]:has-text("In Progress")');
    await page.waitForTimeout(300);

    await page.click('button[role="tab"]:has-text("Closed")');
    await page.waitForTimeout(300);

    await page.click('button[role="tab"]:has-text("All")');
  });

  test('should clear filters', async ({ page }) => {
    await page.goto('/investigations');

    // Apply filters
    await page.click('label:has-text("Priority")');
    await page.click('text=High');

    await page.click('label:has-text("Status")');
    await page.click('text=Open');

    // Clear filters
    await page.click('button:has-text("Clear Filters")');

    // Filters should be reset
    await page.waitForTimeout(300);
  });

  test('should show empty state when no investigations', async ({ page }) => {
    await page.goto('/investigations');

    // Apply filter that returns no results
    const searchInput = page.locator('input[placeholder*="Search"]');
    await searchInput.fill('NONEXISTENT_INVESTIGATION_12345');

    await page.waitForTimeout(500);

    // Should show empty state
    await expect(page.locator('text=No investigations found')).toBeVisible();
  });

  test('should link alert to investigation from alerts page', async ({ page }) => {
    await page.goto('/alerts');

    // Click "Investigate" button on first alert
    const investigateButton = page.locator('button:has-text("Investigate")').first();
    await investigateButton.click();

    // Dialog should open
    await expect(page.locator('text=Link Alert to Investigation')).toBeVisible();

    // Should have options to link to existing or create new
    await expect(page.locator('text=Link to Existing Investigation')).toBeVisible();
    await expect(page.locator('text=Create New Investigation')).toBeVisible();
  });

  test('should create investigation from alert', async ({ page }) => {
    await page.goto('/alerts');

    // Click "Investigate" button on first alert
    const investigateButton = page.locator('button:has-text("Investigate")').first();
    await investigateButton.click();

    // Select "Create New Investigation"
    await page.click('button:has-text("Create New Investigation")');

    // Fill in title
    await page.fill('input[label="Investigation Title"]', 'Investigation from Alert');

    // Click "Create & Link"
    await page.click('button:has-text("Create & Link")');

    // Should redirect to new investigation
    await page.waitForURL(/\/investigations\/inv-/);
  });

  test('should display investigation KPI on dashboard', async ({ page }) => {
    await page.goto('/dashboard');

    // Check for investigation KPI
    await expect(page.locator('text=Open Investigations')).toBeVisible();
  });
});
