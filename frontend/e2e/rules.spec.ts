import { test, expect } from '@playwright/test';

test.describe('Rules Management', () => {
  test.beforeEach(async ({ page }) => {
    // Set up mock API responses
    await page.route('**/api/rules', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              id: 'rule1',
              name: 'Test Rule 1',
              description: 'A test detection rule',
              severity: 'High',
              enabled: true,
              version: 1,
              conditions: [
                { field: 'event_type', operator: 'equals', value: 'login', logic: 'AND' }
              ],
              actions: [
                { type: 'webhook', config: { url: 'https://example.com' } }
              ]
            }
          ])
        });
      } else if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'rule2',
            name: 'New Test Rule',
            description: 'A new test rule',
            severity: 'Medium',
            enabled: true,
            version: 1,
            conditions: [],
            actions: []
          })
        });
      }
    });
  });

  test('should load rules page', async ({ page }) => {
    await page.goto('/rules');

    await expect(page.getByText('Detection Rules')).toBeVisible();
    await expect(page.getByText('Create Rule')).toBeVisible();
  });

  test('should display rules table', async ({ page }) => {
    await page.goto('/rules');

    // Check table headers
    await expect(page.getByText('Name')).toBeVisible();
    await expect(page.getByText('Description')).toBeVisible();
    await expect(page.getByText('Severity')).toBeVisible();
    await expect(page.getByText('Enabled')).toBeVisible();
    await expect(page.getByText('Conditions')).toBeVisible();
    await expect(page.getByText('Actions')).toBeVisible();

    // Check rule data
    await expect(page.getByText('Test Rule 1')).toBeVisible();
    await expect(page.getByText('A test detection rule')).toBeVisible();
    await expect(page.getByText('High')).toBeVisible();
  });

  test('should open create rule dialog', async ({ page }) => {
    await page.goto('/rules');

    await page.getByText('Create Rule').click();

    await expect(page.getByText('Create Detection Rule')).toBeVisible();
    await expect(page.getByText('Rule Name')).toBeVisible();
    await expect(page.getByText('Description')).toBeVisible();
    await expect(page.getByText('Severity')).toBeVisible();
  });

  test('should create a new rule', async ({ page }) => {
    await page.goto('/rules');

    // Open create dialog
    await page.getByText('Create Rule').click();

    // Fill out the form
    await page.getByLabel('Rule Name').fill('New Test Rule');
    await page.getByLabel('Description').fill('A new test rule');
    await page.getByLabel('Severity').click();
    await page.getByText('Medium').click();

    // Submit the form
    await page.getByText('Save Rule').click();

    // Check that dialog closes and success message appears
    await expect(page.getByText('Create Detection Rule')).not.toBeVisible();
  });

  test('should search rules', async ({ page }) => {
    await page.goto('/rules');

    const searchInput = page.getByLabel('Search rules');
    await searchInput.fill('Test Rule 1');

    // Rule should still be visible
    await expect(page.getByText('Test Rule 1')).toBeVisible();

    // Search for non-existent rule
    await searchInput.fill('Non-existent Rule');

    // Should show no results message
    await expect(page.getByText('No rules found')).toBeVisible();
  });

  test('should toggle rule enabled status', async ({ page }) => {
    await page.goto('/rules');

    // Find the switch for the rule
    const switchElement = page.locator('input[type="checkbox"]').first();
    const isChecked = await switchElement.isChecked();

    // Click the switch (using the parent element since switches can be tricky)
    await page.locator('span.MuiSwitch-root').first().click();

    // The switch should toggle (this would trigger an API call in real scenario)
    expect(await switchElement.isChecked()).not.toBe(isChecked);
  });

  test('should open edit rule dialog', async ({ page }) => {
    await page.goto('/rules');

    // Click edit button
    await page.getByText('Edit').first().click();

    await expect(page.getByText('Edit Detection Rule')).toBeVisible();
    await expect(page.getByDisplayValue('Test Rule 1')).toBeVisible();
  });

  test('should open delete confirmation dialog', async ({ page }) => {
    await page.goto('/rules');

    // Click delete button
    await page.getByText('Delete').first().click();

    await expect(page.getByText('Delete Rule')).toBeVisible();
    await expect(page.getByText(/Are you sure you want to delete/)).toBeVisible();
  });

  test('should be responsive on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/rules');

    // Check that page loads on mobile
    await expect(page.getByText('Detection Rules')).toBeVisible();

    // Check that create button is full width on mobile
    const createButton = page.getByText('Create Rule');
    const buttonBox = await createButton.boundingBox();
    expect(buttonBox?.width).toBeGreaterThan(300); // Should be nearly full width

    // Check that table is horizontally scrollable
    const tableContainer = page.locator('.MuiTableContainer-root');
    const overflowX = await tableContainer.evaluate(el => getComputedStyle(el).overflowX);
    expect(overflowX).toBe('auto');
  });
});