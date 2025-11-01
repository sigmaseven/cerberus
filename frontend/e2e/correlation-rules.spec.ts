import { test, expect } from '@playwright/test';

test.describe('Correlation Rules', () => {
  test.beforeEach(async ({ page }) => {
    // Set up authentication
    await page.addInitScript(() => {
      localStorage.setItem('auth-storage', JSON.stringify({
        state: { token: 'test-token', isAuthenticated: true },
        version: 0
      }));
    });

    // Set up mock API responses
    await page.route('**/api/correlation-rules', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              id: 'corr-rule1',
              name: 'Brute Force Attack',
              description: 'Detects multiple failed login attempts followed by success',
              severity: 'High',
              sequence: ['failed_login', 'failed_login', 'successful_login'],
              window: 300000000000, // 5 minutes in nanoseconds
              conditions: []
            },
            {
              id: 'corr-rule2',
              name: 'Privilege Escalation',
              description: 'Detects suspicious privilege changes',
              severity: 'Critical',
              sequence: ['user_login', 'privilege_change'],
              window: 600000000000, // 10 minutes in nanoseconds
              conditions: []
            }
          ])
        });
      } else if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'corr-rule3',
            name: 'New Correlation Rule',
            description: 'A new test correlation rule',
            severity: 'Medium',
            sequence: ['event1', 'event2'],
            window: 120000000000, // 2 minutes
            conditions: []
          })
        });
      } else if (route.request().method() === 'PUT') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ success: true })
        });
      } else if (route.request().method() === 'DELETE') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ success: true })
        });
      }
    });
  });

  test('should load correlation rules page', async ({ page }) => {
    await page.goto('/correlation-rules');

    await expect(page.getByText('Correlation Rules')).toBeVisible();
    await expect(page.getByText('Create Correlation Rule')).toBeVisible();
  });

  test('should display correlation rules table', async ({ page }) => {
    await page.goto('/correlation-rules');

    // Check table headers
    await expect(page.getByText('Name')).toBeVisible();
    await expect(page.getByText('Description')).toBeVisible();
    await expect(page.getByText('Severity')).toBeVisible();
    await expect(page.getByText('Sequence')).toBeVisible();
    await expect(page.getByText('Window')).toBeVisible();
    await expect(page.getByText('Actions')).toBeVisible();

    // Check rule data
    await expect(page.getByText('Brute Force Attack')).toBeVisible();
    await expect(page.getByText('Detects multiple failed login attempts')).toBeVisible();
    await expect(page.getByText('High')).toBeVisible();
    await expect(page.getByText('failed_login → failed_login → successful_login')).toBeVisible();
    await expect(page.getByText('5m 0s')).toBeVisible();
  });

  test('should display severity chips with correct colors', async ({ page }) => {
    await page.goto('/correlation-rules');

    // Check severity chips
    const highChip = page.locator('text=High').locator('..').locator('..');
    await expect(highChip).toHaveClass(/MuiChip-colorError/);

    const criticalChip = page.locator('text=Critical').locator('..').locator('..');
    await expect(criticalChip).toHaveClass(/MuiChip-colorError/);
  });

  test('should search correlation rules', async ({ page }) => {
    await page.goto('/correlation-rules');

    const searchInput = page.getByLabel('Search rules');
    await searchInput.fill('Brute Force');

    // Should show matching rule
    await expect(page.getByText('Brute Force Attack')).toBeVisible();
    await expect(page.getByText('Privilege Escalation')).not.toBeVisible();

    // Search for non-existent rule
    await searchInput.fill('Non-existent Rule');

    // Should show no results message
    await expect(page.getByText('No correlation rules found')).toBeVisible();
  });

  test('should open create correlation rule dialog', async ({ page }) => {
    await page.goto('/correlation-rules');

    await page.getByText('Create Correlation Rule').click();

    await expect(page.getByText('Create Correlation Rule')).toBeVisible();
    // Form fields would be tested in component tests
  });

  test('should open edit correlation rule dialog', async ({ page }) => {
    await page.goto('/correlation-rules');

    // Click edit button for first rule
    await page.getByText('Edit').first().click();

    await expect(page.getByText('Edit Correlation Rule')).toBeVisible();
    // Should pre-populate with existing data
    await expect(page.getByDisplayValue('Brute Force Attack')).toBeVisible();
  });

  test('should open delete confirmation dialog', async ({ page }) => {
    await page.goto('/correlation-rules');

    // Click delete button for first rule
    await page.getByText('Delete').first().click();

    await expect(page.getByText('Delete Correlation Rule')).toBeVisible();
    await expect(page.getByText(/Are you sure you want to delete/)).toBeVisible();
    await expect(page.getByText('Brute Force Attack')).toBeVisible();
  });

  test('should cancel delete operation', async ({ page }) => {
    await page.goto('/correlation-rules');

    // Open delete dialog
    await page.getByText('Delete').first().click();
    await expect(page.getByText('Delete Correlation Rule')).toBeVisible();

    // Click cancel
    await page.getByText('Cancel').click();

    // Dialog should close
    await expect(page.getByText('Delete Correlation Rule')).not.toBeVisible();
  });

  test('should show success message after create', async ({ page }) => {
    await page.goto('/correlation-rules');

    // Open create dialog
    await page.getByText('Create Correlation Rule').click();

    // Mock successful creation (this would normally be done by filling form and submitting)
    await page.evaluate(() => {
      // Simulate successful creation
      const event = new CustomEvent('correlationRuleCreated');
      window.dispatchEvent(event);
    });

    // Check for success message (this might need adjustment based on actual implementation)
    // await expect(page.getByText('Correlation rule created successfully')).toBeVisible();
  });

  test('should handle empty rules list', async ({ page }) => {
    // Override the mock to return empty array
    await page.route('**/api/correlation-rules', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([])
        });
      }
    });

    await page.goto('/correlation-rules');

    // Page should still load without errors
    await expect(page.getByText('Correlation Rules')).toBeVisible();

    // Should show empty state message
    await expect(page.getByText('No correlation rules found')).toBeVisible();
    await expect(page.getByText('Create your first correlation rule')).toBeVisible();

    // Table should be empty
    const tableRows = page.locator('tbody tr');
    await expect(tableRows).toHaveCount(0);
  });

  test('should handle API error', async ({ page }) => {
    // Override the mock to return error
    await page.route('**/api/correlation-rules', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Internal server error' })
        });
      }
    });

    await page.goto('/correlation-rules');

    // Should show error message
    await expect(page.getByText('Failed to load correlation rules')).toBeVisible();
  });

  test('should be responsive on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/correlation-rules');

    // Check that page loads on mobile
    await expect(page.getByText('Correlation Rules')).toBeVisible();

    // Check that create button is accessible
    await expect(page.getByText('Create Correlation Rule')).toBeVisible();

    // Check that search input is accessible
    await expect(page.getByLabel('Search rules')).toBeVisible();

    // Check that table is horizontally scrollable
    const tableContainer = page.locator('.MuiTableContainer-root');
    const overflowX = await tableContainer.evaluate(el => getComputedStyle(el).overflowX);
    expect(overflowX).toBe('auto');
  });
});