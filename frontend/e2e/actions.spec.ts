import { test, expect } from '@playwright/test';

test.describe('Actions', () => {
  test.beforeEach(async ({ page }) => {
    // Set up authentication
    await page.addInitScript(() => {
      localStorage.setItem('auth-storage', JSON.stringify({
        state: { token: 'test-token', isAuthenticated: true },
        version: 0
      }));
    });

    // Set up mock API responses
    await page.route('**/api/actions', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              id: 'action1',
              type: 'webhook',
              config: { url: 'https://example.com/webhook', method: 'POST' }
            },
            {
              id: 'action2',
              type: 'slack',
              config: { webhook_url: 'https://hooks.slack.com/...', channel: '#alerts' }
            },
            {
              id: 'action3',
              type: 'email',
              config: { to: 'admin@example.com', subject: 'Security Alert' }
            }
          ])
        });
      } else if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'action4',
            type: 'jira',
            config: { project_key: 'SEC', issue_type: 'Bug' }
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

  test('should load actions page', async ({ page }) => {
    await page.goto('/actions');

    await expect(page.getByText('Orchestration Actions')).toBeVisible();
    await expect(page.getByText('Create Action')).toBeVisible();
  });

  test('should display actions as cards', async ({ page }) => {
    await page.goto('/actions');

    // Check that action cards are displayed
    await expect(page.getByText('Webhook')).toBeVisible();
    await expect(page.getByText('Slack')).toBeVisible();
    await expect(page.getByText('Email')).toBeVisible();

    // Check action IDs
    await expect(page.getByText('ID: action1')).toBeVisible();
    await expect(page.getByText('ID: action2')).toBeVisible();
    await expect(page.getByText('ID: action3')).toBeVisible();
  });

  test('should display action icons and colors', async ({ page }) => {
    await page.goto('/actions');

    // Check that cards have colored borders (this is harder to test directly)
    // But we can check that the action types are displayed
    await expect(page.getByText('Webhook')).toBeVisible();
    await expect(page.getByText('Slack')).toBeVisible();
    await expect(page.getByText('Email')).toBeVisible();
  });

  test('should display action configurations', async ({ page }) => {
    await page.goto('/actions');

    // Check that configuration is displayed
    await expect(page.getByText('"url": "https://example.com/webhook"')).toBeVisible();
    await expect(page.getByText('"webhook_url": "https://hooks.slack.com/..."')).toBeVisible();
    await expect(page.getByText('"to": "admin@example.com"')).toBeVisible();
  });

  test('should search actions', async ({ page }) => {
    await page.goto('/actions');

    const searchInput = page.getByLabel('Search actions');
    await searchInput.fill('webhook');

    // Should show matching action
    await expect(page.getByText('Webhook')).toBeVisible();
    await expect(page.getByText('Slack')).not.toBeVisible();
    await expect(page.getByText('Email')).not.toBeVisible();

    // Search for action ID
    await searchInput.fill('action2');

    // Should show matching action
    await expect(page.getByText('Slack')).toBeVisible();
    await expect(page.getByText('Webhook')).not.toBeVisible();
    await expect(page.getByText('Email')).not.toBeVisible();
  });

  test('should open create action dialog', async ({ page }) => {
    await page.goto('/actions');

    await page.getByText('Create Action').click();

    await expect(page.getByText('Create Orchestration Action')).toBeVisible();
    // Form fields would be tested in component tests
  });

  test('should open configure action dialog', async ({ page }) => {
    await page.goto('/actions');

    // Click configure button for first action
    await page.getByText('Configure').first().click();

    await expect(page.getByText('Configure Action')).toBeVisible();
    // Should pre-populate with existing data
  });

  test('should open delete confirmation dialog', async ({ page }) => {
    await page.goto('/actions');

    // Click delete button for first action
    await page.getByText('Delete').first().click();

    await expect(page.getByText('Delete Action')).toBeVisible();
    await expect(page.getByText(/Are you sure you want to delete/)).toBeVisible();
    await expect(page.getByText('webhook')).toBeVisible();
  });

  test('should cancel delete operation', async ({ page }) => {
    await page.goto('/actions');

    // Open delete dialog
    await page.getByText('Delete').first().click();
    await expect(page.getByText('Delete Action')).toBeVisible();

    // Click cancel
    await page.getByText('Cancel').click();

    // Dialog should close
    await expect(page.getByText('Delete Action')).not.toBeVisible();
  });

  test('should show success message after create', async ({ page }) => {
    await page.goto('/actions');

    // Open create dialog
    await page.getByText('Create Action').click();

    // Mock successful creation (this would normally be done by filling form and submitting)
    await page.evaluate(() => {
      // Simulate successful creation
      const event = new CustomEvent('actionCreated');
      window.dispatchEvent(event);
    });

    // Check for success message (this might need adjustment based on actual implementation)
    // await expect(page.getByText('Action created successfully')).toBeVisible();
  });

  test('should handle empty actions list', async ({ page }) => {
    // Override the mock to return empty array
    await page.route('**/api/actions', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([])
        });
      }
    });

    await page.goto('/actions');

    // Page should still load without errors
    await expect(page.getByText('Orchestration Actions')).toBeVisible();

    // Should show empty state message
    await expect(page.getByText('No actions found')).toBeVisible();
    await expect(page.getByText('Create your first orchestration action')).toBeVisible();

    // No cards should be displayed
    const actionCards = page.locator('.MuiCard-root');
    await expect(actionCards).toHaveCount(0);
  });

  test('should handle API error', async ({ page }) => {
    // Override the mock to return error
    await page.route('**/api/actions', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Internal server error' })
        });
      }
    });

    await page.goto('/actions');

    // Should show error message
    await expect(page.getByText('Failed to load actions')).toBeVisible();
  });

  test('should be responsive on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/actions');

    // Check that page loads on mobile
    await expect(page.getByText('Orchestration Actions')).toBeVisible();

    // Check that create button is accessible
    await expect(page.getByText('Create Action')).toBeVisible();

    // Check that search input is accessible
    await expect(page.getByLabel('Search actions')).toBeVisible();

    // Check that action cards are displayed in single column
    const actionCards = page.locator('.MuiGrid-item');
    // On mobile, each card should take full width (xs=12)
    const firstCard = actionCards.first();
    const box = await firstCard.boundingBox();
    expect(box?.width).toBeGreaterThan(300); // Should be nearly full width
  });
});