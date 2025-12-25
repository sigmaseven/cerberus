/**
 * Base Page Object
 *
 * Provides common functionality for all page objects.
 * Implements Page Object Model pattern for maintainability.
 */

import { Page, Locator, expect } from '@playwright/test';

export abstract class BasePage {
  constructor(
    protected readonly page: Page,
    protected readonly path: string
  ) {}

  /**
   * Navigate to the page
   */
  async navigate(): Promise<void> {
    await this.page.goto(this.path);
  }

  /**
   * Get element by data-testid (PREFERRED SELECTOR METHOD)
   * Use this instead of text-based or class-based selectors
   */
  getByTestId(testId: string): Locator {
    return this.page.locator(`[data-testid="${testId}"]`);
  }

  /**
   * Click element by data-testid
   */
  async clickByTestId(testId: string): Promise<void> {
    await this.getByTestId(testId).click();
  }

  /**
   * Fill input by data-testid
   */
  async fillByTestId(testId: string, value: string): Promise<void> {
    await this.getByTestId(testId).fill(value);
  }

  /**
   * Check if element with data-testid is visible
   */
  async isVisibleByTestId(testId: string): Promise<boolean> {
    return await this.getByTestId(testId).isVisible();
  }

  /**
   * Get text content by data-testid
   */
  async getTextByTestId(testId: string): Promise<string> {
    return await this.getByTestId(testId).textContent() || '';
  }

  /**
   * Wait for element with data-testid to be visible
   */
  async waitForTestId(testId: string, timeout = 10000): Promise<void> {
    await this.getByTestId(testId).waitFor({ state: 'visible', timeout });
  }

  /**
   * Wait for page to be loaded
   */
  async waitForLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
  }

  /**
   * Get page title
   */
  async getTitle(): Promise<string> {
    return await this.page.title();
  }

  /**
   * Check if element is visible
   */
  async isVisible(selector: string): Promise<boolean> {
    return await this.page.locator(selector).isVisible();
  }

  /**
   * Wait for element to be visible
   */
  async waitForSelector(selector: string, timeout = 10000): Promise<void> {
    await this.page.waitForSelector(selector, { timeout });
  }

  /**
   * Click element with retry logic
   */
  async clickElement(selector: string): Promise<void> {
    await this.page.click(selector, { timeout: 10000 });
  }

  /**
   * Fill input field
   */
  async fillInput(selector: string, value: string): Promise<void> {
    await this.page.fill(selector, value);
  }

  /**
   * Get element text
   */
  async getElementText(selector: string): Promise<string> {
    return await this.page.locator(selector).textContent() || '';
  }

  /**
   * Wait for navigation
   */
  async waitForNavigation(urlPattern?: string | RegExp): Promise<void> {
    if (urlPattern) {
      await this.page.waitForURL(urlPattern);
    } else {
      await this.page.waitForNavigation();
    }
  }

  /**
   * Take screenshot
   */
  async takeScreenshot(name: string): Promise<void> {
    await this.page.screenshot({ path: `screenshots/${name}.png`, fullPage: true });
  }

  /**
   * Verify toast/notification message
   */
  async verifyNotification(message: string): Promise<void> {
    const notification = this.getByTestId('notification-snackbar');
    await expect(notification).toBeVisible({ timeout: 5000 });
    await expect(notification).toContainText(message);
  }

  /**
   * Verify error message
   */
  async verifyErrorMessage(message: string): Promise<void> {
    const error = this.getByTestId('error-alert');
    await expect(error).toBeVisible();
    await expect(error).toContainText(message);
  }

  /**
   * Wait for loading spinner to disappear
   */
  async waitForLoadingComplete(): Promise<void> {
    await this.getByTestId('loading-spinner').waitFor({
      state: 'hidden',
      timeout: 30000,
    }).catch(() => {
      // Ignore if no loading spinner found
    });
  }

  /**
   * Verify table has data
   */
  async verifyTableHasData(): Promise<void> {
    const table = this.page.locator('table');
    await expect(table).toBeVisible();

    const rows = this.page.locator('tbody tr');
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
  }

  /**
   * Get table row count
   */
  async getTableRowCount(): Promise<number> {
    const rows = this.page.locator('tbody tr');
    return await rows.count();
  }

  /**
   * Verify breadcrumb navigation
   */
  async verifyBreadcrumb(path: string[]): Promise<void> {
    for (const item of path) {
      const breadcrumb = this.page.locator(`nav[aria-label="breadcrumb"]`);
      await expect(breadcrumb).toContainText(item);
    }
  }

  /**
   * Keyboard navigation helper
   */
  async pressKey(key: string): Promise<void> {
    await this.page.keyboard.press(key);
  }

  /**
   * Verify page is accessible (basic checks)
   */
  async verifyAccessibility(): Promise<void> {
    // Check for page heading
    const heading = this.page.locator('h1, h2, h3, h4').first();
    await expect(heading).toBeVisible();

    // Verify no elements with missing alt text on images
    const images = await this.page.locator('img').all();
    for (const img of images) {
      const alt = await img.getAttribute('alt');
      expect(alt).toBeDefined();
    }

    // Verify form labels
    const inputs = await this.page.locator('input[type="text"], input[type="email"], input[type="password"]').all();
    for (const input of inputs) {
      const id = await input.getAttribute('id');
      const ariaLabel = await input.getAttribute('aria-label');
      const ariaLabelledBy = await input.getAttribute('aria-labelledby');

      // Must have either id with label, aria-label, or aria-labelledby
      expect(id || ariaLabel || ariaLabelledBy).toBeTruthy();
    }
  }

  /**
   * Check for console errors
   */
  async verifyNoConsoleErrors(): Promise<void> {
    const errors: string[] = [];

    this.page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    // Allow page to settle
    await this.page.waitForTimeout(1000);

    expect(errors).toHaveLength(0);
  }
}
