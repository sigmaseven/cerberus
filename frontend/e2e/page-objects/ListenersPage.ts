/**
 * Listeners Page Object Model
 *
 * Encapsulates all Listeners page interactions.
 * Tests against real backend - no mocks.
 *
 * SELECTOR STRATEGY (Following Playwright Best Practices):
 * Priority order for locators (per Playwright docs):
 * 1. getByRole() - Semantic, accessible, language-agnostic when using ARIA
 * 2. getByLabel() - For form inputs with associated labels
 * 3. getByText() - For non-interactive elements or when role isn't available
 * 4. data-testid - Fallback for elements without semantic meaning
 *
 * This strategy:
 * - Enforces accessibility compliance (tests fail if ARIA roles missing)
 * - Matches how screen readers navigate the page
 * - Works with i18n when using ARIA role queries (not text-based)
 * - Uses data-testid only for structural elements (grid, cards)
 *
 * @see https://playwright.dev/docs/locators#quick-guide
 * @see https://playwright.dev/docs/locators#locate-by-role
 */

import { Page, expect, Locator } from '@playwright/test';
import { BasePage } from './BasePage';

export interface ListenerData {
  name: string;
  description?: string;
  type: 'syslog' | 'json' | 'cef';
  protocol: 'tcp' | 'udp';
  host: string;
  port: number;
  tls?: boolean;
  cert_file?: string;
  key_file?: string;
  tags?: string[];
  source?: string;
}

export class ListenersPage extends BasePage {
  // Expose page for test access
  get testPage() {
    return this.page;
  }

  // Fallback data-testid selectors for elements that need explicit identification
  // Most interactions use semantic selectors (getByRole, getByLabel) instead
  private readonly TEST_IDS = {
    // Grid/Cards
    listenersGrid: 'listeners-grid',
    listenerCard: 'listener-card',
    templateCard: 'listener-template-card',

    // State indicators (used when semantic alternatives aren't available)
    emptyState: 'listeners-empty-state',
  };

  constructor(page: Page) {
    super(page, '/listeners');
  }

  /**
   * Verify listeners page is loaded
   */
  async verifyPageLoaded(): Promise<void> {
    await this.page.waitForURL(/\/listeners/);
    // Wait for either content or empty state
    await this.page.waitForSelector(
      `[data-testid="${this.TEST_IDS.listenersGrid}"], [data-testid="${this.TEST_IDS.emptyState}"]`,
      { timeout: 10000 }
    );
  }

  /**
   * Click create listener button
   */
  async clickCreateListener(): Promise<void> {
    await this.page.getByRole('button', { name: /new listener/i }).click();
    await this.waitForLoadingComplete();
  }

  /**
   * Click templates button
   */
  async clickTemplates(): Promise<void> {
    const templatesBtn = this.page.getByRole('button', { name: /templates/i });
    if (await templatesBtn.isVisible()) {
      await templatesBtn.click();
      await this.waitForLoadingComplete();
    }
  }

  /**
   * Search for listeners (client-side filtering)
   */
  async searchListeners(query: string): Promise<void> {
    const searchInput = this.page.getByPlaceholder(/filter current page/i);
    await searchInput.fill(query);
    // Small delay for debounce
    await this.page.waitForTimeout(400);
  }

  /**
   * Filter by status
   */
  async filterByStatus(status: 'running' | 'stopped' | 'error' | 'starting'): Promise<void> {
    const filterButton = this.page.getByRole('button', { name: /filter status/i });
    if (await filterButton.isVisible()) {
      await filterButton.click();
      await this.page.locator(`[data-value="${status}"]`).click();
      await this.waitForLoadingComplete();
    }
  }

  /**
   * Filter by type
   */
  async filterByType(type: 'syslog' | 'json' | 'cef'): Promise<void> {
    const filterButton = this.page.getByRole('button', { name: /filter type/i });
    if (await filterButton.isVisible()) {
      await filterButton.click();
      await this.page.locator(`[data-value="${type}"]`).click();
      await this.waitForLoadingComplete();
    }
  }

  /**
   * Get listener card by name
   */
  getListenerCard(listenerName: string): Locator {
    return this.page.locator(`[role="listitem"]:has-text("${listenerName}")`).first();
  }

  /**
   * Verify listener exists in grid
   */
  async verifyListenerExists(listenerName: string): Promise<void> {
    const card = this.getListenerCard(listenerName);
    await expect(card).toBeVisible({ timeout: 10000 });
  }

  /**
   * Verify listener does not exist in grid
   */
  async verifyListenerNotExists(listenerName: string): Promise<void> {
    const card = this.getListenerCard(listenerName);
    await expect(card).not.toBeVisible({ timeout: 5000 });
  }

  /**
   * Get number of listeners displayed
   */
  async getListenerCount(): Promise<number> {
    const cards = this.page.locator('[role="listitem"]');
    return await cards.count();
  }

  /**
   * Verify listener status
   */
  async verifyListenerStatus(listenerName: string, status: string): Promise<void> {
    const card = this.getListenerCard(listenerName);
    const statusChip = card.locator('span.MuiChip-label').filter({ hasText: status });
    await expect(statusChip).toBeVisible({ timeout: 10000 });
  }

  /**
   * Open actions menu for listener
   */
  async openActionsMenu(listenerName: string): Promise<void> {
    const card = this.getListenerCard(listenerName);
    const menuButton = card.getByRole('button', { name: /open actions menu/i });
    await menuButton.click();
    await this.page.waitForSelector('[role="menu"]', { state: 'visible' });
  }

  /**
   * Start listener via quick action button
   */
  async startListener(listenerName: string): Promise<void> {
    const card = this.getListenerCard(listenerName);
    const startBtn = card.getByRole('button', { name: /start listener/i });
    await startBtn.click();
    await this.waitForLoadingComplete();
  }

  /**
   * Stop listener via quick action button
   */
  async stopListener(listenerName: string): Promise<void> {
    const card = this.getListenerCard(listenerName);
    const stopBtn = card.getByRole('button', { name: /stop listener/i });
    await stopBtn.click();
    await this.waitForLoadingComplete();
  }

  /**
   * Restart listener via quick action button
   */
  async restartListener(listenerName: string): Promise<void> {
    const card = this.getListenerCard(listenerName);
    const restartBtn = card.getByRole('button', { name: /restart listener/i });
    await restartBtn.click();
    await this.waitForLoadingComplete();
  }

  /**
   * Edit listener via actions menu
   */
  async clickEditListener(listenerName: string): Promise<void> {
    await this.openActionsMenu(listenerName);
    const editMenuItem = this.page.getByRole('menuitem', { name: /edit/i });
    await editMenuItem.click();
    await this.page.waitForSelector('[role="dialog"]', { state: 'visible' });
  }

  /**
   * Delete listener via actions menu
   */
  async clickDeleteListener(listenerName: string): Promise<void> {
    await this.openActionsMenu(listenerName);
    const deleteMenuItem = this.page.getByRole('menuitem', { name: /delete/i });
    await deleteMenuItem.click();
    await this.page.waitForSelector('[role="dialog"]', { state: 'visible' });
  }

  /**
   * Confirm delete in dialog
   */
  async confirmDelete(): Promise<void> {
    const confirmBtn = this.page.getByRole('button', { name: /^delete$/i });
    await confirmBtn.click();
    await this.waitForLoadingComplete();
  }

  /**
   * Cancel delete in dialog
   */
  async cancelDelete(): Promise<void> {
    const cancelBtn = this.page.getByRole('button', { name: /cancel/i });
    await cancelBtn.click();
    await expect(this.page.locator('[role="dialog"]')).not.toBeVisible();
  }

  /**
   * Fill listener form
   */
  async fillListenerForm(listenerData: ListenerData): Promise<void> {
    // Name
    const nameInput = this.page.getByLabel(/^name$/i);
    await nameInput.fill(listenerData.name);

    // Description (optional)
    if (listenerData.description) {
      const descInput = this.page.getByLabel(/description/i);
      await descInput.fill(listenerData.description);
    }

    // Type
    const typeSelect = this.page.getByLabel(/^type$/i);
    await typeSelect.click();
    await this.page.locator(`[data-value="${listenerData.type}"]`).click();

    // Protocol
    const protocolSelect = this.page.getByLabel(/protocol/i);
    await protocolSelect.click();
    await this.page.locator(`[data-value="${listenerData.protocol}"]`).click();

    // Host
    const hostInput = this.page.getByLabel(/host/i);
    await hostInput.fill(listenerData.host);

    // Port
    const portInput = this.page.getByLabel(/port/i);
    await portInput.fill(listenerData.port.toString());

    // TLS (optional)
    if (listenerData.tls !== undefined) {
      const tlsToggle = this.page.getByRole('checkbox', { name: /tls/i });
      const isChecked = await tlsToggle.isChecked();
      if (isChecked !== listenerData.tls) {
        await tlsToggle.click();
      }
    }

    // Source (optional)
    if (listenerData.source) {
      const sourceInput = this.page.getByLabel(/source/i);
      await sourceInput.fill(listenerData.source);
    }

    // Tags (optional)
    if (listenerData.tags && listenerData.tags.length > 0) {
      const tagsInput = this.page.getByLabel(/tags/i);
      await tagsInput.fill(listenerData.tags.join(', '));
    }
  }

  /**
   * Save listener form
   */
  async saveListener(): Promise<void> {
    const saveBtn = this.page.getByRole('button', { name: /^save$|^create$/i });
    await saveBtn.click();
    await this.waitForLoadingComplete();

    // Wait for dialog to close
    await expect(this.page.locator('[role="dialog"]')).not.toBeVisible({ timeout: 5000 });
  }

  /**
   * Cancel listener form
   */
  async cancelListenerForm(): Promise<void> {
    const cancelBtn = this.page.getByRole('button', { name: /cancel/i });
    await cancelBtn.click();
    await expect(this.page.locator('[role="dialog"]')).not.toBeVisible();
  }

  /**
   * Create a new listener (full flow)
   */
  async createListener(listenerData: ListenerData): Promise<void> {
    await this.clickCreateListener();
    await this.fillListenerForm(listenerData);
    await this.saveListener();
    await this.verifyNotification(/created|success/i);
  }

  /**
   * Edit an existing listener (full flow)
   */
  async editListener(listenerName: string, newData: Partial<ListenerData>): Promise<void> {
    await this.clickEditListener(listenerName);

    if (newData.name) {
      const nameInput = this.page.getByLabel(/^name$/i);
      await nameInput.clear();
      await nameInput.fill(newData.name);
    }
    if (newData.description) {
      const descInput = this.page.getByLabel(/description/i);
      await descInput.clear();
      await descInput.fill(newData.description);
    }
    if (newData.host) {
      const hostInput = this.page.getByLabel(/host/i);
      await hostInput.clear();
      await hostInput.fill(newData.host);
    }
    if (newData.port) {
      const portInput = this.page.getByLabel(/port/i);
      await portInput.clear();
      await portInput.fill(newData.port.toString());
    }

    await this.saveListener();
    await this.verifyNotification(/updated|success/i);
  }

  /**
   * Delete a listener (full flow)
   */
  async deleteListener(listenerName: string): Promise<void> {
    await this.clickDeleteListener(listenerName);
    await this.confirmDelete();
    await this.verifyNotification(/deleted|success/i);
    await this.verifyListenerNotExists(listenerName);
  }

  /**
   * Create listener from template
   */
  async createFromTemplate(templateName: string, customName: string): Promise<void> {
    await this.clickTemplates();

    // Find and click template card
    const templateCard = this.page.locator(`[data-testid="${this.TEST_IDS.templateCard}"]:has-text("${templateName}")`);
    await templateCard.click();

    // Customize name
    const nameInput = this.page.getByLabel(/^name$/i);
    await nameInput.clear();
    await nameInput.fill(customName);

    await this.saveListener();
    await this.verifyNotification(/created|success/i);
  }

  /**
   * Verify empty state is shown
   */
  async verifyEmptyState(): Promise<void> {
    const emptyState = this.page.getByText(/no listeners/i);
    await expect(emptyState).toBeVisible();
  }

  /**
   * Verify error is shown
   */
  async verifyErrorShown(messagePattern?: string | RegExp): Promise<void> {
    const errorAlert = this.page.locator('[role="alert"]').filter({ has: this.page.locator('svg[data-testid="ErrorIcon"]') });
    await expect(errorAlert).toBeVisible({ timeout: 5000 });

    if (messagePattern) {
      if (typeof messagePattern === 'string') {
        await expect(errorAlert).toContainText(messagePattern);
      } else {
        const errorText = await errorAlert.textContent();
        expect(errorText).toMatch(messagePattern);
      }
    }
  }

  /**
   * Verify notification appears
   */
  async verifyNotification(messagePattern?: string | RegExp): Promise<void> {
    const notification = this.page.locator('[role="alert"]').last();
    await expect(notification).toBeVisible({ timeout: 5000 });

    if (messagePattern) {
      if (typeof messagePattern === 'string') {
        await expect(notification).toContainText(messagePattern);
      } else {
        const notificationText = await notification.textContent();
        expect(notificationText).toMatch(messagePattern);
      }
    }
  }

  /**
   * Wait for loading to complete
   */
  async waitForLoadingComplete(): Promise<void> {
    // Wait for any loading spinners to disappear
    const spinner = this.page.locator('[role="progressbar"]');
    await spinner.waitFor({ state: 'hidden', timeout: 10000 }).catch(() => {
      // Ignore if no spinner found
    });

    // Wait for network to settle
    await this.page.waitForLoadState('networkidle').catch(() => {
      // Ignore timeout - page may have polling requests
    });
  }

  /**
   * Refresh listeners
   */
  async refreshListeners(): Promise<void> {
    const refreshBtn = this.page.getByRole('button', { name: /refresh/i });
    await refreshBtn.click();
    await this.waitForLoadingComplete();
  }

  /**
   * Navigate to page number
   */
  async goToPage(pageNumber: number): Promise<void> {
    const pagination = this.page.locator('nav[aria-label*="pagination"]');
    if (await pagination.isVisible()) {
      const pageButton = pagination.getByRole('button', { name: `Go to page ${pageNumber}` });
      await pageButton.click();
      await this.waitForLoadingComplete();
    }
  }

  /**
   * Verify form validation errors for all required fields
   */
  async verifyFormValidation(): Promise<void> {
    await this.clickCreateListener();

    // Try to submit without filling required fields
    const saveBtn = this.page.getByRole('button', { name: /^save$|^create$/i });
    await saveBtn.click();

    // Helper to check if input has validation error
    const hasValidationError = async (label: RegExp): Promise<boolean> => {
      const input = this.page.getByLabel(label);
      if (!(await input.isVisible())) return false;

      return await input.evaluate((el) => {
        return el.getAttribute('aria-invalid') === 'true' ||
               el.closest('.Mui-error') !== null ||
               el.classList.contains('Mui-error');
      });
    };

    // Check that at least name field shows validation error
    const nameHasError = await hasValidationError(/^name$/i);
    expect(nameHasError).toBe(true);

    // Verify other required fields show errors (if visible)
    // Note: Some fields may have defaults so won't show errors
    const hostInput = this.page.getByLabel(/host/i);
    if (await hostInput.isVisible()) {
      const hostValue = await hostInput.inputValue();
      if (!hostValue) {
        const hostHasError = await hasValidationError(/host/i);
        expect(hostHasError).toBe(true);
      }
    }

    // Port validation - check if port field is empty or invalid
    const portInput = this.page.getByLabel(/port/i);
    if (await portInput.isVisible()) {
      const portValue = await portInput.inputValue();
      if (!portValue || portValue === '0') {
        const portHasError = await hasValidationError(/port/i);
        expect(portHasError).toBe(true);
      }
    }
  }

  /**
   * Verify listener statistics are displayed
   */
  async verifyListenerStatistics(listenerName: string): Promise<void> {
    const card = this.getListenerCard(listenerName);

    // Check for events received
    await expect(card.getByText(/events:/i)).toBeVisible();

    // Check for rate
    await expect(card.getByText(/rate:/i)).toBeVisible();
  }
}
