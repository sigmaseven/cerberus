/**
 * Dashboard Page Object Model
 *
 * Encapsulates all Dashboard page interactions.
 * Uses data-testid selectors exclusively for stability.
 * Tests against real backend - no mocks.
 *
 * AFFIRMATIONS compliance:
 * - All selectors use data-testid (no fragile text selectors)
 * - Clear method names describing actions
 * - Returns promises for async operations
 * - Includes assertions for common validations
 */

import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export interface DashboardStats {
  totalEvents: number;
  activeAlerts: number;
  rulesFired: number;
  systemHealth: string;
}

export class DashboardPage extends BasePage {
  // Test IDs for dashboard elements
  private readonly TEST_IDS = {
    // KPI Cards
    totalEventsCard: 'kpi-total-events',
    activeAlertsCard: 'kpi-active-alerts',
    rulesFiredCard: 'kpi-rules-fired',
    systemHealthCard: 'kpi-system-health',

    // Chart and visualization
    eventsChart: 'events-over-time-chart',
    systemStatusSection: 'system-status-section',

    // Navigation
    navDashboard: 'nav-dashboard',
    navAlerts: 'nav-alerts',
    navEvents: 'nav-events',
    navRules: 'nav-rules',
    navCorrelationRules: 'nav-correlation-rules',
    navActions: 'nav-actions',
    navListeners: 'nav-listeners',
    navInvestigations: 'nav-investigations',

    // WebSocket status
    connectionStatus: 'websocket-connection-status',

    // Mobile menu
    mobileMenuButton: 'mobile-menu-button',
  };

  constructor(page: Page) {
    super(page, '/dashboard');
  }

  /**
   * Verify dashboard page is loaded
   */
  async verifyPageLoaded(): Promise<void> {
    await this.waitForTestId(this.TEST_IDS.totalEventsCard);
    await expect(this.page).toHaveURL(/\/dashboard/);
  }

  /**
   * Get total events count
   */
  async getTotalEvents(): Promise<number> {
    const text = await this.getTextByTestId(this.TEST_IDS.totalEventsCard);
    const match = text.match(/\d+/);
    return match ? parseInt(match[0], 10) : 0;
  }

  /**
   * Get active alerts count
   */
  async getActiveAlerts(): Promise<number> {
    const text = await this.getTextByTestId(this.TEST_IDS.activeAlertsCard);
    const match = text.match(/\d+/);
    return match ? parseInt(match[0], 10) : 0;
  }

  /**
   * Get rules fired count
   */
  async getRulesFired(): Promise<number> {
    const text = await this.getTextByTestId(this.TEST_IDS.rulesFiredCard);
    const match = text.match(/\d+/);
    return match ? parseInt(match[0], 10) : 0;
  }

  /**
   * Get system health status
   */
  async getSystemHealth(): Promise<string> {
    return await this.getTextByTestId(this.TEST_IDS.systemHealthCard);
  }

  /**
   * Get all dashboard stats
   */
  async getStats(): Promise<DashboardStats> {
    return {
      totalEvents: await this.getTotalEvents(),
      activeAlerts: await this.getActiveAlerts(),
      rulesFired: await this.getRulesFired(),
      systemHealth: await this.getSystemHealth(),
    };
  }

  /**
   * Verify KPI cards are visible
   */
  async verifyKPICardsVisible(): Promise<void> {
    await expect(this.getByTestId(this.TEST_IDS.totalEventsCard)).toBeVisible();
    await expect(this.getByTestId(this.TEST_IDS.activeAlertsCard)).toBeVisible();
    await expect(this.getByTestId(this.TEST_IDS.rulesFiredCard)).toBeVisible();
    await expect(this.getByTestId(this.TEST_IDS.systemHealthCard)).toBeVisible();
  }

  /**
   * Verify chart is visible
   */
  async verifyChartVisible(): Promise<void> {
    await expect(this.getByTestId(this.TEST_IDS.eventsChart)).toBeVisible();
  }

  /**
   * Verify system status section is visible
   */
  async verifySystemStatusVisible(): Promise<void> {
    await expect(this.getByTestId(this.TEST_IDS.systemStatusSection)).toBeVisible();
  }

  /**
   * Navigate to Alerts page
   */
  async navigateToAlerts(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.navAlerts);
    await this.page.waitForURL(/\/alerts/);
  }

  /**
   * Navigate to Events page
   */
  async navigateToEvents(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.navEvents);
    await this.page.waitForURL(/\/events/);
  }

  /**
   * Navigate to Rules page
   */
  async navigateToRules(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.navRules);
    await this.page.waitForURL(/\/rules/);
  }

  /**
   * Navigate to Correlation Rules page
   */
  async navigateToCorrelationRules(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.navCorrelationRules);
    await this.page.waitForURL(/\/correlation-rules/);
  }

  /**
   * Navigate to Actions page
   */
  async navigateToActions(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.navActions);
    await this.page.waitForURL(/\/actions/);
  }

  /**
   * Navigate to Listeners page
   */
  async navigateToListeners(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.navListeners);
    await this.page.waitForURL(/\/listeners/);
  }

  /**
   * Navigate to Investigations page
   */
  async navigateToInvestigations(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.navInvestigations);
    await this.page.waitForURL(/\/investigations/);
  }

  /**
   * Verify navigation menu is visible
   */
  async verifyNavigationVisible(): Promise<void> {
    await expect(this.getByTestId(this.TEST_IDS.navDashboard)).toBeVisible();
    await expect(this.getByTestId(this.TEST_IDS.navAlerts)).toBeVisible();
    await expect(this.getByTestId(this.TEST_IDS.navEvents)).toBeVisible();
    await expect(this.getByTestId(this.TEST_IDS.navRules)).toBeVisible();
  }

  /**
   * Get WebSocket connection status
   */
  async getConnectionStatus(): Promise<string> {
    return await this.getTextByTestId(this.TEST_IDS.connectionStatus);
  }

  /**
   * Verify WebSocket is connected
   */
  async verifyWebSocketConnected(): Promise<void> {
    const status = await this.getConnectionStatus();
    expect(status.toLowerCase()).toContain('live');
  }

  /**
   * Open mobile menu
   */
  async openMobileMenu(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.mobileMenuButton);
  }

  /**
   * Verify responsive layout on mobile
   */
  async verifyMobileLayout(): Promise<void> {
    await this.page.setViewportSize({ width: 375, height: 667 });
    await this.verifyPageLoaded();

    // Mobile menu button should be visible
    await expect(this.getByTestId(this.TEST_IDS.mobileMenuButton)).toBeVisible();

    // KPI cards should still be visible
    await this.verifyKPICardsVisible();
  }

  /**
   * Verify dashboard accessibility
   */
  async verifyAccessibility(): Promise<void> {
    await super.verifyAccessibility();

    // Verify all KPI cards have proper ARIA labels
    const totalEventsCard = this.getByTestId(this.TEST_IDS.totalEventsCard);
    const ariaLabel = await totalEventsCard.getAttribute('aria-label');
    expect(ariaLabel || await totalEventsCard.getAttribute('aria-labelledby')).toBeTruthy();
  }

  /**
   * Wait for stats to update
   */
  async waitForStatsUpdate(expectedEvents: number, timeout = 10000): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const stats = await this.getStats();
      if (stats.totalEvents >= expectedEvents) {
        return;
      }
      await this.page.waitForTimeout(500);
    }

    throw new Error(`Stats did not update to expected value within ${timeout}ms`);
  }
}
