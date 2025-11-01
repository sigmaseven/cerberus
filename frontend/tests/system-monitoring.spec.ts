import { test, expect } from '@playwright/test';
import { SystemMonitoringPage } from './pages/SystemMonitoringPage';

test.describe('System Monitoring', () => {
  let systemMonitoringPage: SystemMonitoringPage;

  test.beforeEach(async ({ page }) => {
    systemMonitoringPage = new SystemMonitoringPage(page);
    await systemMonitoringPage.goto();
  });

  test('should load system monitoring page and display title', async () => {
    await expect(systemMonitoringPage.title).toBeVisible();
  });

  test('should display syslog listener configuration', async () => {
    await expect(systemMonitoringPage.syslogCard).toBeVisible();
    const host = await systemMonitoringPage.getSyslogHost();
    const port = await systemMonitoringPage.getSyslogPort();
    expect(host).toBeTruthy();
    expect(port).toBeTruthy();
  });

  test('should display CEF listener configuration', async () => {
    await expect(systemMonitoringPage.cefCard).toBeVisible();
    const host = await systemMonitoringPage.getCefHost();
    const port = await systemMonitoringPage.getCefPort();
    expect(host).toBeTruthy();
    expect(port).toBeTruthy();
  });

  test('should display JSON listener configuration', async () => {
    await expect(systemMonitoringPage.jsonCard).toBeVisible();
    const host = await systemMonitoringPage.getJsonHost();
    const port = await systemMonitoringPage.getJsonPort();
    const tls = await systemMonitoringPage.getJsonTlsStatus();
    expect(host).toBeTruthy();
    expect(port).toBeTruthy();
    expect(tls).toBeTruthy();
  });

  test('should display correct listener host configurations', async () => {
    const syslogHost = await systemMonitoringPage.getSyslogHost();
    const cefHost = await systemMonitoringPage.getCefHost();
    const jsonHost = await systemMonitoringPage.getJsonHost();

    // Hosts should be valid IP addresses or hostnames
    expect(syslogHost).toMatch(/^(?:\d{1,3}\.){3}\d{1,3}|localhost|[\w.-]+$/);
    expect(cefHost).toMatch(/^(?:\d{1,3}\.){3}\d{1,3}|localhost|[\w.-]+$/);
    expect(jsonHost).toMatch(/^(?:\d{1,3}\.){3}\d{1,3}|localhost|[\w.-]+$/);
  });

  test('should display correct listener port configurations', async () => {
    const syslogPort = await systemMonitoringPage.getSyslogPort();
    const cefPort = await systemMonitoringPage.getCefPort();
    const jsonPort = await systemMonitoringPage.getJsonPort();

    // Ports should be valid numbers
    expect(parseInt(syslogPort!)).toBeGreaterThan(0);
    expect(parseInt(syslogPort!)).toBeLessThan(65536);
    expect(parseInt(cefPort!)).toBeGreaterThan(0);
    expect(parseInt(cefPort!)).toBeLessThan(65536);
    expect(parseInt(jsonPort!)).toBeGreaterThan(0);
    expect(parseInt(jsonPort!)).toBeLessThan(65536);
  });

  test('should display TLS status for JSON listener', async () => {
    const tlsStatus = await systemMonitoringPage.getJsonTlsStatus();
    expect(['Enabled', 'Disabled']).toContain(tlsStatus);
  });

  test('should display all listener cards with proper styling', async () => {
    await expect(systemMonitoringPage.syslogCard).toBeVisible();
    await expect(systemMonitoringPage.cefCard).toBeVisible();
    await expect(systemMonitoringPage.jsonCard).toBeVisible();

    // Check that cards have proper content
    await expect(systemMonitoringPage.syslogCard.locator('text=Syslog Listener')).toBeVisible();
    await expect(systemMonitoringPage.cefCard.locator('text=CEF Listener')).toBeVisible();
    await expect(systemMonitoringPage.jsonCard.locator('text=JSON Listener')).toBeVisible();
  });

  test('should display protocol information for each listener', async () => {
    // Check that protocol information is displayed
    await expect(systemMonitoringPage.syslogCard.locator('text=UDP/TCP')).toBeVisible();
    await expect(systemMonitoringPage.cefCard.locator('text=UDP/TCP')).toBeVisible();
    await expect(systemMonitoringPage.jsonCard.locator('text=HTTP/UDP')).toBeVisible();
  });

  test('should handle page refresh and maintain configuration display', async () => {
    // Get initial values
    const initialSyslogHost = await systemMonitoringPage.getSyslogHost();
    const initialCefPort = await systemMonitoringPage.getCefPort();

    // Refresh the page
    await systemMonitoringPage.page.reload();

    // Check that values are still displayed correctly
    const refreshedSyslogHost = await systemMonitoringPage.getSyslogHost();
    const refreshedCefPort = await systemMonitoringPage.getCefPort();

    expect(refreshedSyslogHost).toBe(initialSyslogHost);
    expect(refreshedCefPort).toBe(initialCefPort);
  });

  test('should display configuration in a user-friendly format', async () => {
    // Ensure that the configuration is presented clearly
    const syslogCard = systemMonitoringPage.syslogCard;
    const cefCard = systemMonitoringPage.cefCard;
    const jsonCard = systemMonitoringPage.jsonCard;

    // Check that each card has a title and relevant details
    await expect(syslogCard.locator('text=Syslog Listener')).toBeVisible();
    await expect(cefCard.locator('text=CEF Listener')).toBeVisible();
    await expect(jsonCard.locator('text=JSON Listener')).toBeVisible();

    // Check that key information is visible
    await expect(syslogCard.locator('text=Host:')).toBeVisible();
    await expect(syslogCard.locator('text=Port:')).toBeVisible();
    await expect(cefCard.locator('text=Host:')).toBeVisible();
    await expect(cefCard.locator('text=Port:')).toBeVisible();
    await expect(jsonCard.locator('text=Host:')).toBeVisible();
    await expect(jsonCard.locator('text=Port:')).toBeVisible();
    await expect(jsonCard.locator('text=TLS:')).toBeVisible();
  });
});