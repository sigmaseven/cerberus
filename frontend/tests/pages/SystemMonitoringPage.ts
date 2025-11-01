import { Page, Locator } from '@playwright/test';

export class SystemMonitoringPage {
  readonly page: Page;
  readonly title: Locator;
  readonly syslogCard: Locator;
  readonly cefCard: Locator;
  readonly jsonCard: Locator;
  readonly syslogHost: Locator;
  readonly syslogPort: Locator;
  readonly cefHost: Locator;
  readonly cefPort: Locator;
  readonly jsonHost: Locator;
  readonly jsonPort: Locator;
  readonly jsonTls: Locator;

  constructor(page: Page) {
    this.page = page;
    this.title = page.locator('h2').filter({ hasText: 'Listeners Configuration' });
    this.syslogCard = page.locator('text=Syslog Listener');
    this.cefCard = page.locator('text=CEF Listener');
    this.jsonCard = page.locator('text=JSON Listener');
    this.syslogHost = page.locator('text=Host:').first();
    this.syslogPort = page.locator('text=Port:').first();
    this.cefHost = page.locator('text=Host:').nth(1);
    this.cefPort = page.locator('text=Port:').nth(1);
    this.jsonHost = page.locator('text=Host:').nth(2);
    this.jsonPort = page.locator('text=Port:').nth(2);
    this.jsonTls = page.locator('text=TLS:');
  }

  async goto() {
    await this.page.goto('/listeners');
  }

  async getSyslogHost() {
    return await this.syslogHost.locator('xpath=following-sibling::*').textContent();
  }

  async getSyslogPort() {
    return await this.syslogPort.locator('xpath=following-sibling::*').textContent();
  }

  async getCefHost() {
    return await this.cefHost.locator('xpath=following-sibling::*').textContent();
  }

  async getCefPort() {
    return await this.cefPort.locator('xpath=following-sibling::*').textContent();
  }

  async getJsonHost() {
    return await this.jsonHost.locator('xpath=following-sibling::*').textContent();
  }

  async getJsonPort() {
    return await this.jsonPort.locator('xpath=following-sibling::*').textContent();
  }

  async getJsonTlsStatus() {
    return await this.jsonTls.locator('xpath=following-sibling::*').textContent();
  }
}