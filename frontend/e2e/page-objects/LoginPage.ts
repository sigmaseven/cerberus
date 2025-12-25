/**
 * Login Page Object
 *
 * Encapsulates login page interactions.
 */

import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export class LoginPage extends BasePage {
  // Test IDs for login elements
  private readonly TEST_IDS = {
    usernameInput: 'login-username-input',
    passwordInput: 'login-password-input',
    loginButton: 'login-submit-button',
    errorMessage: 'login-error-message',
    rememberMeCheckbox: 'login-remember-me-checkbox',
  };

  constructor(page: Page) {
    super(page, '/login');
  }

  /**
   * Perform login
   */
  async login(username: string, password: string): Promise<void> {
    await this.fillByTestId(this.TEST_IDS.usernameInput, username);
    await this.fillByTestId(this.TEST_IDS.passwordInput, password);
    await this.clickByTestId(this.TEST_IDS.loginButton);
  }

  /**
   * Perform login with remember me
   */
  async loginWithRememberMe(username: string, password: string): Promise<void> {
    await this.fillByTestId(this.TEST_IDS.usernameInput, username);
    await this.fillByTestId(this.TEST_IDS.passwordInput, password);
    await this.getByTestId(this.TEST_IDS.rememberMeCheckbox).check();
    await this.clickByTestId(this.TEST_IDS.loginButton);
  }

  /**
   * Verify login error
   */
  async verifyLoginError(message: string): Promise<void> {
    const error = this.getByTestId(this.TEST_IDS.errorMessage);
    await expect(error).toBeVisible();
    await expect(error).toContainText(message);
  }

  /**
   * Verify successful login redirect
   */
  async verifyLoginSuccess(): Promise<void> {
    await this.page.waitForURL('/');
  }

  /**
   * Check if login button is disabled
   */
  async isLoginButtonDisabled(): Promise<boolean> {
    return await this.getByTestId(this.TEST_IDS.loginButton).isDisabled();
  }

  /**
   * Verify login form validation
   */
  async verifyFormValidation(): Promise<void> {
    await this.clickByTestId(this.TEST_IDS.loginButton);

    // Should show validation errors for empty fields
    const usernameError = this.getByTestId('login-username-error');
    const passwordError = this.getByTestId('login-password-error');

    await expect(usernameError).toBeVisible();
    await expect(passwordError).toBeVisible();
  }

  /**
   * Test keyboard navigation
   */
  async testKeyboardNavigation(): Promise<void> {
    await this.getByTestId(this.TEST_IDS.usernameInput).focus();
    await this.page.keyboard.press('Tab');

    const focused = await this.page.evaluate(() => document.activeElement?.tagName);
    expect(focused).toBe('INPUT');
  }

  /**
   * Verify CSRF token is present
   */
  async verifyCSRFProtection(): Promise<void> {
    const cookies = await this.page.context().cookies();
    const csrfCookie = cookies.find(c => c.name === 'csrf_token' || c.name === '_csrf');
    expect(csrfCookie).toBeDefined();
  }
}
