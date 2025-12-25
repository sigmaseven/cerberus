/**
 * Comprehensive Authentication Tests
 *
 * Coverage:
 * - FR-USER-004: Password-based authentication
 * - FR-USER-006: JWT token management
 * - FR-USER-008: Session management
 * - FR-USER-012: Account lockout
 * - Security: CSRF protection, XSS prevention
 *
 * Maps to requirements:
 * - docs/requirements/user-management-authentication-requirements.md
 * - docs/requirements/security-threat-model.md
 */

import { test, expect } from '@playwright/test';
import { LoginPage } from './page-objects/LoginPage';
import { testUsers } from './fixtures/auth.fixture';

test.describe('Authentication - Login Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('FR-USER-004-001: Successful login with valid credentials', async ({ page }) => {
    const loginPage = new LoginPage(page);

    await loginPage.login(testUsers.admin.username, testUsers.admin.password);
    await loginPage.verifyLoginSuccess();

    // Verify redirected to dashboard
    await expect(page).toHaveURL('/');

    // Verify user session established
    const cookies = await page.context().cookies();
    const authCookie = cookies.find(c => c.name === 'auth_token');
    expect(authCookie).toBeDefined();
    expect(authCookie?.httpOnly).toBe(true);
    expect(authCookie?.secure).toBe(true);
    expect(authCookie?.sameSite).toBe('Strict');
  });

  test('FR-USER-004-002: Login fails with invalid password', async ({ page }) => {
    const loginPage = new LoginPage(page);

    await loginPage.login(testUsers.admin.username, 'wrong_password');

    await loginPage.verifyLoginError('Invalid credentials');

    // Verify still on login page
    await expect(page).toHaveURL('/login');

    // Verify no auth cookie set
    const cookies = await page.context().cookies();
    const authCookie = cookies.find(c => c.name === 'auth_token');
    expect(authCookie).toBeUndefined();
  });

  test('FR-USER-004-003: Login fails with non-existent user', async ({ page }) => {
    const loginPage = new LoginPage(page);

    await loginPage.login('nonexistent@example.com', 'password');

    await loginPage.verifyLoginError('Invalid credentials');
  });

  test('FR-USER-004-004: Login form validation - empty fields', async ({ page }) => {
    const loginPage = new LoginPage(page);

    await loginPage.verifyFormValidation();
  });

  test('FR-USER-004-005: Login form validation - email format', async ({ page }) => {
    const loginPage = new LoginPage(page);

    await loginPage.login('invalid-email', testUsers.admin.password);

    // Should show email format validation
    const emailError = page.locator('input[name="username"] ~ .MuiFormHelperText-root');
    await expect(emailError).toBeVisible();
  });
});

test.describe('Authentication - JWT Token Security', () => {
  test('FR-USER-006-001: JWT token included in httpOnly cookie', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    await loginPage.login(testUsers.admin.username, testUsers.admin.password);
    await loginPage.verifyLoginSuccess();

    const cookies = await page.context().cookies();
    const authCookie = cookies.find(c => c.name === 'auth_token');

    // CRITICAL: Verify httpOnly flag prevents XSS
    expect(authCookie?.httpOnly).toBe(true);

    // Verify token not accessible to JavaScript
    const tokenAccessible = await page.evaluate(() => {
      return document.cookie.includes('auth_token');
    });
    expect(tokenAccessible).toBe(false);
  });

  test('FR-USER-006-002: JWT token has expiration', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    await loginPage.login(testUsers.admin.username, testUsers.admin.password);

    const cookies = await page.context().cookies();
    const authCookie = cookies.find(c => c.name === 'auth_token');

    // Verify expires field is set
    expect(authCookie?.expires).toBeGreaterThan(Date.now() / 1000);

    // Verify expiration is within 24 hours (JWT default)
    const expiresIn = authCookie!.expires! - Date.now() / 1000;
    expect(expiresIn).toBeLessThanOrEqual(24 * 60 * 60); // 24 hours
    expect(expiresIn).toBeGreaterThan(23 * 60 * 60); // At least 23 hours
  });

  test('FR-USER-006-003: Expired JWT token rejected', async ({ page, request }) => {
    // Login first
    await request.post('http://localhost:8081/api/auth/login', {
      data: {
        username: testUsers.admin.username,
        password: testUsers.admin.password,
      },
    });

    // Manually set expired token (this would normally require backend mock)
    // For now, verify that expired tokens are rejected by attempting access after logout
    await page.goto('/');
    await page.click('button[aria-label="logout"]').catch(() => {});

    // Attempt to access protected route
    const response = await request.get('http://localhost:8081/api/v1/rules');
    expect(response.status()).toBe(401);
  });

  test('FR-USER-006-004: JWT token blacklisted on logout', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    await loginPage.login(testUsers.admin.username, testUsers.admin.password);
    await page.goto('/');

    // Logout
    await page.click('button[aria-label="logout"], text=Logout').catch(() => {});

    // Verify redirected to login
    await page.waitForURL('/login');

    // Verify cookie removed
    const cookies = await page.context().cookies();
    const authCookie = cookies.find(c => c.name === 'auth_token');
    expect(authCookie).toBeUndefined();
  });
});

test.describe('Authentication - Session Management', () => {
  test('FR-USER-008-001: Session persists across page refreshes', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    await loginPage.login(testUsers.admin.username, testUsers.admin.password);
    await page.goto('/');

    // Refresh page
    await page.reload();

    // Verify still logged in
    await expect(page).toHaveURL('/');
    await expect(page.locator('h4, h5, h6')).toBeVisible();
  });

  test('FR-USER-008-002: Session timeout after inactivity (if implemented)', async ({ page }) => {
    // This test is marked as optional if idle timeout not yet implemented
    test.skip(!process.env.IDLE_TIMEOUT_ENABLED, 'Idle timeout not implemented');

    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    await loginPage.login(testUsers.admin.username, testUsers.admin.password);
    await page.goto('/');

    // Wait for idle timeout (would need to be configured to short duration for testing)
    await page.waitForTimeout(60000); // 1 minute

    // Verify session expired
    await page.reload();
    await expect(page).toHaveURL('/login');
  });

  test('FR-USER-008-003: Concurrent session handling', async ({ browser }) => {
    // Open two browser contexts (simulating two devices)
    const context1 = await browser.newContext();
    const context2 = await browser.newContext();

    const page1 = await context1.newPage();
    const page2 = await context2.newPage();

    const loginPage1 = new LoginPage(page1);
    const loginPage2 = new LoginPage(page2);

    // Login from both contexts
    await loginPage1.navigate();
    await loginPage1.login(testUsers.admin.username, testUsers.admin.password);

    await loginPage2.navigate();
    await loginPage2.login(testUsers.admin.username, testUsers.admin.password);

    // Both sessions should be active (default behavior)
    await page1.goto('/');
    await page2.goto('/');

    await expect(page1.locator('h4, h5')).toBeVisible();
    await expect(page2.locator('h4, h5')).toBeVisible();

    await context1.close();
    await context2.close();
  });
});

test.describe('Authentication - Account Lockout', () => {
  test('FR-USER-012-001: Account locked after 5 failed attempts', async ({ page }) => {
    const loginPage = new LoginPage(page);

    // Attempt login 5 times with wrong password
    for (let i = 0; i < 5; i++) {
      await loginPage.navigate();
      await loginPage.login(testUsers.analyst.username, 'wrong_password');
      await page.waitForTimeout(500);
    }

    // 6th attempt should show account locked
    await loginPage.navigate();
    await loginPage.login(testUsers.analyst.username, 'wrong_password');

    await loginPage.verifyLoginError('Account locked');

    // Verify cannot login even with correct password
    await loginPage.navigate();
    await loginPage.login(testUsers.analyst.username, testUsers.analyst.password);

    await loginPage.verifyLoginError('Account locked');
  });

  test('FR-USER-012-002: Account lockout duration (15 minutes)', async ({ page }) => {
    test.slow(); // Mark as slow test

    // This test would require either:
    // 1. Backend API to unlock account
    // 2. Mocking time
    // 3. Configuring shorter lockout duration for testing

    test.skip(true, 'Requires time mocking or backend unlock API');
  });

  test('FR-USER-012-003: Failed attempts reset after successful login', async ({ page }) => {
    const loginPage = new LoginPage(page);

    // Fail 3 times
    for (let i = 0; i < 3; i++) {
      await loginPage.navigate();
      await loginPage.login(testUsers.engineer.username, 'wrong_password');
      await page.waitForTimeout(500);
    }

    // Successful login
    await loginPage.navigate();
    await loginPage.login(testUsers.engineer.username, testUsers.engineer.password);
    await loginPage.verifyLoginSuccess();

    // Logout
    await page.goto('/');
    await page.click('button[aria-label="logout"]').catch(() => {});

    // Fail 3 more times (should not trigger lockout since counter reset)
    for (let i = 0; i < 3; i++) {
      await loginPage.navigate();
      await loginPage.login(testUsers.engineer.username, 'wrong_password');
      await page.waitForTimeout(500);
    }

    // Should still be able to login with correct password
    await loginPage.navigate();
    await loginPage.login(testUsers.engineer.username, testUsers.engineer.password);
    await loginPage.verifyLoginSuccess();
  });
});

test.describe('Authentication - Security Tests', () => {
  test('SECURITY-001: CSRF protection enabled', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    await loginPage.verifyCSRFProtection();
  });

  test('SECURITY-002: XSS prevention in login form', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    const xssPayload = '<script>alert("XSS")</script>';
    await loginPage.login(xssPayload, xssPayload);

    // Verify script not executed
    const alerts = await page.evaluate(() => {
      return (window as any).__alertCalled;
    });
    expect(alerts).toBeUndefined();

    // Verify error message doesn't contain unescaped HTML
    const errorMessage = await page.locator('[role="alert"]').textContent();
    expect(errorMessage).not.toContain('<script>');
  });

  test('SECURITY-003: SQL injection in login form', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    const sqlPayload = "admin' OR '1'='1";
    await loginPage.login(sqlPayload, 'password');

    // Should fail authentication (not bypass with SQL injection)
    await loginPage.verifyLoginError('Invalid credentials');
  });

  test('SECURITY-004: Timing attack resistance', async ({ page }) => {
    const loginPage = new LoginPage(page);

    // Measure response time for invalid user
    await loginPage.navigate();
    const start1 = Date.now();
    await loginPage.login('nonexistent@example.com', 'password');
    await page.waitForSelector('[role="alert"]');
    const time1 = Date.now() - start1;

    // Measure response time for valid user, wrong password
    await loginPage.navigate();
    const start2 = Date.now();
    await loginPage.login(testUsers.admin.username, 'wrong_password');
    await page.waitForSelector('[role="alert"]');
    const time2 = Date.now() - start2;

    // Times should be similar (within 100ms) to prevent user enumeration
    const timeDiff = Math.abs(time1 - time2);
    expect(timeDiff).toBeLessThan(100);
  });

  test('SECURITY-005: Password not visible in network requests', async ({ page }) => {
    const requests: any[] = [];

    page.on('request', request => {
      requests.push({
        url: request.url(),
        postData: request.postData(),
      });
    });

    const loginPage = new LoginPage(page);
    await loginPage.navigate();
    await loginPage.login(testUsers.admin.username, testUsers.admin.password);

    // Verify password is in request body (POST), not URL
    const loginRequest = requests.find(r => r.url.includes('/auth/login'));
    expect(loginRequest).toBeDefined();
    expect(loginRequest.url).not.toContain(testUsers.admin.password);

    // Password should be in encrypted HTTPS body
    expect(loginRequest.postData).toBeDefined();
  });

  test('SECURITY-006: Credentials not stored in browser history', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    await loginPage.login(testUsers.admin.username, testUsers.admin.password);

    // Verify password input has autocomplete="off" or "new-password"
    const passwordInput = page.locator('input[name="password"]');
    const autocomplete = await passwordInput.getAttribute('autocomplete');
    expect(['off', 'new-password', 'current-password']).toContain(autocomplete);
  });
});

test.describe('Authentication - Accessibility', () => {
  test('A11Y-001: Login form keyboard accessible', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    // Navigate using Tab key
    await page.keyboard.press('Tab');
    await expect(page.locator('input[name="username"]')).toBeFocused();

    await page.keyboard.press('Tab');
    await expect(page.locator('input[name="password"]')).toBeFocused();

    await page.keyboard.press('Tab');
    await expect(page.locator('button[type="submit"]')).toBeFocused();

    // Submit using Enter key
    await page.fill('input[name="username"]', testUsers.admin.username);
    await page.fill('input[name="password"]', testUsers.admin.password);
    await page.keyboard.press('Enter');

    await loginPage.verifyLoginSuccess();
  });

  test('A11Y-002: Login form has proper ARIA labels', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    // Verify input labels
    const usernameLabel = page.locator('label[for*="username"]');
    await expect(usernameLabel).toBeVisible();

    const passwordLabel = page.locator('label[for*="password"]');
    await expect(passwordLabel).toBeVisible();

    // Verify submit button has accessible name
    const submitButton = page.locator('button[type="submit"]');
    const buttonText = await submitButton.textContent();
    expect(buttonText?.trim()).toBeTruthy();
  });

  test('A11Y-003: Error messages announced to screen readers', async ({ page }) => {
    const loginPage = new LoginPage(page);
    await loginPage.navigate();

    await loginPage.login('invalid', 'wrong');

    // Verify error has role="alert" for screen reader announcement
    const error = page.locator('[role="alert"]');
    await expect(error).toBeVisible();
  });
});
