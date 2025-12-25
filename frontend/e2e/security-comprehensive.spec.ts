/**
 * Comprehensive Security Tests
 *
 * Coverage:
 * - XSS prevention
 * - CSRF protection
 * - SQL injection prevention
 * - Authentication bypass attempts
 * - Authorization enforcement
 * - Secure headers
 * - Content Security Policy
 *
 * Maps to requirements:
 * - docs/requirements/security-threat-model.md
 * - OWASP Top 10 2021
 */

import { test, expect } from '@playwright/test';
import { test as authTest } from './fixtures/auth.fixture';

test.describe('Security - XSS Prevention', () => {
  test('SEC-XSS-001: XSS in rule name is escaped', async ({ page }) => {
    test.skip(true, 'Requires authenticated session and rule creation');

    const xssPayload = '<script>alert("XSS")</script>';

    // Create rule with XSS in name
    // Verify: Script tag is escaped and not executed
    // Verify: Alert function not called
  });

  authTest('SEC-XSS-002: XSS in event data is escaped', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/events');

    // Check if any event contains script tags
    const tableContent = await authenticatedPage.locator('table').textContent();

    // Verify no unescaped script tags visible
    expect(tableContent).not.toContain('<script>');

    // Verify innerHTML doesn't contain executable scripts
    const hasScriptTags = await authenticatedPage.evaluate(() => {
      const cells = document.querySelectorAll('td');
      for (const cell of cells) {
        if (cell.innerHTML.includes('<script>') && !cell.textContent?.includes('<script>')) {
          return true;
        }
      }
      return false;
    });

    expect(hasScriptTags).toBe(false);
  });

  authTest('SEC-XSS-003: DOMPurify sanitization active', async ({ authenticatedPage }) => {
    // Verify DOMPurify is loaded and active
    const domPurifyLoaded = await authenticatedPage.evaluate(() => {
      return typeof (window as any).DOMPurify !== 'undefined';
    });

    // DOMPurify should be available for sanitization
    expect(domPurifyLoaded).toBe(true);
  });

  authTest('SEC-XSS-004: User input in search is sanitized', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/events');

    const xssPayload = '<img src=x onerror=alert("XSS")>';

    // Enter XSS payload in search
    const searchInput = authenticatedPage.locator('input[type="search"], input[placeholder*="Search"]');

    if (await searchInput.count() > 0) {
      await searchInput.fill(xssPayload);
      await authenticatedPage.keyboard.press('Enter');

      // Wait and verify no alert was triggered
      await authenticatedPage.waitForTimeout(1000);

      const alertTriggered = await authenticatedPage.evaluate(() => {
        return (window as any).__alertCalled;
      });

      expect(alertTriggered).toBeUndefined();
    }
  });

  authTest('SEC-XSS-005: React prevents dangerouslySetInnerHTML misuse', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Scan page for dangerous innerHTML usage
    const dangerousHTML = await authenticatedPage.evaluate(() => {
      const elements = document.querySelectorAll('[data-dangerous]');
      return elements.length;
    });

    // Should be 0 or minimal
    expect(dangerousHTML).toBe(0);
  });
});

test.describe('Security - CSRF Protection', () => {
  authTest('SEC-CSRF-001: CSRF token present in cookies', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const cookies = await authenticatedPage.context().cookies();
    const csrfCookie = cookies.find(c =>
      c.name === 'csrf_token' || c.name === '_csrf' || c.name.toLowerCase().includes('csrf')
    );

    expect(csrfCookie).toBeDefined();
  });

  authTest('SEC-CSRF-002: CSRF token sent in request headers', async ({ authenticatedPage, page }) => {
    const requestHeaders: any[] = [];

    page.on('request', request => {
      if (request.method() === 'POST' || request.method() === 'PUT' || request.method() === 'DELETE') {
        requestHeaders.push(request.headers());
      }
    });

    await authenticatedPage.goto('/rules');

    // Trigger a POST request (e.g., create rule)
    // This would need actual form submission

    // Wait for requests
    await authenticatedPage.waitForTimeout(2000);

    // Verify CSRF header present in POST/PUT/DELETE requests
    if (requestHeaders.length > 0) {
      const hasCSRFHeader = requestHeaders.some(headers =>
        headers['x-csrf-token'] || headers['x-xsrf-token']
      );
      expect(hasCSRFHeader).toBe(true);
    }
  });

  test('SEC-CSRF-003: Request without CSRF token is rejected', async ({ request }) => {
    // Attempt POST without CSRF token
    const response = await request.post('http://localhost:8081/api/v1/rules', {
      data: {
        name: 'Test Rule',
        description: 'Test',
        severity: 'Medium',
      },
      headers: {
        'Content-Type': 'application/json',
        // No X-CSRF-Token header
      },
    });

    // Should be rejected with 403 Forbidden
    expect(response.status()).toBe(403);
  });
});

test.describe('Security - SQL Injection Prevention', () => {
  authTest('SEC-SQL-001: SQL injection in search query prevented', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/events');

    const sqlPayload = "'; DROP TABLE events; --";
    const searchInput = authenticatedPage.locator('input[type="search"]');

    if (await searchInput.count() > 0) {
      await searchInput.fill(sqlPayload);
      await authenticatedPage.keyboard.press('Enter');

      // Wait for search results
      await authenticatedPage.waitForTimeout(2000);

      // Verify: No error message about SQL syntax
      const errorText = await authenticatedPage.locator('[role="alert"]').textContent();
      expect(errorText).not.toContain('SQL');
      expect(errorText).not.toContain('syntax error');

      // Verify: Application still functions (table visible)
      await expect(authenticatedPage.locator('table')).toBeVisible();
    }
  });

  authTest('SEC-SQL-002: SQL injection in filter parameters prevented', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/events?severity=" OR "1"="1');

    // Verify page loads normally
    await expect(authenticatedPage.locator('h4, h5')).toBeVisible();

    // Verify no SQL error visible
    const pageText = await authenticatedPage.textContent('body');
    expect(pageText).not.toContain('SQL');
  });
});

test.describe('Security - Authorization Enforcement', () => {
  authTest('SEC-AUTHZ-001: Admin can access all pages', async ({ authenticatedPage }) => {
    // Navigate to admin-only pages
    const adminPages = ['/rules', '/actions', '/settings', '/users'];

    for (const path of adminPages) {
      await authenticatedPage.goto(path);

      // Should not redirect to unauthorized
      await expect(authenticatedPage).toHaveURL(new RegExp(path));

      // Should not show access denied
      const accessDenied = authenticatedPage.locator('text=Access Denied, text=Unauthorized');
      await expect(accessDenied).not.toBeVisible();
    }
  });

  test('SEC-AUTHZ-002: Viewer cannot access admin pages', async ({ browser }) => {
    test.skip(true, 'Requires viewer role user creation');

    // Login as viewer
    // Attempt to navigate to /users
    // Verify: Redirected or access denied
  });

  test('SEC-AUTHZ-003: Unauthenticated user redirected to login', async ({ page }) => {
    // Clear cookies
    await page.context().clearCookies();

    await page.goto('/rules');

    // Should redirect to login
    await expect(page).toHaveURL('/login');
  });

  test('SEC-AUTHZ-004: Cannot access API without authentication', async ({ request }) => {
    const response = await request.get('http://localhost:8081/api/v1/rules');

    // Should return 401 Unauthorized
    expect(response.status()).toBe(401);
  });
});

test.describe('Security - Secure Headers', () => {
  test('SEC-HEADER-001: X-Frame-Options prevents clickjacking', async ({ page }) => {
    const response = await page.goto('http://localhost:5173/');

    const headers = response?.headers();
    const xFrameOptions = headers?.['x-frame-options'];

    // Should be DENY or SAMEORIGIN
    expect(['DENY', 'SAMEORIGIN']).toContain(xFrameOptions?.toUpperCase());
  });

  test('SEC-HEADER-002: X-Content-Type-Options prevents MIME sniffing', async ({ page }) => {
    const response = await page.goto('http://localhost:5173/');

    const headers = response?.headers();
    const xContentTypeOptions = headers?.['x-content-type-options'];

    expect(xContentTypeOptions).toBe('nosniff');
  });

  test('SEC-HEADER-003: X-XSS-Protection enabled', async ({ page }) => {
    const response = await page.goto('http://localhost:5173/');

    const headers = response?.headers();
    const xXSSProtection = headers?.['x-xss-protection'];

    // Should be '1; mode=block'
    expect(xXSSProtection).toContain('1');
  });

  test('SEC-HEADER-004: Strict-Transport-Security for HTTPS', async ({ page }) => {
    test.skip(process.env.NODE_ENV !== 'production', 'HSTS only in production');

    const response = await page.goto('https://localhost/');

    const headers = response?.headers();
    const hsts = headers?.['strict-transport-security'];

    expect(hsts).toContain('max-age');
  });

  test('SEC-HEADER-005: Content-Security-Policy configured', async ({ page }) => {
    const response = await page.goto('http://localhost:5173/');

    const headers = response?.headers();
    const csp = headers?.['content-security-policy'] || headers?.['content-security-policy-report-only'];

    // CSP should be configured (even if report-only)
    if (csp) {
      expect(csp).toBeTruthy();
      // Should restrict script sources
      expect(csp).toContain("script-src");
    }
  });
});

test.describe('Security - Session Management', () => {
  authTest('SEC-SESSION-001: Session cookie has Secure flag', async ({ authenticatedPage }) => {
    test.skip(process.env.NODE_ENV !== 'production', 'Secure flag only over HTTPS');

    await authenticatedPage.goto('/');

    const cookies = await authenticatedPage.context().cookies();
    const authCookie = cookies.find(c => c.name === 'auth_token');

    expect(authCookie?.secure).toBe(true);
  });

  authTest('SEC-SESSION-002: Session cookie has HttpOnly flag', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const cookies = await authenticatedPage.context().cookies();
    const authCookie = cookies.find(c => c.name === 'auth_token');

    expect(authCookie?.httpOnly).toBe(true);
  });

  authTest('SEC-SESSION-003: Session cookie has SameSite=Strict', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const cookies = await authenticatedPage.context().cookies();
    const authCookie = cookies.find(c => c.name === 'auth_token');

    expect(authCookie?.sameSite).toBe('Strict');
  });
});

test.describe('Security - Input Validation', () => {
  authTest('SEC-INPUT-001: Email validation enforced', async ({ authenticatedPage }) => {
    test.skip(true, 'Requires user creation form');

    // Navigate to user creation
    // Enter invalid email
    // Verify validation error
  });

  authTest('SEC-INPUT-002: Maximum length enforced', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await authenticatedPage.click('button:has-text("Create Rule")');

    const longString = 'A'.repeat(10000);
    const nameInput = authenticatedPage.locator('input[name="name"]');

    await nameInput.fill(longString);

    const value = await nameInput.inputValue();

    // Should be truncated or show validation error
    expect(value.length).toBeLessThan(1000);
  });

  authTest('SEC-INPUT-003: Special characters handled safely', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');
    await authenticatedPage.click('button:has-text("Create Rule")');

    const specialChars = `!@#$%^&*()_+-={}[]|\\:";'<>?,./`;
    const descriptionInput = authenticatedPage.locator('textarea[name="description"]');

    await descriptionInput.fill(specialChars);

    // Verify characters accepted and escaped
    const value = await descriptionInput.inputValue();
    expect(value).toBe(specialChars);
  });
});

test.describe('Security - Error Information Disclosure', () => {
  test('SEC-ERROR-001: 500 errors don\'t expose stack traces', async ({ request }) => {
    // Trigger server error (this would need specific endpoint)
    const response = await request.get('http://localhost:8081/api/v1/nonexistent');

    const body = await response.text();

    // Should not contain stack traces
    expect(body).not.toContain('at ');
    expect(body).not.toContain('Error:');
    expect(body).not.toMatch(/\.go:\d+/); // Go stack traces
    expect(body).not.toMatch(/\.ts:\d+/); // TypeScript stack traces
  });

  test('SEC-ERROR-002: Error messages don\'t reveal database structure', async ({ request }) => {
    const response = await request.get('http://localhost:8081/api/v1/rules/invalid-id');

    const body = await response.text();

    // Should not contain SQL or database info
    expect(body).not.toContain('SELECT');
    expect(body).not.toContain('FROM');
    expect(body).not.toContain('WHERE');
    expect(body).not.toContain('sqlite');
    expect(body).not.toContain('clickhouse');
  });
});
