/**
 * Authentication Fixtures
 *
 * Provides authenticated browser context for tests that require login.
 * Implements best practices for E2E authentication testing.
 */

import { test as base, expect } from '@playwright/test';

export interface AuthenticatedUser {
  username: string;
  role: 'admin' | 'engineer' | 'analyst' | 'viewer';
  token?: string;
}

type AuthFixtures = {
  authenticatedPage: typeof base;
  adminUser: AuthenticatedUser;
  engineerUser: AuthenticatedUser;
  analystUser: AuthenticatedUser;
  viewerUser: AuthenticatedUser;
};

// Default test users for different roles
export const testUsers = {
  admin: {
    username: 'admin@cerberus.local',
    password: 'Admin123!@#',
    role: 'admin' as const,
  },
  engineer: {
    username: 'engineer@cerberus.local',
    password: 'Engineer123!@#',
    role: 'engineer' as const,
  },
  analyst: {
    username: 'analyst@cerberus.local',
    password: 'Analyst123!@#',
    role: 'analyst' as const,
  },
  viewer: {
    username: 'viewer@cerberus.local',
    password: 'Viewer123!@#',
    role: 'viewer' as const,
  },
};

/**
 * Performs login via UI
 */
export async function loginViaUI(
  page: any,
  username: string,
  password: string
): Promise<void> {
  await page.goto('/login');
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');

  // Wait for navigation to dashboard
  await page.waitForURL('/', { timeout: 10000 });
}

/**
 * Performs login via API (faster for setup)
 */
export async function loginViaAPI(
  page: any,
  username: string,
  password: string
): Promise<string> {
  const response = await page.request.post('http://localhost:8081/api/auth/login', {
    data: { username, password },
  });

  expect(response.ok()).toBeTruthy();

  // Extract token from cookie or response
  const cookies = await page.context().cookies();
  const authCookie = cookies.find((c: any) => c.name === 'auth_token');

  return authCookie?.value || '';
}

/**
 * Extended test fixture with authentication
 */
export const test = base.extend<AuthFixtures>({
  adminUser: async ({}, use) => {
    await use({
      username: testUsers.admin.username,
      role: 'admin',
    });
  },

  engineerUser: async ({}, use) => {
    await use({
      username: testUsers.engineer.username,
      role: 'engineer',
    });
  },

  analystUser: async ({}, use) => {
    await use({
      username: testUsers.analyst.username,
      role: 'analyst',
    });
  },

  viewerUser: async ({}, use) => {
    await use({
      username: testUsers.viewer.username,
      role: 'viewer',
    });
  },

  authenticatedPage: async ({ page }, use) => {
    // Login before each test using this fixture
    await loginViaAPI(
      page,
      testUsers.admin.username,
      testUsers.admin.password
    );

    await use(page as any);

    // Logout after test
    await page.goto('/logout').catch(() => {});
  },
});

export { expect };
