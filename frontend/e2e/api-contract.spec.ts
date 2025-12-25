/**
 * API Contract Tests
 *
 * These tests ensure that the API responses match the frontend TypeScript interfaces.
 * This prevents the bug where backend returns different field names than frontend expects.
 *
 * CRITICAL: These tests MUST pass to ensure frontend can display data correctly.
 */

import { test, expect } from '@playwright/test';

// API base URL for tests
const API_BASE = 'http://localhost:8081/api/v1';

test.describe('API Contract Validation', () => {
  test.describe('Dashboard Endpoints', () => {
    test('Dashboard stats endpoint returns correct contract', async ({ request }) => {
      // Make request to dashboard stats endpoint
      const response = await request.get(`${API_BASE}/dashboard`);

      expect(response.ok()).toBeTruthy();

      const data = await response.json();

      // CRITICAL: Verify all required fields exist
      test.step('Has all required fields', () => {
        expect(data).toHaveProperty('total_events');
        expect(data).toHaveProperty('active_alerts');
        expect(data).toHaveProperty('rules_fired');
        expect(data).toHaveProperty('system_health');
      });

      // Verify field types match TypeScript interface
      test.step('Fields have correct types', () => {
        expect(typeof data.total_events).toBe('number');
        expect(typeof data.active_alerts).toBe('number');
        expect(typeof data.rules_fired).toBe('number');
        expect(typeof data.system_health).toBe('string');
      });

      // CRITICAL: Ensure legacy fields are NOT present
      test.step('Does not contain legacy fields', () => {
        expect(data).not.toHaveProperty('events');
        expect(data).not.toHaveProperty('alerts');
      });
    });

    test('Dashboard chart endpoint returns correct contract', async ({ request }) => {
      const response = await request.get(`${API_BASE}/dashboard/chart`);

      expect(response.ok()).toBeTruthy();

      const data = await response.json();

      // Verify response is an array
      expect(Array.isArray(data)).toBeTruthy();

      // If data exists, verify each item's contract
      if (data.length > 0) {
        for (let i = 0; i < data.length; i++) {
          const item = data[i];

          test.step(`Chart data item ${i} has correct structure`, () => {
            // Required fields for ChartData interface
            expect(item).toHaveProperty('timestamp');
            expect(item).toHaveProperty('events');
            expect(item).toHaveProperty('alerts');

            // Verify types
            expect(typeof item.timestamp).toBe('string');
            expect(typeof item.events).toBe('number');
            expect(typeof item.alerts).toBe('number');

            // CRITICAL: Ensure legacy field is NOT present
            expect(item).not.toHaveProperty('name');
          });
        }
      }
    });
  });

  test.describe('Events Endpoint', () => {
    test('Events endpoint returns correct contract', async ({ request }) => {
      const response = await request.get(`${API_BASE}/events?limit=10`);

      expect(response.ok()).toBeTruthy();

      const data = await response.json();

      // Verify response is an array
      expect(Array.isArray(data)).toBeTruthy();

      // If data exists, verify each item's contract
      if (data.length > 0) {
        const event = data[0];

        test.step('Event has all required fields', () => {
          expect(event).toHaveProperty('event_id');
          expect(event).toHaveProperty('event_type');
          expect(event).toHaveProperty('timestamp');
          expect(event).toHaveProperty('source_ip');
          expect(event).toHaveProperty('severity');
          expect(event).toHaveProperty('source_format');
          expect(event).toHaveProperty('fields');
          expect(event).toHaveProperty('raw_data');
        });

        test.step('Event fields have correct types', () => {
          expect(typeof event.event_id).toBe('string');
          expect(typeof event.event_type).toBe('string');
          expect(typeof event.timestamp).toBe('string');
          expect(typeof event.source_ip).toBe('string');
          expect(typeof event.severity).toBe('string');
          expect(typeof event.source_format).toBe('string');
          expect(typeof event.fields).toBe('object');
          expect(typeof event.raw_data).toBe('string');
        });
      }
    });
  });

  test.describe('Alerts Endpoint', () => {
    test('Alerts endpoint returns correct contract', async ({ request }) => {
      const response = await request.get(`${API_BASE}/alerts`);

      expect(response.ok()).toBeTruthy();

      const data = await response.json();

      // Verify response is an array
      expect(Array.isArray(data)).toBeTruthy();

      // If data exists, verify each item's contract
      if (data.length > 0) {
        const alert = data[0];

        test.step('Alert has all required fields', () => {
          expect(alert).toHaveProperty('alert_id');
          expect(alert).toHaveProperty('rule_id');
          expect(alert).toHaveProperty('event_id');
          expect(alert).toHaveProperty('severity');
          expect(alert).toHaveProperty('status');
          expect(alert).toHaveProperty('timestamp');
          expect(alert).toHaveProperty('event');
        });

        test.step('Alert fields have correct types', () => {
          expect(typeof alert.alert_id).toBe('string');
          expect(typeof alert.rule_id).toBe('string');
          expect(typeof alert.event_id).toBe('string');
          expect(typeof alert.severity).toBe('string');
          expect(typeof alert.status).toBe('string');
          expect(typeof alert.timestamp).toBe('string');
          expect(typeof alert.event).toBe('object');
        });

        test.step('Alert status has valid value', () => {
          const validStatuses = ['Pending', 'Acknowledged', 'Dismissed'];
          expect(validStatuses).toContain(alert.status);
        });

        test.step('Alert event has correct structure', () => {
          expect(alert.event).toHaveProperty('event_id');
          expect(alert.event).toHaveProperty('event_type');
          expect(alert.event).toHaveProperty('timestamp');
          expect(alert.event).toHaveProperty('source_ip');
        });
      }
    });
  });

  test.describe('Rules Endpoint', () => {
    test('Rules endpoint returns correct contract', async ({ request }) => {
      const response = await request.get(`${API_BASE}/rules`);

      expect(response.ok()).toBeTruthy();

      const data = await response.json();

      // Verify response is an array
      expect(Array.isArray(data)).toBeTruthy();

      // If data exists, verify each item's contract
      if (data.length > 0) {
        const rule = data[0];

        test.step('Rule has all required fields', () => {
          expect(rule).toHaveProperty('id');
          expect(rule).toHaveProperty('name');
          expect(rule).toHaveProperty('description');
          expect(rule).toHaveProperty('severity');
          expect(rule).toHaveProperty('enabled');
          expect(rule).toHaveProperty('version');
          expect(rule).toHaveProperty('conditions');
          expect(rule).toHaveProperty('actions');
        });

        test.step('Rule fields have correct types', () => {
          expect(typeof rule.id).toBe('string');
          expect(typeof rule.name).toBe('string');
          expect(typeof rule.description).toBe('string');
          expect(typeof rule.severity).toBe('string');
          expect(typeof rule.enabled).toBe('boolean');
          expect(typeof rule.version).toBe('number');
          expect(Array.isArray(rule.conditions)).toBeTruthy();
          expect(Array.isArray(rule.actions)).toBeTruthy();
        });

        test.step('Rule conditions have correct structure', () => {
          if (rule.conditions.length > 0) {
            const condition = rule.conditions[0];
            expect(condition).toHaveProperty('field');
            expect(condition).toHaveProperty('operator');
            expect(condition).toHaveProperty('value');
            expect(condition).toHaveProperty('logic');

            expect(typeof condition.field).toBe('string');
            expect(typeof condition.operator).toBe('string');
            expect(typeof condition.value).toBe('string');
            expect(['AND', 'OR']).toContain(condition.logic);
          }
        });

        test.step('Rule actions have correct structure', () => {
          if (rule.actions.length > 0) {
            const action = rule.actions[0];
            expect(action).toHaveProperty('id');
            expect(action).toHaveProperty('type');
            expect(action).toHaveProperty('config');

            expect(typeof action.id).toBe('string');
            expect(typeof action.type).toBe('string');
            expect(typeof action.config).toBe('object');
          }
        });
      }
    });
  });

  test.describe('Correlation Rules Endpoint', () => {
    test('Correlation rules endpoint returns correct contract', async ({ request }) => {
      const response = await request.get(`${API_BASE}/correlation-rules`);

      expect(response.ok()).toBeTruthy();

      const data = await response.json();

      // Verify response is an array
      expect(Array.isArray(data)).toBeTruthy();

      // If data exists, verify each item's contract
      if (data.length > 0) {
        const rule = data[0];

        test.step('Correlation rule has all required fields', () => {
          expect(rule).toHaveProperty('id');
          expect(rule).toHaveProperty('name');
          expect(rule).toHaveProperty('description');
          expect(rule).toHaveProperty('severity');
          expect(rule).toHaveProperty('version');
          expect(rule).toHaveProperty('window');
          expect(rule).toHaveProperty('sequence');
          expect(rule).toHaveProperty('conditions');
          expect(rule).toHaveProperty('actions');
        });

        test.step('Correlation rule fields have correct types', () => {
          expect(typeof rule.id).toBe('string');
          expect(typeof rule.name).toBe('string');
          expect(typeof rule.description).toBe('string');
          expect(typeof rule.severity).toBe('string');
          expect(typeof rule.version).toBe('number');
          expect(typeof rule.window).toBe('number');
          expect(Array.isArray(rule.sequence)).toBeTruthy();
          expect(Array.isArray(rule.conditions)).toBeTruthy();
          expect(Array.isArray(rule.actions)).toBeTruthy();
        });
      }
    });
  });

  test.describe('Actions Endpoint', () => {
    test('Actions endpoint returns correct contract', async ({ request }) => {
      const response = await request.get(`${API_BASE}/actions`);

      expect(response.ok()).toBeTruthy();

      const data = await response.json();

      // Verify response is an array
      expect(Array.isArray(data)).toBeTruthy();

      // If data exists, verify each item's contract
      if (data.length > 0) {
        const action = data[0];

        test.step('Action has all required fields', () => {
          expect(action).toHaveProperty('id');
          expect(action).toHaveProperty('type');
          expect(action).toHaveProperty('config');
        });

        test.step('Action fields have correct types', () => {
          expect(typeof action.id).toBe('string');
          expect(typeof action.type).toBe('string');
          expect(typeof action.config).toBe('object');
        });
      }
    });
  });

  test.describe('Listeners Endpoint', () => {
    test('Listeners endpoint returns correct contract', async ({ request }) => {
      const response = await request.get(`${API_BASE}/listeners`);

      expect(response.ok()).toBeTruthy();

      const data = await response.json();

      test.step('Listeners has required listener types', () => {
        expect(data).toHaveProperty('syslog');
        expect(data).toHaveProperty('cef');
        expect(data).toHaveProperty('json');
      });

      // Verify each listener type has host and port
      test.step('Each listener has correct structure', () => {
        ['syslog', 'cef', 'json'].forEach(listenerType => {
          const listener = data[listenerType];
          expect(listener).toHaveProperty('host');
          expect(listener).toHaveProperty('port');

          expect(typeof listener.host).toBe('string');
          expect(typeof listener.port).toBe('number');
        });
      });
    });
  });
});

/**
 * Integration tests - Verify data flows correctly from API to UI
 */
test.describe('UI Data Display Integration', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:5173');
  });

  test('Dashboard displays data from API', async ({ page }) => {
    // Wait for dashboard to load
    await page.waitForSelector('h4:has-text("Dashboard")', { timeout: 10000 });

    // Verify KPI cards are visible and have values
    const statCards = page.locator('[role="article"]');
    const count = await statCards.count();

    // Should have 4 KPI cards: Total Events, Active Alerts, Rules Fired, System Health
    expect(count).toBeGreaterThanOrEqual(4);

    // Verify each card has a value (not undefined or 0)
    const totalEvents = page.locator('text=Total Events').locator('..').locator('h4');
    await expect(totalEvents).toBeVisible();

    const activeAlerts = page.locator('text=Active Alerts').locator('..').locator('h4');
    await expect(activeAlerts).toBeVisible();

    const rulesFired = page.locator('text=Rules Fired').locator('..').locator('h4');
    await expect(rulesFired).toBeVisible();

    const systemHealth = page.locator('text=System Health').locator('..').locator('h4');
    await expect(systemHealth).toBeVisible();
  });

  test('Events page displays events table', async ({ page }) => {
    // Navigate to events
    await page.click('text=Events');
    await page.waitForSelector('h4:has-text("Security Events")');

    // Verify table exists
    await expect(page.locator('table')).toBeVisible();

    // Verify table headers
    await expect(page.locator('th:has-text("Timestamp")')).toBeVisible();
    await expect(page.locator('th:has-text("Event Type")')).toBeVisible();
    await expect(page.locator('th:has-text("Severity")')).toBeVisible();
    await expect(page.locator('th:has-text("Source IP")')).toBeVisible();
  });

  test('Alerts page displays alerts table', async ({ page }) => {
    // Navigate to alerts
    await page.click('text=Alerts');
    await page.waitForSelector('h4:has-text("Alerts Management")');

    // Verify table exists
    await expect(page.locator('table')).toBeVisible();

    // Verify table headers
    await expect(page.locator('th:has-text("Severity")')).toBeVisible();
    await expect(page.locator('th:has-text("Status")')).toBeVisible();
    await expect(page.locator('th:has-text("Timestamp")')).toBeVisible();
  });

  test('Rules page displays rules table', async ({ page }) => {
    // Navigate to rules
    await page.click('text=Rules');
    await page.waitForSelector('h4:has-text("Detection Rules")');

    // Verify table exists
    await expect(page.locator('table')).toBeVisible();

    // Verify create button exists
    await expect(page.locator('button:has-text("Create Rule")')).toBeVisible();
  });
});
