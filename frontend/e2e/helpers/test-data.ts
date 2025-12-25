/**
 * Test Data Helpers
 *
 * Utilities for creating and cleaning up test data.
 * All operations use real API calls - no mocks.
 *
 * Security:
 * - No hardcoded credentials
 * - Proper authentication for all API calls
 * - Cleanup after tests to prevent data pollution
 */

import { APIRequestContext } from '@playwright/test';
import { Rule, CorrelationRule, Action, Event, DynamicListener, ListenerForm, ListenerTemplate } from '../../src/types';

const BACKEND_URL = 'http://localhost:8081';

export interface TestUser {
  username: string;
  password: string;
  token?: string;
}

export class TestDataHelper {
  constructor(private readonly request: APIRequestContext) {}

  /**
   * Authenticate and get token
   */
  async authenticate(username: string, password: string): Promise<string> {
    const response = await this.request.post(`${BACKEND_URL}/api/v1/auth/login`, {
      data: {
        username,
        password,
      },
    });

    if (!response.ok()) {
      throw new Error(`Authentication failed: ${response.status()} ${await response.text()}`);
    }

    const data = await response.json();
    return data.token;
  }

  /**
   * Create a test rule
   */
  async createRule(token: string, ruleData: Partial<Rule>): Promise<Rule> {
    const response = await this.request.post(`${BACKEND_URL}/api/v1/rules`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      data: {
        name: ruleData.name || 'Test Rule',
        description: ruleData.description || 'Test rule description',
        severity: ruleData.severity || 'Medium',
        enabled: ruleData.enabled !== undefined ? ruleData.enabled : true,
        conditions: ruleData.conditions || [],
        actions: ruleData.actions || [],
        tags: ruleData.tags || [],
        mitre_tactics: ruleData.mitre_tactics || [],
        mitre_techniques: ruleData.mitre_techniques || [],
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to create rule: ${response.status()} ${await response.text()}`);
    }

    return await response.json();
  }

  /**
   * Create a test correlation rule
   */
  async createCorrelationRule(token: string, ruleData: Partial<CorrelationRule>): Promise<CorrelationRule> {
    const response = await this.request.post(`${BACKEND_URL}/api/v1/correlation-rules`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      data: {
        name: ruleData.name || 'Test Correlation Rule',
        description: ruleData.description || 'Test correlation rule description',
        severity: ruleData.severity || 'High',
        version: ruleData.version || 1,
        window: ruleData.window || 300000000000, // 5 minutes in nanoseconds
        sequence: ruleData.sequence || [],
        conditions: ruleData.conditions || [],
        actions: ruleData.actions || [],
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to create correlation rule: ${response.status()} ${await response.text()}`);
    }

    return await response.json();
  }

  /**
   * Create a test action
   */
  async createAction(token: string, actionData: Partial<Action>): Promise<Action> {
    const response = await this.request.post(`${BACKEND_URL}/api/v1/actions`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      data: {
        type: actionData.type || 'webhook',
        config: actionData.config || { url: 'https://example.com/webhook', method: 'POST' },
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to create action: ${response.status()} ${await response.text()}`);
    }

    return await response.json();
  }

  /**
   * Create a test event
   */
  async createEvent(token: string, eventData: Partial<Event>): Promise<Event> {
    const response = await this.request.post(`${BACKEND_URL}/api/v1/events/ingest`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      data: {
        event_type: eventData.event_type || 'test_event',
        source_ip: eventData.source_ip || '192.168.1.100',
        timestamp: eventData.timestamp || new Date().toISOString(),
        severity: eventData.severity || 'Medium',
        fields: eventData.fields || {},
        raw_data: eventData.raw_data || '',
        source_format: eventData.source_format || 'json',
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to create event: ${response.status()} ${await response.text()}`);
    }

    return await response.json();
  }

  /**
   * Get all rules
   */
  async getRules(token: string): Promise<Rule[]> {
    const response = await this.request.get(`${BACKEND_URL}/api/v1/rules`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to get rules: ${response.status()}`);
    }

    return await response.json();
  }

  /**
   * Delete a rule
   */
  async deleteRule(token: string, ruleId: string): Promise<void> {
    const response = await this.request.delete(`${BACKEND_URL}/api/v1/rules/${ruleId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete rule: ${response.status()}`);
    }
  }

  /**
   * Delete a correlation rule
   */
  async deleteCorrelationRule(token: string, ruleId: string): Promise<void> {
    const response = await this.request.delete(`${BACKEND_URL}/api/v1/correlation-rules/${ruleId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete correlation rule: ${response.status()}`);
    }
  }

  /**
   * Delete an action
   */
  async deleteAction(token: string, actionId: string): Promise<void> {
    const response = await this.request.delete(`${BACKEND_URL}/api/v1/actions/${actionId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete action: ${response.status()}`);
    }
  }

  /**
   * Delete all alerts
   */
  async deleteAllAlerts(token: string): Promise<void> {
    const response = await this.request.get(`${BACKEND_URL}/api/v1/alerts`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      return; // No alerts to delete
    }

    const alerts = await response.json();

    for (const alert of alerts) {
      await this.request.delete(`${BACKEND_URL}/api/v1/alerts/${alert.alert_id}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
    }
  }

  /**
   * Clean up all test data
   */
  async cleanupAll(token: string): Promise<void> {
    try {
      // Get and delete all rules
      const rules = await this.getRules(token);
      for (const rule of rules) {
        if (rule.name.includes('Test')) {
          await this.deleteRule(token, rule.id);
        }
      }

      // Delete all alerts
      await this.deleteAllAlerts(token);

      // Note: We don't delete actions or correlation rules created by other tests
      // as they might be in use
    } catch (error) {
      console.warn('Cleanup failed:', error);
    }
  }

  /**
   * Create a test listener
   */
  async createListener(token: string, listenerData: Partial<ListenerForm>): Promise<DynamicListener> {
    const response = await this.request.post(`${BACKEND_URL}/api/v1/listeners`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      data: {
        name: listenerData.name || 'Test Listener',
        description: listenerData.description || 'Test listener description',
        type: listenerData.type || 'syslog',
        protocol: listenerData.protocol || 'tcp',
        host: listenerData.host || '0.0.0.0',
        port: listenerData.port || 5140,
        tls: listenerData.tls || false,
        cert_file: listenerData.cert_file || '',
        key_file: listenerData.key_file || '',
        tags: listenerData.tags || [],
        source: listenerData.source || '',
        field_mapping: listenerData.field_mapping || null,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to create listener: ${response.status()} ${await response.text()}`);
    }

    return await response.json();
  }

  /**
   * Get all listeners with pagination
   */
  async getListeners(token: string, page: number = 1, limit: number = 50): Promise<{ items: DynamicListener[]; total: number }> {
    const response = await this.request.get(`${BACKEND_URL}/api/v1/listeners?page=${page}&limit=${limit}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to get listeners: ${response.status()}`);
    }

    return await response.json();
  }

  /**
   * Get a single listener by ID
   */
  async getListener(token: string, listenerId: string): Promise<DynamicListener> {
    const response = await this.request.get(`${BACKEND_URL}/api/v1/listeners/${listenerId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to get listener: ${response.status()}`);
    }

    return await response.json();
  }

  /**
   * Update a listener
   */
  async updateListener(token: string, listenerId: string, listenerData: Partial<ListenerForm>): Promise<DynamicListener> {
    const response = await this.request.put(`${BACKEND_URL}/api/v1/listeners/${listenerId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      data: listenerData,
    });

    if (!response.ok()) {
      throw new Error(`Failed to update listener: ${response.status()} ${await response.text()}`);
    }

    return await response.json();
  }

  /**
   * Delete a listener
   */
  async deleteListener(token: string, listenerId: string): Promise<void> {
    const response = await this.request.delete(`${BACKEND_URL}/api/v1/listeners/${listenerId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to delete listener: ${response.status()}`);
    }
  }

  /**
   * Start a listener
   */
  async startListener(token: string, listenerId: string): Promise<DynamicListener> {
    const response = await this.request.post(`${BACKEND_URL}/api/v1/listeners/${listenerId}/start`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to start listener: ${response.status()} ${await response.text()}`);
    }

    return await response.json();
  }

  /**
   * Stop a listener
   */
  async stopListener(token: string, listenerId: string): Promise<DynamicListener> {
    const response = await this.request.post(`${BACKEND_URL}/api/v1/listeners/${listenerId}/stop`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to stop listener: ${response.status()} ${await response.text()}`);
    }

    return await response.json();
  }

  /**
   * Restart a listener
   */
  async restartListener(token: string, listenerId: string): Promise<DynamicListener> {
    const response = await this.request.post(`${BACKEND_URL}/api/v1/listeners/${listenerId}/restart`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to restart listener: ${response.status()} ${await response.text()}`);
    }

    return await response.json();
  }

  /**
   * Get listener templates
   */
  async getListenerTemplates(token: string): Promise<ListenerTemplate[]> {
    const response = await this.request.get(`${BACKEND_URL}/api/v1/listener-templates`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok()) {
      throw new Error(`Failed to get listener templates: ${response.status()}`);
    }

    return await response.json();
  }

  /**
   * Create listener from template
   */
  async createListenerFromTemplate(token: string, templateId: string, customData: Partial<ListenerForm>): Promise<DynamicListener> {
    const response = await this.request.post(`${BACKEND_URL}/api/v1/listeners/from-template/${templateId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      data: customData,
    });

    if (!response.ok()) {
      throw new Error(`Failed to create listener from template: ${response.status()} ${await response.text()}`);
    }

    return await response.json();
  }

  /**
   * Wait for listener to reach expected status
   */
  async waitForListenerStatus(
    token: string,
    listenerId: string,
    expectedStatus: string,
    timeout: number = 10000
  ): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const listener = await this.getListener(token, listenerId);
      if (listener.status === expectedStatus) {
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    throw new Error(`Listener did not reach status '${expectedStatus}' within ${timeout}ms`);
  }

  /**
   * Wait for condition with timeout
   */
  async waitForCondition(
    condition: () => Promise<boolean>,
    timeout: number = 10000,
    interval: number = 500
  ): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      if (await condition()) {
        return;
      }
      await new Promise(resolve => setTimeout(resolve, interval));
    }

    throw new Error(`Condition not met within ${timeout}ms`);
  }
}

/**
 * Factory function to create test data
 */
export function createTestDataHelper(request: APIRequestContext): TestDataHelper {
  return new TestDataHelper(request);
}
