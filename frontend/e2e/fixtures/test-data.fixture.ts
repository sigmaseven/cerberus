/**
 * Test Data Fixtures
 *
 * Provides reusable test data for E2E tests.
 * Ensures consistency across test suites.
 */

import { Event, Rule, Alert, Action, CorrelationRule, SavedSearch } from '../../src/types';

export const testEvents = {
  sshFailedAuth: {
    event_type: 'auth_failure',
    source_ip: '192.168.1.100',
    severity: 'Medium',
    source_format: 'syslog',
    fields: {
      service: 'ssh',
      username: 'admin',
      port: 22,
      action: 'authentication_failure',
    },
    raw_data: 'Failed password for admin from 192.168.1.100 port 22 ssh2',
    timestamp: new Date().toISOString(),
  } as Partial<Event>,

  webSQLInjection: {
    event_type: 'web_attack',
    source_ip: '10.0.0.50',
    severity: 'Critical',
    source_format: 'json',
    fields: {
      url: '/api/users?id=1 OR 1=1',
      method: 'GET',
      status_code: 500,
      attack_type: 'sql_injection',
    },
    raw_data: 'GET /api/users?id=1 OR 1=1 HTTP/1.1 500',
    timestamp: new Date().toISOString(),
  } as Partial<Event>,

  malwareDetected: {
    event_type: 'malware_detected',
    source_ip: '172.16.0.25',
    severity: 'Critical',
    source_format: 'cef',
    fields: {
      file_path: '/tmp/malicious.exe',
      signature: 'Trojan.Generic.12345',
      action: 'quarantine',
    },
    raw_data: 'CEF:0|AV|Scanner|1.0|100|Malware Detected|10|...',
    timestamp: new Date().toISOString(),
  } as Partial<Event>,
};

export const testRules = {
  sshBruteForce: {
    name: 'SSH Brute Force Detection',
    description: 'Detects multiple failed SSH authentication attempts',
    severity: 'High',
    enabled: true,
    conditions: [
      {
        field: 'event_type',
        operator: 'equals',
        value: 'auth_failure',
        logic: 'AND',
      },
      {
        field: 'service',
        operator: 'equals',
        value: 'ssh',
        logic: 'AND',
      },
    ],
    actions: [],
    tags: ['brute_force', 'authentication'],
    mitre_techniques: ['T1110'],
    mitre_tactics: ['TA0006'],
  } as Partial<Rule>,

  sqlInjection: {
    name: 'SQL Injection Attack',
    description: 'Detects SQL injection patterns in web requests',
    severity: 'Critical',
    enabled: true,
    conditions: [
      {
        field: 'url',
        operator: 'contains',
        value: 'OR 1=1',
        logic: 'OR',
      },
      {
        field: 'url',
        operator: 'contains',
        value: 'UNION SELECT',
        logic: 'OR',
      },
    ],
    actions: [],
    tags: ['web_attack', 'injection'],
    mitre_techniques: ['T1190'],
  } as Partial<Rule>,

  malwareExecution: {
    name: 'Malware Execution',
    description: 'Detects execution of known malware signatures',
    severity: 'Critical',
    enabled: true,
    conditions: [
      {
        field: 'event_type',
        operator: 'equals',
        value: 'malware_detected',
        logic: 'AND',
      },
    ],
    actions: [],
    tags: ['malware', 'execution'],
    mitre_techniques: ['T1204'],
  } as Partial<Rule>,
};

export const testActions = {
  emailAlert: {
    type: 'email',
    config: {
      to: 'soc@cerberus.local',
      subject: 'Security Alert: {{rule_name}}',
      body: 'Alert triggered at {{timestamp}}',
    },
  } as Partial<Action>,

  slackNotification: {
    type: 'slack',
    config: {
      webhook_url: 'https://hooks.slack.com/services/TEST/WEBHOOK',
      channel: '#security-alerts',
      username: 'Cerberus SIEM',
    },
  } as Partial<Action>,

  blockIP: {
    type: 'firewall_block',
    config: {
      duration: 3600,
      interface: 'eth0',
    },
  } as Partial<Action>,
};

export const testCorrelationRules = {
  lateralMovement: {
    name: 'Lateral Movement Detection',
    description: 'Detects user authenticating to multiple hosts',
    severity: 'Critical',
    window: 600000000000, // 10 minutes in nanoseconds
    sequence: ['auth_success', 'auth_success', 'auth_success'],
    conditions: [
      {
        field: 'username',
        operator: 'same',
        value: '',
        logic: 'AND',
      },
      {
        field: 'dest_hostname',
        operator: 'distinct',
        value: '3',
        logic: 'AND',
      },
    ],
    actions: [],
  } as Partial<CorrelationRule>,

  attackChain: {
    name: 'Multi-Stage Attack Chain',
    description: 'Detects sequential attack stages',
    severity: 'Critical',
    window: 1800000000000, // 30 minutes in nanoseconds
    sequence: ['reconnaissance', 'exploitation', 'privilege_escalation'],
    conditions: [
      {
        field: 'source_ip',
        operator: 'same',
        value: '',
        logic: 'AND',
      },
    ],
    actions: [],
  } as Partial<CorrelationRule>,
};

export const testSavedSearches = {
  failedLogins: {
    name: 'Failed Login Attempts',
    description: 'Search for all failed authentication attempts',
    query: 'event_type="auth_failure"',
    is_public: true,
    tags: ['authentication', 'security'],
    created_by: 'admin@cerberus.local',
  } as Partial<SavedSearch>,

  criticalAlerts: {
    name: 'Critical Severity Alerts',
    description: 'All critical severity security events',
    query: 'severity="Critical"',
    is_public: true,
    tags: ['alerts', 'critical'],
    created_by: 'admin@cerberus.local',
  } as Partial<SavedSearch>,
};

/**
 * Generates test data with random values
 */
export function generateTestEvent(overrides?: Partial<Event>): Partial<Event> {
  return {
    event_type: 'test_event',
    source_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
    severity: ['Low', 'Medium', 'High', 'Critical'][Math.floor(Math.random() * 4)],
    source_format: 'json',
    fields: {
      test_id: Math.random().toString(36).substring(7),
    },
    raw_data: 'Test event data',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

export function generateTestRule(overrides?: Partial<Rule>): Partial<Rule> {
  const id = Math.random().toString(36).substring(7);
  return {
    name: `Test Rule ${id}`,
    description: `Automated test rule ${id}`,
    severity: 'Medium',
    enabled: true,
    conditions: [
      {
        field: 'event_type',
        operator: 'equals',
        value: 'test',
        logic: 'AND',
      },
    ],
    actions: [],
    ...overrides,
  };
}
