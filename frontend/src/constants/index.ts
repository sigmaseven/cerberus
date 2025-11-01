/**
 * Available severity levels for events and alerts
 */
export const SEVERITY_OPTIONS = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
];

/**
 * Available operators for rule conditions
 */
export const OPERATOR_OPTIONS = [
  { value: 'equals', label: 'Equals' },
  { value: 'contains', label: 'Contains' },
  { value: 'greater_than', label: 'Greater Than' },
  { value: 'less_than', label: 'Less Than' },
];

/**
 * Available action types for rules
 */
export const ACTION_TYPES = [
  { value: 'webhook', label: 'Webhook' },
  { value: 'jira', label: 'Jira' },
  { value: 'email', label: 'Email' },
  { value: 'slack', label: 'Slack' },
];

/**
 * Dashboard refresh interval in milliseconds
 */
export const REFRESH_INTERVAL_MS = 30000;

/**
 * Nanoseconds per second
 */
export const NANOSECONDS_PER_SECOND = 1e9;

/**
 * Default version for new rules
 */
export const DEFAULT_RULE_VERSION = '1.0';