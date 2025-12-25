/**
 * Get the appropriate Material-UI color for a given severity level
 * @param severity - The severity level (case-insensitive)
 * @returns Material-UI color variant
 */
export const getSeverityColor = (
  severity: string
): 'error' | 'warning' | 'info' | 'default' | 'success' => {
  const normalizedSeverity = severity?.toLowerCase() || '';

  switch (normalizedSeverity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'info';
    default:
      return 'default';
  }
};

/**
 * Get the appropriate Material-UI color for a given alert status
 * @param status - The alert status (case-insensitive)
 * @returns Material-UI color variant
 *
 * Color scheme:
 * - Pending: warning (orange) - needs attention
 * - Acknowledged: info (blue) - being looked at
 * - Investigating: info (blue) - active work in progress
 * - Resolved: success (green) - issue addressed
 * - Escalated: error (red) - urgent, needs immediate attention
 * - Closed: default (gray) - archived/complete
 * - Dismissed: default (gray) - discarded
 * - FalsePositive: default (gray) - not a real threat
 */
export const getStatusColor = (
  status: string
): 'error' | 'warning' | 'info' | 'default' | 'success' => {
  const normalizedStatus = status?.toLowerCase() || '';

  switch (normalizedStatus) {
    case 'escalated':
      return 'error';
    case 'pending':
      return 'warning';
    case 'acknowledged':
    case 'investigating':
      return 'info';
    case 'resolved':
      return 'success';
    case 'closed':
    case 'dismissed':
    case 'falsepositive':
    case 'false_positive':
      return 'default';
    default:
      return 'default';
  }
};

/**
 * WebSocket configuration constants
 */
export const WEBSOCKET_CONFIG = {
  INITIAL_RECONNECT_DELAY: 1000,
  MAX_RECONNECT_DELAY: 30000,
  RETRY_DELAY: 100,
  MAX_RECONNECT_ATTEMPTS: 5,
} as const;

/**
 * Query Client configuration constants
 */
export const QUERY_CONFIG = {
  RETRY_DELAY_BASE: 1000,
  RETRY_DELAY_MAX: 30000,
  STALE_TIME_DEFAULT: 5 * 60 * 1000, // 5 minutes
  STALE_TIME_ALERTS: 1 * 60 * 1000, // 1 minute
  STALE_TIME_EVENTS: 2 * 60 * 1000, // 2 minutes
  STALE_TIME_DASHBOARD: 30 * 1000, // 30 seconds
  STALE_TIME_CONFIG: 10 * 60 * 1000, // 10 minutes
  GC_TIME: 10 * 60 * 1000, // 10 minutes
  MAX_RETRIES: 3,
} as const;

/**
 * Polling interval constants for real-time data refresh
 */
export const POLLING_INTERVALS = {
  DASHBOARD: 5000, // 5 seconds
  RULES: 10000, // 10 seconds
  ALERTS: 10000, // 10 seconds
  CORRELATION_RULES: 10000, // 10 seconds
  LISTENERS: 5000, // 5 seconds
  MITRE_COVERAGE: 60000, // 1 minute
  FIELD_MAPPINGS: 30000, // 30 seconds
  ML_MODELS: 5000, // 5 seconds
  ML_ALERTS: 10000, // 10 seconds
  ERROR_REPORTING_FLUSH: 30000, // 30 seconds
} as const;

/**
 * Time conversion constants
 */
export const TIME_CONSTANTS = {
  MILLISECONDS_PER_SECOND: 1000,
  MILLISECONDS_PER_MINUTE: 60 * 1000,
  MILLISECONDS_PER_HOUR: 60 * 60 * 1000,
  SECONDS_PER_MINUTE: 60,
  SECONDS_PER_HOUR: 3600,
  SECONDS_PER_DAY: 86400,
  MINUTES_PER_HOUR: 60,
} as const;

/**
 * API and data limits
 */
export const LIMITS = {
  API_TIMEOUT: 10000, // 10 seconds
  SEARCH_QUERY_MAX_LENGTH: 10000, // Maximum search query length
  EXPORT_DEFAULT_LIMIT: 10000, // Default export limit
  MAX_PRIORITY: 1000, // Maximum priority value for rules
  CSRF_REFRESH_MIN_INTERVAL: 1000, // Minimum interval between CSRF refreshes
  TOKEN_EXPIRY_BUFFER: 5 * 60 * 1000, // 5 minutes buffer before token expiration
  TOKEN_DEFAULT_LIFETIME: 60 * 60 * 1000, // 1 hour default token lifetime
  RELATED_EVENTS_TIME_WINDOW: 30 * 60 * 1000, // 30 minutes window for related events
} as const;
