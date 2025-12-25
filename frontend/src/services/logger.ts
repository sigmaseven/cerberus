/**
 * Environment-aware logger for API monitoring
 * Prevents console pollution in production and provides hook for telemetry
 */

const isDevelopment = import.meta.env.MODE === 'development';

export const apiMonitoringLogger = {
  /**
   * Log warning messages (only in development)
   * @param message - Warning message
   * @param data - Optional data to log (sanitized in production)
   */
  warn: (message: string, data?: unknown) => {
    if (isDevelopment) {
      console.warn(message, data);
    }
    // TODO: Optionally send to error tracking service (Sentry, LogRocket, etc.)
  },

  /**
   * Log error messages (only in development)
   * @param message - Error message
   * @param error - Error object or unknown error
   */
  error: (message: string, error: unknown) => {
    if (isDevelopment) {
      console.error(message, error);
    }
    // TODO: Send to error tracking in production (Sentry, Datadog, etc.)
  },
};

// Constants for monitoring-related fallback values
export const MONITORING_CONSTANTS = {
  UNKNOWN_ENDPOINT: 'unknown',
  UNKNOWN_METHOD: 'UNKNOWN',
} as const;
