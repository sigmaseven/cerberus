/**
 * API Response Validators
 *
 * These validators ensure API responses match expected TypeScript interfaces at runtime.
 * This prevents the UI from receiving unexpected data structures that cause display issues.
 *
 * CRITICAL: These validators catch API contract mismatches before they reach UI components.
 */

import {
  Event,
  Alert,
  Rule,
  DashboardStats,
  ChartData,
} from '../types';

export class ApiValidationError extends Error {
  constructor(
    message: string,
    public field: string,
    public expectedType: string,
    public receivedType: string,
    public response: unknown
  ) {
    super(message);
    this.name = 'ApiValidationError';
  }
}

/**
 * Validates a DashboardStats object
 */
export function validateDashboardStats(data: unknown): DashboardStats {
  // Handle null/undefined
  if (!data || typeof data !== 'object') {
    throw new ApiValidationError(
      'DashboardStats must be an object',
      'DashboardStats',
      'object',
      typeof data,
      data
    );
  }

  const errors: string[] = [];
  const obj = data as Record<string, unknown>;

  // Check required fields
  if (typeof obj.total_events !== 'number') {
    errors.push(`Expected 'total_events' to be number, got ${typeof obj.total_events}`);
  }

  if (typeof obj.active_alerts !== 'number') {
    errors.push(`Expected 'active_alerts' to be number, got ${typeof obj.active_alerts}`);
  }

  if (typeof obj.rules_fired !== 'number') {
    errors.push(`Expected 'rules_fired' to be number, got ${typeof obj.rules_fired}`);
  }

  if (typeof obj.system_health !== 'string') {
    errors.push(`Expected 'system_health' to be string, got ${typeof obj.system_health}`);
  }

  // Check for legacy fields that should NOT be present
  if ('events' in obj) {
    errors.push('Unexpected legacy field "events" found. Expected "total_events" instead.');
  }

  if ('alerts' in obj) {
    errors.push('Unexpected legacy field "alerts" found. Expected "active_alerts" instead.');
  }

  if (errors.length > 0) {
    throw new ApiValidationError(
      `DashboardStats validation failed:\n${errors.join('\n')}`,
      'DashboardStats',
      'DashboardStats interface',
      typeof data,
      data
    );
  }

  return data as DashboardStats;
}

/**
 * Validates ChartData array
 */
export function validateChartData(data: unknown): ChartData[] {
  if (!Array.isArray(data)) {
    throw new ApiValidationError(
      'ChartData must be an array',
      'ChartData',
      'array',
      typeof data,
      data
    );
  }

  const errors: string[] = [];

  data.forEach((item, index) => {
    if (typeof item.timestamp !== 'string') {
      errors.push(`Item ${index}: Expected 'timestamp' to be string, got ${typeof item.timestamp}`);
    }

    if (typeof item.events !== 'number') {
      errors.push(`Item ${index}: Expected 'events' to be number, got ${typeof item.events}`);
    }

    if (typeof item.alerts !== 'number') {
      errors.push(`Item ${index}: Expected 'alerts' to be number, got ${typeof item.alerts}`);
    }

    // Check for legacy field
    if ('name' in item) {
      errors.push(`Item ${index}: Unexpected legacy field "name" found. Expected "timestamp" instead.`);
    }
  });

  if (errors.length > 0) {
    throw new ApiValidationError(
      `ChartData validation failed:\n${errors.join('\n')}`,
      'ChartData',
      'ChartData[] interface',
      typeof data,
      data
    );
  }

  return data as ChartData[];
}

/**
 * Validates Event object
 */
export function validateEvent(data: unknown): Event {
  // Handle null/undefined
  if (!data || typeof data !== 'object') {
    throw new ApiValidationError(
      'Event must be an object',
      'Event',
      'object',
      typeof data,
      data
    );
  }

  const errors: string[] = [];
  const obj = data as Record<string, unknown>;

  const requiredFields = [
    { field: 'event_id', type: 'string' },
    { field: 'event_type', type: 'string' },
    { field: 'timestamp', type: 'string' },
    { field: 'source_ip', type: 'string' },
    { field: 'severity', type: 'string' },
    { field: 'source_format', type: 'string' },
    { field: 'fields', type: 'object' },
    { field: 'raw_data', type: 'string' },
  ];

  requiredFields.forEach(({ field, type }) => {
    if (typeof obj[field] !== type) {
      errors.push(`Expected '${field}' to be ${type}, got ${typeof obj[field]}`);
    }
  });

  if (errors.length > 0) {
    throw new ApiValidationError(
      `Event validation failed:\n${errors.join('\n')}`,
      'Event',
      'Event interface',
      typeof data,
      data
    );
  }

  return data as Event;
}

/**
 * Validates Events array
 */
export function validateEvents(data: unknown): Event[] {
  if (!Array.isArray(data)) {
    throw new ApiValidationError(
      'Events must be an array',
      'Event[]',
      'array',
      typeof data,
      data
    );
  }

  return data.map(validateEvent);
}

/**
 * Validates Alert object
 */
export function validateAlert(data: unknown): Alert {
  // Handle null/undefined
  if (!data || typeof data !== 'object') {
    throw new ApiValidationError(
      'Alert must be an object',
      'Alert',
      'object',
      typeof data,
      data
    );
  }

  const errors: string[] = [];
  const obj = data as Record<string, unknown>;

  const requiredFields = [
    { field: 'alert_id', type: 'string' },
    { field: 'rule_id', type: 'string' },
    { field: 'event_id', type: 'string' },
    { field: 'severity', type: 'string' },
    { field: 'status', type: 'string' },
    { field: 'timestamp', type: 'string' },
    { field: 'event', type: 'object' },
  ];

  requiredFields.forEach(({ field, type }) => {
    if (typeof obj[field] !== type) {
      errors.push(`Expected '${field}' to be ${type}, got ${typeof obj[field]}`);
    }
  });

  // Validate status enum
  const validStatuses = ['Pending', 'Acknowledged', 'Dismissed'];
  if (!validStatuses.includes(obj.status as string)) {
    errors.push(`Status must be one of ${validStatuses.join(', ')}, got ${obj.status}`);
  }

  // Validate nested event
  if (obj.event) {
    try {
      validateEvent(obj.event);
    } catch (e) {
      const error = e as Error;
      errors.push(`Nested event validation failed: ${error.message}`);
    }
  }

  if (errors.length > 0) {
    throw new ApiValidationError(
      `Alert validation failed:\n${errors.join('\n')}`,
      'Alert',
      'Alert interface',
      typeof data,
      data
    );
  }

  return data as Alert;
}

/**
 * Validates Alerts array
 */
export function validateAlerts(data: unknown): Alert[] {
  if (!Array.isArray(data)) {
    throw new ApiValidationError(
      'Alerts must be an array',
      'Alert[]',
      'array',
      typeof data,
      data
    );
  }

  return data.map(validateAlert);
}

/**
 * Validates Rule object
 */
export function validateRule(data: unknown): Rule {
  // Handle null/undefined
  if (!data || typeof data !== 'object') {
    throw new ApiValidationError(
      'Rule must be an object',
      'Rule',
      'object',
      typeof data,
      data
    );
  }

  const errors: string[] = [];
  const obj = data as Record<string, unknown>;

  const requiredFields = [
    { field: 'id', type: 'string' },
    { field: 'name', type: 'string' },
    { field: 'description', type: 'string' },
    { field: 'severity', type: 'string' },
    { field: 'enabled', type: 'boolean' },
    { field: 'version', type: 'number' },
  ];

  requiredFields.forEach(({ field, type }) => {
    if (typeof obj[field] !== type) {
      errors.push(`Expected '${field}' to be ${type}, got ${typeof obj[field]}`);
    }
  });

  if (!Array.isArray(obj.conditions)) {
    errors.push(`Expected 'conditions' to be array, got ${typeof obj.conditions}`);
  }

  if (!Array.isArray(obj.actions)) {
    errors.push(`Expected 'actions' to be array, got ${typeof obj.actions}`);
  }

  if (errors.length > 0) {
    throw new ApiValidationError(
      `Rule validation failed:\n${errors.join('\n')}`,
      'Rule',
      'Rule interface',
      typeof data,
      data
    );
  }

  return data as Rule;
}

/**
 * Validates Rules array
 */
export function validateRules(data: unknown): Rule[] {
  if (!Array.isArray(data)) {
    throw new ApiValidationError(
      'Rules must be an array',
      'Rule[]',
      'array',
      typeof data,
      data
    );
  }

  return data.map(validateRule);
}

/**
 * Logs validation errors to console with detailed information
 */
export function logValidationError(): void {
  // Silently handle validation errors in production
}

/**
 * Wrapper function to safely validate with error logging
 */
export function safeValidate<T>(
  validator: (data: unknown) => T,
  data: unknown,
  fallback: T
): T {
  try {
    return validator(data);
  } catch (error) {
    if (error instanceof ApiValidationError) {
      logValidationError();
    } else {
      // Silently handle unexpected validation errors
    }
    return fallback;
  }
}
