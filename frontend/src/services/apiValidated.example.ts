/**
 * Example: How to integrate API validators into the API service
 *
 * This file shows how to add runtime validation to API calls.
 * To use this, you can either:
 * 1. Replace the current api.ts with this validated version
 * 2. Gradually add validation to specific endpoints
 * 3. Use it in development mode only
 */

import { apiService } from './api';
import {
  validateDashboardStats,
  validateChartData,
  validateEvents,
  validateAlerts,
  validateRules,
  safeValidate,
} from './apiValidator';
import type { DashboardStats, ChartData, Event, Alert, Rule } from '../types';

/**
 * Validated API service wrapper
 * Add validation only in development mode to catch issues early
 */
const isDevelopment = import.meta.env.MODE === 'development';

export const validatedApiService = {
  /**
   * Get dashboard stats with validation
   */
  async getDashboardStats(): Promise<DashboardStats> {
    const data = await apiService.getDashboardStats();

    if (isDevelopment) {
      // In development, validate and throw on error
      return validateDashboardStats(data);
    }

    // In production, validate with fallback
    return safeValidate(
      validateDashboardStats,
      data,
      {
        total_events: 0,
        active_alerts: 0,
        rules_fired: 0,
        system_health: 'Unknown',
      }
    );
  },

  /**
   * Get chart data with validation
   */
  async getChartData(): Promise<ChartData[]> {
    const data = await apiService.getChartData();

    if (isDevelopment) {
      return validateChartData(data);
    }

    return safeValidate(validateChartData, data, []);
  },

  /**
   * Get events with validation
   */
  async getEvents(limit: number = 100): Promise<PaginationResponse<Event>> {
    const data = await apiService.getEvents(limit);

    if (isDevelopment) {
      return validateEvents(data);
    }

    return safeValidate(validateEvents, data, []);
  },

  /**
   * Get alerts with validation
   */
  async getAlerts(): Promise<Alert[]> {
    const data = await apiService.getAlerts();

    if (isDevelopment) {
      return validateAlerts(data);
    }

    return safeValidate(validateAlerts, data, []);
  },

  /**
   * Get rules with validation
   */
  async getRules(): Promise<Rule[]> {
    const data = await apiService.getRules();

    if (isDevelopment) {
      return validateRules(data);
    }

    return safeValidate(validateRules, data, []);
  },

  // Pass through other methods without validation
  acknowledgeAlert: apiService.acknowledgeAlert.bind(apiService),
  dismissAlert: apiService.dismissAlert.bind(apiService),
  createRule: apiService.createRule.bind(apiService),
  updateRule: apiService.updateRule.bind(apiService),
  deleteRule: apiService.deleteRule.bind(apiService),
  getRule: apiService.getRule.bind(apiService),
  getCorrelationRules: apiService.getCorrelationRules.bind(apiService),
  createCorrelationRule: apiService.createCorrelationRule.bind(apiService),
  updateCorrelationRule: apiService.updateCorrelationRule.bind(apiService),
  deleteCorrelationRule: apiService.deleteCorrelationRule.bind(apiService),
  getCorrelationRule: apiService.getCorrelationRule.bind(apiService),
  getActions: apiService.getActions.bind(apiService),
  createAction: apiService.createAction.bind(apiService),
  updateAction: apiService.updateAction.bind(apiService),
  deleteAction: apiService.deleteAction.bind(apiService),
  getAction: apiService.getAction.bind(apiService),
  getListeners: apiService.getListeners.bind(apiService),
  exportRules: apiService.exportRules.bind(apiService),
  exportCorrelationRules: apiService.exportCorrelationRules.bind(apiService),
  importRules: apiService.importRules.bind(apiService),
  importCorrelationRules: apiService.importCorrelationRules.bind(apiService),
  login: apiService.login.bind(apiService),
  getHealth: apiService.getHealth.bind(apiService),
  subscribeToRealtimeUpdates: apiService.subscribeToRealtimeUpdates.bind(apiService),
  unsubscribeFromRealtimeUpdates: apiService.unsubscribeFromRealtimeUpdates.bind(apiService),
  isWebSocketConnected: apiService.isWebSocketConnected.bind(apiService),
};

/**
 * Usage instructions:
 *
 * To enable validation in your components, replace:
 *   import { apiService } from '../../services/api';
 * with:
 *   import { validatedApiService as apiService } from '../../services/apiValidated';
 *
 * Or globally in vite.config.ts, add an alias:
 *   resolve: {
 *     alias: {
 *       '~/services/api': '/src/services/apiValidated',
 *     },
 *   }
 *
 * Benefits:
 * - Catches API contract issues immediately in development
 * - Provides detailed error messages for debugging
 * - Safe fallbacks in production to prevent crashes
 * - No performance impact in production when disabled
 */
