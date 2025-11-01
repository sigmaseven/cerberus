import axios from 'axios';
import type { Event, Alert, Rule, Action, CorrelationRule, ListenerConfig } from '../types';

const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
});

function createCrud<T extends { id?: string }>(endpoint: string) {
  return {
    get: async (signal?: AbortSignal): Promise<T[]> => {
      const response = await api.get(endpoint, { signal });
      if (!Array.isArray(response.data)) {
        throw new Error(`Invalid response: expected array for ${endpoint}`);
      }
      return response.data;
    },
    create: async (item: Omit<T, 'id'>, signal?: AbortSignal): Promise<T> => {
      const response = await api.post(endpoint, item, { signal });
      return response.data;
    },
    update: async (id: string, item: Partial<T>, signal?: AbortSignal): Promise<T> => {
      const response = await api.put(`${endpoint}/${id}`, item, { signal });
      return response.data;
    },
    delete: async (id: string, signal?: AbortSignal): Promise<void> => {
      await api.delete(`${endpoint}/${id}`, { signal });
    },
  };
}

const rulesCrud = createCrud<Rule>('/rules');
const actionsCrud = createCrud<Action>('/actions');
const correlationRulesCrud = createCrud<CorrelationRule>('/correlation-rules');

export const getEvents = async (limit?: number, signal?: AbortSignal): Promise<Event[]> => {
  const params = limit !== undefined ? { limit: limit.toString() } : undefined;
  const response = await api.get('/events', { params, signal });
  if (!response.data || !Array.isArray(response.data)) {
    throw new Error('Invalid events response');
  }
  return response.data;
};

export const getAlerts = async (signal?: AbortSignal): Promise<Alert[]> => {
  const response = await api.get('/alerts', { signal });
  if (!response.data || !Array.isArray(response.data)) {
    throw new Error('Invalid alerts response');
  }
  return response.data;
};

export const acknowledgeAlert = async (id: string, signal?: AbortSignal): Promise<void> => {
  await api.post(`/alerts/${id}/acknowledge`, {}, { signal });
};

export const dismissAlert = async (id: string, signal?: AbortSignal): Promise<void> => {
  await api.post(`/alerts/${id}/dismiss`, {}, { signal });
};

export const getMetrics = async (signal?: AbortSignal): Promise<string> => {
  const response = await api.get('/metrics', { signal });
  return response.data;
};

export const getRules = rulesCrud.get;
export const createRule = rulesCrud.create;
export const updateRule = rulesCrud.update;
export const deleteRule = rulesCrud.delete;

export const getActions = actionsCrud.get;
export const createAction = actionsCrud.create;
export const updateAction = actionsCrud.update;
export const deleteAction = actionsCrud.delete;

export const getCorrelationRules = correlationRulesCrud.get;
export const createCorrelationRule = correlationRulesCrud.create;
export const updateCorrelationRule = correlationRulesCrud.update;
export const deleteCorrelationRule = correlationRulesCrud.delete;



export const getDashboardStats = async (signal?: AbortSignal): Promise<{ total_events: number; total_alerts: number }> => {
  const response = await api.get('/dashboard', { signal });
  if (typeof response.data !== 'object' || response.data === null ||
      typeof response.data.total_events !== 'number' || typeof response.data.total_alerts !== 'number') {
    throw new Error('Invalid dashboard stats response');
  }
  return response.data;
};

export const getDashboardChart = async (signal?: AbortSignal): Promise<{ name: string; events: number; alerts: number }[]> => {
  const response = await api.get('/dashboard/chart', { signal });
  if (!Array.isArray(response.data) ||
      !response.data.every(item => typeof item.name === 'string' && typeof item.events === 'number' && typeof item.alerts === 'number')) {
    throw new Error('Invalid dashboard chart response');
  }
  return response.data;
};

export const getListeners = async (signal?: AbortSignal): Promise<ListenerConfig> => {
  const response = await api.get('/listeners', { signal });
  const data = response.data;
  if (typeof data !== 'object' || data === null) {
    throw new Error('Invalid listener config response');
  }
  const d = data as Record<string, unknown>;
  if (typeof d.syslog !== 'object' || d.syslog === null || typeof (d.syslog as Record<string, unknown>).port !== 'number' || typeof (d.syslog as Record<string, unknown>).host !== 'string' ||
      typeof d.cef !== 'object' || d.cef === null || typeof (d.cef as Record<string, unknown>).port !== 'number' || typeof (d.cef as Record<string, unknown>).host !== 'string' ||
      typeof d.json !== 'object' || d.json === null || typeof (d.json as Record<string, unknown>).port !== 'number' || typeof (d.json as Record<string, unknown>).host !== 'string' || typeof (d.json as Record<string, unknown>).tls !== 'boolean') {
    throw new Error('Invalid listener config structure');
  }
  return data as ListenerConfig;
};

export { api };