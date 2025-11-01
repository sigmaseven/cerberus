import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  getEvents,
  getAlerts,
  acknowledgeAlert,
  dismissAlert,
  getMetrics,
  getRules,
  createRule,
  updateRule,
  deleteRule,
  getDashboardStats,
  getDashboardChart,
  getListeners,
  api,
} from './api';

describe('API Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getEvents', () => {
    it('should fetch events successfully', async () => {
      const mockEvents = [{ id: '1', type: 'login' }];
      const spy = vi.spyOn(api, 'get').mockResolvedValue({ data: mockEvents });

      const result = await getEvents();

      expect(spy).toHaveBeenCalledWith('/events', { params: undefined, signal: undefined });
      expect(result).toEqual(mockEvents);
    });

    it('should fetch events with limit', async () => {
      const mockEvents = [{ id: '1', type: 'login' }];
      const spy = vi.spyOn(api, 'get').mockResolvedValue({ data: mockEvents });

      const result = await getEvents(10);

      expect(spy).toHaveBeenCalledWith('/events', { params: { limit: '10' }, signal: undefined });
      expect(result).toEqual(mockEvents);
    });

    it('should throw error for invalid response', async () => {
      vi.spyOn(api, 'get').mockResolvedValue({ data: 'invalid' });

      await expect(getEvents()).rejects.toThrow('Invalid events response');
    });
  });

  describe('getAlerts', () => {
    it('should fetch alerts successfully', async () => {
      const mockAlerts = [{ id: '1', severity: 'high' }];
      const spy = vi.spyOn(api, 'get').mockResolvedValue({ data: mockAlerts });

      const result = await getAlerts();

      expect(spy).toHaveBeenCalledWith('/alerts', { signal: undefined });
      expect(result).toEqual(mockAlerts);
    });

    it('should throw error for invalid response', async () => {
      vi.spyOn(api, 'get').mockResolvedValue({ data: 'invalid' });

      await expect(getAlerts()).rejects.toThrow('Invalid alerts response');
    });
  });

  describe('acknowledgeAlert', () => {
    it('should acknowledge alert', async () => {
      const spy = vi.spyOn(api, 'post').mockResolvedValue({});

      await acknowledgeAlert('123');

      expect(spy).toHaveBeenCalledWith('/alerts/123/acknowledge', {}, { signal: undefined });
    });
  });

  describe('dismissAlert', () => {
    it('should dismiss alert', async () => {
      const spy = vi.spyOn(api, 'post').mockResolvedValue({});

      await dismissAlert('123');

      expect(spy).toHaveBeenCalledWith('/alerts/123/dismiss', {}, { signal: undefined });
    });
  });

  describe('getMetrics', () => {
    it('should fetch metrics', async () => {
      const mockMetrics = 'metrics data';
      const spy = vi.spyOn(api, 'get').mockResolvedValue({ data: mockMetrics });

      const result = await getMetrics();

      expect(spy).toHaveBeenCalledWith('/metrics', { signal: undefined });
      expect(result).toEqual(mockMetrics);
    });
  });

  describe('CRUD operations', () => {
    describe('Rules', () => {
      it('should get rules', async () => {
        const mockRules = [{ id: '1', name: 'Rule 1' }];
        const spy = vi.spyOn(api, 'get').mockResolvedValue({ data: mockRules });

        const result = await getRules();

        expect(spy).toHaveBeenCalledWith('/rules', { signal: undefined });
        expect(result).toEqual(mockRules);
      });

      it('should throw error for invalid rules response', async () => {
        vi.spyOn(api, 'get').mockResolvedValue({ data: 'invalid' });

        await expect(getRules()).rejects.toThrow('Invalid response: expected array for /rules');
      });

      it('should create rule', async () => {
        const newRule = { name: 'New Rule', description: 'Test rule', severity: 'high', version: '1.0', conditions: [], actions: [] };
        const createdRule = { id: '2', ...newRule };
        const spy = vi.spyOn(api, 'post').mockResolvedValue({ data: createdRule });

        const result = await createRule(newRule);

        expect(spy).toHaveBeenCalledWith('/rules', newRule, { signal: undefined });
        expect(result).toEqual(createdRule);
      });

      it('should update rule', async () => {
        const updates = { name: 'Updated Rule' };
        const updatedRule = { id: '1', ...updates };
        const spy = vi.spyOn(api, 'put').mockResolvedValue({ data: updatedRule });

        const result = await updateRule('1', updates);

        expect(spy).toHaveBeenCalledWith('/rules/1', updates, { signal: undefined });
        expect(result).toEqual(updatedRule);
      });

      it('should delete rule', async () => {
        const spy = vi.spyOn(api, 'delete').mockResolvedValue({});

        await deleteRule('1');

        expect(spy).toHaveBeenCalledWith('/rules/1', { signal: undefined });
      });
    });

    // Similar tests for Actions and CorrelationRules can be added, but for brevity, focusing on Rules
  });

  describe('getDashboardStats', () => {
    it('should fetch dashboard stats', async () => {
      const mockStats = { total_events: 100, total_alerts: 10 };
      const spy = vi.spyOn(api, 'get').mockResolvedValue({ data: mockStats });

      const result = await getDashboardStats();

      expect(spy).toHaveBeenCalledWith('/dashboard', { signal: undefined });
      expect(result).toEqual(mockStats);
    });

      it('should throw error for invalid response', async () => {
        vi.spyOn(api, 'get').mockResolvedValue({ data: { total_events: 'invalid' } });

        await expect(getDashboardStats()).rejects.toThrow('Invalid dashboard stats response');
      });
  });

  describe('getDashboardChart', () => {
    it('should fetch dashboard chart', async () => {
      const mockChart = [{ name: 'Jan', events: 50, alerts: 5 }];
      const spy = vi.spyOn(api, 'get').mockResolvedValue({ data: mockChart });

      const result = await getDashboardChart();

      expect(spy).toHaveBeenCalledWith('/dashboard/chart', { signal: undefined });
      expect(result).toEqual(mockChart);
    });

      it('should throw error for invalid response', async () => {
        vi.spyOn(api, 'get').mockResolvedValue({ data: [{ name: 123 }] });

        await expect(getDashboardChart()).rejects.toThrow('Invalid dashboard chart response');
      });
  });

  describe('getListeners', () => {
    it('should fetch listeners config', async () => {
      const mockConfig = {
        syslog: { port: 514, host: '0.0.0.0' },
        cef: { port: 515, host: '0.0.0.0' },
        json: { port: 516, host: '0.0.0.0', tls: false }
      };
      const spy = vi.spyOn(api, 'get').mockResolvedValue({ data: mockConfig });

      const result = await getListeners();

      expect(spy).toHaveBeenCalledWith('/listeners', { signal: undefined });
      expect(result).toEqual(mockConfig);
    });

      it('should throw error for invalid response', async () => {
        vi.spyOn(api, 'get').mockResolvedValue({ data: 'invalid' });

        await expect(getListeners()).rejects.toThrow('Invalid listener config response');
      });

      it('should throw error for invalid structure', async () => {
        vi.spyOn(api, 'get').mockResolvedValue({ data: { syslog: { port: 'invalid' } } });

        await expect(getListeners()).rejects.toThrow('Invalid listener config structure');
      });
  });
});