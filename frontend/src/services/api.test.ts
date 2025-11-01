import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { apiService } from './api';
import { Event, Alert, Rule, CorrelationRule, Action, DashboardStats, ChartData } from '../types';

// Mock axios
vi.mock('axios');
const mockedAxios = vi.mocked(axios);

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
});

// Mock WebSocket service
vi.mock('./websocket', () => ({
  websocketService: {
    subscribe: vi.fn(),
    unsubscribe: vi.fn(),
    isConnected: vi.fn().mockReturnValue(true),
  },
}));

describe('ApiService', () => {
  let mockAxiosInstance: any;

  beforeEach(() => {
    vi.clearAllMocks();

    mockAxiosInstance = {
      get: vi.fn(),
      post: vi.fn(),
      put: vi.fn(),
      delete: vi.fn(),
      interceptors: {
        request: { use: vi.fn() },
        response: { use: vi.fn() },
      },
    };

    mockedAxios.create.mockReturnValue(mockAxiosInstance);
  });

  describe('authentication', () => {
    it('should login successfully', async () => {
      const mockResponse = { data: { token: 'test-token' } };
      mockAxiosInstance.post.mockResolvedValue(mockResponse);

      const result = await apiService.login('user', 'pass');

      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/api/auth/login', { username: 'user', password: 'pass' });
      expect(result).toEqual({ token: 'test-token' });
    });
  });

  describe('dashboard', () => {
    it('should get dashboard stats', async () => {
      const mockStats: DashboardStats = {
        total_events: 100,
        active_alerts: 5,
        rules_fired: 10,
        system_health: 'OK',
      };
      const mockResponse = { data: mockStats };
      mockAxiosInstance.get.mockResolvedValue(mockResponse);

      const result = await apiService.getDashboardStats();

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/dashboard');
      expect(result).toEqual(mockStats);
    });

    it('should get chart data', async () => {
      const mockChartData: ChartData[] = [
        { timestamp: '2024-01-01T00:00:00Z', events: 10, alerts: 2 },
      ];
      const mockResponse = { data: mockChartData };
      mockAxiosInstance.get.mockResolvedValue(mockResponse);

      const result = await apiService.getChartData();

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/dashboard/chart');
      expect(result).toEqual(mockChartData);
    });
  });

  describe('events', () => {
    it('should get events with default limit', async () => {
      const mockEvents: Event[] = [
        {
          event_id: '1',
          event_type: 'login',
          fields: {},
          raw_data: 'test',
          severity: 'low',
          source_format: 'json',
          source_ip: '127.0.0.1',
          timestamp: '2024-01-01T00:00:00Z',
        },
      ];
      const mockResponse = { data: mockEvents };
      mockAxiosInstance.get.mockResolvedValue(mockResponse);

      const result = await apiService.getEvents();

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/events?limit=100');
      expect(result).toEqual(mockEvents);
    });

    it('should get events with custom limit', async () => {
      const mockResponse = { data: [] };
      mockAxiosInstance.get.mockResolvedValue(mockResponse);

      await apiService.getEvents(50);

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/events?limit=50');
    });
  });

  describe('alerts', () => {
    it('should get alerts', async () => {
      const mockAlerts: Alert[] = [
        {
          alert_id: '1',
          event: {} as Event,
          event_id: '1',
          rule_id: 'rule1',
          severity: 'high',
          status: 'Pending' as any,
          timestamp: '2024-01-01T00:00:00Z',
        },
      ];
      const mockResponse = { data: mockAlerts };
      mockAxiosInstance.get.mockResolvedValue(mockResponse);

      const result = await apiService.getAlerts();

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/alerts');
      expect(result).toEqual(mockAlerts);
    });

    it('should acknowledge alert', async () => {
      const mockResponse = { data: 'Alert acknowledged' };
      mockAxiosInstance.post.mockResolvedValue(mockResponse);

      const result = await apiService.acknowledgeAlert('alert1');

      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/api/alerts/alert1/acknowledge');
      expect(result).toBe('Alert acknowledged');
    });

    it('should dismiss alert', async () => {
      const mockResponse = { data: 'Alert dismissed' };
      mockAxiosInstance.post.mockResolvedValue(mockResponse);

      const result = await apiService.dismissAlert('alert1');

      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/api/alerts/alert1/dismiss');
      expect(result).toBe('Alert dismissed');
    });
  });

  describe('rules', () => {
    it('should get rules', async () => {
      const mockRules: Rule[] = [
        {
          id: '1',
          name: 'Test Rule',
          description: 'Test description',
          severity: 'high',
          enabled: true,
          version: 1,
          conditions: [],
          actions: [],
        },
      ];
      const mockResponse = { data: mockRules };
      mockAxiosInstance.get.mockResolvedValue(mockResponse);

      const result = await apiService.getRules();

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/rules');
      expect(result).toEqual(mockRules);
    });

    it('should create rule', async () => {
      const newRule: Omit<Rule, 'id'> = {
        name: 'New Rule',
        description: 'New description',
        severity: 'medium',
        enabled: true,
        version: 1,
        conditions: [],
        actions: [],
      };
      const mockResponse = { data: { ...newRule, id: '1' } };
      mockAxiosInstance.post.mockResolvedValue(mockResponse);

      const result = await apiService.createRule(newRule);

      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/api/rules', newRule);
      expect(result).toEqual({ ...newRule, id: '1' });
    });

    it('should update rule', async () => {
      const updatedRule: Partial<Rule> = { enabled: false };
      const mockResponse = { data: { id: '1', ...updatedRule } };
      mockAxiosInstance.put.mockResolvedValue(mockResponse);

      const result = await apiService.updateRule('1', updatedRule);

      expect(mockAxiosInstance.put).toHaveBeenCalledWith('/api/rules/1', updatedRule);
      expect(result).toEqual({ id: '1', ...updatedRule });
    });

    it('should delete rule', async () => {
      const mockResponse = { data: 'Rule deleted' };
      mockAxiosInstance.delete.mockResolvedValue(mockResponse);

      const result = await apiService.deleteRule('1');

      expect(mockAxiosInstance.delete).toHaveBeenCalledWith('/api/rules/1');
      expect(result).toBe('Rule deleted');
    });
  });

  describe('correlation rules', () => {
    it('should get correlation rules', async () => {
      const mockRules: CorrelationRule[] = [
        {
          id: '1',
          name: 'Test Correlation Rule',
          description: 'Test description',
          severity: 'high',
          version: 1,
          window: 3000000000,
          sequence: ['event1', 'event2'],
          conditions: [],
          actions: [],
        },
      ];
      const mockResponse = { data: mockRules };
      mockAxiosInstance.get.mockResolvedValue(mockResponse);

      const result = await apiService.getCorrelationRules();

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/correlation-rules');
      expect(result).toEqual(mockRules);
    });

    it('should create correlation rule', async () => {
      const newRule: Omit<CorrelationRule, 'id'> = {
        name: 'New Correlation Rule',
        description: 'New description',
        severity: 'high',
        version: 1,
        window: 3000000000,
        sequence: ['event1', 'event2'],
        conditions: [],
        actions: [],
      };
      const mockResponse = { data: { ...newRule, id: '1' } };
      mockAxiosInstance.post.mockResolvedValue(mockResponse);

      const result = await apiService.createCorrelationRule(newRule);

      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/api/correlation-rules', newRule);
      expect(result).toEqual({ ...newRule, id: '1' });
    });
  });

  describe('actions', () => {
    it('should get actions', async () => {
      const mockActions: Action[] = [
        {
          id: '1',
          type: 'webhook',
          config: { url: 'https://example.com' },
        },
      ];
      const mockResponse = { data: mockActions };
      mockAxiosInstance.get.mockResolvedValue(mockResponse);

      const result = await apiService.getActions();

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/actions');
      expect(result).toEqual(mockActions);
    });

    it('should create action', async () => {
      const newAction: Omit<Action, 'id'> = {
        type: 'webhook',
        config: { url: 'https://example.com' },
      };
      const mockResponse = { data: { ...newAction, id: '1' } };
      mockAxiosInstance.post.mockResolvedValue(mockResponse);

      const result = await apiService.createAction(newAction);

      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/api/actions', newAction);
      expect(result).toEqual({ ...newAction, id: '1' });
    });
  });

  describe('WebSocket integration', () => {
    it('should subscribe to realtime updates', () => {
      const callbacks = { onEvent: vi.fn() };

      apiService.subscribeToRealtimeUpdates(callbacks);

      expect(require('./websocket').websocketService.subscribe).toHaveBeenCalledWith(callbacks);
    });

    it('should unsubscribe from realtime updates', () => {
      apiService.unsubscribeFromRealtimeUpdates();

      expect(require('./websocket').websocketService.unsubscribe).toHaveBeenCalled();
    });

    it('should check WebSocket connection status', () => {
      const result = apiService.isWebSocketConnected();

      expect(result).toBe(true);
      expect(require('./websocket').websocketService.isConnected).toHaveBeenCalled();
    });
  });
});