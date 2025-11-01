import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { Event, Alert, Rule, CorrelationRule, Action, DashboardStats, ChartData, ListenerStatus } from '../types';
import websocketService, { WebSocketCallbacks } from './websocket';

class ApiService {
  private api: AxiosInstance;

  constructor() {
    this.api = axios.create({
      baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8081',
      timeout: 10000,
    });

    // Request interceptor for authentication
    this.api.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('api_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling
    this.api.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          // Handle unauthorized access
          localStorage.removeItem('api_token');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  // Authentication
  async login(username: string, password: string): Promise<{ token: string }> {
    const response = await this.api.post('/api/auth/login', { username, password });
    return response.data;
  }

  // Dashboard
  async getDashboardStats(): Promise<DashboardStats> {
    const response = await this.api.get('/api/dashboard');
    return response.data;
  }

  async getChartData(): Promise<ChartData[]> {
    const response = await this.api.get('/api/dashboard/chart');
    return response.data;
  }

  // Events
  async getEvents(limit: number = 100): Promise<Event[]> {
    const response = await this.api.get(`/api/events?limit=${limit}`);
    return response.data;
  }

  // Alerts
  async getAlerts(): Promise<Alert[]> {
    const response = await this.api.get('/api/alerts');
    return response.data;
  }

  async acknowledgeAlert(alertId: string): Promise<string> {
    const response = await this.api.post(`/api/alerts/${alertId}/acknowledge`);
    return response.data;
  }

  async dismissAlert(alertId: string): Promise<string> {
    const response = await this.api.post(`/api/alerts/${alertId}/dismiss`);
    return response.data;
  }

  // Rules
  async getRules(): Promise<Rule[]> {
    const response = await this.api.get('/api/rules');
    return response.data;
  }

  async createRule(rule: Omit<Rule, 'id'>): Promise<Rule> {
    const response = await this.api.post('/api/rules', rule);
    return response.data;
  }

  async getRule(id: string): Promise<Rule> {
    const response = await this.api.get(`/api/v1/rules/${id}`);
    return response.data;
  }

  async updateRule(id: string, rule: Partial<Rule>): Promise<Rule> {
    const response = await this.api.put(`/api/rules/${id}`, rule);
    return response.data;
  }

  async deleteRule(id: string): Promise<string> {
    const response = await this.api.delete(`/api/rules/${id}`);
    return response.data;
  }

  // Correlation Rules
  async getCorrelationRules(): Promise<CorrelationRule[]> {
    const response = await this.api.get('/api/correlation-rules');
    return response.data;
  }

  async createCorrelationRule(rule: Omit<CorrelationRule, 'id'>): Promise<CorrelationRule> {
    const response = await this.api.post('/api/correlation-rules', rule);
    return response.data;
  }

  async getCorrelationRule(id: string): Promise<CorrelationRule> {
    const response = await this.api.get(`/api/correlation-rules/${id}`);
    return response.data;
  }

  async updateCorrelationRule(id: string, rule: Partial<CorrelationRule>): Promise<CorrelationRule> {
    const response = await this.api.put(`/api/correlation-rules/${id}`, rule);
    return response.data;
  }

  async deleteCorrelationRule(id: string): Promise<string> {
    const response = await this.api.delete(`/api/correlation-rules/${id}`);
    return response.data;
  }

  // Actions
  async getActions(): Promise<Action[]> {
    const response = await this.api.get('/api/actions');
    return response.data;
  }

  async createAction(action: Omit<Action, 'id'>): Promise<Action> {
    const response = await this.api.post('/api/actions', action);
    return response.data;
  }

  async getAction(id: string): Promise<Action> {
    const response = await this.api.get(`/api/actions/${id}`);
    return response.data;
  }

  async updateAction(id: string, action: Partial<Action>): Promise<Action> {
    const response = await this.api.put(`/api/actions/${id}`, action);
    return response.data;
  }

  async deleteAction(id: string): Promise<string> {
    const response = await this.api.delete(`/api/actions/${id}`);
    return response.data;
  }

  // Listeners
  async getListeners(): Promise<ListenerStatus> {
    const response = await this.api.get('/api/listeners');
    return response.data;
  }

  // Health check
  async getHealth(): Promise<{ status: string }> {
    const response = await this.api.get('/health');
    return response.data;
  }

  // WebSocket subscriptions
  subscribeToRealtimeUpdates(callbacks: WebSocketCallbacks): void {
    websocketService.subscribe(callbacks);
  }

  unsubscribeFromRealtimeUpdates(): void {
    websocketService.unsubscribe();
  }

  isWebSocketConnected(): boolean {
    return websocketService.isConnected();
  }
}

export const apiService = new ApiService();
export default apiService;