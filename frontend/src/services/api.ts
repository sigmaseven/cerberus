import axios, { AxiosInstance } from 'axios';
import { Event, Alert, Rule, CorrelationRule, Action, DashboardStats, ChartData, ListenerStatus, PaginationResponse, SearchRequest, SearchResponse, SavedSearch, SearchField, SearchOperator, QueryValidationResult, ExportRequest } from '../types';
import websocketService, { WebSocketCallbacks } from './websocket';
import errorReportingService from './errorReporting';

class ApiService {
  private api: AxiosInstance;

  constructor() {
    this.api = axios.create({
      baseURL: '/api/v1', // Use relative URLs for proxy with v1 API prefix
      timeout: 10000,
    });

    // Request interceptor for environment-specific configuration
    this.api.interceptors.request.use(
      (config) => {
        // Check if we're in a Playwright test at request time
        const isPlaywrightTest = typeof window !== 'undefined' && (window as { playwright?: unknown }).playwright;

        // For Playwright tests, use full URL including baseURL
        if (isPlaywrightTest) {
          if (config.url && !config.url.startsWith('http')) {
            const baseURL = config.baseURL || '';
            config.url = `http://localhost:8080${baseURL}${config.url}`;
          }
        }

        return config;
      },
      (error) => Promise.reject(error)
    );

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
        // Enhanced error logging and handling
        const errorDetails = {
          url: error.config?.url,
          method: error.config?.method?.toUpperCase(),
          status: error.response?.status,
          statusText: error.response?.statusText,
          data: error.response?.data,
          message: error.message,
          timestamp: new Date().toISOString(),
          userAgent: navigator.userAgent,
          correlationId: this.generateCorrelationId(),
        };

        // Log detailed error information
        console.error('API Error:', errorDetails);

        // Handle specific error types
        if (error.response?.status === 401) {
          // Handle unauthorized access
          console.warn('Unauthorized access - redirecting to login');
          localStorage.removeItem('api_token');
          window.location.href = '/login';
        } else if (error.response?.status >= 500) {
          // Server errors - could send to error reporting service
          console.error('Server error detected:', errorDetails);
          this.reportError(errorDetails);
        } else if (error.code === 'NETWORK_ERROR' || error.code === 'ECONNABORTED') {
          // Network errors
          console.error('Network error detected:', errorDetails);
          this.reportError({
            ...errorDetails,
            type: 'network_error',
            message: 'Network connection failed. Please check your internet connection.',
          });
        }

        // Enhance error object with additional context
        const enhancedError = {
          ...error,
          correlationId: errorDetails.correlationId,
          userMessage: this.getUserFriendlyMessage(error),
          technicalDetails: errorDetails,
        };

        return Promise.reject(enhancedError);
      }
    );
  }

  // Authentication
  async login(username: string, password: string): Promise<{ token: string }> {
    const response = await this.api.post('/auth/login', { username, password });
    return response.data;
  }

  // Dashboard
  async getDashboardStats(): Promise<DashboardStats> {
    const response = await this.api.get('dashboard');
    return response.data;
  }

  async getChartData(): Promise<ChartData> {
    const response = await this.api.get('dashboard/chart');
    return response.data;
  }

  // Events
  async getEvents(page: number = 1, limit: number = 50): Promise<PaginationResponse<Event>> {
    const response = await this.api.get(`events?page=${page}&limit=${limit}`);
    return response.data;
  }

  // Event Search
  async searchEvents(request: SearchRequest): Promise<SearchResponse> {
    const response = await this.api.post('events/search', request);
    return response.data;
  }

  async validateQuery(query: string): Promise<QueryValidationResult> {
    const response = await this.api.post('events/search/validate', { query });
    return response.data;
  }

  async exportEvents(request: ExportRequest): Promise<Blob> {
    const response = await this.api.post('events/export', request, {
      responseType: 'blob',
    });
    return response.data;
  }

  async getSearchFields(): Promise<{ fields: SearchField[] }> {
    const response = await this.api.get('events/search/fields');
    return response.data;
  }

  async getSearchOperators(): Promise<{ operators: SearchOperator[] }> {
    const response = await this.api.get('events/search/operators');
    return response.data;
  }

  // Saved Searches
  async getSavedSearches(tags?: string): Promise<{ items: SavedSearch[]; total: number }> {
    const params = tags ? `?tags=${tags}` : '';
    const response = await this.api.get(`saved-searches${params}`);
    return response.data;
  }

  async getSavedSearch(id: string): Promise<SavedSearch> {
    const response = await this.api.get(`saved-searches/${id}`);
    return response.data;
  }

  async createSavedSearch(search: Omit<SavedSearch, 'id' | 'user_id' | 'created_at' | 'updated_at' | 'last_used' | 'use_count'>): Promise<SavedSearch> {
    const response = await this.api.post('saved-searches', search);
    return response.data;
  }

  async updateSavedSearch(id: string, search: Partial<SavedSearch>): Promise<SavedSearch> {
    const response = await this.api.put(`saved-searches/${id}`, search);
    return response.data;
  }

  async deleteSavedSearch(id: string): Promise<{ message: string }> {
    const response = await this.api.delete(`saved-searches/${id}`);
    return response.data;
  }

  // Alerts
  async getAlerts(page: number = 1, limit: number = 50): Promise<PaginationResponse<Alert>> {
    const response = await this.api.get(`alerts?page=${page}&limit=${limit}`);
    return response.data;
  }

  async acknowledgeAlert(alertId: string): Promise<string> {
    const response = await this.api.post(`alerts/${alertId}/acknowledge`);
    return response.data;
  }

  async dismissAlert(alertId: string): Promise<string> {
    const response = await this.api.post(`alerts/${alertId}/dismiss`);
    return response.data;
  }

  // Rules
  async getRules(page: number = 1, limit: number = 50): Promise<PaginationResponse<Rule>> {
    const response = await this.api.get(`rules?page=${page}&limit=${limit}`);
    return response.data;
  }

  async createRule(rule: Omit<Rule, 'id'>): Promise<Rule> {
    const response = await this.api.post('rules', rule);
    return response.data;
  }

  async getRule(id: string): Promise<Rule> {
    const response = await this.api.get(`rules/${id}`);
    return response.data;
  }

  async updateRule(id: string, rule: Partial<Rule>): Promise<Rule> {
    console.log(`API: Updating rule ${id}`, rule);
    const response = await this.api.put(`rules/${id}`, rule);
    console.log('API: Update response:', response.data);
    return response.data;
  }

  async deleteRule(id: string): Promise<string> {
    const response = await this.api.delete(`rules/${id}`);
    return response.data;
  }

  // Correlation Rules
  async getCorrelationRules(page: number = 1, limit: number = 50): Promise<PaginationResponse<CorrelationRule>> {
    const response = await this.api.get(`correlation-rules?page=${page}&limit=${limit}`);
    return response.data;
  }

  async createCorrelationRule(rule: Omit<CorrelationRule, 'id'>): Promise<CorrelationRule> {
    const response = await this.api.post('correlation-rules', rule);
    return response.data;
  }

  async getCorrelationRule(id: string): Promise<CorrelationRule> {
    const response = await this.api.get(`correlation-rules/${id}`);
    return response.data;
  }

  async updateCorrelationRule(id: string, rule: Partial<CorrelationRule>): Promise<CorrelationRule> {
    const response = await this.api.put(`correlation-rules/${id}`, rule);
    return response.data;
  }

  async deleteCorrelationRule(id: string): Promise<string> {
    const response = await this.api.delete(`correlation-rules/${id}`);
    return response.data;
  }

  // Import/Export
  async exportRules(format: 'json' | 'yaml' = 'json', ids?: string[]): Promise<Blob> {
    const params = new URLSearchParams({ format });
    if (ids && ids.length > 0) {
      params.append('ids', ids.join(','));
    }
    const response = await this.api.get(`rules/export?${params}`, {
      responseType: 'blob',
    });
    return response.data;
  }

  async exportCorrelationRules(format: 'json' | 'yaml' = 'json', ids?: string[]): Promise<Blob> {
    const params = new URLSearchParams({ format });
    if (ids && ids.length > 0) {
      params.append('ids', ids.join(','));
    }
    const response = await this.api.get(`correlation-rules/export?${params}`, {
      responseType: 'blob',
    });
    return response.data;
  }

  async importRules(file: File, conflictResolution: 'skip' | 'overwrite' | 'merge' = 'overwrite'): Promise<ImportResult> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('conflict_resolution', conflictResolution);

    const response = await this.api.post('rules/import', formData);
    return response.data;
  }

  async importCorrelationRules(file: File, conflictResolution: 'skip' | 'overwrite' | 'merge' = 'overwrite'): Promise<ImportResult> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('conflict_resolution', conflictResolution);

    const response = await this.api.post('correlation-rules/import', formData);
    return response.data;
  }

  // Actions
  async getActions(): Promise<Action[]> {
    const response = await this.api.get('actions');
    return response.data;
  }

  async createAction(action: Omit<Action, 'id'>): Promise<Action> {
    const response = await this.api.post('actions', action);
    return response.data;
  }

  async getAction(id: string): Promise<Action> {
    const response = await this.api.get(`actions/${id}`);
    return response.data;
  }

  async updateAction(id: string, action: Partial<Action>): Promise<Action> {
    const response = await this.api.put(`actions/${id}`, action);
    return response.data;
  }

  async deleteAction(id: string): Promise<string> {
    const response = await this.api.delete(`actions/${id}`);
    return response.data;
  }

  // Listeners
  async getListeners(): Promise<ListenerStatus> {
    const response = await this.api.get('listeners');
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

  // Error handling utilities
  private generateCorrelationId(): string {
    return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private reportError(errorDetails: Record<string, unknown>): void {
    // Use the error reporting service
    errorReportingService.reportApiError(errorDetails, {
      status: errorDetails.status as number | undefined,
      method: errorDetails.method as string | undefined,
      url: errorDetails.url as string | undefined,
    });
  }

  private getUserFriendlyMessage(error: Record<string, unknown>): string {
    if (error.response?.status === 400) {
      return 'Invalid request. Please check your input and try again.';
    } else if (error.response?.status === 401) {
      return 'Authentication required. Please log in again.';
    } else if (error.response?.status === 403) {
      return 'Access denied. You do not have permission to perform this action.';
    } else if (error.response?.status === 404) {
      return 'The requested resource was not found.';
    } else if (error.response?.status === 409) {
      return 'A conflict occurred. The resource may already exist.';
    } else if (error.response?.status >= 500) {
      return 'A server error occurred. Please try again later.';
    } else if (error.code === 'NETWORK_ERROR') {
      return 'Network connection failed. Please check your internet connection.';
    } else if (error.code === 'ECONNABORTED') {
      return 'Request timed out. Please try again.';
    } else {
      return 'An unexpected error occurred. Please try again.';
    }
  }
}

export const apiService = new ApiService();
export { ApiService };
export default apiService;