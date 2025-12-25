import axios, { AxiosInstance, AxiosError } from 'axios';
import {
  Event, Alert, Rule, CorrelationRule, Action, DashboardStats, ChartData, ListenerStatus,
  PaginationResponse, SearchRequest, SearchResponse, SavedSearch, SearchField, SearchOperator,
  QueryValidationResult, ExportRequest, ImportResult, StatusChange,
  // Unified Rules API types
  UnifiedRulesListRequest, UnifiedRulesResponse, UnifiedRuleResponse,
  BulkOperationRequest, BulkOperationResponse,
  ValidateRuleRequest, ValidateRuleResponse,
  LifecycleTransitionRequest, LifecycleHistoryEntry,
  RuleTestRequest, RuleTestResult, BatchRuleTestRequest,
  RulePerformanceStats, SlowRule,
  FalsePositiveReportRequest, FalsePositiveReportResponse,
  MigrateCQLRequest, MigrateCQLResponse,
  ImportRulesFormData, ImportRulesResponse, ExportRulesRequest,
  RuleCategory, LifecycleStatus
} from '../types';
import websocketService, { WebSocketCallbacks } from './websocket';
import errorReportingService from './errorReporting';
import { apiMonitoring } from './apiMonitoring';
import { apiMonitoringLogger, MONITORING_CONSTANTS } from './logger';
import InvestigationsService from './investigationsService';
import EventsService from './eventsService';
import MitreService from './mitreService';
import MLService from './mlService';
import FieldMappingsService from './fieldMappingsService';
import ListenersService from './listenersService';
import FeedsService from './feedsService';
import SystemService from './systemService';
import { LIMITS } from '../utils/severity';
import { z } from 'zod';
import {
  DashboardStatsSchema,
  ChartDataSchema,
  EventSchema,
  AlertSchema,
  RuleSchema,
  CorrelationRuleSchema,
  ActionSchema,
  ListenerStatusSchema,
  SearchResponseSchema,
  SavedSearchSchema,
  SavedSearchesResponseSchema,
} from '../schemas/api.schemas';
import { safeParse, safeParseArray, safeParsePagination } from '../utils/validation';

// Extend Axios types to support metadata for API monitoring
declare module 'axios' {
  export interface AxiosRequestConfig {
    metadata?: {
      startTime: number;
    };
  }
}

interface ApiErrorDetails {
  url?: string;
  method?: string;
  status?: number;
  statusText?: string;
  data?: unknown;
  message: string;
  timestamp: string;
  userAgent: string;
  correlationId: string;
}

interface EnhancedError extends AxiosError {
  correlationId?: string;
  userMessage?: string;
  technicalDetails?: ApiErrorDetails;
}

class ApiService {
  private api: AxiosInstance;
  public investigations: InvestigationsService;
  public events: EventsService;
  public mitre: MitreService;
  public ml: MLService;
  public fieldMappings: FieldMappingsService;
  public listeners: ListenersService;
  public feeds: FeedsService;
  public system: SystemService;

  constructor() {
    this.api = axios.create({
      baseURL: '/api/v1', // Use relative URLs for proxy with v1 API prefix
      timeout: LIMITS.API_TIMEOUT,
      withCredentials: true, // SECURITY: Required to send httpOnly auth cookies
    });

    // Initialize sub-services
    this.investigations = new InvestigationsService(this.api);
    this.events = new EventsService(this.api);
    this.mitre = new MitreService(this.api);
    this.ml = new MLService(this.api);
    this.fieldMappings = new FieldMappingsService(this.api);
    this.listeners = new ListenersService(this.api);
    this.feeds = new FeedsService(this.api);
    this.system = new SystemService(this.api);

    // API MONITORING: Request interceptor to attach startTime metadata
    // This MUST come first to ensure all requests are timed
    this.api.interceptors.request.use(
      (config) => {
        config.metadata = { startTime: performance.now() };
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Request interceptor for environment-specific configuration
    this.api.interceptors.request.use(
      (config) => {
        // Check if we're in a Playwright test at request time
        const isPlaywrightTest = typeof window !== 'undefined' && (window as { playwright?: unknown }).playwright;

        // For Playwright tests, use full URL including baseURL
        if (isPlaywrightTest) {
          if (config.url && !config.url.startsWith('http')) {
            const baseURL = config.baseURL || '';
            config.url = `http://localhost:8081${baseURL}${config.url}`;
          }
        }

        return config;
      },
      (error) => Promise.reject(error)
    );

    // Request interceptor for authentication
    // NOTE: JWT tokens are sent via httpOnly cookies by the backend
    // for security (prevents XSS attacks). We set withCredentials to
    // ensure cookies are included in cross-origin requests.
    this.api.interceptors.request.use(
      (config) => {
        // CSRF token is read from non-httpOnly cookie and sent in header
        const csrfToken = document.cookie
          .split('; ')
          .find(row => row.startsWith('csrf_token='))
          ?.split('=')[1];

        if (csrfToken) {
          config.headers['X-CSRF-Token'] = csrfToken;
        }

        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling
    this.api.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        // Enhanced error logging and handling
        const errorDetails: ApiErrorDetails = {
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

        // Only log errors in development
        if (import.meta.env.DEV) {
          console.error('API Error:', errorDetails);
        }

        // Handle specific error types
        if (error.response?.status === 401) {
          // Handle unauthorized access - httpOnly cookie will be cleared by backend
          if (import.meta.env.DEV) {
            console.warn('Unauthorized access - redirecting to login');
          }
          window.location.href = '/login';
        } else if (error.response?.status && error.response.status >= 500) {
          // Server errors - send to error reporting service
          this.reportError(errorDetails);
        } else if (error.code === 'ERR_NETWORK' || error.code === 'ECONNABORTED') {
          // Network errors
          this.reportError(errorDetails);
        }

        // Enhance error object with additional context
        const enhancedError: EnhancedError = error as EnhancedError;
        enhancedError.correlationId = errorDetails.correlationId;
        enhancedError.userMessage = this.getUserFriendlyMessage(error);
        enhancedError.technicalDetails = errorDetails;

        return Promise.reject(enhancedError);
      }
    );

    // API MONITORING: Response interceptors to record metrics
    // These come AFTER error handling to ensure all responses (success/error) are tracked
    this.api.interceptors.response.use(
      (response) => {
        // Record successful API call with error boundary
        const startTime = response.config.metadata?.startTime;
        if (typeof startTime === 'number' && isFinite(startTime)) {
          const duration = performance.now() - startTime;
          try {
            const endpoint = response.config.url || MONITORING_CONSTANTS.UNKNOWN_ENDPOINT;
            if (!response.config.url) {
              apiMonitoringLogger.warn('[API Monitoring] Request missing URL', {
                method: response.config.method,
                status: response.status,
              });
            }
            apiMonitoring.recordAPICall(
              endpoint,
              response.config.method?.toUpperCase() || MONITORING_CONSTANTS.UNKNOWN_METHOD,
              duration,
              response.status
            );
          } catch (error) {
            // Non-blocking: log monitoring failure but don't crash the request
            apiMonitoringLogger.error('[API Monitoring] Failed to record API call:', error);
          }
        } else if (response.config.metadata?.startTime !== undefined) {
          apiMonitoringLogger.warn('[API Monitoring] Invalid startTime type', {
            url: response.config.url,
            startTime: response.config.metadata.startTime,
            type: typeof response.config.metadata.startTime,
          });
        }
        return response;
      },
      (error: AxiosError) => {
        // Record failed API call with error boundary
        const startTime = error.config?.metadata?.startTime;
        if (typeof startTime === 'number' && isFinite(startTime)) {
          const duration = performance.now() - startTime;
          try {
            const endpoint = error.config?.url || MONITORING_CONSTANTS.UNKNOWN_ENDPOINT;
            if (!error.config?.url) {
              apiMonitoringLogger.warn('[API Monitoring] Request missing URL', {
                method: error.config?.method,
                status: error.response?.status,
              });
            }
            apiMonitoring.recordAPICall(
              endpoint,
              error.config?.method?.toUpperCase() || MONITORING_CONSTANTS.UNKNOWN_METHOD,
              duration,
              error.response?.status || 0,
              error.message
            );
          } catch (recordError) {
            // Non-blocking: log monitoring failure but don't crash the request
            apiMonitoringLogger.error('[API Monitoring] Failed to record error:', recordError);
          }
        } else if (error.config?.metadata?.startTime !== undefined) {
          apiMonitoringLogger.warn('[API Monitoring] Invalid startTime type', {
            url: error.config?.url,
            startTime: error.config.metadata.startTime,
            type: typeof error.config.metadata.startTime,
          });
        }
        return Promise.reject(error);
      }
    );

    // Bind methods to preserve 'this' context when passed as callbacks
    this.getAlerts = this.getAlerts.bind(this);
    this.getRules = this.getRules.bind(this);
    this.getCorrelationRules = this.getCorrelationRules.bind(this);
    this.getActions = this.getActions.bind(this);
    this.getEvents = this.getEvents.bind(this);
    this.getDashboardStats = this.getDashboardStats.bind(this);
    this.getChartData = this.getChartData.bind(this);
    this.getListeners = this.getListeners.bind(this);
  }

  // Authentication
  async login(username: string, password: string): Promise<{ token: string }> {
    const response = await this.api.post('/auth/login', { username, password });
    return response.data;
  }

  // Dashboard
  async getDashboardStats(): Promise<DashboardStats> {
    try {
      const response = await this.api.get('dashboard');
      // SECURITY: Validate response structure with lenient fallback
      const defaultStats: DashboardStats = {
        total_events: 0,
        active_alerts: 0,
        rules_fired: 0,
        system_health: 'Unknown',
      };
      return safeParse(DashboardStatsSchema, response.data, defaultStats, 'GET /dashboard');
    } catch (error) {
      // Return default stats on error to prevent UI breaking
      if (import.meta.env.DEV) {
        console.error('Failed to get dashboard stats:', error);
      }
      return {
        total_events: 0,
        active_alerts: 0,
        rules_fired: 0,
        system_health: 'Unknown',
      };
    }
  }

  async getChartData(): Promise<ChartData[]> {
    try {
      const response = await this.api.get('dashboard/chart');
      // SECURITY: Validate response structure with lenient fallback
      return safeParseArray(ChartDataSchema, response.data, 'GET /dashboard/chart');
    } catch (error) {
      // Return empty array on error to prevent chart breaking
      if (import.meta.env.DEV) {
        console.error('Failed to get chart data:', error);
      }
      return [];
    }
  }

  // Events
  async getEvents(page: number = 1, limit: number = 50): Promise<PaginationResponse<Event>> {
    const response = await this.api.get(`events?page=${page}&limit=${limit}`);
    // SECURITY: Validate response structure with lenient fallback
    return safeParsePagination(EventSchema, response.data, 'GET /events');
  }

  // Event Search
  async searchEvents(request: SearchRequest): Promise<SearchResponse> {
    const response = await this.api.post('events/search', request);
    // SECURITY: Validate response structure with lenient fallback
    const defaultResponse: SearchResponse = {
      events: [],
      total: 0,
      page: 1,
      limit: 50,
      query: request.query || '',
    };
    return safeParse(SearchResponseSchema, response.data, defaultResponse, 'POST /events/search');
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
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(
      SavedSearchesResponseSchema,
      response.data,
      { items: [], total: 0 },
      'GET /saved-searches'
    );
  }

  async getSavedSearch(id: string): Promise<SavedSearch | null> {
    const response = await this.api.get(`saved-searches/${id}`);
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(SavedSearchSchema, response.data, null, `GET /saved-searches/${id}`);
  }

  async createSavedSearch(search: Omit<SavedSearch, 'id' | 'created_at' | 'updated_at' | 'usage_count'>): Promise<SavedSearch | null> {
    const response = await this.api.post('saved-searches', search);
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(SavedSearchSchema, response.data, null, 'POST /saved-searches');
  }

  async updateSavedSearch(id: string, search: Partial<SavedSearch>): Promise<SavedSearch | null> {
    const response = await this.api.put(`saved-searches/${id}`, search);
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(SavedSearchSchema, response.data, null, `PUT /saved-searches/${id}`);
  }

  async deleteSavedSearch(id: string): Promise<{ message: string }> {
    const response = await this.api.delete(`saved-searches/${id}`);
    return response.data;
  }

  // Alerts
  async getAlerts(
    page: number = 1,
    limit: number = 50,
    filters?: {
      severity?: string;
      status?: string;
      q?: string;
      disposition?: string;
    }
  ): Promise<PaginationResponse<Alert>> {
    const params = new URLSearchParams();
    params.append('page', String(page));
    params.append('limit', String(limit));

    // Add filter parameters if provided
    if (filters?.severity && filters.severity !== 'all') {
      params.append('severity', filters.severity);
    }
    if (filters?.status && filters.status !== 'all') {
      params.append('status', filters.status);
    }
    if (filters?.q) {
      params.append('q', filters.q);
    }
    if (filters?.disposition && filters.disposition !== 'all') {
      params.append('disposition', filters.disposition);
    }

    const response = await this.api.get(`alerts?${params.toString()}`);
    // SECURITY: Validate response structure with lenient fallback
    return safeParsePagination(AlertSchema, response.data, 'GET /alerts');
  }

  async acknowledgeAlert(alertId: string): Promise<string> {
    const response = await this.api.post(`alerts/${alertId}/acknowledge`);
    return response.data;
  }

  async dismissAlert(alertId: string): Promise<string> {
    const response = await this.api.post(`alerts/${alertId}/dismiss`);
    return response.data;
  }

  async updateAlertStatus(alertId: string, status: string, note?: string): Promise<string> {
    const response = await this.api.put(`alerts/${alertId}/status`, { status, note });
    return response.data;
  }

  async assignAlert(alertId: string, assignTo: string, note?: string): Promise<string> {
    const response = await this.api.put(`alerts/${alertId}/assign`, { assign_to: assignTo, note });
    return response.data;
  }

  async getAlertHistory(alertId: string): Promise<StatusChange[]> {
    try {
      const response = await this.api.get(`alerts/${alertId}/history`);
      return response.data || [];
    } catch {
      // If endpoint doesn't exist or fails, return empty array
      // Timeline will show "No History Available" message
      return [];
    }
  }

  async updateAlertDisposition(
    alertId: string,
    disposition: string,
    reason?: string
  ): Promise<{
    id: string;
    disposition: string;
    disposition_reason: string;
    disposition_set_at: string;
    disposition_set_by: string;
    message: string;
  }> {
    const response = await this.api.put(`alerts/${alertId}/disposition`, {
      disposition,
      reason: reason || '',
    });
    return response.data;
  }

  // Rules
  async getRules(page: number = 1, limit: number = 50): Promise<PaginationResponse<Rule>> {
    const response = await this.api.get(`rules?page=${page}&limit=${limit}`);

    // Backend now returns paginated response: {items, total, page, limit, total_pages}
    // SECURITY: Use safeParseArray to validate items and protect against XSS/prototype pollution
    const data = response.data;
    const rules = safeParseArray(RuleSchema, data.items || [], 'GET /rules');

    return {
      items: rules,
      total: data.total || rules.length,
      page: data.page || page,
      limit: data.limit || limit,
      total_pages: data.total_pages || Math.ceil((data.total || rules.length) / limit),
    };
  }

  async createRule(rule: Omit<Rule, 'id'>): Promise<Rule | null> {
    const response = await this.api.post('rules', rule);
    // SECURITY: Validate created rule before returning to caller
    return safeParse(RuleSchema, response.data, null, 'POST /rules');
  }

  async getRule(id: string): Promise<Rule | null> {
    const response = await this.api.get(`rules/${id}`);
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(RuleSchema, response.data, null, `GET /rules/${id}`);
  }

  async updateRule(id: string, rule: Partial<Rule>): Promise<Rule | null> {
    const response = await this.api.put(`rules/${id}`, rule);
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(RuleSchema, response.data, null, `PUT /rules/${id}`);
  }

  async deleteRule(id: string): Promise<string> {
    const response = await this.api.delete(`rules/${id}`);
    // SECURITY: Validate response is a string and sanitize
    const messageSchema = z.string();
    return safeParse(messageSchema, response.data, 'Rule deleted', `DELETE /rules/${id}`);
  }

  // Correlation Rules
  async getCorrelationRules(page: number = 1, limit: number = 50): Promise<PaginationResponse<CorrelationRule>> {
    const response = await this.api.get(`correlation-rules?page=${page}&limit=${limit}`);

    // Backend returns paginated structure: {items: [...], total, page, limit, total_pages}
    // SECURITY: Use safeParseArray to validate items and protect against XSS/prototype pollution
    const data = response.data;
    const rules = safeParseArray(CorrelationRuleSchema, data.items || [], 'GET /correlation-rules');

    return {
      items: rules,
      total: data.total || rules.length,
      page: data.page || page,
      limit: data.limit || limit,
      total_pages: data.total_pages || Math.ceil(rules.length / limit),
    };
  }

  async createCorrelationRule(rule: Omit<CorrelationRule, 'id'>): Promise<CorrelationRule | null> {
    const response = await this.api.post('correlation-rules', rule);
    // SECURITY: Validate created rule before returning to caller
    return safeParse(CorrelationRuleSchema, response.data, null, 'POST /correlation-rules');
  }

  async getCorrelationRule(id: string): Promise<CorrelationRule | null> {
    const response = await this.api.get(`correlation-rules/${id}`);
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(CorrelationRuleSchema, response.data, null, `GET /correlation-rules/${id}`);
  }

  async updateCorrelationRule(id: string, rule: Partial<CorrelationRule>): Promise<CorrelationRule | null> {
    const response = await this.api.put(`correlation-rules/${id}`, rule);
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(CorrelationRuleSchema, response.data, null, `PUT /correlation-rules/${id}`);
  }

  async deleteCorrelationRule(id: string): Promise<string> {
    const response = await this.api.delete(`correlation-rules/${id}`);
    // SECURITY: Validate response is a string and sanitize
    const messageSchema = z.string();
    return safeParse(messageSchema, response.data, 'Correlation rule deleted', `DELETE /correlation-rules/${id}`);
  }

  // =============================================================================
  // Unified Rules API (TASK 174.7)
  // Consolidated endpoints for detection and correlation rules with SIGMA support
  // =============================================================================

  /**
   * Get unified rules list with advanced filtering
   * Supports filtering by category, lifecycle status, and logsource
   *
   * @param params - Filtering and pagination parameters
   * @returns Paginated unified rules response
   */
  async getUnifiedRules(params?: UnifiedRulesListRequest): Promise<UnifiedRulesResponse> {
    try {
      const queryParams = new URLSearchParams();

      if (params?.category) queryParams.append('category', params.category);
      if (params?.lifecycle_status) queryParams.append('lifecycle_status', params.lifecycle_status);
      if (params?.logsource_category) queryParams.append('logsource_category', params.logsource_category);
      if (params?.logsource_product) queryParams.append('logsource_product', params.logsource_product);
      if (params?.enabled !== undefined) queryParams.append('enabled', String(params.enabled));

      // Handle pagination - convert page to offset if provided
      const limit = params?.limit || 50;
      const offset = params?.offset !== undefined
        ? params.offset
        : params?.page
          ? (params.page - 1) * limit
          : 0;

      queryParams.append('limit', String(limit));
      queryParams.append('offset', String(offset));

      const response = await this.api.get(`rules?${queryParams.toString()}`);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to get unified rules:', error);
      }
      throw error;
    }
  }

  /**
   * Create a unified rule with automatic category detection
   * Backend automatically detects whether this is a detection or correlation rule
   *
   * @param rule - Rule to create (detection or correlation)
   * @returns Created rule with category metadata
   */
  async createUnifiedRule(rule: Omit<Rule, 'id'>): Promise<UnifiedRuleResponse> {
    try {
      const response = await this.api.post('rules', rule);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to create unified rule:', error);
      }
      throw error;
    }
  }

  /**
   * Get a single unified rule by ID
   * Automatically searches both detection and correlation rule stores
   *
   * @param id - Rule ID
   * @returns Rule with category metadata
   */
  async getUnifiedRule(id: string): Promise<UnifiedRuleResponse> {
    try {
      const response = await this.api.get(`rules/${id}`);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to get unified rule:', error);
      }
      throw error;
    }
  }

  /**
   * Update a unified rule with category consistency validation
   * Backend prevents changing rule category (e.g., detection to correlation)
   *
   * @param id - Rule ID
   * @param rule - Updated rule data
   * @returns Updated rule with category metadata
   */
  async updateUnifiedRule(id: string, rule: Partial<Rule>): Promise<UnifiedRuleResponse> {
    try {
      const response = await this.api.put(`rules/${id}`, rule);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to update unified rule:', error);
      }
      throw error;
    }
  }

  /**
   * Delete a unified rule
   * Automatically removes from appropriate storage (detection or correlation)
   *
   * @param id - Rule ID
   * @returns Success message
   */
  async deleteUnifiedRule(id: string): Promise<{ message: string }> {
    try {
      const response = await this.api.delete(`rules/${id}`);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to delete unified rule:', error);
      }
      throw error;
    }
  }

  // Bulk Operations

  /**
   * Enable multiple rules in batch
   * Best-effort processing with partial success support
   *
   * @param ruleIds - Array of rule IDs to enable
   * @returns Bulk operation result with success/failure counts
   */
  async bulkEnableRules(ruleIds: string[]): Promise<BulkOperationResponse> {
    try {
      const response = await this.api.post('rules/bulk-enable', { rule_ids: ruleIds });
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to bulk enable rules:', error);
      }
      throw error;
    }
  }

  /**
   * Disable multiple rules in batch
   * Best-effort processing with partial success support
   *
   * @param ruleIds - Array of rule IDs to disable
   * @returns Bulk operation result with success/failure counts
   */
  async bulkDisableRules(ruleIds: string[]): Promise<BulkOperationResponse> {
    try {
      const response = await this.api.post('rules/bulk-disable', { rule_ids: ruleIds });
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to bulk disable rules:', error);
      }
      throw error;
    }
  }

  /**
   * Delete multiple rules in batch
   * Best-effort processing with partial success support
   *
   * @param ruleIds - Array of rule IDs to delete
   * @returns Bulk operation result with success/failure counts
   */
  async bulkDeleteRules(ruleIds: string[]): Promise<BulkOperationResponse> {
    try {
      const response = await this.api.post('rules/bulk-delete', { rule_ids: ruleIds });
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to bulk delete rules:', error);
      }
      throw error;
    }
  }

  // Import/Export

  /**
   * Import rules from SIGMA YAML files or ZIP archive
   * Supports individual YAML files or ZIP containing multiple rules
   *
   * @param formData - Files and import options
   * @returns Import results with per-file status
   */
  async importUnifiedRules(formData: ImportRulesFormData): Promise<ImportRulesResponse> {
    try {
      // SECURITY: Validate file types before upload
      const ALLOWED_EXTENSIONS = ['.yml', '.yaml', '.zip'];
      for (const file of formData.files) {
        const fileName = file.name.toLowerCase();
        const hasValidExtension = ALLOWED_EXTENSIONS.some(ext => fileName.endsWith(ext));
        if (!hasValidExtension) {
          throw new Error(
            `Invalid file type: ${file.name}. Only YAML (.yml, .yaml) and ZIP files are allowed.`
          );
        }
      }

      const data = new FormData();

      formData.files.forEach((file) => {
        data.append('files', file);
      });

      if (formData.overwrite_existing !== undefined) {
        data.append('overwrite_existing', String(formData.overwrite_existing));
      }

      if (formData.dry_run !== undefined) {
        data.append('dry_run', String(formData.dry_run));
      }

      const response = await this.api.post('rules/import', data, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to import unified rules:', error);
      }
      throw error;
    }
  }

  /**
   * Export rules as SIGMA YAML or JSON in ZIP archive
   * Supports filtering by category and specific rule IDs
   *
   * @param params - Export format and filtering options
   * @returns ZIP file blob
   */
  async exportUnifiedRules(params?: ExportRulesRequest): Promise<Blob> {
    try {
      const queryParams = new URLSearchParams();

      if (params?.format) queryParams.append('format', params.format);
      if (params?.category) queryParams.append('category', params.category);
      if (params?.rule_ids && params.rule_ids.length > 0) {
        params.rule_ids.forEach(id => queryParams.append('rule_ids', id));
      }

      const response = await this.api.get(`rules/export?${queryParams.toString()}`, {
        responseType: 'blob',
      });
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to export unified rules:', error);
      }
      throw error;
    }
  }

  // Validation

  /**
   * Validate SIGMA YAML without creating a rule
   * Returns detailed validation errors and warnings
   *
   * @param request - SIGMA YAML to validate
   * @returns Validation result with category detection
   */
  async validateRule(request: ValidateRuleRequest): Promise<ValidateRuleResponse> {
    try {
      const response = await this.api.post('rules/validate', request);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to validate rule:', error);
      }
      throw error;
    }
  }

  // Lifecycle Management

  /**
   * Transition rule lifecycle status
   * Changes rule status (experimental -> test -> stable, etc.)
   *
   * @param id - Rule ID
   * @param request - New status and optional comment
   * @returns Updated rule
   */
  async transitionRuleLifecycle(
    id: string,
    request: LifecycleTransitionRequest
  ): Promise<UnifiedRuleResponse> {
    try {
      const response = await this.api.post(`rules/${id}/lifecycle`, request);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to transition rule lifecycle:', error);
      }
      throw error;
    }
  }

  /**
   * Get rule lifecycle audit history
   * Returns all status transitions for the rule
   *
   * @param id - Rule ID
   * @returns Array of lifecycle history entries
   */
  async getRuleLifecycleHistory(id: string): Promise<LifecycleHistoryEntry[]> {
    try {
      const response = await this.api.get(`rules/${id}/lifecycle-history`);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to get rule lifecycle history:', error);
      }
      throw error;
    }
  }

  // Testing

  /**
   * Test a rule against sample events
   * Validates rule logic without creating alerts
   *
   * @param request - Rule ID or SIGMA YAML with test events
   * @returns Test results with match details
   */
  async testRule(request: RuleTestRequest): Promise<RuleTestResult> {
    try {
      const response = await this.api.post('rules/test', request);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to test rule:', error);
      }
      throw error;
    }
  }

  /**
   * Batch test rule against multiple events
   * Tests rule against specific event IDs from storage
   *
   * @param request - Rule ID and event IDs
   * @returns Test results
   */
  async batchTestRule(request: BatchRuleTestRequest): Promise<RuleTestResult> {
    try {
      const response = await this.api.post(`rules/${request.rule_id}/test-batch`, request);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to batch test rule:', error);
      }
      throw error;
    }
  }

  // Performance

  /**
   * Get performance statistics for a specific rule
   * Returns execution time metrics and match rates
   *
   * @param id - Rule ID
   * @param timeRange - Optional time range for stats
   * @returns Performance statistics
   */
  async getRulePerformance(
    id: string,
    timeRange?: { start: string; end: string }
  ): Promise<RulePerformanceStats> {
    try {
      const queryParams = new URLSearchParams();
      if (timeRange?.start) queryParams.append('start', timeRange.start);
      if (timeRange?.end) queryParams.append('end', timeRange.end);

      const response = await this.api.get(
        `rules/${id}/performance?${queryParams.toString()}`
      );
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to get rule performance:', error);
      }
      throw error;
    }
  }

  /**
   * List slow-performing rules
   * Identifies rules with high execution times
   *
   * @param limit - Maximum number of results
   * @param threshold - Minimum execution time in ms
   * @returns Array of slow rules
   */
  async getSlowRules(limit: number = 10, threshold?: number): Promise<SlowRule[]> {
    try {
      const queryParams = new URLSearchParams();
      queryParams.append('limit', String(limit));
      if (threshold !== undefined) queryParams.append('threshold', String(threshold));

      const response = await this.api.get(`rules/performance/slow?${queryParams.toString()}`);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to get slow rules:', error);
      }
      throw error;
    }
  }

  /**
   * Report a false positive alert
   * Helps improve rule accuracy by tracking false positives
   *
   * @param request - False positive details
   * @returns Report confirmation
   */
  async reportFalsePositive(
    request: FalsePositiveReportRequest
  ): Promise<FalsePositiveReportResponse> {
    try {
      const response = await this.api.post(
        `rules/${request.rule_id}/false-positive`,
        request
      );
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to report false positive:', error);
      }
      throw error;
    }
  }

  // CQL Migration

  /**
   * Migrate CQL rules to SIGMA format
   * Converts legacy CQL rules to modern SIGMA YAML
   *
   * @param request - Migration options
   * @returns Migration results
   */
  async migrateCQLRules(request: MigrateCQLRequest): Promise<MigrateCQLResponse> {
    try {
      const response = await this.api.post('rules/migrate-cql', request);
      return response.data;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to migrate CQL rules:', error);
      }
      throw error;
    }
  }

  // =============================================================================
  // Unified Rules API - Convenience Methods (TASK 174.7)
  // Simplified wrappers for common operations
  // =============================================================================

  /**
   * Get rules with optional filtering (convenience method)
   * Wrapper for getUnifiedRules with simplified parameters
   *
   * @param category - Optional category filter
   * @param status - Optional lifecycle status filter
   * @returns Unified rules response
   */
  async getRulesUnified(
    category?: RuleCategory,
    status?: LifecycleStatus
  ): Promise<UnifiedRulesResponse> {
    return this.getUnifiedRules({ category, lifecycle_status: status });
  }

  /**
   * Get single rule by ID (convenience method)
   * Wrapper for getUnifiedRule
   *
   * @param id - Rule ID
   * @returns Rule with category metadata
   */
  async getRuleById(id: string): Promise<UnifiedRuleResponse> {
    return this.getUnifiedRule(id);
  }

  /**
   * Create new rule (convenience method)
   * Wrapper for createUnifiedRule
   *
   * @param data - Rule data
   * @returns Created rule with category metadata
   */
  async createRuleUnified(data: Omit<Rule, 'id'>): Promise<UnifiedRuleResponse> {
    return this.createUnifiedRule(data);
  }

  /**
   * Update existing rule (convenience method)
   * Wrapper for updateUnifiedRule
   *
   * @param id - Rule ID
   * @param data - Updated rule data
   * @returns Updated rule with category metadata
   */
  async updateRuleUnified(id: string, data: Partial<Rule>): Promise<UnifiedRuleResponse> {
    return this.updateUnifiedRule(id, data);
  }

  /**
   * Delete rule (convenience method)
   * Wrapper for deleteUnifiedRule
   *
   * @param id - Rule ID
   * @returns Success message
   */
  async deleteRuleUnified(id: string): Promise<{ message: string }> {
    return this.deleteUnifiedRule(id);
  }

  /**
   * Promote rule to next lifecycle stage
   * Convenience method that automatically determines next status
   *
   * @param id - Rule ID
   * @returns Updated rule
   */
  async promoteRule(id: string): Promise<UnifiedRuleResponse> {
    try {
      // Get current rule to determine next status
      const currentRule = await this.getUnifiedRule(id);
      const rule = currentRule.rule as Rule;
      const currentStatus = (rule as { lifecycle_status?: LifecycleStatus }).lifecycle_status || 'experimental';

      // Determine next lifecycle status
      let nextStatus: LifecycleStatus;
      switch (currentStatus) {
        case 'experimental':
          nextStatus = 'test';
          break;
        case 'test':
          nextStatus = 'stable';
          break;
        case 'stable':
          nextStatus = 'stable'; // Already at highest, no change
          break;
        case 'deprecated':
          nextStatus = 'archived';
          break;
        case 'active':
          nextStatus = 'stable';
          break;
        default:
          nextStatus = 'test';
      }

      return this.transitionRuleLifecycle(id, {
        status: nextStatus,
        comment: 'Promoted via convenience method',
      });
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to promote rule:', error);
      }
      throw error;
    }
  }

  /**
   * Mark rule as deprecated with sunset date
   * Convenience method for deprecation workflow
   *
   * @param id - Rule ID
   * @param reason - Deprecation reason
   * @param sunsetDate - Optional sunset date
   * @returns Updated rule
   */
  async deprecateRule(
    id: string,
    reason: string,
    sunsetDate?: string
  ): Promise<UnifiedRuleResponse> {
    try {
      const comment = sunsetDate
        ? `Deprecated: ${reason}. Sunset date: ${sunsetDate}`
        : `Deprecated: ${reason}`;

      return this.transitionRuleLifecycle(id, {
        status: 'deprecated',
        comment,
      });
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to deprecate rule:', error);
      }
      throw error;
    }
  }

  /**
   * Archive a rule
   * Convenience method for archival workflow
   *
   * @param id - Rule ID
   * @returns Updated rule
   */
  async archiveRule(id: string): Promise<UnifiedRuleResponse> {
    try {
      return this.transitionRuleLifecycle(id, {
        status: 'archived',
        comment: 'Archived via convenience method',
      });
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to archive rule:', error);
      }
      throw error;
    }
  }

  /**
   * Get rule version history
   * Convenience wrapper for getRuleLifecycleHistory
   *
   * @param id - Rule ID
   * @returns Lifecycle history entries
   */
  async getRuleHistory(id: string): Promise<LifecycleHistoryEntry[]> {
    return this.getRuleLifecycleHistory(id);
  }

  /**
   * Test rule against sample events (convenience method)
   * Wrapper for testRule
   *
   * @param id - Rule ID
   * @param events - Sample events to test
   * @returns Test results
   */
  async testRuleWithEvents(
    id: string,
    events: Record<string, unknown>[]
  ): Promise<RuleTestResult> {
    return this.testRule({ rule_id: id, events });
  }

  /**
   * Get performance metrics for time range
   * Convenience wrapper with optional time range
   *
   * @param timeRange - Optional time range filter
   * @returns Performance statistics (implementation depends on backend)
   */
  async getPerformanceMetrics(
    timeRange?: { start: string; end: string }
  ): Promise<{ rules: RulePerformanceStats[] }> {
    // PLACEHOLDER: This endpoint is not yet implemented in the backend
    // TODO: Implement when backend endpoint becomes available
    throw new Error('Not Implemented: Performance metrics endpoint is not yet available');
  }

  /**
   * Get rules exceeding performance threshold
   * Convenience wrapper for getSlowRules
   *
   * @param threshold - Execution time threshold in ms
   * @returns Slow rules list
   */
  async getSlowRulesAboveThreshold(threshold?: number): Promise<SlowRule[]> {
    return this.getSlowRules(10, threshold);
  }

  /**
   * Get top performing rules
   * Convenience method for best performing rules
   *
   * @param limit - Number of results
   * @returns Top rules by match rate (implementation depends on backend)
   */
  async getTopRules(limit?: number): Promise<RulePerformanceStats[]> {
    // PLACEHOLDER: This endpoint is not yet implemented in the backend
    // TODO: Implement when backend endpoint becomes available
    throw new Error('Not Implemented: Top rules endpoint is not yet available');
  }

  /**
   * Report false positive alert
   * Convenience wrapper for reportFalsePositive
   *
   * @param ruleId - Rule ID
   * @param reason - False positive reason
   * @param eventId - Optional event ID
   * @param alertId - Optional alert ID
   * @returns Report confirmation
   */
  async reportRuleFalsePositive(
    ruleId: string,
    reason: string,
    eventId?: string,
    alertId?: string
  ): Promise<FalsePositiveReportResponse> {
    return this.reportFalsePositive({
      rule_id: ruleId,
      event_id: eventId || '',
      alert_id: alertId,
      reason,
    });
  }

  // =============================================================================
  // End Unified Rules API - Convenience Methods
  // =============================================================================

  // =============================================================================
  // End Unified Rules API
  // =============================================================================

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
    // SECURITY: Validate response structure with lenient fallback
    return safeParseArray(ActionSchema, response.data, 'GET /actions');
  }

  async createAction(action: Omit<Action, 'id'>): Promise<Action | null> {
    const response = await this.api.post('actions', action);
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(ActionSchema, response.data, null, 'POST /actions');
  }

  async getAction(id: string): Promise<Action | null> {
    const response = await this.api.get(`actions/${id}`);
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(ActionSchema, response.data, null, `GET /actions/${id}`);
  }

  async updateAction(id: string, action: Partial<Action>): Promise<Action | null> {
    const response = await this.api.put(`actions/${id}`, action);
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(ActionSchema, response.data, null, `PUT /actions/${id}`);
  }

  async deleteAction(id: string): Promise<string> {
    const response = await this.api.delete(`actions/${id}`);
    // SECURITY: Validate response is a string and sanitize
    const messageSchema = z.string();
    return safeParse(messageSchema, response.data, 'Action deleted', `DELETE /actions/${id}`);
  }

  // Listeners
  async getListeners(): Promise<ListenerStatus | null> {
    const response = await this.api.get('listeners');
    // SECURITY: Validate response structure with lenient fallback
    return safeParse(ListenerStatusSchema, response.data, null, 'GET /listeners');
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

  private reportError(errorDetails: ApiErrorDetails): void {
    // Use the error reporting service
    errorReportingService.reportApiError(errorDetails, {
      status: errorDetails.status,
      method: errorDetails.method,
      url: errorDetails.url,
    });
  }

  private getUserFriendlyMessage(error: AxiosError): string {
    const status = error.response?.status;

    if (status === 400) {
      return 'Invalid request. Please check your input and try again.';
    } else if (status === 401) {
      return 'Authentication required. Please log in again.';
    } else if (status === 403) {
      return 'Access denied. You do not have permission to perform this action.';
    } else if (status === 404) {
      return 'The requested resource was not found.';
    } else if (status === 409) {
      return 'A conflict occurred. The resource may already exist.';
    } else if (status && status >= 500) {
      return 'A server error occurred. Please try again later.';
    } else if (error.code === 'ERR_NETWORK') {
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