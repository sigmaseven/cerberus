import { AxiosInstance } from 'axios';
import {
  DynamicListener,
  ListenerForm,
  ListenerTemplate,
  ListenerStats,
  ListenerControlResponse,
  PaginationResponse,
} from '../types';
import { ListenerTemplatesArraySchema, safeValidateSchema } from '../schemas/api.schemas';

// UUID validation regex for defensive checks
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validates that an ID is a valid UUID format before making API calls
 * Prevents 400 errors from undefined/null/invalid IDs reaching the backend
 */
function validateId(id: string, operation: string): void {
  if (!id || typeof id !== 'string' || !UUID_REGEX.test(id)) {
    throw new Error(`Invalid listener ID for ${operation}: ${id}`);
  }
}

class ListenersService {
  private api: AxiosInstance;

  constructor(apiInstance: AxiosInstance) {
    this.api = apiInstance;
  }

  // CRUD Operations

  /**
   * Get all listeners with pagination
   */
  async getListeners(
    page = 1,
    limit = 50
  ): Promise<PaginationResponse<DynamicListener>> {
    const response = await this.api.get('/listeners', {
      params: { page, limit },
    });
    return response.data;
  }

  /**
   * Get a single listener by ID
   */
  async getListener(id: string): Promise<DynamicListener> {
    validateId(id, 'getListener');
    const response = await this.api.get(`/listeners/${id}`);
    return response.data;
  }

  /**
   * Create a new listener
   */
  async createListener(listener: ListenerForm): Promise<DynamicListener> {
    const response = await this.api.post('/listeners', listener);
    return response.data;
  }

  /**
   * Update an existing listener (must be stopped first)
   */
  async updateListener(
    id: string,
    updates: Partial<ListenerForm>
  ): Promise<DynamicListener> {
    validateId(id, 'updateListener');
    const response = await this.api.put(`/listeners/${id}`, updates);
    return response.data;
  }

  /**
   * Delete a listener (must be stopped first)
   */
  async deleteListener(id: string): Promise<void> {
    validateId(id, 'deleteListener');
    await this.api.delete(`/listeners/${id}`);
  }

  // Control Operations

  /**
   * Start a stopped listener
   */
  async startListener(id: string): Promise<ListenerControlResponse> {
    validateId(id, 'startListener');
    const response = await this.api.post(`/listeners/${id}/start`);
    return response.data;
  }

  /**
   * Stop a running listener
   */
  async stopListener(id: string): Promise<ListenerControlResponse> {
    validateId(id, 'stopListener');
    const response = await this.api.post(`/listeners/${id}/stop`);
    return response.data;
  }

  /**
   * Restart a listener (stop then start)
   */
  async restartListener(id: string): Promise<ListenerControlResponse> {
    validateId(id, 'restartListener');
    const response = await this.api.post(`/listeners/${id}/restart`);
    return response.data;
  }

  /**
   * Get real-time statistics for a running listener
   */
  async getListenerStats(id: string): Promise<ListenerStats> {
    validateId(id, 'getListenerStats');
    const response = await this.api.get(`/listeners/${id}/stats`);
    return response.data;
  }

  // Template Operations

  /**
   * Get all available listener templates
   * BLOCKING-2 FIX: Validates API response against Zod schema
   * SECURITY: Templates come from backend storage which could be compromised
   */
  async getTemplates(): Promise<ListenerTemplate[]> {
    const response = await this.api.get('/listener-templates');

    // BLOCKING-2 FIX: Validate response data against schema
    const validated = safeValidateSchema(ListenerTemplatesArraySchema, response.data);

    if (!validated) {
      console.warn('ListenersService: Invalid template data from API, using raw data');
      // Fall back to raw data but log warning
      // This allows graceful degradation while alerting developers
      return Array.isArray(response.data) ? response.data : [];
    }

    return validated as ListenerTemplate[];
  }

  /**
   * Get a single template by ID
   */
  async getTemplate(id: string): Promise<ListenerTemplate> {
    validateId(id, 'getTemplate');
    const response = await this.api.get(`/listener-templates/${id}`);
    return response.data;
  }

  /**
   * Create a new listener from a template with optional overrides
   */
  async createFromTemplate(
    templateId: string,
    overrides?: Partial<ListenerForm>
  ): Promise<DynamicListener> {
    validateId(templateId, 'createFromTemplate');
    const response = await this.api.post(
      `/listeners/from-template/${templateId}`,
      overrides || {}
    );
    return response.data;
  }
}

export default ListenersService;
