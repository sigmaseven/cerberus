import { AxiosInstance } from 'axios';
import type {
  Investigation,
  InvestigationStatus,
  InvestigationPriority,
  InvestigationVerdict,
  InvestigationNote,
  MLFeedback,
} from '../types';

export interface CreateInvestigationRequest {
  title: string;
  description: string;
  priority: InvestigationPriority;
  assignee_id?: string;
  alert_ids?: string[];
  mitre_tactics?: string[];
  mitre_techniques?: string[];
}

export interface UpdateInvestigationRequest {
  title?: string;
  description?: string;
  priority?: InvestigationPriority;
  status?: InvestigationStatus;
  assignee_id?: string;
}

export interface CloseInvestigationRequest {
  verdict: InvestigationVerdict;
  resolution_category: string;
  summary: string;
  affected_assets?: string[];
  ml_feedback?: MLFeedback;
}

export interface AddNoteRequest {
  content: string;
}

export interface AddAlertRequest {
  alert_id: string;
}

export interface InvestigationFilters {
  status?: InvestigationStatus;
  priority?: InvestigationPriority;
  assignee_id?: string;
  limit?: number;
  offset?: number;
}

export interface InvestigationListResponse {
  investigations: Investigation[];
  total: number;
  limit: number;
  offset: number;
}

export interface TimelineEvent {
  type: 'alert' | 'note';
  timestamp: string;
  data: any;
}

export interface InvestigationTimelineResponse {
  events: TimelineEvent[];
}

/**
 * Investigation service for managing security investigations
 */
class InvestigationsService {
  constructor(private api: AxiosInstance) {}

  /**
   * Get list of investigations with optional filters
   */
  async getInvestigations(filters?: InvestigationFilters): Promise<InvestigationListResponse> {
    const params = new URLSearchParams();

    if (filters?.status) params.append('status', filters.status);
    if (filters?.priority) params.append('priority', filters.priority);
    if (filters?.assignee_id) params.append('assignee_id', filters.assignee_id);
    if (filters?.limit) params.append('limit', filters.limit.toString());
    if (filters?.offset) params.append('offset', filters.offset.toString());

    const response = await this.api.get(`/investigations?${params.toString()}`);

    // Backend returns paginated response with 'items', map to 'investigations' for frontend
    const data = response.data;
    return {
      investigations: data.items || [],
      total: data.total || 0,
      limit: data.limit || filters?.limit || 25,
      offset: filters?.offset || 0,
    };
  }

  /**
   * Get a single investigation by ID
   */
  async getInvestigation(id: string): Promise<Investigation> {
    const response = await this.api.get(`/investigations/${id}`);
    return response.data;
  }

  /**
   * Create a new investigation
   */
  async createInvestigation(data: CreateInvestigationRequest): Promise<Investigation> {
    const response = await this.api.post('/investigations', data);
    return response.data;
  }

  /**
   * Update an existing investigation
   */
  async updateInvestigation(id: string, data: UpdateInvestigationRequest): Promise<Investigation> {
    const response = await this.api.put(`/investigations/${id}`, data);
    return response.data;
  }

  /**
   * Delete an investigation
   */
  async deleteInvestigation(id: string): Promise<void> {
    await this.api.delete(`/investigations/${id}`);
  }

  /**
   * Close an investigation with verdict and summary
   */
  async closeInvestigation(id: string, data: CloseInvestigationRequest): Promise<Investigation> {
    const response = await this.api.post(`/investigations/${id}/close`, data);
    return response.data;
  }

  /**
   * Add a note to an investigation
   */
  async addNote(id: string, content: string): Promise<Investigation> {
    const response = await this.api.post(`/investigations/${id}/notes`, { content });
    return response.data;
  }

  /**
   * Add an alert to an investigation
   */
  async addAlert(id: string, alertId: string): Promise<Investigation> {
    const response = await this.api.post(`/investigations/${id}/alerts`, { alert_id: alertId });
    return response.data;
  }

  /**
   * Get timeline of events for an investigation
   */
  async getTimeline(id: string): Promise<InvestigationTimelineResponse> {
    const response = await this.api.get(`/investigations/${id}/timeline`);
    return response.data;
  }

  /**
   * Get investigations assigned to current user
   */
  async getMyInvestigations(limit = 50, offset = 0): Promise<InvestigationListResponse> {
    // This will need the user ID from auth context
    // For now, we'll let the backend filter based on the JWT token
    const params = new URLSearchParams({
      limit: limit.toString(),
      offset: offset.toString(),
    });

    const response = await this.api.get(`/investigations/my?${params.toString()}`);

    // Backend returns paginated response with 'items', map to 'investigations' for frontend
    const data = response.data;
    return {
      investigations: data.items || [],
      total: data.total || 0,
      limit: data.limit || limit,
      offset: offset,
    };
  }

  /**
   * Get investigation statistics
   */
  async getStatistics(): Promise<{
    total: number;
    by_status: Record<InvestigationStatus, number>;
    by_priority: Record<InvestigationPriority, number>;
    open_count: number;
    closed_count: number;
    avg_resolution_time_hours: number;
  }> {
    const response = await this.api.get('/investigations/statistics');
    return response.data;
  }
}

export default InvestigationsService;
