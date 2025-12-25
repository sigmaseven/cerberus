import { AxiosInstance } from 'axios';
import { Rule, CorrelationRule, ParsedEvents, TestRuleRequest, TestRuleResponse } from '../types';

class RulesService {
  constructor(private api: AxiosInstance) {}

  // Rules
  async getRules(limit: number = 100): Promise<Rule[]> {
    const response = await this.api.get(`/rules?page=1&limit=${limit}`);
    return response.data.items || [];
  }

  async createRule(rule: Omit<Rule, 'id'>): Promise<Rule> {
    const response = await this.api.post('/rules', rule);
    return response.data;
  }

  async getRule(id: string): Promise<Rule> {
    const response = await this.api.get(`/rules/${id}`);
    return response.data;
  }

  async updateRule(id: string, rule: Partial<Rule>): Promise<Rule> {
    const response = await this.api.put(`/rules/${id}`, rule);
    return response.data;
  }

  async deleteRule(id: string): Promise<string> {
    const response = await this.api.delete(`/rules/${id}`);
    return response.data;
  }

  // Correlation Rules
  async getCorrelationRules(limit: number = 100): Promise<CorrelationRule[]> {
    const response = await this.api.get(`/correlation-rules?page=1&limit=${limit}`);
    // Backend returns array directly, not paginated response
    return Array.isArray(response.data) ? response.data : [];
  }

  async createCorrelationRule(rule: Omit<CorrelationRule, 'id'>): Promise<CorrelationRule> {
    const response = await this.api.post('/correlation-rules', rule);
    return response.data;
  }

  async getCorrelationRule(id: string): Promise<CorrelationRule> {
    const response = await this.api.get(`/correlation-rules/${id}`);
    return response.data;
  }

  async updateCorrelationRule(id: string, rule: Partial<CorrelationRule>): Promise<CorrelationRule> {
    const response = await this.api.put(`/correlation-rules/${id}`, rule);
    return response.data;
  }

  async deleteCorrelationRule(id: string): Promise<string> {
    const response = await this.api.delete(`/correlation-rules/${id}`);
    return response.data;
  }

  // Import/Export for Rules
  async exportRules(format: 'json' | 'yaml' = 'json', ids?: string[]): Promise<Blob> {
    const params = new URLSearchParams();
    params.append('format', format);
    if (ids && ids.length > 0) {
      ids.forEach(id => params.append('ids', id));
    }
    const response = await this.api.get(`/rules/export?${params.toString()}`, {
      responseType: 'blob',
    });

    // Validate that we got the expected content type, not an error response
    const contentType = response.headers['content-type'];
    const expectedType = format === 'yaml' ? 'application/yaml' : 'application/json';

    if (!contentType || !contentType.includes(expectedType)) {
      // Blob might contain error response - try to read it
      const text = await response.data.text();
      throw new Error(`Export failed: ${text}`);
    }

    return response.data;
  }

  async importRules(file: File, conflictResolution: 'skip' | 'overwrite' | 'merge' = 'overwrite'): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('conflict_resolution', conflictResolution);
    // Don't manually set Content-Type - let axios set it with proper boundary parameter
    const response = await this.api.post('/rules/import', formData);
    return response.data;
  }

  // Import/Export for Correlation Rules
  async exportCorrelationRules(format: 'json' | 'yaml' = 'json', ids?: string[]): Promise<Blob> {
    const params = new URLSearchParams();
    params.append('format', format);
    if (ids && ids.length > 0) {
      ids.forEach(id => params.append('ids', id));
    }
    const response = await this.api.get(`/correlation-rules/export?${params.toString()}`, {
      responseType: 'blob',
    });

    // Validate that we got the expected content type, not an error response
    const contentType = response.headers['content-type'];
    const expectedType = format === 'yaml' ? 'application/yaml' : 'application/json';

    if (!contentType || !contentType.includes(expectedType)) {
      // Blob might contain error response - try to read it
      const text = await response.data.text();
      throw new Error(`Export failed: ${text}`);
    }

    return response.data;
  }

  async importCorrelationRules(file: File, conflictResolution: 'skip' | 'overwrite' | 'merge' = 'overwrite'): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('conflict_resolution', conflictResolution);
    // Don't manually set Content-Type - let axios set it with proper boundary parameter
    const response = await this.api.post('/correlation-rules/import', formData);
    return response.data;
  }

  // Rule Testing
  async uploadSampleEvents(file: File): Promise<ParsedEvents> {
    const formData = new FormData();
    formData.append('file', file);
    // Don't manually set Content-Type - let axios set it with proper boundary parameter
    const response = await this.api.post('/rules/test/upload', formData);
    return response.data;
  }

  async testRule(request: TestRuleRequest): Promise<TestRuleResponse> {
    const response = await this.api.post('/rules/test', request);
    return response.data;
  }
}

export default RulesService;