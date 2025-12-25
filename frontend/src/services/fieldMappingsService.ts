import { AxiosInstance } from 'axios';
import {
  FieldMapping,
  FieldMappingForm,
  TestMappingRequest,
  TestMappingResponse,
  FieldDiscoveryResponse,
} from '../types';

class FieldMappingsService {
  constructor(private api: AxiosInstance) {}

  // List all field mappings
  async getFieldMappings(): Promise<FieldMapping[]> {
    const response = await this.api.get('/settings/field-mappings');
    return response.data || [];
  }

  // Get a specific field mapping by ID or name
  async getFieldMapping(idOrName: string): Promise<FieldMapping> {
    const response = await this.api.get(`/settings/field-mappings/${idOrName}`);
    return response.data;
  }

  // Create a new field mapping
  async createFieldMapping(mapping: FieldMappingForm): Promise<FieldMapping> {
    const response = await this.api.post('/settings/field-mappings', mapping);
    return response.data;
  }

  // Update an existing field mapping
  async updateFieldMapping(id: string, mapping: Partial<FieldMappingForm>): Promise<FieldMapping> {
    const response = await this.api.put(`/settings/field-mappings/${id}`, mapping);
    return response.data;
  }

  // Delete a field mapping
  async deleteFieldMapping(id: string): Promise<void> {
    await this.api.delete(`/settings/field-mappings/${id}`);
  }

  // Reload field mappings from YAML file
  async reloadFieldMappings(): Promise<{ message: string }> {
    const response = await this.api.post('/settings/field-mappings/reload');
    return response.data;
  }

  // Test field mapping against a sample log
  async testFieldMapping(request: TestMappingRequest): Promise<TestMappingResponse> {
    const response = await this.api.post('/settings/field-mappings/test', request);
    return response.data;
  }

  // Discover field mappings from sample log
  async discoverFields(sampleLog: Record<string, any>): Promise<FieldDiscoveryResponse> {
    const response = await this.api.post('/settings/field-mappings/discover', sampleLog);
    return response.data;
  }
}

export default FieldMappingsService;
