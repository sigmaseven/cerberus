import { AxiosInstance } from 'axios';
import { SearchRequest, SearchResponse, ExportRequest, SavedSearch, SavedSearchesResponse } from '../types';
import { validateSchema, SearchResponseSchema, SavedSearchesResponseSchema, SavedSearchSchema } from '../schemas/api.schemas';

class SearchService {
  private api: AxiosInstance;

  constructor(apiInstance: AxiosInstance) {
    this.api = apiInstance;
  }

  async searchEvents(request: SearchRequest): Promise<SearchResponse> {
    try {
      // Sanitize search query before sending to backend
      const sanitizedRequest = {
        ...request,
        query: this.sanitizeSearchQuery(request.query),
      };
      const response = await this.api.post('/search', sanitizedRequest);
      // SECURITY: Validate response structure
      return validateSchema(SearchResponseSchema, response.data, 'POST /search');
    } catch (error) {
      // Return empty results on validation error
      if (import.meta.env.DEV) {
        console.error('Search validation error:', error);
      }
      return {
        events: [],
        total: 0,
        page: 1,
        limit: request.limit || 50,
        execution_time_ms: 0,
        query: request.query,
        time_range: request.time_range,
      };
    }
  }

  async validateQuery(query: string): Promise<any> {
    const response = await this.api.post('/search/validate', { query: this.sanitizeSearchQuery(query) });
    return response.data;
  }

  async exportSearch(request: ExportRequest): Promise<Blob> {
    // Sanitize search query before sending to backend
    const sanitizedRequest = {
      ...request,
      query: this.sanitizeSearchQuery(request.query),
    };
    const response = await this.api.post('/search/export', sanitizedRequest, {
      responseType: 'blob',
    });
    return response.data;
  }

  // Alias for exportSearch for backward compatibility
  async exportEvents(request: ExportRequest): Promise<Blob> {
    return this.exportSearch(request);
  }

  // Saved Searches
  async getSavedSearches(): Promise<SavedSearchesResponse> {
    try {
      const response = await this.api.get('/saved-searches');
      // SECURITY: Validate response structure
      return validateSchema(SavedSearchesResponseSchema, response.data, 'GET /saved-searches');
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Get saved searches validation error:', error);
      }
      return { items: [], total: 0 };
    }
  }

  async createSavedSearch(search: Omit<SavedSearch, 'id' | 'created_at' | 'updated_at' | 'usage_count'>): Promise<SavedSearch> {
    const response = await this.api.post('/saved-searches', search);
    // SECURITY: Validate response structure
    return validateSchema(SavedSearchSchema, response.data, 'POST /saved-searches');
  }

  async deleteSavedSearch(id: string): Promise<void> {
    await this.api.delete(`/saved-searches/${id}`);
  }

  async executeSavedSearch(id: string): Promise<SearchResponse> {
    try {
      const response = await this.api.post(`/saved-searches/${id}/execute`);
      // SECURITY: Validate response structure
      return validateSchema(SearchResponseSchema, response.data, `POST /saved-searches/${id}/execute`);
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Execute saved search validation error:', error);
      }
      return {
        events: [],
        total: 0,
        page: 1,
        limit: 50,
        execution_time_ms: 0,
        query: '',
      };
    }
  }

  private sanitizeSearchQuery(query: string): string {
    // Enhanced input validation using strict allowlist approach for search queries
    // Only allow specific characters and operators that are safe for search expressions

    // First, limit query length to prevent resource exhaustion
    if (query.length > 10000) { // Reduced from 50000 for better security
      throw new Error('Search query too long (maximum 10000 characters)');
    }

    // Block obviously malicious patterns first (fail fast)
    const dangerousPatterns = [
      /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|vbscript|onload|onerror|eval|alert|confirm|prompt)\b)/gi,
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/gi,
      /vbscript:/gi,
      /data:/gi,
      /[\u0000-\u001F\u007F]/g, // Control characters
      /[;&|`$()]/g, // Command injection characters
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(query)) {
        throw new Error('Search query contains prohibited patterns that could enable injection attacks');
      }
    }

    // Strict allowlist of permitted characters:
    // - Alphanumeric characters (a-z, A-Z, 0-9)
    // - Spaces and basic punctuation: . , : - _
    // - Search operators: AND OR NOT ( )
    // - Quotes: " '
    // - Comparison operators: < > = ! (but not combined like <= >= != ==)
    // - Field separators: :
    // - Limited wildcards: * (but not ? to prevent regex injection)
    const allowedPattern = /[^a-zA-Z0-9\s.,:\-_()<>"'*!=]/g;

    const sanitized = query
      // Remove all characters not in the strict allowlist
      .replace(allowedPattern, '')
      // Remove HTML/script tags (additional check)
      .replace(/<[^>]*>/g, '')
      // Remove dangerous operator combinations
      .replace(/<=/g, '<')
      .replace(/>=/g, '>')
      .replace(/!=/g, '!')
      .replace(/==/g, '=')
      // Collapse multiple spaces
      .replace(/\s+/g, ' ')
      // Trim whitespace
      .trim();

    // Additional validation: check for suspicious patterns in the sanitized result
    const suspiciousPatterns = [
      /(\w+)\s*=\s*['"]?\s*(union|select|insert|update|delete|drop|create|alter|exec|execute)/gi,
      /['"]\s*;\s*(union|select|insert|update|delete|drop|create|alter|exec|execute)/gi,
      /\bor\b\s+\d+\s*=\s*\d+/gi, // Common tautology attacks
      /\b(\w+)\s*=\s*\1\b/gi, // Tautology attacks
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(sanitized)) {
        throw new Error('Search query contains suspicious patterns that may indicate injection attempts');
      }
    }

    // Final length check after sanitization
    if (sanitized.length === 0) {
      throw new Error('Search query is empty after sanitization');
    }

    return sanitized;
  }
}

export default SearchService;