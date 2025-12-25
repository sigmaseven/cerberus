/**
 * Feed Management Service (TASK 155.2)
 * Provides API methods for managing SIGMA rule feeds
 */

import { AxiosInstance } from 'axios';
import {
  Feed,
  FeedForm,
  FeedSyncResult,
  FeedsSummary,
  FeedTemplate,
  FeedTestResult,
  PaginationResponse,
} from '../types';
import { FeedTemplatesArraySchema, FeedsArraySchema, safeValidateSchema } from '../schemas/api.schemas';

class FeedsService {
  private api: AxiosInstance;

  constructor(apiInstance: AxiosInstance) {
    this.api = apiInstance;
  }

  // ==========================================================================
  // CRUD Operations
  // ==========================================================================

  /**
   * Get all feeds with pagination
   */
  async getFeeds(page = 1, limit = 50): Promise<PaginationResponse<Feed>> {
    const response = await this.api.get('/feeds', {
      params: { page, limit },
    });
    return response.data;
  }

  /**
   * Get a single feed by ID
   */
  async getFeed(id: string): Promise<Feed> {
    const response = await this.api.get(`/feeds/${id}`);
    return response.data;
  }

  /**
   * Create a new feed
   */
  async createFeed(feed: FeedForm): Promise<Feed> {
    const response = await this.api.post('/feeds', feed);
    return response.data;
  }

  /**
   * Update an existing feed
   */
  async updateFeed(id: string, updates: Partial<FeedForm>): Promise<Feed> {
    const response = await this.api.put(`/feeds/${id}`, updates);
    return response.data;
  }

  /**
   * Delete a feed
   */
  async deleteFeed(id: string): Promise<void> {
    await this.api.delete(`/feeds/${id}`);
  }

  // ==========================================================================
  // Sync Operations
  // ==========================================================================

  /**
   * Sync a single feed (fetch and import rules)
   */
  async syncFeed(id: string): Promise<FeedSyncResult> {
    const response = await this.api.post(`/feeds/${id}/sync`);
    return response.data;
  }

  /**
   * Sync all enabled feeds
   */
  async syncAllFeeds(): Promise<FeedSyncResult[]> {
    const response = await this.api.post('/feeds/sync-all');
    return response.data;
  }

  /**
   * Get sync history for a feed
   */
  async getFeedHistory(
    id: string,
    limit = 10
  ): Promise<FeedSyncResult[]> {
    const response = await this.api.get(`/feeds/${id}/history`, {
      params: { limit },
    });
    return response.data;
  }

  // ==========================================================================
  // Control Operations
  // ==========================================================================

  /**
   * Enable a feed (starts auto-syncing if configured)
   */
  async enableFeed(id: string): Promise<void> {
    await this.api.post(`/feeds/${id}/enable`);
  }

  /**
   * Disable a feed (stops auto-syncing)
   */
  async disableFeed(id: string): Promise<void> {
    await this.api.post(`/feeds/${id}/disable`);
  }

  /**
   * Test feed connectivity and configuration
   */
  async testFeed(id: string): Promise<FeedTestResult> {
    const response = await this.api.post(`/feeds/${id}/test`);
    return response.data;
  }

  // ==========================================================================
  // Template Operations
  // ==========================================================================

  /**
   * Get all available feed templates
   * SECURITY: Validates API response against Zod schema
   */
  async getTemplates(): Promise<FeedTemplate[]> {
    const response = await this.api.get('/feeds/templates');

    // Validate response data against schema
    const validated = safeValidateSchema(FeedTemplatesArraySchema, response.data);

    if (!validated) {
      console.warn('FeedsService: Invalid template data from API, using raw data');
      return Array.isArray(response.data) ? response.data : [];
    }

    return validated as FeedTemplate[];
  }

  // ==========================================================================
  // Stats Operations
  // ==========================================================================

  /**
   * Get aggregate statistics for a feed
   */
  async getFeedStats(id: string): Promise<Feed['stats']> {
    const response = await this.api.get(`/feeds/${id}/stats`);
    return response.data;
  }

  /**
   * Get summary statistics for all feeds (TASK 157.2)
   * Used by the dashboard FeedStatsWidget
   */
  async getFeedsSummary(): Promise<FeedsSummary> {
    const response = await this.api.get('/feeds/summary');
    return response.data;
  }

  // ==========================================================================
  // Batch Operations
  // ==========================================================================

  /**
   * Delete multiple feeds at once
   */
  async deleteFeeds(ids: string[]): Promise<void> {
    await Promise.all(ids.map((id) => this.deleteFeed(id)));
  }

  /**
   * Enable multiple feeds at once
   */
  async enableFeeds(ids: string[]): Promise<void> {
    await Promise.all(ids.map((id) => this.enableFeed(id)));
  }

  /**
   * Disable multiple feeds at once
   */
  async disableFeeds(ids: string[]): Promise<void> {
    await Promise.all(ids.map((id) => this.disableFeed(id)));
  }
}

export default FeedsService;
