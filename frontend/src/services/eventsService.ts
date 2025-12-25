import { AxiosInstance } from 'axios';
import { Event, PaginationResponse } from '../types';
import { EventsPage } from '../schemas/api.schemas';

class EventsService {
  constructor(private api: AxiosInstance) {}

  /**
   * Get events using offset-based pagination (legacy)
   */
  async getEvents(limit: number = 100, page: number = 1): Promise<PaginationResponse<Event>> {
    const response = await this.api.get(`/events?page=${page}&limit=${limit}`);
    return response.data;
  }

  /**
   * Get events using cursor-based pagination
   * @param cursor - Optional cursor for next page
   * @param limit - Number of events per page
   * @returns EventsPage with cursor for next page
   */
  async getEventsPage(cursor?: string, limit: number = 50): Promise<EventsPage> {
    const params = new URLSearchParams({ limit: limit.toString() });
    if (cursor) {
      params.append('cursor', cursor);
    }
    const response = await this.api.get(`/events/cursor?${params.toString()}`);
    return response.data;
  }
}

export default EventsService;