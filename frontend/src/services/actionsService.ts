import { AxiosInstance } from 'axios';
import { Action } from '../types';

class ActionsService {
  private api: AxiosInstance;

  constructor(apiInstance: AxiosInstance) {
    this.api = apiInstance;
  }

  async getActions(): Promise<Action[]> {
    const response = await this.api.get('/actions');
    return response.data.items || response.data;
  }

  async createAction(action: Omit<Action, 'id'>): Promise<Action> {
    const response = await this.api.post('/actions', action);
    return response.data;
  }

  async getAction(id: string): Promise<Action> {
    const response = await this.api.get(`/actions/${id}`);
    return response.data;
  }

  async updateAction(id: string, action: Partial<Action>): Promise<Action> {
    const response = await this.api.put(`/actions/${id}`, action);
    return response.data;
  }

  async deleteAction(id: string): Promise<string> {
    const response = await this.api.delete(`/actions/${id}`);
    return response.data;
  }
}

export default ActionsService;