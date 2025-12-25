import { AxiosInstance } from 'axios';
import { DashboardStats, ChartData } from '../types';

class DashboardService {
  constructor(private api: AxiosInstance) {}

  async getDashboardStats(): Promise<DashboardStats> {
    const response = await this.api.get('/dashboard');
    return response.data;
  }

  async getChartData(): Promise<ChartData[]> {
    const response = await this.api.get('/dashboard/chart');
    return response.data;
  }
}

export default DashboardService;