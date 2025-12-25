import { AxiosInstance } from 'axios';
import { Alert, AlertStatus } from '../types';

class AlertsService {
  constructor(private api: AxiosInstance) {}

  async getAlerts(limit: number = 100): Promise<Alert[]> {
    const response = await this.api.get(`/alerts?page=1&limit=${limit}`);
    return response.data.items || [];
  }

  async acknowledgeAlert(alertId: string): Promise<string> {
    const response = await this.api.post(`/alerts/${alertId}/acknowledge`);
    return response.data;
  }

  async dismissAlert(alertId: string): Promise<string> {
    const response = await this.api.post(`/alerts/${alertId}/dismiss`);
    return response.data;
  }

  async deleteAlert(alertId: string): Promise<string> {
    const response = await this.api.delete(`/alerts/${alertId}`);
    return response.data;
  }

  async assignAlert(alertId: string, assignTo: string, note?: string): Promise<string> {
    const response = await this.api.put(`/alerts/${alertId}/assign`, {
      assign_to: assignTo,
      note: note,
    });
    return response.data;
  }

  async updateAlertStatus(alertId: string, status: AlertStatus, note?: string): Promise<string> {
    const response = await this.api.put(`/alerts/${alertId}/status`, {
      status: status,
      note: note,
    });
    return response.data;
  }
}

export default AlertsService;