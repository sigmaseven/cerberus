import { AxiosInstance } from 'axios';
import { MLStatus, MLHealth } from '../types';

class MLService {
  private api: AxiosInstance;

  constructor(apiInstance: AxiosInstance) {
    this.api = apiInstance;
  }

  async getMLStatus(): Promise<MLStatus> {
    const response = await this.api.get('/ml/status');
    return response.data;
  }

  async getMLHealth(): Promise<MLHealth> {
    const response = await this.api.get('/ml/health');
    return response.data;
  }

  async getMLPerformanceHistory(): Promise<MLStatus['performance_history']> {
    const response = await this.api.get('/ml/performance');
    return response.data;
  }

  async forceMLTraining(): Promise<{ message: string }> {
    const response = await this.api.post('/ml/train');
    return response.data;
  }

  async updateMLConfig(config: {
    enabled: boolean;
    batch_size: number;
    training_interval: string;
    retrain_threshold: number;
    validation_ratio: number;
    enable_continuous: boolean;
    drift_detection: boolean;
    min_confidence: number;
    algorithms: string[];
    voting_strategy: string;
  }): Promise<{ message: string }> {
    const response = await this.api.put('/ml/config', config);
    return response.data;
  }
}

export default MLService;