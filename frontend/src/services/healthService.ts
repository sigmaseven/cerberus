class HealthService {
  private api: any; // We'll inject the axios instance

  constructor(apiInstance: any) {
    this.api = apiInstance;
  }

  async getHealth(): Promise<{ status: string }> {
    const response = await this.api.get('/health');
    return response.data;
  }
}

export default HealthService;