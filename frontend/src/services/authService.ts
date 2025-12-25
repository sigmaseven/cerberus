import { AxiosInstance } from 'axios';

class AuthService {
  constructor(private api: AxiosInstance) {}

  async login(username: string, password: string): Promise<{ message: string }> {
    const response = await this.api.post('/auth/login', { username, password });
    return response.data;
  }

  async logout(): Promise<{ message: string }> {
    const response = await this.api.post('/auth/logout');
    return response.data;
  }

  async checkAuth(): Promise<{ authenticated: boolean; username?: string; csrfToken?: string }> {
    try {
      const response = await this.api.get('/auth/status');
      return {
        authenticated: true,
        username: response.data.username,
        csrfToken: response.data.csrf_token
      };
    } catch (error) {
      return { authenticated: false };
    }
  }

  async getAuthConfig(): Promise<{ authEnabled: boolean }> {
    const response = await this.api.get('/auth/config');
    return response.data;
  }
}

export default AuthService;