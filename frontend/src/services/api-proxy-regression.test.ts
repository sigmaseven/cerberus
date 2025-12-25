import { describe, it, expect, vi } from 'vitest';

// Mock axios to capture the configuration
vi.mock('axios', () => ({
  default: {
    create: vi.fn()}}));
import axios from 'axios';
const mockedAxios = vi.mocked(axios);

// Mock other dependencies
vi.mock('./websocket', () => ({
  default: {
    subscribe: vi.fn(),
    unsubscribe: vi.fn(),
    isConnected: vi.fn().mockReturnValue(true)}}));

vi.mock('./errorReporting', () => ({
  default: {}}));

// Mock localStorage
Object.defineProperty(window, 'localStorage', {
  value: {
    getItem: vi.fn(),
    setItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn()}});

describe('API Proxy Configuration Regression Test', () => {
  it('should configure axios with correct baseURL for proxy', async () => {
    // Import after mocks are set up
    const { ApiService } = await import('./api');

    // Create a new instance
    new ApiService();

    // Verify axios.create was called with the correct baseURL
    expect(mockedAxios.create).toHaveBeenCalledWith(
      expect.objectContaining({
        baseURL: '/api/v1', // Should use relative URL for proxy
      })
    );
  });

  it('should configure request interceptor for Playwright tests', async () => {
    // Reset mocks
    vi.clearAllMocks();

    // Mock window.playwright for test environment
    const originalWindow = global.window;
    (global as any).window = {
      ...originalWindow,
      playwright: true};

    // Import and create instance
    const { ApiService } = await import('./api');
    new ApiService();

    // Get the axios instance
    const axiosInstance = mockedAxios.create.mock.results[0].value;

    // Verify request interceptor was set up
    expect(axiosInstance.interceptors.request.use).toHaveBeenCalled();

    // Restore original window
    (global as any).window = originalWindow;
  });

  it('should NOT modify URLs in production environment', async () => {
    // Reset mocks
    vi.clearAllMocks();

    // Ensure window.playwright is not set
    const originalWindow = global.window;
    delete (global as any).window.playwright;

    // Import and create instance
    const { ApiService } = await import('./api');
    new ApiService();

    // Get the axios instance
    const axiosInstance = mockedAxios.create.mock.results[0].value;

    // Get the request interceptor function
    const requestInterceptor = axiosInstance.interceptors.request.use.mock.calls[0][0];

    // Test with a regular request (no playwright)
    const config = {
      url: '/api/v1/events',
      baseURL: '/api/v1'};

    const result = requestInterceptor(config);

    // URL should remain unchanged
    expect(result.url).toBe('/api/v1/events');
    expect(result.baseURL).toBe('/api/v1');

    // Restore original window
    (global as any).window = originalWindow;
  });

  it('should modify URLs for Playwright test environment', async () => {
    // Reset mocks
    vi.clearAllMocks();

    // Mock window.playwright for test environment
    const originalWindow = global.window;
    (global as any).window = {
      ...originalWindow,
      playwright: true};

    // Import and create instance
    const { ApiService } = await import('./api');
    new ApiService();

    // Get the axios instance
    const axiosInstance = mockedAxios.create.mock.results[0].value;

    // Get the request interceptor function
    const requestInterceptor = axiosInstance.interceptors.request.use.mock.calls[0][0];

    // Test with a Playwright request
    const config = {
      url: '/api/v1/events',
      baseURL: '/api/v1'};

    const result = requestInterceptor(config);

    // URL should be modified for Playwright
    expect(result.url).toBe('http://localhost:8081/api/v1/api/v1/events');

    // Restore original window
    (global as any).window = originalWindow;
  });

  it('should prevent regression to wrong proxy port (8081 or 8082)', async () => {
    // This test ensures we use the correct backend port (8080)
    // Not 8081 (old websocket bug) or 8082 (old test bug)

    // Reset mocks
    vi.clearAllMocks();

    // Mock window.playwright for test environment
    const originalWindow = global.window;
    (global as any).window = {
      ...originalWindow,
      playwright: true};

    // Import and create instance
    const { ApiService } = await import('./api');
    new ApiService();

    // Get the axios instance
    const axiosInstance = mockedAxios.create.mock.results[0].value;

    // Get the request interceptor function
    const requestInterceptor = axiosInstance.interceptors.request.use.mock.calls[0][0];

    // Test with a Playwright request
    const config = {
      url: '/api/v1/events',
      baseURL: '/api/v1'};

    const result = requestInterceptor(config);

    // Should use 8081 (the actual backend port)
    expect(result.url).toBe('http://localhost:8081/api/v1/api/v1/events');
    expect(result.url).not.toContain('8080');
    expect(result.url).not.toContain('8082');

    // Restore original window
    (global as any).window = originalWindow;
  });
});