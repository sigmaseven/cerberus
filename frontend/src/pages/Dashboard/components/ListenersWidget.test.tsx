import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import ListenersWidget from './ListenersWidget';
import { apiService } from '../../../services/api';

// Mock the API service
vi.mock('../../../services/api', () => ({
  apiService: {
    listeners: {
      getListeners: vi.fn(),
    },
  },
}));

const mockListeners = [
  {
    id: '1',
    name: 'Syslog Listener',
    description: 'Test syslog listener',
    type: 'syslog' as const,
    protocol: 'tcp' as const,
    host: '0.0.0.0',
    port: 514,
    tls: false,
    status: 'running' as const,
    tags: [],
    source: 'test',
    events_received: 1500,
    events_per_minute: 50,
    error_count: 2,
    created_at: '2024-01-01T00:00:00Z',
    created_by: 'admin',
    updated_at: '2024-01-01T00:00:00Z',
  },
  {
    id: '2',
    name: 'JSON Listener',
    description: 'Test JSON listener',
    type: 'json' as const,
    protocol: 'http' as const,
    host: '0.0.0.0',
    port: 8080,
    tls: false,
    status: 'stopped' as const,
    tags: [],
    source: 'test',
    events_received: 500,
    events_per_minute: 0,
    error_count: 0,
    created_at: '2024-01-01T00:00:00Z',
    created_by: 'admin',
    updated_at: '2024-01-01T00:00:00Z',
  },
  {
    id: '3',
    name: 'CEF Listener',
    description: 'Test CEF listener',
    type: 'cef' as const,
    protocol: 'udp' as const,
    host: '0.0.0.0',
    port: 5145,
    tls: false,
    status: 'error' as const,
    tags: [],
    source: 'test',
    events_received: 100,
    events_per_minute: 0,
    error_count: 10,
    created_at: '2024-01-01T00:00:00Z',
    created_by: 'admin',
    updated_at: '2024-01-01T00:00:00Z',
  },
];

function renderWidget() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
      },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ListenersWidget />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe('ListenersWidget', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render loading state initially', () => {
    vi.mocked(apiService.listeners.getListeners).mockReturnValue(
      new Promise(() => {}) // Never resolves - stays in loading
    );

    renderWidget();
    expect(screen.getByText('Listeners')).toBeInTheDocument();
  });

  it('should render listeners data after loading', async () => {
    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: mockListeners,
      total: 3,
      page: 1,
      limit: 100,
    });

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('Listeners')).toBeInTheDocument();
    });

    // Check aggregate stats are displayed
    await waitFor(() => {
      expect(screen.getByText('1 Running')).toBeInTheDocument();
    });
    expect(screen.getByText('1 Stopped')).toBeInTheDocument();
    expect(screen.getByText('1 Error')).toBeInTheDocument();
  });

  it('should show View All link to listeners page', async () => {
    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: mockListeners,
      total: 3,
      page: 1,
      limit: 100,
    });

    renderWidget();

    await waitFor(() => {
      const viewAllLink = screen.getByRole('link', { name: /view all listeners/i });
      expect(viewAllLink).toBeInTheDocument();
      expect(viewAllLink).toHaveAttribute('href', '/listeners');
    });
  });

  it('should display error state when API fails', async () => {
    vi.mocked(apiService.listeners.getListeners).mockRejectedValue(
      new Error('Network Error')
    );

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText(/failed to load listener data/i)).toBeInTheDocument();
      expect(screen.getByText(/network error/i)).toBeInTheDocument();
    });
  });

  it('should show retry button in error state', async () => {
    const mockGetListeners = vi.mocked(apiService.listeners.getListeners);
    mockGetListeners.mockRejectedValueOnce(new Error('Network Error'));

    renderWidget();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    });

    // Simulate retry
    mockGetListeners.mockResolvedValueOnce({
      items: mockListeners,
      total: 3,
      page: 1,
      limit: 100,
    });

    const retryButton = screen.getByRole('button', { name: /retry/i });
    await userEvent.click(retryButton);

    await waitFor(() => {
      expect(mockGetListeners).toHaveBeenCalledTimes(2);
    });
  });

  it('should show empty state when no listeners', async () => {
    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      limit: 100,
    });

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText(/no listeners configured/i)).toBeInTheDocument();
    });
  });

  it('should display total events received', async () => {
    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: mockListeners,
      total: 3,
      page: 1,
      limit: 100,
    });

    renderWidget();

    // Total events = 1500 + 500 + 100 = 2100
    await waitFor(() => {
      expect(screen.getByText('2,100')).toBeInTheDocument();
    });
    expect(screen.getByText('Total Events')).toBeInTheDocument();
  });

  it('should display total errors', async () => {
    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: mockListeners,
      total: 3,
      page: 1,
      limit: 100,
    });

    renderWidget();

    // Total errors = 2 + 0 + 10 = 12
    await waitFor(() => {
      expect(screen.getByText('12')).toBeInTheDocument();
    });
    expect(screen.getByText('Total Errors')).toBeInTheDocument();
  });

  it('should show health percentage', async () => {
    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: mockListeners,
      total: 3,
      page: 1,
      limit: 100,
    });

    renderWidget();

    // 1 running out of 3 = 33%
    await waitFor(() => {
      expect(screen.getByText('33%')).toBeInTheDocument();
    });
  });

  it('should display top listeners sorted by events per minute', async () => {
    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: mockListeners,
      total: 3,
      page: 1,
      limit: 100,
    });

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('Top Active Listeners')).toBeInTheDocument();
    });

    // Syslog Listener has highest events_per_minute (50)
    expect(screen.getByText('Syslog Listener')).toBeInTheDocument();
  });

  // Edge case tests

  it('should handle all listeners in error state (health = 0%)', async () => {
    const allErrorListeners = [
      { ...mockListeners[0], status: 'error' as const },
      { ...mockListeners[1], status: 'error' as const },
      { ...mockListeners[2], status: 'error' as const },
    ];

    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: allErrorListeners,
      total: 3,
      page: 1,
      limit: 100,
    });

    renderWidget();

    // 0 running out of 3 = 0%
    await waitFor(() => {
      expect(screen.getByText('0%')).toBeInTheDocument();
    });
    expect(screen.getByText('3 Error')).toBeInTheDocument();
  });

  it('should handle all listeners running (health = 100%)', async () => {
    const allRunningListeners = [
      { ...mockListeners[0], status: 'running' as const },
      { ...mockListeners[1], status: 'running' as const },
      { ...mockListeners[2], status: 'running' as const },
    ];

    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: allRunningListeners,
      total: 3,
      page: 1,
      limit: 100,
    });

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('100%')).toBeInTheDocument();
    });
    expect(screen.getByText('3 Running')).toBeInTheDocument();
  });

  it('should sanitize invalid numeric values (null/undefined)', async () => {
    const invalidListeners = [
      {
        ...mockListeners[0],
        events_received: null as unknown as number,
        events_per_minute: undefined as unknown as number,
        error_count: null as unknown as number,
      },
    ];

    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: invalidListeners,
      total: 1,
      page: 1,
      limit: 100,
    });

    renderWidget();

    // Should not crash and should show 0 for invalid values
    await waitFor(() => {
      expect(screen.getByText('0')).toBeInTheDocument(); // Total Events
    });
  });

  it('should sanitize negative numeric values', async () => {
    const negativeListeners = [
      {
        ...mockListeners[0],
        events_received: -100,
        events_per_minute: -50,
        error_count: -10,
      },
    ];

    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: negativeListeners,
      total: 1,
      page: 1,
      limit: 100,
    });

    renderWidget();

    // Negative values should be treated as 0
    await waitFor(() => {
      expect(screen.getByText('0')).toBeInTheDocument();
    });
  });

  it('should sanitize NaN values', async () => {
    const nanListeners = [
      {
        ...mockListeners[0],
        events_received: NaN,
        events_per_minute: NaN,
        error_count: NaN,
      },
    ];

    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: nanListeners,
      total: 1,
      page: 1,
      limit: 100,
    });

    renderWidget();

    // NaN values should be treated as 0
    await waitFor(() => {
      expect(screen.getByText('0')).toBeInTheDocument();
    });
  });

  it('should handle unknown listener statuses gracefully', async () => {
    const unknownStatusListeners = [
      {
        ...mockListeners[0],
        status: 'unknown_status' as 'running', // Type hack to test runtime handling
      },
    ];

    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: unknownStatusListeners,
      total: 1,
      page: 1,
      limit: 100,
    });

    renderWidget();

    // Should not crash and should display the status
    await waitFor(() => {
      expect(screen.getByText('unknown_status')).toBeInTheDocument();
    });
  });

  it('should handle API returning malformed data (null items)', async () => {
    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: null as unknown as never[],
      total: 0,
      page: 1,
      limit: 100,
    });

    renderWidget();

    // Should show empty state instead of crashing
    await waitFor(() => {
      expect(screen.getByText(/no listeners configured/i)).toBeInTheDocument();
    });
  });

  it('should have accessible labels', async () => {
    vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
      items: mockListeners,
      total: 3,
      page: 1,
      limit: 100,
    });

    renderWidget();

    await waitFor(() => {
      // Check health bar has aria-label
      const healthBar = screen.getByRole('progressbar');
      expect(healthBar).toHaveAttribute('aria-label');
      expect(healthBar.getAttribute('aria-label')).toContain('Listener health');
    });
  });
});
