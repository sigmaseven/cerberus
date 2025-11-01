import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import Dashboard from './index';
import { apiService } from '../../services/api';
import { DashboardStats, ChartData } from '../../types';

// Mock the API service
vi.mock('../../services/api', () => ({
  apiService: {
    getDashboardStats: vi.fn(),
    getChartData: vi.fn(),
    subscribeToRealtimeUpdates: vi.fn(),
    unsubscribeFromRealtimeUpdates: vi.fn(),
    isWebSocketConnected: vi.fn(),
  },
}));

const createTestQueryClient = () => new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
    },
  },
});

const renderWithProviders = (component: React.ReactElement) => {
  const testQueryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={testQueryClient}>
      {component}
    </QueryClientProvider>
  );
};

describe('Dashboard', () => {
  const mockStats: DashboardStats = {
    total_events: 1000,
    active_alerts: 5,
    rules_fired: 25,
    system_health: 'OK',
  };

  const mockChartData: ChartData[] = [
    { timestamp: '2024-01-01T00:00:00Z', events: 100, alerts: 5 },
    { timestamp: '2024-01-01T01:00:00Z', events: 150, alerts: 3 },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    (apiService.getDashboardStats as any).mockResolvedValue(mockStats);
    (apiService.getChartData as any).mockResolvedValue(mockChartData);
    (apiService.isWebSocketConnected as any).mockReturnValue(true);
  });

  it('renders dashboard title', () => {
    renderWithProviders(<Dashboard />);
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
  });

  it('displays loading state initially', () => {
    renderWithProviders(<Dashboard />);
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  it('renders dashboard statistics after loading', async () => {
    renderWithProviders(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByText('Total Events')).toBeInTheDocument();
      expect(screen.getByText('Active Alerts')).toBeInTheDocument();
      expect(screen.getByText('Rules Fired')).toBeInTheDocument();
      expect(screen.getByText('System Health')).toBeInTheDocument();
    });

    expect(screen.getByText('1000')).toBeInTheDocument(); // total_events
    expect(screen.getByText('5')).toBeInTheDocument(); // active_alerts
    expect(screen.getByText('25')).toBeInTheDocument(); // rules_fired
    expect(screen.getByText('OK')).toBeInTheDocument(); // system_health
  });

  it('renders chart section', async () => {
    renderWithProviders(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByText('Events Over Time')).toBeInTheDocument();
    });
  });

  it('renders system status section', async () => {
    renderWithProviders(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByText('System Status')).toBeInTheDocument();
    });
  });

  it('shows WebSocket connection status', async () => {
    renderWithProviders(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByText('Live')).toBeInTheDocument();
    });
  });

  it('shows offline status when WebSocket disconnected', async () => {
    (apiService.isWebSocketConnected as any).mockReturnValue(false);

    renderWithProviders(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByText('Offline')).toBeInTheDocument();
    });
  });

  it('subscribes to real-time updates on mount', () => {
    renderWithProviders(<Dashboard />);

    expect(apiService.subscribeToRealtimeUpdates).toHaveBeenCalledWith({
      onDashboardStats: expect.any(Function),
      onConnect: expect.any(Function),
      onDisconnect: expect.any(Function),
    });
  });

  it('unsubscribes from real-time updates on unmount', () => {
    const { unmount } = renderWithProviders(<Dashboard />);

    unmount();

    expect(apiService.unsubscribeFromRealtimeUpdates).toHaveBeenCalled();
  });

  it('handles API errors gracefully', async () => {
    (apiService.getDashboardStats as any).mockRejectedValue(new Error('API Error'));
    (apiService.getChartData as any).mockRejectedValue(new Error('API Error'));

    renderWithProviders(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByText('Failed to load dashboard data. Please check your connection and try again.')).toBeInTheDocument();
    });
  });

  it('displays real-time stats updates', async () => {
    const { rerender } = renderWithProviders(<Dashboard />);

    // Wait for initial load
    await waitFor(() => {
      expect(screen.getByText('1000')).toBeInTheDocument();
    });

    // Simulate real-time update
    const updatedStats = { ...mockStats, total_events: 1200 };
    (apiService.getDashboardStats as any).mockResolvedValue(updatedStats);

    // Trigger a re-render (in real app this would happen via WebSocket)
    rerender(
      <QueryClientProvider client={createTestQueryClient()}>
        <Dashboard />
      </QueryClientProvider>
    );

    // The stats should update (this tests the real-time display logic)
    await waitFor(() => {
      expect(screen.getByText('1200')).toBeInTheDocument();
    });
  });
});