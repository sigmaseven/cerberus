import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import Listeners from './index';
import { apiService } from '../../services/api';
import { ListenerStatus } from '../../types';

// Mock the API service
vi.mock('../../services/api', () => ({
  apiService: {
    getListeners: vi.fn(),
    subscribeToRealtimeUpdates: vi.fn(),
    unsubscribeFromRealtimeUpdates: vi.fn(),
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

describe('Listeners', () => {
  const mockListenerStatus: ListenerStatus = {
    syslog: {
      active: true,
      port: 514,
      events_per_minute: 45.2,
      errors: 0,
    },
    cef: {
      active: false,
      port: 515,
      events_per_minute: 0,
      errors: 2,
    },
    json: {
      active: true,
      port: 516,
      events_per_minute: 12.8,
      errors: 1,
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (apiService.getListeners as any).mockResolvedValue(mockListenerStatus);
  });

  it('renders listeners title', () => {
    renderWithProviders(<Listeners />);
    expect(screen.getByText('Event Listeners')).toBeInTheDocument();
  });

  it('displays loading state initially', () => {
    renderWithProviders(<Listeners />);
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  it('renders all listener cards after loading', async () => {
    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getByText('SYSLOG Listener')).toBeInTheDocument();
      expect(screen.getByText('CEF Listener')).toBeInTheDocument();
      expect(screen.getByText('JSON Listener')).toBeInTheDocument();
    });
  });

  it('displays correct status for active listeners', async () => {
    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getAllByText('Active')).toHaveLength(2); // syslog and json are active
      expect(screen.getByText('Inactive')).toBeInTheDocument(); // cef is inactive
    });
  });

  it('displays port information', async () => {
    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getByText('Port: 514')).toBeInTheDocument(); // syslog
      expect(screen.getByText('Port: 515')).toBeInTheDocument(); // cef
      expect(screen.getByText('Port: 516')).toBeInTheDocument(); // json
    });
  });

  it('displays events per minute', async () => {
    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getByText('Events/min: 45.2')).toBeInTheDocument(); // syslog
      expect(screen.getByText('Events/min: 0')).toBeInTheDocument(); // cef
      expect(screen.getByText('Events/min: 12.8')).toBeInTheDocument(); // json
    });
  });

  it('displays error counts', async () => {
    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getAllByText('Errors: 0')).toHaveLength(1); // syslog
      expect(screen.getByText('Errors: 2')).toBeInTheDocument(); // cef
      expect(screen.getByText('Errors: 1')).toBeInTheDocument(); // json
    });
  });

  it('shows error alert for listeners with errors', async () => {
    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getByText('Check logs for error details')).toBeInTheDocument();
    });
  });

  it('renders refresh and configure buttons', async () => {
    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getByText('Refresh')).toBeInTheDocument();
      expect(screen.getByText('Configure')).toBeInTheDocument();
    });
  });

  it('calls refetch when refresh button is clicked', async () => {
    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getByText('Refresh')).toBeInTheDocument();
    });

    const refreshButton = screen.getByText('Refresh');
    fireEvent.click(refreshButton);

    // The refetch function should be called (this is tested via the query client)
    expect(apiService.getListeners).toHaveBeenCalledTimes(2); // Initial load + refresh
  });

  it('opens configuration dialog when configure button is clicked', async () => {
    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getByText('Configure')).toBeInTheDocument();
    });

    const configureButton = screen.getByText('Configure');
    fireEvent.click(configureButton);

    expect(screen.getByText('Listener Configuration')).toBeInTheDocument();
    expect(screen.getByText('Close')).toBeInTheDocument();
  });

  it('closes configuration dialog when close button is clicked', async () => {
    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getByText('Configure')).toBeInTheDocument();
    });

    // Open dialog
    fireEvent.click(screen.getByText('Configure'));
    expect(screen.getByText('Listener Configuration')).toBeInTheDocument();

    // Close dialog
    fireEvent.click(screen.getByText('Close'));
    expect(screen.queryByText('Listener Configuration')).not.toBeInTheDocument();
  });

  it('subscribes to real-time listener updates on mount', () => {
    renderWithProviders(<Listeners />);

    expect(apiService.subscribeToRealtimeUpdates).toHaveBeenCalledWith({
      onListenerStatus: expect.any(Function),
    });
  });

  it('unsubscribes from real-time updates on unmount', () => {
    const { unmount } = renderWithProviders(<Listeners />);

    unmount();

    expect(apiService.unsubscribeFromRealtimeUpdates).toHaveBeenCalled();
  });

  it('handles API errors gracefully', async () => {
    (apiService.getListeners as any).mockRejectedValue(new Error('API Error'));

    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getByText('Failed to load listener status. Please check your connection and try again.')).toBeInTheDocument();
    });
  });

  it('formats events per minute correctly', async () => {
    const customStatus: ListenerStatus = {
      ...mockListenerStatus,
      syslog: { ...mockListenerStatus.syslog, events_per_minute: 0.5 },
    };
    (apiService.getListeners as any).mockResolvedValue(customStatus);

    renderWithProviders(<Listeners />);

    await waitFor(() => {
      expect(screen.getByText('Events/min: < 1')).toBeInTheDocument();
    });
  });
});