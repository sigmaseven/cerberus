import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import Listeners from './index';
import { apiService } from '../../services/api';
import type { DynamicListener, PaginationResponse } from '../../types';

// Mock the API service
vi.mock('../../services/api', () => ({
  apiService: {
    listeners: {
      getListeners: vi.fn(),
      createListener: vi.fn(),
      updateListener: vi.fn(),
      deleteListener: vi.fn(),
      startListener: vi.fn(),
      stopListener: vi.fn(),
      restartListener: vi.fn(),
      getTemplates: vi.fn(),
    },
    subscribeToRealtimeUpdates: vi.fn(),
    unsubscribeFromRealtimeUpdates: vi.fn(),
  },
}));

// Mock sanitize utility (returns input for testing)
vi.mock('../../utils/sanitize', () => ({
  escapeHTML: (str: string) => str,
}));

// Mock severity utility
vi.mock('../../utils/severity', () => ({
  POLLING_INTERVALS: {
    LISTENERS: 5000,
  },
  LIMITS: {
    API_TIMEOUT: 30000,
  },
}));

// Mock SectionErrorBoundary
vi.mock('../../components/SectionErrorBoundary', () => ({
  SectionErrorBoundary: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

const createTestQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
      },
    },
  });

const renderWithProviders = (component: React.ReactElement) => {
  const testQueryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={testQueryClient}>{component}</QueryClientProvider>
  );
};

// Mock listener factory
const createMockListener = (overrides: Partial<DynamicListener> = {}): DynamicListener => ({
  id: 'listener-1',
  name: 'Test Syslog Listener',
  description: 'Test listener for syslog events',
  type: 'syslog',
  protocol: 'tcp',
  host: '0.0.0.0',
  port: 514,
  tls: false,
  status: 'running',
  tags: ['production', 'security'],
  source: 'network-devices',
  events_received: 12500,
  events_per_minute: 45.2,
  error_count: 0,
  created_at: '2024-01-15T10:00:00Z',
  created_by: 'admin',
  updated_at: '2024-01-15T10:00:00Z',
  started_at: '2024-01-15T10:00:00Z',
  ...overrides,
});

// Mock paginated response factory
const createMockPaginatedResponse = (
  listeners: DynamicListener[],
  total?: number
): PaginationResponse<DynamicListener> => ({
  items: listeners,
  total: total ?? listeners.length,
  page: 1,
  limit: 12,
});

describe('Listeners Page', () => {
  const mockRunningListener = createMockListener({
    id: 'listener-running',
    name: 'Running Syslog Listener',
    status: 'running',
    events_received: 12500,
    events_per_minute: 45.2,
    error_count: 0,
  });

  const mockStoppedListener = createMockListener({
    id: 'listener-stopped',
    name: 'Stopped CEF Listener',
    type: 'cef',
    status: 'stopped',
    port: 515,
    events_received: 0,
    events_per_minute: 0,
    error_count: 0,
    started_at: undefined,
  });

  const mockErrorListener = createMockListener({
    id: 'listener-error',
    name: 'Error JSON Listener',
    type: 'json',
    status: 'error',
    port: 516,
    events_received: 5000,
    events_per_minute: 12.8,
    error_count: 5,
  });

  const mockPaginatedResponse = createMockPaginatedResponse([
    mockRunningListener,
    mockStoppedListener,
    mockErrorListener,
  ]);

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiService.listeners.getListeners).mockResolvedValue(mockPaginatedResponse);
    vi.mocked(apiService.listeners.getTemplates).mockResolvedValue([]);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Page Rendering', () => {
    it('renders listeners title', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Event Listeners')).toBeInTheDocument();
      });
    });

    it('displays loading skeleton initially', () => {
      renderWithProviders(<Listeners />);
      // Skeleton creates progressbar accessibility role
      expect(screen.getAllByRole('progressbar').length).toBeGreaterThan(0);
    });

    it('renders all listener cards after loading', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
        expect(screen.getByText('Error JSON Listener')).toBeInTheDocument();
      });
    });

    it('displays correct status chips', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        const runningChips = screen.getAllByText('running');
        const stoppedChips = screen.getAllByText('stopped');
        const errorChips = screen.getAllByText('error');

        expect(runningChips).toHaveLength(1);
        expect(stoppedChips).toHaveLength(1);
        expect(errorChips).toHaveLength(1);
      });
    });

    it('displays listener type and protocol', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('SYSLOG / TCP')).toBeInTheDocument();
        expect(screen.getByText('CEF / TCP')).toBeInTheDocument();
        expect(screen.getByText('JSON / TCP')).toBeInTheDocument();
      });
    });

    it('displays host and port information', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('0.0.0.0:514')).toBeInTheDocument();
        expect(screen.getByText('0.0.0.0:515')).toBeInTheDocument();
        expect(screen.getByText('0.0.0.0:516')).toBeInTheDocument();
      });
    });

    it('displays events statistics', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText(/Events:.*12,500/)).toBeInTheDocument();
        expect(screen.getByText(/Rate:.*45.2\/min/)).toBeInTheDocument();
      });
    });

    it('displays error count when non-zero', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText(/Errors:.*5/)).toBeInTheDocument();
      });
    });

    it('displays tags on listener cards', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('production')).toBeInTheDocument();
        expect(screen.getByText('security')).toBeInTheDocument();
      });
    });

    it('displays status summary chips', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('1 Running')).toBeInTheDocument();
        expect(screen.getByText('1 Stopped')).toBeInTheDocument();
        expect(screen.getByText('1 Errors')).toBeInTheDocument();
      });
    });
  });

  describe('Header Actions', () => {
    it('renders refresh and new listener buttons', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /refresh/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /new listener/i })).toBeInTheDocument();
      });
    });

    it('calls refetch when refresh button is clicked', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /refresh/i })).toBeInTheDocument();
      });

      const refreshButton = screen.getByRole('button', { name: /refresh/i });
      await userEvent.click(refreshButton);

      expect(apiService.listeners.getListeners).toHaveBeenCalledTimes(2);
    });

    it('opens create dialog when new listener button is clicked', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /new listener/i })).toBeInTheDocument();
      });

      await userEvent.click(screen.getByRole('button', { name: /new listener/i }));

      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(screen.getByText('Create New Listener')).toBeInTheDocument();
    });
  });

  describe('Search/Filter', () => {
    it('renders search input with helper text', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        const searchInput = screen.getByLabelText(/filter listeners/i);
        expect(searchInput).toBeInTheDocument();
        expect(screen.getByText(/filters the current page only/i)).toBeInTheDocument();
      });
    });

    it('filters listeners by name (client-side)', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const searchInput = screen.getByLabelText(/filter listeners/i);
      await userEvent.type(searchInput, 'CEF');

      await waitFor(() => {
        expect(screen.queryByText('Running Syslog Listener')).not.toBeInTheDocument();
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
        expect(screen.queryByText('Error JSON Listener')).not.toBeInTheDocument();
      });
    });

    it('shows empty state when no listeners match search', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const searchInput = screen.getByLabelText(/filter listeners/i);
      await userEvent.type(searchInput, 'nonexistent');

      await waitFor(() => {
        expect(screen.getByText(/no listeners match your search/i)).toBeInTheDocument();
      });
    });
  });

  describe('Listener Control Operations', () => {
    it('shows start button for stopped listeners', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
      });

      // Find the stopped listener card and check for start button
      const stoppedCard = screen.getByText('Stopped CEF Listener').closest('[role="listitem"]');
      expect(stoppedCard).toBeInTheDocument();

      const startButton = within(stoppedCard!).getByRole('button', { name: /start listener/i });
      expect(startButton).toBeInTheDocument();
    });

    it('shows stop and restart buttons for running listeners', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const runningCard = screen.getByText('Running Syslog Listener').closest('[role="listitem"]');
      expect(runningCard).toBeInTheDocument();

      const stopButton = within(runningCard!).getByRole('button', { name: /stop listener/i });
      const restartButton = within(runningCard!).getByRole('button', { name: /restart listener/i });

      expect(stopButton).toBeInTheDocument();
      expect(restartButton).toBeInTheDocument();
    });

    it('calls startListener when start button is clicked', async () => {
      vi.mocked(apiService.listeners.startListener).mockResolvedValue({
        status: 'success',
        message: 'Listener started',
      });

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
      });

      const stoppedCard = screen.getByText('Stopped CEF Listener').closest('[role="listitem"]');
      const startButton = within(stoppedCard!).getByRole('button', { name: /start listener/i });

      await userEvent.click(startButton);

      expect(apiService.listeners.startListener).toHaveBeenCalledWith('listener-stopped');
    });

    it('calls stopListener when stop button is clicked', async () => {
      vi.mocked(apiService.listeners.stopListener).mockResolvedValue({
        status: 'success',
        message: 'Listener stopped',
      });

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const runningCard = screen.getByText('Running Syslog Listener').closest('[role="listitem"]');
      const stopButton = within(runningCard!).getByRole('button', { name: /stop listener/i });

      await userEvent.click(stopButton);

      expect(apiService.listeners.stopListener).toHaveBeenCalledWith('listener-running');
    });

    it('calls restartListener when restart button is clicked', async () => {
      vi.mocked(apiService.listeners.restartListener).mockResolvedValue({
        status: 'success',
        message: 'Listener restarted',
      });

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const runningCard = screen.getByText('Running Syslog Listener').closest('[role="listitem"]');
      const restartButton = within(runningCard!).getByRole('button', { name: /restart listener/i });

      await userEvent.click(restartButton);

      expect(apiService.listeners.restartListener).toHaveBeenCalledWith('listener-running');
    });
  });

  describe('Actions Menu', () => {
    it('opens actions menu when menu button is clicked', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const runningCard = screen.getByText('Running Syslog Listener').closest('[role="listitem"]');
      const menuButton = within(runningCard!).getByRole('button', { name: /open actions menu/i });

      await userEvent.click(menuButton);

      expect(screen.getByRole('menu')).toBeInTheDocument();
    });

    it('shows stop and restart options in menu for running listener', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const runningCard = screen.getByText('Running Syslog Listener').closest('[role="listitem"]');
      const menuButton = within(runningCard!).getByRole('button', { name: /open actions menu/i });

      await userEvent.click(menuButton);

      expect(screen.getByRole('menuitem', { name: /stop/i })).toBeInTheDocument();
      expect(screen.getByRole('menuitem', { name: /restart/i })).toBeInTheDocument();
    });

    it('shows start option in menu for stopped listener', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
      });

      const stoppedCard = screen.getByText('Stopped CEF Listener').closest('[role="listitem"]');
      const menuButton = within(stoppedCard!).getByRole('button', { name: /open actions menu/i });

      await userEvent.click(menuButton);

      expect(screen.getByRole('menuitem', { name: /start/i })).toBeInTheDocument();
    });

    it('disables edit option for running listeners', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const runningCard = screen.getByText('Running Syslog Listener').closest('[role="listitem"]');
      const menuButton = within(runningCard!).getByRole('button', { name: /open actions menu/i });

      await userEvent.click(menuButton);

      const editMenuItem = screen.getByRole('menuitem', { name: /edit/i });
      expect(editMenuItem).toHaveAttribute('aria-disabled', 'true');
    });

    it('enables edit option for stopped listeners', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
      });

      const stoppedCard = screen.getByText('Stopped CEF Listener').closest('[role="listitem"]');
      const menuButton = within(stoppedCard!).getByRole('button', { name: /open actions menu/i });

      await userEvent.click(menuButton);

      const editMenuItem = screen.getByRole('menuitem', { name: /edit/i });
      expect(editMenuItem).not.toHaveAttribute('aria-disabled', 'true');
    });

    it('disables delete option for running listeners', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const runningCard = screen.getByText('Running Syslog Listener').closest('[role="listitem"]');
      const menuButton = within(runningCard!).getByRole('button', { name: /open actions menu/i });

      await userEvent.click(menuButton);

      const deleteMenuItem = screen.getByRole('menuitem', { name: /delete/i });
      expect(deleteMenuItem).toHaveAttribute('aria-disabled', 'true');
    });
  });

  describe('Create Dialog', () => {
    it('opens create dialog and shows form', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /new listener/i })).toBeInTheDocument();
      });

      await userEvent.click(screen.getByRole('button', { name: /new listener/i }));

      const dialog = screen.getByRole('dialog');
      expect(dialog).toBeInTheDocument();
      expect(within(dialog).getByText('Create New Listener')).toBeInTheDocument();
    });

    it('closes create dialog when cancel is clicked', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /new listener/i })).toBeInTheDocument();
      });

      await userEvent.click(screen.getByRole('button', { name: /new listener/i }));
      expect(screen.getByRole('dialog')).toBeInTheDocument();

      // The ListenerForm has a cancel button
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      await userEvent.click(cancelButton);

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      });
    });
  });

  describe('Edit Dialog', () => {
    it('opens edit dialog from actions menu for stopped listener', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
      });

      const stoppedCard = screen.getByText('Stopped CEF Listener').closest('[role="listitem"]');
      const menuButton = within(stoppedCard!).getByRole('button', { name: /open actions menu/i });

      await userEvent.click(menuButton);

      const editMenuItem = screen.getByRole('menuitem', { name: /edit/i });
      await userEvent.click(editMenuItem);

      await waitFor(() => {
        const dialog = screen.getByRole('dialog');
        expect(dialog).toBeInTheDocument();
        expect(within(dialog).getByText('Edit Listener')).toBeInTheDocument();
      });
    });
  });

  describe('Delete Dialog', () => {
    it('opens delete confirmation dialog from actions menu', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
      });

      const stoppedCard = screen.getByText('Stopped CEF Listener').closest('[role="listitem"]');
      const menuButton = within(stoppedCard!).getByRole('button', { name: /open actions menu/i });

      await userEvent.click(menuButton);

      const deleteMenuItem = screen.getByRole('menuitem', { name: /delete/i });
      await userEvent.click(deleteMenuItem);

      await waitFor(() => {
        const dialog = screen.getByRole('dialog');
        expect(dialog).toBeInTheDocument();
        expect(within(dialog).getByText(/delete listener/i)).toBeInTheDocument();
        expect(within(dialog).getByText(/are you sure/i)).toBeInTheDocument();
      });
    });

    it('calls deleteListener when confirmed', async () => {
      vi.mocked(apiService.listeners.deleteListener).mockResolvedValue(undefined);

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
      });

      const stoppedCard = screen.getByText('Stopped CEF Listener').closest('[role="listitem"]');
      const menuButton = within(stoppedCard!).getByRole('button', { name: /open actions menu/i });

      await userEvent.click(menuButton);
      await userEvent.click(screen.getByRole('menuitem', { name: /delete/i }));

      // Confirm deletion
      const confirmButton = screen.getByRole('button', { name: /^delete$/i });
      await userEvent.click(confirmButton);

      expect(apiService.listeners.deleteListener).toHaveBeenCalledWith('listener-stopped');
    });

    it('closes delete dialog when canceled', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
      });

      const stoppedCard = screen.getByText('Stopped CEF Listener').closest('[role="listitem"]');
      const menuButton = within(stoppedCard!).getByRole('button', { name: /open actions menu/i });

      await userEvent.click(menuButton);
      await userEvent.click(screen.getByRole('menuitem', { name: /delete/i }));

      // Cancel
      await userEvent.click(screen.getByRole('button', { name: /cancel/i }));

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      });
    });
  });

  describe('Real-time Updates', () => {
    it('subscribes to real-time listener updates on mount', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(apiService.subscribeToRealtimeUpdates).toHaveBeenCalledWith({
          onListenerStatus: expect.any(Function),
        });
      });
    });

    it('unsubscribes from real-time updates on unmount', async () => {
      const { unmount } = renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      unmount();

      expect(apiService.unsubscribeFromRealtimeUpdates).toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    it('displays error alert when API fails', async () => {
      vi.mocked(apiService.listeners.getListeners).mockRejectedValue(new Error('Network error'));

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText(/failed to load listeners/i)).toBeInTheDocument();
      });
    });

    it('shows retry button on error', async () => {
      vi.mocked(apiService.listeners.getListeners).mockRejectedValue(new Error('Network error'));

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
      });
    });

    it('retries when retry button is clicked', async () => {
      vi.mocked(apiService.listeners.getListeners)
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce(mockPaginatedResponse);

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
      });

      await userEvent.click(screen.getByRole('button', { name: /retry/i }));

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });
    });

    it('shows snackbar notification on control operation failure', async () => {
      vi.mocked(apiService.listeners.startListener).mockRejectedValue(
        new Error('Failed to start listener')
      );

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Stopped CEF Listener')).toBeInTheDocument();
      });

      const stoppedCard = screen.getByText('Stopped CEF Listener').closest('[role="listitem"]');
      const startButton = within(stoppedCard!).getByRole('button', { name: /start listener/i });

      await userEvent.click(startButton);

      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeInTheDocument();
      });
    });
  });

  describe('Empty State', () => {
    it('displays empty state when no listeners exist', async () => {
      vi.mocked(apiService.listeners.getListeners).mockResolvedValue(
        createMockPaginatedResponse([])
      );

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(
          screen.getByText(/no listeners configured/i)
        ).toBeInTheDocument();
      });
    });
  });

  describe('Pagination', () => {
    it('displays pagination when multiple pages exist', async () => {
      vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
        items: [mockRunningListener],
        total: 25,
        page: 1,
        limit: 12,
      });

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByLabelText(/listeners pagination/i)).toBeInTheDocument();
      });
    });

    it('does not display pagination when single page', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      expect(screen.queryByLabelText(/listeners pagination/i)).not.toBeInTheDocument();
    });

    it('calls getListeners with new page when pagination is clicked', async () => {
      vi.mocked(apiService.listeners.getListeners).mockResolvedValue({
        items: [mockRunningListener],
        total: 25,
        page: 1,
        limit: 12,
      });

      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByLabelText(/listeners pagination/i)).toBeInTheDocument();
      });

      const page2Button = screen.getByRole('button', { name: /page 2/i });
      await userEvent.click(page2Button);

      expect(apiService.listeners.getListeners).toHaveBeenCalledWith(2, 12);
    });
  });

  describe('Accessibility', () => {
    it('has accessible listeners grid with list role', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByRole('list', { name: /listeners/i })).toBeInTheDocument();
      });
    });

    it('has accessible listitem roles for each listener', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        const listItems = screen.getAllByRole('listitem');
        expect(listItems.length).toBe(3);
      });
    });

    it('has accessible menu buttons with proper aria attributes', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const menuButtons = screen.getAllByRole('button', { name: /open actions menu/i });
      expect(menuButtons.length).toBeGreaterThan(0);

      menuButtons.forEach((button) => {
        expect(button).toHaveAttribute('aria-haspopup', 'menu');
      });
    });

    it('has accessible action buttons with aria-label', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        expect(screen.getByText('Running Syslog Listener')).toBeInTheDocument();
      });

      const stopButton = screen.getByRole('button', {
        name: /stop listener running syslog listener/i,
      });
      expect(stopButton).toBeInTheDocument();
    });

    it('has live region for status summary', async () => {
      renderWithProviders(<Listeners />);

      await waitFor(() => {
        const statusRegion = screen.getByRole('status');
        expect(statusRegion).toBeInTheDocument();
        expect(statusRegion).toHaveAttribute('aria-live', 'polite');
      });
    });
  });
});
