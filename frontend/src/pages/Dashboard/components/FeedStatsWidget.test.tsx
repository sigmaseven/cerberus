/**
 * FeedStatsWidget.test.tsx (TASK 157.2)
 * Comprehensive tests for the FeedStatsWidget dashboard component
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import FeedStatsWidget from './FeedStatsWidget';
import { apiService } from '../../../services/api';
import { FeedsSummary } from '../../../types';

// Mock the API service
vi.mock('../../../services/api', () => ({
  apiService: {
    feeds: {
      getFeedsSummary: vi.fn(),
    },
  },
}));

// Mock date-fns to have predictable output
vi.mock('date-fns', () => ({
  formatDistanceToNow: vi.fn(() => '5 minutes ago'),
}));

const mockSummaryHealthy: FeedsSummary = {
  total_feeds: 5,
  active_feeds: 4,
  total_rules: 1250,
  last_sync: '2024-01-15T10:30:00Z',
  health_status: 'healthy',
  error_count: 0,
};

const mockSummaryWarning: FeedsSummary = {
  total_feeds: 5,
  active_feeds: 3,
  total_rules: 800,
  last_sync: '2024-01-15T09:00:00Z',
  health_status: 'warning',
  error_count: 0,
};

const mockSummaryError: FeedsSummary = {
  total_feeds: 5,
  active_feeds: 4,
  total_rules: 1100,
  last_sync: '2024-01-14T15:00:00Z',
  health_status: 'error',
  error_count: 2,
};

const mockSummaryEmpty: FeedsSummary = {
  total_feeds: 0,
  active_feeds: 0,
  total_rules: 0,
  last_sync: null,
  health_status: 'healthy',
  error_count: 0,
};

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
        <FeedStatsWidget />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe('FeedStatsWidget', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ==========================================================================
  // Loading State Tests
  // ==========================================================================

  it('should render loading state initially', () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockReturnValue(
      new Promise(() => {}) // Never resolves - stays in loading
    );

    renderWidget();
    expect(screen.getByText('Rule Sources')).toBeInTheDocument();
  });

  // ==========================================================================
  // Successful Data Rendering Tests
  // ==========================================================================

  it('should render feed summary data after loading', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(mockSummaryHealthy);

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('Rule Sources')).toBeInTheDocument();
    });

    // Check active/total feeds display
    await waitFor(() => {
      expect(screen.getByText('4/5')).toBeInTheDocument();
    });
    expect(screen.getByText('Active Feeds')).toBeInTheDocument();

    // Check total rules
    expect(screen.getByText('1,250')).toBeInTheDocument();
    expect(screen.getByText('Rules Imported')).toBeInTheDocument();

    // Check last sync
    expect(screen.getByText('Last Sync')).toBeInTheDocument();
  });

  it('should show healthy status when all feeds healthy', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(mockSummaryHealthy);

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('All Feeds Healthy')).toBeInTheDocument();
    });
  });

  it('should show warning status when feeds have warnings', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(mockSummaryWarning);

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('Some Feeds Warning')).toBeInTheDocument();
    });
  });

  it('should show error status with error count when feeds have errors', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(mockSummaryError);

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('Feed Errors Detected')).toBeInTheDocument();
    });

    // Check error count is displayed
    expect(screen.getByText('(2 feeds with errors)')).toBeInTheDocument();
  });

  // ==========================================================================
  // Navigation Tests
  // ==========================================================================

  it('should have manage feeds button linking to settings', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(mockSummaryHealthy);

    renderWidget();

    await waitFor(() => {
      const settingsLink = screen.getByRole('link', { name: /go to feed settings/i });
      expect(settingsLink).toBeInTheDocument();
      expect(settingsLink).toHaveAttribute('href', '/settings?tab=feeds');
    });
  });

  it('should show "Add Your First Feed" button when no feeds', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(mockSummaryEmpty);

    renderWidget();

    await waitFor(() => {
      const addFeedButton = screen.getByRole('link', { name: /navigate to settings to add your first feed/i });
      expect(addFeedButton).toBeInTheDocument();
      expect(addFeedButton).toHaveAttribute('href', '/settings?tab=feeds');
    });
  });

  // ==========================================================================
  // Error State Tests
  // ==========================================================================

  it('should display error state when API fails', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockRejectedValue(
      new Error('Network Error')
    );

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText(/failed to load feed data/i)).toBeInTheDocument();
      expect(screen.getByText(/network error/i)).toBeInTheDocument();
    });
  });

  it('should show retry button in error state', async () => {
    const mockGetSummary = vi.mocked(apiService.feeds.getFeedsSummary);
    mockGetSummary.mockRejectedValueOnce(new Error('Network Error'));

    renderWidget();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    });

    // Simulate retry
    mockGetSummary.mockResolvedValueOnce(mockSummaryHealthy);

    const retryButton = screen.getByRole('button', { name: /retry/i });
    await userEvent.click(retryButton);

    await waitFor(() => {
      expect(mockGetSummary).toHaveBeenCalledTimes(2);
    });
  });

  // ==========================================================================
  // Refresh Button Tests
  // ==========================================================================

  it('should have refresh button that triggers refetch', async () => {
    const mockGetSummary = vi.mocked(apiService.feeds.getFeedsSummary);
    mockGetSummary.mockResolvedValue(mockSummaryHealthy);

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('Rule Sources')).toBeInTheDocument();
    });

    const refreshButton = screen.getByRole('button', { name: /refresh feed statistics/i });
    expect(refreshButton).toBeInTheDocument();

    // Click refresh
    await userEvent.click(refreshButton);

    await waitFor(() => {
      expect(mockGetSummary).toHaveBeenCalledTimes(2);
    });
  });

  // ==========================================================================
  // Empty State Tests
  // ==========================================================================

  it('should show empty state when no feeds configured', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(mockSummaryEmpty);

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText(/no rule feeds configured/i)).toBeInTheDocument();
    });

    // Should still show healthy status (default)
    expect(screen.getByText('All Feeds Healthy')).toBeInTheDocument();
  });

  it('should show "Never synced" when last_sync is null', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(mockSummaryEmpty);

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('Never synced')).toBeInTheDocument();
    });
  });

  // ==========================================================================
  // Edge Case Tests
  // ==========================================================================

  it('should handle large numbers with proper formatting', async () => {
    const largeSummary: FeedsSummary = {
      total_feeds: 100,
      active_feeds: 95,
      total_rules: 1500000,
      last_sync: '2024-01-15T10:30:00Z',
      health_status: 'healthy',
      error_count: 0,
    };

    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(largeSummary);

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('1,500,000')).toBeInTheDocument();
    });
    expect(screen.getByText('95/100')).toBeInTheDocument();
  });

  it('should handle single feed with error (singular text)', async () => {
    const singleErrorSummary: FeedsSummary = {
      total_feeds: 5,
      active_feeds: 4,
      total_rules: 1000,
      last_sync: '2024-01-15T10:30:00Z',
      health_status: 'error',
      error_count: 1,
    };

    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(singleErrorSummary);

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('(1 feed with errors)')).toBeInTheDocument();
    });
  });

  it('should handle zero active feeds', async () => {
    const noActiveSummary: FeedsSummary = {
      total_feeds: 5,
      active_feeds: 0,
      total_rules: 500,
      last_sync: '2024-01-10T10:30:00Z',
      health_status: 'warning',
      error_count: 0,
    };

    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(noActiveSummary);

    renderWidget();

    await waitFor(() => {
      expect(screen.getByText('0/5')).toBeInTheDocument();
    });
  });

  it('should handle invalid/malformed last_sync date gracefully', async () => {
    // Unmock date-fns for this test to check real error handling
    vi.unmock('date-fns');

    const invalidDateSummary: FeedsSummary = {
      total_feeds: 1,
      active_feeds: 1,
      total_rules: 100,
      last_sync: 'invalid-date-string',
      health_status: 'healthy',
      error_count: 0,
    };

    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(invalidDateSummary);

    renderWidget();

    // Should not crash - widget should still render
    await waitFor(() => {
      expect(screen.getByText('Rule Sources')).toBeInTheDocument();
    });
  });

  // ==========================================================================
  // Accessibility Tests
  // ==========================================================================

  it('should have accessible labels for health status', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(mockSummaryHealthy);

    renderWidget();

    await waitFor(() => {
      const healthChip = screen.getByRole('button', { name: /feed health status/i });
      expect(healthChip).toBeInTheDocument();
    });
  });

  it('should have accessible refresh button', async () => {
    vi.mocked(apiService.feeds.getFeedsSummary).mockResolvedValue(mockSummaryHealthy);

    renderWidget();

    await waitFor(() => {
      const refreshButton = screen.getByRole('button', { name: /refresh feed statistics/i });
      expect(refreshButton).toBeInTheDocument();
    });
  });
});
