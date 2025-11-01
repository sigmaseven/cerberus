import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { vi } from 'vitest';
import { Dashboard } from './Dashboard';

// Mock the API functions
vi.mock('../services/api', () => ({
  getEvents: vi.fn(),
  getDashboardStats: vi.fn(),
  getDashboardChart: vi.fn(),
}));

// Mock the utils
vi.mock('../utils', () => ({
  getSeverityColor: vi.fn(() => 'blue'),
  getSeverityIcon: vi.fn(() => () => React.createElement('div', { 'data-testid': 'icon' })),
}));

// Mock constants
vi.mock('../constants', () => ({
  REFRESH_INTERVAL_MS: 30000,
}));

import { getEvents, getDashboardStats, getDashboardChart } from '../services/api';

const mockGetEvents = vi.mocked(getEvents);
const mockGetDashboardStats = vi.mocked(getDashboardStats);
const mockGetDashboardChart = vi.mocked(getDashboardChart);

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Mock successful API responses
    mockGetEvents.mockResolvedValue([
      {
        event_id: '1',
        event_type: 'Test Event',
        severity: 'high',
        timestamp: '2023-01-01T00:00:00Z',
        source_format: 'syslog',
        raw_data: 'test raw data',
        fields: {},
      },
    ]);
    mockGetDashboardStats.mockResolvedValue({
      total_events: 100,
      total_alerts: 10,
    });
    mockGetDashboardChart.mockResolvedValue([
      { name: 'Jan', events: 10, alerts: 1 },
    ]);
  });

  const renderDashboard = () =>
    render(
      <MantineProvider>
        <Notifications />
        <Dashboard />
      </MantineProvider>
    );

  it('renders loading state initially', () => {
    // Mock to return pending promises to simulate loading
    mockGetEvents.mockReturnValue(new Promise(() => {}));
    mockGetDashboardStats.mockReturnValue(new Promise(() => {}));
    mockGetDashboardChart.mockReturnValue(new Promise(() => {}));

    renderDashboard();
    expect(screen.getAllByText('Loading...')).toHaveLength(2);
  });

  it('renders dashboard data after loading', async () => {
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText('100')).toBeInTheDocument(); // total_events
      expect(screen.getByText('10')).toBeInTheDocument(); // total_alerts
      expect(screen.getByText('Test Event - 2023-01-01T00:00:00Z')).toBeInTheDocument();
    });
  });

  it('handles refresh button click', async () => {
    renderDashboard();

    await waitFor(() => {
      expect(mockGetEvents).toHaveBeenCalledTimes(1);
    });

    const refreshButton = screen.getByRole('button', { name: /refresh/i });
    fireEvent.click(refreshButton);

    await waitFor(() => {
      expect(mockGetEvents).toHaveBeenCalledTimes(2);
      expect(mockGetDashboardStats).toHaveBeenCalledTimes(2);
      expect(mockGetDashboardChart).toHaveBeenCalledTimes(2);
    });
  });

  it('handles API errors gracefully', async () => {
    mockGetEvents.mockRejectedValueOnce(new Error('API Error'));

    renderDashboard();

    // Should still render the stats and chart if they succeed
    await waitFor(() => {
      expect(screen.getByText('100')).toBeInTheDocument();
    });

    // Check that error notification is shown
    await waitFor(() => {
      expect(screen.getByText('Failed to load recent events: API Error')).toBeInTheDocument();
    });
  });

  it('handles dashboard stats error', async () => {
    mockGetDashboardStats.mockRejectedValueOnce(new Error('Stats Error'));

    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText('Failed to load dashboard stats: Stats Error')).toBeInTheDocument();
    });
  });

  it('handles dashboard chart error', async () => {
    mockGetDashboardChart.mockRejectedValueOnce(new Error('Chart Error'));

    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText('Failed to load chart data: Chart Error')).toBeInTheDocument();
    });
  });

});