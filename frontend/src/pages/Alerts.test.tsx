import { render, screen, waitFor } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { vi } from 'vitest';
import { Alerts } from './Alerts';
import type { Alert } from '../types';

// Mock the API functions
vi.mock('../services/api', () => ({
  getAlerts: vi.fn(),
  acknowledgeAlert: vi.fn(),
  dismissAlert: vi.fn(),
}));

// Mock the Table component
vi.mock('../components/Table', () => ({
  Table: ({ records }: { records: Alert[] }) => (
    <div data-testid="table">
      {records.map((record, index) => (
        <div key={index} data-testid={`table-row-${index}`}>
          {record.alert_id}
        </div>
      ))}
    </div>
  ),
}));

// Mock constants and utils
vi.mock('../constants', () => ({
  SEVERITY_OPTIONS: ['low', 'medium', 'high', 'critical'],
}));

vi.mock('../utils', () => ({
  getSeverityColor: vi.fn(() => 'red'),
  escapeHtml: vi.fn((str) => str),
}));

import { getAlerts } from '../services/api';

const mockGetAlerts = vi.mocked(getAlerts);

describe('Alerts', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetAlerts.mockResolvedValue([
      {
        alert_id: '1',
        rule_id: 'rule1',
        event_id: 'event1',
        severity: 'high',
        status: 'New',
        timestamp: '2023-01-01T00:00:00Z',
        event: {
          event_id: 'event1',
          timestamp: '2023-01-01T00:00:00Z',
          source_format: 'syslog',
          severity: 'high',
          event_type: 'login',
          raw_data: 'raw data',
          fields: {},
        },
      },
    ]);
  });

  const renderAlerts = () =>
    render(
      <MantineProvider>
        <Notifications />
        <Alerts />
      </MantineProvider>
    );

  it('renders loading state initially', () => {
    mockGetAlerts.mockReturnValue(new Promise(() => {}));
    renderAlerts();
    expect(screen.queryByText('Alerts')).not.toBeInTheDocument();
  });

  it('renders alerts after loading', async () => {
    renderAlerts();

    await waitFor(() => {
      expect(screen.getByText('Alerts')).toBeInTheDocument();
      expect(screen.getByTestId('table')).toBeInTheDocument();
    });
  });

  it('handles API errors gracefully', async () => {
    mockGetAlerts.mockRejectedValueOnce(new Error('API Error'));

    renderAlerts();

    await waitFor(() => {
      expect(screen.getByText('Failed to load alerts')).toBeInTheDocument();
    });
  });
});