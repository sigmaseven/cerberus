import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { vi } from 'vitest';
import { Actions } from './Actions';
import type { Action } from '../types';

// Mock the API functions
vi.mock('../services/api', () => ({
  getActions: vi.fn(),
  deleteAction: vi.fn(),
  updateAction: vi.fn(),
  createAction: vi.fn(),
}));

// Mock the Table component
vi.mock('../components/Table', () => ({
  Table: ({ records }: { records: Action[] }) => (
    <div data-testid="table">
      {records.map((record, index) => (
        <div key={index} data-testid={`table-row-${index}`}>
          {record.id}
        </div>
      ))}
    </div>
  ),
}));

// Mock constants
vi.mock('../constants', () => ({
  ACTION_TYPES: ['webhook', 'slack', 'email'],
}));

import { getActions } from '../services/api';

const mockGetActions = vi.mocked(getActions);

describe('Actions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetActions.mockResolvedValue([
      {
        id: '1',
        type: 'webhook',
        config: { url: 'https://example.com' },
      },
    ]);
  });

  const renderActions = () =>
    render(
      <MantineProvider>
        <Notifications />
        <Actions />
      </MantineProvider>
    );

  it('renders loading state initially', () => {
    mockGetActions.mockReturnValue(new Promise(() => {}));
    renderActions();
    // The component shows a Loader, but we can check for the title not being there yet
    expect(screen.queryByText('Actions')).not.toBeInTheDocument();
  });

  it('renders actions after loading', async () => {
    renderActions();

    await waitFor(() => {
      expect(screen.getByText('Actions')).toBeInTheDocument();
      expect(screen.getByTestId('table')).toBeInTheDocument();
    });
  });

  it('handles API errors gracefully', async () => {
    mockGetActions.mockRejectedValueOnce(new Error('API Error'));

    renderActions();

    await waitFor(() => {
      expect(screen.getByText('Failed to load actions')).toBeInTheDocument();
    });
  });

  it('opens create modal when Add Action button is clicked', async () => {
    renderActions();

    await waitFor(() => {
      expect(screen.getByText('Add Action')).toBeInTheDocument();
    });

    const addButton = screen.getByText('Add Action');
    fireEvent.click(addButton);

    await waitFor(() => {
      expect(screen.getByText('Create Action')).toBeInTheDocument();
    });
  });
});