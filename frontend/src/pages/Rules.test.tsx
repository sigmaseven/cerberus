import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { vi } from 'vitest';
import { Rules } from './Rules';
import type { Rule } from '../types';

// Mock the API functions
vi.mock('../services/api', () => ({
  getRules: vi.fn(),
  deleteRule: vi.fn(),
  updateRule: vi.fn(),
  createRule: vi.fn(),
}));

// Mock the Table component
vi.mock('../components/Table', () => ({
  Table: ({ records }: { records: Rule[] }) => (
    <div data-testid="table">
      {records.map((record, index) => (
        <div key={index} data-testid={`table-row-${index}`}>
          {record.name}
        </div>
      ))}
    </div>
  ),
}));

// Mock constants
vi.mock('../constants', () => ({
  SEVERITY_OPTIONS: ['low', 'medium', 'high', 'critical'],
  OPERATOR_OPTIONS: ['equals', 'contains', 'regex'],
  ACTION_TYPES: ['webhook', 'slack', 'email'],
  DEFAULT_RULE_VERSION: 1,
}));

import { getRules } from '../services/api';

const mockGetRules = vi.mocked(getRules);

describe('Rules', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetRules.mockResolvedValue([
      {
        id: '1',
        name: 'Test Rule',
        description: 'A test rule',
        severity: 'medium',
        enabled: true,
        version: '1',
        conditions: [{ field: 'event_type', operator: 'equals', value: 'login', logic: 'AND' }],
        actions: [{ type: 'webhook', config: { url: 'https://example.com' } }],
      },
    ]);
  });

  const renderRules = () =>
    render(
      <MantineProvider>
        <Notifications />
        <Rules />
      </MantineProvider>
    );

  it('renders loading state initially', () => {
    mockGetRules.mockReturnValue(new Promise(() => {}));
    renderRules();
    expect(screen.queryByText('Rules')).not.toBeInTheDocument();
  });

  it('renders rules after loading', async () => {
    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Rules')).toBeInTheDocument();
      expect(screen.getByTestId('table')).toBeInTheDocument();
    });
  });

  it('handles API errors gracefully', async () => {
    mockGetRules.mockRejectedValueOnce(new Error('API Error'));

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Failed to load rules')).toBeInTheDocument();
    });
  });

  it('opens create modal when Add Rule button is clicked', async () => {
    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Add Rule')).toBeInTheDocument();
    });

    const addButton = screen.getByText('Add Rule');
    fireEvent.click(addButton);

    await waitFor(() => {
      expect(screen.getByText('Create Rule')).toBeInTheDocument();
    });
  });
});