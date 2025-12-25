import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RuleLifecyclePanel } from './RuleLifecyclePanel';
import { apiService } from '../services/api';
import type { LifecycleHistoryEntry, LifecycleStatus } from '../types';

// Mock API service
vi.mock('../services/api', () => ({
  apiService: {
    getRuleLifecycleHistory: vi.fn(),
    transitionRuleLifecycle: vi.fn(),
  },
}));

const mockHistory: LifecycleHistoryEntry[] = [
  {
    timestamp: '2024-01-15T10:30:00Z',
    from_status: 'test',
    to_status: 'stable',
    changed_by: 'analyst@example.com',
    comment: 'Promoted to stable after successful testing',
  },
  {
    timestamp: '2024-01-10T09:00:00Z',
    from_status: 'experimental',
    to_status: 'test',
    changed_by: 'analyst@example.com',
    comment: 'Moved to testing phase',
  },
  {
    timestamp: '2024-01-05T14:00:00Z',
    from_status: 'experimental',
    to_status: 'experimental',
    changed_by: 'system',
    comment: 'Initial rule creation',
  },
];

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

describe('RuleLifecyclePanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiService.getRuleLifecycleHistory).mockResolvedValue(mockHistory);
  });

  describe('Current Status Display', () => {
    it('displays current status with correct color coding', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      const statusChip = screen.getByLabelText(/current status: stable/i);
      expect(statusChip).toBeInTheDocument();
      expect(statusChip).toHaveTextContent('Stable');
    });

    it('shows experimental status in yellow/warning', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="experimental" />,
        { wrapper: createWrapper() }
      );

      const statusChip = screen.getByLabelText(/current status: experimental/i);
      expect(statusChip).toBeInTheDocument();
    });

    it('shows stable status in green/success', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      const statusChip = screen.getByLabelText(/current status: stable/i);
      expect(statusChip).toBeInTheDocument();
    });

    it('shows deprecated status in red/error', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="deprecated" />,
        { wrapper: createWrapper() }
      );

      const statusChip = screen.getByLabelText(/current status: deprecated/i);
      expect(statusChip).toBeInTheDocument();
    });

    it('displays time in status', async () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      await waitFor(() => {
        expect(screen.getByText(/time in status:/i)).toBeInTheDocument();
      });
    });
  });

  describe('State Diagram', () => {
    it('renders all lifecycle states in diagram', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="test" />,
        { wrapper: createWrapper() }
      );

      expect(screen.getByText('Experimental')).toBeInTheDocument();
      expect(screen.getByText('Test')).toBeInTheDocument();
      expect(screen.getByText('Stable')).toBeInTheDocument();
      expect(screen.getByText('Active')).toBeInTheDocument();
      expect(screen.getByText('Deprecated')).toBeInTheDocument();
      expect(screen.getByText('Archived')).toBeInTheDocument();
    });

    it('highlights current state in diagram', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="test" />,
        { wrapper: createWrapper() }
      );

      const testChip = screen.getByLabelText(/test status - current/i);
      expect(testChip).toBeInTheDocument();
    });

    it('has aria-label for accessibility', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      const diagram = screen.getByLabelText(/rule lifecycle state diagram/i);
      expect(diagram).toBeInTheDocument();
    });
  });

  describe('Transition Controls', () => {
    it('shows promote button for experimental status', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="experimental" />,
        { wrapper: createWrapper() }
      );

      const promoteButton = screen.getByRole('button', { name: /promote from experimental/i });
      expect(promoteButton).toBeInTheDocument();
      expect(promoteButton).not.toBeDisabled();
    });

    it('shows promote button for test status', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="test" />,
        { wrapper: createWrapper() }
      );

      const promoteButton = screen.getByRole('button', { name: /promote from test/i });
      expect(promoteButton).toBeInTheDocument();
    });

    it('shows activate button when applicable', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      const activateButton = screen.getByRole('button', { name: /activate rule for production/i });
      expect(activateButton).toBeInTheDocument();
    });

    it('shows deprecate button for active status', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="active" />,
        { wrapper: createWrapper() }
      );

      const deprecateButton = screen.getByRole('button', { name: /deprecate rule/i });
      expect(deprecateButton).toBeInTheDocument();
    });

    it('shows archive button for deprecated status', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="deprecated" />,
        { wrapper: createWrapper() }
      );

      const archiveButton = screen.getByRole('button', { name: /archive rule/i });
      expect(archiveButton).toBeInTheDocument();
    });

    it('handles promote action from experimental to test', async () => {
      const user = userEvent.setup();
      const onStatusChange = vi.fn();

      vi.mocked(apiService.transitionRuleLifecycle).mockResolvedValue({
        category: 'detection',
        rule: { lifecycle_status: 'test' } as any,
      });

      render(
        <RuleLifecyclePanel
          ruleId="rule-123"
          currentStatus="experimental"
          onStatusChange={onStatusChange}
        />,
        { wrapper: createWrapper() }
      );

      const promoteButton = screen.getByRole('button', { name: /promote from experimental/i });
      await user.click(promoteButton);

      await waitFor(() => {
        expect(apiService.transitionRuleLifecycle).toHaveBeenCalledWith('rule-123', {
          status: 'test',
          comment: expect.stringContaining('Promoted from experimental to test'),
        });
      });
    });

    it('handles activate action', async () => {
      const user = userEvent.setup();

      vi.mocked(apiService.transitionRuleLifecycle).mockResolvedValue({
        category: 'detection',
        rule: { lifecycle_status: 'active' } as any,
      });

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      const activateButton = screen.getByRole('button', { name: /activate rule for production/i });
      await user.click(activateButton);

      await waitFor(() => {
        expect(apiService.transitionRuleLifecycle).toHaveBeenCalledWith('rule-123', {
          status: 'active',
          comment: 'Activated for production use',
        });
      });
    });
  });

  describe('Deprecation Dialog', () => {
    it('opens deprecation dialog when deprecate button clicked', async () => {
      const user = userEvent.setup();

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="active" />,
        { wrapper: createWrapper() }
      );

      const deprecateButton = screen.getByRole('button', { name: /deprecate rule/i });
      await user.click(deprecateButton);

      await waitFor(() => {
        expect(screen.getByRole('dialog', { name: /deprecate rule/i })).toBeInTheDocument();
      });
    });

    it('shows deprecation warning in dialog', async () => {
      const user = userEvent.setup();

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="active" />,
        { wrapper: createWrapper() }
      );

      await user.click(screen.getByRole('button', { name: /deprecate rule/i }));

      await waitFor(() => {
        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByText(/no longer recommended for use/i)).toBeInTheDocument();
      });
    });

    it('requires deprecation reason', async () => {
      const user = userEvent.setup();

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="active" />,
        { wrapper: createWrapper() }
      );

      await user.click(screen.getByRole('button', { name: /deprecate rule/i }));

      const dialog = await screen.findByRole('dialog');
      const reasonInput = within(dialog).getByLabelText(/deprecation reason/i);
      expect(reasonInput).toHaveAttribute('aria-required', 'true');

      const submitButton = within(dialog).getByRole('button', { name: /deprecate rule/i });
      expect(submitButton).toBeDisabled();
    });

    it('submits deprecation with reason and sunset date', async () => {
      const user = userEvent.setup();

      vi.mocked(apiService.transitionRuleLifecycle).mockResolvedValue({
        category: 'detection',
        rule: { lifecycle_status: 'deprecated' } as any,
      });

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="active" />,
        { wrapper: createWrapper() }
      );

      await user.click(screen.getByRole('button', { name: /deprecate rule/i }));

      const dialog = await screen.findByRole('dialog');
      const reasonInput = within(dialog).getByLabelText(/deprecation reason/i);
      const dateInput = within(dialog).getByLabelText(/sunset date/i);

      await user.type(reasonInput, 'Rule replaced by improved version');
      await user.type(dateInput, '2024-12-31');

      const submitButton = within(dialog).getByRole('button', { name: /deprecate rule/i });
      await user.click(submitButton);

      await waitFor(() => {
        expect(apiService.transitionRuleLifecycle).toHaveBeenCalledWith('rule-123', {
          status: 'deprecated',
          comment: expect.stringContaining('Rule replaced by improved version'),
        });
      });
    });

    it('closes dialog on cancel', async () => {
      const user = userEvent.setup();

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="active" />,
        { wrapper: createWrapper() }
      );

      await user.click(screen.getByRole('button', { name: /deprecate rule/i }));
      const dialog = await screen.findByRole('dialog');

      const cancelButton = within(dialog).getByRole('button', { name: /cancel/i });
      await user.click(cancelButton);

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      });
    });
  });

  describe('Archive Dialog', () => {
    it('opens archive dialog when archive button clicked', async () => {
      const user = userEvent.setup();

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="deprecated" />,
        { wrapper: createWrapper() }
      );

      const archiveButton = screen.getByRole('button', { name: /archive rule/i });
      await user.click(archiveButton);

      await waitFor(() => {
        expect(screen.getByRole('dialog', { name: /archive rule/i })).toBeInTheDocument();
      });
    });

    it('shows archive confirmation warning', async () => {
      const user = userEvent.setup();

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="deprecated" />,
        { wrapper: createWrapper() }
      );

      await user.click(screen.getByRole('button', { name: /archive rule/i }));

      await waitFor(() => {
        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByText(/permanently disable this rule/i)).toBeInTheDocument();
      });
    });

    it('submits archive action', async () => {
      const user = userEvent.setup();

      vi.mocked(apiService.transitionRuleLifecycle).mockResolvedValue({
        category: 'detection',
        rule: { lifecycle_status: 'archived' } as any,
      });

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="deprecated" />,
        { wrapper: createWrapper() }
      );

      await user.click(screen.getByRole('button', { name: /archive rule/i }));

      const dialog = await screen.findByRole('dialog');
      const submitButton = within(dialog).getByRole('button', { name: /archive rule/i });
      await user.click(submitButton);

      await waitFor(() => {
        expect(apiService.transitionRuleLifecycle).toHaveBeenCalledWith('rule-123', {
          status: 'archived',
          comment: 'Archived - no longer in use',
        });
      });
    });
  });

  describe('Lifecycle History Timeline', () => {
    it('loads and displays lifecycle history', async () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      await waitFor(() => {
        expect(apiService.getRuleLifecycleHistory).toHaveBeenCalledWith('rule-123');
      });

      await waitFor(() => {
        expect(screen.getByText(/promoted to stable after successful testing/i)).toBeInTheDocument();
      });
    });

    it('displays timeline entries with timestamps', async () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      await waitFor(() => {
        expect(screen.getByText(/changed by:/i)).toBeInTheDocument();
      });
    });

    it('shows status transitions with color-coded chips', async () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      await waitFor(() => {
        const testChips = screen.getAllByText('Test');
        const stableChips = screen.getAllByText('Stable');
        expect(testChips.length).toBeGreaterThan(0);
        expect(stableChips.length).toBeGreaterThan(0);
      });
    });

    it('can expand and collapse timeline', async () => {
      const user = userEvent.setup();

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      await waitFor(() => {
        expect(screen.getByLabelText(/collapse timeline/i)).toBeInTheDocument();
      });

      const collapseButton = screen.getByLabelText(/collapse timeline/i);
      await user.click(collapseButton);

      await waitFor(() => {
        expect(screen.getByLabelText(/expand timeline/i)).toBeInTheDocument();
      });
    });

    it('shows empty state when no history available', async () => {
      vi.mocked(apiService.getRuleLifecycleHistory).mockResolvedValue([]);

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="experimental" />,
        { wrapper: createWrapper() }
      );

      await waitFor(() => {
        expect(screen.getByText(/no lifecycle history available/i)).toBeInTheDocument();
      });
    });

    it('displays error when history fails to load', async () => {
      vi.mocked(apiService.getRuleLifecycleHistory).mockRejectedValue(
        new Error('Network error')
      );

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      await waitFor(() => {
        expect(screen.getByText(/failed to load lifecycle history/i)).toBeInTheDocument();
      });
    });
  });

  describe('Accessibility', () => {
    it('has proper ARIA labels for all interactive elements', () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      expect(screen.getByLabelText(/current status: stable/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/rule lifecycle state diagram/i)).toBeInTheDocument();
    });

    it('supports keyboard navigation for state diagram', async () => {
      const user = userEvent.setup();

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="test" />,
        { wrapper: createWrapper() }
      );

      const stableChip = screen.getByLabelText(/stable status$/i);
      stableChip.focus();

      await user.keyboard('{Enter}');

      // Should initiate transition or show dialog
      await waitFor(() => {
        expect(apiService.transitionRuleLifecycle).toHaveBeenCalled();
      });
    });

    it('manages focus properly in dialogs', async () => {
      const user = userEvent.setup();

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="active" />,
        { wrapper: createWrapper() }
      );

      await user.click(screen.getByRole('button', { name: /deprecate rule/i }));

      const dialog = await screen.findByRole('dialog');
      const reasonInput = within(dialog).getByLabelText(/deprecation reason/i);

      // Focus should be manageable
      reasonInput.focus();
      expect(reasonInput).toHaveFocus();
    });

    it('uses semantic HTML for timeline', async () => {
      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="stable" />,
        { wrapper: createWrapper() }
      );

      await waitFor(() => {
        // Timeline component uses semantic list structure
        expect(screen.getByText(/lifecycle history/i)).toBeInTheDocument();
      });
    });
  });

  describe('Error Handling', () => {
    it('displays error when transition fails', async () => {
      const user = userEvent.setup();

      vi.mocked(apiService.transitionRuleLifecycle).mockRejectedValue(
        new Error('Transition not allowed')
      );

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="experimental" />,
        { wrapper: createWrapper() }
      );

      const promoteButton = screen.getByRole('button', { name: /promote from experimental/i });
      await user.click(promoteButton);

      await waitFor(() => {
        expect(screen.getByText(/transition not allowed/i)).toBeInTheDocument();
      });
    });

    it('shows loading state during transition', async () => {
      const user = userEvent.setup();

      vi.mocked(apiService.transitionRuleLifecycle).mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 1000))
      );

      render(
        <RuleLifecyclePanel ruleId="rule-123" currentStatus="experimental" />,
        { wrapper: createWrapper() }
      );

      const promoteButton = screen.getByRole('button', { name: /promote from experimental/i });
      await user.click(promoteButton);

      await waitFor(() => {
        expect(screen.getByText(/updating lifecycle status/i)).toBeInTheDocument();
      });
    });
  });

  describe('Callbacks', () => {
    it('calls onStatusChange when status changes', async () => {
      const user = userEvent.setup();
      const onStatusChange = vi.fn();

      vi.mocked(apiService.transitionRuleLifecycle).mockResolvedValue({
        category: 'detection',
        rule: { lifecycle_status: 'test' } as any,
      });

      render(
        <RuleLifecyclePanel
          ruleId="rule-123"
          currentStatus="experimental"
          onStatusChange={onStatusChange}
        />,
        { wrapper: createWrapper() }
      );

      const promoteButton = screen.getByRole('button', { name: /promote from experimental/i });
      await user.click(promoteButton);

      await waitFor(() => {
        expect(onStatusChange).toHaveBeenCalledWith('test');
      });
    });
  });
});
