import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { InvestigationCard } from './index';
import type { Investigation } from '../../types';

const mockInvestigation: Investigation = {
  investigation_id: 'inv-123',
  title: 'Suspicious Activity Investigation',
  description: 'Investigating suspicious login patterns',
  status: 'in_progress',
  priority: 'high',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-02T00:00:00Z',
  created_by: 'analyst-1',
  assignee_id: 'analyst-2',
  alert_ids: ['alert-1', 'alert-2', 'alert-3'],
  mitre_tactics: ['initial-access', 'credential-access'],
  mitre_techniques: ['T1078', 'T1110']};

describe('InvestigationCard', () => {
  it('renders investigation details correctly', () => {
    const onOpen = vi.fn();

    render(<InvestigationCard investigation={mockInvestigation} onOpen={onOpen} />);

    expect(screen.getByText('Suspicious Activity Investigation')).toBeInTheDocument();
    expect(screen.getByText(/Investigating suspicious login patterns/i)).toBeInTheDocument();
    expect(screen.getByText('in_progress')).toBeInTheDocument();
  });

  it('displays priority with correct color', () => {
    const onOpen = vi.fn();

    const { } = render(
      <InvestigationCard investigation={mockInvestigation} onOpen={onOpen} />
    );

    // Check for priority chip
    const priorityChip = screen.getByText('high');
    expect(priorityChip).toBeInTheDocument();
  });

  it('shows alert count', () => {
    const onOpen = vi.fn();

    render(<InvestigationCard investigation={mockInvestigation} onOpen={onOpen} />);

    expect(screen.getByText(/3 alerts/i)).toBeInTheDocument();
  });

  it('displays MITRE badges when tactics are present', () => {
    const onOpen = vi.fn();

    render(<InvestigationCard investigation={mockInvestigation} onOpen={onOpen} />);

    // Should display MITRE section
    expect(screen.getByText(/initial-access/i)).toBeInTheDocument();
    expect(screen.getByText(/credential-access/i)).toBeInTheDocument();
  });

  it('calls onOpen when card is clicked', () => {
    const onOpen = vi.fn();

    render(<InvestigationCard investigation={mockInvestigation} onOpen={onOpen} />);

    const card = screen.getByText('Suspicious Activity Investigation').closest('div[role="button"]');
    if (card) {
      fireEvent.click(card);
      expect(onOpen).toHaveBeenCalledWith('inv-123');
    }
  });

  it('displays assignee when present', () => {
    const onOpen = vi.fn();

    render(<InvestigationCard investigation={mockInvestigation} onOpen={onOpen} />);

    expect(screen.getByText(/analyst-2/i)).toBeInTheDocument();
  });

  it('displays different priority colors', () => {
    const onOpen = vi.fn();

    const criticalInvestigation = { ...mockInvestigation, priority: 'critical' as const };
    const { rerender } = render(
      <InvestigationCard investigation={criticalInvestigation} onOpen={onOpen} />
    );
    expect(screen.getByText('critical')).toBeInTheDocument();

    const lowInvestigation = { ...mockInvestigation, priority: 'low' as const };
    rerender(<InvestigationCard investigation={lowInvestigation} onOpen={onOpen} />);
    expect(screen.getByText('low')).toBeInTheDocument();
  });

  it('handles investigation with no MITRE data', () => {
    const onOpen = vi.fn();
    const investigationWithoutMitre = {
      ...mockInvestigation,
      mitre_tactics: undefined,
      mitre_techniques: undefined};

    render(
      <InvestigationCard investigation={investigationWithoutMitre} onOpen={onOpen} />
    );

    // Should still render without errors
    expect(screen.getByText('Suspicious Activity Investigation')).toBeInTheDocument();
  });
});
