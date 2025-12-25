import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor  } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { InvestigationForm } from './InvestigationForm';
import type { Alert as AlertType } from '../../types';

const mockAlerts: AlertType[] = [
  {
    alert_id: 'alert-1',
    title: 'Suspicious Login',
    severity: 'high',
    status: 'new',
    timestamp: '2024-01-01T00:00:00Z',
    rule_id: 'rule-1',
    event: {
      event_id: 'event-1',
      event_type: 'login',
      timestamp: '2024-01-01T00:00:00Z',
      source_ip: '192.168.1.1',
      fields: {}}},
  {
    alert_id: 'alert-2',
    title: 'Malware Detected',
    severity: 'critical',
    status: 'new',
    timestamp: '2024-01-01T01:00:00Z',
    rule_id: 'rule-2',
    event: {
      event_id: 'event-2',
      event_type: 'malware',
      timestamp: '2024-01-01T01:00:00Z',
      source_ip: '192.168.1.2',
      fields: {}}},
];

describe('InvestigationForm', () => {
  it('renders form fields correctly', () => {
    const onSubmit = vi.fn();
    const onCancel = vi.fn();

    render(
      <InvestigationForm
        onSubmit={onSubmit}
        onCancel={onCancel}
        availableAlerts={mockAlerts}
      />
    );

    expect(screen.getByLabelText(/title/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/description/i)).toBeInTheDocument();
    expect(screen.getByText(/priority/i)).toBeInTheDocument();
    expect(screen.getByText(/critical/i)).toBeInTheDocument();
    expect(screen.getByText(/high/i)).toBeInTheDocument();
    expect(screen.getByText(/medium/i)).toBeInTheDocument();
    expect(screen.getByText(/low/i)).toBeInTheDocument();
  });

  it('validates required fields', async () => {
    const onSubmit = vi.fn();
    const onCancel = vi.fn();

    render(
      <InvestigationForm
        onSubmit={onSubmit}
        onCancel={onCancel}
      />
    );

    const submitButton = screen.getByRole('button', { name: /create investigation/i });

    // Submit button should be disabled when fields are empty
    expect(submitButton).toBeDisabled();
  });

  it('enables submit button when required fields are filled', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    const onCancel = vi.fn();

    render(
      <InvestigationForm
        onSubmit={onSubmit}
        onCancel={onCancel}
      />
    );

    const titleInput = screen.getByLabelText(/title/i);
    const descriptionInput = screen.getByLabelText(/description/i);

    await user.type(titleInput, 'Test Investigation');
    await user.type(descriptionInput, 'This is a test investigation');

    const submitButton = screen.getByRole('button', { name: /create investigation/i });
    expect(submitButton).toBeEnabled();
  });

  it('calls onSubmit with correct data', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    const onCancel = vi.fn();

    render(
      <InvestigationForm
        onSubmit={onSubmit}
        onCancel={onCancel}
      />
    );

    await user.type(screen.getByLabelText(/title/i), 'Test Investigation');
    await user.type(screen.getByLabelText(/description/i), 'Test description');

    // Click medium priority
    await user.click(screen.getByRole('button', { name: /medium/i }));

    await user.click(screen.getByRole('button', { name: /create investigation/i }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith({
        title: 'Test Investigation',
        description: 'Test description',
        priority: 'medium'});
    });
  });

  it('calls onCancel when cancel button is clicked', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    const onCancel = vi.fn();

    render(
      <InvestigationForm
        onSubmit={onSubmit}
        onCancel={onCancel}
      />
    );

    await user.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
  });

  it('shows error when submit fails', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn().mockRejectedValue(new Error('Failed to create'));
    const onCancel = vi.fn();

    render(
      <InvestigationForm
        onSubmit={onSubmit}
        onCancel={onCancel}
      />
    );

    await user.type(screen.getByLabelText(/title/i), 'Test Investigation');
    await user.type(screen.getByLabelText(/description/i), 'Test description');
    await user.click(screen.getByRole('button', { name: /create investigation/i }));

    await waitFor(() => {
      expect(screen.getByText(/failed to submit investigation/i)).toBeInTheDocument();
    });
  });

  it('populates form with initial data', () => {
    const onSubmit = vi.fn();
    const onCancel = vi.fn();
    const initialData = {
      title: 'Existing Investigation',
      description: 'Existing description',
      priority: 'high' as const,
      assignee_id: 'user-123'};

    render(
      <InvestigationForm
        onSubmit={onSubmit}
        onCancel={onCancel}
        initialData={initialData}
      />
    );

    expect(screen.getByLabelText(/title/i)).toHaveValue('Existing Investigation');
    expect(screen.getByLabelText(/description/i)).toHaveValue('Existing description');
    expect(screen.getByLabelText(/assignee/i)).toHaveValue('user-123');
  });
});
