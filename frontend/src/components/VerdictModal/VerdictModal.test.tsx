import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { VerdictModal } from './index';

describe('VerdictModal', () => {
  it('renders modal when open', () => {
    const onClose = vi.fn();
    const onSubmit = vi.fn();

    render(
      <VerdictModal
        open={true}
        onClose={onClose}
        onSubmit={onSubmit}
        investigationId="inv-123"
        investigationTitle="Test Investigation"
      />
    );

    expect(screen.getByText(/close investigation/i)).toBeInTheDocument();
    expect(screen.getByText(/inv-123/i)).toBeInTheDocument();
    expect(screen.getByText(/test investigation/i)).toBeInTheDocument();
  });

  it('does not render modal when closed', () => {
    const onClose = vi.fn();
    const onSubmit = vi.fn();

    render(
      <VerdictModal
        open={false}
        onClose={onClose}
        onSubmit={onSubmit}
        investigationId="inv-123"
        investigationTitle="Test Investigation"
      />
    );

    expect(screen.queryByText(/close investigation/i)).not.toBeInTheDocument();
  });

  it('shows all verdict options', () => {
    const onClose = vi.fn();
    const onSubmit = vi.fn();

    render(
      <VerdictModal
        open={true}
        onClose={onClose}
        onSubmit={onSubmit}
        investigationId="inv-123"
        investigationTitle="Test Investigation"
      />
    );

    expect(screen.getByText(/true positive/i)).toBeInTheDocument();
    expect(screen.getByText(/false positive/i)).toBeInTheDocument();
    expect(screen.getByText(/inconclusive/i)).toBeInTheDocument();
  });

  it('shows resolution category options', () => {
    const onClose = vi.fn();
    const onSubmit = vi.fn();

    render(
      <VerdictModal
        open={true}
        onClose={onClose}
        onSubmit={onSubmit}
        investigationId="inv-123"
        investigationTitle="Test Investigation"
      />
    );

    expect(screen.getByText(/malware infection/i)).toBeInTheDocument();
    expect(screen.getByText(/unauthorized access/i)).toBeInTheDocument();
    expect(screen.getByText(/data exfiltration/i)).toBeInTheDocument();
    expect(screen.getByText(/phishing attack/i)).toBeInTheDocument();
  });

  it('requires summary before submitting', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onSubmit = vi.fn();

    render(
      <VerdictModal
        open={true}
        onClose={onClose}
        onSubmit={onSubmit}
        investigationId="inv-123"
        investigationTitle="Test Investigation"
      />
    );

    const submitButton = screen.getByRole('button', { name: /close investigation/i });

    // Should be disabled without summary
    expect(submitButton).toBeDisabled();
  });

  it('submits verdict with required fields', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onSubmit = vi.fn().mockResolvedValue(undefined);

    render(
      <VerdictModal
        open={true}
        onClose={onClose}
        onSubmit={onSubmit}
        investigationId="inv-123"
        investigationTitle="Test Investigation"
      />
    );

    // Select resolution category
    await user.click(screen.getByText(/malware infection/i));

    // Fill in summary
    const summaryInput = screen.getByLabelText(/investigation summary/i);
    await user.type(summaryInput, 'Investigation completed successfully');

    // Submit
    const submitButton = screen.getByRole('button', { name: /close investigation/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          verdict: 'true_positive',
          resolution_category: 'Malware Infection',
          summary: 'Investigation completed successfully'})
      );
    });
  });

  it('includes ML feedback when provided', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onSubmit = vi.fn().mockResolvedValue(undefined);

    render(
      <VerdictModal
        open={true}
        onClose={onClose}
        onSubmit={onSubmit}
        investigationId="inv-123"
        investigationTitle="Test Investigation"
      />
    );

    // Select resolution category
    await user.click(screen.getByText(/malware infection/i));

    // Fill in summary
    await user.type(screen.getByLabelText(/investigation summary/i), 'Test summary');

    // Enable ML feedback
    const mlCheckbox = screen.getByRole('checkbox', { name: /provide ml feedback/i });
    await user.click(mlCheckbox);

    // Fill ML feedback
    const feedbackInput = screen.getByLabelText(/additional feedback/i);
    await user.type(feedbackInput, 'ML detection was accurate');

    // Submit
    await user.click(screen.getByRole('button', { name: /close investigation/i }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          ml_feedback: expect.objectContaining({
            was_correct: true,
            feedback_notes: 'ML detection was accurate'})})
      );
    });
  });

  it('shows error when submit fails', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onSubmit = vi.fn().mockRejectedValue(new Error('Server error'));

    render(
      <VerdictModal
        open={true}
        onClose={onClose}
        onSubmit={onSubmit}
        investigationId="inv-123"
        investigationTitle="Test Investigation"
      />
    );

    await user.click(screen.getByText(/malware infection/i));
    await user.type(screen.getByLabelText(/investigation summary/i), 'Test summary');
    await user.click(screen.getByRole('button', { name: /close investigation/i }));

    await waitFor(() => {
      expect(screen.getByText(/server error/i)).toBeInTheDocument();
    });
  });

  it('calls onClose when cancel is clicked', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onSubmit = vi.fn();

    render(
      <VerdictModal
        open={true}
        onClose={onClose}
        onSubmit={onSubmit}
        investigationId="inv-123"
        investigationTitle="Test Investigation"
      />
    );

    await user.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onClose).toHaveBeenCalled();
  });

  it('handles affected assets input', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onSubmit = vi.fn().mockResolvedValue(undefined);

    render(
      <VerdictModal
        open={true}
        onClose={onClose}
        onSubmit={onSubmit}
        investigationId="inv-123"
        investigationTitle="Test Investigation"
      />
    );

    await user.click(screen.getByText(/malware infection/i));
    await user.type(screen.getByLabelText(/investigation summary/i), 'Test summary');

    const assetsInput = screen.getByLabelText(/affected assets/i);
    await user.type(assetsInput, 'server-01\nserver-02\n192.168.1.100');

    await user.click(screen.getByRole('button', { name: /close investigation/i }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          affected_assets: ['server-01', 'server-02', '192.168.1.100']})
      );
    });
  });
});
