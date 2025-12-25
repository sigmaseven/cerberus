import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';
import { ActionForm } from './ActionForm';
import { Action } from '../../types';

// Mock MUI components that might cause issues
let labelText = '';
vi.mock('@mui/material', () => ({
  Dialog: ({ children, open }: { children: React.ReactNode; open: boolean }) => open ? (
    <div data-testid="dialog" role="dialog">
      {children}
    </div>
  ) : null,
  DialogTitle: ({ children }: { children: React.ReactNode }) => <div data-testid="dialog-title">{children}</div>,
  DialogContent: ({ children }: { children: React.ReactNode }) => <div data-testid="dialog-content">{children}</div>,
  DialogActions: ({ children }: { children: React.ReactNode }) => <div data-testid="dialog-actions">{children}</div>,
  TextField: ({ label, placeholder, ...props }: { label?: string; placeholder?: string; [key: string]: unknown }) => (
    <label>
      {label}
      <input
        data-testid={`input-${(label as string)?.toLowerCase().replace(/[^a-z0-9]/g, '-')}`}
        aria-label={label}
        placeholder={placeholder || label}
        {...(props as Record<string, unknown>)}
      />
    </label>
  ),
  Button: ({ children, ...props }: { children: React.ReactNode; [key: string]: unknown }) => <button {...(props as Record<string, unknown>)}>{children}</button>,
  FormControl: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  InputLabel: ({ children }: { children: React.ReactNode }) => {
    labelText = children as string;
    return null;
  },
  Select: ({ children, ...props }: { children: React.ReactNode; name?: string; [key: string]: unknown }) => (
    <label>
      {labelText}
      <select
        data-testid={`select-${(props as { name?: string }).name || 'unnamed'}`}
        aria-label={labelText}
        {...(props as Record<string, unknown>)}
      >
        {children}
      </select>
    </label>
  ),
  MenuItem: ({ children, ...props }: { children: React.ReactNode; [key: string]: unknown }) => <option {...(props as Record<string, unknown>)}>{children}</option>,
  Box: ({ children, ...props }: { children?: React.ReactNode; [key: string]: unknown }) => <div {...(props as Record<string, unknown>)}>{children}</div>,
  Typography: ({ children, ...props }: { children?: React.ReactNode; [key: string]: unknown }) => <div {...(props as Record<string, unknown>)}>{children}</div>,
  Grid: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Alert: ({ children }: { children: React.ReactNode }) => <div>{children}</div>}));

// Mock MUI icons - none needed for ActionForm

const mockOnClose = vi.fn();
const mockOnSubmit = vi.fn();

const defaultProps = {
  open: true,
  onClose: mockOnClose,
  onSubmit: mockOnSubmit,
  title: 'Create Action'};

describe('ActionForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders form with default values', () => {
    render(<ActionForm {...defaultProps} />);

    expect(screen.getByText('Create Action')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Action Name')).toBeInTheDocument();
    expect(screen.getByText('Action Type')).toBeInTheDocument();
    expect(screen.getByText('Configuration')).toBeInTheDocument();
  });

  it('renders with initial data', () => {
    const initialData: Partial<Action> = {
      id: 'test-action',
      type: 'email',
      config: {
        smtp_server: 'smtp.example.com',
        to: 'admin@example.com'
      }
    };

    render(<ActionForm {...defaultProps} initialData={initialData} />);

    expect(screen.getByDisplayValue('test-action')).toBeInTheDocument();
    expect(screen.getByText('Email Notification')).toBeInTheDocument();
  });

  it('validates required fields', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    const submitButton = screen.getByRole('button', { name: /Save Action/i });
    await user.click(submitButton);

    // Should not submit with empty required fields
    expect(mockOnSubmit).not.toHaveBeenCalled();
  });

  it('renders webhook configuration fields', async () => {
    render(<ActionForm {...defaultProps} />);

    // Default is webhook, so fields should be visible
    expect(screen.getByLabelText('Webhook URL')).toBeInTheDocument();
    expect(screen.getByText('Method')).toBeInTheDocument();
    expect(screen.getByLabelText('Headers (JSON)')).toBeInTheDocument();
  });

  it('renders jira configuration fields when type changes', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Change to Jira
    const typeSelect = screen.getByText('Action Type').nextElementSibling;
    await user.click(typeSelect);
    const jiraOption = screen.getByText('Jira Ticket');
    await user.click(jiraOption);

    await waitFor(() => {
      expect(screen.getByLabelText(/Jira Base URL/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/Username\/Email/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/API Token/i)).toBeInTheDocument();
    });
  });

  it('renders slack configuration fields when type changes', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Change to Slack
    const typeSelect = screen.getByText('Action Type').nextElementSibling;
    await user.click(typeSelect);
    const slackOption = screen.getByText('Slack Message');
    await user.click(slackOption);

    await waitFor(() => {
      expect(screen.getByLabelText(/Slack Webhook URL/i)).toBeInTheDocument();
    });
  });

  it('renders email configuration fields when type changes', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Change to Email
    const typeSelect = screen.getByText('Action Type').nextElementSibling;
    await user.click(typeSelect);
    const emailOption = screen.getByText('Email Notification');
    await user.click(emailOption);

    await waitFor(() => {
      expect(screen.getByLabelText(/SMTP Server/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/Port/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/Username/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/Password/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/To Address/i)).toBeInTheDocument();
    });
  });

  it('changes configuration template when type changes', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Fill webhook URL
    const urlInput = screen.getByLabelText(/Webhook URL/i);
    await user.type(urlInput, 'https://example.com/webhook');

    // Change to email
    const typeSelect = screen.getByText('Action Type').nextElementSibling;
    await user.click(typeSelect);
    const emailOption = screen.getByText('Email Notification');
    await user.click(emailOption);

    await waitFor(() => {
      // Webhook URL should be cleared and email fields should appear
      expect(urlInput).not.toBeInTheDocument();
      expect(screen.getByLabelText(/SMTP Server/i)).toBeInTheDocument();
    });
  });

  it('submits webhook action with valid data', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Fill required fields
    await user.type(screen.getByLabelText(/Action Name/i), 'Test Webhook Action');
    await user.type(screen.getByLabelText(/Webhook URL/i), 'https://example.com/webhook');

    // Submit form
    const submitButton = screen.getByRole('button', { name: /Save Action/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith({
        name: 'Test Webhook Action',
        type: 'webhook',
        config: {
          url: 'https://example.com/webhook',
          method: 'POST',
          headers: {}}
      });
      expect(mockOnClose).toHaveBeenCalled();
    });
  });

  it('submits email action with valid data', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Change to email
    const typeSelect = screen.getByText('Action Type').nextElementSibling;
    await user.click(typeSelect);
    const emailOption = screen.getByText('Email Notification');
    await user.click(emailOption);

    await waitFor(() => {
      expect(screen.getByLabelText(/SMTP Server/i)).toBeInTheDocument();
    });

    // Fill required fields
    await user.type(screen.getByLabelText(/Action Name/i), 'Test Email Action');
    await user.type(screen.getByLabelText(/SMTP Server/i), 'smtp.example.com');
    await user.type(screen.getByLabelText(/Username/i), 'user@example.com');
    await user.type(screen.getByLabelText(/Password/i), 'password123');
    await user.type(screen.getByLabelText(/To Address/i), 'admin@example.com');

    // Submit form
    const submitButton = screen.getByRole('button', { name: /Save Action/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith({
        name: 'Test Email Action',
        type: 'email',
        config: {
          smtp_server: 'smtp.example.com',
          port: 587,
          username: 'user@example.com',
          password: 'password123',
          from: '',
          to: 'admin@example.com'}
      });
    });
  });

  it('submits jira action with valid data', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Change to Jira
    const typeSelect = screen.getByText('Action Type').nextElementSibling;
    await user.click(typeSelect);
    const jiraOption = screen.getByText('Jira Ticket');
    await user.click(jiraOption);

    await waitFor(() => {
      expect(screen.getByLabelText(/Jira Base URL/i)).toBeInTheDocument();
    });

    // Fill required fields
    await user.type(screen.getByLabelText(/Action Name/i), 'Test Jira Action');
    await user.type(screen.getByLabelText(/Jira Base URL/i), 'https://company.atlassian.net');
    await user.type(screen.getByLabelText(/Username\/Email/i), 'user@company.com');
    await user.type(screen.getByLabelText(/API Token/i), 'token123');
    await user.type(screen.getByLabelText(/Project Key/i), 'PROJ');

    // Submit form
    const submitButton = screen.getByRole('button', { name: /Save Action/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith({
        name: 'Test Jira Action',
        type: 'jira',
        config: {
          base_url: 'https://company.atlassian.net',
          username: 'user@company.com',
          token: 'token123',
          project: 'PROJ'}
      });
    });
  });

  it('submits slack action with valid data', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Change to Slack
    const typeSelect = screen.getByText('Action Type').nextElementSibling;
    await user.click(typeSelect);
    const slackOption = screen.getByText('Slack Message');
    await user.click(slackOption);

    await waitFor(() => {
      expect(screen.getByLabelText(/Slack Webhook URL/i)).toBeInTheDocument();
    });

    // Fill required fields
    await user.type(screen.getByLabelText(/Action Name/i), 'Test Slack Action');
    await user.type(screen.getByLabelText(/Slack Webhook URL/i), 'https://hooks.slack.com/services/...');

    // Submit form
    const submitButton = screen.getByRole('button', { name: /Save Action/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith({
        name: 'Test Slack Action',
        type: 'slack',
        config: {
          webhook_url: 'https://hooks.slack.com/services/...'}
      });
    });
  });

  it('shows JSON preview', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Fill some data
    await user.type(screen.getByLabelText(/Action Name/i), 'Test Action');
    await user.type(screen.getByLabelText(/Webhook URL/i), 'https://example.com');

    // Click preview button
    const previewButton = screen.getByRole('button', { name: /Show JSON Preview/i });
    await user.click(previewButton);

    await waitFor(() => {
      expect(screen.getByText('JSON Preview:')).toBeInTheDocument();
      expect(screen.getByText(/"name": "Test Action"/)).toBeInTheDocument();
      expect(screen.getByText(/"type": "webhook"/)).toBeInTheDocument();
    });
  });

  it('closes dialog on cancel', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    const cancelButton = screen.getByRole('button', { name: /Cancel/i });
    await user.click(cancelButton);

    expect(mockOnClose).toHaveBeenCalled();
  });

  it('handles method selection for webhook', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    const methodSelect = screen.getByLabelText(/Method/i);
    await user.click(methodSelect);

    const putOption = screen.getByText('PUT');
    await user.click(putOption);

    expect(methodSelect).toHaveTextContent('PUT');
  });

  it('handles port input for email', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Change to email
    const typeSelect = screen.getByText('Action Type').nextElementSibling;
    await user.click(typeSelect);
    const emailOption = screen.getByText('Email Notification');
    await user.click(emailOption);

    await waitFor(() => {
      const portInputs = screen.getAllByLabelText(/Port/i);
      expect(portInputs.length).toBeGreaterThan(0);
    });
  });

  it('displays security warning', () => {
    render(<ActionForm {...defaultProps} />);

    expect(screen.getByText(/Action configurations contain sensitive information/)).toBeInTheDocument();
  });

  it('handles initial data with different action types', () => {
    const initialData: Partial<Action> = {
      id: 'slack-action',
      type: 'slack',
      config: {
        webhook_url: 'https://hooks.slack.com/test'
      }
    };

    render(<ActionForm {...defaultProps} initialData={initialData} />);

    expect(screen.getByDisplayValue('slack-action')).toBeInTheDocument();
    expect(screen.getByDisplayValue('https://hooks.slack.com/test')).toBeInTheDocument();
  });

  it('validates action type enum', async () => {
    const user = userEvent.setup();
    render(<ActionForm {...defaultProps} />);

    // Fill name but leave type as invalid (though it should default to webhook)
    await user.type(screen.getByLabelText(/Action Name/i), 'Test Action');

    const submitButton = screen.getByRole('button', { name: /Save Action/i });
    await user.click(submitButton);

    // Should submit successfully with default webhook type
    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalled();
    });
  });
});