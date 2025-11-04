import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';
import { RuleForm } from './RuleForm';
import { Rule } from '../../types';

// Mock MUI components that might cause issues
vi.mock('@mui/material', () => ({
  Dialog: ({ children, open }: any) => open ? (
    <div data-testid="dialog" role="dialog">
      {children}
    </div>
  ) : null,
  DialogTitle: ({ children }: any) => <div data-testid="dialog-title">{children}</div>,
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogActions: ({ children }: any) => <div data-testid="dialog-actions">{children}</div>,
  TextField: ({ label, error, helperText, fullWidth, multiline, ...props }: any) => (
    <input aria-label={label} placeholder={label} {...props} />
  ),
  Button: ({ children, startIcon, ...props }: any) => <button {...props}>{children}</button>,
  FormControl: ({ children }: any) => <div>{children}</div>,
  InputLabel: ({ children }: any) => <label>{children}</label>,
  Select: ({ children, value, onChange, ...props }: any) => (
    <select value={value} onChange={onChange} {...props}>
      {children}
    </select>
  ),
  MenuItem: ({ children, value, ...props }: any) => <option value={value} {...props}>{children}</option>,
  Box: ({ children, component, sx, ...props }: any) => <div {...props}>{children}</div>,
  Typography: ({ children, variant, gutterBottom, ...props }: any) => <div {...props}>{children}</div>,
  IconButton: ({ children, ...props }: any) => <button {...props}>{children}</button>,
  Chip: ({ label }: any) => <span>{label}</span>,
  Grid: ({ children, container, item, spacing, alignItems, xs, sm, ...props }: any) => <div>{children}</div>,
  Accordion: ({ children }: any) => <div>{children}</div>,
  AccordionSummary: ({ children, expandIcon }: any) => <div>{children}</div>,
  AccordionDetails: ({ children }: any) => <div>{children}</div>,
}));

// Mock MUI icons
vi.mock('@mui/icons-material', () => ({
  Add: () => <span>+</span>,
  Delete: () => <span>-</span>,
  ExpandMore: () => <span>v</span>,
}));

const mockOnClose = vi.fn();
const mockOnSubmit = vi.fn();

const defaultProps = {
  open: true,
  onClose: mockOnClose,
  onSubmit: mockOnSubmit,
  title: 'Create Rule',
};

describe('RuleForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders form with default values', () => {
    render(<RuleForm {...defaultProps} />);

    expect(screen.getByText('Create Rule')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Rule Name/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Description/i)).toBeInTheDocument();
    expect(screen.getByText('Enabled')).toBeInTheDocument();
  });

  it('renders with initial data', () => {
    const initialData: Partial<Rule> = {
      name: 'Test Rule',
      description: 'Test Description',
      severity: 'High',
      enabled: false,
      conditions: [
        { field: 'event_type', operator: 'equals', value: 'login', logic: 'AND' }
      ],
      actions: [
        { type: 'webhook', config: { url: 'https://example.com' } }
      ]
    };

    render(<RuleForm {...defaultProps} initialData={initialData} />);

    expect(screen.getByDisplayValue('Test Rule')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Test Description')).toBeInTheDocument();
  });

  it('validates required fields', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    // Should not submit with empty required fields
    expect(mockOnSubmit).not.toHaveBeenCalled();
  });

  it('allows adding and removing conditions', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    // Initially should have 1 condition
    expect(screen.getAllByText('Conditions (1)')).toHaveLength(1);

    // Add condition
    const addConditionButton = screen.getByRole('button', { name: /Add Condition/i });
    await user.click(addConditionButton);

    await waitFor(() => {
      expect(screen.getAllByText('Conditions (2)')).toHaveLength(1);
    });

    // Remove condition (should be disabled when only 1 left)
    const removeButtons = screen.getAllByRole('button', { name: '' }); // Delete icons
    expect(removeButtons[0]).toBeDisabled();
  });

  it('allows adding and removing actions', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    // Initially should have 0 actions (regression test: actions are optional)
    expect(screen.getAllByText('Actions (0)')).toHaveLength(1);

    // Add action
    const addActionButton = screen.getByRole('button', { name: /Add Action/i });
    await user.click(addActionButton);

    await waitFor(() => {
      expect(screen.getAllByText('Actions (1)')).toHaveLength(1);
    });

    // Add another action
    await user.click(addActionButton);

    await waitFor(() => {
      expect(screen.getAllByText('Actions (2)')).toHaveLength(1);
    });

    // Remove action buttons should always be enabled (no minimum actions required)
    const removeButtons = screen.getAllByRole('button', { name: '' }); // Delete icons
    const actionRemoveButtons = removeButtons.filter(btn => !btn.disabled);
    expect(actionRemoveButtons.length).toBeGreaterThan(0);
  });

  it('submits form with valid data', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    // Fill required fields
    await user.type(screen.getByPlaceholderText(/Rule Name/i), 'Test Rule');
    await user.type(screen.getByPlaceholderText(/Description/i), 'Test Description');

    // Submit form
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith({
        name: 'Test Rule',
        description: 'Test Description',
        severity: 'Medium',
        enabled: true,
        conditions: [
          { field: 'event_type', operator: 'equals', value: '', logic: 'AND' }
        ],
        actions: [] // Regression test: actions are optional, defaults to empty array
      });
    });
  });

  it('shows JSON preview', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    // Fill some data
    await user.type(screen.getByPlaceholderText(/Rule Name/i), 'Test Rule');
    await user.type(screen.getByPlaceholderText(/Description/i), 'Test Description');

    // Click preview button
    const previewButton = screen.getByRole('button', { name: /Show JSON Preview/i });
    await user.click(previewButton);

    await waitFor(() => {
      expect(screen.getByText('JSON Preview:')).toBeInTheDocument();
      expect(screen.getByText(/"name": "Test Rule"/)).toBeInTheDocument();
    });
  });

  it('closes dialog on cancel', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    const cancelButton = screen.getByRole('button', { name: /Cancel/i });
    await user.click(cancelButton);

    expect(mockOnClose).toHaveBeenCalled();
  });

  it('handles condition field changes', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    // Find condition value input
    const valueInputs = screen.getAllByLabelText('Value');
    await user.type(valueInputs[0], 'test_value');

    expect(valueInputs[0]).toHaveValue('test_value');
  });

  it('handles action config changes', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    // Find action config input
    const configInputs = screen.getAllByPlaceholderText('{"url": "https://example.com/webhook"}');
    await user.type(configInputs[0], '{"url": "https://test.com"}');

    expect(configInputs[0]).toHaveValue('{"url": "https://test.com"}');
  });

  it('validates minimum conditions and actions', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    // Try to submit with empty conditions/actions arrays (but form has defaults)
    await user.type(screen.getByPlaceholderText(/Rule Name/i), 'Test Rule');
    await user.type(screen.getByPlaceholderText(/Description/i), 'Test Description');

    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    // Should succeed since defaults provide minimum requirements
    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalled();
    });
  });

  it('handles severity selection', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    const severitySelect = screen.getByLabelText(/Severity/i);
    await user.click(severitySelect);

    const highOption = screen.getByText('High');
    await user.click(highOption);

    expect(severitySelect).toHaveTextContent('High');
  });

  it('toggles enabled checkbox', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    const checkbox = screen.getByLabelText('Enabled');
    expect(checkbox).toBeChecked();

    await user.click(checkbox);
    expect(checkbox).not.toBeChecked();
  });

  // REGRESSION TESTS for bugs found during development

  it('REGRESSION: resets form when dialog opens with new initialData', async () => {
    const initialData1: Partial<Rule> = {
      id: 'rule1',
      name: 'First Rule',
      description: 'First Description',
      severity: 'High',
      enabled: true,
      version: 1,
      conditions: [{ field: 'event_type', operator: 'equals', value: 'login', logic: 'AND' }],
      actions: []
    };

    const { rerender } = render(<RuleForm {...defaultProps} open={false} initialData={initialData1} />);

    // Open dialog with first rule
    rerender(<RuleForm {...defaultProps} open={true} initialData={initialData1} />);
    expect(screen.getByDisplayValue('First Rule')).toBeInTheDocument();

    // Close dialog
    rerender(<RuleForm {...defaultProps} open={false} initialData={initialData1} />);

    // Open dialog with different rule
    const initialData2: Partial<Rule> = {
      id: 'rule2',
      name: 'Second Rule',
      description: 'Second Description',
      severity: 'Low',
      enabled: false,
      version: 2,
      conditions: [{ field: 'source_ip', operator: 'contains', value: '192.168', logic: 'AND' }],
      actions: []
    };

    rerender(<RuleForm {...defaultProps} open={true} initialData={initialData2} />);

    // Form should reset to show second rule data
    await waitFor(() => {
      expect(screen.getByDisplayValue('Second Rule')).toBeInTheDocument();
      expect(screen.getByDisplayValue('Second Description')).toBeInTheDocument();
    });
  });

  it('REGRESSION: handles undefined actions array during submit', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    // Fill required fields without adding any actions
    await user.type(screen.getByPlaceholderText(/Rule Name/i), 'Rule Without Actions');
    await user.type(screen.getByPlaceholderText(/Description/i), 'Testing optional actions');

    // Submit form
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    // Should successfully submit with empty actions array
    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Rule Without Actions',
          description: 'Testing optional actions',
          actions: []
        })
      );
    });
  });

  it('REGRESSION: parses JSON config strings in actions on submit', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    // Fill required fields
    await user.type(screen.getByPlaceholderText(/Rule Name/i), 'Rule With Webhook');
    await user.type(screen.getByPlaceholderText(/Description/i), 'Testing JSON parsing');

    // Add an action
    const addActionButton = screen.getByRole('button', { name: /Add Action/i });
    await user.click(addActionButton);

    await waitFor(() => {
      expect(screen.getAllByText('Actions (1)')).toHaveLength(1);
    });

    // Fill in action config as JSON string
    const configInput = screen.getByPlaceholderText('{"url": "https://example.com/webhook"}');
    await user.clear(configInput);
    await user.type(configInput, '{"url": "https://test.com/webhook"}');

    // Submit form
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    // Config should be parsed from string to object
    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          actions: [
            expect.objectContaining({
              type: 'webhook',
              config: { url: 'https://test.com/webhook' } // Should be parsed object, not string
            })
          ]
        })
      );
    });
  });

  it('REGRESSION: allows removing all actions', async () => {
    const user = userEvent.setup();

    const initialData: Partial<Rule> = {
      name: 'Rule With Actions',
      description: 'Has actions initially',
      severity: 'Medium',
      enabled: true,
      version: 1,
      conditions: [{ field: 'event_type', operator: 'equals', value: 'test', logic: 'AND' }],
      actions: [
        { type: 'webhook', config: { url: 'https://example.com' } },
        { type: 'email', config: { smtp_server: 'smtp.example.com', port: 587, from: 'a@b.com', to: 'c@d.com' } }
      ]
    };

    render(<RuleForm {...defaultProps} initialData={initialData} />);

    // Should show 2 actions
    await waitFor(() => {
      expect(screen.getAllByText('Actions (2)')).toHaveLength(1);
    });

    // Remove both actions
    const removeButtons = screen.getAllByRole('button', { name: '' }).filter(btn => !btn.disabled);
    await user.click(removeButtons[0]);

    await waitFor(() => {
      expect(screen.getAllByText('Actions (1)')).toHaveLength(1);
    });

    const removeButtons2 = screen.getAllByRole('button', { name: '' }).filter(btn => !btn.disabled);
    await user.click(removeButtons2[0]);

    await waitFor(() => {
      expect(screen.getAllByText('Actions (0)')).toHaveLength(1);
    });

    // Submit with 0 actions should work
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          actions: []
        })
      );
    });
  });

  // REGRESSION TESTS for form submission bug (2025-11-04)
  // Bug: Form validation failed when editing rules with numeric values in conditions
  // Root cause: Zod schema only accepted strings, but backend returns numbers for some fields

  it('REGRESSION: accepts numeric values in condition fields', async () => {
    const user = userEvent.setup();

    const initialData: Partial<Rule> = {
      name: 'Windows Failed Login',
      description: 'Detects failed login attempts',
      severity: 'Medium',
      enabled: true,
      version: 1,
      conditions: [
        { field: 'event_type', operator: 'equals', value: 'security', logic: 'AND' },
        { field: 'fields.event_id', operator: 'equals', value: 4625, logic: 'AND' } // NUMERIC VALUE
      ],
      actions: []
    };

    render(<RuleForm {...defaultProps} initialData={initialData} />);

    // Form should load without errors
    await waitFor(() => {
      expect(screen.getByDisplayValue('Windows Failed Login')).toBeInTheDocument();
    });

    // Submit should work with numeric values
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Windows Failed Login',
          conditions: expect.arrayContaining([
            expect.objectContaining({ value: 'security' }),
            expect.objectContaining({ value: 4625 }) // Numeric value should be preserved
          ])
        })
      );
    });
  });

  it('REGRESSION: accepts string values in condition fields', async () => {
    const user = userEvent.setup();

    const initialData: Partial<Rule> = {
      name: 'String Value Rule',
      description: 'Rule with string condition values',
      severity: 'Low',
      enabled: true,
      version: 1,
      conditions: [
        { field: 'event_type', operator: 'contains', value: 'login', logic: 'AND' },
        { field: 'source_ip', operator: 'starts_with', value: '192.168', logic: 'AND' }
      ],
      actions: []
    };

    render(<RuleForm {...defaultProps} initialData={initialData} />);

    // Form should load without errors
    await waitFor(() => {
      expect(screen.getByDisplayValue('String Value Rule')).toBeInTheDocument();
    });

    // Submit should work with string values
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'String Value Rule',
          conditions: expect.arrayContaining([
            expect.objectContaining({ value: 'login' }),
            expect.objectContaining({ value: '192.168' })
          ])
        })
      );
    });
  });

  it('REGRESSION: accepts mixed numeric and string values in different conditions', async () => {
    const user = userEvent.setup();

    const initialData: Partial<Rule> = {
      name: 'Mixed Value Types Rule',
      description: 'Rule with both numeric and string condition values',
      severity: 'High',
      enabled: true,
      version: 1,
      conditions: [
        { field: 'event_type', operator: 'equals', value: 'security', logic: 'AND' },
        { field: 'fields.event_id', operator: 'equals', value: 4740, logic: 'AND' },
        { field: 'fields.user', operator: 'contains', value: 'admin', logic: 'OR' },
        { field: 'fields.port', operator: 'greater_than', value: 1024, logic: 'AND' }
      ],
      actions: []
    };

    render(<RuleForm {...defaultProps} initialData={initialData} />);

    // Form should load without errors
    await waitFor(() => {
      expect(screen.getByDisplayValue('Mixed Value Types Rule')).toBeInTheDocument();
    });

    // Submit should work with mixed value types
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Mixed Value Types Rule',
          conditions: expect.arrayContaining([
            expect.objectContaining({ field: 'event_type', value: 'security' }),
            expect.objectContaining({ field: 'fields.event_id', value: 4740 }),
            expect.objectContaining({ field: 'fields.user', value: 'admin' }),
            expect.objectContaining({ field: 'fields.port', value: 1024 })
          ])
        })
      );
    });
  });

  it('REGRESSION: validates empty string values are rejected', async () => {
    const user = userEvent.setup();

    render(<RuleForm {...defaultProps} />);

    // Fill required fields
    await user.type(screen.getByPlaceholderText(/Rule Name/i), 'Test Rule');
    await user.type(screen.getByPlaceholderText(/Description/i), 'Test Description');

    // Leave condition value empty (default is empty string)
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    // Should not submit with empty condition value
    await waitFor(() => {
      expect(mockOnSubmit).not.toHaveBeenCalled();
    });
  });

  it('REGRESSION: Select components work with Controller (severity)', async () => {
    const user = userEvent.setup();
    render(<RuleForm {...defaultProps} />);

    // Severity select should be controlled by react-hook-form
    const severitySelect = screen.getByLabelText(/Severity/i);

    // Should have default value
    expect(severitySelect).toHaveValue('Medium');

    // Should be changeable
    await user.selectOptions(severitySelect, 'Critical');
    expect(severitySelect).toHaveValue('Critical');

    // Fill other required fields and submit
    await user.type(screen.getByPlaceholderText(/Rule Name/i), 'Critical Rule');
    await user.type(screen.getByPlaceholderText(/Description/i), 'A critical severity rule');

    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          severity: 'Critical'
        })
      );
    });
  });

  it('REGRESSION: Select components work with Controller (condition operators)', async () => {
    const user = userEvent.setup();

    const initialData: Partial<Rule> = {
      name: 'Operator Test Rule',
      description: 'Testing operator selects',
      severity: 'Medium',
      enabled: true,
      version: 1,
      conditions: [
        { field: 'event_type', operator: 'equals', value: 'test', logic: 'AND' },
        { field: 'source_ip', operator: 'contains', value: '192', logic: 'OR' }
      ],
      actions: []
    };

    render(<RuleForm {...defaultProps} initialData={initialData} />);

    // Operators should be loaded from initialData
    await waitFor(() => {
      const operatorSelects = screen.getAllByLabelText(/Operator/i);
      expect(operatorSelects[0]).toHaveValue('equals');
      expect(operatorSelects[1]).toHaveValue('contains');
    });

    // Should be changeable
    const operatorSelects = screen.getAllByLabelText(/Operator/i);
    await user.selectOptions(operatorSelects[0], 'regex');
    expect(operatorSelects[0]).toHaveValue('regex');

    // Submit should include updated operator
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          conditions: expect.arrayContaining([
            expect.objectContaining({ operator: 'regex' })
          ])
        })
      );
    });
  });

  it('REGRESSION: form does not submit when validation fails', async () => {
    const user = userEvent.setup();

    const initialData: Partial<Rule> = {
      name: '', // Invalid: empty name
      description: '', // Invalid: empty description
      severity: 'Medium',
      enabled: true,
      version: 1,
      conditions: [
        { field: 'event_type', operator: 'equals', value: '', logic: 'AND' } // Invalid: empty value
      ],
      actions: []
    };

    render(<RuleForm {...defaultProps} initialData={initialData} />);

    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    // Should not call onSubmit due to validation errors
    await waitFor(() => {
      expect(mockOnSubmit).not.toHaveBeenCalled();
    });
  });

  it('REGRESSION: preserves action type when using Controller', async () => {
    const user = userEvent.setup();

    const initialData: Partial<Rule> = {
      name: 'Action Type Test',
      description: 'Testing action type preservation',
      severity: 'Medium',
      enabled: true,
      version: 1,
      conditions: [
        { field: 'event_type', operator: 'equals', value: 'test', logic: 'AND' }
      ],
      actions: [
        { type: 'webhook', config: { url: 'https://example.com' } },
        { type: 'slack', config: { webhook_url: 'https://slack.com/webhook' } },
        { type: 'jira', config: { base_url: 'https://jira.com', project: 'PROJ' } }
      ]
    };

    render(<RuleForm {...defaultProps} initialData={initialData} />);

    // Action types should be loaded correctly
    await waitFor(() => {
      expect(screen.getAllByText('Actions (3)')).toHaveLength(1);
      const actionTypeSelects = screen.getAllByLabelText(/Action Type/i);
      expect(actionTypeSelects[0]).toHaveValue('webhook');
      expect(actionTypeSelects[1]).toHaveValue('slack');
      expect(actionTypeSelects[2]).toHaveValue('jira');
    });

    // Change first action type
    const actionTypeSelects = screen.getAllByLabelText(/Action Type/i);
    await user.selectOptions(actionTypeSelects[0], 'email');
    expect(actionTypeSelects[0]).toHaveValue('email');

    // Submit should include updated action type
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          actions: expect.arrayContaining([
            expect.objectContaining({ type: 'email' }),
            expect.objectContaining({ type: 'slack' }),
            expect.objectContaining({ type: 'jira' })
          ])
        })
      );
    });
  });
});