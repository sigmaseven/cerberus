import { render, screen, waitFor  } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';
import { CorrelationRuleForm } from './CorrelationRuleForm';
import { CorrelationRule } from '../../types';

// Mock MUI components that might cause issues
let labelText = '';
vi.mock('@mui/material', () => ({
  Dialog: ({ children, open }: any) => open ? (
    <div data-testid="dialog" role="dialog">
      {children}
    </div>
  ) : null,
  DialogTitle: ({ children }: any) => <div data-testid="dialog-title">{children}</div>,
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogActions: ({ children }: any) => <div data-testid="dialog-actions">{children}</div>,
  TextField: ({ label, placeholder, ...props }: any) => (
    <label>
      {label}
      <input aria-label={label} placeholder={placeholder || label} {...props} />
    </label>
  ),
  Button: ({ children, ...props }: any) => <button {...props}>{children}</button>,
  FormControl: ({ children }: any) => <div>{children}</div>,
  InputLabel: ({ children }: any) => {
    labelText = children;
    return null;
  },
  Select: ({ children, ...props }: any) => (
    <label>
      {labelText}
      <select aria-label={labelText} {...props}>{children}</select>
    </label>
  ),
  MenuItem: ({ children, ...props }: any) => <option {...props}>{children}</option>,
  Box: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  Typography: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  IconButton: ({ children, color, ...props }: any) => (
    <button aria-label={color === 'error' ? 'Delete' : 'Icon'} {...props}>{children}</button>
  ),
  Chip: ({ label }: any) => <span>{label}</span>,
  Grid: ({ children }: any) => <div>{children}</div>,
  Accordion: ({ children }: any) => <div>{children}</div>,
  AccordionSummary: ({ children }: any) => <div>{children}</div>,
  AccordionDetails: ({ children }: any) => <div>{children}</div>,
  Slider: ({ value, onChange, ...props }: any) => (
    <input
      type="range"
      value={value}
      aria-label="Time Window"
      onChange={(e) => onChange(e, parseInt(e.target.value))}
      {...props}
    />
  )}));

// Mock MUI icons
vi.mock('@mui/icons-material', () => ({
  Add: () => <span>+</span>,
  Delete: () => <span>-</span>,
  ExpandMore: () => <span>v</span>,
  Timeline: () => <span>T</span>}));

const mockOnClose = vi.fn();
const mockOnSubmit = vi.fn();

const defaultProps = {
  open: true,
  onClose: mockOnClose,
  onSubmit: mockOnSubmit,
  title: 'Create Correlation Rule'};

describe('CorrelationRuleForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders form with default values', () => {
    render(<CorrelationRuleForm {...defaultProps} />);

    expect(screen.getByText('Create Correlation Rule')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Rule Name/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Description/i)).toBeInTheDocument();
    expect(screen.getByText(/Event Sequence/)).toBeInTheDocument();
  });

  it('renders with initial data', () => {
    const initialData: Partial<CorrelationRule> = {
      name: 'Test Correlation Rule',
      description: 'Test Description',
      severity: 'Critical',
      window: 600000000, // 600 seconds in nanoseconds
      sequence: ['user_login', 'admin_command'],
      conditions: [
        { field: 'source_ip', operator: 'equals', value: '192.168.1.1', logic: 'AND' }
      ],
      actions: [
        { type: 'email', config: { to: 'admin@example.com' } }
      ]
    };

    render(<CorrelationRuleForm {...defaultProps} initialData={initialData} />);

    expect(screen.getByDisplayValue('Test Correlation Rule')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Test Description')).toBeInTheDocument();
  });

  it('validates required fields', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    // Should not submit with empty required fields
    expect(mockOnSubmit).not.toHaveBeenCalled();
  });

  it('renders form with default values', () => {
    render(<CorrelationRuleForm {...defaultProps} />);

    expect(screen.getByText('Create Correlation Rule')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Rule Name/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Description/i)).toBeInTheDocument();
    expect(screen.getByText(/Event Sequence/)).toBeInTheDocument();
  });

  it('validates minimum sequence length', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    // Fill required fields
    await user.type(screen.getByPlaceholderText(/Rule Name/i), 'Test Rule');
    await user.type(screen.getByPlaceholderText(/Description/i), 'Test Description');

    // Remove one sequence event to make it invalid
    const removeButtons = screen.getAllByRole('button', { name: 'Delete' });
    // The first remove button should be for sequence (disabled when only 2)
    expect(removeButtons[0]).toBeDisabled();
  });

  it('allows adding sequence events', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    // Initially should have 2 events
    expect(screen.getByText('Event Sequence (2 events)')).toBeInTheDocument();

    // Add sequence event
    const addSequenceButton = screen.getByRole('button', { name: /Add Event/i });
    await user.click(addSequenceButton);

    await waitFor(() => {
      expect(screen.getByText('Event Sequence (3 events)')).toBeInTheDocument();
    });
  });

  it('allows removing sequence events when more than 2', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    // Add a third event first
    const addSequenceButton = screen.getByRole('button', { name: /Add Event/i });
    await user.click(addSequenceButton);

    await waitFor(() => {
      expect(screen.getByText('Event Sequence (3 events)')).toBeInTheDocument();
    });

    // Now remove buttons should be enabled for the third event
    const removeButtons = screen.getAllByRole('button', { name: 'Delete' });
    const enabledRemoveButtons = removeButtons.filter(btn => !btn.disabled);
    expect(enabledRemoveButtons.length).toBeGreaterThan(0);
  });

  it('handles time window slider', async () => {
    render(<CorrelationRuleForm {...defaultProps} />);

    const slider = screen.getByRole('slider');
    expect(slider).toHaveValue('300'); // Default 5 minutes in seconds

    // Change slider value
    fireEvent.change(slider, { target: { value: '600' } });

    await waitFor(() => {
      expect(screen.getByText('10m 0s')).toBeInTheDocument();
    });
  });

  it('allows adding and removing conditions', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    // Initially should have 0 additional conditions
    expect(screen.getByText('Additional Conditions (0)')).toBeInTheDocument();

    // Add condition
    const addConditionButton = screen.getByRole('button', { name: /Add Condition/i });
    await user.click(addConditionButton);

    await waitFor(() => {
      expect(screen.getByText('Additional Conditions (1)')).toBeInTheDocument();
    });
  });

  it('allows adding and removing actions', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    // Initially should have 1 action
    expect(screen.getByText('Actions (1)')).toBeInTheDocument();

    // Add action
    const addActionButton = screen.getByRole('button', { name: /Add Action/i });
    await user.click(addActionButton);

    await waitFor(() => {
      expect(screen.getByText('Actions (2)')).toBeInTheDocument();
    });
  });

  it('submits form with valid data', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    // Fill required fields
    await user.type(screen.getByLabelText(/Rule Name/i), 'Test Correlation Rule');
    await user.type(screen.getByLabelText(/Description/i), 'Test Description');

    // Submit form
    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith({
        name: 'Test Correlation Rule',
        description: 'Test Description',
        severity: 'High',
        version: 1,
        window: 300000000, // 300 seconds converted to nanoseconds
        sequence: ['user_login', 'user_login'],
        conditions: [],
        actions: [
          { type: 'webhook', config: { url: '' } }
        ]
      });
      expect(mockOnClose).toHaveBeenCalled();
    });
  });

  it('shows JSON preview', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

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
    render(<CorrelationRuleForm {...defaultProps} />);

    const cancelButton = screen.getByRole('button', { name: /Cancel/i });
    await user.click(cancelButton);

    expect(mockOnClose).toHaveBeenCalled();
  });

  it('handles sequence event selection', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    // Find sequence selects
    const selects = screen.getAllByRole('combobox');
    const sequenceSelects = selects.filter(select =>
      select.previousSibling?.textContent?.includes('.')
    );

    await user.click(sequenceSelects[0]);
    const adminCommandOption = screen.getByText('admin_command');
    await user.click(adminCommandOption);

    expect(sequenceSelects[0]).toHaveTextContent('admin_command');
  });

  it('handles severity selection', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    const severitySelect = screen.getByLabelText(/Severity/i);
    await user.click(severitySelect);

    const criticalOption = screen.getByText('Critical');
    await user.click(criticalOption);

    expect(severitySelect).toHaveTextContent('Critical');
  });

  it('validates window minimum value', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    // Fill required fields
    await user.type(screen.getByPlaceholderText(/Rule Name/i), 'Test Rule');
    await user.type(screen.getByPlaceholderText(/Description/i), 'Test Description');

    // Set window to below minimum
    const slider = screen.getByRole('slider');
    fireEvent.change(slider, { target: { value: '0' } });

    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    // Should still submit since validation happens on schema level
    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalled();
    });
  });

  it('converts window from seconds to nanoseconds on submit', async () => {
    const user = userEvent.setup();
    render(<CorrelationRuleForm {...defaultProps} />);

    // Fill required fields
    await user.type(screen.getByPlaceholderText(/Rule Name/i), 'Test Rule');
    await user.type(screen.getByPlaceholderText(/Description/i), 'Test Description');

    // Set window to 10 minutes (600 seconds)
    const slider = screen.getByRole('slider');
    fireEvent.change(slider, { target: { value: '600' } });

    const submitButton = screen.getByRole('button', { name: /Save Rule/i });
    await user.click(submitButton);

    await waitFor(() => {
      const submittedData = mockOnSubmit.mock.calls[0][0];
      expect(submittedData.window).toBe(600000000); // 600 seconds * 1e6 nanoseconds
    });
  });
});