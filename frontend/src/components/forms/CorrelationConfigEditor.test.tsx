import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CorrelationConfigEditor } from './CorrelationConfigEditor';

describe('CorrelationConfigEditor', () => {
  const mockOnChange = vi.fn();

  const defaultProps = {
    value: {
      type: 'event_count' as const,
      group_by: ['source_ip'],
      timespan: '5m',
      condition: {
        operator: 'gte' as const,
        value: 10,
      },
    },
    onChange: mockOnChange,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Visual Mode', () => {
    it('should render correlation type selector', () => {
      render(<CorrelationConfigEditor {...defaultProps} />);

      expect(screen.getByLabelText(/correlation type/i)).toBeInTheDocument();
    });

    it('should display all correlation type options', async () => {
      const user = userEvent.setup();
      render(<CorrelationConfigEditor {...defaultProps} />);

      const typeSelect = screen.getByLabelText(/correlation type/i);
      await user.click(typeSelect);

      await waitFor(() => {
        expect(screen.getByText(/Event Count/i)).toBeInTheDocument();
        expect(screen.getByText(/Value Count/i)).toBeInTheDocument();
        expect(screen.getByText(/Sequence/i)).toBeInTheDocument();
        expect(screen.getByText(/Temporal/i)).toBeInTheDocument();
        expect(screen.getByText(/Rare Events/i)).toBeInTheDocument();
        expect(screen.getByText(/Statistical/i)).toBeInTheDocument();
        expect(screen.getByText(/Attack Chain/i)).toBeInTheDocument();
      });
    });

    it('should render common fields (group_by, timespan)', () => {
      render(<CorrelationConfigEditor {...defaultProps} />);

      expect(screen.getByLabelText(/group by fields/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/timespan/i)).toBeInTheDocument();
    });

    it('should render event_count specific fields', () => {
      render(<CorrelationConfigEditor {...defaultProps} />);

      expect(screen.getByLabelText(/operator/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/threshold value/i)).toBeInTheDocument();
    });

    it('should render value_count specific fields when type is value_count', async () => {
      const user = userEvent.setup();
      const props = {
        ...defaultProps,
        value: {
          ...defaultProps.value,
          type: 'value_count' as const,
          distinct_field: 'source_ip',
        },
      };

      render(<CorrelationConfigEditor {...props} />);

      expect(screen.getByLabelText(/distinct field/i)).toBeInTheDocument();
    });

    it('should render sequence specific fields when type is sequence', async () => {
      const props = {
        ...defaultProps,
        value: {
          type: 'sequence' as const,
          group_by: [],
          timespan: '5m',
          ordered: true,
          events: ['user_login', 'file_access'],
        },
      };

      render(<CorrelationConfigEditor {...props} />);

      expect(screen.getByLabelText(/require ordered sequence/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/event sequence/i)).toBeInTheDocument();
    });

    it('should render statistical specific fields when type is statistical', () => {
      const props = {
        ...defaultProps,
        value: {
          type: 'statistical' as const,
          group_by: [],
          timespan: '5m',
          baseline_window: '24h',
          std_dev_threshold: 2,
        },
      };

      render(<CorrelationConfigEditor {...props} />);

      expect(screen.getByLabelText(/baseline window/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/standard deviation threshold/i)).toBeInTheDocument();
    });

    it('should render chain specific fields when type is chain', () => {
      const props = {
        ...defaultProps,
        value: {
          type: 'chain' as const,
          group_by: [],
          timespan: '5m',
          stages: [
            { name: 'Initial Access', detection_ref: 'rule_1', timeout: '30m' },
          ],
        },
      };

      render(<CorrelationConfigEditor {...props} />);

      expect(screen.getByText(/attack chain stages/i)).toBeInTheDocument();
      expect(screen.getByDisplayValue('Initial Access')).toBeInTheDocument();
    });
  });

  describe('Mode Toggle', () => {
    it('should render mode toggle buttons', () => {
      render(<CorrelationConfigEditor {...defaultProps} />);

      expect(screen.getByLabelText(/visual mode/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/yaml mode/i)).toBeInTheDocument();
    });

    it('should switch to YAML mode when YAML button is clicked', async () => {
      const user = userEvent.setup();
      render(<CorrelationConfigEditor {...defaultProps} />);

      const yamlButton = screen.getByLabelText(/yaml mode/i);
      await user.click(yamlButton);

      // CodeMirror editor should be present
      await waitFor(() => {
        const editor = document.querySelector('.cm-editor');
        expect(editor).toBeInTheDocument();
      });
    });

    it('should switch back to visual mode', async () => {
      const user = userEvent.setup();
      render(<CorrelationConfigEditor {...defaultProps} />);

      // Switch to YAML
      const yamlButton = screen.getByLabelText(/yaml mode/i);
      await user.click(yamlButton);

      // Switch back to visual
      const visualButton = screen.getByLabelText(/visual mode/i);
      await user.click(visualButton);

      // Visual mode fields should be present
      expect(screen.getByLabelText(/correlation type/i)).toBeInTheDocument();
    });
  });

  describe('Chain Stages Management', () => {
    it('should add a new stage when Add Stage button is clicked', async () => {
      const user = userEvent.setup();
      const props = {
        ...defaultProps,
        value: {
          type: 'chain' as const,
          group_by: [],
          timespan: '5m',
          stages: [],
        },
      };

      render(<CorrelationConfigEditor {...props} />);

      const addButton = screen.getByRole('button', { name: /add stage/i });
      await user.click(addButton);

      await waitFor(() => {
        expect(screen.getByText(/stage 1/i)).toBeInTheDocument();
      });
    });

    it('should remove a stage when delete button is clicked', async () => {
      const user = userEvent.setup();
      const props = {
        ...defaultProps,
        value: {
          type: 'chain' as const,
          group_by: [],
          timespan: '5m',
          stages: [
            { name: 'Stage 1', detection_ref: 'rule_1', timeout: '30m' },
          ],
        },
      };

      render(<CorrelationConfigEditor {...props} />);

      const deleteButton = screen.getByLabelText(/remove stage/i);
      await user.click(deleteButton);

      await waitFor(() => {
        expect(screen.queryByDisplayValue('Stage 1')).not.toBeInTheDocument();
      });
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels on form controls', () => {
      render(<CorrelationConfigEditor {...defaultProps} />);

      expect(screen.getByLabelText(/correlation type/i)).toHaveAccessibleName();
      expect(screen.getByLabelText(/operator/i)).toHaveAccessibleName();
    });

    it('should be keyboard navigable', async () => {
      const user = userEvent.setup();
      render(<CorrelationConfigEditor {...defaultProps} />);

      // Tab through controls
      await user.tab();
      await user.tab();

      // Should be able to focus on select
      const typeSelect = screen.getByLabelText(/correlation type/i);
      expect(typeSelect).toHaveFocus();
    });

    it('should disable all controls when disabled prop is true', () => {
      render(<CorrelationConfigEditor {...defaultProps} disabled />);

      const typeSelect = screen.getByLabelText(/correlation type/i);
      expect(typeSelect).toBeDisabled();
    });
  });

  describe('Error Handling', () => {
    it('should display error message when error prop is provided', () => {
      render(
        <CorrelationConfigEditor
          {...defaultProps}
          error="Invalid configuration"
        />
      );

      expect(screen.getByText(/invalid configuration/i)).toBeInTheDocument();
    });
  });

  describe('onChange Callback', () => {
    it('should call onChange when form values change', async () => {
      const user = userEvent.setup();
      render(<CorrelationConfigEditor {...defaultProps} />);

      const timespanInput = screen.getByLabelText(/timespan/i);
      await user.clear(timespanInput);
      await user.type(timespanInput, '10m');

      await waitFor(() => {
        expect(mockOnChange).toHaveBeenCalled();
      });
    });
  });
});
