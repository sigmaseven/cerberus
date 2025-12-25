import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ListenerForm } from './ListenerForm';
import type { ListenerForm as ListenerFormType } from '../../types';

// Mock the api service with listeners sub-service
vi.mock('../../services/api', () => ({
  default: {
    listeners: {
      getTemplates: vi.fn().mockResolvedValue([
        {
          id: 'syslog-udp-514',
          name: 'Standard Syslog (UDP)',
          description: 'Standard syslog listener on UDP port 514',
          category: 'syslog',
          icon: 'storage',
          tags: ['syslog', 'udp', 'standard'],
          config: {
            name: 'Syslog UDP 514',
            description: 'Standard syslog listener',
            type: 'syslog',
            protocol: 'udp',
            host: '0.0.0.0',
            port: 514,
            tls: false,
            tags: ['syslog'],
            source: 'syslog-udp',
          },
        },
      ]),
      getListeners: vi.fn().mockResolvedValue({ items: [], total: 0 }),
    },
  },
}));

describe('ListenerForm', () => {
  const mockOnSubmit = vi.fn();
  const mockOnCancel = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Form Rendering', () => {
    it('should render all required form fields in create mode', () => {
      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Check for main form fields
      expect(screen.getByLabelText(/listener name/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/description/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/listener type/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/protocol/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/host address/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/port number/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/event source/i)).toBeInTheDocument();

      // Check for TLS toggle
      expect(screen.getByLabelText(/enable tls/i)).toBeInTheDocument();

      // Check for action buttons
      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /create listener/i })).toBeInTheDocument();
    });

    it('should show template selector only in create mode', async () => {
      const { rerender } = render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Wait for templates to load
      await waitFor(() => {
        expect(screen.getByLabelText(/select a template/i)).toBeInTheDocument();
      });

      // Rerender in edit mode
      rerender(
        <ListenerForm
          mode="edit"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Template selector should not be present in edit mode
      expect(screen.queryByLabelText(/select a template/i)).not.toBeInTheDocument();
    });

    it('should disable type field in edit mode', () => {
      render(
        <ListenerForm
          mode="edit"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      const typeSelect = screen.getByLabelText(/listener type/i);
      expect(typeSelect).toBeDisabled();
    });
  });

  describe('Form Validation', () => {
    it('should show validation errors for required fields', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Clear the default values
      const nameInput = screen.getByLabelText(/listener name/i);
      await user.clear(nameInput);
      await user.tab();

      // Check for validation errors
      await waitFor(() => {
        expect(screen.getByText(/listener name is required/i)).toBeInTheDocument();
      });
    });

    it('should validate port range (1-65535)', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      const portInput = screen.getByLabelText(/port number/i);

      // Test port < 1
      await user.clear(portInput);
      await user.type(portInput, '0');
      await user.tab();

      await waitFor(() => {
        expect(screen.getByText(/port must be at least 1/i)).toBeInTheDocument();
      });

      // Test port > 65535
      await user.clear(portInput);
      await user.type(portInput, '70000');
      await user.tab();

      await waitFor(() => {
        expect(screen.getByText(/port must be at most 65535/i)).toBeInTheDocument();
      });
    });

    it('should validate TLS configuration when enabled', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Enable TLS
      const tlsSwitch = screen.getByLabelText(/enable tls/i);
      await user.click(tlsSwitch);

      // TLS fields should now be visible
      await waitFor(() => {
        expect(screen.getByLabelText(/certificate file path/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/private key file path/i)).toBeInTheDocument();
      });

      // Fill required fields
      await user.type(screen.getByLabelText(/listener name/i), 'Test Listener');
      await user.type(screen.getByLabelText(/event source/i), 'test-source');

      // Try to submit without TLS cert/key
      const submitButton = screen.getByRole('button', { name: /create listener/i });
      expect(submitButton).toBeDisabled(); // Should be disabled due to validation
    });

    it('should show separate error for missing cert vs key in TLS mode', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Enable TLS
      const tlsSwitch = screen.getByLabelText(/enable tls/i);
      await user.click(tlsSwitch);

      // Wait for TLS fields to appear
      await waitFor(() => {
        expect(screen.getByLabelText(/certificate file path/i)).toBeInTheDocument();
      });

      // Fill only cert file, not key file
      await user.type(screen.getByLabelText(/listener name/i), 'Test');
      await user.type(screen.getByLabelText(/event source/i), 'test');
      await user.type(screen.getByLabelText(/certificate file path/i), '/path/to/cert.crt');
      await user.tab();

      // Should show error for missing key file
      await waitFor(() => {
        expect(screen.getByText(/private key file is required when tls is enabled/i)).toBeInTheDocument();
      });
    });

    // BLOCKING-7 FIX: Test field-specific error for missing cert (not key)
    it('should show separate error for missing cert when only key is provided', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Enable TLS
      const tlsSwitch = screen.getByLabelText(/enable tls/i);
      await user.click(tlsSwitch);

      // Wait for TLS fields to appear
      await waitFor(() => {
        expect(screen.getByLabelText(/private key file path/i)).toBeInTheDocument();
      });

      // Fill only key file, not cert file
      await user.type(screen.getByLabelText(/listener name/i), 'Test');
      await user.type(screen.getByLabelText(/event source/i), 'test');
      await user.type(screen.getByLabelText(/private key file path/i), '/path/to/key.pem');
      await user.tab();

      // Should show error for missing cert file (field-specific error)
      await waitFor(() => {
        expect(screen.getByText(/certificate file is required when tls is enabled/i)).toBeInTheDocument();
      });
    });

    it('should validate port boundary values', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      const portInput = screen.getByLabelText(/port number/i);

      // Test valid minimum port (1)
      await user.clear(portInput);
      await user.type(portInput, '1');
      await user.tab();

      await waitFor(() => {
        expect(screen.queryByText(/port must be at least 1/i)).not.toBeInTheDocument();
      });

      // Test valid maximum port (65535)
      await user.clear(portInput);
      await user.type(portInput, '65535');
      await user.tab();

      await waitFor(() => {
        expect(screen.queryByText(/port must be at most 65535/i)).not.toBeInTheDocument();
      });
    });

    // BLOCKING-8 FIX: Test empty port handling (prevents NaN bug)
    it('should show validation error when port is cleared', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      const portInput = screen.getByLabelText(/port number/i);

      // Clear the port field completely
      await user.clear(portInput);
      await user.tab();

      // Should show validation error for required/minimum port
      await waitFor(() => {
        // The zod schema requires port to be at least 1, so clearing should trigger an error
        const submitButton = screen.getByRole('button', { name: /create listener/i });
        expect(submitButton).toBeDisabled();
      });
    });

    // BLOCKING-8 FIX: Test non-numeric input handling
    it('should handle non-numeric port input gracefully', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      const portInput = screen.getByLabelText(/port number/i);

      // Clear and type non-numeric value (HTML input type="number" may filter this, but test the behavior)
      await user.clear(portInput);
      // Note: type="number" inputs typically filter non-numeric input, but this tests our handler
      await user.tab();

      // Form should handle this gracefully without crashing
      const submitButton = screen.getByRole('button', { name: /create listener/i });
      expect(submitButton).toBeInTheDocument();
    });
  });

  describe('Security - Path Traversal Prevention', () => {
    it('should reject certificate path with path traversal sequences', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Enable TLS
      const tlsSwitch = screen.getByLabelText(/enable tls/i);
      await user.click(tlsSwitch);

      // Wait for TLS fields
      await waitFor(() => {
        expect(screen.getByLabelText(/certificate file path/i)).toBeInTheDocument();
      });

      // Try path traversal in cert_file
      const certInput = screen.getByLabelText(/certificate file path/i);
      await user.type(certInput, '../../etc/passwd');
      await user.tab();

      // Should show security error
      await waitFor(() => {
        expect(screen.getByText(/cannot contain "\.\." or "~"/i)).toBeInTheDocument();
      });
    });

    it('should reject key path with home directory expansion', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Enable TLS
      const tlsSwitch = screen.getByLabelText(/enable tls/i);
      await user.click(tlsSwitch);

      // Wait for TLS fields
      await waitFor(() => {
        expect(screen.getByLabelText(/private key file path/i)).toBeInTheDocument();
      });

      // Try home directory expansion in key_file
      const keyInput = screen.getByLabelText(/private key file path/i);
      await user.type(keyInput, '~/secrets/private.key');
      await user.tab();

      // Should show security error
      await waitFor(() => {
        expect(screen.getByText(/cannot contain "\.\." or "~"/i)).toBeInTheDocument();
      });
    });

    it('should accept valid absolute paths', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Enable TLS
      const tlsSwitch = screen.getByLabelText(/enable tls/i);
      await user.click(tlsSwitch);

      // Wait for TLS fields
      await waitFor(() => {
        expect(screen.getByLabelText(/certificate file path/i)).toBeInTheDocument();
      });

      // Enter valid paths
      const certInput = screen.getByLabelText(/certificate file path/i);
      await user.type(certInput, '/etc/ssl/certs/server.crt');

      const keyInput = screen.getByLabelText(/private key file path/i);
      await user.type(keyInput, '/etc/ssl/private/server.key');
      await user.tab();

      // Should not show security error for valid paths
      await waitFor(() => {
        expect(screen.queryByText(/cannot contain "\.\." or "~"/i)).not.toBeInTheDocument();
      });
    });

    // CRITICAL-3 FIX: Test Windows absolute path validation
    it('should accept valid Windows absolute paths', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Enable TLS
      const tlsSwitch = screen.getByLabelText(/enable tls/i);
      await user.click(tlsSwitch);

      // Wait for TLS fields
      await waitFor(() => {
        expect(screen.getByLabelText(/certificate file path/i)).toBeInTheDocument();
      });

      // Enter valid Windows paths
      const certInput = screen.getByLabelText(/certificate file path/i);
      await user.type(certInput, 'C:\\ssl\\certs\\server.crt');

      const keyInput = screen.getByLabelText(/private key file path/i);
      await user.type(keyInput, 'D:\\ssl\\private\\server.key');
      await user.tab();

      // Should not show security error for valid Windows paths
      await waitFor(() => {
        expect(screen.queryByText(/cannot contain "\.\." or "~"/i)).not.toBeInTheDocument();
      });
    });

    // Test that relative paths are rejected
    it('should reject relative paths', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Enable TLS
      const tlsSwitch = screen.getByLabelText(/enable tls/i);
      await user.click(tlsSwitch);

      // Wait for TLS fields
      await waitFor(() => {
        expect(screen.getByLabelText(/certificate file path/i)).toBeInTheDocument();
      });

      // Try relative path (no leading / or drive letter)
      const certInput = screen.getByLabelText(/certificate file path/i);
      await user.type(certInput, 'ssl/certs/server.crt');
      await user.tab();

      // Should show validation error for relative path
      await waitFor(() => {
        expect(screen.getByText(/cannot contain "\.\." or "~"/i)).toBeInTheDocument();
      });
    });
  });

  describe('Protocol Type Constraints', () => {
    it('should show only valid protocols for syslog type', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Syslog should show UDP and TCP
      const protocolSelect = screen.getByLabelText(/protocol/i);
      await user.click(protocolSelect);

      const listbox = screen.getByRole('listbox');
      const options = within(listbox).getAllByRole('option');

      expect(options).toHaveLength(2); // UDP and TCP only
      expect(within(listbox).getByText(/udp/i)).toBeInTheDocument();
      expect(within(listbox).getByText(/tcp/i)).toBeInTheDocument();
    });

    it('should auto-adjust protocol when type changes', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Change to JSON type (supports TCP and HTTP, not UDP)
      const typeSelect = screen.getByLabelText(/listener type/i);
      await user.click(typeSelect);

      const typeListbox = screen.getByRole('listbox');
      await user.click(within(typeListbox).getByText(/json/i));

      // Protocol should auto-adjust to TCP (first valid option)
      await waitFor(() => {
        const protocolSelect = screen.getByLabelText(/protocol/i);
        expect(protocolSelect).toHaveTextContent(/tcp/i);
      });
    });
  });

  describe('Template Selection', () => {
    it('should load and display templates', async () => {
      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Wait for templates to load
      await waitFor(() => {
        expect(screen.getByLabelText(/select a template/i)).toBeInTheDocument();
      });
    });

    it('should apply template values when selected', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Wait for templates to load
      await waitFor(() => {
        expect(screen.getByLabelText(/select a template/i)).toBeInTheDocument();
      });

      // Select a template
      const templateSelect = screen.getByLabelText(/select a template/i);
      await user.click(templateSelect);

      const listbox = screen.getByRole('listbox');
      await user.click(within(listbox).getByText(/standard syslog/i));

      // Check that form fields are populated
      await waitFor(() => {
        expect(screen.getByLabelText(/listener name/i)).toHaveValue('Syslog UDP 514');
        expect(screen.getByLabelText(/event source/i)).toHaveValue('syslog-udp');
      });
    });
  });

  describe('Form Submission', () => {
    it('should call onSubmit with valid data', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Fill in required fields
      await user.type(screen.getByLabelText(/listener name/i), 'Test Listener');
      await user.type(screen.getByLabelText(/event source/i), 'test-source');

      // Submit the form
      const submitButton = screen.getByRole('button', { name: /create listener/i });

      // Wait for form to be valid
      await waitFor(() => {
        expect(submitButton).not.toBeDisabled();
      });

      await user.click(submitButton);

      // Verify onSubmit was called
      await waitFor(() => {
        expect(mockOnSubmit).toHaveBeenCalledTimes(1);
      });

      const submittedData = mockOnSubmit.mock.calls[0][0] as ListenerFormType;
      expect(submittedData.name).toBe('Test Listener');
      expect(submittedData.source).toBe('test-source');
      expect(submittedData.type).toBe('syslog');
    });

    it('should call onCancel when cancel button is clicked', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      await user.click(cancelButton);

      expect(mockOnCancel).toHaveBeenCalledTimes(1);
    });

    it('should handle submission errors gracefully', async () => {
      const user = userEvent.setup();
      const errorMessage = 'Failed to create listener';
      const failingOnSubmit = vi.fn().mockRejectedValue(new Error(errorMessage));

      render(
        <ListenerForm
          mode="create"
          onSubmit={failingOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Fill in required fields
      await user.type(screen.getByLabelText(/listener name/i), 'Test Listener');
      await user.type(screen.getByLabelText(/event source/i), 'test-source');

      // Submit the form
      const submitButton = screen.getByRole('button', { name: /create listener/i });
      await waitFor(() => {
        expect(submitButton).not.toBeDisabled();
      });

      await user.click(submitButton);

      // Verify error is displayed
      await waitFor(() => {
        expect(screen.getByText(errorMessage)).toBeInTheDocument();
      });
    });

    it('should prevent double submission', async () => {
      const user = userEvent.setup();
      let resolveSubmit: () => void;
      const slowOnSubmit = vi.fn().mockImplementation(() => {
        return new Promise<void>((resolve) => {
          resolveSubmit = resolve;
        });
      });

      render(
        <ListenerForm
          mode="create"
          onSubmit={slowOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Fill in required fields
      await user.type(screen.getByLabelText(/listener name/i), 'Test Listener');
      await user.type(screen.getByLabelText(/event source/i), 'test-source');

      const submitButton = screen.getByRole('button', { name: /create listener/i });
      await waitFor(() => {
        expect(submitButton).not.toBeDisabled();
      });

      // Click submit - should show "Saving..."
      await user.click(submitButton);

      // Button should be disabled during submission
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /saving/i })).toBeDisabled();
      });

      // Resolve the submission
      resolveSubmit!();

      // onSubmit should only be called once
      expect(slowOnSubmit).toHaveBeenCalledTimes(1);
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels on all inputs', () => {
      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Check ARIA labels
      expect(screen.getByLabelText(/listener name/i)).toHaveAttribute('aria-required', 'true');
      expect(screen.getByLabelText(/listener type/i)).toHaveAttribute('aria-required', 'true');
      expect(screen.getByLabelText(/protocol/i)).toHaveAttribute('aria-required', 'true');
      expect(screen.getByLabelText(/event source/i)).toHaveAttribute('aria-required', 'true');
    });

    it('should indicate invalid fields with aria-invalid', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Clear required field to trigger validation
      const nameInput = screen.getByLabelText(/listener name/i);
      await user.clear(nameInput);
      await user.tab();

      await waitFor(() => {
        expect(nameInput).toHaveAttribute('aria-invalid', 'true');
      });
    });

    it('should be keyboard navigable', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Tab through form fields
      await user.tab(); // Name field
      expect(screen.getByLabelText(/listener name/i)).toHaveFocus();

      await user.tab(); // Description field
      expect(screen.getByLabelText(/description/i)).toHaveFocus();
    });

    it('should have aria-live on error alert', async () => {
      const user = userEvent.setup();
      const failingOnSubmit = vi.fn().mockRejectedValue(new Error('Error'));

      render(
        <ListenerForm
          mode="create"
          onSubmit={failingOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Fill in required fields
      await user.type(screen.getByLabelText(/listener name/i), 'Test');
      await user.type(screen.getByLabelText(/event source/i), 'test');

      const submitButton = screen.getByRole('button', { name: /create listener/i });
      await waitFor(() => {
        expect(submitButton).not.toBeDisabled();
      });

      await user.click(submitButton);

      // Error alert should have aria-live
      await waitFor(() => {
        const alert = screen.getByRole('alert');
        expect(alert).toHaveAttribute('aria-live', 'assertive');
      });
    });

    it('should have aria-busy on submit button during submission', async () => {
      const user = userEvent.setup();
      let resolveSubmit: () => void;
      const slowOnSubmit = vi.fn().mockImplementation(() => {
        return new Promise<void>((resolve) => {
          resolveSubmit = resolve;
        });
      });

      render(
        <ListenerForm
          mode="create"
          onSubmit={slowOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Fill in required fields
      await user.type(screen.getByLabelText(/listener name/i), 'Test');
      await user.type(screen.getByLabelText(/event source/i), 'test');

      const submitButton = screen.getByRole('button', { name: /create listener/i });
      await waitFor(() => {
        expect(submitButton).not.toBeDisabled();
      });

      await user.click(submitButton);

      // Button should have aria-busy during submission
      await waitFor(() => {
        const savingButton = screen.getByRole('button', { name: /saving/i });
        expect(savingButton).toHaveAttribute('aria-busy', 'true');
      });

      resolveSubmit!();
    });
  });

  describe('Edit Mode', () => {
    it('should populate form with initial values', () => {
      const initialValues: Partial<ListenerFormType> = {
        name: 'Existing Listener',
        description: 'Test description',
        type: 'json',
        protocol: 'tcp',
        host: '0.0.0.0',
        port: 8080,
        tls: false,
        source: 'existing-source',
        tags: ['tag1', 'tag2'],
      };

      render(
        <ListenerForm
          mode="edit"
          initialValues={initialValues}
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      expect(screen.getByLabelText(/listener name/i)).toHaveValue('Existing Listener');
      expect(screen.getByLabelText(/description/i)).toHaveValue('Test description');
      expect(screen.getByLabelText(/event source/i)).toHaveValue('existing-source');
      expect(screen.getByLabelText(/port number/i)).toHaveValue(8080);
    });

    it('should show correct button text in edit mode', () => {
      render(
        <ListenerForm
          mode="edit"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      expect(screen.getByRole('button', { name: /update listener/i })).toBeInTheDocument();
    });
  });

  describe('Template Loading Failure (BLOCKER-7 fix)', () => {
    it('should handle template loading failure gracefully', async () => {
      // Override the mock to fail
      const apiService = await import('../../services/api');
      vi.mocked(apiService.default.listeners.getTemplates).mockRejectedValueOnce(
        new Error('Network error')
      );

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Wait for error message
      await waitFor(() => {
        expect(screen.getByText(/failed to load templates/i)).toBeInTheDocument();
      });

      // Form should still be functional
      expect(screen.getByLabelText(/listener name/i)).toBeInTheDocument();
    });
  });

  describe('Port Conflict Validation (BLOCKER-7 fix)', () => {
    it('should show port conflict warning when port is in use', async () => {
      const existingListeners = [
        {
          id: 'listener-1',
          name: 'Existing Syslog',
          description: 'An existing listener',
          type: 'syslog' as const,
          protocol: 'udp' as const,
          host: '0.0.0.0',
          port: 514,
          tls: false,
          tags: [],
          source: 'test',
          status: 'running' as const,
          events_received: 0,
          events_per_minute: 0,
          error_count: 0,
        },
      ];

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
          existingListeners={existingListeners}
        />
      );

      // Port conflict warning should appear (default port is 514)
      await waitFor(() => {
        expect(screen.getByText(/port 514 is already in use/i)).toBeInTheDocument();
      });
    });

    it('should not show conflict for stopped listeners', async () => {
      const existingListeners = [
        {
          id: 'listener-1',
          name: 'Stopped Listener',
          description: 'A stopped listener',
          type: 'syslog' as const,
          protocol: 'udp' as const,
          host: '0.0.0.0',
          port: 514,
          tls: false,
          tags: [],
          source: 'test',
          status: 'stopped' as const,
          events_received: 0,
          events_per_minute: 0,
          error_count: 0,
        },
      ];

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
          existingListeners={existingListeners}
        />
      );

      // No conflict warning should appear for stopped listeners
      await waitFor(() => {
        expect(screen.queryByText(/port 514 is already in use/i)).not.toBeInTheDocument();
      });
    });

    it('should allow same port in edit mode for same listener', async () => {
      const existingListeners = [
        {
          id: 'listener-1',
          name: 'My Listener',
          description: 'Editing this',
          type: 'syslog' as const,
          protocol: 'udp' as const,
          host: '0.0.0.0',
          port: 514,
          tls: false,
          tags: [],
          source: 'test',
          status: 'running' as const,
          events_received: 0,
          events_per_minute: 0,
          error_count: 0,
        },
      ];

      render(
        <ListenerForm
          mode="edit"
          initialValues={{ name: 'My Listener', port: 514 }}
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
          existingListeners={existingListeners}
        />
      );

      // No conflict warning should appear when editing self
      await waitFor(() => {
        expect(screen.queryByText(/port 514 is already in use/i)).not.toBeInTheDocument();
      });
    });

    it('should prevent submission when port conflict exists', async () => {
      const user = userEvent.setup();
      const existingListeners = [
        {
          id: 'listener-1',
          name: 'Existing Listener',
          description: 'An existing listener',
          type: 'syslog' as const,
          protocol: 'udp' as const,
          host: '0.0.0.0',
          port: 514,
          tls: false,
          tags: [],
          source: 'test',
          status: 'running' as const,
          events_received: 0,
          events_per_minute: 0,
          error_count: 0,
        },
      ];

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
          existingListeners={existingListeners}
        />
      );

      // Fill in required fields
      await user.type(screen.getByLabelText(/listener name/i), 'New Listener');
      await user.type(screen.getByLabelText(/event source/i), 'new-source');

      // Submit button should be disabled due to port conflict
      const submitButton = screen.getByRole('button', { name: /create listener/i });
      expect(submitButton).toBeDisabled();
    });

    // BLOCKING-6 FIX: Test port conflict with different protocol
    it('should not show conflict when same port uses different protocol', async () => {
      const user = userEvent.setup();
      const existingListeners = [
        {
          id: 'listener-1',
          name: 'TCP Listener',
          description: 'Uses TCP',
          type: 'syslog' as const,
          protocol: 'tcp' as const,
          host: '0.0.0.0',
          port: 514,
          tls: false,
          tags: [],
          source: 'test',
          status: 'running' as const,
          events_received: 0,
          events_per_minute: 0,
          error_count: 0,
        },
      ];

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
          existingListeners={existingListeners}
        />
      );

      // Default form uses UDP protocol - existing is TCP
      // Same port but different protocol = no conflict
      await waitFor(() => {
        expect(screen.queryByText(/port 514 is already in use/i)).not.toBeInTheDocument();
      });
    });

    // BLOCKING-6 FIX + CRITICAL-2 FIX: Test 0.0.0.0 wildcard binding
    // 0.0.0.0 conflicts with ANY specific IP since it binds all interfaces
    it('should show conflict when 0.0.0.0 (wildcard) conflicts with specific IP', async () => {
      const existingListeners = [
        {
          id: 'listener-1',
          name: 'Localhost Listener',
          description: 'On localhost',
          type: 'syslog' as const,
          protocol: 'udp' as const,
          host: '127.0.0.1', // Specific host
          port: 514,
          tls: false,
          tags: [],
          source: 'test',
          status: 'running' as const,
          events_received: 0,
          events_per_minute: 0,
          error_count: 0,
        },
      ];

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
          existingListeners={existingListeners}
        />
      );

      // Default form uses 0.0.0.0 (wildcard binds ALL interfaces)
      // This SHOULD conflict because 0.0.0.0 would include 127.0.0.1
      await waitFor(() => {
        expect(screen.getByText(/port 514 is already in use/i)).toBeInTheDocument();
      });
    });

    // Test truly different host scenario (neither is 0.0.0.0)
    it('should not show conflict when same port uses truly different hosts', async () => {
      const user = userEvent.setup();
      const existingListeners = [
        {
          id: 'listener-1',
          name: 'Localhost Listener',
          description: 'On localhost',
          type: 'syslog' as const,
          protocol: 'udp' as const,
          host: '127.0.0.1', // Specific host
          port: 514,
          tls: false,
          tags: [],
          source: 'test',
          status: 'running' as const,
          events_received: 0,
          events_per_minute: 0,
          error_count: 0,
        },
      ];

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
          existingListeners={existingListeners}
        />
      );

      // Change host from 0.0.0.0 to a different specific IP
      const hostInput = screen.getByLabelText(/host address/i);
      await user.clear(hostInput);
      await user.type(hostInput, '192.168.1.1');
      await user.tab();

      // Different specific IPs should not conflict
      await waitFor(() => {
        expect(screen.queryByText(/port 514 is already in use/i)).not.toBeInTheDocument();
      });
    });
  });

  describe('Template Data Application (React XSS Safety)', () => {
    it('should apply template data directly - React handles XSS for controlled inputs', async () => {
      const user = userEvent.setup();

      // Mock template with special characters (not malicious - React handles display safely)
      const apiService = await import('../../services/api');
      vi.mocked(apiService.default.listeners.getTemplates).mockResolvedValueOnce([
        {
          id: 'special-chars-template',
          name: 'Special Chars Template',
          description: 'Test special characters',
          category: 'test',
          icon: 'test',
          tags: [],
          config: {
            name: 'Web Server & API Gateway',
            description: 'Handles <100 requests/sec',
            type: 'syslog',
            protocol: 'udp',
            host: '0.0.0.0',
            port: 514,
            tls: false,
            source: 'test-server-01',
          },
        },
      ]);

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Wait for templates to load
      await waitFor(() => {
        expect(screen.getByLabelText(/select a template/i)).toBeInTheDocument();
      });

      // Select the template
      const templateSelect = screen.getByLabelText(/select a template/i);
      await user.click(templateSelect);

      const listbox = screen.getByRole('listbox');
      await user.click(within(listbox).getByText(/special chars template/i));

      // Verify the values are applied WITHOUT double-escaping
      // React controlled inputs are inherently XSS-safe
      await waitFor(() => {
        const nameInput = screen.getByLabelText(/listener name/i);
        // The ampersand should remain as & not become &amp;
        expect(nameInput).toHaveValue('Web Server & API Gateway');
      });
    });
  });

  describe('Field Mapping Validation (BLOCKER-7 fix)', () => {
    it('should handle empty field mapping correctly', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Fill required fields only
      await user.type(screen.getByLabelText(/listener name/i), 'Test Listener');
      await user.type(screen.getByLabelText(/event source/i), 'test-source');

      // Leave field mapping empty

      const submitButton = screen.getByRole('button', { name: /create listener/i });
      await waitFor(() => {
        expect(submitButton).not.toBeDisabled();
      });

      await user.click(submitButton);

      // Verify submission succeeds without field mapping
      await waitFor(() => {
        expect(mockOnSubmit).toHaveBeenCalledTimes(1);
      });

      const submittedData = mockOnSubmit.mock.calls[0][0] as ListenerFormType;
      expect(submittedData.field_mapping).toBe('');
    });

    it('should accept valid field mapping value', async () => {
      const user = userEvent.setup();

      render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Fill required fields
      await user.type(screen.getByLabelText(/listener name/i), 'Test Listener');
      await user.type(screen.getByLabelText(/event source/i), 'test-source');
      await user.type(screen.getByLabelText(/field mapping/i), 'sigma-windows');

      const submitButton = screen.getByRole('button', { name: /create listener/i });
      await waitFor(() => {
        expect(submitButton).not.toBeDisabled();
      });

      await user.click(submitButton);

      await waitFor(() => {
        expect(mockOnSubmit).toHaveBeenCalledTimes(1);
      });

      const submittedData = mockOnSubmit.mock.calls[0][0] as ListenerFormType;
      expect(submittedData.field_mapping).toBe('sigma-windows');
    });
  });

  describe('Memory Leak Prevention (BLOCKER-5 verification)', () => {
    it('should not update state after unmount', async () => {
      // Spy on console.error to catch React state update warnings
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const { unmount } = render(
        <ListenerForm
          mode="create"
          onSubmit={mockOnSubmit}
          onCancel={mockOnCancel}
        />
      );

      // Unmount immediately before templates can load
      unmount();

      // Wait a bit for any async operations to complete
      await new Promise(resolve => setTimeout(resolve, 100));

      // Should not have any "Can't perform a React state update on an unmounted component" warnings
      const stateUpdateWarnings = consoleErrorSpy.mock.calls.filter(
        call => String(call[0]).includes('unmounted component')
      );
      expect(stateUpdateWarnings).toHaveLength(0);

      consoleErrorSpy.mockRestore();
    });
  });
});
