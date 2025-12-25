/**
 * ListenerForm Usage Examples
 *
 * This file demonstrates various integration patterns for the ListenerForm component.
 * These examples can be used as reference when implementing listener management features.
 */

import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  Button,
  Box,
  Snackbar,
  Alert,
} from '@mui/material';
import { Add as AddIcon, Edit as EditIcon } from '@mui/icons-material';
import { ListenerForm } from './ListenerForm';
import type { DynamicListener, ListenerForm as ListenerFormType } from '../../types';

/**
 * Example 1: Create Listener Dialog
 *
 * Basic usage for creating a new listener with a dialog wrapper.
 */
export function CreateListenerExample() {
  const [open, setOpen] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (values: ListenerFormType) => {
    try {
      // Import service dynamically
      const { default: ListenersService } = await import('../../services/listenersService');
      const { default: apiService } = await import('../../services/api');
      const listenersService = new ListenersService((apiService as any).api);

      // Create the listener
      const newListener = await listenersService.createListener(values);

      console.log('Created listener:', newListener);

      // Close dialog and show success message
      setOpen(false);
      setSuccess(true);
    } catch (error) {
      console.error('Failed to create listener:', error);
      throw error; // Let the form handle the error
    }
  };

  return (
    <>
      <Button
        variant="contained"
        startIcon={<AddIcon />}
        onClick={() => setOpen(true)}
      >
        Create Listener
      </Button>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create New Listener</DialogTitle>
        <DialogContent>
          <ListenerForm
            mode="create"
            onSubmit={handleSubmit}
            onCancel={() => setOpen(false)}
          />
        </DialogContent>
      </Dialog>

      <Snackbar
        open={success}
        autoHideDuration={6000}
        onClose={() => setSuccess(false)}
      >
        <Alert severity="success" onClose={() => setSuccess(false)}>
          Listener created successfully!
        </Alert>
      </Snackbar>
    </>
  );
}

/**
 * Example 2: Edit Listener Dialog
 *
 * Usage for editing an existing listener with pre-populated values.
 */
export function EditListenerExample({ listener }: { listener: DynamicListener }) {
  const [open, setOpen] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (values: ListenerFormType) => {
    try {
      const { default: ListenersService } = await import('../../services/listenersService');
      const { default: apiService } = await import('../../services/api');
      const listenersService = new ListenersService((apiService as any).api);

      // Update the listener
      const updatedListener = await listenersService.updateListener(listener.id, values);

      console.log('Updated listener:', updatedListener);

      setOpen(false);
      setSuccess(true);
    } catch (error) {
      console.error('Failed to update listener:', error);
      throw error;
    }
  };

  return (
    <>
      <Button
        variant="outlined"
        startIcon={<EditIcon />}
        onClick={() => setOpen(true)}
        size="small"
      >
        Edit
      </Button>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Edit Listener: {listener.name}</DialogTitle>
        <DialogContent>
          <ListenerForm
            mode="edit"
            initialValues={listener}
            onSubmit={handleSubmit}
            onCancel={() => setOpen(false)}
          />
        </DialogContent>
      </Dialog>

      <Snackbar
        open={success}
        autoHideDuration={6000}
        onClose={() => setSuccess(false)}
      >
        <Alert severity="success" onClose={() => setSuccess(false)}>
          Listener updated successfully!
        </Alert>
      </Snackbar>
    </>
  );
}

/**
 * Example 3: Inline Form (No Dialog)
 *
 * Usage without a dialog wrapper for embedded forms.
 */
export function InlineListenerFormExample() {
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = async (values: ListenerFormType) => {
    try {
      const { default: ListenersService } = await import('../../services/listenersService');
      const { default: apiService } = await import('../../services/api');
      const listenersService = new ListenersService((apiService as any).api);

      await listenersService.createListener(values);
      setSubmitted(true);
    } catch (error) {
      console.error('Failed to create listener:', error);
      throw error;
    }
  };

  const handleCancel = () => {
    // Navigate away or reset form
    console.log('Form cancelled');
  };

  if (submitted) {
    return (
      <Alert severity="success">
        Listener created successfully! Redirecting...
      </Alert>
    );
  }

  return (
    <Box sx={{ maxWidth: 800, mx: 'auto', p: 3 }}>
      <ListenerForm
        mode="create"
        onSubmit={handleSubmit}
        onCancel={handleCancel}
      />
    </Box>
  );
}

/**
 * Example 4: With Custom Validation
 *
 * Adding extra validation on top of the form's built-in rules.
 */
export function CustomValidationExample() {
  const [open, setOpen] = useState(false);

  const handleSubmit = async (values: ListenerFormType) => {
    // Custom validation example: check for port conflicts
    const { default: ListenersService } = await import('../../services/listenersService');
    const { default: apiService } = await import('../../services/api');
    const listenersService = new ListenersService((apiService as any).api);

    // Get existing listeners
    const { items: existingListeners } = await listenersService.getListeners(1, 100);

    // Check for port conflict
    const conflict = existingListeners.find(
      (listener) =>
        listener.port === values.port &&
        listener.protocol === values.protocol &&
        listener.host === values.host
    );

    if (conflict) {
      throw new Error(
        `Port ${values.port} is already in use by listener "${conflict.name}" on ${values.protocol.toUpperCase()}`
      );
    }

    // If no conflict, create the listener
    await listenersService.createListener(values);
    setOpen(false);
  };

  return (
    <>
      <Button onClick={() => setOpen(true)}>Create Listener</Button>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create New Listener</DialogTitle>
        <DialogContent>
          <ListenerForm
            mode="create"
            onSubmit={handleSubmit}
            onCancel={() => setOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </>
  );
}

/**
 * Example 5: With State Management
 *
 * Integration with a state management solution (e.g., Zustand, Redux).
 */
export function StateManagementExample() {
  const [open, setOpen] = useState(false);

  const handleSubmit = async (values: ListenerFormType) => {
    try {
      const { default: ListenersService } = await import('../../services/listenersService');
      const { default: apiService } = await import('../../services/api');
      const listenersService = new ListenersService((apiService as any).api);

      const newListener = await listenersService.createListener(values);

      // Update global state (example with hypothetical store)
      // useListenersStore.getState().addListener(newListener);

      // Or trigger a refetch
      // queryClient.invalidateQueries(['listeners']);

      setOpen(false);
    } catch (error) {
      console.error('Failed to create listener:', error);
      throw error;
    }
  };

  return (
    <>
      <Button onClick={() => setOpen(true)}>Create Listener</Button>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create New Listener</DialogTitle>
        <DialogContent>
          <ListenerForm
            mode="create"
            onSubmit={handleSubmit}
            onCancel={() => setOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </>
  );
}

/**
 * Example 6: Template-First Workflow
 *
 * Encouraging users to start with a template.
 */
export function TemplateFirstExample() {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button
        variant="contained"
        startIcon={<AddIcon />}
        onClick={() => setOpen(true)}
      >
        Quick Create from Template
      </Button>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Create Listener
        </DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2 }}>
            <strong>Quick Start:</strong> Select a template below to quickly configure
            a listener, or configure manually if you prefer.
          </Alert>

          <ListenerForm
            mode="create"
            onSubmit={async (values) => {
              const { default: ListenersService } = await import('../../services/listenersService');
              const { default: apiService } = await import('../../services/api');
              const listenersService = new ListenersService((apiService as any).api);

              await listenersService.createListener(values);
              setOpen(false);
            }}
            onCancel={() => setOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </>
  );
}

/**
 * Example 7: Multi-Step Wizard
 *
 * Using the form as part of a multi-step process.
 */
export function MultiStepWizardExample() {
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState<'configure' | 'review' | 'complete'>('configure');
  const [formData, setFormData] = useState<ListenerFormType | null>(null);

  const handleSubmit = async (values: ListenerFormType) => {
    // Store data and move to review step
    setFormData(values);
    setStep('review');
  };

  const handleConfirm = async () => {
    if (!formData) return;

    try {
      const { default: ListenersService } = await import('../../services/listenersService');
      const { default: apiService } = await import('../../services/api');
      const listenersService = new ListenersService((apiService as any).api);

      await listenersService.createListener(formData);
      setStep('complete');
    } catch (error) {
      console.error('Failed to create listener:', error);
      setStep('configure');
    }
  };

  return (
    <>
      <Button onClick={() => setOpen(true)}>Create Listener (Wizard)</Button>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Create Listener - Step {step === 'configure' ? '1' : step === 'review' ? '2' : '3'} of 3
        </DialogTitle>
        <DialogContent>
          {step === 'configure' && (
            <ListenerForm
              mode="create"
              onSubmit={handleSubmit}
              onCancel={() => setOpen(false)}
            />
          )}

          {step === 'review' && formData && (
            <Box>
              <Alert severity="info" sx={{ mb: 2 }}>
                Review your configuration before creating the listener.
              </Alert>
              <pre>{JSON.stringify(formData, null, 2)}</pre>
              <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                <Button onClick={() => setStep('configure')}>Back</Button>
                <Button variant="contained" onClick={handleConfirm}>
                  Confirm & Create
                </Button>
              </Box>
            </Box>
          )}

          {step === 'complete' && (
            <Alert severity="success">
              Listener created successfully!
            </Alert>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
