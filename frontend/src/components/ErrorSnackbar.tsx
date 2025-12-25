import { Snackbar, Alert, AlertColor } from '@mui/material';

interface SnackbarState {
  open: boolean;
  message: string;
  severity: AlertColor;
}

interface ErrorSnackbarProps {
  snackbar: SnackbarState;
  onClose: () => void;
}

/**
 * Formats an error message by converting escaped characters to their actual values.
 * Handles cases where the backend sends literal "\\n" as two characters.
 */
export function formatErrorMessage(message: string): string {
  if (!message) return '';
  return message
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '\t')
    .replace(/\\r/g, '');
}

/**
 * ErrorSnackbar component that properly displays error messages with stack traces.
 *
 * Features:
 * - Preserves newlines and indentation in error messages
 * - Longer duration for errors (10s vs 4s for success)
 * - Monospace font for errors to display stack traces nicely
 * - Scrollable for long stack traces
 */
export function ErrorSnackbar({ snackbar, onClose }: ErrorSnackbarProps) {
  const isError = snackbar.severity === 'error';

  return (
    <Snackbar
      open={snackbar.open}
      autoHideDuration={isError ? 10000 : 4000}
      onClose={onClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    >
      <Alert
        onClose={onClose}
        severity={snackbar.severity}
        sx={{
          width: '100%',
          maxWidth: isError ? '600px' : '400px',
          '& .MuiAlert-message': {
            whiteSpace: 'pre-wrap',
            fontFamily: isError ? 'monospace' : 'inherit',
            fontSize: isError ? '0.85rem' : 'inherit',
            maxHeight: '300px',
            overflow: 'auto',
          }
        }}
      >
        {formatErrorMessage(snackbar.message)}
      </Alert>
    </Snackbar>
  );
}

export default ErrorSnackbar;
