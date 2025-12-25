import { Alert, AlertProps, Box, Collapse, IconButton, Typography } from '@mui/material';
import { ExpandMore, ExpandLess } from '@mui/icons-material';
import { useState } from 'react';

interface ErrorAlertProps extends Omit<AlertProps, 'children'> {
  message: string;
  /** Whether to show expandable details for stack traces */
  expandable?: boolean;
}

/**
 * ErrorAlert component that properly formats error messages with stack traces.
 *
 * Features:
 * - Preserves newlines and indentation in error messages
 * - Optionally makes long stack traces expandable
 * - Handles escape characters properly (\n, \t)
 */
export function ErrorAlert({ message, expandable = true, ...alertProps }: ErrorAlertProps) {
  const [expanded, setExpanded] = useState(false);

  // Parse the message to handle escaped characters
  const formattedMessage = formatErrorMessage(message);

  // Check if this looks like a stack trace (has newlines or multiple lines)
  const hasStackTrace = formattedMessage.includes('\n') && formattedMessage.split('\n').length > 3;

  // For stack traces, split into summary and details
  const lines = formattedMessage.split('\n');
  const summary = lines.slice(0, 2).join('\n');
  const details = lines.slice(2).join('\n');

  if (!hasStackTrace || !expandable) {
    // Simple error message - just show it with proper whitespace handling
    return (
      <Alert
        {...alertProps}
        sx={{
          ...alertProps.sx,
          '& .MuiAlert-message': {
            whiteSpace: 'pre-wrap',
            fontFamily: 'monospace',
            fontSize: '0.875rem',
            overflow: 'auto',
            maxHeight: '300px',
          }
        }}
      >
        {formattedMessage}
      </Alert>
    );
  }

  // Stack trace - show expandable
  return (
    <Alert
      {...alertProps}
      sx={{
        ...alertProps.sx,
        '& .MuiAlert-message': {
          width: '100%',
        }
      }}
    >
      <Box sx={{ width: '100%' }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <Typography
            component="pre"
            sx={{
              whiteSpace: 'pre-wrap',
              fontFamily: 'monospace',
              fontSize: '0.875rem',
              margin: 0,
              flex: 1,
            }}
          >
            {summary}
          </Typography>
          <IconButton
            size="small"
            onClick={() => setExpanded(!expanded)}
            aria-label={expanded ? 'Hide details' : 'Show details'}
          >
            {expanded ? <ExpandLess /> : <ExpandMore />}
          </IconButton>
        </Box>
        <Collapse in={expanded}>
          <Typography
            component="pre"
            sx={{
              whiteSpace: 'pre-wrap',
              fontFamily: 'monospace',
              fontSize: '0.75rem',
              margin: 0,
              marginTop: 1,
              padding: 1,
              backgroundColor: 'rgba(0, 0, 0, 0.1)',
              borderRadius: 1,
              overflow: 'auto',
              maxHeight: '300px',
            }}
          >
            {details}
          </Typography>
        </Collapse>
      </Box>
    </Alert>
  );
}

/**
 * Formats an error message by converting escaped characters to their actual values.
 *
 * @param message - The raw error message from the API
 * @returns The formatted message with proper newlines and tabs
 */
export function formatErrorMessage(message: string): string {
  if (!message) return '';

  // Replace literal escape sequences with actual characters
  // This handles cases where the backend sends "\\n" as two characters
  return message
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '\t')
    .replace(/\\r/g, '\r');
}

export default ErrorAlert;
