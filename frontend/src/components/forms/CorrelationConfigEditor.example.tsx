import { useState } from 'react';
import { Box, Typography, Paper, Alert } from '@mui/material';
import { CorrelationConfigEditor } from './CorrelationConfigEditor';

/**
 * Example Usage: CorrelationConfigEditor Component
 *
 * This file demonstrates all 7 correlation types supported by the
 * CorrelationConfigEditor with practical examples.
 */

export function CorrelationConfigEditorExample() {
  const [config, setConfig] = useState<Record<string, unknown> | null>({
    type: 'event_count',
    group_by: ['source_ip'],
    timespan: '5m',
    count: 10,
    condition: '>=',
  });

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        CorrelationConfigEditor Examples
      </Typography>

      {/* Event Count Example */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          1. Event Count
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          Trigger when the number of events exceeds a threshold within a time
          window.
        </Typography>
        <Alert severity="info" sx={{ mb: 2 }}>
          Example: Detect when more than 10 failed login attempts occur from
          the same IP within 5 minutes.
        </Alert>
        <CorrelationConfigEditor
          value={{
            type: 'event_count',
            group_by: ['source_ip'],
            timespan: '5m',
            count: 10,
            condition: '>=',
          }}
          onChange={(newConfig) => console.log('Event Count:', newConfig)}
        />
      </Paper>

      {/* Current Configuration Display */}
      <Paper sx={{ p: 3, mt: 4 }}>
        <Typography variant="h6" gutterBottom>
          Current Configuration
        </Typography>
        <pre
          style={{
            background: '#1e1e1e',
            color: '#d4d4d4',
            padding: '16px',
            borderRadius: '4px',
            overflow: 'auto',
          }}
        >
          {JSON.stringify(config, null, 2)}
        </pre>
      </Paper>
    </Box>
  );
}
