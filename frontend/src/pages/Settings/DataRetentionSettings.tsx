import React from 'react';
import {
  Box,
  Typography,
  TextField,
  Grid,
  Card,
  CardContent,
  Alert,
  InputAdornment,
} from '@mui/material';
import { AccessTime as TimeIcon } from '@mui/icons-material';
import { Settings } from '../../types';

interface DataRetentionSettingsProps {
  settings: Settings;
  pendingChanges: Record<string, unknown>;
  onChange: (key: string, value: unknown) => void;
}

export default function DataRetentionSettings({
  settings,
  pendingChanges,
  onChange,
}: DataRetentionSettingsProps) {
  const getEffectiveValue = (key: string, defaultValue: unknown) => {
    return pendingChanges[key] !== undefined ? pendingChanges[key] : defaultValue;
  };

  const eventRetention = getEffectiveValue('retention.events', settings.retention.events);
  const alertRetention = getEffectiveValue('retention.alerts', settings.retention.alerts);

  const handleChange = (key: string) => (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = parseInt(event.target.value, 10);
    if (!isNaN(value)) {
      onChange(key, value);
    }
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Data Retention Configuration
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Configure how long event and alert data is stored in the system. Older data will be automatically deleted.
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }}>
        Changes to retention settings are applied immediately. Cleanup runs every 24 hours.
      </Alert>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <TimeIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">Event Retention</Typography>
              </Box>
              <TextField
                fullWidth
                type="number"
                label="Retention Period"
                value={eventRetention}
                onChange={handleChange('retention.events')}
                InputProps={{
                  endAdornment: <InputAdornment position="end">days</InputAdornment>,
                }}
                inputProps={{
                  min: 1,
                  max: 365,
                  step: 1,
                }}
                helperText="How long to keep event logs (1-365 days)"
              />
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
                Current setting will keep events for {eventRetention} days before deletion.
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <TimeIcon color="warning" sx={{ mr: 1 }} />
                <Typography variant="h6">Alert Retention</Typography>
              </Box>
              <TextField
                fullWidth
                type="number"
                label="Retention Period"
                value={alertRetention}
                onChange={handleChange('retention.alerts')}
                InputProps={{
                  endAdornment: <InputAdornment position="end">days</InputAdornment>,
                }}
                inputProps={{
                  min: 1,
                  max: 730,
                  step: 1,
                }}
                helperText="How long to keep alerts (1-730 days)"
              />
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
                Current setting will keep alerts for {alertRetention} days before deletion.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Box sx={{ mt: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          Recommendations:
        </Typography>
        <Typography variant="body2" color="text.secondary" component="ul" sx={{ pl: 2 }}>
          <li>Keep events for at least 30 days for effective threat hunting and analysis</li>
          <li>Keep alerts longer (90+ days) for compliance and reporting requirements</li>
          <li>Adjust retention periods based on available storage capacity</li>
          <li>Consider exporting historical data before reducing retention periods</li>
        </Typography>
      </Box>
    </Box>
  );
}
