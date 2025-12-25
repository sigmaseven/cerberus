import React from 'react';
import {
  Box,
  Typography,
  TextField,
  Grid,
  Card,
  CardContent,
  Alert,
  Switch,
  FormControlLabel,
  Chip,
} from '@mui/material';
import {
  Router as RouterIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { Settings } from '../../types';

interface ListenerSettingsProps {
  settings: Settings;
  pendingChanges: Record<string, unknown>;
  onChange: (key: string, value: unknown) => void;
}

export default function ListenerSettings({
  settings,
  pendingChanges,
  onChange,
}: ListenerSettingsProps) {
  const getEffectiveValue = (key: string, defaultValue: unknown) => {
    return pendingChanges[key] !== undefined ? pendingChanges[key] : defaultValue;
  };

  const syslogHost = getEffectiveValue('listeners.syslog.host', settings.listeners.syslog.host);
  const syslogPort = getEffectiveValue('listeners.syslog.port', settings.listeners.syslog.port);
  const cefHost = getEffectiveValue('listeners.cef.host', settings.listeners.cef.host);
  const cefPort = getEffectiveValue('listeners.cef.port', settings.listeners.cef.port);
  const jsonHost = getEffectiveValue('listeners.json.host', settings.listeners.json.host);
  const jsonPort = getEffectiveValue('listeners.json.port', settings.listeners.json.port);
  const jsonTls = getEffectiveValue('listeners.json.tls', settings.listeners.json.tls);

  const handleTextChange = (key: string) => (event: React.ChangeEvent<HTMLInputElement>) => {
    onChange(key, event.target.value);
  };

  const handleNumberChange = (key: string) => (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = parseInt(event.target.value, 10);
    if (!isNaN(value)) {
      onChange(key, value);
    }
  };

  const handleSwitchChange = (key: string) => (event: React.ChangeEvent<HTMLInputElement>) => {
    onChange(key, event.target.checked);
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Listener Configuration
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Configure network listeners for ingesting events from different sources. All listener changes require a server restart.
      </Typography>

      <Alert severity="warning" sx={{ mb: 3 }}>
        <strong>Restart Required:</strong> All listener configuration changes require a server restart to take effect.
      </Alert>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <RouterIcon color="primary" sx={{ mr: 1 }} />
                  <Typography variant="h6">Syslog</Typography>
                </Box>
                <Chip label="UDP" size="small" color="primary" />
              </Box>

              <TextField
                fullWidth
                label="Host"
                value={syslogHost}
                onChange={handleTextChange('listeners.syslog.host')}
                margin="normal"
                helperText="IP address to bind to (0.0.0.0 for all)"
              />

              <TextField
                fullWidth
                type="number"
                label="Port"
                value={syslogPort}
                onChange={handleNumberChange('listeners.syslog.port')}
                margin="normal"
                inputProps={{
                  min: 1,
                  max: 65535,
                }}
                helperText="UDP port for Syslog messages"
              />

              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
                Standard Syslog listener for receiving RFC 3164 and RFC 5424 messages.
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <RouterIcon color="secondary" sx={{ mr: 1 }} />
                  <Typography variant="h6">CEF</Typography>
                </Box>
                <Chip label="UDP" size="small" color="secondary" />
              </Box>

              <TextField
                fullWidth
                label="Host"
                value={cefHost}
                onChange={handleTextChange('listeners.cef.host')}
                margin="normal"
                helperText="IP address to bind to (0.0.0.0 for all)"
              />

              <TextField
                fullWidth
                type="number"
                label="Port"
                value={cefPort}
                onChange={handleNumberChange('listeners.cef.port')}
                margin="normal"
                inputProps={{
                  min: 1,
                  max: 65535,
                }}
                helperText="UDP port for CEF messages"
              />

              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
                Common Event Format listener for ArcSight and other CEF-compatible sources.
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <RouterIcon color="success" sx={{ mr: 1 }} />
                  <Typography variant="h6">JSON</Typography>
                </Box>
                <Chip label="TCP" size="small" color="success" />
              </Box>

              <TextField
                fullWidth
                label="Host"
                value={jsonHost}
                onChange={handleTextChange('listeners.json.host')}
                margin="normal"
                helperText="IP address to bind to (0.0.0.0 for all)"
              />

              <TextField
                fullWidth
                type="number"
                label="Port"
                value={jsonPort}
                onChange={handleNumberChange('listeners.json.port')}
                margin="normal"
                inputProps={{
                  min: 1,
                  max: 65535,
                }}
                helperText="TCP port for JSON messages"
              />

              <FormControlLabel
                control={
                  <Switch
                    checked={jsonTls}
                    onChange={handleSwitchChange('listeners.json.tls')}
                  />
                }
                label={
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <SecurityIcon sx={{ mr: 0.5, fontSize: 16 }} />
                    <Typography variant="body2">Enable TLS</Typography>
                  </Box>
                }
                sx={{ mt: 2 }}
              />

              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
                JSON listener for structured event data over TCP with optional TLS encryption.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Box sx={{ mt: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          Best Practices:
        </Typography>
        <Typography variant="body2" color="text.secondary" component="ul" sx={{ pl: 2 }}>
          <li>Use standard ports (514 for Syslog, 515 for CEF) when possible</li>
          <li>Enable TLS for JSON listener when transmitting sensitive data</li>
          <li>Bind to specific IPs instead of 0.0.0.0 to limit exposure</li>
          <li>Ensure firewall rules allow traffic on configured ports</li>
          <li>Monitor listener status on the Dashboard page</li>
        </Typography>
      </Box>
    </Box>
  );
}
