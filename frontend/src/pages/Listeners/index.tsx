import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Alert,
  CircularProgress,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import {
  Wifi as WifiIcon,
  WifiOff as WifiOffIcon,
  Refresh as RefreshIcon,
  Settings as SettingsIcon,
} from '@mui/icons-material';
import { apiService } from '../../services/api';

function Listeners() {
  const [configDialogOpen, setConfigDialogOpen] = useState(false);

  const { data: listeners, isLoading, error, refetch } = useQuery({
    queryKey: ['listeners'],
    queryFn: apiService.getListeners,
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  useEffect(() => {
    // Subscribe to real-time listener status updates
    apiService.subscribeToRealtimeUpdates({
      onListenerStatus: (status: any) => {
        // Invalidate and refetch listener status
        refetch();
      },
    });

    // Cleanup on unmount
    return () => {
      apiService.unsubscribeFromRealtimeUpdates();
    };
  }, [refetch]);

  const getStatusColor = (active: boolean): 'success' | 'error' => {
    return active ? 'success' : 'error';
  };

  const getStatusIcon = (active: boolean) => {
    return active ? <WifiIcon /> : <WifiOffIcon />;
  };

  const formatEventsPerMinute = (rate: number) => {
    if (rate === 0) return '0';
    if (rate < 1) return '< 1';
    return rate.toFixed(1);
  };

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error">
        Failed to load listener status. Please check your connection and try again.
      </Alert>
    );
  }

  return (
    <Box>
      <Box sx={{
        display: 'flex',
        flexDirection: { xs: 'column', sm: 'row' },
        justifyContent: { xs: 'flex-start', sm: 'space-between' },
        alignItems: { xs: 'flex-start', sm: 'center' },
        gap: { xs: 2, sm: 1 },
        mb: 3
      }}>
        <Typography variant="h4" sx={{ mb: { xs: 0, sm: 0 } }}>
          Event Listeners
        </Typography>
        <Box sx={{
          display: 'flex',
          gap: 1,
          width: { xs: '100%', sm: 'auto' },
          justifyContent: { xs: 'space-between', sm: 'flex-end' }
        }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => refetch()}
          >
            Refresh
          </Button>
          <Button
            variant="outlined"
            startIcon={<SettingsIcon />}
            onClick={() => setConfigDialogOpen(true)}
          >
            Configure
          </Button>
        </Box>
      </Box>

      <Typography variant="body1" color="textSecondary" gutterBottom>
        Monitor the status of event ingestion listeners. Each listener processes events from different sources.
      </Typography>

      <Grid container spacing={{ xs: 2, sm: 3 }}>
        {listeners && Object.entries(listeners).map(([name, status]: [string, { active: boolean; port: number; events_per_minute: number; errors: number }]) => (
          <Grid item xs={12} sm={6} lg={4} key={name}>
            <Card
              sx={{
                height: '100%',
                borderLeft: `4px solid ${status.active ? '#4caf50' : '#f44336'}`,
              }}
            >
              <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <Box sx={{ color: status.active ? '#4caf50' : '#f44336', mr: 2 }}>
                    {getStatusIcon(status.active)}
                  </Box>
                  <Box>
                    <Typography variant="h6" component="div">
                      {name.toUpperCase()} Listener
                    </Typography>
                    <Chip
                      label={status.active ? 'Active' : 'Inactive'}
                      color={getStatusColor(status.active)}
                      size="small"
                      sx={{ mt: 0.5 }}
                    />
                  </Box>
                </Box>

                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    Port: {status.port}
                  </Typography>
                </Box>

                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    Events/min: {formatEventsPerMinute(status.events_per_minute)}
                  </Typography>
                </Box>

                <Box>
                  <Typography variant="body2" color="textSecondary">
                    Errors: {status.errors}
                  </Typography>
                  {status.errors > 0 && (
                    <Alert severity="warning" sx={{ mt: 1, py: 0 }}>
                      <Typography variant="caption">
                        Check logs for error details
                      </Typography>
                    </Alert>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Configuration Dialog */}
      <Dialog open={configDialogOpen} onClose={() => setConfigDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Listener Configuration</DialogTitle>
        <DialogContent>
          <Typography variant="body1" gutterBottom>
            Listener configuration is managed through the Cerberus configuration file.
            To modify listener settings, update the configuration and restart the service.
          </Typography>

          <Typography variant="body2" color="textSecondary" sx={{ mt: 2 }}>
            Common configuration options:
          </Typography>

          <Box component="ul" sx={{ mt: 1, pl: 3 }}>
            <li>Port numbers for each listener</li>
            <li>Enable/disable specific listeners</li>
            <li>Connection timeouts and buffer sizes</li>
            <li>TLS/SSL certificate configuration</li>
            <li>Rate limiting and throttling settings</li>
          </Box>

          <Alert severity="info" sx={{ mt: 3 }}>
            <Typography variant="body2">
              <strong>Note:</strong> Configuration changes require a service restart to take effect.
            </Typography>
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default Listeners;