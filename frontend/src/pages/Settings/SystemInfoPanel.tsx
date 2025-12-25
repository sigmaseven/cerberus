import React from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Button,
  List,
  ListItem,
  ListItemText,
  Divider,
  CircularProgress,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Computer as ComputerIcon,
  Storage as StorageIcon,
  Router as RouterIcon,
  Event as EventIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { SystemInfo } from '../../types';

interface SystemInfoPanelProps {
  systemInfo: SystemInfo | null;
  onRefresh: () => void;
}

export default function SystemInfoPanel({ systemInfo, onRefresh }: SystemInfoPanelProps) {
  if (!systemInfo) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '300px' }}>
        <CircularProgress />
      </Box>
    );
  }

  const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (days > 0) {
      return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
      return `${hours}h ${minutes}m`;
    } else {
      return `${minutes}m`;
    }
  };

  const formatNumber = (num: number): string => {
    return num.toLocaleString();
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h6">System Information</Typography>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={onRefresh}
          size="small"
        >
          Refresh
        </Button>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <ComputerIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">System</Typography>
              </Box>

              <List dense>
                <ListItem>
                  <ListItemText
                    primary="Version"
                    secondary={systemInfo.version}
                  />
                  <Chip label="v1.0.0" size="small" color="primary" />
                </ListItem>
                <Divider />
                <ListItem>
                  <ListItemText
                    primary="Go Version"
                    secondary={systemInfo.go_version}
                  />
                </ListItem>
                <Divider />
                <ListItem>
                  <ListItemText
                    primary="Uptime"
                    secondary={formatUptime(systemInfo.uptime)}
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <StorageIcon color="success" sx={{ mr: 1 }} />
                <Typography variant="h6">Data Statistics</Typography>
              </Box>

              <List dense>
                <ListItem>
                  <ListItemText
                    primary="Total Events"
                    secondary={formatNumber(systemInfo.total_events)}
                  />
                  <EventIcon color="action" />
                </ListItem>
                <Divider />
                <ListItem>
                  <ListItemText
                    primary="Total Alerts"
                    secondary={formatNumber(systemInfo.total_alerts)}
                  />
                  <WarningIcon color="warning" />
                </ListItem>
                <Divider />
                <ListItem>
                  <ListItemText
                    primary="Last Cleanup"
                    secondary={
                      systemInfo.last_cleanup
                        ? new Date(systemInfo.last_cleanup).toLocaleString()
                        : 'Never'
                    }
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <RouterIcon color="secondary" sx={{ mr: 1 }} />
                <Typography variant="h6">Active Listeners</Typography>
              </Box>

              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {systemInfo.active_listeners.length > 0 ? (
                  systemInfo.active_listeners.map((listener) => (
                    <Chip
                      key={listener}
                      label={listener.toUpperCase()}
                      color="success"
                      variant="outlined"
                      icon={<RouterIcon />}
                    />
                  ))
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    No active listeners
                  </Typography>
                )}
              </Box>

              <Box sx={{ mt: 3 }}>
                <Typography variant="caption" color="text.secondary" display="block">
                  Active listeners are accepting and processing events. Configure listeners in the
                  "Listeners" tab.
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Box sx={{ mt: 3 }}>
        <Typography variant="caption" color="text.secondary">
          System information is read-only and reflects the current state of the Cerberus SIEM instance.
          Data is refreshed when you click the Refresh button or navigate to this tab.
        </Typography>
      </Box>
    </Box>
  );
}
