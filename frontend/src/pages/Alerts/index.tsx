import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Button,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  CircularProgress,
} from '@mui/material';
import { apiService } from '../../services/api';
import { Alert as AlertType, AlertStatus } from '../../types';

function Alerts() {
  const [selectedAlert, setSelectedAlert] = useState<AlertType | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [newAlerts, setNewAlerts] = useState<AlertType[]>([]);

  const queryClient = useQueryClient();

  // Server-side filtering - pass filters to API
  const { data: alerts, isLoading, error } = useQuery({
    queryKey: ['alerts', filterSeverity, filterStatus, searchTerm],
    queryFn: () => apiService.getAlerts(1, 100, {
      severity: filterSeverity,
      status: filterStatus,
      q: searchTerm || undefined,
    }),
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  useEffect(() => {
    // Subscribe to real-time alert updates
    apiService.subscribeToRealtimeUpdates({
      onAlert: (alert: AlertType) => {
        // Add new alert to the beginning of the list
        setNewAlerts(prev => [alert, ...prev.slice(0, 9)]); // Keep only last 10 new alerts

        // Invalidate and refetch alerts to get the latest data
        queryClient.invalidateQueries({ queryKey: ['alerts'] });
      },
    });

    // Cleanup on unmount
    return () => {
      apiService.unsubscribeFromRealtimeUpdates();
    };
  }, [queryClient]);

  const acknowledgeMutation = useMutation({
    mutationFn: (alertId: string) => apiService.acknowledgeAlert(alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });

  const dismissMutation = useMutation({
    mutationFn: (alertId: string) => apiService.dismissAlert(alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });

  const handleAcknowledge = (alertId: string) => {
    acknowledgeMutation.mutate(alertId);
  };

  const handleDismiss = (alertId: string) => {
    dismissMutation.mutate(alertId);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'error';
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'info';
      default:
        return 'default';
    }
  };

  const getStatusColor = (status: AlertStatus) => {
    switch (status) {
      case AlertStatus.Pending:
        return 'warning';
      case AlertStatus.Acknowledged:
        return 'success';
      case AlertStatus.Investigating:
        return 'info';
      case AlertStatus.Resolved:
        return 'success';
      case AlertStatus.Escalated:
        return 'error';
      case AlertStatus.Closed:
        return 'default';
      case AlertStatus.Dismissed:
        return 'default';
      case AlertStatus.FalsePositive:
        return 'warning';
      default:
        return 'default';
    }
  };

  // Server-side filtering is now active - use items directly
  // Client-side filter kept as safety net for any edge cases
  const filteredAlerts = alerts?.items?.filter((alert) => {
    // Severity filter (server handles this, but defensive check)
    const matchesSeverity = filterSeverity === 'all' ||
      (alert.severity && alert.severity.toLowerCase() === filterSeverity.toLowerCase());
    // Status filter (server handles this, but defensive check)
    const matchesStatus = filterStatus === 'all' ||
      (alert.status && alert.status.toLowerCase() === filterStatus.toLowerCase());
    // Search filter
    const matchesSearch = !searchTerm ||
      (alert.rule_id && alert.rule_id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (alert.rule_name && alert.rule_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (alert.event?.event_type && alert.event.event_type.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesSeverity && matchesStatus && matchesSearch;
  });

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
        Failed to load alerts. Please check your connection and try again.
      </Alert>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Alerts Management
      </Typography>

      {newAlerts.length > 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="body2">
            🔔 {newAlerts.length} new alert{newAlerts.length !== 1 ? 's' : ''} received
          </Typography>
        </Alert>
      )}

      <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        <TextField
          label="Search"
          variant="outlined"
          size="small"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          sx={{ minWidth: 200 }}
        />

        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Severity</InputLabel>
          <Select
            value={filterSeverity}
            label="Severity"
            onChange={(e) => setFilterSeverity(e.target.value)}
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="critical">Critical</MenuItem>
            <MenuItem value="high">High</MenuItem>
            <MenuItem value="medium">Medium</MenuItem>
            <MenuItem value="low">Low</MenuItem>
          </Select>
        </FormControl>

        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Status</InputLabel>
          <Select
            value={filterStatus}
            label="Status"
            onChange={(e) => setFilterStatus(e.target.value)}
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value={AlertStatus.Pending}>Pending</MenuItem>
            <MenuItem value={AlertStatus.Acknowledged}>Acknowledged</MenuItem>
            <MenuItem value={AlertStatus.Investigating}>Investigating</MenuItem>
            <MenuItem value={AlertStatus.Resolved}>Resolved</MenuItem>
            <MenuItem value={AlertStatus.Escalated}>Escalated</MenuItem>
            <MenuItem value={AlertStatus.Closed}>Closed</MenuItem>
            <MenuItem value={AlertStatus.Dismissed}>Dismissed</MenuItem>
            <MenuItem value={AlertStatus.FalsePositive}>False Positive</MenuItem>
          </Select>
        </FormControl>

        <Button variant="contained" color="primary">
          Bulk Acknowledge
        </Button>
        <Button variant="outlined" color="secondary">
          Bulk Dismiss
        </Button>
        <Button variant="outlined">
          Export CSV
        </Button>
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Timestamp</TableCell>
              <TableCell>Rule</TableCell>
              <TableCell>Source</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredAlerts?.map((alert) => (
              <TableRow key={alert.alert_id}>
                <TableCell>{alert.alert_id}</TableCell>
                <TableCell>
                  <Chip
                    label={alert.severity}
                    color={getSeverityColor(alert.severity) as any}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={alert.status}
                    color={getStatusColor(alert.status) as any}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  {new Date(alert.timestamp).toLocaleString()}
                </TableCell>
                <TableCell>{alert.rule_id}</TableCell>
                <TableCell>{alert.event.source_ip}</TableCell>
                <TableCell>
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={() => setSelectedAlert(alert)}
                    sx={{ mr: 1 }}
                  >
                    View
                  </Button>
                  {alert.status === AlertStatus.Pending && (
                    <>
                      <Button
                        size="small"
                        variant="contained"
                        color="primary"
                        onClick={() => handleAcknowledge(alert.alert_id)}
                        sx={{ mr: 1 }}
                      >
                        Ack
                      </Button>
                      <Button
                        size="small"
                        variant="outlined"
                        color="secondary"
                        onClick={() => handleDismiss(alert.alert_id)}
                      >
                        Dismiss
                      </Button>
                    </>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog
        open={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Alert Details</DialogTitle>
        <DialogContent>
          {selectedAlert && (
            <Box sx={{ pt: 2 }}>
              <Typography variant="h6" gutterBottom>
                Alert Information
              </Typography>
              <Typography><strong>ID:</strong> {selectedAlert.alert_id}</Typography>
              <Typography><strong>Severity:</strong> {selectedAlert.severity}</Typography>
              <Typography><strong>Status:</strong> {selectedAlert.status}</Typography>
              <Typography><strong>Timestamp:</strong> {new Date(selectedAlert.timestamp).toLocaleString()}</Typography>
              <Typography><strong>Rule:</strong> {selectedAlert.rule_id}</Typography>
              <Typography><strong>Source IP:</strong> {selectedAlert.event.source_ip}</Typography>

              <Typography variant="h6" sx={{ mt: 3, mb: 1 }}>
                Event Data
              </Typography>
              <Typography><strong>Event Type:</strong> {selectedAlert.event.event_type}</Typography>
              <Typography><strong>Raw Data:</strong></Typography>
              <Box
                component="pre"
                sx={{
                  bgcolor: 'grey.100',
                  p: 2,
                  borderRadius: 1,
                  overflow: 'auto',
                  maxHeight: 200,
                  fontSize: '0.875rem',
                }}
              >
                {JSON.stringify(selectedAlert.event.fields, null, 2)}
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSelectedAlert(null)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default Alerts;