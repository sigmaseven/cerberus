import { Box, Button, Dialog, DialogTitle, DialogContent, DialogActions, TextField, Select, MenuItem, FormControl, InputLabel, Typography, Chip } from '@mui/material';
import { CheckCircle, Cancel, Person, Update, FileDownload, Gavel } from '@mui/icons-material';
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiService } from '../../services/api';
import { Alert, AlertStatus, AlertDisposition } from '../../types';

interface ActionsPanelProps {
  alert: Alert;
  onAlertUpdated?: () => void;
}

const ActionsPanel = ({ alert, onAlertUpdated }: ActionsPanelProps) => {
  const queryClient = useQueryClient();

  // Dismiss dialog state
  const [dismissDialogOpen, setDismissDialogOpen] = useState(false);
  const [dismissReason, setDismissReason] = useState('');

  // Assign dialog state
  const [assignDialogOpen, setAssignDialogOpen] = useState(false);
  const [assignTo, setAssignTo] = useState('');
  const [assignNote, setAssignNote] = useState('');

  // Update status dialog state
  const [statusDialogOpen, setStatusDialogOpen] = useState(false);
  const [newStatus, setNewStatus] = useState<AlertStatus>(AlertStatus.Investigating);
  const [statusNote, setStatusNote] = useState('');

  // Disposition dialog state
  const [dispositionDialogOpen, setDispositionDialogOpen] = useState(false);
  const [newDisposition, setNewDisposition] = useState<AlertDisposition>(alert.disposition || 'undetermined');
  const [dispositionReason, setDispositionReason] = useState(alert.disposition_reason || '');



  // Acknowledge mutation
  const acknowledgeMutation = useMutation({
    mutationFn: (alertId: string) => apiService.acknowledgeAlert(alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      if (onAlertUpdated) onAlertUpdated();
    },
  });

  // Dismiss mutation
  const dismissMutation = useMutation({
    mutationFn: (alertId: string) => apiService.dismissAlert(alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setDismissDialogOpen(false);
      setDismissReason('');
      if (onAlertUpdated) onAlertUpdated();
    },
  });

  // Assign mutation
  const assignMutation = useMutation({
    mutationFn: ({ alertId, assignTo, note }: { alertId: string; assignTo: string; note?: string }) =>
      apiService.assignAlert(alertId, assignTo, note),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setAssignDialogOpen(false);
      setAssignTo('');
      setAssignNote('');
      if (onAlertUpdated) onAlertUpdated();
    },
  });

  // Update status mutation
  const updateStatusMutation = useMutation({
    mutationFn: ({ alertId, status, note }: { alertId: string; status: AlertStatus; note?: string }) =>
      apiService.updateAlertStatus(alertId, status, note),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setStatusDialogOpen(false);
      setStatusNote('');
      if (onAlertUpdated) onAlertUpdated();
    },
  });

  // Update disposition mutation
  const updateDispositionMutation = useMutation({
    mutationFn: ({ alertId, disposition, reason }: { alertId: string; disposition: string; reason?: string }) =>
      apiService.updateAlertDisposition(alertId, disposition, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setDispositionDialogOpen(false);
      if (onAlertUpdated) onAlertUpdated();
    },
  });



  const handleAcknowledge = () => {
    acknowledgeMutation.mutate(alert.alert_id);
  };

  const handleDismiss = () => {
    setDismissDialogOpen(true);
  };

  const handleDismissConfirm = () => {
    if (dismissReason.trim()) {
      dismissMutation.mutate(alert.alert_id);
    }
  };

  const handleAssign = () => {
    setAssignDialogOpen(true);
  };

  const handleAssignConfirm = () => {
    if (assignTo.trim()) {
      assignMutation.mutate({
        alertId: alert.alert_id,
        assignTo: assignTo.trim(),
        note: assignNote.trim() || undefined,
      });
    }
  };

  const handleUpdateStatus = () => {
    setStatusDialogOpen(true);
  };

  const handleUpdateStatusConfirm = () => {
    updateStatusMutation.mutate({
      alertId: alert.alert_id,
      status: newStatus,
      note: statusNote.trim() || undefined,
    });
  };

  const handleSetDisposition = () => {
    setNewDisposition(alert.disposition || 'undetermined');
    setDispositionReason(alert.disposition_reason || '');
    setDispositionDialogOpen(true);
  };

  const handleSetDispositionConfirm = () => {
    updateDispositionMutation.mutate({
      alertId: alert.alert_id,
      disposition: newDisposition,
      reason: dispositionReason.trim() || undefined,
    });
  };



  const handleExport = () => {
    // Export single alert as JSON
    const dataStr = JSON.stringify(alert, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `alert-${alert.alert_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const isAcknowledged = alert.status === AlertStatus.Acknowledged || alert.status === AlertStatus.Investigating;
  const isDismissed = alert.status === AlertStatus.Dismissed;

  return (
    <>
      <Box
        sx={{
          borderTop: 1,
          borderColor: 'divider',
          p: 2,
          backgroundColor: '#424242',
          display: 'flex',
          gap: 1,
          flexWrap: 'wrap',
          justifyContent: 'flex-end',
        }}
      >
        <Button
          variant="contained"
          color="primary"
          startIcon={<CheckCircle />}
          onClick={handleAcknowledge}
          disabled={isAcknowledged || isDismissed || acknowledgeMutation.isPending}
          size="small"
        >
          Acknowledge
        </Button>

        <Button
          variant="outlined"
          color="inherit"
          startIcon={<Person />}
          onClick={handleAssign}
          disabled={isDismissed || assignMutation.isPending}
          size="small"
        >
          Assign
        </Button>

        <Button
          variant="outlined"
          color="primary"
          startIcon={<Update />}
          onClick={handleUpdateStatus}
          disabled={isDismissed || updateStatusMutation.isPending}
          size="small"
        >
          Update Status
        </Button>

        <Button
          variant="outlined"
          color="secondary"
          startIcon={<Gavel />}
          onClick={handleSetDisposition}
          disabled={updateDispositionMutation.isPending}
          size="small"
        >
          Set Disposition
        </Button>

        <Button
          variant="outlined"
          color="error"
          startIcon={<Cancel />}
          onClick={handleDismiss}
          disabled={isDismissed || dismissMutation.isPending}
          size="small"
        >
          Dismiss
        </Button>

        <Button
          variant="outlined"
          color="inherit"
          startIcon={<FileDownload />}
          onClick={handleExport}
          size="small"
        >
          Export
        </Button>
      </Box>

      {/* Dismiss Confirmation Dialog */}
      <Dialog open={dismissDialogOpen} onClose={() => setDismissDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Dismiss Alert</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Dismissal Reason (required)"
            fullWidth
            multiline
            rows={3}
            value={dismissReason}
            onChange={(e) => setDismissReason(e.target.value)}
            placeholder="Explain why this alert is being dismissed..."
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDismissDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleDismissConfirm}
            variant="contained"
            color="error"
            disabled={!dismissReason.trim() || dismissMutation.isPending}
          >
            Confirm Dismiss
          </Button>
        </DialogActions>
      </Dialog>

      {/* Assign Alert Dialog */}
      <Dialog open={assignDialogOpen} onClose={() => setAssignDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Assign Alert</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              autoFocus
              label="Assign To (Username or Email)"
              fullWidth
              value={assignTo}
              onChange={(e) => setAssignTo(e.target.value)}
              required
              placeholder="Enter username or email address"
            />
            <TextField
              label="Note (Optional)"
              fullWidth
              multiline
              rows={3}
              value={assignNote}
              onChange={(e) => setAssignNote(e.target.value)}
              placeholder="Add a note about the assignment..."
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAssignDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleAssignConfirm}
            variant="contained"
            color="primary"
            disabled={!assignTo.trim() || assignMutation.isPending}
          >
            {assignMutation.isPending ? 'Assigning...' : 'Assign'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Update Status Dialog */}
      <Dialog open={statusDialogOpen} onClose={() => setStatusDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Update Alert Status</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <FormControl fullWidth>
              <InputLabel>New Status</InputLabel>
              <Select
                value={newStatus}
                label="New Status"
                onChange={(e) => setNewStatus(e.target.value as AlertStatus)}
              >
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
            <TextField
              label="Note (Optional)"
              fullWidth
              multiline
              rows={3}
              value={statusNote}
              onChange={(e) => setStatusNote(e.target.value)}
              placeholder="Add a note about the status change..."
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setStatusDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleUpdateStatusConfirm}
            variant="contained"
            color="primary"
            disabled={updateStatusMutation.isPending}
          >
            {updateStatusMutation.isPending ? 'Updating...' : 'Update Status'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Set Disposition Dialog */}
      <Dialog open={dispositionDialogOpen} onClose={() => setDispositionDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Set Alert Disposition</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            {alert.disposition && alert.disposition !== 'undetermined' && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  Current disposition:
                </Typography>
                <Chip
                  label={alert.disposition.replace('_', ' ')}
                  size="small"
                  color={
                    alert.disposition === 'true_positive' ? 'error' :
                    alert.disposition === 'false_positive' ? 'success' :
                    alert.disposition === 'benign' ? 'info' :
                    alert.disposition === 'suspicious' ? 'warning' :
                    'default'
                  }
                />
              </Box>
            )}
            <FormControl fullWidth>
              <InputLabel>Disposition</InputLabel>
              <Select
                value={newDisposition}
                label="Disposition"
                onChange={(e) => setNewDisposition(e.target.value as AlertDisposition)}
              >
                <MenuItem value="undetermined">Undetermined</MenuItem>
                <MenuItem value="true_positive">True Positive</MenuItem>
                <MenuItem value="false_positive">False Positive</MenuItem>
                <MenuItem value="benign">Benign</MenuItem>
                <MenuItem value="suspicious">Suspicious</MenuItem>
                <MenuItem value="inconclusive">Inconclusive</MenuItem>
              </Select>
            </FormControl>
            <TextField
              label="Reason"
              fullWidth
              multiline
              rows={3}
              value={dispositionReason}
              onChange={(e) => setDispositionReason(e.target.value)}
              placeholder="Explain the reasoning for this disposition..."
              helperText={newDisposition === 'false_positive' ? 'A reason is recommended for false positives' : ''}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDispositionDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleSetDispositionConfirm}
            variant="contained"
            color="primary"
            disabled={updateDispositionMutation.isPending}
          >
            {updateDispositionMutation.isPending ? 'Saving...' : 'Save Disposition'}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ActionsPanel;
