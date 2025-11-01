import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  Chip,
  Alert,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Snackbar,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Webhook as WebhookIcon,
  BugReport as JiraIcon,
  Chat as SlackIcon,
  Email as EmailIcon,
} from '@mui/icons-material';
import { apiService } from '../../services/api';
import { Action } from '../../types';
import { ActionForm } from '../../components/forms/ActionForm';

function Actions() {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedAction, setSelectedAction] = useState<Action | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const queryClient = useQueryClient();

  const { data: actions, isLoading, error } = useQuery({
    queryKey: ['actions'],
    queryFn: apiService.getActions,
  });

  const createMutation = useMutation({
    mutationFn: (actionData: Omit<Action, 'id'>) => apiService.createAction(actionData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['actions'] });
      setSnackbar({ open: true, message: 'Action created successfully', severity: 'success' });
      setCreateDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to create action', severity: 'error' });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: Partial<Action> }) =>
      apiService.updateAction(id, action),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['actions'] });
      setSnackbar({ open: true, message: 'Action updated successfully', severity: 'success' });
      setEditDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to update action', severity: 'error' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiService.deleteAction(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['actions'] });
      setSnackbar({ open: true, message: 'Action deleted successfully', severity: 'success' });
      setDeleteDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to delete action', severity: 'error' });
    },
  });

  const handleCreateAction = (actionData: any) => {
    const newAction: Omit<Action, 'id'> = {
      type: actionData.type,
      config: actionData.config,
    };
    createMutation.mutate(newAction);
  };

  const handleUpdateAction = (actionData: any) => {
    if (selectedAction) {
      updateMutation.mutate({
        id: selectedAction.id,
        action: {
          type: actionData.type,
          config: actionData.config,
        },
      });
    }
  };

  const handleEditAction = (action: Action) => {
    setSelectedAction(action);
    setEditDialogOpen(true);
  };

  const handleDeleteAction = (action: Action) => {
    setSelectedAction(action);
    setDeleteDialogOpen(true);
  };

  const confirmDelete = () => {
    if (selectedAction) {
      deleteMutation.mutate(selectedAction.id);
    }
  };

  const getActionIcon = (type: string) => {
    switch (type) {
      case 'webhook':
        return <WebhookIcon fontSize="large" />;
      case 'jira':
        return <JiraIcon fontSize="large" />;
      case 'slack':
        return <SlackIcon fontSize="large" />;
      case 'email':
        return <EmailIcon fontSize="large" />;
      default:
        return <WebhookIcon fontSize="large" />;
    }
  };

  const getActionColor = (type: string) => {
    switch (type) {
      case 'webhook':
        return '#2196f3';
      case 'jira':
        return '#0052cc';
      case 'slack':
        return '#4a154b';
      case 'email':
        return '#1976d2';
      default:
        return '#1976d2';
    }
  };

  const filteredActions = actions?.filter((action) =>
    action.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
    action.id.toLowerCase().includes(searchTerm.toLowerCase())
  );

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
        Failed to load actions. Please check your connection and try again.
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
          Orchestration Actions
        </Typography>
      </Box>

      <Box sx={{
        mb: 3,
        display: 'flex',
        flexDirection: { xs: 'column', sm: 'row' },
        gap: 2,
        alignItems: { xs: 'stretch', sm: 'center' }
      }}>
        <Button
          variant="contained"
          color="primary"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialogOpen(true)}
        >
          Create Action
        </Button>

        <TextField
          label="Search actions"
          variant="outlined"
          size="small"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          sx={{ minWidth: 250 }}
        />
      </Box>

      <Grid container spacing={{ xs: 2, sm: 3 }}>
        {filteredActions?.map((action) => (
          <Grid item xs={12} sm={6} lg={4} key={action.id}>
            <Card
              sx={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                borderLeft: `4px solid ${getActionColor(action.type)}`,
              }}
            >
              <CardContent sx={{ flexGrow: 1, p: { xs: 2, sm: 3 } }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <Box sx={{ color: getActionColor(action.type), mr: 2 }}>
                    {getActionIcon(action.type)}
                  </Box>
                  <Box>
                    <Typography variant="h6" component="div">
                      {action.type.charAt(0).toUpperCase() + action.type.slice(1)}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      ID: {action.id}
                    </Typography>
                  </Box>
                </Box>

                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    Configuration:
                  </Typography>
                  <Box
                    component="pre"
                    sx={{
                      bgcolor: 'grey.100',
                      p: 1,
                      borderRadius: 1,
                      fontSize: '0.75rem',
                      overflow: 'hidden',
                      maxHeight: 80,
                      mt: 0.5,
                    }}
                  >
                    {JSON.stringify(action.config, null, 2)}
                  </Box>
                </Box>
              </CardContent>

              <CardActions>
                <Button
                  size="small"
                  startIcon={<EditIcon />}
                  onClick={() => handleEditAction(action)}
                >
                  Configure
                </Button>
                <Button
                  size="small"
                  color="error"
                  startIcon={<DeleteIcon />}
                  onClick={() => handleDeleteAction(action)}
                >
                  Delete
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      {filteredActions?.length === 0 && (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <Typography variant="h6" color="textSecondary">
            No actions found
          </Typography>
          <Typography variant="body2" color="textSecondary">
            {searchTerm ? 'Try adjusting your search terms' : 'Create your first orchestration action'}
          </Typography>
        </Box>
      )}

      {/* Create Action Dialog */}
      <ActionForm
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        onSubmit={handleCreateAction}
        title="Create Orchestration Action"
      />

      {/* Edit Action Dialog */}
      <ActionForm
        open={editDialogOpen}
        onClose={() => setEditDialogOpen(false)}
        onSubmit={handleUpdateAction}
        initialData={selectedAction || undefined}
        title="Configure Action"
      />

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete Action</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the action "{selectedAction?.type}"?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button onClick={confirmDelete} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default Actions;