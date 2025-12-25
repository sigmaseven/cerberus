import { useState } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  Alert,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Snackbar,
  Chip,
  IconButton,
  Tooltip,
} from '@mui/material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Lock as LockIcon,
  Refresh as RefreshIcon,
  Transform as TransformIcon,
  Science as TestIcon,
} from '@mui/icons-material';

import { apiService } from '../../services/api';
import { FieldMapping, FieldMappingForm } from '../../types';

function FieldMappings() {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedMapping, setSelectedMapping] = useState<FieldMapping | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [formData, setFormData] = useState<FieldMappingForm>({
    name: '',
    description: '',
    mappings: {},
  });
  const [mappingInput, setMappingInput] = useState({ from: '', to: '' });
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const queryClient = useQueryClient();

  // Fetch field mappings from API
  const { data: mappings, isLoading, error } = useQuery({
    queryKey: ['fieldMappings'],
    queryFn: () => apiService.fieldMappings.getFieldMappings(),
    refetchInterval: 30000, // Poll every 30 seconds
  });

  // Reload from YAML mutation
  const reloadMutation = useMutation({
    mutationFn: () => apiService.fieldMappings.reloadFieldMappings(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fieldMappings'] });
      setSnackbar({ open: true, message: 'Field mappings reloaded successfully', severity: 'success' });
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : 'Unknown error';
      setSnackbar({ open: true, message: `Failed to reload mappings: ${message}`, severity: 'error' });
    },
  });

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (mapping: FieldMappingForm) => apiService.fieldMappings.createFieldMapping(mapping),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fieldMappings'] });
      setCreateDialogOpen(false);
      resetForm();
      setSnackbar({ open: true, message: 'Field mapping created successfully', severity: 'success' });
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : 'Unknown error';
      setSnackbar({ open: true, message: `Failed to create mapping: ${message}`, severity: 'error' });
    },
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, mapping }: { id: string; mapping: Partial<FieldMappingForm> }) =>
      apiService.fieldMappings.updateFieldMapping(id, mapping),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fieldMappings'] });
      setEditDialogOpen(false);
      resetForm();
      setSnackbar({ open: true, message: 'Field mapping updated successfully', severity: 'success' });
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : 'Unknown error';
      setSnackbar({ open: true, message: `Failed to update mapping: ${message}`, severity: 'error' });
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiService.fieldMappings.deleteFieldMapping(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fieldMappings'] });
      setDeleteDialogOpen(false);
      setSnackbar({ open: true, message: 'Field mapping deleted successfully', severity: 'success' });
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : 'Unknown error';
      setSnackbar({ open: true, message: `Failed to delete mapping: ${message}`, severity: 'error' });
    },
  });

  const resetForm = () => {
    setFormData({ name: '', description: '', mappings: {} });
    setMappingInput({ from: '', to: '' });
  };

  const handleOpenCreateDialog = () => {
    resetForm();
    setCreateDialogOpen(true);
  };

  const handleOpenEditDialog = (mapping: FieldMapping) => {
    setSelectedMapping(mapping);
    setFormData({
      name: mapping.name,
      description: mapping.description,
      mappings: { ...mapping.mappings },
    });
    setEditDialogOpen(true);
  };

  const handleOpenDeleteDialog = (mapping: FieldMapping) => {
    setSelectedMapping(mapping);
    setDeleteDialogOpen(true);
  };

  const handleAddMapping = () => {
    if (mappingInput.from && mappingInput.to) {
      setFormData((prev) => ({
        ...prev,
        mappings: {
          ...prev.mappings,
          [mappingInput.from]: mappingInput.to,
        },
      }));
      setMappingInput({ from: '', to: '' });
    }
  };

  const handleRemoveMapping = (from: string) => {
    const newMappings = { ...formData.mappings };
    delete newMappings[from];
    setFormData((prev) => ({
      ...prev,
      mappings: newMappings,
    }));
  };

  const handleCreate = () => {
    createMutation.mutate(formData);
  };

  const handleUpdate = () => {
    if (selectedMapping) {
      updateMutation.mutate({
        id: selectedMapping.id,
        mapping: formData,
      });
    }
  };

  const handleDelete = () => {
    if (selectedMapping) {
      deleteMutation.mutate(selectedMapping.id);
    }
  };

  const filteredMappings = mappings?.filter((mapping) =>
    mapping.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    mapping.description.toLowerCase().includes(searchTerm.toLowerCase())
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
        Failed to load field mappings. Please check your connection and try again.
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
        <Typography variant="h4" component="h1" sx={{ mb: { xs: 0, sm: 0 } }}>
          Field Mappings
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
          >
            Reload from YAML
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleOpenCreateDialog}
          >
            Create Mapping
          </Button>
        </Box>
      </Box>

      <Typography variant="body1" color="textSecondary" gutterBottom sx={{ mb: 3 }}>
        Manage field mappings for normalizing log sources to SIGMA standard. Builtin mappings are read-only.
      </Typography>

      <TextField
        fullWidth
        variant="outlined"
        placeholder="Search field mappings..."
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        sx={{ mb: 3 }}
      />

      <Grid container spacing={3}>
        {filteredMappings?.map((mapping) => (
          <Grid item xs={12} md={6} lg={4} key={mapping.id}>
            <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <CardContent sx={{ flexGrow: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <TransformIcon sx={{ mr: 1, color: mapping.is_builtin ? '#ff9800' : '#2196f3' }} />
                  <Typography variant="h6" component="div">
                    {mapping.name}
                  </Typography>
                  {mapping.is_builtin && (
                    <Chip
                      icon={<LockIcon />}
                      label="Builtin"
                      size="small"
                      color="warning"
                      sx={{ ml: 1 }}
                    />
                  )}
                </Box>

                <Typography variant="body2" color="textSecondary" gutterBottom>
                  {mapping.description}
                </Typography>

                <Box sx={{ mt: 2 }}>
                  <Typography variant="caption" color="textSecondary">
                    Field Mappings ({Object.keys(mapping.mappings).length}):
                  </Typography>
                  <Box sx={{ mt: 1, maxHeight: 150, overflowY: 'auto' }}>
                    {Object.entries(mapping.mappings).slice(0, 5).map(([from, to]) => (
                      <Typography key={from} variant="caption" display="block" sx={{ fontFamily: 'monospace' }}>
                        {from} → {to}
                      </Typography>
                    ))}
                    {Object.keys(mapping.mappings).length > 5 && (
                      <Typography variant="caption" color="textSecondary">
                        ... and {Object.keys(mapping.mappings).length - 5} more
                      </Typography>
                    )}
                    {Object.keys(mapping.mappings).length === 0 && (
                      <Typography variant="caption" color="textSecondary">
                        No normalization (direct SIGMA fields)
                      </Typography>
                    )}
                  </Box>
                </Box>
              </CardContent>

              <CardActions sx={{ justifyContent: 'flex-end', p: 2 }}>
                <Button
                  size="small"
                  startIcon={<EditIcon />}
                  onClick={() => handleOpenEditDialog(mapping)}
                  disabled={mapping.is_builtin}
                >
                  Edit
                </Button>
                <Button
                  size="small"
                  color="error"
                  startIcon={<DeleteIcon />}
                  onClick={() => handleOpenDeleteDialog(mapping)}
                  disabled={mapping.is_builtin}
                >
                  Delete
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Create Dialog */}
      <Dialog open={createDialogOpen} onClose={() => setCreateDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create Field Mapping</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            sx={{ mt: 2, mb: 2 }}
            required
          />
          <TextField
            fullWidth
            label="Description"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            multiline
            rows={2}
            sx={{ mb: 2 }}
          />

          <Typography variant="subtitle2" sx={{ mb: 1 }}>Field Mappings</Typography>
          <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
            <TextField
              label="Raw Field"
              value={mappingInput.from}
              onChange={(e) => setMappingInput({ ...mappingInput, from: e.target.value })}
              size="small"
            />
            <TextField
              label="SIGMA Field"
              value={mappingInput.to}
              onChange={(e) => setMappingInput({ ...mappingInput, to: e.target.value })}
              size="small"
            />
            <Button variant="contained" onClick={handleAddMapping}>Add</Button>
          </Box>

          <Box sx={{ maxHeight: 200, overflowY: 'auto' }}>
            {Object.entries(formData.mappings).map(([from, to]) => (
              <Box key={from} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                  {from} → {to}
                </Typography>
                <IconButton size="small" onClick={() => handleRemoveMapping(from)}>
                  <DeleteIcon fontSize="small" />
                </IconButton>
              </Box>
            ))}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleCreate}
            disabled={!formData.name || createMutation.isPending}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={editDialogOpen} onClose={() => setEditDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Edit Field Mapping</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            sx={{ mt: 2, mb: 2 }}
            required
          />
          <TextField
            fullWidth
            label="Description"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            multiline
            rows={2}
            sx={{ mb: 2 }}
          />

          <Typography variant="subtitle2" sx={{ mb: 1 }}>Field Mappings</Typography>
          <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
            <TextField
              label="Raw Field"
              value={mappingInput.from}
              onChange={(e) => setMappingInput({ ...mappingInput, from: e.target.value })}
              size="small"
            />
            <TextField
              label="SIGMA Field"
              value={mappingInput.to}
              onChange={(e) => setMappingInput({ ...mappingInput, to: e.target.value })}
              size="small"
            />
            <Button variant="contained" onClick={handleAddMapping}>Add</Button>
          </Box>

          <Box sx={{ maxHeight: 200, overflowY: 'auto' }}>
            {Object.entries(formData.mappings).map(([from, to]) => (
              <Box key={from} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                  {from} → {to}
                </Typography>
                <IconButton size="small" onClick={() => handleRemoveMapping(from)}>
                  <DeleteIcon fontSize="small" />
                </IconButton>
              </Box>
            ))}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleUpdate}
            disabled={!formData.name || updateMutation.isPending}
          >
            Update
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete Field Mapping</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the field mapping "{selectedMapping?.name}"?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            onClick={handleDelete}
            disabled={deleteMutation.isPending}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default FieldMappings;
