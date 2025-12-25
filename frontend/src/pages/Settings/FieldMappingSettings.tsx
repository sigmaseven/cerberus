import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Stack,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  CircularProgress,
  Tooltip,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  Science as TestIcon,
  AutoFixHigh as DiscoverIcon,
  ExpandMore as ExpandMoreIcon,
  Save as SaveIcon,
  Close as CloseIcon,
  Lock as LockIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiService } from '../../services/api';
import {
  FieldMapping,
  FieldMappingForm,
  TestMappingRequest,
  TestMappingResponse,
  FieldDiscoveryResponse,
} from '../../types';

export default function FieldMappingSettings() {
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Dialog states
  const [editDialog, setEditDialog] = useState(false);
  const [testDialog, setTestDialog] = useState(false);
  const [discoverDialog, setDiscoverDialog] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<FieldMapping | null>(null);

  // Form states
  const [selectedMapping, setSelectedMapping] = useState<FieldMapping | null>(null);
  const [formData, setFormData] = useState<FieldMappingForm>({
    name: '',
    description: '',
    mappings: {},
  });
  const [isNewMapping, setIsNewMapping] = useState(false);

  // Test states
  const [testLogSource, setTestLogSource] = useState('');
  const [testSampleLog, setTestSampleLog] = useState('');
  const [testResult, setTestResult] = useState<TestMappingResponse | null>(null);

  // Discovery states
  const [discoverySampleLog, setDiscoverySampleLog] = useState('');
  const [discoveryResult, setDiscoveryResult] = useState<FieldDiscoveryResponse | null>(null);

  // Fetch field mappings
  const { data: mappings, isLoading } = useQuery({
    queryKey: ['fieldMappings'],
    queryFn: () => apiService.fieldMappings.getFieldMappings(),
    refetchInterval: 30000,
  });

  // Reload mutation
  const reloadMutation = useMutation({
    mutationFn: () => apiService.fieldMappings.reloadFieldMappings(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fieldMappings'] });
      setSuccess('Field mappings reloaded successfully');
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(`Failed to reload mappings: ${message}`);
    },
  });

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (mapping: FieldMappingForm) => apiService.fieldMappings.createFieldMapping(mapping),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fieldMappings'] });
      setEditDialog(false);
      resetForm();
      setSuccess('Field mapping created successfully');
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(`Failed to create mapping: ${message}`);
    },
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, mapping }: { id: string; mapping: Partial<FieldMappingForm> }) =>
      apiService.fieldMappings.updateFieldMapping(id, mapping),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fieldMappings'] });
      setEditDialog(false);
      resetForm();
      setSuccess('Field mapping updated successfully');
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(`Failed to update mapping: ${message}`);
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiService.fieldMappings.deleteFieldMapping(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fieldMappings'] });
      setDeleteConfirm(null);
      setSuccess('Field mapping deleted successfully');
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(`Failed to delete mapping: ${message}`);
    },
  });

  const resetForm = () => {
    setFormData({ name: '', description: '', mappings: {} });
    setSelectedMapping(null);
  };

  const handleCreateNew = () => {
    resetForm();
    setIsNewMapping(true);
    setEditDialog(true);
  };

  const handleEdit = (mapping: FieldMapping) => {
    setSelectedMapping(mapping);
    setFormData({
      name: mapping.name,
      description: mapping.description,
      mappings: { ...mapping.mappings },
    });
    setIsNewMapping(false);
    setEditDialog(true);
  };

  const handleSaveMapping = () => {
    if (!formData.name.trim()) {
      setError('Mapping name is required');
      return;
    }

    if (isNewMapping) {
      createMutation.mutate(formData);
    } else if (selectedMapping) {
      updateMutation.mutate({
        id: selectedMapping.id,
        mapping: formData,
      });
    }
  };

  const handleDelete = () => {
    if (deleteConfirm) {
      deleteMutation.mutate(deleteConfirm.id);
    }
  };

  const handleTestMapping = async () => {
    try {
      const sampleLog = JSON.parse(testSampleLog);
      const result = await apiService.fieldMappings.testFieldMapping({
        log_source: testLogSource || undefined,
        sample_log: sampleLog,
      });
      setTestResult(result);
      setError(null);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(`Failed to test mapping. Check JSON format. ${message}`);
    }
  };

  const handleDiscoverFields = async () => {
    try {
      const sampleLog = JSON.parse(discoverySampleLog);
      const result = await apiService.fieldMappings.discoverFields(sampleLog);
      setDiscoveryResult(result);
      setError(null);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(`Failed to discover fields. Check JSON format. ${message}`);
    }
  };

  const handleApplyDiscovered = () => {
    if (discoveryResult) {
      setFormData({
        name: discoveryResult.detected_source,
        description: `Auto-discovered mapping for ${discoveryResult.detected_source}`,
        mappings: discoveryResult.suggested_mappings,
      });
      setIsNewMapping(true);
      setDiscoverDialog(false);
      setEditDialog(true);
    }
  };

  const addMappingField = () => {
    setFormData({
      ...formData,
      mappings: {
        ...formData.mappings,
        '': '',
      },
    });
  };

  const updateMappingField = (oldKey: string, newKey: string, value: string) => {
    const updated = { ...formData.mappings };
    if (oldKey !== newKey) {
      delete updated[oldKey];
    }
    if (newKey.trim()) {
      updated[newKey] = value;
    }
    setFormData({ ...formData, mappings: updated });
  };

  const removeMappingField = (key: string) => {
    const updated = { ...formData.mappings };
    delete updated[key];
    setFormData({ ...formData, mappings: updated });
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h6" gutterBottom>
            Field Mapping Configuration
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Configure how raw log fields are normalized to SIGMA standard field names
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
          >
            Reload
          </Button>
          <Button
            variant="outlined"
            startIcon={<TestIcon />}
            onClick={() => setTestDialog(true)}
          >
            Test
          </Button>
          <Button
            variant="outlined"
            startIcon={<DiscoverIcon />}
            onClick={() => setDiscoverDialog(true)}
          >
            Discover
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleCreateNew}
          >
            Add Mapping
          </Button>
        </Stack>
      </Box>

      <Alert severity="info" sx={{ mb: 3 }}>
        Field mappings normalize raw log field names to SIGMA standard fields, enabling detection rules
        to work across different log sources. Builtin mappings are read-only and cannot be modified.
      </Alert>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}

      <Grid container spacing={2}>
        {mappings?.map((mapping) => (
          <Grid item xs={12} key={mapping.id}>
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: 'flex', alignItems: 'center', width: '100%', pr: 2 }}>
                  <Typography sx={{ flexGrow: 1, fontWeight: 'medium' }}>
                    {mapping.name}
                  </Typography>
                  {mapping.is_builtin && (
                    <Chip
                      icon={<LockIcon />}
                      label="Builtin"
                      size="small"
                      color="warning"
                      sx={{ mr: 1 }}
                    />
                  )}
                  <Chip
                    label={`${Object.keys(mapping.mappings).length} mappings`}
                    size="small"
                    sx={{ mr: 2 }}
                  />
                  <Stack direction="row" spacing={1}>
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleEdit(mapping);
                      }}
                      disabled={mapping.is_builtin}
                    >
                      <EditIcon fontSize="small" />
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        setDeleteConfirm(mapping);
                      }}
                      disabled={mapping.is_builtin}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Stack>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                {mapping.description && (
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {mapping.description}
                  </Typography>
                )}
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell><strong>Raw Field</strong></TableCell>
                        <TableCell><strong>SIGMA Field</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {Object.keys(mapping.mappings).length > 0 ? (
                        Object.entries(mapping.mappings).map(([raw, sigma]) => (
                          <TableRow key={raw}>
                            <TableCell><code>{raw}</code></TableCell>
                            <TableCell><code>{sigma}</code></TableCell>
                          </TableRow>
                        ))
                      ) : (
                        <TableRow>
                          <TableCell colSpan={2} align="center">
                            <Typography variant="body2" color="text.secondary">
                              No normalization (direct SIGMA fields)
                            </Typography>
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </TableContainer>
              </AccordionDetails>
            </Accordion>
          </Grid>
        ))}
      </Grid>

      {/* Edit/Create Dialog */}
      <Dialog open={editDialog} onClose={() => setEditDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {isNewMapping ? 'Create Field Mapping' : `Edit Field Mapping: ${formData.name}`}
        </DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="e.g., windows_sysmon, firewall, custom_app"
            sx={{ mb: 2, mt: 1 }}
            helperText="Unique identifier for this field mapping"
            required
            disabled={!isNewMapping}
          />

          <TextField
            fullWidth
            label="Description"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            placeholder="Describe this field mapping"
            multiline
            rows={2}
            sx={{ mb: 2 }}
          />

          <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
            Field Mappings
          </Typography>

          <Stack spacing={2}>
            {Object.entries(formData.mappings).map(([rawField, sigmaField]) => (
              <Box key={rawField} sx={{ display: 'flex', gap: 1 }}>
                <TextField
                  label="Raw Field"
                  value={rawField}
                  onChange={(e) => updateMappingField(rawField, e.target.value, sigmaField)}
                  size="small"
                  sx={{ flex: 1 }}
                />
                <TextField
                  label="SIGMA Field"
                  value={sigmaField}
                  onChange={(e) => updateMappingField(rawField, rawField, e.target.value)}
                  size="small"
                  sx={{ flex: 1 }}
                />
                <IconButton onClick={() => removeMappingField(rawField)} size="small">
                  <CloseIcon />
                </IconButton>
              </Box>
            ))}
          </Stack>

          <Button
            startIcon={<AddIcon />}
            onClick={addMappingField}
            sx={{ mt: 2 }}
          >
            Add Field
          </Button>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialog(false)}>Cancel</Button>
          <Button
            onClick={handleSaveMapping}
            variant="contained"
            startIcon={<SaveIcon />}
            disabled={createMutation.isPending || updateMutation.isPending}
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>

      {/* Test Dialog */}
      <Dialog open={testDialog} onClose={() => setTestDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Test Field Mapping</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Log Source (optional)"
            value={testLogSource}
            onChange={(e) => setTestLogSource(e.target.value)}
            placeholder="Leave empty for auto-detection"
            sx={{ mb: 2, mt: 1 }}
          />

          <TextField
            fullWidth
            multiline
            rows={8}
            label="Sample Log (JSON)"
            value={testSampleLog}
            onChange={(e) => setTestSampleLog(e.target.value)}
            placeholder='{"process_name": "cmd.exe", "command_line": "whoami", ...}'
            sx={{ mb: 2 }}
          />

          <Button
            variant="contained"
            startIcon={<TestIcon />}
            onClick={handleTestMapping}
            fullWidth
          >
            Test Mapping
          </Button>

          {testResult && (
            <Box sx={{ mt: 3 }}>
              <Alert severity="success" sx={{ mb: 2 }}>
                Detected source: <strong>{testResult.detected_source}</strong> |
                Applied mapping: <strong>{testResult.applied_mapping}</strong>
              </Alert>

              <Typography variant="subtitle2" gutterBottom>Normalized Fields:</Typography>
              <Paper sx={{ p: 2, bgcolor: 'grey.100' }}>
                <pre style={{ margin: 0, fontSize: '0.875rem', overflow: 'auto' }}>
                  {JSON.stringify(testResult.normalized_log, null, 2)}
                </pre>
              </Paper>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTestDialog(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Discovery Dialog */}
      <Dialog open={discoverDialog} onClose={() => setDiscoverDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Discover Field Mappings</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, mt: 1 }}>
            Paste a sample log event and we'll auto-suggest SIGMA field mappings
          </Typography>

          <TextField
            fullWidth
            multiline
            rows={8}
            label="Sample Log (JSON)"
            value={discoverySampleLog}
            onChange={(e) => setDiscoverySampleLog(e.target.value)}
            placeholder='{"process_name": "cmd.exe", "user": "admin", ...}'
            sx={{ mb: 2 }}
          />

          <Button
            variant="contained"
            startIcon={<DiscoverIcon />}
            onClick={handleDiscoverFields}
            fullWidth
          >
            Discover Fields
          </Button>

          {discoveryResult && (
            <Box sx={{ mt: 3 }}>
              <Alert severity="info" sx={{ mb: 2 }}>
                Detected log source: <strong>{discoveryResult.detected_source}</strong>
              </Alert>

              <Typography variant="subtitle2" gutterBottom>Suggested Mappings:</Typography>
              <TableContainer component={Paper} sx={{ mb: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Raw Field</TableCell>
                      <TableCell>→</TableCell>
                      <TableCell>SIGMA Field</TableCell>
                      <TableCell>Type</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {Object.entries(discoveryResult.suggested_mappings).map(([raw, sigma]) => (
                      <TableRow key={raw}>
                        <TableCell><code>{raw}</code></TableCell>
                        <TableCell>→</TableCell>
                        <TableCell><code>{sigma}</code></TableCell>
                        <TableCell>{discoveryResult.field_types[raw]}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              {discoveryResult.unmapped_fields.length > 0 && (
                <>
                  <Typography variant="subtitle2" gutterBottom>Unmapped Fields:</Typography>
                  <Box sx={{ mb: 2 }}>
                    {discoveryResult.unmapped_fields.map((field) => (
                      <Chip key={field} label={field} size="small" sx={{ mr: 1, mb: 1 }} />
                    ))}
                  </Box>
                </>
              )}

              <Button
                variant="contained"
                onClick={handleApplyDiscovered}
                fullWidth
              >
                Use These Mappings
              </Button>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDiscoverDialog(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteConfirm} onClose={() => setDeleteConfirm(null)}>
        <DialogTitle>Confirm Delete</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the field mapping "<strong>{deleteConfirm?.name}</strong>"?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          <Button
            onClick={handleDelete}
            color="error"
            variant="contained"
            disabled={deleteMutation.isPending}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
