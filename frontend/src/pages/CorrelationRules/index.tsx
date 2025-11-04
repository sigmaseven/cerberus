import { useState } from 'react';
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
  Alert,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Snackbar,
  TablePagination,
} from '@mui/material';
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon, Timeline as TimelineIcon, Upload as UploadIcon, Download as DownloadIcon } from '@mui/icons-material';
import { apiService } from '../../services/api';
import { CorrelationRule, ImportResult } from '../../types';
import { CorrelationRuleForm } from '../../components/forms/CorrelationRuleForm';
import ExportDialog from '../../components/import-export/ExportDialog';
import ImportDialog from '../../components/import-export/ImportDialog';

function CorrelationRules() {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<CorrelationRule | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [exportLoading, setExportLoading] = useState(false);
  const [importLoading, setImportLoading] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);

  const queryClient = useQueryClient();

  // Fetch correlation rules from API
  const { data: paginatedData, isLoading, error } = useQuery({
    queryKey: ['correlationRules', page, rowsPerPage],
    queryFn: () => apiService.getCorrelationRules(page + 1, rowsPerPage), // Backend uses 1-indexed pages
    refetchInterval: 10000, // Poll every 10 seconds
  });

  const rules = paginatedData?.items || [];
  const totalRules = paginatedData?.total || 0;

  // Mutation for creating correlation rules
  const createMutation = useMutation({
    mutationFn: (ruleData: any) => apiService.createCorrelationRule(ruleData),
    onSuccess: async () => {
      // Wait for the query to refetch before closing the dialog
      await queryClient.invalidateQueries({ queryKey: ['correlationRules'] });
      setCreateDialogOpen(false);
      setSnackbar({ open: true, message: 'Correlation rule created successfully', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to create correlation rule', severity: 'error' });
    },
  });

  // Mutation for updating correlation rules
  const updateMutation = useMutation({
    mutationFn: ({ id, rule }: { id: string; rule: any }) => apiService.updateCorrelationRule(id, rule),
    onSuccess: async () => {
      // Wait for the query to refetch before closing the dialog
      await queryClient.invalidateQueries({ queryKey: ['correlationRules'] });
      setEditDialogOpen(false);
      setSnackbar({ open: true, message: 'Correlation rule updated successfully', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to update correlation rule', severity: 'error' });
    },
  });

  // Mutation for deleting correlation rules
  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiService.deleteCorrelationRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['correlationRules'] });
      setSnackbar({ open: true, message: 'Correlation rule deleted successfully', severity: 'success' });
      setDeleteDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to delete correlation rule', severity: 'error' });
    },
  });

  // Import/Export handlers
  const handleExport = async (format: 'json' | 'yaml') => {
    setExportLoading(true);
    setExportError(null);

    try {
      const blob = await apiService.exportCorrelationRules(format);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `correlation_rules.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      setSnackbar({ open: true, message: 'Correlation rules exported successfully', severity: 'success' });
    } catch (error: any) {
      setExportError(error.message || 'Failed to export correlation rules');
    } finally {
      setExportLoading(false);
    }
  };

  const handleImport = async (file: File, conflictResolution: 'skip' | 'overwrite' | 'merge') => {
    setImportLoading(true);
    setImportError(null);

    try {
      const result: ImportResult = await apiService.importCorrelationRules(file, conflictResolution);
      queryClient.invalidateQueries({ queryKey: ['correlationRules'] });

      if (result.success) {
        setSnackbar({
          open: true,
          message: `Import completed: ${result.successfulImports} correlation rules imported, ${result.failedImports} failed`,
          severity: 'success'
        });
      } else {
        setImportError(`Import failed: ${result.failedImports} correlation rules failed to import`);
      }
    } catch (error: any) {
      setImportError(error.message || 'Failed to import correlation rules');
    } finally {
      setImportLoading(false);
    }
  };

  const handleCreateRule = (ruleData: any) => {
    const newRule: Omit<CorrelationRule, 'id'> = {
      ...ruleData,
    };
    createMutation.mutate(newRule);
  };

  const handleUpdateRule = (ruleData: any) => {
    if (selectedRule) {
      updateMutation.mutate({
        id: selectedRule.id,
        rule: {
          ...ruleData,
          version: selectedRule.version,
        },
      });
    }
  };

  const handleEditRule = (rule: CorrelationRule) => {
    // Always get the latest version from the query cache, not the stale closure
    const latestRule = rules?.find(r => r.id === rule.id) || rule;
    setSelectedRule(latestRule);
    setEditDialogOpen(true);
  };

  const handleDeleteRule = (rule: CorrelationRule) => {
    setSelectedRule(rule);
    setDeleteDialogOpen(true);
  };

  const confirmDelete = () => {
    if (selectedRule) {
      deleteMutation.mutate(selectedRule.id);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'error';
      case 'High':
        return 'error';
      case 'Medium':
        return 'warning';
      case 'Low':
        return 'info';
      default:
        return 'default';
    }
  };

  const formatWindow = (windowNs: number) => {
    const seconds = windowNs / 1000000000;
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  const filteredRules = rules?.filter((rule) =>
    rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    rule.description.toLowerCase().includes(searchTerm.toLowerCase())
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
        Failed to load correlation rules. Please check your connection and try again.
      </Alert>
    );
  }

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        Correlation Rules
      </Typography>

       <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap', alignItems: 'center' }}>
         <Button
           variant="contained"
           color="primary"
           startIcon={<AddIcon />}
           onClick={() => setCreateDialogOpen(true)}
         >
           Create Correlation Rule
         </Button>

         <Button
           variant="outlined"
           startIcon={<UploadIcon />}
           onClick={() => setImportDialogOpen(true)}
         >
           Import
         </Button>

         <Button
           variant="outlined"
           startIcon={<DownloadIcon />}
           onClick={() => setExportDialogOpen(true)}
         >
           Export
         </Button>

         <TextField
          label="Search rules"
          variant="outlined"
          size="small"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          sx={{ minWidth: 250 }}
        />
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Sequence</TableCell>
              <TableCell>Window</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredRules?.map((rule) => (
              <TableRow key={rule.id}>
                <TableCell>{rule.name}</TableCell>
                <TableCell sx={{ maxWidth: 300 }}>
                  <Box sx={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {rule.description}
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip
                    label={rule.severity}
                    color={getSeverityColor(rule.severity) as any}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    <TimelineIcon fontSize="small" />
                    <Typography variant="body2">
                      {rule.sequence.join(' → ')}
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip
                    label={formatWindow(rule.window)}
                    size="small"
                    variant="outlined"
                  />
                </TableCell>
                <TableCell sx={{ minWidth: 160 }}>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={<EditIcon />}
                      onClick={() => handleEditRule(rule)}
                      sx={{
                        color: '#00ff00',
                        borderColor: '#00ff00',
                        '&:hover': {
                          borderColor: '#00cc00',
                          backgroundColor: 'rgba(0, 255, 0, 0.08)',
                        },
                      }}
                    >
                      Edit
                    </Button>
                    <Button
                      size="small"
                      variant="outlined"
                      color="error"
                      startIcon={<DeleteIcon />}
                      onClick={() => handleDeleteRule(rule)}
                    >
                      Delete
                    </Button>
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <TablePagination
          component="div"
          count={totalRules}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(event) => {
            setRowsPerPage(parseInt(event.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[10, 25, 50, 100]}
        />
      </TableContainer>

      {filteredRules?.length === 0 && (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <Typography variant="h6" color="textSecondary">
            No correlation rules found
          </Typography>
          <Typography variant="body2" color="textSecondary">
            {searchTerm ? 'Try adjusting your search terms' : 'Create your first correlation rule'}
          </Typography>
        </Box>
      )}

      {/* Create Rule Dialog */}
      <CorrelationRuleForm
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        onSubmit={handleCreateRule}
        title="Create Correlation Rule"
      />

      {/* Edit Rule Dialog */}
      <CorrelationRuleForm
        open={editDialogOpen}
        onClose={() => setEditDialogOpen(false)}
        onSubmit={handleUpdateRule}
        initialData={selectedRule || undefined}
        title="Edit Correlation Rule"
      />

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Delete Correlation Rule</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the correlation rule "{selectedRule?.name}"?
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

      {/* Import/Export Dialogs */}
      <ExportDialog
        open={exportDialogOpen}
        onClose={() => setExportDialogOpen(false)}
        title="Export Correlation Rules"
        onExport={handleExport}
        loading={exportLoading}
        error={exportError}
      />

      <ImportDialog
        open={importDialogOpen}
        onClose={() => setImportDialogOpen(false)}
        title="Import Correlation Rules"
        onImport={handleImport}
        loading={importLoading}
        error={importError}
      />

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

export default CorrelationRules;