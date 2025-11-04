import { useState } from 'react';
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
  Switch,
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
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon, Upload as UploadIcon, Download as DownloadIcon } from '@mui/icons-material';
import { apiService } from '../../services/api';
import { Rule, ImportResult } from '../../types';
import { RuleForm } from '../../components/forms/RuleForm';
import ExportDialog from '../../components/import-export/ExportDialog';
import ImportDialog from '../../components/import-export/ImportDialog';

function Rules() {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null);
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

  // Fetch rules from API
  const { data: paginatedData, isLoading, error } = useQuery({
    queryKey: ['rules', page, rowsPerPage],
    queryFn: () => apiService.getRules(page + 1, rowsPerPage), // Backend uses 1-indexed pages
    refetchInterval: 10000, // Poll every 10 seconds
  });

  const rules = paginatedData?.items || [];
  const totalRules = paginatedData?.total || 0;

  // Mutations for CRUD operations
  const createMutation = useMutation({
    mutationFn: (rule: Omit<Rule, 'id'>) => apiService.createRule(rule),
    onSuccess: async () => {
      // Wait for the query to refetch before closing the dialog
      await queryClient.invalidateQueries({ queryKey: ['rules'] });
      setCreateDialogOpen(false);
      setSnackbar({ open: true, message: 'Rule created successfully', severity: 'success' });
    },
    onError: (error: any) => {
      setSnackbar({ open: true, message: `Failed to create rule: ${error.message}`, severity: 'error' });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, rule }: { id: string; rule: Partial<Rule> }) => apiService.updateRule(id, rule),
    onSuccess: async () => {
      // Wait for the query to refetch before closing the dialog
      await queryClient.invalidateQueries({ queryKey: ['rules'] });
      setEditDialogOpen(false);
      setSnackbar({ open: true, message: 'Rule updated successfully', severity: 'success' });
    },
    onError: (error: any) => {
      setSnackbar({ open: true, message: `Failed to update rule: ${error.message}`, severity: 'error' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiService.deleteRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      setDeleteDialogOpen(false);
      setSnackbar({ open: true, message: 'Rule deleted successfully', severity: 'success' });
    },
    onError: (error: any) => {
      setSnackbar({ open: true, message: `Failed to delete rule: ${error.message}`, severity: 'error' });
    },
  });

  // Import/Export handlers
  const handleExport = async (format: 'json' | 'yaml') => {
    setExportLoading(true);
    setExportError(null);

    try {
      const blob = await apiService.exportRules(format);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `rules.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      setSnackbar({ open: true, message: 'Rules exported successfully', severity: 'success' });
    } catch (error: any) {
      setExportError(error.message || 'Failed to export rules');
    } finally {
      setExportLoading(false);
    }
  };

  const handleImport = async (file: File, conflictResolution: 'skip' | 'overwrite' | 'merge') => {
    setImportLoading(true);
    setImportError(null);

    try {
      const result: ImportResult = await apiService.importRules(file, conflictResolution);
      queryClient.invalidateQueries({ queryKey: ['rules'] });

      if (result.success) {
        setSnackbar({
          open: true,
          message: `Import completed: ${result.successfulImports} rules imported, ${result.failedImports} failed`,
          severity: 'success'
        });
      } else {
        setImportError(`Import failed: ${result.failedImports} rules failed to import`);
      }
    } catch (error: any) {
      setImportError(error.message || 'Failed to import rules');
    } finally {
      setImportLoading(false);
    }
  };

  const handleCreateRule = (ruleData: any) => {
    const newRule: Omit<Rule, 'id'> = {
      ...ruleData,
      version: 1,
    };
    createMutation.mutate(newRule);
  };

  const handleUpdateRule = (ruleData: any) => {
    if (selectedRule) {
      const updatePayload = {
        ...ruleData,
        version: selectedRule.version,
      };
      console.log('Updating rule:', selectedRule.id);
      console.log('Update payload:', JSON.stringify(updatePayload, null, 2));
      updateMutation.mutate({
        id: selectedRule.id,
        rule: updatePayload,
      });
    }
  };

  const handleToggleEnabled = (rule: Rule) => {
    updateMutation.mutate({
      id: rule.id,
      rule: { enabled: !rule.enabled },
    });
  };

  const handleEditRule = (rule: Rule) => {
    // Always get the latest version from the query cache, not the stale closure
    const latestRule = rules?.find(r => r.id === rule.id) || rule;
    setSelectedRule(latestRule);
    setEditDialogOpen(true);
  };

  const handleDeleteRule = (rule: Rule) => {
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
        Failed to load rules. Please check your connection and try again.
      </Alert>
    );
  }

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        Detection Rules
      </Typography>

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
           fullWidth={{ xs: true, sm: false }}
         >
           Create Rule
         </Button>

         <Button
           variant="outlined"
           startIcon={<UploadIcon />}
           onClick={() => setImportDialogOpen(true)}
           fullWidth={{ xs: true, sm: false }}
         >
           Import
         </Button>

         <Button
           variant="outlined"
           startIcon={<DownloadIcon />}
           onClick={() => setExportDialogOpen(true)}
           fullWidth={{ xs: true, sm: false }}
         >
           Export
         </Button>

         <TextField
          label="Search rules"
          variant="outlined"
          size="small"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          sx={{ minWidth: { xs: '100%', sm: 250 } }}
          fullWidth={{ xs: true, sm: false }}
        />
      </Box>

      <TableContainer component={Paper} sx={{ overflowX: 'auto' }}>
        <Table>
           <TableHead>
             <TableRow>
               <TableCell>Rule Details</TableCell>
               <TableCell>Conditions</TableCell>
               <TableCell>Actions</TableCell>
             </TableRow>
           </TableHead>
          <TableBody>
             {filteredRules?.map((rule) => (
               <TableRow key={rule.id}>
                 <TableCell sx={{ minWidth: 300 }}>
                   <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
                     <Typography variant="body2" sx={{ fontWeight: 500, minWidth: 120 }}>
                       {rule.name}
                     </Typography>
                     <Chip
                       label={rule.severity}
                       color={getSeverityColor(rule.severity) as any}
                       size="small"
                     />
                     <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                       <Typography variant="body2" color="textSecondary">
                         Enabled:
                       </Typography>
                       <Switch
                         checked={rule.enabled}
                         onChange={() => handleToggleEnabled(rule)}
                         size="small"
                       />
                     </Box>
                   </Box>
                   <Box sx={{
                     overflow: 'hidden',
                     textOverflow: 'ellipsis',
                     whiteSpace: { xs: 'nowrap', sm: 'normal' }
                   }}>
                     <Typography variant="body2" color="textSecondary">
                       {rule.description}
                     </Typography>
                   </Box>
                 </TableCell>
                 <TableCell sx={{ minWidth: 100 }}>
                   <Chip
                     label={`${rule.conditions.length} condition${rule.conditions.length !== 1 ? 's' : ''}`}
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
            No rules found
          </Typography>
          <Typography variant="body2" color="textSecondary">
            {searchTerm ? 'Try adjusting your search terms' : 'Create your first detection rule'}
          </Typography>
        </Box>
      )}

      {/* Create Rule Dialog */}
      <RuleForm
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        onSubmit={handleCreateRule}
        title="Create Detection Rule"
      />

      {/* Edit Rule Dialog */}
      <RuleForm
        open={editDialogOpen}
        onClose={() => setEditDialogOpen(false)}
        onSubmit={handleUpdateRule}
        initialData={selectedRule || undefined}
        title="Edit Detection Rule"
      />

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Delete Rule</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the rule "{selectedRule?.name}"?
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
        title="Export Detection Rules"
        onExport={handleExport}
        loading={exportLoading}
        error={exportError}
      />

      <ImportDialog
        open={importDialogOpen}
        onClose={() => setImportDialogOpen(false)}
        title="Import Detection Rules"
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

export default Rules;