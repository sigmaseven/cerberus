import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
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
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Stack,
} from '@mui/material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon, Upload as UploadIcon, Download as DownloadIcon, Assessment as AssessmentIcon } from '@mui/icons-material';
import { apiService } from '../../services/api';
import { Rule, ImportResult, RuleCategory, LifecycleStatus, UnifiedRuleResponse } from '../../types';
import { RuleForm } from '../../components/forms/RuleForm';
import ExportDialog from '../../components/import-export/ExportDialog';
import ImportDialog from '../../components/import-export/ImportDialog';
import { ProtectedComponent } from '../../components/ProtectedComponent';

/**
 * Extended Rule type with optional lifecycle and performance metadata
 * These fields may be present on rules returned from the unified API
 */
type RuleWithMetadata = Rule & {
  lifecycle_status?: LifecycleStatus;
  performance_stats?: {
    avg_execution_time_ms?: number;
    total_executions?: number;
    total_matches?: number;
  };
};

function Rules() {
  const navigate = useNavigate();
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
  const [categoryFilter, setCategoryFilter] = useState<RuleCategory>('all');
  const [lifecycleFilter, setLifecycleFilter] = useState<LifecycleStatus | ''>('');

  const queryClient = useQueryClient();

  // Fetch rules from API using unified endpoint
  const { data: unifiedData, isLoading, error } = useQuery({
    queryKey: ['unifiedRules', page, rowsPerPage, categoryFilter, lifecycleFilter],
    queryFn: () => apiService.getUnifiedRules({
      category: categoryFilter === 'all' ? undefined : categoryFilter,
      lifecycle_status: lifecycleFilter || undefined,
      page: page + 1,
      limit: rowsPerPage,
    }),
    refetchInterval: 10000, // Poll every 10 seconds
  });

  const unifiedRules = unifiedData?.items || [];
  const totalRules = unifiedData?.total || 0;

  // Mutations for CRUD operations
  const createMutation = useMutation({
    mutationFn: (rule: Omit<Rule, 'id'>) => apiService.createRule(rule),
    onSuccess: async () => {
      // Wait for the query to refetch before closing the dialog
      await queryClient.invalidateQueries({ queryKey: ['unifiedRules'] });
      setCreateDialogOpen(false);
      setSnackbar({ open: true, message: 'Rule created successfully', severity: 'success' });
    },
    onError: (error: Error) => {
      setSnackbar({ open: true, message: `Failed to create rule: ${error.message}`, severity: 'error' });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, rule }: { id: string; rule: Partial<Rule> }) => apiService.updateRule(id, rule),
    onSuccess: async () => {
      // Wait for the query to refetch before closing the dialog
      await queryClient.invalidateQueries({ queryKey: ['unifiedRules'] });
      setEditDialogOpen(false);
      setSnackbar({ open: true, message: 'Rule updated successfully', severity: 'success' });
    },
    onError: (error: Error) => {
      setSnackbar({ open: true, message: `Failed to update rule: ${error.message}`, severity: 'error' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiService.deleteRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['unifiedRules'] });
      setDeleteDialogOpen(false);
      setSnackbar({ open: true, message: 'Rule deleted successfully', severity: 'success' });
    },
    onError: (error: Error) => {
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
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to export rules';
      setExportError(errorMessage);
    } finally {
      setExportLoading(false);
    }
  };

  const handleImport = async (file: File, conflictResolution: 'skip' | 'overwrite' | 'merge') => {
    setImportLoading(true);
    setImportError(null);

    try {
      const result: ImportResult = await apiService.importRules(file, conflictResolution);
      queryClient.invalidateQueries({ queryKey: ['unifiedRules'] });

      if (result.success) {
        setSnackbar({
          open: true,
          message: `Import completed: ${result.successfulImports} rules imported, ${result.failedImports} failed`,
          severity: 'success'
        });
      } else {
        setImportError(`Import failed: ${result.failedImports} rules failed to import`);
      }
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to import rules';
      setImportError(errorMessage);
    } finally {
      setImportLoading(false);
    }
  };

  const handleCreateRule = (ruleData: Omit<Rule, 'id' | 'version'>) => {
    const newRule: Omit<Rule, 'id'> = {
      ...ruleData,
      version: 1,
    };
    createMutation.mutate(newRule);
  };

  const handleUpdateRule = (ruleData: Omit<Rule, 'id' | 'version'>) => {
    if (selectedRule) {
      const updatePayload: Partial<Rule> = {
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

  const handleToggleEnabled = (unifiedRule: UnifiedRuleResponse) => {
    const rule = unifiedRule.rule as Rule;
    updateMutation.mutate({
      id: rule.id,
      rule: { enabled: !rule.enabled },
    });
  };

  const handleEditRule = (unifiedRule: UnifiedRuleResponse) => {
    const rule = unifiedRule.rule as Rule;
    // Always get the latest version from the query cache, not the stale closure
    const latestUnified = unifiedRules?.find(ur => (ur.rule as Rule).id === rule.id);
    const latestRule = latestUnified ? (latestUnified.rule as Rule) : rule;
    setSelectedRule(latestRule);
    setEditDialogOpen(true);
  };

  const handleDeleteRule = (unifiedRule: UnifiedRuleResponse) => {
    const rule = unifiedRule.rule as Rule;
    setSelectedRule(rule);
    setDeleteDialogOpen(true);
  };

  const confirmDelete = () => {
    if (selectedRule) {
      deleteMutation.mutate(selectedRule.id);
    }
  };

  const getSeverityColor = (severity: string): 'error' | 'warning' | 'info' | 'default' => {
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

  const getCategoryColor = (category: RuleCategory): 'primary' | 'secondary' | 'default' => {
    switch (category) {
      case 'detection':
        return 'primary'; // blue
      case 'correlation':
        return 'secondary'; // purple
      default:
        return 'default';
    }
  };

  const getLifecycleColor = (status: LifecycleStatus | undefined): 'success' | 'info' | 'warning' | 'error' | 'default' => {
    switch (status) {
      case 'stable':
        return 'success'; // green
      case 'test':
        return 'info'; // blue
      case 'experimental':
        return 'warning'; // yellow
      case 'deprecated':
        return 'error'; // red
      case 'active':
        return 'success'; // green
      default:
        return 'default';
    }
  };

  const getLogsourceInfo = (rule: Rule) => {
    if (!rule.logsource) return { category: '-', product: '-', service: '-' };
    const logsource = rule.logsource as Record<string, unknown>;
    return {
      category: (logsource.category as string) || '-',
      product: (logsource.product as string) || '-',
      service: (logsource.service as string) || '-',
    };
  };

  const filteredRules = unifiedRules?.filter((unifiedRule) => {
    const rule = unifiedRule.rule as Rule;
    return rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rule.description.toLowerCase().includes(searchTerm.toLowerCase());
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
        Failed to load rules. Please check your connection and try again.
      </Alert>
    );
  }

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        Detection Rules
      </Typography>

      {/* Action Buttons Row */}
      <Box sx={{
        mb: 2,
        display: 'flex',
        flexDirection: { xs: 'column', sm: 'row' },
        gap: 2,
        alignItems: { xs: 'stretch', sm: 'center' }
      }}>
        {/* TASK 3.6: Protect Create Rule button with write:rules permission */}
        <ProtectedComponent permission="write:rules">
          <Button
            variant="contained"
            color="primary"
            startIcon={<AddIcon />}
            onClick={() => setCreateDialogOpen(true)}
            fullWidth={{ xs: true, sm: false }}
          >
            Create Rule
          </Button>
        </ProtectedComponent>

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

        <Button
          variant="outlined"
          startIcon={<AssessmentIcon />}
          onClick={() => navigate('/rules/performance')}
          fullWidth={{ xs: true, sm: false }}
          sx={{ ml: { sm: 'auto' } }}
        >
          Performance
        </Button>
      </Box>

      {/* Filter Controls Row */}
      <Stack
        direction={{ xs: 'column', sm: 'row' }}
        spacing={2}
        sx={{ mb: 3 }}
      >
        <FormControl size="small" sx={{ minWidth: { xs: '100%', sm: 150 } }}>
          <InputLabel id="category-filter-label">Category</InputLabel>
          <Select
            labelId="category-filter-label"
            value={categoryFilter}
            onChange={(e) => {
              setCategoryFilter(e.target.value as RuleCategory);
              setPage(0); // Reset to first page when filter changes
            }}
            label="Category"
            aria-label="Filter rules by category"
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="detection">Detection</MenuItem>
            <MenuItem value="correlation">Correlation</MenuItem>
          </Select>
        </FormControl>

        <FormControl size="small" sx={{ minWidth: { xs: '100%', sm: 150 } }}>
          <InputLabel id="lifecycle-filter-label">Lifecycle</InputLabel>
          <Select
            labelId="lifecycle-filter-label"
            value={lifecycleFilter}
            onChange={(e) => {
              setLifecycleFilter(e.target.value as LifecycleStatus | '');
              setPage(0); // Reset to first page when filter changes
            }}
            label="Lifecycle"
            aria-label="Filter rules by lifecycle status"
          >
            <MenuItem value="">All</MenuItem>
            <MenuItem value="experimental">Experimental</MenuItem>
            <MenuItem value="test">Test</MenuItem>
            <MenuItem value="stable">Stable</MenuItem>
            <MenuItem value="active">Active</MenuItem>
            <MenuItem value="deprecated">Deprecated</MenuItem>
          </Select>
        </FormControl>

        <TextField
          label="Search rules"
          variant="outlined"
          size="small"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          sx={{ minWidth: { xs: '100%', sm: 250 }, flex: 1 }}
          aria-label="Search rules by name or description"
        />
      </Stack>

      <TableContainer component={Paper} sx={{ overflowX: 'auto' }}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Rule Details</TableCell>
              <TableCell>Category</TableCell>
              <TableCell>Lifecycle</TableCell>
              <TableCell>Logsource</TableCell>
              <TableCell>Conditions</TableCell>
              <TableCell>Avg Eval Time</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredRules?.map((unifiedRule) => {
              const rule = unifiedRule.rule as Rule;
              const category = unifiedRule.category;
              const logsource = getLogsourceInfo(rule);

              return (
                <TableRow key={rule.id}>
                  <TableCell sx={{ minWidth: 300 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
                      <Typography variant="body2" sx={{ fontWeight: 500, minWidth: 120 }}>
                        {rule.name}
                      </Typography>
                      <Chip
                        label={rule.severity}
                        color={getSeverityColor(rule.severity)}
                        size="small"
                      />
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2" color="textSecondary">
                          Enabled:
                        </Typography>
                        <Switch
                          checked={rule.enabled}
                          onChange={() => handleToggleEnabled(unifiedRule)}
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
                  <TableCell sx={{ minWidth: 120 }}>
                    <Chip
                      label={category === 'detection' ? 'Detection' : 'Correlation'}
                      color={getCategoryColor(category)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell sx={{ minWidth: 120 }}>
                    {(rule as RuleWithMetadata).lifecycle_status ? (
                      <Chip
                        label={(rule as RuleWithMetadata).lifecycle_status}
                        color={getLifecycleColor((rule as RuleWithMetadata).lifecycle_status)}
                        size="small"
                        sx={{ textTransform: 'capitalize' }}
                      />
                    ) : (
                      <Typography variant="body2" color="textSecondary">
                        -
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell sx={{ minWidth: 180 }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                      {logsource.category !== '-' && (
                        <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                          <Typography variant="caption" color="textSecondary" sx={{ minWidth: 60 }}>
                            Category:
                          </Typography>
                          <Chip
                            label={logsource.category}
                            size="small"
                            variant="outlined"
                            sx={{ height: 20, fontSize: '0.7rem' }}
                          />
                        </Box>
                      )}
                      {logsource.product !== '-' && (
                        <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                          <Typography variant="caption" color="textSecondary" sx={{ minWidth: 60 }}>
                            Product:
                          </Typography>
                          <Chip
                            label={logsource.product}
                            size="small"
                            variant="outlined"
                            sx={{ height: 20, fontSize: '0.7rem' }}
                          />
                        </Box>
                      )}
                      {logsource.service !== '-' && (
                        <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                          <Typography variant="caption" color="textSecondary" sx={{ minWidth: 60 }}>
                            Service:
                          </Typography>
                          <Chip
                            label={logsource.service}
                            size="small"
                            variant="outlined"
                            sx={{ height: 20, fontSize: '0.7rem' }}
                          />
                        </Box>
                      )}
                      {logsource.category === '-' && logsource.product === '-' && logsource.service === '-' && (
                        <Typography variant="body2" color="textSecondary">
                          -
                        </Typography>
                      )}
                    </Box>
                  </TableCell>
                  <TableCell sx={{ minWidth: 100 }}>
                    <Chip
                      label={`${rule.conditions?.length || 0} condition${(rule.conditions?.length || 0) !== 1 ? 's' : ''}`}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell sx={{ minWidth: 100 }}>
                    {(rule as RuleWithMetadata).performance_stats?.avg_execution_time_ms !== undefined ? (
                      <Typography variant="body2">
                        {(rule as RuleWithMetadata).performance_stats.avg_execution_time_ms.toFixed(2)} ms
                      </Typography>
                    ) : (
                      <Typography variant="body2" color="textSecondary">
                        -
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell sx={{ minWidth: 160 }}>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      {/* TASK 3.6: Protect Edit button with write:rules permission */}
                      <ProtectedComponent permission="write:rules">
                        <Button
                          size="small"
                          variant="outlined"
                          color="primary"
                          startIcon={<EditIcon />}
                          onClick={() => handleEditRule(unifiedRule)}
                          aria-label={`Edit rule ${rule.name}`}
                        >
                          Edit
                        </Button>
                      </ProtectedComponent>
                      {/* TASK 3.6: Protect Delete button with write:rules permission */}
                      <ProtectedComponent permission="write:rules">
                        <Button
                          size="small"
                          variant="outlined"
                          color="error"
                          startIcon={<DeleteIcon />}
                          onClick={() => handleDeleteRule(unifiedRule)}
                          aria-label={`Delete rule ${rule.name}`}
                        >
                          Delete
                        </Button>
                      </ProtectedComponent>
                    </Box>
                  </TableCell>
                </TableRow>
              );
            })}
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
        autoHideDuration={snackbar.severity === 'error' ? 10000 : 4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          sx={{
            width: '100%',
            maxWidth: snackbar.severity === 'error' ? '600px' : '400px',
            '& .MuiAlert-message': {
              whiteSpace: 'pre-wrap',
              fontFamily: snackbar.severity === 'error' ? 'monospace' : 'inherit',
              fontSize: snackbar.severity === 'error' ? '0.85rem' : 'inherit',
              maxHeight: '300px',
              overflow: 'auto',
            }
          }}
        >
          {snackbar.message.replace(/\\n/g, '\n').replace(/\\t/g, '\t')}
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default Rules;