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
} from '@mui/material';
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon, Timeline as TimelineIcon } from '@mui/icons-material';
import { apiService } from '../../services/api';
import { CorrelationRule } from '../../types';
import { CorrelationRuleForm } from '../../components/forms/CorrelationRuleForm';

function CorrelationRules() {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<CorrelationRule | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const queryClient = useQueryClient();

  const { data: rules, isLoading, error } = useQuery({
    queryKey: ['correlation-rules'],
    queryFn: apiService.getCorrelationRules,
  });

  const createMutation = useMutation({
    mutationFn: (ruleData: Omit<CorrelationRule, 'id'>) => apiService.createCorrelationRule(ruleData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['correlation-rules'] });
      setSnackbar({ open: true, message: 'Correlation rule created successfully', severity: 'success' });
      setCreateDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to create correlation rule', severity: 'error' });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, rule }: { id: string; rule: Partial<CorrelationRule> }) =>
      apiService.updateCorrelationRule(id, rule),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['correlation-rules'] });
      setSnackbar({ open: true, message: 'Correlation rule updated successfully', severity: 'success' });
      setEditDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to update correlation rule', severity: 'error' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiService.deleteCorrelationRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['correlation-rules'] });
      setSnackbar({ open: true, message: 'Correlation rule deleted successfully', severity: 'success' });
      setDeleteDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to delete correlation rule', severity: 'error' });
    },
  });

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
        rule: ruleData,
      });
    }
  };

  const handleEditRule = (rule: CorrelationRule) => {
    setSelectedRule(rule);
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
      <Typography variant="h4" gutterBottom>
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
                <TableCell>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<EditIcon />}
                    onClick={() => handleEditRule(rule)}
                    sx={{ mr: 1 }}
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
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
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
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
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