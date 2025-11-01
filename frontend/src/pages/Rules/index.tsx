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
} from '@mui/material';
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon } from '@mui/icons-material';
import { apiService } from '../../services/api';
import { Rule } from '../../types';
import { RuleForm } from '../../components/forms/RuleForm';

function Rules() {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const queryClient = useQueryClient();

  const { data: rules, isLoading, error } = useQuery({
    queryKey: ['rules'],
    queryFn: apiService.getRules,
  });

  const createMutation = useMutation({
    mutationFn: (ruleData: Omit<Rule, 'id'>) => apiService.createRule(ruleData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      setSnackbar({ open: true, message: 'Rule created successfully', severity: 'success' });
      setCreateDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to create rule', severity: 'error' });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, rule }: { id: string; rule: Partial<Rule> }) =>
      apiService.updateRule(id, rule),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      setSnackbar({ open: true, message: 'Rule updated successfully', severity: 'success' });
      setEditDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to update rule', severity: 'error' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiService.deleteRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      setSnackbar({ open: true, message: 'Rule deleted successfully', severity: 'success' });
      setDeleteDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to delete rule', severity: 'error' });
    },
  });

  const handleCreateRule = (ruleData: any) => {
    const newRule: Omit<Rule, 'id'> = {
      ...ruleData,
      version: 1,
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

  const handleToggleEnabled = (rule: Rule) => {
    updateMutation.mutate({
      id: rule.id,
      rule: { enabled: !rule.enabled },
    });
  };

  const handleEditRule = (rule: Rule) => {
    setSelectedRule(rule);
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
      <Typography variant="h4" gutterBottom>
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
              <TableCell>Name</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Enabled</TableCell>
              <TableCell>Conditions</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredRules?.map((rule) => (
              <TableRow key={rule.id}>
                <TableCell sx={{ minWidth: 120 }}>
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>
                    {rule.name}
                  </Typography>
                </TableCell>
                <TableCell sx={{ maxWidth: { xs: 150, sm: 300 }, minWidth: 120 }}>
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
                <TableCell sx={{ minWidth: 80 }}>
                  <Chip
                    label={rule.severity}
                    color={getSeverityColor(rule.severity) as any}
                    size="small"
                  />
                </TableCell>
                <TableCell sx={{ minWidth: 80 }}>
                  <Switch
                    checked={rule.enabled}
                    onChange={() => handleToggleEnabled(rule)}
                    size="small"
                  />
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
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
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