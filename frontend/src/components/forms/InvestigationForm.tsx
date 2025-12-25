import React from 'react';
import {
  Box,
  TextField,
  Button,
  FormControl,
  FormLabel,
  Stack,
  Chip,
  Alert,
  Autocomplete,
  Typography,
  Divider} from '@mui/material';
import { Add as AddIcon } from '@mui/icons-material';
import type { InvestigationPriority, Alert as AlertType } from '../../types';

interface InvestigationFormData {
  title: string;
  description: string;
  priority: InvestigationPriority;
  assignee_id?: string;
  alert_ids?: string[];
}

interface InvestigationFormProps {
  onSubmit: (data: InvestigationFormData) => Promise<void>;
  onCancel: () => void;
  initialData?: Partial<InvestigationFormData>;
  availableAlerts?: AlertType[];
  loading?: boolean;
}

export const InvestigationForm: React.FC<InvestigationFormProps> = ({
  onSubmit,
  onCancel,
  initialData,
  availableAlerts = [],
  loading = false}) => {
  const [title, setTitle] = React.useState(initialData?.title || '');
  const [description, setDescription] = React.useState(initialData?.description || '');
  const [priority, setPriority] = React.useState<InvestigationPriority>(
    initialData?.priority || 'medium'
  );
  const [assigneeId, setAssigneeId] = React.useState(initialData?.assignee_id || '');
  const [selectedAlerts, setSelectedAlerts] = React.useState<AlertType[]>([]);
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!title.trim()) {
      setError('Title is required');
      return;
    }

    if (!description.trim()) {
      setError('Description is required');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const data: InvestigationFormData = {
        title: title.trim(),
        description: description.trim(),
        priority};

      if (assigneeId) {
        data.assignee_id = assigneeId;
      }

      if (selectedAlerts.length > 0) {
        data.alert_ids = selectedAlerts.map(alert => alert.alert_id);
      }

      await onSubmit(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit investigation');
    } finally {
      setSubmitting(false);
    }
  };

  const getPriorityColor = (p: InvestigationPriority): 'error' | 'warning' | 'info' | 'success' => {
    switch (p) {
      case 'critical':
        return 'error';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'low':
        return 'success';
    }
  };

  return (
    <Box component="form" onSubmit={handleSubmit} sx={{ maxWidth: 800, mx: 'auto' }}>
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Investigation Details
        </Typography>

        <Stack spacing={3}>
          {/* Title */}
          <TextField
            label="Title *"
            fullWidth
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Brief description of the incident"
            disabled={loading || submitting}
            required
          />

          {/* Description */}
          <TextField
            label="Description *"
            fullWidth
            multiline
            rows={4}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Detailed description of what you're investigating, initial observations, and scope..."
            disabled={loading || submitting}
            required
          />

          {/* Priority */}
          <FormControl fullWidth>
            <FormLabel sx={{ mb: 1, fontWeight: 600 }}>Priority *</FormLabel>
            <Stack direction="row" spacing={1}>
              {(['critical', 'high', 'medium', 'low'] as InvestigationPriority[]).map((p) => (
                <Chip
                  key={p}
                  label={p.charAt(0).toUpperCase() + p.slice(1)}
                  onClick={() => setPriority(p)}
                  color={priority === p ? getPriorityColor(p) : 'default'}
                  variant={priority === p ? 'filled' : 'outlined'}
                  disabled={loading || submitting}
                  sx={{
                    textTransform: 'capitalize',
                    minWidth: 80}}
                />
              ))}
            </Stack>
          </FormControl>

          {/* Assignee */}
          <TextField
            label="Assignee (optional)"
            fullWidth
            value={assigneeId}
            onChange={(e) => setAssigneeId(e.target.value)}
            placeholder="Username or ID of the assigned analyst"
            disabled={loading || submitting}
            helperText="Leave empty to assign to yourself"
          />

          <Divider />

          {/* Link Alerts */}
          <FormControl fullWidth>
            <FormLabel sx={{ mb: 1, fontWeight: 600 }}>
              Link Related Alerts (optional)
            </FormLabel>
            <Autocomplete
              multiple
              options={availableAlerts}
              getOptionLabel={(option) => `${option.alert_id} - ${option.title}`}
              value={selectedAlerts}
              onChange={(_, newValue) => setSelectedAlerts(newValue)}
              disabled={loading || submitting}
              renderInput={(params) => (
                <TextField
                  {...params}
                  placeholder="Search for alerts to link to this investigation"
                />
              )}
              renderTags={(value, getTagProps) =>
                value.map((option, index) => (
                  <Chip
                    {...getTagProps({ index })}
                    key={option.alert_id}
                    label={`${option.alert_id.substring(0, 8)}... - ${option.title}`}
                    size="small"
                  />
                ))
              }
            />
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>
              You can link additional alerts later from the investigation workspace
            </Typography>
          </FormControl>
        </Stack>
      </Paper>

      {/* Actions */}
      <Box sx={{ mt: 3, display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
        <Button
          onClick={onCancel}
          disabled={submitting}
          variant="outlined"
        >
          Cancel
        </Button>
        <Button
          type="submit"
          variant="contained"
          disabled={loading || submitting || !title.trim() || !description.trim()}
          startIcon={<AddIcon />}
        >
          {submitting ? 'Creating...' : 'Create Investigation'}
        </Button>
      </Box>
    </Box>
  );
};

export default InvestigationForm;
