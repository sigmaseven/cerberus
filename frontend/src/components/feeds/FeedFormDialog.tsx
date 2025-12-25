/**
 * FeedFormDialog Component (Task 156.2)
 * Dialog for creating and editing SIGMA rule feeds
 */

import { useState, useEffect, useMemo } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Switch,
  Chip,
  Grid,
  Alert,
  CircularProgress,
  Autocomplete,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  Tooltip,
  IconButton,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Help as HelpIcon,
  GitHub as GitIcon,
  Folder as FolderIcon,
  Schedule as ScheduleIcon,
} from '@mui/icons-material';
import type {
  Feed,
  FeedForm,
  FeedTemplate,
} from '../../types';

// Severity options for minimum severity filter
const SEVERITY_OPTIONS = ['informational', 'low', 'medium', 'high', 'critical'];

// Cron presets for scheduled updates
const SCHEDULE_PRESETS = [
  { label: 'Every hour', value: '0 * * * *' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
  { label: 'Every 12 hours', value: '0 */12 * * *' },
  { label: 'Daily at midnight', value: '0 0 * * *' },
  { label: 'Weekly on Sunday', value: '0 0 * * 0' },
];

interface FeedFormDialogProps {
  open: boolean;
  mode: 'create' | 'edit';
  feed?: Feed | null;
  templates?: FeedTemplate[];
  onSubmit: (data: FeedForm) => Promise<void>;
  onCancel: () => void;
  isSubmitting?: boolean;
  error?: string | null;
}

const defaultFormValues: FeedForm = {
  name: '',
  description: '',
  type: 'git',
  enabled: true,
  priority: 100,
  url: '',
  branch: 'main',
  path: '',
  auth_config: undefined,
  include_paths: [],
  exclude_paths: [],
  include_tags: [],
  exclude_tags: [],
  min_severity: undefined,
  auto_enable_rules: false,
  update_strategy: 'manual',
  update_schedule: '',
  tags: [],
  metadata: undefined,
};

export default function FeedFormDialog({
  open,
  mode,
  feed,
  templates = [],
  onSubmit,
  onCancel,
  isSubmitting = false,
  error,
}: FeedFormDialogProps) {
  // Form state
  const [formData, setFormData] = useState<FeedForm>(defaultFormValues);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Reset form when dialog opens/closes or feed changes
  useEffect(() => {
    if (open) {
      if (mode === 'edit' && feed) {
        setFormData({
          name: feed.name,
          description: feed.description ?? '',
          type: feed.type,
          enabled: feed.enabled,
          priority: feed.priority,
          url: feed.url ?? '',
          branch: feed.branch ?? 'main',
          path: feed.path ?? '',
          auth_config: feed.auth_config,
          include_paths: feed.include_paths ?? [],
          exclude_paths: feed.exclude_paths ?? [],
          include_tags: feed.include_tags ?? [],
          exclude_tags: feed.exclude_tags ?? [],
          min_severity: feed.min_severity,
          auto_enable_rules: feed.auto_enable_rules,
          update_strategy: feed.update_strategy,
          update_schedule: feed.update_schedule ?? '',
          tags: feed.tags ?? [],
          metadata: feed.metadata,
        });
        setShowAdvanced(
          !!(feed.include_paths?.length || feed.exclude_paths?.length ||
             feed.include_tags?.length || feed.exclude_tags?.length ||
             feed.min_severity || feed.auth_config)
        );
      } else {
        setFormData(defaultFormValues);
        setShowAdvanced(false);
      }
      setValidationErrors({});
      setSelectedTemplate('');
    }
  }, [open, mode, feed]);

  // Apply template
  const handleTemplateSelect = (templateId: string) => {
    setSelectedTemplate(templateId);
    const template = templates.find(t => t.id === templateId);
    if (template?.config) {
      setFormData(prev => ({
        ...prev,
        ...template.config,
        name: prev.name || template.name,
        description: prev.description || template.description,
      }));
    }
  };

  // Form field handlers
  const handleChange = (field: keyof FeedForm) => (
    event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const value = event.target.type === 'number'
      ? parseInt(event.target.value, 10)
      : event.target.value;
    setFormData(prev => ({ ...prev, [field]: value }));
    // Clear validation error when field changes
    if (validationErrors[field]) {
      setValidationErrors(prev => {
        const next = { ...prev };
        delete next[field];
        return next;
      });
    }
  };

  const handleSelectChange = (field: keyof FeedForm) => (
    event: { target: { value: unknown } }
  ) => {
    setFormData(prev => ({ ...prev, [field]: event.target.value }));
    if (validationErrors[field]) {
      setValidationErrors(prev => {
        const next = { ...prev };
        delete next[field];
        return next;
      });
    }
  };

  const handleSwitchChange = (field: keyof FeedForm) => (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    setFormData(prev => ({ ...prev, [field]: event.target.checked }));
  };

  const handleTagsChange = (field: 'tags' | 'include_paths' | 'exclude_paths' | 'include_tags' | 'exclude_tags') => (
    _: React.SyntheticEvent,
    value: string[]
  ) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  // Validation
  const validateForm = (): boolean => {
    const errors: Record<string, string> = {};

    if (!formData.name.trim()) {
      errors.name = 'Name is required';
    } else if (formData.name.length > 200) {
      errors.name = 'Name must be 200 characters or less';
    }

    if (formData.type === 'git') {
      if (!formData.url?.trim()) {
        errors.url = 'URL is required for git feeds';
      } else if (!formData.url.match(/^(https?|git):\/\/.+/)) {
        errors.url = 'Invalid URL format';
      }
    } else if (formData.type === 'filesystem') {
      if (!formData.path?.trim()) {
        errors.path = 'Path is required for filesystem feeds';
      }
    }

    if (formData.priority < 1 || formData.priority > 1000) {
      errors.priority = 'Priority must be between 1 and 1000';
    }

    if (formData.update_strategy === 'scheduled' && !formData.update_schedule?.trim()) {
      errors.update_schedule = 'Schedule is required for scheduled updates';
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  // Submit handler
  const handleSubmit = async () => {
    if (!validateForm()) {
      return;
    }

    // Clean up empty optional fields
    const cleanedData: FeedForm = {
      ...formData,
      description: formData.description?.trim() || undefined,
      url: formData.url?.trim() || undefined,
      branch: formData.type === 'git' ? (formData.branch?.trim() || 'main') : undefined,
      path: formData.path?.trim() || undefined,
      auth_config: formData.auth_config && Object.keys(formData.auth_config).length > 0 ? formData.auth_config : undefined,
      include_paths: formData.include_paths?.length ? formData.include_paths : undefined,
      exclude_paths: formData.exclude_paths?.length ? formData.exclude_paths : undefined,
      include_tags: formData.include_tags?.length ? formData.include_tags : undefined,
      exclude_tags: formData.exclude_tags?.length ? formData.exclude_tags : undefined,
      min_severity: formData.min_severity || undefined,
      update_schedule: formData.update_strategy === 'scheduled' ? formData.update_schedule : undefined,
      tags: formData.tags?.length ? formData.tags : undefined,
      metadata: formData.metadata && Object.keys(formData.metadata).length > 0 ? formData.metadata : undefined,
    };

    await onSubmit(cleanedData);
  };

  // Type icon
  const typeIcon = useMemo(() => {
    switch (formData.type) {
      case 'git':
        return <GitIcon />;
      case 'filesystem':
        return <FolderIcon />;
      default:
        return null;
    }
  }, [formData.type]);

  return (
    <Dialog
      open={open}
      onClose={onCancel}
      maxWidth="md"
      fullWidth
      aria-labelledby="feed-form-dialog-title"
    >
      <DialogTitle id="feed-form-dialog-title">
        {mode === 'create' ? 'Add SIGMA Rule Feed' : `Edit Feed: ${feed?.name ?? ''}`}
      </DialogTitle>

      <DialogContent dividers>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, pt: 1 }}>
          {error && (
            <Alert severity="error">{error}</Alert>
          )}

          {/* Template Selection (create mode only) */}
          {mode === 'create' && templates.length > 0 && (
            <FormControl fullWidth>
              <InputLabel id="template-select-label">Start from Template (Optional)</InputLabel>
              <Select
                labelId="template-select-label"
                value={selectedTemplate}
                label="Start from Template (Optional)"
                onChange={(e) => handleTemplateSelect(e.target.value as string)}
              >
                <MenuItem value="">
                  <em>None - Start from scratch</em>
                </MenuItem>
                {templates.map(template => (
                  <MenuItem key={template.id} value={template.id}>
                    <Box sx={{ display: 'flex', flexDirection: 'column' }}>
                      <Typography variant="body1">{template.name}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {template.description}
                      </Typography>
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}

          {/* Basic Information */}
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Basic Information
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={8}>
                <TextField
                  fullWidth
                  label="Feed Name"
                  value={formData.name}
                  onChange={handleChange('name')}
                  error={!!validationErrors.name}
                  helperText={validationErrors.name || 'A descriptive name for this feed'}
                  required
                  disabled={isSubmitting}
                />
              </Grid>
              <Grid item xs={12} sm={4}>
                <TextField
                  fullWidth
                  type="number"
                  label="Priority"
                  value={formData.priority}
                  onChange={handleChange('priority')}
                  error={!!validationErrors.priority}
                  helperText={validationErrors.priority || 'Lower = higher priority'}
                  InputProps={{
                    inputProps: { min: 1, max: 1000 },
                  }}
                  disabled={isSubmitting}
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Description"
                  value={formData.description}
                  onChange={handleChange('description')}
                  multiline
                  rows={2}
                  helperText="Optional description of this feed's purpose"
                  disabled={isSubmitting}
                />
              </Grid>
            </Grid>
          </Box>

          <Divider />

          {/* Feed Type & Source */}
          <Box>
            <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              {typeIcon}
              Feed Source
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <FormControl fullWidth>
                  <InputLabel id="type-select-label">Feed Type</InputLabel>
                  <Select
                    labelId="type-select-label"
                    value={formData.type}
                    label="Feed Type"
                    onChange={handleSelectChange('type')}
                    disabled={isSubmitting}
                  >
                    <MenuItem value="git">
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <GitIcon fontSize="small" />
                        Git Repository
                      </Box>
                    </MenuItem>
                    <MenuItem value="filesystem">
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <FolderIcon fontSize="small" />
                        Local Filesystem
                      </Box>
                    </MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.enabled}
                      onChange={handleSwitchChange('enabled')}
                      disabled={isSubmitting}
                    />
                  }
                  label="Enable Feed"
                />
              </Grid>

              {/* Git-specific fields */}
              {formData.type === 'git' && (
                <>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Repository URL"
                      value={formData.url}
                      onChange={handleChange('url')}
                      error={!!validationErrors.url}
                      helperText={validationErrors.url || 'Git repository URL (e.g., https://github.com/SigmaHQ/sigma.git)'}
                      required
                      disabled={isSubmitting}
                      placeholder="https://github.com/SigmaHQ/sigma.git"
                    />
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <TextField
                      fullWidth
                      label="Branch"
                      value={formData.branch}
                      onChange={handleChange('branch')}
                      helperText="Git branch to sync from"
                      disabled={isSubmitting}
                      placeholder="main"
                    />
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <TextField
                      fullWidth
                      label="Subdirectory (Optional)"
                      value={formData.path}
                      onChange={handleChange('path')}
                      helperText="Only sync rules from this subdirectory"
                      disabled={isSubmitting}
                      placeholder="rules/windows"
                    />
                  </Grid>
                </>
              )}

              {/* Filesystem-specific fields */}
              {formData.type === 'filesystem' && (
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Directory Path"
                    value={formData.path}
                    onChange={handleChange('path')}
                    error={!!validationErrors.path}
                    helperText={validationErrors.path || 'Absolute path to directory containing SIGMA rules'}
                    required
                    disabled={isSubmitting}
                    placeholder="/path/to/sigma/rules"
                  />
                </Grid>
              )}
            </Grid>
          </Box>

          <Divider />

          {/* Update Strategy */}
          <Box>
            <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <ScheduleIcon />
              Update Strategy
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <FormControl fullWidth>
                  <InputLabel id="update-strategy-label">Update Strategy</InputLabel>
                  <Select
                    labelId="update-strategy-label"
                    value={formData.update_strategy}
                    label="Update Strategy"
                    onChange={handleSelectChange('update_strategy')}
                    disabled={isSubmitting}
                  >
                    <MenuItem value="manual">
                      <Box>
                        <Typography variant="body1">Manual</Typography>
                        <Typography variant="caption" color="text.secondary">
                          Sync only when triggered manually
                        </Typography>
                      </Box>
                    </MenuItem>
                    <MenuItem value="startup">
                      <Box>
                        <Typography variant="body1">On Startup</Typography>
                        <Typography variant="caption" color="text.secondary">
                          Sync when server starts
                        </Typography>
                      </Box>
                    </MenuItem>
                    <MenuItem value="scheduled">
                      <Box>
                        <Typography variant="body1">Scheduled</Typography>
                        <Typography variant="caption" color="text.secondary">
                          Sync on a cron schedule
                        </Typography>
                      </Box>
                    </MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.auto_enable_rules}
                      onChange={handleSwitchChange('auto_enable_rules')}
                      disabled={isSubmitting}
                    />
                  }
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      Auto-enable imported rules
                      <Tooltip title="When enabled, newly imported rules will be automatically enabled for detection">
                        <IconButton size="small">
                          <HelpIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  }
                />
              </Grid>

              {/* Schedule field */}
              {formData.update_strategy === 'scheduled' && (
                <Grid item xs={12}>
                  <Autocomplete
                    freeSolo
                    options={SCHEDULE_PRESETS}
                    getOptionLabel={(option) =>
                      typeof option === 'string' ? option : option.label
                    }
                    value={SCHEDULE_PRESETS.find(p => p.value === formData.update_schedule) || formData.update_schedule}
                    onChange={(_, newValue) => {
                      const value = typeof newValue === 'string'
                        ? newValue
                        : newValue?.value ?? '';
                      setFormData(prev => ({ ...prev, update_schedule: value }));
                    }}
                    onInputChange={(_, newValue) => {
                      setFormData(prev => ({ ...prev, update_schedule: newValue }));
                    }}
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Cron Schedule"
                        error={!!validationErrors.update_schedule}
                        helperText={validationErrors.update_schedule || 'Cron expression (e.g., "0 0 * * *" for daily at midnight)'}
                        required
                        disabled={isSubmitting}
                      />
                    )}
                    disabled={isSubmitting}
                  />
                </Grid>
              )}
            </Grid>
          </Box>

          {/* Advanced Options */}
          <Accordion
            expanded={showAdvanced}
            onChange={() => setShowAdvanced(!showAdvanced)}
            sx={{ mt: 2 }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography>Advanced Options</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {/* Path Filters */}
                <Grid item xs={12} sm={6}>
                  <Autocomplete
                    multiple
                    freeSolo
                    options={[]}
                    value={formData.include_paths ?? []}
                    onChange={handleTagsChange('include_paths')}
                    renderTags={(value, getTagProps) =>
                      value.map((option, index) => (
                        <Chip
                          variant="outlined"
                          label={option}
                          {...getTagProps({ index })}
                          key={option}
                        />
                      ))
                    }
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Include Paths"
                        helperText="Only include rules from these paths (glob patterns)"
                        placeholder="rules/windows/**"
                      />
                    )}
                    disabled={isSubmitting}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Autocomplete
                    multiple
                    freeSolo
                    options={[]}
                    value={formData.exclude_paths ?? []}
                    onChange={handleTagsChange('exclude_paths')}
                    renderTags={(value, getTagProps) =>
                      value.map((option, index) => (
                        <Chip
                          variant="outlined"
                          label={option}
                          {...getTagProps({ index })}
                          key={option}
                        />
                      ))
                    }
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Exclude Paths"
                        helperText="Exclude rules from these paths"
                        placeholder="**/deprecated/**"
                      />
                    )}
                    disabled={isSubmitting}
                  />
                </Grid>

                {/* Tag Filters */}
                <Grid item xs={12} sm={6}>
                  <Autocomplete
                    multiple
                    freeSolo
                    options={['attack.execution', 'attack.persistence', 'attack.privilege_escalation']}
                    value={formData.include_tags ?? []}
                    onChange={handleTagsChange('include_tags')}
                    renderTags={(value, getTagProps) =>
                      value.map((option, index) => (
                        <Chip
                          variant="outlined"
                          label={option}
                          {...getTagProps({ index })}
                          key={option}
                        />
                      ))
                    }
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Include Tags"
                        helperText="Only include rules with these tags"
                      />
                    )}
                    disabled={isSubmitting}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Autocomplete
                    multiple
                    freeSolo
                    options={[]}
                    value={formData.exclude_tags ?? []}
                    onChange={handleTagsChange('exclude_tags')}
                    renderTags={(value, getTagProps) =>
                      value.map((option, index) => (
                        <Chip
                          variant="outlined"
                          label={option}
                          {...getTagProps({ index })}
                          key={option}
                        />
                      ))
                    }
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Exclude Tags"
                        helperText="Exclude rules with these tags"
                      />
                    )}
                    disabled={isSubmitting}
                  />
                </Grid>

                {/* Minimum Severity */}
                <Grid item xs={12} sm={6}>
                  <FormControl fullWidth>
                    <InputLabel id="min-severity-label">Minimum Severity</InputLabel>
                    <Select
                      labelId="min-severity-label"
                      value={formData.min_severity ?? ''}
                      label="Minimum Severity"
                      onChange={handleSelectChange('min_severity')}
                      disabled={isSubmitting}
                    >
                      <MenuItem value="">
                        <em>No filter</em>
                      </MenuItem>
                      {SEVERITY_OPTIONS.map(severity => (
                        <MenuItem key={severity} value={severity}>
                          {severity.charAt(0).toUpperCase() + severity.slice(1)}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>

                {/* Feed Tags */}
                <Grid item xs={12} sm={6}>
                  <Autocomplete
                    multiple
                    freeSolo
                    options={['official', 'community', 'internal', 'windows', 'linux', 'cloud']}
                    value={formData.tags ?? []}
                    onChange={handleTagsChange('tags')}
                    renderTags={(value, getTagProps) =>
                      value.map((option, index) => (
                        <Chip
                          variant="outlined"
                          label={option}
                          {...getTagProps({ index })}
                          key={option}
                        />
                      ))
                    }
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Feed Tags"
                        helperText="Tags to organize this feed"
                      />
                    )}
                    disabled={isSubmitting}
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        </Box>
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onCancel} disabled={isSubmitting}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={isSubmitting}
          startIcon={isSubmitting ? <CircularProgress size={20} /> : undefined}
        >
          {isSubmitting ? 'Saving...' : mode === 'create' ? 'Create Feed' : 'Save Changes'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
