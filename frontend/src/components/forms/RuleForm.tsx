import { useState, useEffect, useCallback } from 'react';
import { useForm, useFieldArray, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Box,
  Typography,
  IconButton,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  ToggleButton,
  ToggleButtonGroup,
  Chip,
  Alert,
  FormHelperText,
  Autocomplete,
  Slider,
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
} from '@mui/icons-material';
import { Rule, Action, RuleCategory, LifecycleStatus, CorrelationConfig } from '../../types';
import yaml from 'js-yaml';
import { YamlEditor } from '../YamlEditor';
import api from '../../services/api';

// Maximum YAML size: 100KB
const MAX_YAML_SIZE = 100 * 1024;

// Helper function to convert detection JSON to YAML
function convertDetectionToYaml(rule: Partial<Rule>): string {
  // DEBUG: Log what we receive
  console.log('[RuleForm] convertDetectionToYaml input:', {
    hasRule: !!rule,
    hasSigmaYaml: !!rule.sigma_yaml,
    sigmaYamlLength: rule.sigma_yaml?.length,
    sigmaYamlPreview: rule.sigma_yaml?.substring(0, 200),
    hasDetection: !!rule.detection,
    ruleName: rule.name,
  });

  // First check if we have sigma_yaml
  if (rule.sigma_yaml) {
    return rule.sigma_yaml;
  }

  // Try to parse the query field which may contain JSON detection
  const queryStr = rule.query;
  if (queryStr && typeof queryStr === 'string') {
    try {
      const detection = JSON.parse(queryStr);
      // Build a minimal SIGMA rule YAML
      const sigmaRule: Record<string, unknown> = {
        title: rule.name ?? 'Untitled Rule',
        description: rule.description ?? '',
        status: 'experimental',
        logsource: rule.logsource ?? {},
        detection: detection,
      };
      if (rule.severity) {
        sigmaRule.level = rule.severity.toLowerCase();
      }
      if (rule.tags && rule.tags.length > 0) {
        sigmaRule.tags = rule.tags;
      }
      return yaml.dump(sigmaRule, { indent: 2, lineWidth: -1 });
    } catch {
      // If JSON parse fails, continue to next check
    }
  }

  // Try detection field directly
  if (rule.detection && Object.keys(rule.detection).length > 0) {
    const sigmaRule: Record<string, unknown> = {
      title: rule.name ?? 'Untitled Rule',
      description: rule.description ?? '',
      status: 'experimental',
      logsource: rule.logsource ?? {},
      detection: rule.detection,
    };
    if (rule.severity) {
      sigmaRule.level = rule.severity.toLowerCase();
    }
    if (rule.tags && rule.tags.length > 0) {
      sigmaRule.tags = rule.tags;
    }
    return yaml.dump(sigmaRule, { indent: 2, lineWidth: -1 });
  }

  // Return default template
  return `title: New Rule
description: Enter rule description
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
level: medium
`;
}
// =============================================================================
// Form Schemas
// =============================================================================

const actionSchema = z.object({
  type: z.string().min(1, 'Action type is required'),
  config: z.union([z.string(), z.record(z.unknown())]),
});

// Detection rule fields (SIGMA)
const detectionRuleSchema = z.object({
  title: z.string().min(1, 'Rule title is required'),
  description: z.string().min(1, 'Description is required'),
  severity: z.enum(['Low', 'Medium', 'High', 'Critical']),
  enabled: z.boolean(),
  rule_category: z.literal('detection'),
  lifecycle_status: z.enum(['experimental', 'test', 'stable', 'deprecated', 'active']).optional(),
  actions: z.array(actionSchema).optional(),
  tags: z.array(z.string()).optional(),
  // SIGMA fields (visual mode)
  detection: z.record(z.unknown()).optional(),
  logsource: z.record(z.unknown()).optional(),
  condition: z.string().optional(),
  // Raw YAML mode
  sigma_yaml: z.string().optional(),
}).refine(
  (data) => {
    // Either sigma_yaml OR detection must be present
    return data.sigma_yaml || (data.detection && Object.keys(data.detection).length > 0);
  },
  {
    message: 'Either SIGMA YAML or detection logic is required',
    path: ['detection'],
  }
);

// Correlation rule fields
const correlationRuleSchema = z.object({
  title: z.string().min(1, 'Rule title is required'),
  description: z.string().min(1, 'Description is required'),
  severity: z.enum(['Low', 'Medium', 'High', 'Critical']),
  enabled: z.boolean(),
  rule_category: z.literal('correlation'),
  lifecycle_status: z.enum(['experimental', 'test', 'stable', 'deprecated', 'active']).optional(),
  actions: z.array(actionSchema).optional(),
  tags: z.array(z.string()).optional(),
  // Correlation-specific fields
  correlation_config: z.object({
    type: z.enum(['event_count', 'value_count', 'sequence', 'temporal', 'rare', 'statistical', 'chain']),
    group_by: z.array(z.string()).optional(),
    timespan: z.string().optional(),
    ordered: z.boolean().optional(),
    events: z.array(z.string()).optional(),
    distinct_field: z.string().optional(),
    baseline_window: z.string().optional(),
    std_dev_threshold: z.number().optional(),
  }),
});

const ruleFormSchema = z.discriminatedUnion('rule_category', [
  detectionRuleSchema,
  correlationRuleSchema,
]);

type RuleFormData = z.infer<typeof ruleFormSchema>;

// =============================================================================
// Component Props
// =============================================================================

interface RuleFormProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: RuleFormData) => void;
  initialData?: Partial<Rule>;
  title: string;
}

// =============================================================================
// Constants
// =============================================================================

const actionTypes = [
  { value: 'webhook', label: 'Webhook' },
  { value: 'jira', label: 'Jira Ticket' },
  { value: 'slack', label: 'Slack Message' },
  { value: 'email', label: 'Email Notification' },
];

const correlationTypes = [
  { value: 'event_count', label: 'Event Count', description: 'Trigger when event count threshold is reached' },
  { value: 'value_count', label: 'Value Count', description: 'Trigger on distinct value counts' },
  { value: 'sequence', label: 'Sequence', description: 'Trigger on ordered event sequence' },
  { value: 'temporal', label: 'Temporal', description: 'Trigger on time-based patterns' },
  { value: 'rare', label: 'Rare Events', description: 'Trigger on statistically rare events' },
  { value: 'statistical', label: 'Statistical', description: 'Trigger on statistical anomalies' },
  { value: 'chain', label: 'Chain', description: 'Multi-stage correlation chain' },
];

const commonEventTypes = [
  'user_login',
  'user_logout',
  'file_access',
  'file_modify',
  'file_delete',
  'admin_command',
  'network_connection',
  'firewall_block',
  'authentication_failure',
  'privilege_escalation',
];

const commonFields = [
  'event_type',
  'source_ip',
  'dest_ip',
  'user',
  'hostname',
  'process',
  'command',
  'status',
  'severity',
];

// =============================================================================
// Main Component
// =============================================================================

export function RuleForm({ open, onClose, onSubmit, initialData, title }: RuleFormProps) {
  const [editMode, setEditMode] = useState<'visual' | 'yaml'>('visual');
  const [yamlContent, setYamlContent] = useState<string>('');
  const [yamlValidation, setYamlValidation] = useState<{
    valid: boolean;
    errors?: string[];
    warnings?: string[];
  } | null>(null);
  const [jsonPreview, setJsonPreview] = useState<string>('');

  // Determine initial category from initialData
  const initialCategory: RuleCategory =
    initialData?.correlation_config ? 'correlation' : 'detection';

  const {
    register,
    control,
    handleSubmit,
    watch,
    setValue,
    reset,
    formState,
  } = useForm<RuleFormData>({
    resolver: zodResolver(ruleFormSchema),
    mode: 'onChange',
    defaultValues: {
      title: '',
      description: '',
      severity: 'Medium',
      enabled: true,
      rule_category: 'detection',
      lifecycle_status: 'experimental',
      actions: [],
      tags: [],
      detection: {},
      logsource: {},
      condition: '',
      sigma_yaml: '',
    } as RuleFormData,
  });

  // Reset form when initialData changes or dialog opens
  useEffect(() => {
    if (open) {
      const category: RuleCategory = initialData?.correlation_config ? 'correlation' : 'detection';

      if (category === 'detection') {
        const resetData: RuleFormData = {
          title: initialData?.name ?? '',
          description: initialData?.description ?? '',
          severity: (initialData?.severity ?? 'Medium') as 'Low' | 'Medium' | 'High' | 'Critical',
          enabled: initialData?.enabled ?? true,
          rule_category: 'detection',
          lifecycle_status: (initialData?.lifecycle_status ?? 'experimental') as LifecycleStatus,
          actions: initialData?.actions?.map((action) => ({
            type: action.type ?? 'webhook',
            config: typeof action.config === 'object'
              ? JSON.stringify(action.config, null, 2)
              : (action.config ?? '{}'),
          })) ?? [],
          tags: initialData?.tags ?? [],
          detection: initialData?.detection ?? {},
          logsource: initialData?.logsource ?? {},
          condition: initialData?.condition ?? '',
          sigma_yaml: initialData?.sigma_yaml ?? '',
        };
        reset(resetData, { keepDefaultValues: false });
      } else {
        const resetData: RuleFormData = {
          title: initialData?.name ?? '',
          description: initialData?.description ?? '',
          severity: (initialData?.severity ?? 'Medium') as 'Low' | 'Medium' | 'High' | 'Critical',
          enabled: initialData?.enabled ?? true,
          rule_category: 'correlation',
          lifecycle_status: (initialData?.lifecycle_status ?? 'experimental') as LifecycleStatus,
          actions: initialData?.actions?.map((action) => ({
            type: action.type ?? 'webhook',
            config: typeof action.config === 'object'
              ? JSON.stringify(action.config, null, 2)
              : (action.config ?? '{}'),
          })) ?? [],
          tags: initialData?.tags ?? [],
          correlation_config: initialData?.correlation_config ?? {
            type: 'event_count' as const,
            group_by: [],
            timespan: '5m',
          },
        };
        reset(resetData, { keepDefaultValues: false });
      }

      // Always use YAML mode - convert detection JSON to YAML if needed
      const yamlResult = convertDetectionToYaml(initialData ?? {});
      console.log('[RuleForm] Setting yamlContent, length:', yamlResult.length, 'preview:', yamlResult.substring(0, 300));
      setYamlContent(yamlResult);
      setEditMode('yaml');
    }
  }, [open, initialData, reset]);

  // Handle detection change from SIGMA editor
  const handleDetectionChange = useCallback((detection: Record<string, unknown>, logsource: Record<string, unknown>) => {
    // Type-safe setValue for detection fields (only valid for detection rules)
    const currentCategory = watchedValues.rule_category;
    if (currentCategory === 'detection') {
      setValue('detection', detection, { shouldValidate: true });
      setValue('logsource', logsource, { shouldValidate: true });
    }
  }, [setValue, watchedValues.rule_category]);

  // Validate YAML in real-time with race condition protection
  useEffect(() => {
    let cancelled = false;

    if (editMode === 'yaml' && yamlContent?.trim()) {
      // Check YAML size limit
      const yamlSizeBytes = new Blob([yamlContent]).size;
      if (yamlSizeBytes > MAX_YAML_SIZE) {
        setYamlValidation({
          valid: false,
          errors: [`YAML size exceeds maximum limit of ${MAX_YAML_SIZE / 1024}KB`],
        });
        return;
      }

      const debounceTimer = setTimeout(async () => {
        try {
          const result = await api.validateRule({ sigma_yaml: yamlContent });
          if (!cancelled) {
            setYamlValidation(result);
          }
        } catch (error) {
          if (!cancelled) {
            setYamlValidation({
              valid: false,
              errors: ['Failed to validate YAML'],
            });
          }
        }
      }, 500);

      return () => {
        cancelled = true;
        clearTimeout(debounceTimer);
      };
    } else {
      setYamlValidation(null);
    }
  }, [yamlContent, editMode]);

  const {
    fields: actionFields,
    append: appendAction,
    remove: removeAction,
  } = useFieldArray({
    control,
    name: 'actions',
  });

  const watchedValues = watch();
  const watchedCategory = watch('rule_category');
  const watchedCorrelationType = watchedCategory === 'correlation'
    ? (watchedValues as Extract<RuleFormData, { rule_category: 'correlation' }>).correlation_config?.type
    : undefined;

  const handleFormSubmit = (data: RuleFormData) => {
    // Process actions from JSON strings to objects with safe error handling
    const processedActions = data.actions?.map((action) => {
      if (typeof action.config === 'string') {
        try {
          return {
            ...action,
            config: JSON.parse(action.config) as Record<string, unknown>
          };
        } catch (err) {
          throw new Error(`Invalid JSON in action configuration: ${(err as Error).message}`);
        }
      }
      return action;
    }) ?? [];

    const processedData = {
      ...data,
      actions: processedActions,
      // In YAML mode, clear detection fields and use sigma_yaml
      ...(editMode === 'yaml' && data.rule_category === 'detection' ? {
        sigma_yaml: yamlContent,
        detection: undefined,
        logsource: undefined,
      } : {}),
    };
    onSubmit(processedData);
  };

  const showJsonPreview = () => {
    const ruleData = {
      id: initialData?.id || `rule_${Date.now()}`,
      ...watchedValues,
      version: initialData?.version || 1,
    };
    setJsonPreview(JSON.stringify(ruleData, null, 2));
  };

  const addAction = () => {
    appendAction({
      type: 'webhook',
      config: JSON.stringify({ url: '' }, null, 2),
    });
  };

  const formatTimespan = (value: string): string => {
    const match = value.match(/^(\d+)([smhd])$/);
    if (!match) return value;
    const [, num, unit] = match;
    const labels: Record<string, string> = { s: 'seconds', m: 'minutes', h: 'hours', d: 'days' };
    return `${num} ${labels[unit] || unit}`;
  };

  // =============================================================================
  // Render Functions
  // =============================================================================

  const renderCategorySelector = () => (
    <FormControl fullWidth sx={{ mb: 2 }}>
      <InputLabel>Rule Category</InputLabel>
      <Controller
        name="rule_category"
        control={control}
        render={({ field }) => (
          <Select
            {...field}
            disabled={!!initialData?.id} // Prevent changing category on edit
          >
            <MenuItem value="detection">Detection Rule</MenuItem>
            <MenuItem value="correlation">Correlation Rule</MenuItem>
          </Select>
        )}
      />
      {initialData?.id && (
        <FormHelperText>Category cannot be changed after creation</FormHelperText>
      )}
    </FormControl>
  );

  const renderLifecycleSelector = () => (
    <FormControl fullWidth sx={{ mb: 2 }}>
      <InputLabel>Lifecycle Status</InputLabel>
      <Controller
        name="lifecycle_status"
        control={control}
        render={({ field }) => (
          <Select {...field}>
            <MenuItem value="experimental">Experimental</MenuItem>
            <MenuItem value="test">Test</MenuItem>
            <MenuItem value="stable">Stable</MenuItem>
            <MenuItem value="active">Active</MenuItem>
            <MenuItem value="deprecated">Deprecated</MenuItem>
          </Select>
        )}
      />
      <FormHelperText>
        {watchedValues.lifecycle_status === 'experimental' && 'Under development, may have issues'}
        {watchedValues.lifecycle_status === 'test' && 'Ready for testing in non-production'}
        {watchedValues.lifecycle_status === 'stable' && 'Tested and production-ready'}
        {watchedValues.lifecycle_status === 'active' && 'Currently active in production'}
        {watchedValues.lifecycle_status === 'deprecated' && 'Scheduled for removal'}
      </FormHelperText>
    </FormControl>
  );

  const renderDetectionFields = () => {
    if (watchedCategory !== 'detection') return null;

    return (
      <Box>
        {/* SIGMA YAML Editor */}
        <Box sx={{ mb: 2 }}>
          <Typography variant="subtitle1">SIGMA Detection (YAML)</Typography>
        </Box>


        {editMode === 'yaml' && (
          <Box>
            <Typography variant="caption" color="text.secondary" gutterBottom>
              Enter raw SIGMA YAML rule content
            </Typography>
            <YamlEditor
              value={yamlContent}
              onChange={setYamlContent}
              minHeight="300px"
              error={yamlValidation?.valid === false}
            />
            {yamlValidation && (
              <Box sx={{ mt: 1 }}>
                {yamlValidation.valid ? (
                  <Alert severity="success">YAML is valid</Alert>
                ) : (
                  <Alert severity="error">
                    <Typography variant="subtitle2">Validation Errors:</Typography>
                    <ul style={{ margin: 0, paddingLeft: '20px' }}>
                      {yamlValidation.errors?.map((error, idx) => (
                        <li key={idx}>{error}</li>
                      ))}
                    </ul>
                  </Alert>
                )}
                {yamlValidation.warnings && yamlValidation.warnings.length > 0 && (
                  <Alert severity="warning" sx={{ mt: 1 }}>
                    <Typography variant="subtitle2">Warnings:</Typography>
                    <ul style={{ margin: 0, paddingLeft: '20px' }}>
                      {yamlValidation.warnings.map((warning, idx) => (
                        <li key={idx}>{warning}</li>
                      ))}
                    </ul>
                  </Alert>
                )}
              </Box>
            )}
          </Box>
        )}
      </Box>
    );
  };

  const renderCorrelationFields = () => {
    if (watchedCategory !== 'correlation') return null;

    return (
      <Box>
        <Typography variant="subtitle1" gutterBottom>Correlation Configuration</Typography>

        {/* Correlation Type Selector */}
        <FormControl fullWidth sx={{ mb: 2 }}>
          <InputLabel>Correlation Type</InputLabel>
          <Controller
            name="correlation_config.type"
            control={control}
            render={({ field }) => (
              <Select {...field}>
                {correlationTypes.map((type) => (
                  <MenuItem key={type.value} value={type.value}>
                    <Box>
                      <Typography variant="body2">{type.label}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {type.description}
                      </Typography>
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            )}
          />
        </FormControl>

        {/* Timespan */}
        {watchedCategory === 'correlation' && (
          <TextField
            fullWidth
            label="Timespan"
            {...register('correlation_config.timespan')}
            placeholder="5m"
            helperText="Time window for correlation (e.g., 5m, 1h, 30s)"
            sx={{ mb: 2 }}
          />
        )}

        {/* Group By (multi-input) */}
        <Controller
          name="correlation_config.group_by"
          control={control}
          render={({ field }) => (
            <Autocomplete
              multiple
              freeSolo
              options={commonFields}
              value={field.value || []}
              onChange={(_, newValue) => field.onChange(newValue)}
              renderTags={(value, getTagProps) =>
                value.map((option, index) => (
                  <Chip label={option} {...getTagProps({ index })} key={index} />
                ))
              }
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Group By Fields"
                  placeholder="Add field..."
                  helperText="Fields to group correlation events by"
                />
              )}
              sx={{ mb: 2 }}
            />
          )}
        />

        {/* Type-specific fields */}
        {watchedCorrelationType === 'sequence' && (
          <Box>
            <Typography variant="subtitle2" gutterBottom>Sequence Configuration</Typography>
            <Controller
              name="correlation_config.ordered"
              control={control}
              render={({ field }) => (
                <FormControl component="fieldset" sx={{ mb: 2 }}>
                  <label>
                    <input
                      type="checkbox"
                      checked={field.value || false}
                      onChange={(e) => field.onChange(e.target.checked)}
                    />
                    {' '}Require ordered sequence
                  </label>
                </FormControl>
              )}
            />
            <Controller
              name="correlation_config.events"
              control={control}
              render={({ field }) => (
                <Autocomplete
                  multiple
                  freeSolo
                  options={commonEventTypes}
                  value={field.value || []}
                  onChange={(_, newValue) => field.onChange(newValue)}
                  renderTags={(value, getTagProps) =>
                    value.map((option, index) => (
                      <Chip label={option} {...getTagProps({ index })} key={index} />
                    ))
                  }
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      label="Event Sequence"
                      placeholder="Add event type..."
                      helperText="Ordered list of event types in the sequence"
                    />
                  )}
                  sx={{ mb: 2 }}
                />
              )}
            />
          </Box>
        )}

        {watchedCategory === 'correlation' && watchedCorrelationType === 'value_count' && (
          <TextField
            fullWidth
            label="Distinct Field"
            {...register('correlation_config.distinct_field')}
            placeholder="source_ip"
            helperText="Field to count distinct values for"
            sx={{ mb: 2 }}
          />
        )}

        {watchedCategory === 'correlation' && (watchedCorrelationType === 'rare' || watchedCorrelationType === 'statistical') && (
          <Box>
            <TextField
              fullWidth
              label="Baseline Window"
              {...register('correlation_config.baseline_window')}
              placeholder="24h"
              helperText="Historical window for baseline calculation"
              sx={{ mb: 2 }}
            />
            {watchedCorrelationType === 'statistical' && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="caption" gutterBottom>
                  Standard Deviation Threshold
                </Typography>
                <Controller
                  name="correlation_config.std_dev_threshold"
                  control={control}
                  render={({ field }) => (
                    <Slider
                      {...field}
                      value={field.value || 2}
                      min={1}
                      max={5}
                      step={0.5}
                      marks
                      valueLabelDisplay="auto"
                      onChange={(_, value) => field.onChange(value)}
                    />
                  )}
                />
              </Box>
            )}
          </Box>
        )}
      </Box>
    );
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent dividers>
        <Box component="form" sx={{ mt: 2 }}>
          {/* Category Selector */}
          {renderCategorySelector()}

          {/* Basic Fields */}
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start', mb: 2 }}>
            <TextField
              sx={{ flex: 1 }}
              label="Rule Title"
              {...register('title')}
              error={!!formState.errors.title}
              helperText={formState.errors.title?.message}
            />
            <FormControl sx={{ minWidth: 120 }}>
              <InputLabel>Severity</InputLabel>
              <Controller
                name="severity"
                control={control}
                render={({ field }) => (
                  <Select {...field}>
                    <MenuItem value="Low">Low</MenuItem>
                    <MenuItem value="Medium">Medium</MenuItem>
                    <MenuItem value="High">High</MenuItem>
                    <MenuItem value="Critical">Critical</MenuItem>
                  </Select>
                )}
              />
            </FormControl>
            <FormControl component="fieldset" sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
              <label>
                <input type="checkbox" {...register('enabled')} />
                {' '}Enabled
              </label>
            </FormControl>
          </Box>

          <TextField
            fullWidth
            multiline
            rows={2}
            label="Description"
            {...register('description')}
            error={!!formState.errors.description}
            helperText={formState.errors.description?.message}
            sx={{ mb: 2 }}
          />

          {/* Lifecycle Status */}
          {renderLifecycleSelector()}

          {/* Tags */}
          <Controller
            name="tags"
            control={control}
            render={({ field }) => (
              <Autocomplete
                multiple
                freeSolo
                options={[]}
                value={field.value || []}
                onChange={(_, newValue) => field.onChange(newValue)}
                renderTags={(value, getTagProps) =>
                  value.map((option, index) => (
                    <Chip label={option} {...getTagProps({ index })} key={index} />
                  ))
                }
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label="Tags"
                    placeholder="Add tag..."
                  />
                )}
                sx={{ mb: 3 }}
              />
            )}
          />

          {/* Validation Error Alerts */}
          {formState.errors.detection && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {formState.errors.detection.message ?? 'Detection logic is required'}
            </Alert>
          )}

          {formState.errors.correlation_config && (
            <Alert severity="error" sx={{ mb: 2 }}>
              Correlation configuration is invalid
            </Alert>
          )}

          {/* Category-Specific Fields */}
          {renderDetectionFields()}
          {renderCorrelationFields()}

          {/* Actions */}
          <Accordion sx={{ mt: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Actions ({actionFields.length})</Typography>
            </AccordionSummary>
            <AccordionDetails>
              {actionFields.map((field, index) => (
                <Box key={field.id} sx={{ mb: 2, p: 2, border: '1px solid #333', borderRadius: 1 }}>
                  <Grid container spacing={2} alignItems="center">
                    <Grid item xs={12} sm={4}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Action Type</InputLabel>
                        <Controller
                          name={`actions.${index}.type`}
                          control={control}
                          render={({ field }) => (
                            <Select {...field}>
                              {actionTypes.map((type) => (
                                <MenuItem key={type.value} value={type.value}>
                                  {type.label}
                                </MenuItem>
                              ))}
                            </Select>
                          )}
                        />
                      </FormControl>
                    </Grid>
                    <Grid item xs={12} sm={7}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Configuration (JSON)"
                        placeholder='{"url": "https://example.com/webhook"}'
                        {...register(`actions.${index}.config`)}
                        multiline
                        rows={2}
                      />
                    </Grid>
                    <Grid item xs={12} sm={1}>
                      <IconButton
                        color="error"
                        onClick={() => removeAction(index)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Grid>
                  </Grid>
                </Box>
              ))}
              <Button
                startIcon={<AddIcon />}
                onClick={addAction}
                variant="outlined"
                sx={{ mt: 1 }}
              >
                Add Action
              </Button>
            </AccordionDetails>
          </Accordion>

          {/* JSON Preview */}
          <Box sx={{ mt: 3 }}>
            <Button variant="outlined" onClick={showJsonPreview}>
              Show JSON Preview
            </Button>
            {jsonPreview && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  JSON Preview:
                </Typography>
                <Box
                  component="pre"
                  sx={{
                    bgcolor: 'grey.900',
                    p: 2,
                    borderRadius: 1,
                    overflow: 'auto',
                    maxHeight: 200,
                    fontSize: '0.75rem',
                  }}
                >
                  {jsonPreview}
                </Box>
              </Box>
            )}
          </Box>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          onClick={(e) => {
            handleSubmit(
              handleFormSubmit,
              (errors) => {
                console.error('Form validation failed:', errors);
              }
            )(e);
          }}
          variant="contained"
          disabled={
            (editMode === 'yaml' && yamlValidation?.valid !== true) ||
            !formState.isValid ||
            formState.isSubmitting
          }
        >
          Save Rule
        </Button>
      </DialogActions>
    </Dialog>
  );
}
