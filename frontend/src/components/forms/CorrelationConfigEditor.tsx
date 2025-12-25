import { useState, useEffect, useCallback } from 'react';
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Box,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  ToggleButton,
  ToggleButtonGroup,
  Chip,
  Alert,
  FormHelperText,
  Autocomplete,
  IconButton,
  Paper,
  Stack,
  FormControlLabel,
  Checkbox,
  Button,
  Grid,
} from '@mui/material';
import {
  Code as CodeIcon,
  EditNote as EditNoteIcon,
  Delete as DeleteIcon,
  Add as AddIcon,
} from '@mui/icons-material';
import * as yaml from 'js-yaml';
import { YamlEditor } from '../YamlEditor';

// =============================================================================
// Type Definitions
// =============================================================================

/**
 * Supported correlation types as per Task 174.3 requirements
 * NOTE: Local interface renamed to avoid collision with global CorrelationConfig in types/index.ts
 */
type CorrelationType =
  | 'event_count'
  | 'value_count'
  | 'temporal_proximity'
  | 'value_list'
  | 'rare_value'
  | 'threshold'
  | 'sequence';

/**
 * Condition configuration for event_count and threshold types
 */
interface ConditionConfig {
  operator: '>' | '<' | '>=' | '<=';
  value: number;
}

/**
 * Local correlation configuration matching all 7 correlation types
 * RENAMED from CorrelationConfig to avoid collision with global type in types/index.ts
 */
interface CorrelationConfigLocal {
  type: CorrelationType;
  group_by?: string[];
  timespan?: string;

  // event_count fields
  count?: number;
  condition?: string; // operator for event_count (e.g., ">=", ">")

  // value_count fields
  count_field?: string;

  // temporal_proximity fields
  events?: string[];
  max_gap?: string;

  // value_list fields
  field?: string;
  values?: string[];

  // rare_value fields
  baseline_window?: string;
  threshold?: number; // used by rare_value and threshold types

  // threshold fields (shares 'threshold' with rare_value)
  // condition operator is reused from event_count

  // sequence fields
  ordered?: boolean;
}

interface CorrelationConfigEditorProps {
  value: CorrelationConfigLocal | null;
  onChange: (config: CorrelationConfigLocal) => void;
  disabled?: boolean;
  error?: string;
}

// =============================================================================
// Validation Schema - BLOCKER 3 FIX: Discriminated union with required fields per type
// =============================================================================

const correlationConfigSchema = z.discriminatedUnion('type', [
  // event_count: requires count and condition
  z.object({
    type: z.literal('event_count'),
    group_by: z.array(z.string()).optional(),
    timespan: z.string().optional(),
    count: z.number().min(1, 'Count must be at least 1'),
    condition: z.enum(['>', '>=', '<', '<='], {
      errorMap: () => ({ message: 'Condition is required for event_count' })
    }),
  }),
  // value_count: requires count_field, count, and condition
  z.object({
    type: z.literal('value_count'),
    group_by: z.array(z.string()).optional(),
    timespan: z.string().optional(),
    count_field: z.string().min(1, 'Count field is required for value_count'),
    count: z.number().min(1, 'Count must be at least 1'),
    condition: z.enum(['>', '>=', '<', '<='], {
      errorMap: () => ({ message: 'Condition is required for value_count' })
    }),
  }),
  // temporal_proximity: requires events, timespan, and max_gap
  z.object({
    type: z.literal('temporal_proximity'),
    group_by: z.array(z.string()).optional(),
    timespan: z.string().min(1, 'Timespan is required for temporal_proximity'),
    events: z.array(z.string()).min(2, 'At least 2 events required for temporal_proximity'),
    max_gap: z.string().min(1, 'Max gap is required for temporal_proximity'),
  }),
  // value_list: requires field and values
  z.object({
    type: z.literal('value_list'),
    group_by: z.array(z.string()).optional(),
    field: z.string().min(1, 'Field is required for value_list'),
    values: z.array(z.string()).min(1, 'At least one value required for value_list'),
  }),
  // rare_value: requires field, baseline_window, and threshold
  z.object({
    type: z.literal('rare_value'),
    group_by: z.array(z.string()).optional(),
    field: z.string().min(1, 'Field is required for rare_value'),
    baseline_window: z.string().min(1, 'Baseline window is required for rare_value'),
    threshold: z.number().min(0).max(1, 'Threshold must be between 0 and 1 for rare_value'),
  }),
  // threshold: requires field, threshold value, and condition
  z.object({
    type: z.literal('threshold'),
    group_by: z.array(z.string()).optional(),
    field: z.string().min(1, 'Field is required for threshold'),
    threshold: z.number({ required_error: 'Threshold value is required' }),
    condition: z.enum(['>', '>=', '<', '<='], {
      errorMap: () => ({ message: 'Condition is required for threshold' })
    }),
  }),
  // sequence: requires events, timespan, and ordered flag
  z.object({
    type: z.literal('sequence'),
    events: z.array(z.string()).min(2, 'At least 2 events required for sequence'),
    timespan: z.string().min(1, 'Timespan is required for sequence'),
    ordered: z.boolean(),
  }),
]);

// =============================================================================
// Constants
// =============================================================================

const CORRELATION_TYPES = [
  {
    value: 'event_count' as const,
    label: 'Event Count',
    description: 'Trigger when event count meets condition within timespan',
    requiredFields: ['group_by', 'timespan', 'count', 'condition'],
  },
  {
    value: 'value_count' as const,
    label: 'Value Count',
    description: 'Count distinct values of a field within timespan',
    requiredFields: ['group_by', 'timespan', 'count_field', 'count', 'condition'],
  },
  {
    value: 'temporal_proximity' as const,
    label: 'Temporal Proximity',
    description: 'Detect events occurring close together in time',
    requiredFields: ['group_by', 'timespan', 'events', 'max_gap'],
  },
  {
    value: 'value_list' as const,
    label: 'Value List',
    description: 'Match when field value is in specified list',
    requiredFields: ['group_by', 'field', 'values'],
  },
  {
    value: 'rare_value' as const,
    label: 'Rare Value',
    description: 'Detect statistically rare field values',
    requiredFields: ['group_by', 'field', 'baseline_window', 'threshold'],
  },
  {
    value: 'threshold' as const,
    label: 'Threshold',
    description: 'Trigger when field value crosses threshold',
    requiredFields: ['group_by', 'field', 'threshold', 'condition'],
  },
  {
    value: 'sequence' as const,
    label: 'Sequence',
    description: 'Detect ordered or unordered event sequences',
    requiredFields: ['events', 'timespan', 'ordered'],
  },
];

const TIMESPAN_PRESETS = ['5m', '15m', '30m', '1h', '6h', '12h', '24h', '7d'];

const COMMON_FIELDS = [
  'event_type',
  'source_ip',
  'dest_ip',
  'user',
  'username',
  'hostname',
  'process',
  'command',
  'status',
  'severity',
  'action',
  'bytes',
  'duration',
  'port',
];

const COMMON_EVENT_TYPES = [
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
  'process_creation',
  'registry_modification',
];

const CONDITION_OPERATORS = [
  { value: '>', label: 'Greater than (>)' },
  { value: '>=', label: 'Greater or equal (>=)' },
  { value: '<', label: 'Less than (<)' },
  { value: '<=', label: 'Less or equal (<=)' },
];

// =============================================================================
// Main Component
// =============================================================================

/**
 * CorrelationConfigEditor Component
 *
 * A comprehensive editor for correlation configurations supporting 7 correlation types.
 * Features visual builder mode and raw YAML editing mode with bidirectional sync.
 *
 * Accessibility:
 * - Keyboard navigation fully supported
 * - ARIA labels on all interactive elements
 * - Focus states clearly visible
 * - Error states use color + text for distinction
 *
 * Performance:
 * - Form validation uses Zod for type-safe schemas
 * - React Hook Form minimizes re-renders
 * - YAML parsing errors are caught and displayed
 *
 * @param value - Current correlation configuration
 * @param onChange - Callback when configuration changes
 * @param disabled - Whether editor is disabled
 * @param error - External error message to display
 */
export function CorrelationConfigEditor({
  value,
  onChange,
  disabled = false,
  error,
}: CorrelationConfigEditorProps) {
  const [editMode, setEditMode] = useState<'visual' | 'yaml'>('visual');
  const [yamlContent, setYamlContent] = useState<string>('');
  const [yamlError, setYamlError] = useState<string | null>(null);
  const [isInitialized, setIsInitialized] = useState(false); // BLOCKER 4 FIX: Track initialization

  // Initialize form with default values
  const {
    control,
    watch,
    setValue,
    getValues,
    formState: { errors },
  } = useForm<CorrelationConfigLocal>({
    resolver: zodResolver(correlationConfigSchema),
    mode: 'onChange',
    defaultValues: value || {
      type: 'event_count',
      group_by: [],
      timespan: '5m',
      count: 10,
      condition: '>=',
    },
  });

  const watchedType = watch('type');
  const watchedEvents = watch('events');
  const watchedValues = watch('values');
  const watchedGroupBy = watch('group_by');
  const watchedCount = watch('count');
  const watchedCondition = watch('condition');
  const watchedField = watch('field');
  const watchedOrdered = watch('ordered');

  // BLOCKER 4 FIX: Sync form values with parent onChange (visual mode only)
  // Prevent race condition during initialization
  useEffect(() => {
    const subscription = watch((formData) => {
      if (editMode === 'visual' && isInitialized) {
        onChange(formData as CorrelationConfigLocal);
      }
    });

    // Set initialized after first render to prevent race condition
    const timer = setTimeout(() => setIsInitialized(true), 0);

    return () => {
      subscription.unsubscribe();
      clearTimeout(timer);
    };
  }, [watch, onChange, editMode, isInitialized]);

  // BLOCKER 5 FIX: Generate YAML preview from current form values
  // Removed getValues from dependency array to prevent memory leak
  useEffect(() => {
    try {
      const currentValues = getValues();
      const yamlStr = yaml.dump(currentValues, {
        indent: 2,
        lineWidth: -1,
        noRefs: true,
        sortKeys: false,
      });
      setYamlContent(yamlStr);
      setYamlError(null);
    } catch (err) {
      // Critical Concern #3: Clear yamlContent on serialization error for recovery
      setYamlContent('');
      setYamlError('Failed to serialize configuration to YAML');
    }
  }, [
    watchedType,
    watchedEvents,
    watchedValues,
    watchedGroupBy,
    watchedCount,
    watchedCondition,
    watchedField,
    watchedOrdered,
  ]);

  // BLOCKER 2 FIX: Handle YAML content changes in YAML mode with SAFE parsing
  const handleYamlChange = useCallback(
    (newYaml: string) => {
      setYamlContent(newYaml);

      // Critical Concern #1: Add YAML size validation to prevent DoS
      if (newYaml.length > 100000) {
        setYamlError('YAML too large (max 100KB)');
        return;
      }

      // Attempt to parse and update form values
      try {
        // BLOCKER 2 FIX: Use JSON_SCHEMA to prevent code execution via !!js/function
        const parsed = yaml.load(newYaml, { schema: yaml.JSON_SCHEMA }) as CorrelationConfigLocal;
        const validated = correlationConfigSchema.parse(parsed);

        // Update form values
        Object.keys(validated).forEach((key) => {
          setValue(
            key as keyof CorrelationConfigLocal,
            validated[key as keyof CorrelationConfigLocal]
          );
        });

        onChange(validated);
        setYamlError(null);
      } catch (err) {
        if (err instanceof z.ZodError) {
          setYamlError(`Validation error: ${err.errors[0]?.message || 'Invalid schema'}`);
        } else if (err instanceof Error) {
          setYamlError(err.message);
        } else {
          setYamlError('Invalid YAML format');
        }
      }
    },
    [setValue, onChange]
  );

  // Handle mode toggle
  const handleModeChange = useCallback(
    (_event: React.MouseEvent<HTMLElement>, newMode: 'visual' | 'yaml' | null) => {
      if (newMode !== null) {
        setEditMode(newMode);
      }
    },
    []
  );

  // Add event to events array
  const handleAddEvent = useCallback(() => {
    const currentEvents = watchedEvents || [];
    setValue('events', [...currentEvents, '']);
  }, [watchedEvents, setValue]);

  // Remove event from events array
  const handleRemoveEvent = useCallback(
    (index: number) => {
      const currentEvents = watchedEvents || [];
      setValue(
        'events',
        currentEvents.filter((_, i) => i !== index)
      );
    },
    [watchedEvents, setValue]
  );

  // Update event at specific index
  const handleUpdateEvent = useCallback(
    (index: number, value: string) => {
      const currentEvents = [...(watchedEvents || [])];
      currentEvents[index] = value;
      setValue('events', currentEvents);
    },
    [watchedEvents, setValue]
  );

  // Add value to values array
  const handleAddValue = useCallback(() => {
    const currentValues = watchedValues || [];
    setValue('values', [...currentValues, '']);
  }, [watchedValues, setValue]);

  // Remove value from values array
  const handleRemoveValue = useCallback(
    (index: number) => {
      const currentValues = watchedValues || [];
      setValue(
        'values',
        currentValues.filter((_, i) => i !== index)
      );
    },
    [watchedValues, setValue]
  );

  // Update value at specific index
  const handleUpdateValue = useCallback(
    (index: number, value: string) => {
      const currentValues = [...(watchedValues || [])];
      currentValues[index] = value;
      setValue('values', currentValues);
    },
    [watchedValues, setValue]
  );

  // =============================================================================
  // Render Functions
  // =============================================================================

  const renderTypeSelector = () => (
    <FormControl fullWidth disabled={disabled} error={!!errors.type}>
      <InputLabel id="correlation-type-label">Correlation Type</InputLabel>
      <Controller
        name="type"
        control={control}
        render={({ field }) => (
          <Select
            {...field}
            labelId="correlation-type-label"
            label="Correlation Type"
            aria-label="Correlation Type"
          >
            {CORRELATION_TYPES.map((type) => (
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
      {errors.type && <FormHelperText>{errors.type.message}</FormHelperText>}
    </FormControl>
  );

  const renderGroupByField = () => (
    <Controller
      name="group_by"
      control={control}
      render={({ field }) => (
        <Autocomplete
          multiple
          freeSolo
          disabled={disabled}
          options={COMMON_FIELDS}
          value={field.value || []}
          onChange={(_, newValue) => field.onChange(newValue)}
          renderTags={(value, getTagProps) =>
            value.map((option, index) => {
              const { key, ...tagProps } = getTagProps({ index });
              return (
                <Chip
                  label={option}
                  {...tagProps}
                  key={key}
                  onDelete={tagProps.onDelete}
                  tabIndex={0}
                  onKeyDown={(e) => {
                    // Critical Concern #2: Fix keyboard deletion for accessibility
                    if ((e.key === 'Delete' || e.key === 'Backspace') && tagProps.onDelete) {
                      tagProps.onDelete(e);
                    }
                  }}
                />
              );
            })
          }
          renderInput={(params) => (
            <TextField
              {...params}
              label="Group By Fields"
              placeholder="Add field..."
              helperText="Fields to group correlation events by (e.g., source_ip, user)"
              error={!!errors.group_by}
            />
          )}
        />
      )}
    />
  );

  const renderTimespanField = () => (
    <Controller
      name="timespan"
      control={control}
      render={({ field }) => (
        <Autocomplete
          freeSolo
          disabled={disabled}
          options={TIMESPAN_PRESETS}
          value={field.value || ''}
          onChange={(_, newValue) => field.onChange(newValue)}
          renderInput={(params) => (
            <TextField
              {...params}
              label="Timespan"
              placeholder="5m"
              helperText="Time window for correlation (e.g., 5m, 1h, 30s)"
              error={!!errors.timespan}
            />
          )}
        />
      )}
    />
  );

  const renderEventCountFields = () => (
    <>
      {renderGroupByField()}
      {renderTimespanField()}
      <Stack direction="row" spacing={2}>
        <Controller
          name="count"
          control={control}
          render={({ field }) => (
            <TextField
              {...field}
              type="number"
              label="Count"
              disabled={disabled}
              value={field.value || 10}
              onChange={(e) => field.onChange(Number(e.target.value))}
              error={!!errors.count}
              helperText="Number of events"
              sx={{ flex: 1 }}
            />
          )}
        />
        <Controller
          name="condition"
          control={control}
          render={({ field }) => (
            <FormControl sx={{ minWidth: 200 }} disabled={disabled}>
              <InputLabel>Condition</InputLabel>
              <Select {...field} value={field.value || '>='} label="Condition">
                {CONDITION_OPERATORS.map((op) => (
                  <MenuItem key={op.value} value={op.value}>
                    {op.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
        />
      </Stack>
    </>
  );

  const renderValueCountFields = () => (
    <>
      {renderGroupByField()}
      {renderTimespanField()}
      <Controller
        name="count_field"
        control={control}
        render={({ field }) => (
          <Autocomplete
            freeSolo
            disabled={disabled}
            options={COMMON_FIELDS}
            value={field.value || ''}
            onChange={(_, newValue) => field.onChange(newValue)}
            renderInput={(params) => (
              <TextField
                {...params}
                label="Count Field"
                placeholder="source_ip"
                helperText="Field to count distinct values for"
                error={!!errors.count_field}
              />
            )}
          />
        )}
      />
      <Stack direction="row" spacing={2}>
        <Controller
          name="count"
          control={control}
          render={({ field }) => (
            <TextField
              {...field}
              type="number"
              label="Count"
              disabled={disabled}
              value={field.value || 10}
              onChange={(e) => field.onChange(Number(e.target.value))}
              error={!!errors.count}
              helperText="Number of distinct values"
              sx={{ flex: 1 }}
            />
          )}
        />
        <Controller
          name="condition"
          control={control}
          render={({ field }) => (
            <FormControl sx={{ minWidth: 200 }} disabled={disabled}>
              <InputLabel>Condition</InputLabel>
              <Select {...field} value={field.value || '>='} label="Condition">
                {CONDITION_OPERATORS.map((op) => (
                  <MenuItem key={op.value} value={op.value}>
                    {op.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
        />
      </Stack>
    </>
  );

  const renderTemporalProximityFields = () => (
    <>
      {renderGroupByField()}
      {renderTimespanField()}
      <Box>
        <Typography variant="subtitle2" gutterBottom>
          Event Sequence
        </Typography>
        <Stack spacing={2}>
          {(watchedEvents || []).map((event, index) => (
            <Stack key={index} direction="row" spacing={1}>
              <Autocomplete
                freeSolo
                disabled={disabled}
                options={COMMON_EVENT_TYPES}
                value={event}
                onChange={(_, newValue) =>
                  handleUpdateEvent(index, newValue || '')
                }
                sx={{ flex: 1 }}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label={`Event ${index + 1}`}
                    placeholder="user_login"
                  />
                )}
              />
              <IconButton
                onClick={() => handleRemoveEvent(index)}
                disabled={disabled}
                aria-label={`Remove event ${index + 1}`}
                color="error"
              >
                <DeleteIcon />
              </IconButton>
            </Stack>
          ))}
          <Button
            startIcon={<AddIcon />}
            onClick={handleAddEvent}
            disabled={disabled}
            variant="outlined"
          >
            Add Event
          </Button>
        </Stack>
      </Box>
      <Controller
        name="max_gap"
        control={control}
        render={({ field }) => (
          <TextField
            {...field}
            fullWidth
            disabled={disabled}
            label="Max Gap"
            placeholder="30s"
            helperText="Maximum time gap between events"
            error={!!errors.max_gap}
          />
        )}
      />
    </>
  );

  const renderValueListFields = () => (
    <>
      {renderGroupByField()}
      <Controller
        name="field"
        control={control}
        render={({ field }) => (
          <Autocomplete
            freeSolo
            disabled={disabled}
            options={COMMON_FIELDS}
            value={field.value || ''}
            onChange={(_, newValue) => field.onChange(newValue)}
            renderInput={(params) => (
              <TextField
                {...params}
                label="Field"
                placeholder="status"
                helperText="Field to match against value list"
                error={!!errors.field}
              />
            )}
          />
        )}
      />
      <Box>
        <Typography variant="subtitle2" gutterBottom>
          Values
        </Typography>
        <Stack spacing={2}>
          {(watchedValues || []).map((value, index) => (
            <Stack key={index} direction="row" spacing={1}>
              <TextField
                fullWidth
                disabled={disabled}
                label={`Value ${index + 1}`}
                placeholder="failed"
                value={value}
                onChange={(e) => handleUpdateValue(index, e.target.value)}
              />
              <IconButton
                onClick={() => handleRemoveValue(index)}
                disabled={disabled}
                aria-label={`Remove value ${index + 1}`}
                color="error"
              >
                <DeleteIcon />
              </IconButton>
            </Stack>
          ))}
          <Button
            startIcon={<AddIcon />}
            onClick={handleAddValue}
            disabled={disabled}
            variant="outlined"
          >
            Add Value
          </Button>
        </Stack>
      </Box>
    </>
  );

  const renderRareValueFields = () => (
    <>
      {renderGroupByField()}
      <Controller
        name="field"
        control={control}
        render={({ field }) => (
          <Autocomplete
            freeSolo
            disabled={disabled}
            options={COMMON_FIELDS}
            value={field.value || ''}
            onChange={(_, newValue) => field.onChange(newValue)}
            renderInput={(params) => (
              <TextField
                {...params}
                label="Field"
                placeholder="command"
                helperText="Field to analyze for rare values"
                error={!!errors.field}
              />
            )}
          />
        )}
      />
      <Controller
        name="baseline_window"
        control={control}
        render={({ field }) => (
          <TextField
            {...field}
            fullWidth
            disabled={disabled}
            label="Baseline Window"
            placeholder="24h"
            helperText="Historical window for baseline calculation"
            error={!!errors.baseline_window}
          />
        )}
      />
      <Controller
        name="threshold"
        control={control}
        render={({ field }) => (
          <TextField
            {...field}
            type="number"
            fullWidth
            disabled={disabled}
            label="Threshold"
            placeholder="0.01"
            helperText="Rarity threshold (e.g., 0.01 for 1%)"
            value={field.value || 0.01}
            onChange={(e) => field.onChange(Number(e.target.value))}
            error={!!errors.threshold}
            inputProps={{ step: 0.01, min: 0, max: 1 }}
          />
        )}
      />
    </>
  );

  const renderThresholdFields = () => (
    <>
      {renderGroupByField()}
      <Controller
        name="field"
        control={control}
        render={({ field }) => (
          <Autocomplete
            freeSolo
            disabled={disabled}
            options={COMMON_FIELDS}
            value={field.value || ''}
            onChange={(_, newValue) => field.onChange(newValue)}
            renderInput={(params) => (
              <TextField
                {...params}
                label="Field"
                placeholder="bytes"
                helperText="Field to compare against threshold"
                error={!!errors.field}
              />
            )}
          />
        )}
      />
      <Stack direction="row" spacing={2}>
        <Controller
          name="threshold"
          control={control}
          render={({ field }) => (
            <TextField
              {...field}
              type="number"
              label="Threshold"
              disabled={disabled}
              value={field.value || 1000}
              onChange={(e) => field.onChange(Number(e.target.value))}
              error={!!errors.threshold}
              helperText="Threshold value"
              sx={{ flex: 1 }}
            />
          )}
        />
        <Controller
          name="condition"
          control={control}
          render={({ field }) => (
            <FormControl sx={{ minWidth: 200 }} disabled={disabled}>
              <InputLabel>Condition</InputLabel>
              <Select {...field} value={field.value || '>'} label="Condition">
                {CONDITION_OPERATORS.map((op) => (
                  <MenuItem key={op.value} value={op.value}>
                    {op.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
        />
      </Stack>
    </>
  );

  const renderSequenceFields = () => (
    <>
      <Box>
        <Typography variant="subtitle2" gutterBottom>
          Event Sequence
        </Typography>
        <Stack spacing={2}>
          {(watchedEvents || []).map((event, index) => (
            <Stack key={index} direction="row" spacing={1}>
              <Autocomplete
                freeSolo
                disabled={disabled}
                options={COMMON_EVENT_TYPES}
                value={event}
                onChange={(_, newValue) =>
                  handleUpdateEvent(index, newValue || '')
                }
                sx={{ flex: 1 }}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label={`Event ${index + 1}`}
                    placeholder="user_login"
                  />
                )}
              />
              <IconButton
                onClick={() => handleRemoveEvent(index)}
                disabled={disabled}
                aria-label={`Remove event ${index + 1}`}
                color="error"
              >
                <DeleteIcon />
              </IconButton>
            </Stack>
          ))}
          <Button
            startIcon={<AddIcon />}
            onClick={handleAddEvent}
            disabled={disabled}
            variant="outlined"
          >
            Add Event
          </Button>
        </Stack>
      </Box>
      {renderTimespanField()}
      <Controller
        name="ordered"
        control={control}
        render={({ field }) => (
          <FormControlLabel
            control={
              <Checkbox
                checked={field.value || false}
                onChange={(e) => field.onChange(e.target.checked)}
                disabled={disabled}
              />
            }
            label="Require ordered sequence"
          />
        )}
      />
    </>
  );

  const renderTypeSpecificFields = () => {
    switch (watchedType) {
      case 'event_count':
        return renderEventCountFields();
      case 'value_count':
        return renderValueCountFields();
      case 'temporal_proximity':
        return renderTemporalProximityFields();
      case 'value_list':
        return renderValueListFields();
      case 'rare_value':
        return renderRareValueFields();
      case 'threshold':
        return renderThresholdFields();
      case 'sequence':
        return renderSequenceFields();
      default:
        return null;
    }
  };

  // =============================================================================
  // Main Render
  // =============================================================================

  return (
    <Box>
      {/* Mode Toggle */}
      <Box
        sx={{
          mb: 2,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <Typography variant="subtitle1" sx={{ fontWeight: 'medium' }}>
          Correlation Configuration
        </Typography>
        <ToggleButtonGroup
          value={editMode}
          exclusive
          onChange={handleModeChange}
          size="small"
          disabled={disabled}
          aria-label="Edit mode"
        >
          <ToggleButton value="visual" aria-label="Visual mode">
            <EditNoteIcon sx={{ mr: 0.5 }} fontSize="small" />
            Visual
          </ToggleButton>
          <ToggleButton value="yaml" aria-label="YAML mode">
            <CodeIcon sx={{ mr: 0.5 }} fontSize="small" />
            YAML
          </ToggleButton>
        </ToggleButtonGroup>
      </Box>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* YAML Mode */}
      {editMode === 'yaml' && (
        <Box>
          <YamlEditor
            value={yamlContent}
            onChange={handleYamlChange}
            readOnly={disabled}
            minHeight="400px"
            error={!!yamlError}
          />
          {yamlError && (
            <Alert severity="error" sx={{ mt: 1 }}>
              <Typography variant="subtitle2">YAML Error:</Typography>
              <Typography variant="body2">{yamlError}</Typography>
            </Alert>
          )}
        </Box>
      )}

      {/* Visual Mode */}
      {editMode === 'visual' && (
        <Grid container spacing={3}>
          {/* Visual Editor */}
          <Grid item xs={12} md={6}>
            <Stack spacing={3}>
              {renderTypeSelector()}
              {renderTypeSpecificFields()}
            </Stack>
          </Grid>

          {/* Live YAML Preview */}
          <Grid item xs={12} md={6}>
            <Box>
              <Typography
                variant="subtitle2"
                gutterBottom
                sx={{ fontWeight: 'medium' }}
              >
                YAML Preview
              </Typography>
              <YamlEditor
                value={yamlContent}
                onChange={() => {}} // Read-only in visual mode
                readOnly={true}
                minHeight="400px"
              />
            </Box>
          </Grid>
        </Grid>
      )}
    </Box>
  );
}
