import { useState, useEffect } from 'react';
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
  Chip,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
} from '@mui/icons-material';
import { Rule, Condition, Action } from '../../types';

const conditionSchema = z.object({
  field: z.string().min(1, 'Field is required'),
  operator: z.string().min(1, 'Operator is required'),
  value: z.union([z.string(), z.number()]).refine(val => val !== '' && val != null, { message: 'Value is required' }),
  logic: z.enum(['AND', 'OR']),
});

const actionSchema = z.object({
  type: z.string().min(1, 'Action type is required'),
  config: z.union([z.string(), z.record(z.any())]),
});

const ruleFormSchema = z.object({
  name: z.string().min(1, 'Rule name is required'),
  description: z.string().min(1, 'Description is required'),
  severity: z.enum(['Low', 'Medium', 'High', 'Critical']),
  enabled: z.boolean(),
  conditions: z.array(conditionSchema).min(1, 'At least one condition is required'),
  actions: z.array(actionSchema).optional(),
});

type RuleFormData = z.infer<typeof ruleFormSchema>;

interface RuleFormProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: RuleFormData) => void;
  initialData?: Partial<Rule>;
  title: string;
}

const operators = [
  { value: 'equals', label: 'Equals' },
  { value: 'not_equals', label: 'Not Equals' },
  { value: 'contains', label: 'Contains' },
  { value: 'starts_with', label: 'Starts With' },
  { value: 'ends_with', label: 'Ends With' },
  { value: 'greater_than', label: 'Greater Than' },
  { value: 'less_than', label: 'Less Than' },
  { value: 'greater_than_or_equal', label: 'Greater Than or Equal' },
  { value: 'less_than_or_equal', label: 'Less Than or Equal' },
  { value: 'regex', label: 'Regex Match' },
];

const actionTypes = [
  { value: 'webhook', label: 'Webhook' },
  { value: 'jira', label: 'Jira Ticket' },
  { value: 'slack', label: 'Slack Message' },
  { value: 'email', label: 'Email Notification' },
];

const commonFields = [
  'event_type',
  'event_id',
  'timestamp',
  'source_ip',
  'source_format',
  'severity',
  'fields.user',
  'fields.status',
  'fields.ip',
  'fields.port',
  'fields.method',
  'fields.url',
  'fields.user_agent',
];

export function RuleForm({ open, onClose, onSubmit, initialData, title }: RuleFormProps) {
  const [jsonPreview, setJsonPreview] = useState<string>('');

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
    mode: 'onChange', // Validate on change to show errors immediately
    defaultValues: {
      name: '',
      description: '',
      severity: 'Medium',
      enabled: true,
      conditions: [
        { field: 'event_type', operator: 'equals', value: '', logic: 'AND' },
      ],
      actions: [],
    },
  });

  // Reset form when initialData changes or dialog opens
  useEffect(() => {
    if (open) {
      const resetData = {
        name: initialData?.name || '',
        description: initialData?.description || '',
        severity: (initialData?.severity || 'Medium') as 'Low' | 'Medium' | 'High' | 'Critical',
        enabled: initialData?.enabled ?? true,
        conditions: (initialData?.conditions && initialData.conditions.length > 0)
          ? initialData.conditions.map(c => ({
              field: c.field || 'event_type',
              operator: c.operator || 'equals',
              value: c.value !== null && c.value !== undefined ? c.value : '',
              logic: (c.logic || 'AND') as 'AND' | 'OR',
            }))
          : [{ field: 'event_type', operator: 'equals', value: '', logic: 'AND' as const }],
        actions: initialData?.actions?.map((action) => ({
          type: action.type || 'webhook',
          config: typeof action.config === 'object'
            ? JSON.stringify(action.config, null, 2)
            : (action.config || '{}'),
        })) || [],
      };
      console.log('Resetting form with data:', resetData);
      reset(resetData, { keepDefaultValues: false });
    }
  }, [open, initialData, reset]);

  const {
    fields: conditionFields,
    append: appendCondition,
    remove: removeCondition,
  } = useFieldArray({
    control,
    name: 'conditions',
  });

  const {
    fields: actionFields,
    append: appendAction,
    remove: removeAction,
  } = useFieldArray({
    control,
    name: 'actions',
  });

  const watchedValues = watch();

  const handleFormSubmit = (data: RuleFormData) => {
    console.log('RuleForm handleFormSubmit called with data:', data);
    console.log('Form errors:', formState.errors);
    try {
      // Parse action configs from JSON strings to objects
      const processedData = {
        ...data,
        actions: data.actions?.map((action) => ({
          ...action,
          config: typeof action.config === 'string'
            ? JSON.parse(action.config)
            : action.config,
        })) || [],
      };
      console.log('Processed data to be submitted:', processedData);
      onSubmit(processedData);
    } catch (error) {
      console.error('Failed to parse action configuration:', error);
      alert('Invalid JSON in action configuration. Please check your input.');
    }
  };

  const showJsonPreview = () => {
    const ruleData = {
      id: initialData?.id || `rule_${Date.now()}`,
      ...watchedValues,
      version: initialData?.version || 1,
    };
    setJsonPreview(JSON.stringify(ruleData, null, 2));
  };

  const addCondition = () => {
    appendCondition({
      field: 'event_type',
      operator: 'equals',
      value: '',
      logic: 'AND',
    });
  };

  const addAction = () => {
    appendAction({
      type: 'webhook',
      config: JSON.stringify({ url: '' }, null, 2),
    });
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent dividers>
        <Box component="form" sx={{ mt: 2 }}>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start', mb: 2 }}>
            <TextField
              sx={{ flex: 1 }}
              label="Rule Name"
              {...register('name')}
              error={!!formState.errors.name}
              helperText={formState.errors.name?.message}
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
            sx={{ mb: 3 }}
          />

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Conditions ({conditionFields.length})</Typography>
            </AccordionSummary>
            <AccordionDetails>
              {conditionFields.map((field, index) => (
                <Box key={field.id} sx={{ mb: 2, p: 2, border: '1px solid #333', borderRadius: 1 }}>
                  <Grid container spacing={2} alignItems="center">
                    <Grid item xs={12} sm={3}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Field</InputLabel>
                        <Controller
                          name={`conditions.${index}.field`}
                          control={control}
                          render={({ field }) => (
                            <Select {...field}>
                              {commonFields.map((fieldName) => (
                                <MenuItem key={fieldName} value={fieldName}>
                                  {fieldName}
                                </MenuItem>
                              ))}
                            </Select>
                          )}
                        />
                      </FormControl>
                    </Grid>
                    <Grid item xs={12} sm={2}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Logic</InputLabel>
                        <Controller
                          name={`conditions.${index}.logic`}
                          control={control}
                          render={({ field }) => (
                            <Select {...field}>
                              <MenuItem value="AND">AND</MenuItem>
                              <MenuItem value="OR">OR</MenuItem>
                            </Select>
                          )}
                        />
                      </FormControl>
                    </Grid>
                    <Grid item xs={12} sm={3}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Operator</InputLabel>
                        <Controller
                          name={`conditions.${index}.operator`}
                          control={control}
                          render={({ field }) => (
                            <Select {...field}>
                              {operators.map((op) => (
                                <MenuItem key={op.value} value={op.value}>
                                  {op.label}
                                </MenuItem>
                              ))}
                            </Select>
                          )}
                        />
                      </FormControl>
                    </Grid>
                    <Grid item xs={12} sm={3}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Value"
                        {...register(`conditions.${index}.value`)}
                      />
                    </Grid>
                    <Grid item xs={12} sm={1}>
                      <IconButton
                        color="error"
                        onClick={() => removeCondition(index)}
                        disabled={conditionFields.length === 1}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Grid>
                  </Grid>
                </Box>
              ))}
              <Button
                startIcon={<AddIcon />}
                onClick={addCondition}
                variant="outlined"
                sx={{ mt: 1 }}
              >
                Add Condition
              </Button>
            </AccordionDetails>
          </Accordion>

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
            console.log('Save button clicked');
            console.log('Current form values:', watch());
            console.log('Form errors:', formState.errors);
            console.log('Form state isValid:', formState.isValid);
            console.log('Form state isValidating:', formState.isValidating);
            console.log('Form state isDirty:', formState.isDirty);
            console.log('Form state dirtyFields:', formState.dirtyFields);

            // Try calling handleSubmit with error handler
            handleSubmit(
              handleFormSubmit,
              (errors) => {
                console.error('Form validation failed:', errors);
              }
            )(e);
          }}
          variant="contained"
        >
          Save Rule
        </Button>
      </DialogActions>
    </Dialog>
  );
}