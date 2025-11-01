import { useState } from 'react';
import { useForm, useFieldArray } from 'react-hook-form';
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
  Slider,
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { CorrelationRule, Condition, Action } from '../../types';

const conditionSchema = z.object({
  field: z.string().min(1, 'Field is required'),
  operator: z.string().min(1, 'Operator is required'),
  value: z.string().min(1, 'Value is required'),
  logic: z.enum(['AND', 'OR']),
});

const actionSchema = z.object({
  type: z.string().min(1, 'Action type is required'),
  config: z.record(z.any()),
});

const correlationRuleFormSchema = z.object({
  name: z.string().min(1, 'Rule name is required'),
  description: z.string().min(1, 'Description is required'),
  severity: z.enum(['Low', 'Medium', 'High', 'Critical']),
  version: z.number().min(1),
  window: z.number().min(1000, 'Window must be at least 1 second'),
  sequence: z.array(z.string()).min(2, 'At least 2 events required in sequence'),
  conditions: z.array(conditionSchema).optional(),
  actions: z.array(actionSchema).min(1, 'At least one action is required'),
});

type CorrelationRuleFormData = z.infer<typeof correlationRuleFormSchema>;

interface CorrelationRuleFormProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: CorrelationRuleFormData) => void;
  initialData?: Partial<CorrelationRule>;
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

export function CorrelationRuleForm({ open, onClose, onSubmit, initialData, title }: CorrelationRuleFormProps) {
  const [jsonPreview, setJsonPreview] = useState<string>('');

  const {
    register,
    control,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
  } = useForm<CorrelationRuleFormData>({
    resolver: zodResolver(correlationRuleFormSchema),
    defaultValues: {
      name: initialData?.name || '',
      description: initialData?.description || '',
      severity: initialData?.severity || 'High',
      version: initialData?.version || 1,
      window: initialData?.window ? initialData.window / 1000000 : 300, // Convert to seconds
      sequence: initialData?.sequence || ['user_login', 'user_login'],
      conditions: initialData?.conditions || [],
      actions: initialData?.actions || [
        { type: 'webhook', config: { url: '' } },
      ],
    },
  });

  const {
    fields: sequenceFields,
    append: appendSequence,
    remove: removeSequence,
  } = useFieldArray({
    control,
    name: 'sequence',
  });

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
  const watchedWindow = watch('window');

  const handleFormSubmit = (data: CorrelationRuleFormData) => {
    // Convert window from seconds to nanoseconds
    const submitData = {
      ...data,
      window: data.window * 1000000,
    };
    onSubmit(submitData);
    onClose();
  };

  const showJsonPreview = () => {
    const ruleData = {
      id: initialData?.id || `correlation_rule_${Date.now()}`,
      ...watchedValues,
      window: watchedValues.window * 1000000, // Convert to nanoseconds for preview
    };
    setJsonPreview(JSON.stringify(ruleData, null, 2));
  };

  const addSequenceEvent = () => {
    appendSequence('user_login');
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
      config: { url: '' },
    });
  };

  const formatWindowLabel = (value: number) => {
    if (value < 60) return `${value}s`;
    if (value < 3600) return `${Math.floor(value / 60)}m ${value % 60}s`;
    return `${Math.floor(value / 3600)}h ${Math.floor((value % 3600) / 60)}m`;
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Box component="form" sx={{ mt: 2 }}>
          <Grid container spacing={3}>
            <Grid item xs={12} sm={8}>
              <TextField
                fullWidth
                label="Rule Name"
                {...register('name')}
                error={!!errors.name}
                helperText={errors.name?.message}
              />
            </Grid>
            <Grid item xs={12} sm={4}>
              <FormControl fullWidth>
                <InputLabel>Severity</InputLabel>
                <Select {...register('severity')} defaultValue="High">
                  <MenuItem value="Low">Low</MenuItem>
                  <MenuItem value="Medium">Medium</MenuItem>
                  <MenuItem value="High">High</MenuItem>
                  <MenuItem value="Critical">Critical</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={2}
                label="Description"
                {...register('description')}
                error={!!errors.description}
                helperText={errors.description?.message}
              />
            </Grid>
          </Grid>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">
                <TimelineIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Event Sequence ({sequenceFields.length} events)
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Define the sequence of events that must occur within the time window to trigger this rule.
              </Typography>

              <Box sx={{ my: 2 }}>
                <Typography gutterBottom>Time Window: {formatWindowLabel(watchedWindow)}</Typography>
                <Slider
                  value={watchedWindow}
                  onChange={(_, value) => setValue('window', value as number)}
                  min={1}
                  max={3600}
                  step={1}
                  marks={[
                    { value: 60, label: '1m' },
                    { value: 300, label: '5m' },
                    { value: 600, label: '10m' },
                    { value: 1800, label: '30m' },
                    { value: 3600, label: '1h' },
                  ]}
                  valueLabelDisplay="auto"
                  valueLabelFormat={formatWindowLabel}
                />
              </Box>

              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
                {sequenceFields.map((field, index) => (
                  <Box key={field.id} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Chip
                      label={`${index + 1}.`}
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                    <FormControl size="small" sx={{ minWidth: 150 }}>
                      <Select
                        {...register(`sequence.${index}`)}
                        defaultValue="user_login"
                      >
                        {commonEventTypes.map((eventType) => (
                          <MenuItem key={eventType} value={eventType}>
                            {eventType}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => removeSequence(index)}
                      disabled={sequenceFields.length === 2}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Box>
                ))}
              </Box>

              <Button
                startIcon={<AddIcon />}
                onClick={addSequenceEvent}
                variant="outlined"
                size="small"
              >
                Add Event
              </Button>
            </AccordionDetails>
          </Accordion>

          <Accordion sx={{ mt: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Additional Conditions ({conditionFields.length})</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Optional conditions to apply to the triggering event.
              </Typography>

              {conditionFields.map((field, index) => (
                <Box key={field.id} sx={{ mb: 2, p: 2, border: '1px solid #333', borderRadius: 1 }}>
                  <Grid container spacing={2} alignItems="center">
                    <Grid item xs={12} sm={3}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Field</InputLabel>
                        <Select {...register(`conditions.${index}.field`)} defaultValue="event_type">
                          {commonFields.map((fieldName) => (
                            <MenuItem key={fieldName} value={fieldName}>
                              {fieldName}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    </Grid>
                    <Grid item xs={12} sm={2}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Logic</InputLabel>
                        <Select {...register(`conditions.${index}.logic`)} defaultValue="AND">
                          <MenuItem value="AND">AND</MenuItem>
                          <MenuItem value="OR">OR</MenuItem>
                        </Select>
                      </FormControl>
                    </Grid>
                    <Grid item xs={12} sm={3}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Operator</InputLabel>
                        <Select {...register(`conditions.${index}.operator`)} defaultValue="equals">
                          {operators.map((op) => (
                            <MenuItem key={op.value} value={op.value}>
                              {op.label}
                            </MenuItem>
                          ))}
                        </Select>
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
                        <Select {...register(`actions.${index}.type`)} defaultValue="webhook">
                          {actionTypes.map((type) => (
                            <MenuItem key={type.value} value={type.value}>
                              {type.label}
                            </MenuItem>
                          ))}
                        </Select>
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
                        disabled={actionFields.length === 1}
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
        <Button onClick={handleSubmit(handleFormSubmit)} variant="contained">
          Save Rule
        </Button>
      </DialogActions>
    </Dialog>
  );
}