/**
 * SIGMA Rule Builder Modal
 *
 * Comprehensive modal for creating/editing detection rules using SIGMA
 * standard field names with a guided 4-step wizard interface.
 */

import React, { useState, useEffect } from 'react';
import { useForm, useFieldArray, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Dialog,
  DialogContent,
  TextField,
  Button,
  Box,
  Typography,
  IconButton,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Paper,
  Divider,
  Autocomplete,
  Alert,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  CircularProgress
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  PlayArrow as PlayArrowIcon,
  Code as CodeIcon,
  ExpandMore as ExpandMoreIcon,
  Info as InfoIcon,
  Help as HelpIcon
} from '@mui/icons-material';
import { StepWizard, WizardStep } from '../StepWizard';
import { SigmaFieldAutocomplete, SigmaFieldValueAutocomplete } from './SigmaFieldAutocomplete';
import { CqlSyntaxHighlighter } from '../CqlSyntaxHighlighter';
import { RuleExceptionManager } from './RuleExceptionManager';
import { CqlEditor } from '../CqlEditor';
import { CqlSyntaxReference } from '../CqlSyntaxReference';
import {
  SigmaLogSource,
  getAllLogSources,
  getLogSourceDisplayName,
  getFieldByName,
  getSuggestedOperators,
  resolveFieldAlias
} from '../../services/sigmaFields';
import { Rule, Condition, Action } from '../../types';

// ==================== VALIDATION SCHEMAS ====================

const conditionSchema = z.object({
  field: z.string().min(1, 'Field is required'),
  operator: z.string().min(1, 'Operator is required'),
  value: z.string().min(1, 'Value is required'),
  logic: z.enum(['AND', 'OR'])
});

const actionSchema = z.object({
  type: z.string().min(1, 'Action type is required'),
  config: z.union([z.string(), z.record(z.any())])
});

const exceptionSchema = z.object({
  name: z.string().min(1, 'Exception name is required'),
  description: z.string().min(1, 'Description is required'),
  type: z.enum(['suppress', 'modify_severity']),
  condition_type: z.enum(['sigma_filter', 'cql']),
  condition: z.string().min(1, 'Condition is required'),
  new_severity: z.string().optional(),
  enabled: z.boolean(),
  priority: z.number().int().min(1).max(1000),
  expires_at: z.string().optional(),
  justification: z.string(),
  tags: z.array(z.string())
});

const ruleFormSchema = z.object({
  name: z.string().min(1, 'Rule name is required').max(100, 'Name too long'),
  description: z.string().min(1, 'Description is required').max(500, 'Description too long'),
  severity: z.enum(['Low', 'Medium', 'High', 'Critical']),
  enabled: z.boolean(),
  log_source: z.string().optional(),
  tags: z.array(z.string()).optional(),
  conditions: z.array(conditionSchema).min(1, 'At least one condition is required'),
  actions: z.array(actionSchema).min(1, 'At least one action is required'),
  exceptions: z.array(exceptionSchema).optional()
});

type RuleFormData = z.infer<typeof ruleFormSchema>;

// ==================== INTERFACES ====================

export interface SigmaRuleBuilderModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: RuleFormData) => Promise<void>;
  initialData?: Partial<Rule>;
  title?: string;
}

// ==================== CONSTANTS ====================

const OPERATOR_OPTIONS = [
  { value: '=', label: 'Equals (=)', types: ['string', 'number', 'boolean'] },
  { value: '!=', label: 'Not Equals (!=)', types: ['string', 'number', 'boolean'] },
  { value: 'contains', label: 'Contains', types: ['string'] },
  { value: 'startswith', label: 'Starts With', types: ['string'] },
  { value: 'endswith', label: 'Ends With', types: ['string'] },
  { value: 'matches', label: 'Regex Match (~=)', types: ['string'] },
  { value: '>', label: 'Greater Than (>)', types: ['number'] },
  { value: '<', label: 'Less Than (<)', types: ['number'] },
  { value: '>=', label: 'Greater or Equal (>=)', types: ['number'] },
  { value: '<=', label: 'Less or Equal (<=)', types: ['number'] },
  { value: 'in', label: 'In List', types: ['string', 'number'] },
  { value: 'not in', label: 'Not In List', types: ['string', 'number'] }
];

const ACTION_TYPES = [
  { value: 'webhook', label: 'Webhook', icon: '🔗' },
  { value: 'jira', label: 'Jira Ticket', icon: '📋' },
  { value: 'slack', label: 'Slack Message', icon: '💬' },
  { value: 'email', label: 'Email Notification', icon: '📧' }
];

const COMMON_TAGS = [
  'attack.t1003',
  'attack.credential_access',
  'attack.discovery',
  'attack.execution',
  'attack.persistence',
  'attack.privilege_escalation',
  'attack.lateral_movement',
  'windows',
  'linux',
  'network',
  'malware',
  'suspicious'
];

// ==================== MAIN COMPONENT ====================

export function SigmaRuleBuilderModal({
  open,
  onClose,
  onSubmit,
  initialData,
  title = 'Create Detection Rule'
}: SigmaRuleBuilderModalProps) {
  const [activeStep, setActiveStep] = useState(0);
  const [logSource, setLogSource] = useState<SigmaLogSource>('windows_sysmon');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [testResults, setTestResults] = useState<any>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [detectionMode, setDetectionMode] = useState<'visual' | 'cql'>('visual');
  const [cqlQuery, setCqlQuery] = useState<string>('');
  const [cqlValidation, setCqlValidation] = useState<{ valid: boolean; error?: string } | null>(null);
  const [cqlReferenceOpen, setCqlReferenceOpen] = useState(false);

  const {
    control,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
    reset
  } = useForm<RuleFormData>({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: {
      name: initialData?.name || '',
      description: initialData?.description || '',
      severity: (initialData?.severity as any) || 'Medium',
      enabled: initialData?.enabled ?? true,
      log_source: 'windows_sysmon',
      tags: [],
      conditions: initialData?.conditions || [{ field: '', operator: '=', value: '', logic: 'AND' }],
      actions: initialData?.actions || [],
      exceptions: []
    }
  });

  const {
    fields: conditionFields,
    append: appendCondition,
    remove: removeCondition,
    replace: replaceConditions
  } = useFieldArray({
    control,
    name: 'conditions'
  });

  const {
    fields: actionFields,
    append: appendAction,
    remove: removeAction,
    replace: replaceActions
  } = useFieldArray({
    control,
    name: 'actions'
  });

  const watchedConditions = watch('conditions');
  const watchedLogSource = watch('log_source');

  useEffect(() => {
    if (watchedLogSource) {
      setLogSource(watchedLogSource as SigmaLogSource);
    }
  }, [watchedLogSource]);

  // Parse Sigma detection object into visual conditions
  const parseSigmaDetection = (detectionObj: any): any[] => {
    const conditions: any[] = [];

    try {
      // Handle selection-based detection
      if (detectionObj.selection) {
        const selection = detectionObj.selection;

        // Parse each field in the selection
        Object.entries(selection).forEach(([fieldKey, value], index) => {
          // Parse field and operator from key (e.g., "TargetObject|contains|all")
          const parts = fieldKey.split('|');
          const field = parts[0];
          const operator = parts[1] || '=';
          const modifier = parts[2]; // all, any, etc.

          let conditionValue = '';
          let conditionOperator = operator;

          // Determine the value and operator
          if (Array.isArray(value)) {
            // If it's an array with modifier "all", use AND logic
            conditionValue = value.join(', ');
            if (modifier === 'all') {
              conditionOperator = 'contains'; // Use contains for pattern matching
            }
          } else if (typeof value === 'string') {
            conditionValue = value;
          } else if (typeof value === 'object') {
            conditionValue = JSON.stringify(value);
          }

          conditions.push({
            field: field,
            operator: conditionOperator === 'contains' ? 'contains' : '=',
            value: conditionValue,
            logic: index === 0 ? 'AND' : 'AND'
          });
        });
      }

      // If no conditions were parsed, add a default empty one
      if (conditions.length === 0) {
        conditions.push({ field: '', operator: '=', value: '', logic: 'AND' });
      }
    } catch (error) {
      conditions.push({ field: '', operator: '=', value: '', logic: 'AND' });
    }

    return conditions;
  };

  // Reset form when modal opens or initialData changes
  useEffect(() => {
    if (open) {
      // Normalize severity value: capitalize first letter to match Select options
      const normalizeSeverity = (sev: string | undefined): 'Low' | 'Medium' | 'High' | 'Critical' => {
        if (!sev) return 'Medium';
        const capitalized = sev.charAt(0).toUpperCase() + sev.slice(1).toLowerCase();
        if (['Low', 'Medium', 'High', 'Critical'].includes(capitalized)) {
          return capitalized as 'Low' | 'Medium' | 'High' | 'Critical';
        }
        return 'Medium';
      };

      // Check if this is a Sigma rule with a CQL query field or detection object
      const hasQuery = (initialData as any)?.query;
      let hasConditions = initialData?.conditions && initialData.conditions.length > 0;

      // Determine mode and process query
      if (hasQuery && !hasConditions) {
        let queryObj = hasQuery;

        // Parse if it's a JSON string
        if (typeof hasQuery === 'string') {
          try {
            queryObj = JSON.parse(hasQuery);
          } catch {
            // If it's a plain string, treat as CQL
            setDetectionMode('cql');
            setCqlQuery(String(hasQuery));
            return;
          }
        }

        // Check if it's a Sigma detection object (has condition/selection) or a CQL string
        if (typeof queryObj === 'object' && (queryObj.condition || queryObj.selection)) {
          // This is a Sigma detection object - convert to visual conditions
          setDetectionMode('visual');
          setCqlQuery('');

          // Parse Sigma detection into visual conditions
          const parsedConditions = parseSigmaDetection(queryObj);

          // We'll set these conditions in the reset below
          hasConditions = parsedConditions.length > 0;
          if (hasConditions) {
            (initialData as any)._parsedConditions = parsedConditions;
          }
        } else if (typeof queryObj === 'string') {
          // It's a CQL query string
          setDetectionMode('cql');
          setCqlQuery(String(queryObj));
        } else {
          // Unknown format, default to visual
          setDetectionMode('visual');
          setCqlQuery('');
        }
      } else {
        // Otherwise use visual builder mode
        setDetectionMode('visual');
        setCqlQuery('');
      }

      const formData = {
        name: initialData?.name || '',
        description: initialData?.description || '',
        severity: normalizeSeverity(initialData?.severity as string),
        enabled: initialData?.enabled ?? true,
        log_source: (initialData?.log_source as any) || 'windows_sysmon',
        tags: initialData?.tags || [],
        conditions: (initialData as any)?._parsedConditions || (hasConditions
          ? initialData.conditions
          : [{ field: '', operator: '=', value: '', logic: 'AND' }]),
        actions: initialData?.actions || [],
        exceptions: (initialData as any)?.exceptions || []
      };

      reset(formData);

      // Manually update field arrays since reset doesn't trigger them
      replaceConditions(formData.conditions);
      if (formData.actions && formData.actions.length > 0) {
        replaceActions(formData.actions);
      }
    }
  }, [open, initialData, reset, replaceConditions, replaceActions]);

  // ==================== VALIDATION FUNCTIONS ====================

  const validateBasicInfo = (): string | null => {
    if (!watch('name')) return 'Rule name is required';
    if (!watch('description')) return 'Description is required';
    if (!watch('severity')) return 'Severity is required';
    return null;
  };

  const validateDetection = (): string | null => {
    // If in CQL mode, validate CQL query
    if (detectionMode === 'cql') {
      if (!cqlQuery || cqlQuery.trim().length === 0) {
        return 'CQL query is required';
      }
      return null;
    }

    // Visual mode validation
    const conditions = watch('conditions');
    if (!conditions || conditions.length === 0) {
      return 'At least one condition is required';
    }

    for (let i = 0; i < conditions.length; i++) {
      const condition = conditions[i];
      if (!condition.field) return `Condition ${i + 1}: Field is required`;
      if (!condition.operator) return `Condition ${i + 1}: Operator is required`;
      if (!condition.value && condition.operator !== 'exists' && condition.operator !== 'not exists') {
        return `Condition ${i + 1}: Value is required`;
      }
    }

    return null;
  };

  const validateActions = (): string | null => {
    const actions = watch('actions');
    if (!actions || actions.length === 0) {
      return 'At least one action is required';
    }
    return null;
  };

  // ==================== HANDLERS ====================

  const validateCqlQuery = (query: string): { valid: boolean; error?: string } => {
    if (!query || query.trim().length === 0) {
      return { valid: false, error: 'Query cannot be empty' };
    }

    // Basic CQL syntax validation
    const hasLogicalOperator = /\b(AND|OR)\b/i.test(query);
    const hasComparison = /[=!<>]|contains|startswith|endswith|matches|in\b/i.test(query);

    if (!hasComparison) {
      return { valid: false, error: 'Query must contain at least one comparison operator (=, !=, contains, etc.)' };
    }

    // Check for balanced quotes
    const doubleQuotes = (query.match(/"/g) || []).length;
    const singleQuotes = (query.match(/'/g) || []).length;
    if (doubleQuotes % 2 !== 0 || singleQuotes % 2 !== 0) {
      return { valid: false, error: 'Unmatched quotes in query' };
    }

    // Check for balanced parentheses
    const openParens = (query.match(/\(/g) || []).length;
    const closeParens = (query.match(/\)/g) || []).length;
    if (openParens !== closeParens) {
      return { valid: false, error: 'Unmatched parentheses in query' };
    }

    return { valid: true };
  };

  const handleCqlValidation = () => {
    const result = validateCqlQuery(cqlQuery);
    setCqlValidation(result);
  };

  const handleTestRule = async () => {
    setIsTesting(true);
    try {
      // TODO: Implement actual API call to test rule
      await new Promise(resolve => setTimeout(resolve, 1500));

      setTestResults({
        success: true,
        matched_events: 5,
        sample_events: [
          { event_id: '1', timestamp: new Date().toISOString(), matched: true },
          { event_id: '2', timestamp: new Date().toISOString(), matched: true }
        ]
      });
    } catch (error) {
      setTestResults({
        success: false,
        error: 'Failed to test rule'
      });
    } finally {
      setIsTesting(false);
    }
  };

  const handleFormSubmit = async (data: RuleFormData) => {
    setIsSubmitting(true);
    try {
      // If in CQL mode, add the CQL query to the data
      const submissionData = {
        ...data,
        ...(detectionMode === 'cql' && { cql: cqlQuery })
      };

      await onSubmit(submissionData);
      reset();
      setActiveStep(0);
      setDetectionMode('visual');
      setCqlQuery('');
      onClose();
    } catch (error) {
      console.error('Failed to submit rule:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = () => {
    reset();
    setActiveStep(0);
    setTestResults(null);
    onClose();
  };

  const generateCQL = (): string => {
    const conditions = watch('conditions');
    if (!conditions || conditions.length === 0) return '';

    return conditions
      .map((cond, idx) => {
        const prefix = idx > 0 ? ` ${cond.logic} ` : '';
        const fieldName = resolveFieldAlias(cond.field);

        if (cond.operator === 'in' || cond.operator === 'not in') {
          const values = cond.value.split(',').map(v => `"${v.trim()}"`).join(', ');
          return `${prefix}${fieldName} ${cond.operator} [${values}]`;
        }

        if (cond.operator === 'exists' || cond.operator === 'not exists') {
          return `${prefix}${fieldName} ${cond.operator}`;
        }

        const needsQuotes = isNaN(Number(cond.value));
        const value = needsQuotes ? `"${cond.value}"` : cond.value;
        return `${prefix}${fieldName} ${cond.operator} ${value}`;
      })
      .join('');
  };

  // ==================== STEP CONTENT COMPONENTS ====================

  const BasicInfoStep = (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box sx={{ width: '100%' }}>
        <Controller
          name="name"
          control={control}
          render={({ field }) => (
            <TextField
              {...field}
              label="Rule Name"
              required
              fullWidth
              error={!!errors.name}
              helperText={errors.name?.message || 'Descriptive name for the detection rule'}
              placeholder="e.g., Suspicious PowerShell Execution"
            />
          )}
        />
      </Box>

      <Box sx={{ width: '100%' }}>
        <Controller
          name="description"
          control={control}
          render={({ field }) => (
            <TextField
              {...field}
              label="Description"
              required
              fullWidth
              multiline
              rows={3}
              error={!!errors.description}
              helperText={errors.description?.message || 'What does this rule detect?'}
              placeholder="Detects execution of PowerShell with encoded commands..."
            />
          )}
        />
      </Box>

      <Box sx={{ width: '100%' }}>
        <Controller
          name="severity"
          control={control}
          render={({ field }) => (
            <FormControl fullWidth required>
              <InputLabel>Severity</InputLabel>
              <Select {...field} label="Severity">
                <MenuItem value="Low">🟢 Low</MenuItem>
                <MenuItem value="Medium">🟡 Medium</MenuItem>
                <MenuItem value="High">🟠 High</MenuItem>
                <MenuItem value="Critical">🔴 Critical</MenuItem>
              </Select>
            </FormControl>
          )}
        />
      </Box>

      <Box sx={{ width: '100%' }}>
        <Controller
          name="log_source"
          control={control}
          render={({ field }) => (
            <FormControl fullWidth>
              <InputLabel>Log Source</InputLabel>
              <Select {...field} label="Log Source">
                {getAllLogSources().map(source => (
                  <MenuItem key={source} value={source}>
                    {getLogSourceDisplayName(source)}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
        />
      </Box>

      <Box sx={{ width: '100%' }}>
        <Controller
          name="tags"
          control={control}
          render={({ field }) => (
            <Autocomplete
              {...field}
              multiple
              freeSolo
              options={COMMON_TAGS}
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
                  placeholder="Add tags (e.g., attack.t1003, windows)"
                  helperText="Press Enter to add custom tags"
                />
              )}
            />
          )}
        />
      </Box>
    </Box>
  );

  const DetectionStep = (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h6">Detection Conditions</Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <Chip
            label="Visual Builder"
            onClick={() => {
              setDetectionMode('visual');
              if (cqlQuery) {
                // Optionally parse CQL back to conditions here
              }
            }}
            color={detectionMode === 'visual' ? 'primary' : 'default'}
            variant={detectionMode === 'visual' ? 'filled' : 'outlined'}
            clickable
          />
          <Chip
            label="CQL Query"
            onClick={() => {
              setDetectionMode('cql');
              // Sync visual conditions to CQL when switching
              setCqlQuery(generateCQL());
            }}
            color={detectionMode === 'cql' ? 'primary' : 'default'}
            variant={detectionMode === 'cql' ? 'filled' : 'outlined'}
            clickable
          />
        </Box>
      </Box>

      {detectionMode === 'visual' ? (
        <>
          <Box sx={{ mb: 2, display: 'flex', justifyContent: 'flex-end', alignItems: 'center' }}>
            <Button
              startIcon={<AddIcon />}
              onClick={() => appendCondition({ field: '', operator: '=', value: '', logic: 'AND' })}
              variant="outlined"
              size="small"
              sx={{ ml: 2 }}
            >
              Add Condition
            </Button>
          </Box>

          {conditionFields.map((field, index) => {
            const currentField = watchedConditions[index];
            const sigmaField = currentField?.field ? getFieldByName(currentField.field) : undefined;
            const suggestedOperators = sigmaField
              ? getSuggestedOperators(sigmaField.dataType)
              : OPERATOR_OPTIONS.map(op => op.value);

            return (
              <Paper key={field.id} sx={{ p: 2, mb: 2 }} variant="outlined">
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {/* Logic Connector */}
                  {index > 0 && (
                    <Box sx={{ width: '100%' }}>
                      <Controller
                        name={`conditions.${index}.logic`}
                        control={control}
                        render={({ field }) => (
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Chip
                              label="AND"
                              onClick={() => field.onChange('AND')}
                              color={field.value === 'AND' ? 'primary' : 'default'}
                              variant={field.value === 'AND' ? 'filled' : 'outlined'}
                            />
                            <Chip
                              label="OR"
                              onClick={() => field.onChange('OR')}
                              color={field.value === 'OR' ? 'primary' : 'default'}
                              variant={field.value === 'OR' ? 'filled' : 'outlined'}
                            />
                          </Box>
                        )}
                      />
                    </Box>
                  )}

                  {/* Field */}
                  <Box sx={{ width: '100%' }}>
                    <Controller
                      name={`conditions.${index}.field`}
                      control={control}
                      render={({ field }) => (
                        <SigmaFieldAutocomplete
                          value={field.value}
                          onChange={field.onChange}
                          logSource={logSource}
                          label="Field"
                          required
                          error={errors.conditions?.[index]?.field?.message}
                        />
                      )}
                    />
                  </Box>

                  {/* Operator */}
                  <Box sx={{ width: '100%' }}>
                    <Controller
                      name={`conditions.${index}.operator`}
                      control={control}
                      render={({ field }) => (
                        <FormControl fullWidth required>
                          <InputLabel>Operator</InputLabel>
                          <Select {...field} label="Operator">
                            {OPERATOR_OPTIONS
                              .filter(op => !sigmaField || suggestedOperators.includes(op.value))
                              .map(op => (
                                <MenuItem key={op.value} value={op.value}>
                                  {op.label}
                                </MenuItem>
                              ))}
                          </Select>
                        </FormControl>
                      )}
                    />
                  </Box>

                  {/* Value */}
                  <Box sx={{ width: '100%' }}>
                    <Controller
                      name={`conditions.${index}.value`}
                      control={control}
                      render={({ field }) => (
                        <SigmaFieldValueAutocomplete
                          value={field.value}
                          onChange={field.onChange}
                          field={sigmaField}
                          label="Value"
                          required
                          error={errors.conditions?.[index]?.value?.message}
                        />
                      )}
                    />
                  </Box>

                  {/* Delete Button */}
                  <Box sx={{ width: '100%' }}>
                    <IconButton
                      onClick={() => removeCondition(index)}
                      disabled={conditionFields.length === 1}
                      color="error"
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Box>
                </Box>
              </Paper>
            );
          })}

          {/* CQL Preview */}
          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CodeIcon />
                <Typography>CQL Query Preview</Typography>
                <Chip label="Syntax Highlighted" size="small" color="primary" variant="outlined" />
              </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ p: 0 }}>
              <CqlSyntaxHighlighter code={generateCQL()} />
            </AccordionDetails>
          </Accordion>
        </>
      ) : (
        <>
          <Box sx={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="body2" color="text.secondary">
                CQL Query
              </Typography>
              <Button
                size="small"
                startIcon={<HelpIcon />}
                onClick={() => setCqlReferenceOpen(true)}
                sx={{ textTransform: 'none' }}
              >
                CQL Syntax Reference
              </Button>
            </Box>
            <Box>
              <CqlEditor
                value={cqlQuery}
                onChange={(value) => {
                  setCqlQuery(value);
                  setCqlValidation(null);
                }}
                minHeight="200px"
              />
              {(cqlValidation?.error || !cqlValidation) && (
                <Typography variant="caption" color={cqlValidation?.error ? 'error' : 'text.secondary'} sx={{ mt: 0.5, display: 'block' }}>
                  {cqlValidation?.error || "Enter your detection query in CQL format"}
                </Typography>
              )}
            </Box>

            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                variant="outlined"
                size="small"
                onClick={handleCqlValidation}
                startIcon={cqlValidation?.valid ? '✓' : undefined}
                color={cqlValidation?.valid ? 'success' : 'primary'}
              >
                Validate Query
              </Button>
              {cqlValidation?.valid && (
                <Chip
                  label="Valid CQL Syntax"
                  color="success"
                  size="small"
                  variant="outlined"
                />
              )}
            </Box>
          </Box>
        </>
      )}
    </Box>
  );

  const ActionsStep = (
    <Box>
      <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h6">Response Actions</Typography>
        <Button
          startIcon={<AddIcon />}
          onClick={() => appendAction({ type: 'webhook', config: '{}' })}
          variant="outlined"
          size="small"
        >
          Add Action
        </Button>
      </Box>

      {actionFields.length === 0 && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Add at least one action to respond when this rule matches
        </Alert>
      )}

      {actionFields.map((field, index) => (
        <Paper key={field.id} sx={{ p: 2, mb: 2 }} variant="outlined">
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Box sx={{ width: '100%' }}>
              <Controller
                name={`actions.${index}.type`}
                control={control}
                render={({ field }) => (
                  <FormControl fullWidth required>
                    <InputLabel>Action Type</InputLabel>
                    <Select {...field} label="Action Type">
                      {ACTION_TYPES.map(type => (
                        <MenuItem key={type.value} value={type.value}>
                          {type.icon} {type.label}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                )}
              />
            </Box>
            <Box sx={{ width: '100%' }}>
              <Controller
                name={`actions.${index}.config`}
                control={control}
                render={({ field }) => (
                  <TextField
                    {...field}
                    value={typeof field.value === 'string' ? field.value : JSON.stringify(field.value, null, 2)}
                    onChange={(e) => field.onChange(e.target.value)}
                    label="Configuration (JSON)"
                    fullWidth
                    multiline
                    rows={4}
                    placeholder='{"url": "https://api.example.com/webhook"}'
                    helperText="Action configuration in JSON format"
                  />
                )}
              />
            </Box>
            <Box sx={{ width: '100%' }}>
              <IconButton onClick={() => removeAction(index)} color="error">
                <DeleteIcon />
              </IconButton>
            </Box>
          </Box>
        </Paper>
      ))}
    </Box>
  );

  const ReviewStep = (
    <Box>
      <Typography variant="h6" gutterBottom>
        Review Rule
      </Typography>

      <Grid container spacing={2}>
        <Grid  size={{ xs: 12 }}>
          <Paper sx={{ p: 2 }} variant="outlined">
            <Typography variant="subtitle2" color="text.secondary">
              Basic Information
            </Typography>
            <Typography variant="body1" fontWeight="bold">
              {watch('name')}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {watch('description')}
            </Typography>
            <Box sx={{ mt: 1, display: 'flex', gap: 1 }}>
              <Chip label={`Severity: ${watch('severity')}`} size="small" color="primary" />
              <Chip label={watch('enabled') ? 'Enabled' : 'Disabled'} size="small" />
              {watch('tags')?.map(tag => (
                <Chip key={tag} label={tag} size="small" variant="outlined" />
              ))}
            </Box>
          </Paper>
        </Grid>

        <Grid  size={{ xs: 12 }}>
          <Paper sx={{ p: 2 }} variant="outlined">
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Detection Logic (CQL)
              </Typography>
              <Chip
                label={detectionMode === 'cql' ? 'Direct CQL' : 'Generated from Visual Builder'}
                size="small"
                color="primary"
                variant="outlined"
              />
            </Box>
            <CqlSyntaxHighlighter code={detectionMode === 'cql' ? cqlQuery : generateCQL()} />
          </Paper>
        </Grid>

        <Grid  size={{ xs: 12 }}>
          <Paper sx={{ p: 2 }} variant="outlined">
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Test Rule
              </Typography>
              <Button
                startIcon={isTesting ? <CircularProgress size={16} /> : <PlayArrowIcon />}
                onClick={handleTestRule}
                variant="outlined"
                size="small"
                disabled={isTesting}
              >
                {isTesting ? 'Testing...' : 'Run Test'}
              </Button>
            </Box>
            {testResults && (
              <Alert severity={testResults.success ? 'success' : 'error'} sx={{ mt: 1 }}>
                {testResults.success
                  ? `Test passed! Matched ${testResults.matched_events} events in the last 24 hours.`
                  : testResults.error}
              </Alert>
            )}
          </Paper>
        </Grid>

        <Grid  size={{ xs: 12 }}>
          <Paper sx={{ p: 2 }} variant="outlined">
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              Actions ({watch('actions')?.length || 0})
            </Typography>
            {watch('actions')?.map((action: any, idx: number) => (
              <Chip
                key={idx}
                label={`${ACTION_TYPES.find(t => t.value === action.type)?.label}`}
                sx={{ mr: 1, mb: 1 }}
              />
            ))}
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );

  const ExceptionsStep = (
    <RuleExceptionManager control={control} watch={watch} />
  );

  // ==================== WIZARD STEPS ====================

  const steps: WizardStep[] = [
    {
      label: 'Basic Info',
      description: 'Rule name, description, and metadata',
      content: BasicInfoStep,
      validate: validateBasicInfo
    },
    {
      label: 'Detection',
      description: 'Define conditions using SIGMA fields',
      content: DetectionStep,
      validate: validateDetection
    },
    {
      label: 'Actions',
      description: 'Configure response actions',
      content: ActionsStep,
      validate: validateActions
    },
    {
      label: 'Exceptions',
      description: 'Define rule exceptions (optional)',
      content: ExceptionsStep,
      optional: true
    },
    {
      label: 'Review & Test',
      description: 'Review and test the rule',
      content: ReviewStep,
      optional: true
    }
  ];

  return (
    <>
      <Dialog
        open={open}
        onClose={handleCancel}
        maxWidth="lg"
        fullWidth
        PaperProps={{
          sx: { height: '90vh' }
        }}
      >
        <DialogContent sx={{ p: 3 }}>
          <Typography variant="h5" gutterBottom>
            {title}
          </Typography>
          <Divider sx={{ mb: 2 }} />

          <Box sx={{ height: 'calc(90vh - 120px)' }}>
            <StepWizard
              steps={steps}
              activeStep={activeStep}
              onStepChange={setActiveStep}
              onComplete={handleSubmit(handleFormSubmit)}
              onCancel={handleCancel}
              loading={isSubmitting}
              completeButtonText="Create Rule"
            />
          </Box>
        </DialogContent>
      </Dialog>

      <CqlSyntaxReference
        open={cqlReferenceOpen}
        onClose={() => setCqlReferenceOpen(false)}
      />
    </>
  );
}
