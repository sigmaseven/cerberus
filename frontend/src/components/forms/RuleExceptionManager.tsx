/**
 * Rule Exception Manager Component
 *
 * Manages inline exceptions for a detection rule within the rule builder modal.
 * Allows adding, editing, and removing exceptions that can suppress or modify alerts.
 */

import React, { useState } from 'react';
import { useFieldArray, Controller, Control, UseFormWatch } from 'react-hook-form';
import {
  Box,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  Chip,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  RadioGroup,
  FormControlLabel,
  Radio,
  FormLabel,
  Grid,
  Autocomplete,
  Tooltip,
  Stack
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  Info as InfoIcon,
  Block as BlockIcon,
  Edit as EditIcon
} from '@mui/icons-material';
import { ExceptionType, ConditionType } from '../../types';
import { CqlSyntaxHighlighter } from '../CqlSyntaxHighlighter';

interface ExceptionFormData {
  name: string;
  description: string;
  type: ExceptionType;
  condition_type: ConditionType;
  condition: string;
  new_severity?: string;
  enabled: boolean;
  priority: number;
  expires_at?: string;
  justification: string;
  tags: string[];
}

interface RuleExceptionManagerProps {
  control: Control<any>;
  watch: UseFormWatch<any>;
}

const SEVERITY_OPTIONS = [
  { value: 'critical', label: '🔴 Critical' },
  { value: 'high', label: '🟠 High' },
  { value: 'medium', label: '🟡 Medium' },
  { value: 'low', label: '🟢 Low' },
  { value: 'info', label: 'ℹ️ Info' }
];

const COMMON_EXCEPTION_TAGS = [
  'false-positive',
  'known-issue',
  'maintenance',
  'testing',
  'approved',
  'temporary'
];

export function RuleExceptionManager({ control, watch }: RuleExceptionManagerProps) {
  const [expandedIndex, setExpandedIndex] = useState<number | false>(false);

  const {
    fields: exceptionFields,
    append: appendException,
    remove: removeException
  } = useFieldArray({
    control,
    name: 'exceptions'
  });

  const handleAddException = () => {
    const newException: ExceptionFormData = {
      name: '',
      description: '',
      type: 'suppress',
      condition_type: 'cql',
      condition: '',
      enabled: true,
      priority: 100,
      justification: '',
      tags: []
    };
    appendException(newException);
    setExpandedIndex(exceptionFields.length); // Expand the newly added exception
  };

  const getExceptionTypeIcon = (type: ExceptionType) => {
    return type === 'suppress' ? <BlockIcon /> : <EditIcon />;
  };

  const getExceptionTypeColor = (type: ExceptionType): 'error' | 'warning' => {
    return type === 'suppress' ? 'error' : 'warning';
  };

  return (
    <Box>
      {/* Header with info */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <Typography variant="h6">Rule Exceptions</Typography>
          <Tooltip title="Exceptions allow you to suppress or modify alerts that match specific conditions. Use them to handle false positives or adjust severity for known scenarios.">
            <InfoIcon color="action" fontSize="small" />
          </Tooltip>
        </Box>
        <Typography variant="body2" color="text.secondary">
          Define conditions where this rule should not trigger alerts (suppress) or should trigger with a different severity (modify).
        </Typography>
      </Box>

      {/* Exception list */}
      {exceptionFields.length === 0 ? (
        <Alert severity="info" sx={{ mb: 2 }}>
          No exceptions defined. Exceptions are optional but can help reduce false positives.
        </Alert>
      ) : (
        <Box sx={{ mb: 2 }}>
          {exceptionFields.map((field, index) => {
            const exceptionData = watch(`exceptions.${index}`);
            const isExpanded = expandedIndex === index;

            return (
              <Accordion
                key={field.id}
                expanded={isExpanded}
                onChange={() => setExpandedIndex(isExpanded ? false : index)}
                sx={{ mb: 1 }}
              >
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                    {getExceptionTypeIcon(exceptionData?.type || 'suppress')}
                    <Typography sx={{ flexGrow: 1 }}>
                      {exceptionData?.name || `Exception ${index + 1}`}
                    </Typography>
                    <Chip
                      label={exceptionData?.type === 'suppress' ? 'Suppress' : 'Modify Severity'}
                      color={getExceptionTypeColor(exceptionData?.type || 'suppress')}
                      size="small"
                    />
                    {!exceptionData?.enabled && (
                      <Chip label="Disabled" size="small" variant="outlined" />
                    )}
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Stack spacing={2}>
                    {/* Name */}
                    <Controller
                      name={`exceptions.${index}.name`}
                      control={control}
                      rules={{ required: 'Exception name is required' }}
                      render={({ field, fieldState: { error } }) => (
                        <TextField
                          {...field}
                          label="Exception Name"
                          required
                          fullWidth
                          error={!!error}
                          helperText={error?.message}
                          placeholder="e.g., Exclude maintenance windows"
                        />
                      )}
                    />

                    {/* Description */}
                    <Controller
                      name={`exceptions.${index}.description`}
                      control={control}
                      rules={{ required: 'Description is required' }}
                      render={({ field, fieldState: { error } }) => (
                        <TextField
                          {...field}
                          label="Description"
                          required
                          fullWidth
                          multiline
                          rows={2}
                          error={!!error}
                          helperText={error?.message}
                          placeholder="Describe what this exception does and why it's needed"
                        />
                      )}
                    />

                    {/* Exception Type */}
                    <FormControl component="fieldset">
                      <FormLabel component="legend">Exception Type</FormLabel>
                      <Controller
                        name={`exceptions.${index}.type`}
                        control={control}
                        render={({ field }) => (
                          <RadioGroup {...field} row>
                            <FormControlLabel
                              value="suppress"
                              control={<Radio />}
                              label="Suppress (Don't create alert)"
                            />
                            <FormControlLabel
                              value="modify_severity"
                              control={<Radio />}
                              label="Modify Severity"
                            />
                          </RadioGroup>
                        )}
                      />
                    </FormControl>

                    {/* New Severity (shown only for modify_severity type) */}
                    {exceptionData?.type === 'modify_severity' && (
                      <Controller
                        name={`exceptions.${index}.new_severity`}
                        control={control}
                        rules={{ required: 'Severity is required for modify type' }}
                        render={({ field, fieldState: { error } }) => (
                          <FormControl fullWidth required error={!!error}>
                            <InputLabel>New Severity</InputLabel>
                            <Select {...field} label="New Severity">
                              {SEVERITY_OPTIONS.map((opt) => (
                                <MenuItem key={opt.value} value={opt.value}>
                                  {opt.label}
                                </MenuItem>
                              ))}
                            </Select>
                            {error && <Typography variant="caption" color="error">{error.message}</Typography>}
                          </FormControl>
                        )}
                      />
                    )}

                    {/* Condition Type */}
                    <FormControl component="fieldset">
                      <FormLabel component="legend">Condition Type</FormLabel>
                      <Controller
                        name={`exceptions.${index}.condition_type`}
                        control={control}
                        render={({ field }) => (
                          <RadioGroup {...field} row>
                            <FormControlLabel
                              value="cql"
                              control={<Radio />}
                              label="CQL Query"
                            />
                            <FormControlLabel
                              value="sigma_filter"
                              control={<Radio />}
                              label="SIGMA Filter"
                            />
                          </RadioGroup>
                        )}
                      />
                    </FormControl>

                    {/* Condition */}
                    <Box>
                      <Controller
                        name={`exceptions.${index}.condition`}
                        control={control}
                        rules={{ required: 'Condition is required' }}
                        render={({ field, fieldState: { error } }) => (
                          <>
                            <TextField
                              {...field}
                              label={`${exceptionData?.condition_type === 'cql' ? 'CQL' : 'SIGMA'} Condition`}
                              required
                              fullWidth
                              multiline
                              rows={4}
                              error={!!error}
                              helperText={error?.message || `Enter the ${exceptionData?.condition_type === 'cql' ? 'CQL query' : 'SIGMA filter'} that defines when this exception applies`}
                              placeholder={exceptionData?.condition_type === 'cql'
                                ? 'event.user.name = "admin" AND event.action = "login"'
                                : 'user: admin\naction: login'}
                              sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}
                            />
                            {field.value && exceptionData?.condition_type === 'cql' && (
                              <Box sx={{ mt: 1 }}>
                                <Typography variant="caption" color="text.secondary" gutterBottom>
                                  Preview:
                                </Typography>
                                <CqlSyntaxHighlighter query={field.value} />
                              </Box>
                            )}
                          </>
                        )}
                      />
                    </Box>

                    <Grid container spacing={2}>
                      {/* Priority */}
                      <Grid  size={{ xs: 12, sm: 6 }}>
                        <Controller
                          name={`exceptions.${index}.priority`}
                          control={control}
                          render={({ field }) => (
                            <TextField
                              {...field}
                              type="number"
                              label="Priority"
                              fullWidth
                              helperText="Lower number = higher priority"
                              InputProps={{ inputProps: { min: 1, max: 1000 } }}
                            />
                          )}
                        />
                      </Grid>

                      {/* Expires At */}
                      <Grid  size={{ xs: 12, sm: 6 }}>
                        <Controller
                          name={`exceptions.${index}.expires_at`}
                          control={control}
                          render={({ field }) => (
                            <TextField
                              {...field}
                              type="datetime-local"
                              label="Expires At (Optional)"
                              fullWidth
                              InputLabelProps={{ shrink: true }}
                              helperText="Leave empty for permanent exception"
                            />
                          )}
                        />
                      </Grid>
                    </Grid>

                    {/* Justification */}
                    <Controller
                      name={`exceptions.${index}.justification`}
                      control={control}
                      render={({ field }) => (
                        <TextField
                          {...field}
                          label="Justification"
                          fullWidth
                          multiline
                          rows={2}
                          placeholder="Document why this exception is needed (optional but recommended)"
                        />
                      )}
                    />

                    {/* Tags */}
                    <Controller
                      name={`exceptions.${index}.tags`}
                      control={control}
                      render={({ field }) => (
                        <Autocomplete
                          {...field}
                          multiple
                          freeSolo
                          options={COMMON_EXCEPTION_TAGS}
                          value={field.value || []}
                          onChange={(_, newValue) => field.onChange(newValue)}
                          renderTags={(value, getTagProps) =>
                            value.map((option, index) => (
                              <Chip label={option} {...getTagProps({ index })} size="small" key={index} />
                            ))
                          }
                          renderInput={(params) => (
                            <TextField
                              {...params}
                              label="Tags"
                              placeholder="Add tags..."
                              helperText="Press Enter to add custom tags"
                            />
                          )}
                        />
                      )}
                    />

                    {/* Enabled toggle */}
                    <FormControlLabel
                      control={
                        <Controller
                          name={`exceptions.${index}.enabled`}
                          control={control}
                          render={({ field }) => (
                            <input
                              type="checkbox"
                              checked={field.value}
                              onChange={field.onChange}
                            />
                          )}
                        />
                      }
                      label="Exception Enabled"
                    />

                    {/* Actions */}
                    <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
                      <Button
                        variant="outlined"
                        color="error"
                        startIcon={<DeleteIcon />}
                        onClick={() => removeException(index)}
                      >
                        Remove Exception
                      </Button>
                    </Box>
                  </Stack>
                </AccordionDetails>
              </Accordion>
            );
          })}
        </Box>
      )}

      {/* Add exception button */}
      <Button
        variant="outlined"
        startIcon={<AddIcon />}
        onClick={handleAddException}
        fullWidth
      >
        Add Exception
      </Button>
    </Box>
  );
}
