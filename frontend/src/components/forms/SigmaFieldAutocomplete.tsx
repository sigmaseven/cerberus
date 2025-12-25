/**
 * SIGMA Field Autocomplete Component
 *
 * Intelligent autocomplete for SIGMA standard fields with:
 * - Grouping by category
 * - Rich tooltips with descriptions and examples
 * - Filtering by log source
 * - Common values suggestions
 */

import React from 'react';
import {
  Autocomplete,
  TextField,
  Box,
  Typography,
  Chip,
  Tooltip,
  Paper
} from '@mui/material';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import {
  SigmaField,
  SigmaLogSource,
  getFieldsForLogSource,
  getCategoryDisplayName,
  SIGMA_FIELDS
} from '../../services/sigmaFields';

export interface SigmaFieldAutocompleteProps {
  /** Current field value */
  value: string;

  /** Change handler */
  onChange: (fieldName: string) => void;

  /** Log source for filtering fields */
  logSource?: SigmaLogSource;

  /** Error message */
  error?: string;

  /** Helper text */
  helperText?: string;

  /** Label */
  label?: string;

  /** Required field */
  required?: boolean;

  /** Disabled state */
  disabled?: boolean;

  /** Show all fields regardless of log source */
  showAllFields?: boolean;
}

export function SigmaFieldAutocomplete({
  value,
  onChange,
  logSource = 'windows_sysmon',
  error,
  helperText,
  label = 'Field',
  required = false,
  disabled = false,
  showAllFields = false
}: SigmaFieldAutocompleteProps) {
  // Get fields based on log source (or all fields)
  const fields = showAllFields
    ? SIGMA_FIELDS
    : getFieldsForLogSource(logSource);

  // Find current field object
  const currentField = fields.find(f => f.name === value) || null;

  return (
    <Autocomplete
      value={currentField}
      onChange={(_, newValue) => onChange(newValue?.name || '')}
      options={fields}
      groupBy={(option) => getCategoryDisplayName(option.category)}
      getOptionLabel={(option) => option.name}
      isOptionEqualToValue={(option, value) => option.name === value.name}
      disabled={disabled}
      renderInput={(params) => (
        <TextField
          {...params}
          label={label}
          required={required}
          error={!!error}
          helperText={error || helperText}
          placeholder="Select or type field name..."
        />
      )}
      renderOption={(props, option) => (
        <Box component="li" {...props} sx={{ display: 'block !important', py: 1.5 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
            <Typography
              variant="body2"
              fontWeight="bold"
              sx={{ fontFamily: 'monospace', fontSize: '0.9rem' }}
            >
              {option.name}
            </Typography>
            <Chip
              label={option.dataType}
              size="small"
              sx={{
                height: 20,
                fontSize: '0.7rem',
                bgcolor: getDataTypeColor(option.dataType),
                color: 'white'
              }}
            />
          </Box>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ display: 'block', mb: 0.5 }}
          >
            {option.description}
          </Typography>
          <Typography
            variant="caption"
            sx={{
              display: 'block',
              fontFamily: 'monospace',
              fontSize: '0.75rem',
              color: 'primary.main',
              bgcolor: 'action.hover',
              px: 1,
              py: 0.5,
              borderRadius: 0.5
            }}
          >
            {option.example}
          </Typography>
          {option.commonValues && option.commonValues.length > 0 && (
            <Box sx={{ mt: 0.5, display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
              {option.commonValues.slice(0, 3).map((val, idx) => (
                <Chip
                  key={idx}
                  label={val}
                  size="small"
                  variant="outlined"
                  sx={{ height: 18, fontSize: '0.65rem' }}
                />
              ))}
            </Box>
          )}
        </Box>
      )}
      renderGroup={(params) => (
        <li key={params.key}>
          <Box
            sx={{
              position: 'sticky',
              top: -8,
              py: 1,
              px: 2,
              bgcolor: 'background.paper',
              borderBottom: 1,
              borderColor: 'divider',
              zIndex: 1
            }}
          >
            <Typography variant="subtitle2" fontWeight="bold" color="primary">
              {params.group}
            </Typography>
          </Box>
          <ul style={{ padding: 0 }}>{params.children}</ul>
        </li>
      )}
      PaperComponent={({ children, ...other }) => (
        <Paper
          {...other}
          sx={{
            maxHeight: 500,
            '& .MuiAutocomplete-listbox': {
              maxHeight: 450,
              '& .MuiAutocomplete-option': {
                alignItems: 'flex-start'
              }
            }
          }}
        >
          {children}
        </Paper>
      )}
      slotProps={{
        popper: {
          placement: 'bottom-start',
          modifiers: [
            {
              name: 'flip',
              enabled: false
            }
          ]
        }
      }}
    />
  );
}

/**
 * SIGMA Field with Value Autocomplete
 * Provides autocomplete for field values based on common values
 */
export interface SigmaFieldValueAutocompleteProps {
  /** Current value */
  value: string;

  /** Change handler */
  onChange: (value: string) => void;

  /** SIGMA field for context */
  field?: SigmaField;

  /** Error message */
  error?: string;

  /** Helper text */
  helperText?: string;

  /** Label */
  label?: string;

  /** Required field */
  required?: boolean;

  /** Disabled state */
  disabled?: boolean;
}

export function SigmaFieldValueAutocomplete({
  value,
  onChange,
  field,
  error,
  helperText,
  label = 'Value',
  required = false,
  disabled = false
}: SigmaFieldValueAutocompleteProps) {
  const commonValues = field?.commonValues || [];
  const hasCommonValues = commonValues.length > 0;

  return (
    <Autocomplete
      freeSolo
      value={value}
      onChange={(_, newValue) => onChange(newValue || '')}
      onInputChange={(_, newInputValue) => onChange(newInputValue)}
      options={commonValues}
      disabled={disabled}
      renderInput={(params) => (
        <TextField
          {...params}
          label={label}
          required={required}
          error={!!error}
          helperText={error || helperText}
          placeholder={
            hasCommonValues
              ? 'Select common value or type custom...'
              : 'Enter value...'
          }
          InputProps={{
            ...params.InputProps,
            endAdornment: (
              <>
                {params.InputProps.endAdornment}
                {field && (
                  <Tooltip
                    title={
                      <Box>
                        <Typography variant="caption" fontWeight="bold">
                          {field.name}
                        </Typography>
                        <Typography variant="caption" display="block">
                          {field.description}
                        </Typography>
                        <Typography
                          variant="caption"
                          display="block"
                          sx={{ mt: 0.5, fontFamily: 'monospace' }}
                        >
                          {field.example}
                        </Typography>
                      </Box>
                    }
                  >
                    <InfoOutlinedIcon
                      sx={{ fontSize: 18, color: 'action.active', mr: 1 }}
                    />
                  </Tooltip>
                )}
              </>
            )
          }}
        />
      )}
      renderOption={(props, option) => (
        <Box component="li" {...props}>
          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
            {option}
          </Typography>
        </Box>
      )}
    />
  );
}

/**
 * Get color for data type badge
 */
function getDataTypeColor(dataType: string): string {
  const colors: Record<string, string> = {
    string: '#2196f3',
    number: '#4caf50',
    boolean: '#ff9800',
    array: '#9c27b0',
    timestamp: '#f44336'
  };
  return colors[dataType] || '#757575';
}
