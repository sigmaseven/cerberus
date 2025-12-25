import { useState } from 'react';
import {
  Box,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Typography,
  Stack,
  SelectChangeEvent,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  FilterList as FilterListIcon,
  Clear as ClearIcon,
} from '@mui/icons-material';

export interface RuleFilters {
  search?: string;
  severity?: string[];
  enabled?: boolean | null;
  type?: string[];
  author?: string[];
  tag?: string[];
  tactic?: string[];
  technique?: string[];
}

interface RuleFilterPanelProps {
  filters: RuleFilters;
  onFiltersChange: (filters: RuleFilters) => void;
  onApply: () => void;
  onClear: () => void;
}

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const ENABLED_OPTIONS = [
  { value: 'all', label: 'All Rules' },
  { value: 'true', label: 'Enabled Only' },
  { value: 'false', label: 'Disabled Only' },
];

// Common MITRE ATT&CK Tactics
const MITRE_TACTICS = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

export function RuleFilterPanel({ filters, onFiltersChange, onApply, onClear }: RuleFilterPanelProps) {
  const [expanded, setExpanded] = useState(true);

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    onFiltersChange({ ...filters, search: event.target.value });
  };

  const handleSeverityChange = (event: SelectChangeEvent<string[]>) => {
    const value = event.target.value;
    onFiltersChange({
      ...filters,
      severity: typeof value === 'string' ? value.split(',') : value,
    });
  };

  const handleEnabledChange = (event: SelectChangeEvent<string>) => {
    const value = event.target.value;
    let enabled: boolean | null = null;
    if (value === 'true') enabled = true;
    else if (value === 'false') enabled = false;
    onFiltersChange({ ...filters, enabled });
  };

  const handleTacticChange = (event: SelectChangeEvent<string[]>) => {
    const value = event.target.value;
    onFiltersChange({
      ...filters,
      tactic: typeof value === 'string' ? value.split(',') : value,
    });
  };

  const getEnabledValue = (): string => {
    if (filters.enabled === true) return 'true';
    if (filters.enabled === false) return 'false';
    return 'all';
  };

  const hasActiveFilters = (): boolean => {
    return !!(
      filters.search ||
      (filters.severity && filters.severity.length > 0) ||
      filters.enabled !== undefined ||
      (filters.tactic && filters.tactic.length > 0)
    );
  };

  return (
    <Accordion expanded={expanded} onChange={() => setExpanded(!expanded)}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
          <FilterListIcon />
          <Typography variant="h6">Filters</Typography>
          {hasActiveFilters() && (
            <Chip
              label={`${Object.values(filters).filter((v) => v !== null && v !== undefined && (Array.isArray(v) ? v.length > 0 : true)).length} active`}
              size="small"
              color="primary"
            />
          )}
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        <Stack spacing={2}>
          {/* Search */}
          <TextField
            label="Search Rules"
            placeholder="Search by name, description, or tags..."
            value={filters.search || ''}
            onChange={handleSearchChange}
            fullWidth
            size="small"
          />

          {/* Severity Filter */}
          <FormControl fullWidth size="small">
            <InputLabel>Severity</InputLabel>
            <Select
              multiple
              value={filters.severity || []}
              onChange={handleSeverityChange}
              label="Severity"
              renderValue={(selected) => (
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {selected.map((value) => (
                    <Chip key={value} label={value} size="small" />
                  ))}
                </Box>
              )}
            >
              {SEVERITIES.map((severity) => (
                <MenuItem key={severity} value={severity.toLowerCase()}>
                  {severity}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Enabled Status Filter */}
          <FormControl fullWidth size="small">
            <InputLabel>Status</InputLabel>
            <Select value={getEnabledValue()} onChange={handleEnabledChange} label="Status">
              {ENABLED_OPTIONS.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* MITRE ATT&CK Tactics Filter */}
          <FormControl fullWidth size="small">
            <InputLabel>MITRE ATT&CK Tactics</InputLabel>
            <Select
              multiple
              value={filters.tactic || []}
              onChange={handleTacticChange}
              label="MITRE ATT&CK Tactics"
              renderValue={(selected) => (
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {selected.map((value) => (
                    <Chip
                      key={value}
                      label={value.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                      size="small"
                    />
                  ))}
                </Box>
              )}
            >
              {MITRE_TACTICS.map((tactic) => (
                <MenuItem key={tactic} value={tactic}>
                  {tactic.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Action Buttons */}
          <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
            <Button
              variant="outlined"
              startIcon={<ClearIcon />}
              onClick={onClear}
              disabled={!hasActiveFilters()}
            >
              Clear Filters
            </Button>
            <Button variant="contained" startIcon={<FilterListIcon />} onClick={onApply}>
              Apply Filters
            </Button>
          </Box>
        </Stack>
      </AccordionDetails>
    </Accordion>
  );
}
