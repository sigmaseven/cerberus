import React, { useState } from 'react';
import { getSeverityColor } from '../../utils/severity';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  Box,
  Chip,
  Typography,
  Stack,
  Divider,
  Switch,
  ToggleButtonGroup,
  ToggleButton} from '@mui/material';
import {
  Close as CloseIcon,
  ViewList as ViewListIcon,
  Code as CodeIcon,
  DataObject as DataObjectIcon} from '@mui/icons-material';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus, vs } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { CqlSyntaxHighlighter } from '../CqlSyntaxHighlighter';
import { Rule, Condition } from '../../types';

interface RuleDetailModalProps {
  open: boolean;
  rule: Rule | null;
  onClose: () => void;
}

type ViewMode = 'simple' | 'json' | 'cql';

/**
 * Convert conditions array to CQL query string
 */
function conditionsToCql(conditions: Condition[]): string {
  if (!conditions || conditions.length === 0) {
    return 'No conditions';
  }

  const parts: string[] = [];

  for (let i = 0; i < conditions.length; i++) {
    const condition = conditions[i];
    let part = '';

    // Format the value
    let formattedValue = String(condition.value);
    if (typeof condition.value === 'string' && !condition.value.match(/^\d+$/)) {
      // Quote string values
      formattedValue = `"${condition.value}"`;
    }

    // Build the condition
    switch (condition.operator.toLowerCase()) {
      case 'equals':
      case '=':
      case '==':
        part = `${condition.field} = ${formattedValue}`;
        break;
      case 'contains':
        part = `${condition.field} contains ${formattedValue}`;
        break;
      case 'startswith':
        part = `${condition.field} startswith ${formattedValue}`;
        break;
      case 'endswith':
        part = `${condition.field} endswith ${formattedValue}`;
        break;
      case 'matches':
      case 'regex':
        part = `${condition.field} matches ${formattedValue}`;
        break;
      case 'in':
        part = `${condition.field} in ${formattedValue}`;
        break;
      case 'not in':
        part = `${condition.field} not in ${formattedValue}`;
        break;
      case '>':
        part = `${condition.field} > ${formattedValue}`;
        break;
      case '>=':
        part = `${condition.field} >= ${formattedValue}`;
        break;
      case '<':
        part = `${condition.field} < ${formattedValue}`;
        break;
      case '<=':
        part = `${condition.field} <= ${formattedValue}`;
        break;
      case '!=':
      case 'not equals':
        part = `${condition.field} != ${formattedValue}`;
        break;
      default:
        part = `${condition.field} ${condition.operator} ${formattedValue}`;
    }

    parts.push(part);

    // Add logical operator if not the last condition
    if (i < conditions.length - 1 && condition.logic) {
      parts.push(condition.logic);
    }
  }

  return parts.join(' ');
}

/**
 * Convert Sigma-style condition object to formatted JSON
 */
function formatConditionsAsJson(rule: any): string {
  // Check if rule has Sigma-style conditions
  if (rule.condition || rule.selection || rule.detection) {
    const sigmaConditions: any = {};

    if (rule.condition) {
      sigmaConditions.condition = rule.condition;
    }

    // Add all selection/filter keys
    Object.keys(rule).forEach((key) => {
      if (key !== 'id' && key !== 'name' && key !== 'description' &&
          key !== 'severity' && key !== 'enabled' && key !== 'actions' &&
          key !== 'version' && key !== 'conditions' && key !== 'query') {
        sigmaConditions[key] = rule[key];
      }
    });

    if (Object.keys(sigmaConditions).length > 0) {
      return JSON.stringify(sigmaConditions, null, 2);
    }
  }

  // Fallback to standard conditions
  if (rule.conditions && rule.conditions.length > 0) {
    return JSON.stringify(rule.conditions, null, 2);
  }

  return '[]';
}

const RuleDetailModal: React.FC<RuleDetailModalProps> = ({ open, rule, onClose }) => {
  const [viewMode, setViewMode] = useState<ViewMode>('simple');
  const [isDarkMode, setIsDarkMode] = useState(false);

  // Detect theme mode
  React.useEffect(() => {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    setIsDarkMode(prefersDark);
  }, []);

  if (!rule) return null;

  const handleViewModeChange = (
    event: React.MouseEvent<HTMLElement>,
    newMode: ViewMode | null,
  ) => {
    if (newMode !== null) {
      setViewMode(newMode);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      PaperProps={{
        sx: {
          maxHeight: '90vh'}}}
    >
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Typography variant="h6">Rule Details</Typography>
          <IconButton onClick={onClose} size="small">
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>

      <DialogContent dividers sx={{ p: 3 }}>
        {/* Rule Header - matching Rules page table style */}
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
            <Typography variant="body2" sx={{ fontWeight: 500, minWidth: 120 }}>
              {rule.name}
            </Typography>
            <Chip
              label={rule.severity}
              color={getSeverityColor(rule.severity) as any}
              size="small"
            />
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="body2" color="textSecondary">
                Enabled:
              </Typography>
              <Switch
                checked={rule.enabled}
                size="small"
                disabled
              />
            </Box>
          </Box>
        </Box>

        <Divider sx={{ mb: 3 }} />

        {/* Description */}
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            Description
          </Typography>
          <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
            {rule.description}
          </Typography>
        </Box>

        <Divider sx={{ mb: 3 }} />

        {/* Metadata */}
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            Metadata
          </Typography>
          <Stack direction="row" spacing={2} sx={{ mt: 1 }}>
            <Box>
              <Typography variant="caption" color="text.secondary">
                Rule ID
              </Typography>
              <Typography variant="body2" fontFamily="monospace">
                {rule.id}
              </Typography>
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">
                Version
              </Typography>
              <Typography variant="body2">
                {rule.version}
              </Typography>
            </Box>
          </Stack>
        </Box>

        <Divider sx={{ mb: 3 }} />

        {/* Conditions */}
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="subtitle2" color="text.secondary">
              Detection Conditions
            </Typography>
            {(rule.conditions && rule.conditions.length > 0) || (rule as any).query ? (
              <ToggleButtonGroup
                value={viewMode}
                exclusive
                onChange={handleViewModeChange}
                size="small"
                aria-label="condition view mode"
              >
                <ToggleButton value="simple" aria-label="simple view">
                  <ViewListIcon fontSize="small" sx={{ mr: 0.5 }} />
                  Simple
                </ToggleButton>
                <ToggleButton value="json" aria-label="json view">
                  <DataObjectIcon fontSize="small" sx={{ mr: 0.5 }} />
                  JSON
                </ToggleButton>
                {rule.conditions && rule.conditions.length > 0 && (
                  <ToggleButton value="cql" aria-label="cql view">
                    <CodeIcon fontSize="small" sx={{ mr: 0.5 }} />
                    CQL
                  </ToggleButton>
                )}
              </ToggleButtonGroup>
            ) : null}
          </Box>

          {rule.conditions && rule.conditions.length > 0 ? (
            <Box sx={{ mt: 1 }}>
              <Chip
                label={`${rule.conditions.length} condition${rule.conditions.length !== 1 ? 's' : ''}`}
                size="small"
                variant="outlined"
                sx={{ mb: 2 }}
              />

              {/* Simple View */}
              {viewMode === 'simple' && (
                <Stack spacing={1.5}>
                  {rule.conditions.map((condition, idx) => (
                    <Paper key={idx} variant="outlined" sx={{ p: 2 }}>
                      <Stack spacing={0.5}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="caption" color="text.secondary" sx={{ minWidth: 60 }}>
                            Field:
                          </Typography>
                          <Typography variant="body2" fontFamily="monospace">
                            {condition.field}
                          </Typography>
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="caption" color="text.secondary" sx={{ minWidth: 60 }}>
                            Operator:
                          </Typography>
                          <Chip label={condition.operator} size="small" variant="outlined" />
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="caption" color="text.secondary" sx={{ minWidth: 60 }}>
                            Value:
                          </Typography>
                          <Typography variant="body2" fontFamily="monospace">
                            {typeof condition.value === 'object'
                              ? JSON.stringify(condition.value)
                              : String(condition.value)}
                          </Typography>
                        </Box>
                        {condition.logic && idx < rule.conditions.length - 1 && (
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                            <Chip label={condition.logic} size="small" color="primary" />
                          </Box>
                        )}
                      </Stack>
                    </Paper>
                  ))}
                </Stack>
              )}

              {/* JSON View */}
              {viewMode === 'json' && (
                <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
                  <SyntaxHighlighter
                    language="json"
                    style={isDarkMode ? vscDarkPlus : vs}
                    customStyle={{
                      margin: 0,
                      borderRadius: 0,
                      fontSize: '0.875rem'}}
                  >
                    {formatConditionsAsJson(rule)}
                  </SyntaxHighlighter>
                </Paper>
              )}

              {/* CQL View */}
              {viewMode === 'cql' && (
                <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
                  <CqlSyntaxHighlighter code={conditionsToCql(rule.conditions)} />
                </Paper>
              )}
            </Box>
          ) : (rule as any).query ? (
            <Box sx={{ mt: 1 }}>
              <Chip
                label="CQL Query"
                size="small"
                variant="outlined"
                color="primary"
                sx={{ mb: 2 }}
              />

              {/* Simple/CQL View - same for native CQL queries */}
              {(viewMode === 'simple' || viewMode === 'cql') && (
                <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
                  <CqlSyntaxHighlighter code={(rule as any).query} />
                </Paper>
              )}

              {/* JSON View */}
              {viewMode === 'json' && (
                <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
                  <SyntaxHighlighter
                    language="json"
                    style={isDarkMode ? vscDarkPlus : vs}
                    customStyle={{
                      margin: 0,
                      borderRadius: 0,
                      fontSize: '0.875rem'}}
                  >
                    {formatConditionsAsJson(rule)}
                  </SyntaxHighlighter>
                </Paper>
              )}
            </Box>
          ) : (
            <Chip
              label="0 conditions"
              size="small"
              variant="outlined"
              sx={{ mt: 1 }}
            />
          )}
        </Box>

        <Divider sx={{ mb: 3 }} />

        {/* Actions */}
        <Box>
          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            Actions
          </Typography>
          {rule.actions && rule.actions.length > 0 ? (
            <Stack spacing={1} mt={1}>
              {rule.actions.map((action, idx) => (
                <Paper key={idx} variant="outlined" sx={{ p: 2 }}>
                  <Stack direction="row" spacing={2} alignItems="center">
                    <Chip label={action.type} color="primary" size="small" />
                    <Box>
                      <Typography variant="body2">
                        {action.name || `Action ${idx + 1}`}
                      </Typography>
                      {action.config && (
                        <Typography variant="caption" color="text.secondary">
                          Config: {Object.keys(action.config).length} parameter(s)
                        </Typography>
                      )}
                    </Box>
                  </Stack>
                </Paper>
              ))}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              No actions configured
            </Typography>
          )}
        </Box>
      </DialogContent>
    </Dialog>
  );
};

export default RuleDetailModal;
