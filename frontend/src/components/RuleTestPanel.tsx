/**
 * RuleTestPanel.tsx (TASK 174.4)
 * Panel component for testing rules against sample events before deployment
 *
 * Features:
 * - Event input via JSON array textarea with 1MB size limit
 * - File upload with 1MB max size validation
 * - Real-time JSON syntax validation
 * - Test execution with loading states
 * - Results visualization with match details
 * - Evaluation time display
 * - Correlation state display for correlation rules
 * - Clear/reset functionality
 *
 * Accessibility:
 * - Full keyboard navigation support
 * - ARIA labels and roles
 * - Screen reader announcements
 * - Focus management
 *
 * Security:
 * - 1MB size limit prevents DoS attacks
 * - Safe JSON parsing with try-catch
 * - Proper error handling
 */

import { useState, useCallback, useRef, useMemo } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Typography,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemText,
  Paper,
  CircularProgress,
  Stack,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  ExpandMore as ExpandMoreIcon,
  Upload as UploadIcon,
  Clear as ClearIcon,
  Close as CloseIcon,
  Speed as SpeedIcon,
  Event as EventIcon,
} from '@mui/icons-material';
import { JsonEditor } from './JsonEditor';
import api from '../services/api';
import { RuleTestResult, RuleTestRequest } from '../types';

// =============================================================================
// Constants
// =============================================================================

/** Maximum JSON size: 1MB (prevents DoS attacks) */
const MAX_JSON_SIZE_BYTES = 1024 * 1024; // 1MB

// =============================================================================
// Types & Interfaces
// =============================================================================

export interface RuleTestPanelProps {
  /** Rule ID to test */
  ruleId: string;
  /** Optional callback when panel is closed */
  onClose?: () => void;
}

interface TestResultWithTiming extends RuleTestResult {
  evaluationTimeMs?: number;
  correlationState?: Record<string, unknown>;
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Calculate byte size of a string (UTF-8 encoded)
 */
const getByteSize = (str: string): number => {
  return new Blob([str]).size;
};

/**
 * Format bytes to human-readable format
 */
const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${Math.round((bytes / Math.pow(k, i)) * 100) / 100} ${sizes[i]}`;
};

/**
 * Validate JSON events array with size limit
 */
const validateEventsJSON = (jsonString: string): { valid: boolean; error?: string; events?: Record<string, unknown>[] } => {
  if (!jsonString.trim()) {
    return { valid: false, error: 'Events JSON cannot be empty' };
  }

  // Check size limit (DoS prevention)
  const sizeBytes = getByteSize(jsonString);
  if (sizeBytes > MAX_JSON_SIZE_BYTES) {
    return {
      valid: false,
      error: `JSON size (${formatBytes(sizeBytes)}) exceeds maximum allowed size (${formatBytes(MAX_JSON_SIZE_BYTES)})`
    };
  }

  try {
    const parsed = JSON.parse(jsonString);

    if (!Array.isArray(parsed)) {
      return { valid: false, error: 'Events must be a JSON array' };
    }

    if (parsed.length === 0) {
      return { valid: false, error: 'Events array cannot be empty' };
    }

    if (parsed.some(item => typeof item !== 'object' || item === null)) {
      return { valid: false, error: 'All events must be JSON objects' };
    }

    return { valid: true, events: parsed as Record<string, unknown>[] };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? `Invalid JSON: ${error.message}` : 'Invalid JSON format'
    };
  }
};

/**
 * Get evaluation time color based on performance thresholds
 */
const getEvaluationTimeColor = (timeMs: number): 'success' | 'warning' | 'error' => {
  if (timeMs < 10) return 'success';
  if (timeMs < 100) return 'warning';
  return 'error';
};

/**
 * Format number with commas for readability
 */
const formatNumber = (num: number): string => {
  return new Intl.NumberFormat().format(num);
};

/**
 * Announce message to screen readers
 */
const announceToScreenReader = (message: string): void => {
  const announcement = document.createElement('div');
  announcement.setAttribute('role', 'status');
  announcement.setAttribute('aria-live', 'polite');
  announcement.className = 'sr-only';
  announcement.style.position = 'absolute';
  announcement.style.left = '-10000px';
  announcement.style.width = '1px';
  announcement.style.height = '1px';
  announcement.style.overflow = 'hidden';
  announcement.textContent = message;
  document.body.appendChild(announcement);
  setTimeout(() => {
    if (announcement.parentNode) {
      document.body.removeChild(announcement);
    }
  }, 1000);
};

// =============================================================================
// Main Component
// =============================================================================

export function RuleTestPanel({ ruleId, onClose }: RuleTestPanelProps) {
  // State Management
  const [eventsJSON, setEventsJSON] = useState<string>('[]');
  const [isLoading, setIsLoading] = useState(false);
  const [currentResult, setCurrentResult] = useState<TestResultWithTiming | null>(null);
  const [validationError, setValidationError] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Derived state
  const eventValidation = useMemo(() => validateEventsJSON(eventsJSON), [eventsJSON]);
  const eventCount = eventValidation.valid ? (eventValidation.events?.length ?? 0) : 0;
  const canRunTest = eventValidation.valid && !isLoading;
  const jsonSize = useMemo(() => getByteSize(eventsJSON), [eventsJSON]);

  /**
   * Handle file upload with size validation
   */
  const handleFileUpload = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file size before reading (DoS prevention)
    if (file.size > MAX_JSON_SIZE_BYTES) {
      setValidationError(
        `File size (${formatBytes(file.size)}) exceeds maximum allowed size (${formatBytes(MAX_JSON_SIZE_BYTES)})`
      );
      announceToScreenReader('File upload failed: file too large');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setEventsJSON(content);
      setValidationError('');
      announceToScreenReader('File uploaded successfully');
    };
    reader.onerror = () => {
      const errorMsg = 'Failed to read file';
      setValidationError(errorMsg);
      announceToScreenReader(errorMsg);
    };
    reader.readAsText(file);

    // Reset file input
    if (event.target) {
      event.target.value = '';
    }
  }, []);

  /**
   * Execute rule test with timing
   */
  const handleRunTest = useCallback(async () => {
    if (!eventValidation.valid || !eventValidation.events) {
      setValidationError(eventValidation.error || 'Invalid events');
      return;
    }

    setIsLoading(true);
    setValidationError('');
    setCurrentResult(null);

    const startTime = performance.now();

    try {
      const testRequest: RuleTestRequest = {
        rule_id: ruleId,
        events: eventValidation.events,
      };

      const result = await api.testRule(testRequest);
      const endTime = performance.now();
      const evaluationTimeMs = Math.round(endTime - startTime);

      // Update state with results including timing
      const resultWithTiming: TestResultWithTiming = {
        ...result,
        evaluationTimeMs,
      };
      setCurrentResult(resultWithTiming);

      // Announce to screen readers
      const message = result.matched
        ? `Test passed: ${result.match_count} of ${result.events_tested} events matched in ${evaluationTimeMs}ms`
        : `Test failed: no events matched`;
      announceToScreenReader(message);

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Test execution failed';
      setValidationError(errorMessage);
      announceToScreenReader(`Test failed: ${errorMessage}`);
    } finally {
      setIsLoading(false);
    }
  }, [eventValidation, ruleId]);

  /**
   * Clear all test data and reset to initial state
   */
  const handleClear = useCallback(() => {
    setEventsJSON('[]');
    setCurrentResult(null);
    setValidationError('');
    announceToScreenReader('Test panel cleared');
  }, []);

  // =============================================================================
  // Render
  // =============================================================================

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header with close button */}
      {onClose && (
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Typography variant="h5" component="h1">
            Rule Test Panel
          </Typography>
          <IconButton onClick={onClose} aria-label="Close test panel">
            <CloseIcon />
          </IconButton>
        </Box>
      )}

      {/* Event Input Section */}
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6" component="h2">
              Sample Events
            </Typography>
            <Stack direction="row" spacing={1} alignItems="center">
              <Chip
                icon={<EventIcon />}
                label={`${formatNumber(eventCount)} event${eventCount !== 1 ? 's' : ''}`}
                color={eventCount > 0 ? 'primary' : 'default'}
                size="small"
              />
              <Chip
                label={formatBytes(jsonSize)}
                color={jsonSize > MAX_JSON_SIZE_BYTES * 0.9 ? 'warning' : 'default'}
                size="small"
                title={`Size: ${formatBytes(jsonSize)} / ${formatBytes(MAX_JSON_SIZE_BYTES)} max`}
              />
            </Stack>
          </Box>

          {/* Event JSON Editor */}
          <Box mb={2}>
            <JsonEditor
              value={eventsJSON}
              onChange={setEventsJSON}
              placeholder='Enter events as JSON array, e.g.: [{"event_type": "login", "username": "admin"}]'
              error={!eventValidation.valid && eventsJSON.length > 0}
              minHeight="250px"
            />
            {!eventValidation.valid && eventsJSON.length > 0 && (
              <Alert severity="error" sx={{ mt: 1 }} role="alert">
                {eventValidation.error}
              </Alert>
            )}
          </Box>

          {/* Action Buttons */}
          <Stack direction="row" spacing={2} flexWrap="wrap">
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,application/json"
              style={{ display: 'none' }}
              onChange={handleFileUpload}
              aria-label="Upload JSON file (max 1MB)"
            />
            <Button
              variant="outlined"
              startIcon={<UploadIcon />}
              onClick={() => fileInputRef.current?.click()}
              aria-label="Upload JSON file (maximum 1MB)"
            >
              Upload JSON File
            </Button>

            <Button
              variant="outlined"
              startIcon={<ClearIcon />}
              onClick={handleClear}
              disabled={eventsJSON === '[]' && !currentResult}
              aria-label="Clear events and results"
            >
              Clear All
            </Button>
          </Stack>
        </CardContent>
      </Card>

      {/* Test Execution */}
      <Box>
        <Button
          variant="contained"
          size="large"
          startIcon={isLoading ? <CircularProgress size={20} color="inherit" /> : <PlayIcon />}
          onClick={handleRunTest}
          disabled={!canRunTest}
          fullWidth
          aria-label={isLoading ? 'Test running' : 'Run test'}
        >
          {isLoading ? 'Running Test...' : 'Run Test'}
        </Button>

        {validationError && (
          <Alert severity="error" sx={{ mt: 2 }} role="alert">
            {validationError}
          </Alert>
        )}
      </Box>

      {/* Test Results */}
      {currentResult && (
        <Card>
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
              <Typography variant="h6" component="h2">
                Test Results
              </Typography>
              {currentResult.matched ? (
                <Chip
                  icon={<CheckCircleIcon />}
                  label="PASS"
                  color="success"
                  size="large"
                />
              ) : (
                <Chip
                  icon={<ErrorIcon />}
                  label="FAIL"
                  color="error"
                  size="large"
                />
              )}
            </Box>

            {/* Key Metrics */}
            <Stack spacing={2}>
              {/* Match Results */}
              <Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Match Results
                </Typography>
                <Typography variant="h6">
                  {currentResult.match_count} of {currentResult.events_tested} events matched
                </Typography>
              </Box>

              {/* Evaluation Time */}
              {currentResult.evaluationTimeMs !== undefined && (
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Evaluation Time
                  </Typography>
                  <Box display="flex" alignItems="center" gap={1}>
                    <SpeedIcon
                      fontSize="small"
                      color={getEvaluationTimeColor(currentResult.evaluationTimeMs)}
                    />
                    <Typography variant="h6">
                      {currentResult.evaluationTimeMs} ms
                    </Typography>
                    {currentResult.evaluationTimeMs > 100 && (
                      <Chip
                        label="Slow"
                        color="warning"
                        size="small"
                      />
                    )}
                  </Box>
                </Box>
              )}

              {/* Correlation State (if available) */}
              {currentResult.correlationState && Object.keys(currentResult.correlationState).length > 0 && (
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Correlation State
                  </Typography>
                  <Paper variant="outlined" sx={{ p: 2, backgroundColor: 'background.default' }}>
                    <pre style={{ margin: 0, fontSize: '12px', overflow: 'auto' }}>
                      {JSON.stringify(currentResult.correlationState, null, 2)}
                    </pre>
                  </Paper>
                </Box>
              )}

              {/* Matched Events List */}
              {currentResult.matches.length > 0 && (
                <Accordion>
                  <AccordionSummary
                    expandIcon={<ExpandMoreIcon />}
                    aria-label="Expand matched events details"
                  >
                    <Typography>
                      Matched Events ({currentResult.matches.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {currentResult.matches.map((match, index) => (
                        <ListItem key={index}>
                          <ListItemText
                            primary={`Event #${match.event_index + 1}`}
                            secondary={
                              match.matched_conditions.length > 0
                                ? `Matched conditions: ${match.matched_conditions.join(', ')}`
                                : 'No specific conditions matched'
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Errors */}
              {currentResult.errors && currentResult.errors.length > 0 && (
                <Alert severity="error" role="alert">
                  <Typography variant="subtitle2" gutterBottom>
                    Errors ({currentResult.errors.length})
                  </Typography>
                  <List dense>
                    {currentResult.errors.map((error, index) => (
                      <ListItem key={index} sx={{ py: 0.5 }}>
                        <Typography variant="body2">{error}</Typography>
                      </ListItem>
                    ))}
                  </List>
                </Alert>
              )}

              {/* Success message when no errors */}
              {(!currentResult.errors || currentResult.errors.length === 0) && currentResult.matched && (
                <Alert severity="success" role="status">
                  Rule successfully matched {currentResult.match_count} event{currentResult.match_count !== 1 ? 's' : ''}
                </Alert>
              )}
            </Stack>
          </CardContent>
        </Card>
      )}
    </Box>
  );
}
