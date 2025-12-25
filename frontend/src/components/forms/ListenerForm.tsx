import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Box,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Switch,
  Alert,
  CircularProgress,
  Typography,
  Grid,
  Chip,
  Autocomplete,
  Divider,
  FormHelperText,
} from '@mui/material';
import {
  InfoOutlined as InfoIcon,
  Security as SecurityIcon,
  CloudUpload as CloudUploadIcon,
} from '@mui/icons-material';
import { ListenerTemplateSelector } from './ListenerTemplateSelector';
import type {
  ListenerForm as ListenerFormType,
  ListenerTemplate,
  ListenerType,
  ListenerProtocol,
  DynamicListener,
} from '../../types';
import apiService from '../../services/api';

// ============================================================================
// Constants
// ============================================================================

/** Maximum length for listener name field */
const MAX_LISTENER_NAME_LENGTH = 100;

/** Maximum length for description field */
const MAX_DESCRIPTION_LENGTH = 500;

/**
 * Type-specific protocol mapping
 * Ensures protocol options are contextually appropriate for each listener type
 */
const PROTOCOL_OPTIONS: Record<ListenerType, ListenerProtocol[]> = {
  syslog: ['udp', 'tcp'],
  cef: ['udp', 'tcp'],
  json: ['tcp', 'http'],
  fluentd: ['tcp', 'http'],
  fluentbit: ['tcp', 'http'],
};

/**
 * Default values for listener form - centralized to avoid duplication
 */
const DEFAULT_LISTENER_VALUES: ListenerFormType = {
  name: '',
  description: '',
  type: 'syslog' as ListenerType,
  protocol: 'udp' as ListenerProtocol,
  host: '0.0.0.0',
  port: 514,
  tls: false,
  cert_file: '',
  key_file: '',
  tags: [] as string[],
  source: '',
  field_mapping: '',
};

// ============================================================================
// Validation Utilities
// ============================================================================

/**
 * Path validation - prevents path traversal attacks
 * BLOCKING-2 FIX: Enhanced to handle URL encoding, backslashes, and UNC paths
 * CRITICAL-3 FIX: Support both Unix and Windows absolute paths
 */
const isValidPath = (path: string): boolean => {
  if (!path) return true; // Empty paths are allowed (optional fields)

  // Decode URL-encoded sequences first
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(path);
  } catch {
    // Invalid URL encoding - reject
    return false;
  }

  // Block null bytes (security bypass attempt) - check before normalization
  if (path.includes('\0') || path.includes('%00')) return false;

  // Normalize backslashes to forward slashes for traversal detection
  const normalizedPath = decodedPath.replace(/\\/g, '/');

  // Block path traversal sequences (after normalization)
  if (normalizedPath.includes('..')) return false;

  // Block home directory expansion
  if (normalizedPath.includes('~')) return false;

  // Block UNC paths (Windows network paths) - security risk
  if (path.startsWith('//') || path.startsWith('\\\\')) return false;

  // CRITICAL-3 FIX: Check if path is absolute (cross-platform)
  // Unix absolute: starts with /
  // Windows absolute: starts with drive letter (C:, D:, etc.)
  const isUnixAbsolute = normalizedPath.startsWith('/');
  const isWindowsAbsolute = /^[a-zA-Z]:/.test(path);

  if (!isUnixAbsolute && !isWindowsAbsolute) {
    // Relative paths are not allowed - prevents path manipulation
    return false;
  }

  return true;
};

/**
 * Validation schema with comprehensive business rules
 * - Port must be in valid range (1-65535)
 * - TLS requires both cert_file AND key_file with field-specific errors
 * - Protocol must match listener type
 * - Source is required for data attribution
 * - Certificate paths validated against path traversal
 */
const listenerFormSchema = z.object({
  name: z.string()
    .min(1, 'Listener name is required')
    .max(MAX_LISTENER_NAME_LENGTH, `Name must be ${MAX_LISTENER_NAME_LENGTH} characters or less`),
  description: z.string()
    .max(MAX_DESCRIPTION_LENGTH, `Description must be ${MAX_DESCRIPTION_LENGTH} characters or less`),
  type: z.enum(['syslog', 'cef', 'json', 'fluentd', 'fluentbit'], {
    message: 'Invalid listener type',
  }),
  protocol: z.enum(['udp', 'tcp', 'http'], {
    message: 'Invalid protocol',
  }),
  host: z.string().min(1, 'Host is required'),
  port: z.number()
    .int('Port must be an integer')
    .min(1, 'Port must be at least 1')
    .max(65535, 'Port must be at most 65535'),
  tls: z.boolean(),
  cert_file: z.string().optional().refine(
    (path) => isValidPath(path || ''),
    'Certificate path cannot contain ".." or "~" for security reasons'
  ),
  key_file: z.string().optional().refine(
    (path) => isValidPath(path || ''),
    'Key path cannot contain ".." or "~" for security reasons'
  ),
  tags: z.array(z.string()).optional(),
  source: z.string().min(1, 'Source is required for event attribution'),
  field_mapping: z.string().optional(),
}).refine(
  (data) => {
    // Protocol validation: ensure protocol is valid for the selected type
    const validProtocols = PROTOCOL_OPTIONS[data.type];
    return validProtocols.includes(data.protocol);
  },
  {
    message: 'Selected protocol is not valid for this listener type',
    path: ['protocol'],
  }
).superRefine((data, ctx) => {
  // TLS validation with field-specific error messages
  if (data.tls) {
    if (!data.cert_file) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Certificate file is required when TLS is enabled',
        path: ['cert_file'],
      });
    }
    if (!data.key_file) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Private key file is required when TLS is enabled',
        path: ['key_file'],
      });
    }
  }
});

type ListenerFormData = z.infer<typeof listenerFormSchema>;

// ============================================================================
// Component Props
// ============================================================================

interface ListenerFormProps {
  initialValues?: Partial<ListenerFormType>;
  onSubmit: (values: ListenerFormType) => Promise<void>;
  onCancel: () => void;
  mode: 'create' | 'edit';
  /** Existing listeners for port conflict validation (optional - will be fetched if not provided) */
  existingListeners?: DynamicListener[];
}

// ============================================================================
// Component
// ============================================================================

/**
 * ListenerForm Component
 *
 * A production-grade form for creating and editing event listeners with:
 * - Template-based quick configuration
 * - Manual configuration with comprehensive validation
 * - Type-specific protocol constraints
 * - TLS certificate management
 * - Tag management with autocomplete
 * - Port conflict validation
 * - Accessible keyboard navigation and screen reader support
 * - Loading states and error handling
 *
 * @example
 * ```tsx
 * <ListenerForm
 *   mode="create"
 *   onSubmit={async (values) => await api.listeners.create(values)}
 *   onCancel={() => setDialogOpen(false)}
 * />
 * ```
 */
export function ListenerForm({
  initialValues,
  onSubmit,
  onCancel,
  mode,
  existingListeners: propsExistingListeners,
}: ListenerFormProps) {
  // ============================================================================
  // State
  // ============================================================================
  const [templates, setTemplates] = useState<ListenerTemplate[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [loadingTemplates, setLoadingTemplates] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [existingListeners, setExistingListeners] = useState<DynamicListener[]>(propsExistingListeners || []);
  const [portConflictError, setPortConflictError] = useState<string>('');

  // Ref for cleanup on unmount (BLOCKER-5 fix)
  const isMountedRef = useRef(true);

  // Ref for tracking initial values changes with deep comparison (BLOCKER-2 fix)
  const initialValuesJsonRef = useRef<string>('');

  // ============================================================================
  // Form Setup
  // ============================================================================

  // Memoize default values to prevent unnecessary re-renders
  const formDefaultValues = useMemo(() => ({
    ...DEFAULT_LISTENER_VALUES,
    ...initialValues,
  }), [initialValues]);

  const {
    control,
    register,
    handleSubmit,
    watch,
    setValue,
    reset,
    formState: { errors, isValid, isDirty },
  } = useForm<ListenerFormData>({
    resolver: zodResolver(listenerFormSchema),
    mode: 'onChange',
    defaultValues: formDefaultValues,
  });

  // Watch specific fields using useCallback for stability
  const watchedType = watch('type');
  const watchedTls = watch('tls');
  const watchedPort = watch('port');
  const watchedHost = watch('host');
  const watchedProtocol = watch('protocol');

  // ============================================================================
  // Effects
  // ============================================================================

  /**
   * Cleanup on unmount (BLOCKER-5 fix)
   */
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  /**
   * Validate protocol when listener type changes
   * Automatically adjusts protocol if current selection is invalid for new type
   */
  useEffect(() => {
    const validProtocols = PROTOCOL_OPTIONS[watchedType];
    if (!validProtocols.includes(watchedProtocol)) {
      // Auto-select first valid protocol for better UX
      setValue('protocol', validProtocols[0], {
        shouldValidate: false,
        shouldDirty: false,
      });
    }
  }, [watchedType, watchedProtocol, setValue]);

  /**
   * Reset form when initial values change (BLOCKER-2 fix)
   * Uses JSON serialization for deep comparison instead of reference comparison
   * Only resets if form hasn't been dirtied by user
   */
  useEffect(() => {
    if (initialValues) {
      const newValuesJson = JSON.stringify(initialValues);
      if (newValuesJson !== initialValuesJsonRef.current && !isDirty) {
        initialValuesJsonRef.current = newValuesJson;
        reset({
          ...DEFAULT_LISTENER_VALUES,
          ...initialValues,
        });
      }
    }
  }, [initialValues, reset, isDirty]);

  /**
   * Port conflict validation (BLOCKER-3 fix)
   * Checks if the selected port is already in use by another listener
   * BLOCKING-4 FIX: Type-safe status check with proper type guard
   * BLOCKING-5 FIX: Added cleanup flag for mounted check
   */
  useEffect(() => {
    let isCancelled = false;

    // Early return with cleanup for invalid inputs
    if (!existingListeners.length || !watchedPort || !watchedHost) {
      if (!isCancelled) {
        setPortConflictError('');
      }
      return () => { isCancelled = true; };
    }

    const conflict = existingListeners.find(listener => {
      // Skip self in edit mode - compare by ID if available, otherwise by name
      if (mode === 'edit') {
        // BLOCKING-4 FIX: Safe runtime check for id instead of unsafe type assertion
        // Check if initialValues has an id property and it's a string
        const maybeId = initialValues && 'id' in initialValues ? initialValues.id : undefined;
        const editingId = typeof maybeId === 'string' ? maybeId : undefined;
        if (editingId && listener.id === editingId) return false;
        if (initialValues?.name === listener.name) return false;
      }
      // BLOCKING-4 FIX: Type-safe status check
      // Status must exist AND not be 'stopped' - explicit type guard
      const isRunning = typeof listener.status === 'string' &&
        listener.status !== 'stopped';

      // CRITICAL-2 FIX: Handle 0.0.0.0 wildcard binding correctly
      // 0.0.0.0 binds to ALL interfaces, so it conflicts with ANY specific IP
      const hasHostConflict =
        listener.host === watchedHost ||         // Exact match
        listener.host === '0.0.0.0' ||           // Existing is wildcard (binds all)
        watchedHost === '0.0.0.0';               // New is wildcard (would bind all)

      return (
        listener.port === watchedPort &&
        hasHostConflict &&
        listener.protocol === watchedProtocol &&
        isRunning
      );
    });

    if (!isCancelled) {
      if (conflict) {
        setPortConflictError(
          `Port ${watchedPort} is already in use by listener "${conflict.name}"`
        );
      } else {
        setPortConflictError('');
      }
    }

    return () => { isCancelled = true; };
  }, [watchedPort, watchedHost, watchedProtocol, existingListeners, mode, initialValues]);

  // ============================================================================
  // Data Loading Functions
  // ============================================================================

  /**
   * Load available listener templates (BLOCKER-5 fix)
   * Uses isMountedRef to prevent state updates after unmount
   */
  const loadTemplates = useCallback(async () => {
    setLoadingTemplates(true);
    setErrorMessage('');

    try {
      const templatesData = await apiService.listeners.getTemplates();
      // BLOCKER-5: Check if still mounted before updating state
      if (isMountedRef.current) {
        setTemplates(templatesData);
      }
    } catch (error) {
      console.error('Failed to load listener templates:', error);
      if (isMountedRef.current) {
        setErrorMessage('Failed to load templates. You can still create a listener manually.');
      }
    } finally {
      if (isMountedRef.current) {
        setLoadingTemplates(false);
      }
    }
  }, []);

  /**
   * Load existing listeners for port conflict validation (BLOCKER-3 fix)
   * CRITICAL-2 fix: Shows warning when fetch fails so user knows validation is unavailable
   * BLOCKING-1 FIX: Added AbortController for proper race condition handling
   */
  const loadExistingListeners = useCallback(async (signal?: AbortSignal) => {
    try {
      const response = await apiService.listeners.getListeners(1, 1000); // Get all listeners
      // Check both mounted ref AND abort signal for race condition safety
      if (isMountedRef.current && !signal?.aborted) {
        setExistingListeners(response.items || []);
      }
    } catch (error) {
      // Ignore abort errors - they're expected when component unmounts or new fetch starts
      if (error instanceof Error && error.name === 'AbortError') {
        return;
      }
      console.error('Failed to load existing listeners for validation:', error);
      // CRITICAL-2 fix: Inform user that port conflict validation is unavailable
      if (isMountedRef.current && !signal?.aborted) {
        setPortConflictError('Warning: Could not verify port availability. Proceed with caution.');
      }
    }
  }, []);

  /**
   * Load templates and existing listeners on mount
   * BLOCKING-1 REOPEN FIX: Moved useEffect AFTER callback definitions to prevent
   * dependency order violations. Dependencies are now stable.
   */
  useEffect(() => {
    const abortController = new AbortController();

    if (mode === 'create') {
      loadTemplates();
    }
    // Only fetch existing listeners if not provided via props
    if (!propsExistingListeners) {
      loadExistingListeners(abortController.signal);
    }

    // Cleanup: abort any pending fetch on unmount or dependency change
    return () => {
      abortController.abort();
    };
    // Note: loadTemplates and loadExistingListeners are stable callbacks (empty deps)
    // so they won't cause re-renders. Omitting from deps with eslint comment.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, propsExistingListeners]);

  // ============================================================================
  // Event Handlers
  // ============================================================================

  /**
   * Apply selected template to form
   * Pre-fills form fields while allowing manual overrides
   * Note: React controlled inputs are inherently XSS-safe - escapeHTML is NOT needed here.
   * XSS protection should be at API response validation and backend output escaping.
   */
  const handleTemplateSelect = useCallback((templateId: string) => {
    setSelectedTemplate(templateId);
    setErrorMessage('');

    const template = templates.find(t => t.id === templateId);
    if (!template?.config) return;

    const config = template.config;
    // Apply template values directly - React controlled inputs are XSS-safe
    if (config.name) setValue('name', config.name);
    if (config.description) setValue('description', config.description);
    if (config.type) setValue('type', config.type);
    if (config.protocol) setValue('protocol', config.protocol);
    if (config.host) setValue('host', config.host);
    if (typeof config.port === 'number') setValue('port', config.port);
    if (typeof config.tls === 'boolean') setValue('tls', config.tls);
    if (config.cert_file) setValue('cert_file', config.cert_file);
    if (config.key_file) setValue('key_file', config.key_file);
    if (Array.isArray(config.tags)) setValue('tags', config.tags);
    if (config.source) setValue('source', config.source);
    if (config.field_mapping) setValue('field_mapping', config.field_mapping);
  }, [templates, setValue]);

  /**
   * Handle form submission
   * Validates data, checks port conflicts, manages loading state, and handles errors
   * (BLOCKER-4 fix: React handles XSS for error messages automatically)
   */
  const handleFormSubmit = useCallback(async (data: ListenerFormData) => {
    // Check for port conflicts before submission
    if (portConflictError) {
      setErrorMessage(portConflictError);
      return;
    }

    setSubmitting(true);
    setErrorMessage('');

    try {
      // Explicitly construct ListenerFormType for type safety
      const listenerData: ListenerFormType = {
        name: data.name,
        description: data.description,
        type: data.type,
        protocol: data.protocol,
        host: data.host,
        port: data.port,
        tls: data.tls,
        cert_file: data.cert_file,
        key_file: data.key_file,
        tags: data.tags,
        source: data.source,
        field_mapping: data.field_mapping,
      };
      await onSubmit(listenerData);
    } catch (error) {
      console.error('Failed to submit listener form:', error);
      // BLOCKER-4 fix: React automatically escapes text content, no need for escapeHTML
      const errorMsg = error instanceof Error
        ? error.message
        : 'Failed to save listener. Please check your input and try again.';
      if (isMountedRef.current) {
        setErrorMessage(errorMsg);
      }
    } finally {
      if (isMountedRef.current) {
        setSubmitting(false);
      }
    }
  }, [onSubmit, portConflictError]);

  // ============================================================================
  // Computed Values
  // ============================================================================

  /**
   * Get available protocols for current listener type
   */
  const availableProtocols = PROTOCOL_OPTIONS[watchedType] || [];

  /**
   * Combined form validity including port conflict check
   */
  const isFormValid = isValid && !portConflictError;

  // ============================================================================
  // Render Helpers
  // ============================================================================

  /**
   * Helper to generate unique IDs for accessibility (BLOCKER-6 fix)
   */
  const getErrorId = (fieldName: string) => `${fieldName}-error`;

  return (
    <Box component="form" onSubmit={handleSubmit(handleFormSubmit)} noValidate>
      {/* Template Selection - Only in create mode */}
      {mode === 'create' && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CloudUploadIcon fontSize="small" />
            Quick Start with Template
          </Typography>

          {/* BLOCKING-5 FIX: Pass error message when templates fail to load */}
          <ListenerTemplateSelector
            templates={templates}
            selectedTemplateId={selectedTemplate}
            onSelectTemplate={handleTemplateSelect}
            loading={loadingTemplates}
            error={errorMessage && errorMessage.includes('template') ? errorMessage : undefined}
          />

          <Divider sx={{ mt: 3, mb: 3 }} />
        </Box>
      )}

      {/* Error Display with proper accessibility (BLOCKER-6 fix) */}
      {errorMessage && (
        <Alert
          severity="error"
          sx={{ mb: 3 }}
          onClose={() => setErrorMessage('')}
          role="alert"
          aria-live="assertive"
          aria-atomic="true"
        >
          {errorMessage}
        </Alert>
      )}

      {/* Port Conflict Warning (BLOCKER-3 fix) */}
      {portConflictError && (
        <Alert
          severity="warning"
          sx={{ mb: 3 }}
          role="alert"
          aria-live="polite"
        >
          {portConflictError}
        </Alert>
      )}

      {/* Basic Information */}
      <Grid container spacing={2}>
        <Grid size={12}>
          <TextField
            fullWidth
            label="Listener Name"
            {...register('name')}
            error={!!errors.name}
            helperText={errors.name?.message}
            disabled={submitting}
            required
            slotProps={{
              input: {
                'aria-label': 'Listener name',
                'aria-required': true,
                'aria-invalid': !!errors.name,
                'aria-describedby': errors.name ? getErrorId('name') : undefined,
              },
              formHelperText: {
                id: getErrorId('name'),
                role: errors.name ? 'alert' : undefined,
              },
            }}
          />
        </Grid>

        <Grid size={12}>
          <TextField
            fullWidth
            multiline
            rows={2}
            label="Description"
            {...register('description')}
            error={!!errors.description}
            helperText={errors.description?.message || 'Optional description of this listener'}
            disabled={submitting}
            slotProps={{
              input: {
                'aria-label': 'Description',
              },
            }}
          />
        </Grid>

        {/* Type and Protocol Configuration */}
        <Grid size={{ xs: 12, sm: 6 }}>
          <FormControl fullWidth error={!!errors.type} disabled={mode === 'edit' || submitting}>
            <InputLabel id="type-label" required>Listener Type</InputLabel>
            <Controller
              name="type"
              control={control}
              render={({ field }) => (
                <Select
                  {...field}
                  labelId="type-label"
                  id="type-select"
                  label="Listener Type *"
                  aria-label="Listener type"
                  aria-required="true"
                  aria-invalid={!!errors.type}
                >
                  <MenuItem value="syslog">Syslog</MenuItem>
                  <MenuItem value="cef">CEF (Common Event Format)</MenuItem>
                  <MenuItem value="json">JSON</MenuItem>
                  <MenuItem value="fluentd">Fluentd</MenuItem>
                  <MenuItem value="fluentbit">Fluent Bit</MenuItem>
                </Select>
              )}
            />
            {mode === 'edit' && (
              <FormHelperText>Type cannot be changed in edit mode</FormHelperText>
            )}
            {errors.type && (
              <FormHelperText id={getErrorId('type')} role="alert">
                {errors.type.message}
              </FormHelperText>
            )}
          </FormControl>
        </Grid>

        <Grid size={{ xs: 12, sm: 6 }}>
          <FormControl fullWidth error={!!errors.protocol} disabled={submitting}>
            <InputLabel id="protocol-label" required>Protocol</InputLabel>
            <Controller
              name="protocol"
              control={control}
              render={({ field }) => (
                <Select
                  {...field}
                  labelId="protocol-label"
                  id="protocol-select"
                  label="Protocol *"
                  aria-label="Protocol"
                  aria-required="true"
                  aria-invalid={!!errors.protocol}
                >
                  {availableProtocols.map((protocol) => (
                    <MenuItem key={protocol} value={protocol}>
                      {protocol.toUpperCase()}
                    </MenuItem>
                  ))}
                </Select>
              )}
            />
            {errors.protocol && (
              <FormHelperText id={getErrorId('protocol')} role="alert">
                {errors.protocol.message}
              </FormHelperText>
            )}
          </FormControl>
        </Grid>

        {/* Network Configuration */}
        <Grid size={{ xs: 12, sm: 8 }}>
          <TextField
            fullWidth
            label="Host"
            {...register('host')}
            error={!!errors.host}
            helperText={errors.host?.message || 'Default: 0.0.0.0 (all interfaces)'}
            disabled={submitting}
            required
            slotProps={{
              input: {
                'aria-label': 'Host address',
                'aria-required': true,
                'aria-describedby': errors.host ? getErrorId('host') : undefined,
              },
              formHelperText: {
                id: getErrorId('host'),
                role: errors.host ? 'alert' : undefined,
              },
            }}
          />
        </Grid>

        <Grid size={{ xs: 12, sm: 4 }}>
          <Controller
            name="port"
            control={control}
            render={({ field }) => (
              <TextField
                {...field}
                fullWidth
                type="number"
                label="Port"
                error={!!errors.port || !!portConflictError}
                helperText={errors.port?.message || portConflictError}
                disabled={submitting}
                required
                onChange={(e) => {
                  // BLOCKING-8 FIX + BLOCKING-2 FIX: Handle empty/invalid input without
                  // corrupting form state. Keep previous value on invalid input rather
                  // than setting undefined (which violates non-optional number schema).
                  const value = e.target.value;
                  if (value === '' || value === null || value === undefined) {
                    // For empty input, let the HTML input handle display
                    // Keep previous value to avoid schema corruption
                    // The required validation will show error message
                    return;
                  }
                  const parsed = parseInt(value, 10);
                  // Only update if we got a valid number within range
                  if (!Number.isNaN(parsed) && parsed >= 1 && parsed <= 65535) {
                    field.onChange(parsed);
                  }
                  // Invalid input: don't update - keep previous valid value
                }}
                slotProps={{
                  htmlInput: {
                    min: 1,
                    max: 65535,
                    'aria-label': 'Port number',
                    'aria-required': true,
                    'aria-invalid': !!errors.port || !!portConflictError,
                    'aria-describedby': (errors.port || portConflictError) ? getErrorId('port') : undefined,
                  },
                  formHelperText: {
                    id: getErrorId('port'),
                    role: (errors.port || portConflictError) ? 'alert' : undefined,
                  },
                }}
              />
            )}
          />
        </Grid>

        {/* Source Configuration */}
        <Grid size={12}>
          <TextField
            fullWidth
            label="Source"
            {...register('source')}
            error={!!errors.source}
            helperText={errors.source?.message || 'Identifies the origin of events from this listener'}
            disabled={submitting}
            required
            placeholder="e.g., firewall-prod, application-server-01"
            slotProps={{
              input: {
                'aria-label': 'Event source',
                'aria-required': true,
                'aria-describedby': errors.source ? getErrorId('source') : undefined,
              },
              formHelperText: {
                id: getErrorId('source'),
                role: errors.source ? 'alert' : undefined,
              },
            }}
          />
        </Grid>

        {/* TLS Configuration */}
        <Grid size={12}>
          <Box sx={{
            p: 2,
            bgcolor: 'background.paper',
            borderRadius: 1,
            border: '1px solid',
            borderColor: 'divider',
          }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <SecurityIcon fontSize="small" color="primary" />
              <Typography variant="subtitle2">TLS Configuration</Typography>
            </Box>

            <Controller
              name="tls"
              control={control}
              render={({ field }) => (
                <FormControlLabel
                  control={
                    <Switch
                      {...field}
                      checked={field.value}
                      disabled={submitting}
                      inputProps={{
                        'aria-label': 'Enable TLS encryption',
                      }}
                    />
                  }
                  label="Enable TLS/SSL encryption"
                />
              )}
            />

            {watchedTls && (
              <Grid container spacing={2} sx={{ mt: 1 }}>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <TextField
                    fullWidth
                    label="Certificate File Path"
                    {...register('cert_file')}
                    error={!!errors.cert_file}
                    helperText={errors.cert_file?.message}
                    disabled={submitting}
                    required
                    placeholder="/path/to/certificate.crt"
                    slotProps={{
                      input: {
                        'aria-label': 'TLS certificate file path',
                        'aria-required': watchedTls,
                        'aria-describedby': errors.cert_file ? getErrorId('cert_file') : undefined,
                      },
                      formHelperText: {
                        id: getErrorId('cert_file'),
                        role: errors.cert_file ? 'alert' : undefined,
                      },
                    }}
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <TextField
                    fullWidth
                    label="Private Key File Path"
                    {...register('key_file')}
                    error={!!errors.key_file}
                    helperText={errors.key_file?.message}
                    disabled={submitting}
                    required
                    placeholder="/path/to/private-key.key"
                    slotProps={{
                      input: {
                        'aria-label': 'TLS private key file path',
                        'aria-required': watchedTls,
                        'aria-describedby': errors.key_file ? getErrorId('key_file') : undefined,
                      },
                      formHelperText: {
                        id: getErrorId('key_file'),
                        role: errors.key_file ? 'alert' : undefined,
                      },
                    }}
                  />
                </Grid>
              </Grid>
            )}
          </Box>
        </Grid>

        {/* Tags */}
        <Grid size={12}>
          <Controller
            name="tags"
            control={control}
            render={({ field }) => (
              <Autocomplete
                {...field}
                multiple
                freeSolo
                options={[]}
                value={field.value || []}
                onChange={(_, newValue) => field.onChange(newValue)}
                disabled={submitting}
                renderTags={(value, getTagProps) =>
                  value.map((option, index) => (
                    <Chip
                      label={option}
                      {...getTagProps({ index })}
                      key={option}
                    />
                  ))
                }
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label="Tags"
                    placeholder="Add tags and press Enter"
                    helperText="Optional tags for categorization and filtering"
                    slotProps={{
                      htmlInput: {
                        ...params.inputProps,
                        'aria-label': 'Add tags',
                      },
                    }}
                  />
                )}
              />
            )}
          />
        </Grid>

        {/* Field Mapping */}
        <Grid size={12}>
          <TextField
            fullWidth
            label="Field Mapping (Optional)"
            {...register('field_mapping')}
            error={!!errors.field_mapping}
            helperText={errors.field_mapping?.message || 'Optional custom field mapping configuration'}
            disabled={submitting}
            placeholder="e.g., field-mapping-name"
            slotProps={{
              input: {
                'aria-label': 'Field mapping',
              },
            }}
          />
        </Grid>
      </Grid>

      {/* Information Box */}
      <Alert severity="info" icon={<InfoIcon />} sx={{ mt: 3 }}>
        <Typography variant="body2">
          <strong>Port Selection Guidelines:</strong>
        </Typography>
        <Typography variant="caption" component="div">
          - Syslog/CEF: Port 514 (UDP/TCP)
          <br />
          - HTTP listeners: Port 8080 or above
          <br />
          - Ports below 1024 require elevated privileges on Linux/Unix systems
        </Typography>
      </Alert>

      {/* Action Buttons */}
      <Box sx={{ mt: 3, display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
        <Button
          variant="outlined"
          onClick={onCancel}
          disabled={submitting}
          aria-label="Cancel listener creation"
        >
          Cancel
        </Button>
        <Button
          type="submit"
          variant="contained"
          disabled={submitting || !isFormValid}
          aria-label={mode === 'create' ? 'Create listener' : 'Update listener'}
          aria-busy={submitting}
          startIcon={submitting ? <CircularProgress size={20} /> : null}
        >
          {submitting ? 'Saving...' : mode === 'create' ? 'Create Listener' : 'Update Listener'}
        </Button>
      </Box>
    </Box>
  );
}
