/**
 * Feed Setup Wizard Component (TASK 160.2, 160.3)
 *
 * First-run setup wizard for configuring Sigma rule feeds.
 * Shows on first app load, persists state to localStorage.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  IconButton,
  Typography,
  Box,
  Alert,
  CircularProgress,
  Card,
  CardContent,
  CardActionArea,
  Checkbox,
  Grid,
  Chip,
  Skeleton,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import RuleIcon from '@mui/icons-material/Rule';
import SecurityIcon from '@mui/icons-material/Security';
import CloudDownloadIcon from '@mui/icons-material/CloudDownload';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { StepWizard, WizardStep } from './StepWizard';
import { FeedTemplate } from '../types';

// ============================================================================
// Types
// ============================================================================

export interface WizardState {
  currentStep: number;
  selectedTemplates: string[];
  syncSchedule: {
    type: 'manual' | 'interval' | 'cron';
    intervalMinutes?: number;
    cronExpression?: string;
  };
  syncProgress: {
    current: number;
    total: number;
    currentFeed: string | null;
  } | null;
  completedSteps: number[];
}

const STORAGE_KEY = 'cerberus_feed_setup_wizard';

const DEFAULT_STATE: WizardState = {
  currentStep: 0,
  selectedTemplates: [],
  syncSchedule: {
    type: 'manual',
  },
  syncProgress: null,
  completedSteps: [],
};

// ============================================================================
// Step Components
// ============================================================================

interface StepContentProps {
  wizardState: WizardState;
  updateState: (updates: Partial<WizardState>) => void;
}

/**
 * Step 1: Welcome & Overview (TASK 160.3)
 */
const WelcomeStep: React.FC<StepContentProps> = () => (
  <Box>
    <Box sx={{ textAlign: 'center', mb: 4 }}>
      <SecurityIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
      <Typography variant="h4" gutterBottom>
        Welcome to Cerberus SIEM
      </Typography>
      <Typography variant="body1" color="text.secondary">
        Your comprehensive Security Information and Event Management solution
      </Typography>
    </Box>

    <Typography variant="body1" paragraph>
      This setup wizard will help you configure your first <strong>Sigma rule feeds</strong>.
      Sigma rules are vendor-agnostic detection rules that help identify security threats
      in your logs.
    </Typography>

    <Box sx={{ my: 3 }}>
      <Typography variant="h6" gutterBottom>
        What are Sigma Rule Feeds?
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Sigma rule feeds are repositories of community-maintained detection rules.
        By subscribing to feeds, you can automatically import and update rules from
        trusted sources like SigmaHQ, keeping your detection coverage up-to-date.
      </Typography>
    </Box>

    <Typography variant="body1" paragraph>
      In the following steps, you will:
    </Typography>
    <Box component="ul" sx={{ pl: 3, mb: 3 }}>
      <Typography component="li" variant="body1" sx={{ mb: 1 }}>
        <strong>Select feeds</strong> - Choose from pre-configured community rule repositories
      </Typography>
      <Typography component="li" variant="body1" sx={{ mb: 1 }}>
        <strong>Configure schedule</strong> - Set how often feeds should sync automatically
      </Typography>
      <Typography component="li" variant="body1" sx={{ mb: 1 }}>
        <strong>Review & confirm</strong> - Verify your selections before applying
      </Typography>
      <Typography component="li" variant="body1">
        <strong>Initial sync</strong> - Import your first batch of detection rules
      </Typography>
    </Box>

    <Alert severity="info" icon={<CloudDownloadIcon />}>
      You can skip this wizard and configure feeds manually later from the Settings page.
    </Alert>
  </Box>
);

/**
 * Template Card Component (TASK 160.3)
 */
interface TemplateCardProps {
  template: FeedTemplate;
  selected: boolean;
  onToggle: () => void;
}

const TemplateCard: React.FC<TemplateCardProps> = ({ template, selected, onToggle }) => {
  // Extract rule count from description if available
  const ruleCountMatch = template.description?.match(/(\d+)\+?\s*rules?/i);
  const ruleCount = ruleCountMatch ? ruleCountMatch[1] : null;

  return (
    <Card
      variant="outlined"
      sx={{
        height: '100%',
        border: selected ? 2 : 1,
        borderColor: selected ? 'primary.main' : 'divider',
        bgcolor: selected ? 'action.selected' : 'background.paper',
        transition: 'all 0.2s ease-in-out',
        '&:hover': {
          borderColor: 'primary.main',
          boxShadow: 2,
        },
      }}
    >
      <CardActionArea
        onClick={onToggle}
        sx={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}
      >
        <CardContent sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <Box sx={{ display: 'flex', alignItems: 'flex-start', mb: 1 }}>
            <Checkbox
              checked={selected}
              sx={{ p: 0, mr: 1 }}
              color="primary"
            />
            <Box sx={{ flex: 1 }}>
              <Typography variant="subtitle1" fontWeight="bold">
                {template.name}
              </Typography>
            </Box>
            {selected && (
              <CheckCircleOutlineIcon color="primary" sx={{ ml: 1 }} />
            )}
          </Box>

          <Typography
            variant="body2"
            color="text.secondary"
            sx={{ flex: 1, mb: 2 }}
          >
            {template.description}
          </Typography>

          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Chip
              icon={<RuleIcon />}
              label={ruleCount ? `${ruleCount}+ rules` : 'Rules available'}
              size="small"
              variant="outlined"
              color={selected ? 'primary' : 'default'}
            />
            <Chip
              label={template.type}
              size="small"
              variant="outlined"
              color={selected ? 'primary' : 'default'}
            />
          </Box>
        </CardContent>
      </CardActionArea>
    </Card>
  );
};

/**
 * Step 2: Template Selection (TASK 160.3)
 */
interface TemplateSelectionStepProps extends StepContentProps {
  templates: FeedTemplate[];
  isLoading: boolean;
  error: Error | null;
}

const TemplateSelectionStep: React.FC<TemplateSelectionStepProps> = ({
  wizardState,
  updateState,
  templates,
  isLoading,
  error,
}) => {
  const handleToggleTemplate = (templateId: string) => {
    const currentSelected = wizardState.selectedTemplates;
    const newSelected = currentSelected.includes(templateId)
      ? currentSelected.filter((id) => id !== templateId)
      : [...currentSelected, templateId];
    updateState({ selectedTemplates: newSelected });
  };

  const handleSelectAll = () => {
    if (wizardState.selectedTemplates.length === templates.length) {
      updateState({ selectedTemplates: [] });
    } else {
      updateState({ selectedTemplates: templates.map((t) => t.id) });
    }
  };

  if (error) {
    return (
      <Alert severity="error">
        Failed to load feed templates. Please try again or skip this step.
        <Typography variant="caption" display="block" sx={{ mt: 1 }}>
          {error.message}
        </Typography>
      </Alert>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
        <Box>
          <Typography variant="h6" gutterBottom sx={{ mb: 0 }}>
            Select Rule Feed Templates
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Choose from the following pre-configured rule feed templates.
          </Typography>
        </Box>
        {!isLoading && templates.length > 0 && (
          <Chip
            label={
              wizardState.selectedTemplates.length === templates.length
                ? 'Deselect All'
                : 'Select All'
            }
            onClick={handleSelectAll}
            variant="outlined"
            size="small"
          />
        )}
      </Box>

      {wizardState.selectedTemplates.length === 0 && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Please select at least one feed template to continue, or skip the wizard to configure feeds later.
        </Alert>
      )}

      {isLoading ? (
        <Grid container spacing={2}>
          {[1, 2, 3].map((i) => (
            <Grid item xs={12} sm={6} md={4} key={i}>
              <Skeleton variant="rectangular" height={180} sx={{ borderRadius: 1 }} />
            </Grid>
          ))}
        </Grid>
      ) : (
        <Grid container spacing={2}>
          {templates.map((template) => (
            <Grid item xs={12} sm={6} md={4} key={template.id}>
              <TemplateCard
                template={template}
                selected={wizardState.selectedTemplates.includes(template.id)}
                onToggle={() => handleToggleTemplate(template.id)}
              />
            </Grid>
          ))}
        </Grid>
      )}

      {!isLoading && templates.length === 0 && (
        <Alert severity="info">
          No feed templates are currently available. You can configure feeds manually from the Settings page.
        </Alert>
      )}

      <Box sx={{ mt: 3, p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
        <Typography variant="subtitle2">
          Selected: {wizardState.selectedTemplates.length} of {templates.length} templates
        </Typography>
      </Box>
    </Box>
  );
};

/**
 * Schedule Option Component (TASK 160.4)
 */
interface ScheduleOptionProps {
  value: WizardState['syncSchedule']['type'];
  currentValue: WizardState['syncSchedule']['type'];
  title: string;
  description: string;
  icon: React.ReactNode;
  children?: React.ReactNode;
  onSelect: () => void;
}

const ScheduleOption: React.FC<ScheduleOptionProps> = ({
  value,
  currentValue,
  title,
  description,
  icon,
  children,
  onSelect,
}) => {
  const isSelected = value === currentValue;

  return (
    <Card
      variant="outlined"
      sx={{
        mb: 2,
        border: isSelected ? 2 : 1,
        borderColor: isSelected ? 'primary.main' : 'divider',
        bgcolor: isSelected ? 'action.selected' : 'background.paper',
        transition: 'all 0.2s ease-in-out',
        cursor: 'pointer',
        '&:hover': {
          borderColor: 'primary.main',
          boxShadow: 1,
        },
      }}
      onClick={onSelect}
    >
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
          <Checkbox
            checked={isSelected}
            sx={{ p: 0, mr: 2 }}
            color="primary"
          />
          <Box sx={{ flex: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
              {icon}
              <Typography variant="subtitle1" fontWeight="bold">
                {title}
              </Typography>
            </Box>
            <Typography variant="body2" color="text.secondary">
              {description}
            </Typography>
            {isSelected && children && (
              <Box sx={{ mt: 2 }} onClick={(e) => e.stopPropagation()}>
                {children}
              </Box>
            )}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

/**
 * Step 3: Schedule Configuration (TASK 160.4)
 */
const ScheduleStep: React.FC<StepContentProps> = ({ wizardState, updateState }) => {
  const handleScheduleTypeChange = (type: WizardState['syncSchedule']['type']) => {
    updateState({
      syncSchedule: {
        ...wizardState.syncSchedule,
        type,
      },
    });
  };

  const handleIntervalChange = (minutes: number) => {
    updateState({
      syncSchedule: {
        ...wizardState.syncSchedule,
        intervalMinutes: minutes,
      },
    });
  };

  const handleCronChange = (expression: string) => {
    updateState({
      syncSchedule: {
        ...wizardState.syncSchedule,
        cronExpression: expression,
      },
    });
  };

  // Common interval presets
  const intervalPresets = [
    { label: 'Every hour', value: 60 },
    { label: 'Every 6 hours', value: 360 },
    { label: 'Every 12 hours', value: 720 },
    { label: 'Daily', value: 1440 },
    { label: 'Weekly', value: 10080 },
  ];

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Configure Sync Schedule
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Choose how often feeds should be synchronized to keep your detection rules up to date.
        More frequent syncs ensure you have the latest rules but may use more resources.
      </Typography>

      <ScheduleOption
        value="manual"
        currentValue={wizardState.syncSchedule.type}
        title="Manual Only"
        description="Feeds will only sync when manually triggered. Best for testing or low-resource environments."
        icon={<RuleIcon color={wizardState.syncSchedule.type === 'manual' ? 'primary' : 'action'} />}
        onSelect={() => handleScheduleTypeChange('manual')}
      />

      <ScheduleOption
        value="interval"
        currentValue={wizardState.syncSchedule.type}
        title="Scheduled Interval"
        description="Automatically sync feeds at regular intervals. Recommended for most deployments."
        icon={<CloudDownloadIcon color={wizardState.syncSchedule.type === 'interval' ? 'primary' : 'action'} />}
        onSelect={() => handleScheduleTypeChange('interval')}
      >
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
          {intervalPresets.map((preset) => (
            <Chip
              key={preset.value}
              label={preset.label}
              onClick={() => handleIntervalChange(preset.value)}
              color={wizardState.syncSchedule.intervalMinutes === preset.value ? 'primary' : 'default'}
              variant={wizardState.syncSchedule.intervalMinutes === preset.value ? 'filled' : 'outlined'}
              size="small"
            />
          ))}
        </Box>
        {wizardState.syncSchedule.intervalMinutes && (
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
            Feeds will sync every{' '}
            {wizardState.syncSchedule.intervalMinutes >= 1440
              ? `${Math.floor(wizardState.syncSchedule.intervalMinutes / 1440)} day(s)`
              : wizardState.syncSchedule.intervalMinutes >= 60
              ? `${Math.floor(wizardState.syncSchedule.intervalMinutes / 60)} hour(s)`
              : `${wizardState.syncSchedule.intervalMinutes} minute(s)`}
          </Typography>
        )}
      </ScheduleOption>

      <ScheduleOption
        value="cron"
        currentValue={wizardState.syncSchedule.type}
        title="Custom Cron Expression"
        description="Use a cron expression for precise scheduling. For advanced users."
        icon={<SecurityIcon color={wizardState.syncSchedule.type === 'cron' ? 'primary' : 'action'} />}
        onSelect={() => handleScheduleTypeChange('cron')}
      >
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
            Enter a cron expression (minute hour day-of-month month day-of-week)
          </Typography>
          <Box
            component="input"
            type="text"
            value={wizardState.syncSchedule.cronExpression || ''}
            onChange={(e) => handleCronChange(e.target.value)}
            placeholder="0 */6 * * *"
            sx={{
              width: '100%',
              p: 1.5,
              border: 1,
              borderColor: 'divider',
              borderRadius: 1,
              bgcolor: 'background.paper',
              fontFamily: 'monospace',
              fontSize: '0.875rem',
              '&:focus': {
                outline: 'none',
                borderColor: 'primary.main',
              },
            }}
          />
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
            Example: <code>0 */6 * * *</code> = Every 6 hours at minute 0
          </Typography>
        </Box>
      </ScheduleOption>

      <Alert severity="info" sx={{ mt: 2 }}>
        You can change the sync schedule later from the Settings page.
      </Alert>
    </Box>
  );
};

/**
 * Step 4: Review & Confirm (TASK 160.4)
 */
interface ReviewStepProps extends StepContentProps {
  templates: FeedTemplate[];
}

const ReviewStep: React.FC<ReviewStepProps> = ({ wizardState, templates }) => {
  const selectedTemplates = wizardState.selectedTemplates
    .map((id) => templates.find((t) => t.id === id))
    .filter((t): t is FeedTemplate => t !== undefined);

  // Format schedule for display
  const getScheduleDescription = () => {
    switch (wizardState.syncSchedule.type) {
      case 'manual':
        return 'Manual only (no automatic syncing)';
      case 'interval':
        if (!wizardState.syncSchedule.intervalMinutes) return 'Interval (not configured)';
        const mins = wizardState.syncSchedule.intervalMinutes;
        if (mins >= 1440) return `Every ${Math.floor(mins / 1440)} day(s)`;
        if (mins >= 60) return `Every ${Math.floor(mins / 60)} hour(s)`;
        return `Every ${mins} minute(s)`;
      case 'cron':
        return `Custom cron: ${wizardState.syncSchedule.cronExpression || '(not configured)'}`;
      default:
        return 'Not configured';
    }
  };

  // Estimate total rules
  const estimatedRules = selectedTemplates.reduce((total, template) => {
    const match = template.description?.match(/(\d+)\+?\s*rules?/i);
    return total + (match ? parseInt(match[1], 10) : 0);
  }, 0);

  return (
    <Box>
      <Box sx={{ textAlign: 'center', mb: 3 }}>
        <CheckCircleOutlineIcon sx={{ fontSize: 48, color: 'success.main', mb: 1 }} />
        <Typography variant="h6" gutterBottom>
          Review Your Configuration
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Please review your selections before completing the setup.
        </Typography>
      </Box>

      {/* Selected Feeds Section */}
      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <RuleIcon color="primary" />
            <Typography variant="subtitle1" fontWeight="bold">
              Selected Feeds ({selectedTemplates.length})
            </Typography>
          </Box>
          {selectedTemplates.length > 0 ? (
            <>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                {selectedTemplates.map((template) => (
                  <Box
                    key={template.id}
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      p: 1.5,
                      bgcolor: 'background.default',
                      borderRadius: 1,
                    }}
                  >
                    <Typography variant="body2">{template.name}</Typography>
                    <Chip
                      label={template.type}
                      size="small"
                      variant="outlined"
                    />
                  </Box>
                ))}
              </Box>
              {estimatedRules > 0 && (
                <Alert severity="success" sx={{ mt: 2 }}>
                  Estimated total rules to import: <strong>{estimatedRules.toLocaleString()}+</strong>
                </Alert>
              )}
            </>
          ) : (
            <Alert severity="warning">
              No feeds selected. You can add feeds later from the Settings page.
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Sync Schedule Section */}
      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <CloudDownloadIcon color="primary" />
            <Typography variant="subtitle1" fontWeight="bold">
              Sync Schedule
            </Typography>
          </Box>
          <Box
            sx={{
              p: 1.5,
              bgcolor: 'background.default',
              borderRadius: 1,
            }}
          >
            <Typography variant="body2">{getScheduleDescription()}</Typography>
          </Box>
        </CardContent>
      </Card>

      {/* What happens next */}
      <Alert severity="info">
        <Typography variant="subtitle2" gutterBottom>
          What happens when you click "Finish Setup":
        </Typography>
        <Box component="ul" sx={{ m: 0, pl: 2 }}>
          <Typography component="li" variant="body2">
            {selectedTemplates.length} feed(s) will be created with your configuration
          </Typography>
          <Typography component="li" variant="body2">
            Initial synchronization will begin to import rules
          </Typography>
          <Typography component="li" variant="body2">
            The setup wizard will close and you can start using Cerberus
          </Typography>
        </Box>
      </Alert>
    </Box>
  );
};

/**
 * Step 5: Completion & Summary (TASK 160.5)
 */
interface CompletionStepProps extends StepContentProps {
  templates: FeedTemplate[];
}

const CompletionStep: React.FC<CompletionStepProps> = ({ wizardState, templates }) => {
  // Get selected templates for summary
  const selectedTemplates = wizardState.selectedTemplates
    .map((id) => templates.find((t) => t.id === id))
    .filter((t): t is FeedTemplate => t !== undefined);

  // Estimate total rules
  const estimatedRules = selectedTemplates.reduce((total, template) => {
    const match = template.description?.match(/(\d+)\+?\s*rules?/i);
    return total + (match ? parseInt(match[1], 10) : 0);
  }, 0);

  // Format schedule for display
  const getScheduleDescription = () => {
    switch (wizardState.syncSchedule.type) {
      case 'manual':
        return 'Manual sync only';
      case 'interval':
        if (!wizardState.syncSchedule.intervalMinutes) return 'Scheduled interval';
        const mins = wizardState.syncSchedule.intervalMinutes;
        if (mins >= 1440) return `Sync every ${Math.floor(mins / 1440)} day(s)`;
        if (mins >= 60) return `Sync every ${Math.floor(mins / 60)} hour(s)`;
        return `Sync every ${mins} minute(s)`;
      case 'cron':
        return 'Custom schedule';
      default:
        return 'Not configured';
    }
  };

  // Show progress during sync
  if (wizardState.syncProgress) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <CircularProgress size={60} sx={{ mb: 3 }} />
        <Typography variant="h6" gutterBottom>
          Syncing Feeds...
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Syncing feed {wizardState.syncProgress.current} of {wizardState.syncProgress.total}
        </Typography>
        {wizardState.syncProgress.currentFeed && (
          <Chip
            label={wizardState.syncProgress.currentFeed}
            color="primary"
            variant="outlined"
          />
        )}
      </Box>
    );
  }

  return (
    <Box>
      {/* Success Header */}
      <Box sx={{ textAlign: 'center', mb: 4 }}>
        <CheckCircleOutlineIcon sx={{ fontSize: 72, color: 'success.main', mb: 2 }} />
        <Typography variant="h5" gutterBottom>
          Setup Complete!
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Your Cerberus SIEM is ready to detect threats.
        </Typography>
      </Box>

      {/* Summary Statistics */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={4}>
          <Card variant="outlined" sx={{ textAlign: 'center', py: 2 }}>
            <Typography variant="h4" color="primary.main">
              {selectedTemplates.length}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Feed{selectedTemplates.length !== 1 ? 's' : ''} Configured
            </Typography>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card variant="outlined" sx={{ textAlign: 'center', py: 2 }}>
            <Typography variant="h4" color="primary.main">
              {estimatedRules > 0 ? `${(estimatedRules / 1000).toFixed(1)}k+` : '0'}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Rules Available
            </Typography>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card variant="outlined" sx={{ textAlign: 'center', py: 2 }}>
            <SecurityIcon sx={{ fontSize: 32, color: 'primary.main', mb: 0.5 }} />
            <Typography variant="body2" color="text.secondary">
              {getScheduleDescription()}
            </Typography>
          </Card>
        </Grid>
      </Grid>

      {/* What's Next */}
      <Alert severity="success" sx={{ mb: 2 }}>
        <Typography variant="subtitle2" gutterBottom>
          What happens when you finish:
        </Typography>
        <Box component="ul" sx={{ m: 0, pl: 2 }}>
          <Typography component="li" variant="body2">
            Your feed configuration will be saved
          </Typography>
          <Typography component="li" variant="body2">
            You can trigger the initial sync from the Feeds settings
          </Typography>
          <Typography component="li" variant="body2">
            Start monitoring your security events on the Dashboard
          </Typography>
        </Box>
      </Alert>

      {/* Tips */}
      <Box sx={{ p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
        <Typography variant="subtitle2" gutterBottom>
          Quick Tips:
        </Typography>
        <Typography variant="body2" color="text.secondary">
          - Navigate to <strong>Settings &gt; Feeds</strong> to manage your rule feeds
        </Typography>
        <Typography variant="body2" color="text.secondary">
          - Use the <strong>Rules</strong> page to view and manage individual detection rules
        </Typography>
        <Typography variant="body2" color="text.secondary">
          - Check the <strong>Dashboard</strong> for real-time security insights
        </Typography>
      </Box>
    </Box>
  );
};

// ============================================================================
// Main Component
// ============================================================================

export interface FeedSetupWizardProps {
  /** Force the wizard to show (for reopening from settings) */
  forceOpen?: boolean;
  /** Callback when wizard is closed */
  onClose?: () => void;
}

export function FeedSetupWizard({ forceOpen = false, onClose }: FeedSetupWizardProps) {
  const queryClient = useQueryClient();
  const [isOpen, setIsOpen] = useState(false);
  const [wizardState, setWizardState] = useState<WizardState>(DEFAULT_STATE);
  const [hasCheckedFirstRun, setHasCheckedFirstRun] = useState(false);

  // Check first-run status from API
  const { data: isFirstRun, isLoading: checkingFirstRun } = useQuery({
    queryKey: ['system', 'firstRun'],
    queryFn: () => api.system.checkFirstRun(),
    staleTime: Infinity, // Only check once per session
    retry: false,
    enabled: !forceOpen && !hasCheckedFirstRun,
  });

  // Fetch feed templates (TASK 160.3)
  const {
    data: templates = [],
    isLoading: loadingTemplates,
    error: templatesError,
  } = useQuery({
    queryKey: ['feeds', 'templates'],
    queryFn: () => api.feeds.getTemplates(),
    enabled: isOpen,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  // Complete setup mutation
  const completeSetupMutation = useMutation({
    mutationFn: (skipped: boolean) => api.system.completeSetup(skipped),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system', 'firstRun'] });
      clearStoredState();
      setIsOpen(false);
      onClose?.();
    },
  });

  // Load state from localStorage
  const loadStoredState = useCallback((): WizardState => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        return { ...DEFAULT_STATE, ...JSON.parse(stored) };
      }
    } catch (error) {
      console.warn('Failed to load wizard state from localStorage:', error);
    }
    return DEFAULT_STATE;
  }, []);

  // Save state to localStorage
  const saveState = useCallback((state: WizardState) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (error) {
      console.warn('Failed to save wizard state to localStorage:', error);
    }
  }, []);

  // Clear stored state
  const clearStoredState = useCallback(() => {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (error) {
      console.warn('Failed to clear wizard state from localStorage:', error);
    }
  }, []);

  // Update wizard state
  const updateState = useCallback(
    (updates: Partial<WizardState>) => {
      setWizardState((prev) => {
        const newState = { ...prev, ...updates };
        saveState(newState);
        return newState;
      });
    },
    [saveState]
  );

  // Handle step change
  const handleStepChange = useCallback(
    (step: number) => {
      updateState({
        currentStep: step,
        completedSteps: [...new Set([...wizardState.completedSteps, wizardState.currentStep])],
      });
    },
    [updateState, wizardState.completedSteps, wizardState.currentStep]
  );

  // Handle wizard completion
  const handleComplete = useCallback(() => {
    completeSetupMutation.mutate(false);
  }, [completeSetupMutation]);

  // Handle wizard skip/cancel
  const handleSkip = useCallback(() => {
    completeSetupMutation.mutate(true);
  }, [completeSetupMutation]);

  // Handle dialog close
  const handleClose = useCallback(() => {
    // Don't allow closing by clicking outside during processing
    if (completeSetupMutation.isPending) return;
    handleSkip();
  }, [completeSetupMutation.isPending, handleSkip]);

  // Initialize wizard state and check if should show
  useEffect(() => {
    if (forceOpen) {
      setWizardState(loadStoredState());
      setIsOpen(true);
      return;
    }

    if (!checkingFirstRun && isFirstRun !== undefined) {
      setHasCheckedFirstRun(true);
      if (isFirstRun) {
        setWizardState(loadStoredState());
        setIsOpen(true);
      }
    }
  }, [forceOpen, isFirstRun, checkingFirstRun, loadStoredState]);

  // Validation for template selection step (TASK 160.3)
  const validateTemplateSelection = useCallback((): string | null => {
    if (wizardState.selectedTemplates.length === 0) {
      return 'Please select at least one feed template to continue.';
    }
    return null;
  }, [wizardState.selectedTemplates]);

  // Define wizard steps
  const steps: WizardStep[] = [
    {
      label: 'Welcome',
      description: 'Introduction to Cerberus setup',
      content: <WelcomeStep wizardState={wizardState} updateState={updateState} />,
    },
    {
      label: 'Select Feeds',
      description: 'Choose rule feed templates',
      content: (
        <TemplateSelectionStep
          wizardState={wizardState}
          updateState={updateState}
          templates={templates}
          isLoading={loadingTemplates}
          error={templatesError as Error | null}
        />
      ),
      validate: validateTemplateSelection,
      optional: true, // Allow skipping validation if user wants to skip
    },
    {
      label: 'Schedule',
      description: 'Configure sync schedule',
      content: <ScheduleStep wizardState={wizardState} updateState={updateState} />,
      optional: true,
    },
    {
      label: 'Review',
      description: 'Confirm your selections',
      content: (
        <ReviewStep
          wizardState={wizardState}
          updateState={updateState}
          templates={templates}
        />
      ),
    },
    {
      label: 'Complete',
      description: 'Finish setup',
      content: (
        <CompletionStep
          wizardState={wizardState}
          updateState={updateState}
          templates={templates}
        />
      ),
    },
  ];

  // Don't render if checking or not open
  if (!isOpen) {
    return null;
  }

  return (
    <Dialog
      open={isOpen}
      onClose={handleClose}
      maxWidth="md"
      fullWidth
      disableEscapeKeyDown={completeSetupMutation.isPending}
      PaperProps={{
        sx: { height: '80vh', maxHeight: 700 },
      }}
    >
      <DialogTitle sx={{ m: 0, p: 2, display: 'flex', alignItems: 'center' }}>
        <Typography variant="h6" component="span" sx={{ flex: 1 }}>
          Feed Setup Wizard
        </Typography>
        <IconButton
          aria-label="close"
          onClick={handleSkip}
          disabled={completeSetupMutation.isPending}
          sx={{ color: 'text.secondary' }}
        >
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      <DialogContent dividers sx={{ display: 'flex', flexDirection: 'column', p: 3 }}>
        {completeSetupMutation.isError && (
          <Alert severity="error" sx={{ mb: 2 }}>
            Failed to complete setup. Please try again.
          </Alert>
        )}
        <StepWizard
          steps={steps}
          activeStep={wizardState.currentStep}
          onStepChange={handleStepChange}
          onComplete={handleComplete}
          onCancel={handleSkip}
          completeButtonText="Finish Setup"
          cancelButtonText="Skip Wizard"
          loading={completeSetupMutation.isPending}
        />
      </DialogContent>
    </Dialog>
  );
}

export default FeedSetupWizard;
