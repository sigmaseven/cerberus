import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Typography,
  Alert,
  CircularProgress,
  Stack,
  Paper,
  Divider,
  IconButton,
  Tooltip,
  Skeleton,
} from '@mui/material';
import {
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineConnector,
  TimelineContent,
  TimelineDot,
  TimelineOppositeContent,
} from '@mui/lab';
import {
  Science as ExperimentalIcon,
  BugReport as TestIcon,
  CheckCircle as StableIcon,
  Warning as DeprecatedIcon,
  Archive as ArchivedIcon,
  PlayArrow as ActiveIcon,
  ArrowForward,
  TrendingUp,
  Block,
  ArchiveOutlined,
  Info,
  ExpandMore,
  ExpandLess,
  CalendarToday,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiService } from '../services/api';
import {
  LifecycleStatus,
  LifecycleHistoryEntry,
  Rule,
} from '../types';

interface RuleLifecyclePanelProps {
  ruleId: string;
  currentStatus: LifecycleStatus;
  onStatusChange?: (newStatus: LifecycleStatus) => void;
}

/**
 * RuleLifecyclePanel - Comprehensive lifecycle management for detection rules
 *
 * Features:
 * - Visual state diagram showing lifecycle progression
 * - Current status display with color coding
 * - Transition controls for status changes
 * - Deprecation dialog with reason and sunset date
 * - Timeline view of all lifecycle changes
 * - Full accessibility support
 *
 * Lifecycle Flow:
 * experimental → test → stable → (active OR deprecated) → archived
 */
export const RuleLifecyclePanel: React.FC<RuleLifecyclePanelProps> = ({
  ruleId,
  currentStatus,
  onStatusChange,
}) => {
  // State management
  const [deprecateDialogOpen, setDeprecateDialogOpen] = useState(false);
  const [archiveDialogOpen, setArchiveDialogOpen] = useState(false);
  const [deprecateReason, setDeprecateReason] = useState('');
  const [sunsetDate, setSunsetDate] = useState('');
  const [timelineExpanded, setTimelineExpanded] = useState(true);
  const [actionError, setActionError] = useState<string | null>(null);

  const queryClient = useQueryClient();

  // Fetch lifecycle history
  const {
    data: history,
    isLoading: historyLoading,
    error: historyError,
  } = useQuery<LifecycleHistoryEntry[]>({
    queryKey: ['rule-lifecycle-history', ruleId],
    queryFn: () => apiService.getRuleLifecycleHistory(ruleId),
    enabled: !!ruleId,
  });

  // Transition mutation
  const transitionMutation = useMutation({
    mutationFn: (request: { status: LifecycleStatus; comment?: string }) =>
      apiService.transitionRuleLifecycle(ruleId, request),
    onSuccess: (data) => {
      // Invalidate queries to refresh data
      queryClient.invalidateQueries({ queryKey: ['rule-lifecycle-history', ruleId] });
      queryClient.invalidateQueries({ queryKey: ['rule', ruleId] });
      queryClient.invalidateQueries({ queryKey: ['rules'] });

      // Call parent callback with safe type guard
      if (onStatusChange && data.rule && 'lifecycle_status' in data.rule) {
        const newStatus = (data.rule as Rule).lifecycle_status || currentStatus;
        onStatusChange(newStatus);
      }

      // Close dialogs
      setDeprecateDialogOpen(false);
      setArchiveDialogOpen(false);
      setDeprecateReason('');
      setSunsetDate('');
      setActionError(null);
    },
    onError: (error: Error) => {
      setActionError(error?.message || 'Failed to transition lifecycle status');
    },
  });

  // Reset error when dialog closes
  useEffect(() => {
    if (!deprecateDialogOpen && !archiveDialogOpen) {
      setActionError(null);
    }
  }, [deprecateDialogOpen, archiveDialogOpen]);

  /**
   * Get status color for visual coding
   */
  const getStatusColor = (
    status: LifecycleStatus
  ): 'success' | 'primary' | 'warning' | 'error' | 'default' => {
    switch (status) {
      case 'stable':
      case 'active':
        return 'success';
      case 'test':
        return 'primary';
      case 'experimental':
        return 'warning';
      case 'deprecated':
        return 'error';
      default:
        return 'default';
    }
  };

  /**
   * Get icon for each status
   */
  const getStatusIcon = (status: LifecycleStatus) => {
    switch (status) {
      case 'experimental':
        return <ExperimentalIcon />;
      case 'test':
        return <TestIcon />;
      case 'stable':
        return <StableIcon />;
      case 'deprecated':
        return <DeprecatedIcon />;
      case 'active':
        return <ActiveIcon />;
      default:
        return <Info />;
    }
  };

  /**
   * Get formatted status label
   */
  const getStatusLabel = (status: LifecycleStatus): string => {
    return status.charAt(0).toUpperCase() + status.slice(1);
  };

  /**
   * Determine valid transitions from current status
   */
  const getValidTransitions = (): LifecycleStatus[] => {
    switch (currentStatus) {
      case 'experimental':
        return ['test', 'deprecated', 'active'];
      case 'test':
        return ['stable', 'experimental', 'deprecated', 'active'];
      case 'stable':
        return ['active', 'deprecated'];
      case 'deprecated':
        return ['active', 'archived'];
      case 'active':
        return ['deprecated'];
      default:
        return [];
    }
  };

  /**
   * Check if transition is valid
   */
  const canTransitionTo = (targetStatus: LifecycleStatus): boolean => {
    return getValidTransitions().includes(targetStatus);
  };

  /**
   * Handle promote action (experimental→test, test→stable, stable→active)
   */
  const handlePromote = () => {
    let targetStatus: LifecycleStatus;

    if (currentStatus === 'experimental') {
      targetStatus = 'test';
    } else if (currentStatus === 'test') {
      targetStatus = 'stable';
    } else if (currentStatus === 'stable') {
      targetStatus = 'active';
    } else {
      return; // Invalid state for promotion
    }

    transitionMutation.mutate({
      status: targetStatus,
      comment: `Promoted from ${currentStatus} to ${targetStatus}`,
    });
  };

  /**
   * Handle activate action (quick transition to active)
   */
  const handleActivate = () => {
    if (!canTransitionTo('active')) return;

    transitionMutation.mutate({
      status: 'active',
      comment: 'Activated for production use',
    });
  };

  /**
   * Handle deprecate action (with dialog)
   */
  const handleDeprecate = () => {
    if (!deprecateReason.trim()) {
      setActionError('Deprecation reason is required');
      return;
    }

    const comment = sunsetDate
      ? `Deprecated: ${deprecateReason.trim()} (Sunset date: ${sunsetDate})`
      : `Deprecated: ${deprecateReason.trim()}`;

    transitionMutation.mutate({
      status: 'deprecated',
      comment,
    });
  };

  /**
   * Handle archive action (with confirmation)
   */
  const handleArchive = () => {
    transitionMutation.mutate({
      status: 'archived',
      comment: 'Archived - no longer in use',
    });
  };

  /**
   * Calculate time in current status
   */
  const getTimeInStatus = (): string => {
    if (!history || history.length === 0) return 'Unknown';

    const lastChange = history[0]; // Most recent is first
    const changeDate = new Date(lastChange.timestamp);
    const now = new Date();
    const diffMs = now.getTime() - changeDate.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return '1 day';
    if (diffDays < 30) return `${diffDays} days`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)} months`;
    return `${Math.floor(diffDays / 365)} years`;
  };

  /**
   * Format timestamp for display
   */
  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return {
      time: date.toLocaleTimeString(),
      date: date.toLocaleDateString(),
    };
  };

  /**
   * Render state diagram
   */
  const renderStateDiagram = () => {
    const states: { status: LifecycleStatus; label: string }[] = [
      { status: 'experimental', label: 'Experimental' },
      { status: 'test', label: 'Test' },
      { status: 'stable', label: 'Stable' },
      { status: 'active', label: 'Active' },
    ];

    return (
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 1,
          flexWrap: 'wrap',
          mb: 3,
        }}
        role="img"
        aria-label="Rule lifecycle state diagram"
      >
        {states.map((state, index) => (
          <React.Fragment key={state.status}>
            <Tooltip title={`${state.label} status`}>
              <Chip
                icon={getStatusIcon(state.status)}
                label={state.label}
                color={state.status === currentStatus ? getStatusColor(state.status) : 'default'}
                variant={state.status === currentStatus ? 'filled' : 'outlined'}
                sx={{
                  fontWeight: state.status === currentStatus ? 'bold' : 'normal',
                  cursor: canTransitionTo(state.status) ? 'pointer' : 'default',
                  '&:hover': canTransitionTo(state.status)
                    ? {
                        transform: 'scale(1.05)',
                        boxShadow: 2,
                      }
                    : {},
                  transition: 'all 0.2s',
                }}
                onClick={() => {
                  if (canTransitionTo(state.status)) {
                    if (state.status === 'deprecated') {
                      setDeprecateDialogOpen(true);
                    } else {
                      transitionMutation.mutate({
                        status: state.status,
                        comment: `Transitioned to ${state.status}`,
                      });
                    }
                  }
                }}
                aria-current={state.status === currentStatus}
                aria-label={`${state.label} status${state.status === currentStatus ? ' - current' : ''}`}
              />
            </Tooltip>
            {index < states.length - 1 && (
              <ArrowForward
                sx={{
                  color: 'text.secondary',
                  opacity: 0.5,
                }}
                aria-hidden="true"
              />
            )}
          </React.Fragment>
        ))}

        {/* Show deprecated state separately */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, ml: 2 }}>
          <Divider orientation="vertical" flexItem sx={{ mx: 1 }} />
          <Tooltip title="Deprecated status">
            <Chip
              icon={<DeprecatedIcon />}
              label="Deprecated"
              color={currentStatus === 'deprecated' ? 'error' : 'default'}
              variant={currentStatus === 'deprecated' ? 'filled' : 'outlined'}
              sx={{
                fontWeight: currentStatus === 'deprecated' ? 'bold' : 'normal',
                cursor: canTransitionTo('deprecated') ? 'pointer' : 'default',
                '&:hover': canTransitionTo('deprecated')
                  ? {
                      transform: 'scale(1.05)',
                      boxShadow: 2,
                    }
                  : {},
                transition: 'all 0.2s',
              }}
              onClick={() => {
                if (canTransitionTo('deprecated')) {
                  setDeprecateDialogOpen(true);
                }
              }}
              aria-current={currentStatus === 'deprecated'}
              aria-label={`Deprecated status${currentStatus === 'deprecated' ? ' - current' : ''}`}
            />
          </Tooltip>
          <ArrowForward sx={{ color: 'text.secondary', opacity: 0.5 }} aria-hidden="true" />
          <Tooltip title="Archived status">
            <Chip
              icon={<ArchivedIcon />}
              label="Archived"
              color={currentStatus === 'archived' ? 'default' : 'default'}
              variant={currentStatus === 'archived' ? 'filled' : 'outlined'}
              disabled={!canTransitionTo('archived')}
              aria-label={`Archived status${currentStatus === 'archived' ? ' - current' : ''}`}
            />
          </Tooltip>
        </Box>
      </Box>
    );
  };

  return (
    <Box>
      {/* Current Status Display */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Current Lifecycle Status
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <Chip
              icon={getStatusIcon(currentStatus)}
              label={getStatusLabel(currentStatus)}
              color={getStatusColor(currentStatus)}
              size="large"
              sx={{
                fontSize: '1.1rem',
                fontWeight: 'bold',
                py: 3,
                px: 2,
              }}
              aria-label={`Current status: ${getStatusLabel(currentStatus)}`}
            />
            <Typography variant="body2" color="text.secondary">
              Time in status: <strong>{getTimeInStatus()}</strong>
            </Typography>
          </Box>

          {/* State Diagram */}
          {renderStateDiagram()}

          {/* Transition Controls */}
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {/* Promote Button */}
            {(currentStatus === 'experimental' ||
              currentStatus === 'test' ||
              currentStatus === 'stable') && (
              <Button
                variant="contained"
                color="primary"
                startIcon={<TrendingUp />}
                onClick={handlePromote}
                disabled={transitionMutation.isPending}
                aria-label={`Promote from ${currentStatus} to next stage`}
              >
                Promote
              </Button>
            )}

            {/* Activate Button */}
            {canTransitionTo('active') && currentStatus !== 'active' && (
              <Button
                variant="contained"
                color="success"
                startIcon={<ActiveIcon />}
                onClick={handleActivate}
                disabled={transitionMutation.isPending}
                aria-label="Activate rule for production"
              >
                Activate
              </Button>
            )}

            {/* Deprecate Button */}
            {canTransitionTo('deprecated') && (
              <Button
                variant="outlined"
                color="error"
                startIcon={<Block />}
                onClick={() => setDeprecateDialogOpen(true)}
                disabled={transitionMutation.isPending}
                aria-label="Deprecate rule"
              >
                Deprecate
              </Button>
            )}

            {/* Archive Button */}
            {canTransitionTo('archived') && (
              <Button
                variant="outlined"
                color="warning"
                startIcon={<ArchiveOutlined />}
                onClick={() => setArchiveDialogOpen(true)}
                disabled={transitionMutation.isPending}
                aria-label="Archive rule"
              >
                Archive
              </Button>
            )}
          </Stack>

          {/* Action feedback */}
          {transitionMutation.isPending && (
            <Alert severity="info" sx={{ mt: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CircularProgress size={16} />
                <Typography variant="body2">Updating lifecycle status...</Typography>
              </Box>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Lifecycle History Timeline */}
      <Card>
        <CardContent>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              mb: 2,
            }}
          >
            <Typography variant="h6">Lifecycle History</Typography>
            <IconButton
              onClick={() => setTimelineExpanded(!timelineExpanded)}
              aria-label={timelineExpanded ? 'Collapse timeline' : 'Expand timeline'}
              aria-expanded={timelineExpanded}
            >
              {timelineExpanded ? <ExpandLess /> : <ExpandMore />}
            </IconButton>
          </Box>

          {timelineExpanded && (
            <>
              {historyLoading && (
                <Box sx={{ py: 3 }}>
                  <Skeleton variant="rectangular" height={80} sx={{ mb: 2 }} />
                  <Skeleton variant="rectangular" height={80} sx={{ mb: 2 }} />
                  <Skeleton variant="rectangular" height={80} />
                </Box>
              )}

              {historyError && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  Failed to load lifecycle history: {(historyError as Error).message}
                </Alert>
              )}

              {!historyLoading && !historyError && (!history || history.length === 0) && (
                <Box sx={{ py: 3, textAlign: 'center', color: 'text.secondary' }}>
                  <Info sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                  <Typography variant="body2">No lifecycle history available</Typography>
                </Box>
              )}

              {!historyLoading && !historyError && history && history.length > 0 && (
                <Timeline position="right">
                  {history.map((entry, index) => {
                    const timestamp = formatTimestamp(entry.timestamp);
                    const isLast = index === history.length - 1;

                    return (
                      <TimelineItem key={entry.timestamp + `-${index}`}>
                        <TimelineOppositeContent
                          color="text.secondary"
                          sx={{ flex: 0.2, py: 2 }}
                        >
                          <Typography variant="body2" fontWeight="bold">
                            {timestamp.time}
                          </Typography>
                          <Typography variant="caption">{timestamp.date}</Typography>
                        </TimelineOppositeContent>

                        <TimelineSeparator>
                          <TimelineDot
                            color={getStatusColor(entry.to_status)}
                            variant={index === 0 ? 'filled' : 'outlined'}
                          >
                            {getStatusIcon(entry.to_status)}
                          </TimelineDot>
                          {!isLast && <TimelineConnector />}
                        </TimelineSeparator>

                        <TimelineContent sx={{ py: 2 }}>
                          <Paper elevation={index === 0 ? 3 : 1} sx={{ p: 2 }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                              <Chip
                                label={getStatusLabel(entry.from_status)}
                                size="small"
                                variant="outlined"
                                color={getStatusColor(entry.from_status)}
                              />
                              <Typography variant="body2" color="text.secondary">
                                →
                              </Typography>
                              <Chip
                                label={getStatusLabel(entry.to_status)}
                                size="small"
                                color={getStatusColor(entry.to_status)}
                              />
                            </Box>

                            <Typography
                              variant="body2"
                              color="text.secondary"
                              sx={{ mb: entry.comment ? 1 : 0 }}
                            >
                              Changed by: <strong>{entry.changed_by || 'System'}</strong>
                            </Typography>

                            {entry.comment && (
                              <Box
                                sx={{
                                  mt: 1,
                                  p: 1.5,
                                  backgroundColor: 'rgba(0, 0, 0, 0.03)',
                                  borderRadius: 1,
                                  borderLeft: 3,
                                  borderColor: getStatusColor(entry.to_status) + '.main',
                                }}
                              >
                                <Typography
                                  variant="caption"
                                  color="text.secondary"
                                  display="block"
                                  sx={{ mb: 0.5 }}
                                >
                                  Comment:
                                </Typography>
                                <Typography variant="body2">{entry.comment}</Typography>
                              </Box>
                            )}
                          </Paper>
                        </TimelineContent>
                      </TimelineItem>
                    );
                  })}
                </Timeline>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Deprecate Dialog */}
      <Dialog
        open={deprecateDialogOpen}
        onClose={() => {
          if (!transitionMutation.isPending) {
            setDeprecateDialogOpen(false);
            setDeprecateReason('');
            setSunsetDate('');
            setActionError(null);
          }
        }}
        maxWidth="sm"
        fullWidth
        aria-labelledby="deprecate-dialog-title"
      >
        <DialogTitle id="deprecate-dialog-title">
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <DeprecatedIcon color="error" />
            <Typography variant="h6">Deprecate Rule</Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="body2">
              Deprecating this rule will mark it as no longer recommended for use. Active alerts
              will continue to fire, but analysts will be notified of the deprecation status.
            </Typography>
          </Alert>

          {actionError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {actionError}
            </Alert>
          )}

          <TextField
            label="Deprecation Reason"
            placeholder="Explain why this rule is being deprecated..."
            multiline
            rows={4}
            fullWidth
            required
            value={deprecateReason}
            onChange={(e) => setDeprecateReason(e.target.value)}
            sx={{ mb: 2 }}
            disabled={transitionMutation.isPending}
            inputProps={{
              'aria-label': 'Deprecation reason',
              'aria-required': true,
            }}
          />

          <TextField
            label="Sunset Date (Optional)"
            type="date"
            fullWidth
            value={sunsetDate}
            onChange={(e) => setSunsetDate(e.target.value)}
            InputLabelProps={{ shrink: true }}
            disabled={transitionMutation.isPending}
            helperText="Optional: Specify when this rule will be archived"
            InputProps={{
              startAdornment: <CalendarToday sx={{ mr: 1, color: 'text.secondary' }} />,
            }}
            inputProps={{
              'aria-label': 'Sunset date',
              min: new Date().toISOString().split('T')[0],
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setDeprecateDialogOpen(false);
              setDeprecateReason('');
              setSunsetDate('');
              setActionError(null);
            }}
            disabled={transitionMutation.isPending}
          >
            Cancel
          </Button>
          <Button
            onClick={handleDeprecate}
            variant="contained"
            color="error"
            disabled={!deprecateReason.trim() || transitionMutation.isPending}
            startIcon={transitionMutation.isPending ? <CircularProgress size={16} /> : null}
          >
            {transitionMutation.isPending ? 'Deprecating...' : 'Deprecate Rule'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Archive Dialog */}
      <Dialog
        open={archiveDialogOpen}
        onClose={() => {
          if (!transitionMutation.isPending) {
            setArchiveDialogOpen(false);
            setActionError(null);
          }
        }}
        maxWidth="sm"
        fullWidth
        aria-labelledby="archive-dialog-title"
      >
        <DialogTitle id="archive-dialog-title">
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ArchivedIcon color="warning" />
            <Typography variant="h6">Archive Rule</Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>
              Are you sure you want to archive this rule?
            </Typography>
            <Typography variant="body2">
              Archiving will permanently disable this rule and stop all alert generation. This
              action is typically performed after a rule has been deprecated and is no longer
              needed.
            </Typography>
          </Alert>

          {actionError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {actionError}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setArchiveDialogOpen(false);
              setActionError(null);
            }}
            disabled={transitionMutation.isPending}
          >
            Cancel
          </Button>
          <Button
            onClick={handleArchive}
            variant="contained"
            color="warning"
            disabled={transitionMutation.isPending}
            startIcon={transitionMutation.isPending ? <CircularProgress size={16} /> : null}
          >
            {transitionMutation.isPending ? 'Archiving...' : 'Archive Rule'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default RuleLifecyclePanel;
