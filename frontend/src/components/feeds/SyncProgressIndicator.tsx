/**
 * SyncProgressIndicator Component (Task 156.4)
 * Shows real-time sync progress for SIGMA rule feeds
 */

import { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  LinearProgress,
  Paper,
  Collapse,
  IconButton,
  Chip,
  Alert,
  List,
  ListItem,
  Divider,
} from '@mui/material';
import {
  Sync as SyncIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Schedule as ScheduleIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  CloudDownload as DownloadIcon,
  Rule as RuleIcon,
} from '@mui/icons-material';
import type { FeedSyncResult } from '../../types';

interface SyncOperation {
  feedId: string;
  feedName: string;
  status: 'pending' | 'syncing' | 'completed' | 'error';
  progress?: number;
  message?: string;
  result?: FeedSyncResult;
  startedAt: Date;
  completedAt?: Date;
}

interface SyncProgressIndicatorProps {
  operations: SyncOperation[];
  onDismiss?: (feedId: string) => void;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

/**
 * Format duration from start time
 */
const formatElapsedTime = (startedAt: Date, completedAt?: Date): string => {
  const endTime = completedAt || new Date();
  const diffMs = endTime.getTime() - startedAt.getTime();
  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);

  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
};

/**
 * Get status icon based on operation state
 */
const getStatusIcon = (status: SyncOperation['status']) => {
  switch (status) {
    case 'pending':
      return <ScheduleIcon color="action" />;
    case 'syncing':
      return <SyncIcon color="primary" className="sync-spin" />;
    case 'completed':
      return <CheckCircleIcon color="success" />;
    case 'error':
      return <ErrorIcon color="error" />;
    default:
      return <SyncIcon />;
  }
};

/**
 * Get status color
 */
const getStatusColor = (status: SyncOperation['status']): 'default' | 'primary' | 'success' | 'error' => {
  switch (status) {
    case 'pending':
      return 'default';
    case 'syncing':
      return 'primary';
    case 'completed':
      return 'success';
    case 'error':
      return 'error';
    default:
      return 'default';
  }
};

/**
 * Single sync operation item
 */
function SyncOperationItem({
  operation,
  onDismiss,
}: {
  operation: SyncOperation;
  onDismiss?: (feedId: string) => void;
}) {
  const [showDetails, setShowDetails] = useState(false);
  const [elapsedTime, setElapsedTime] = useState(
    formatElapsedTime(operation.startedAt, operation.completedAt)
  );

  // Update elapsed time every second while syncing
  useEffect(() => {
    if (operation.status === 'syncing') {
      const interval = setInterval(() => {
        setElapsedTime(formatElapsedTime(operation.startedAt));
      }, 1000);
      return () => clearInterval(interval);
    } else if (operation.completedAt) {
      setElapsedTime(formatElapsedTime(operation.startedAt, operation.completedAt));
    }
  }, [operation.status, operation.startedAt, operation.completedAt]);

  return (
    <Box sx={{ py: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        {getStatusIcon(operation.status)}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="body2" fontWeight="medium" noWrap>
              {operation.feedName}
            </Typography>
            <Chip
              label={operation.status}
              color={getStatusColor(operation.status)}
              size="small"
              sx={{ height: 20 }}
            />
            <Typography variant="caption" color="text.secondary">
              {elapsedTime}
            </Typography>
          </Box>
          {operation.message && (
            <Typography variant="caption" color="text.secondary">
              {operation.message}
            </Typography>
          )}
        </Box>
        {operation.result && (
          <IconButton
            size="small"
            onClick={() => setShowDetails(!showDetails)}
            aria-label={showDetails ? 'Hide details' : 'Show details'}
          >
            {showDetails ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </IconButton>
        )}
        {(operation.status === 'completed' || operation.status === 'error') && onDismiss && (
          <IconButton
            size="small"
            onClick={() => onDismiss(operation.feedId)}
            aria-label="Dismiss"
          >
            <ErrorIcon fontSize="small" />
          </IconButton>
        )}
      </Box>

      {/* Progress bar for syncing operations */}
      {operation.status === 'syncing' && (
        <LinearProgress
          variant={operation.progress !== undefined ? 'determinate' : 'indeterminate'}
          value={operation.progress}
          sx={{ mt: 1, borderRadius: 1 }}
        />
      )}

      {/* Details section */}
      <Collapse in={showDetails && !!operation.result}>
        <Box sx={{ mt: 1, pl: 4 }}>
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            <Chip
              icon={<DownloadIcon />}
              label={`Imported: ${operation.result?.stats?.imported_rules ?? 0}`}
              size="small"
              color="success"
              variant="outlined"
            />
            <Chip
              icon={<RuleIcon />}
              label={`Updated: ${operation.result?.stats?.updated_rules ?? 0}`}
              size="small"
              color="info"
              variant="outlined"
            />
            <Chip
              icon={<ErrorIcon />}
              label={`Failed: ${operation.result?.stats?.failed_rules ?? 0}`}
              size="small"
              color={operation.result?.stats?.failed_rules ? 'error' : 'default'}
              variant="outlined"
            />
            <Chip
              label={`Skipped: ${operation.result?.stats?.skipped_rules ?? 0}`}
              size="small"
              variant="outlined"
            />
          </Box>
          {operation.result?.errors && operation.result.errors.length > 0 && (
            <Alert severity="warning" sx={{ mt: 1 }}>
              <Typography variant="caption">
                {operation.result.errors.length} error(s):
              </Typography>
              <List dense sx={{ py: 0 }}>
                {operation.result.errors.slice(0, 3).map((err, idx) => (
                  <ListItem key={idx} sx={{ py: 0 }}>
                    <Typography variant="caption" color="error">
                      {err}
                    </Typography>
                  </ListItem>
                ))}
                {operation.result.errors.length > 3 && (
                  <ListItem sx={{ py: 0 }}>
                    <Typography variant="caption">
                      ...and {operation.result.errors.length - 3} more
                    </Typography>
                  </ListItem>
                )}
              </List>
            </Alert>
          )}
        </Box>
      </Collapse>
    </Box>
  );
}

/**
 * Main SyncProgressIndicator component
 */
export default function SyncProgressIndicator({
  operations,
  onDismiss,
  collapsed = false,
  onToggleCollapse,
}: SyncProgressIndicatorProps) {
  if (operations.length === 0) {
    return null;
  }

  const activeOperations = operations.filter(op => op.status === 'syncing' || op.status === 'pending');
  const completedOperations = operations.filter(op => op.status === 'completed' || op.status === 'error');
  const hasErrors = operations.some(op => op.status === 'error');
  const allCompleted = activeOperations.length === 0 && completedOperations.length > 0;

  return (
    <Paper
      elevation={3}
      sx={{
        position: 'fixed',
        bottom: 16,
        right: 16,
        width: 400,
        maxWidth: 'calc(100vw - 32px)',
        zIndex: 1200,
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          px: 2,
          py: 1.5,
          bgcolor: hasErrors ? 'error.main' : allCompleted ? 'success.main' : 'primary.main',
          color: 'white',
          cursor: 'pointer',
        }}
        onClick={onToggleCollapse}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SyncIcon
            sx={{
              animation: activeOperations.length > 0 ? 'spin 1s linear infinite' : 'none',
              '@keyframes spin': {
                '0%': { transform: 'rotate(0deg)' },
                '100%': { transform: 'rotate(360deg)' },
              },
            }}
          />
          <Typography variant="subtitle2">
            {activeOperations.length > 0
              ? `Syncing ${activeOperations.length} feed${activeOperations.length > 1 ? 's' : ''}...`
              : hasErrors
              ? 'Sync completed with errors'
              : 'Sync completed'}
          </Typography>
        </Box>
        <IconButton size="small" sx={{ color: 'inherit' }}>
          {collapsed ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        </IconButton>
      </Box>

      {/* Overall progress */}
      {activeOperations.length > 0 && (
        <LinearProgress
          variant="indeterminate"
          sx={{ height: 3 }}
        />
      )}

      {/* Operations list */}
      <Collapse in={!collapsed}>
        <Box sx={{ maxHeight: 300, overflow: 'auto', px: 2, py: 1 }}>
          {/* Active operations */}
          {activeOperations.length > 0 && (
            <>
              {activeOperations.map(op => (
                <SyncOperationItem
                  key={op.feedId}
                  operation={op}
                  onDismiss={onDismiss}
                />
              ))}
              {completedOperations.length > 0 && <Divider sx={{ my: 1 }} />}
            </>
          )}

          {/* Completed operations */}
          {completedOperations.map(op => (
            <SyncOperationItem
              key={op.feedId}
              operation={op}
              onDismiss={onDismiss}
            />
          ))}
        </Box>
      </Collapse>

      {/* Summary footer */}
      {allCompleted && !collapsed && (
        <Box sx={{ px: 2, py: 1, bgcolor: 'grey.100' }}>
          <Typography variant="caption" color="text.secondary">
            {completedOperations.filter(op => op.status === 'completed').length} succeeded,{' '}
            {completedOperations.filter(op => op.status === 'error').length} failed
          </Typography>
        </Box>
      )}
    </Paper>
  );
}

/**
 * Hook for managing sync operations state
 */
// eslint-disable-next-line react-refresh/only-export-components
export function useSyncOperations() {
  const [operations, setOperations] = useState<SyncOperation[]>([]);
  const [collapsed, setCollapsed] = useState(false);

  const startSync = (feedId: string, feedName: string) => {
    setOperations(prev => {
      // Remove any existing operation for this feed
      const filtered = prev.filter(op => op.feedId !== feedId);
      return [
        ...filtered,
        {
          feedId,
          feedName,
          status: 'syncing' as const,
          startedAt: new Date(),
        },
      ];
    });
  };

  const updateProgress = (feedId: string, progress: number, message?: string) => {
    setOperations(prev =>
      prev.map(op =>
        op.feedId === feedId
          ? { ...op, progress, message }
          : op
      )
    );
  };

  const completeSync = (feedId: string, result: FeedSyncResult) => {
    setOperations(prev =>
      prev.map(op =>
        op.feedId === feedId
          ? {
              ...op,
              status: result.success ? 'completed' as const : 'error' as const,
              result,
              completedAt: new Date(),
            }
          : op
      )
    );
  };

  const dismissOperation = (feedId: string) => {
    setOperations(prev => prev.filter(op => op.feedId !== feedId));
  };

  const clearCompleted = () => {
    setOperations(prev => prev.filter(op => op.status === 'syncing' || op.status === 'pending'));
  };

  const toggleCollapse = () => {
    setCollapsed(prev => !prev);
  };

  return {
    operations,
    collapsed,
    startSync,
    updateProgress,
    completeSync,
    dismissOperation,
    clearCompleted,
    toggleCollapse,
  };
}
