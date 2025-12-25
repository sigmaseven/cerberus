/**
 * FeedStatsWidget.tsx (TASK 157.2)
 * Dashboard widget displaying SIGMA feed health and rule import statistics
 */
import { useQuery } from '@tanstack/react-query';
import { Link as RouterLink } from 'react-router-dom';
import { formatDistanceToNow } from 'date-fns';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  Alert,
  Skeleton,
  Button,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  RssFeed as FeedIcon,
  CheckCircle as HealthyIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
  Settings as SettingsIcon,
} from '@mui/icons-material';
import { apiService } from '../../../services/api';
import { FeedsSummary, FeedHealthStatus } from '../../../types';

// Constants - avoid magic numbers
const POLLING_INTERVAL_MS = 60000; // 60 seconds as per requirements
const GC_TIME_MS = 300000; // 5 minutes cache garbage collection

// Health status color and icon mapping
const HEALTH_COLORS: Record<FeedHealthStatus, 'success' | 'warning' | 'error'> = {
  healthy: 'success',
  warning: 'warning',
  error: 'error',
};

const HEALTH_ICONS: Record<FeedHealthStatus, React.ReactNode> = {
  healthy: <HealthyIcon fontSize="small" />,
  warning: <WarningIcon fontSize="small" />,
  error: <ErrorIcon fontSize="small" />,
};

const HEALTH_LABELS: Record<FeedHealthStatus, string> = {
  healthy: 'All Feeds Healthy',
  warning: 'Some Feeds Warning',
  error: 'Feed Errors Detected',
};

/**
 * Safe number formatting with fallback
 */
const safeNumber = (value: unknown, defaultValue = 0): number => {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) {
    return defaultValue;
  }
  return num;
};

/**
 * Format the last sync time as a relative string
 */
const formatLastSync = (lastSync: string | null): string => {
  if (!lastSync) {
    return 'Never synced';
  }
  try {
    const date = new Date(lastSync);
    if (isNaN(date.getTime())) {
      return 'Unknown';
    }
    return formatDistanceToNow(date, { addSuffix: true });
  } catch {
    return 'Unknown';
  }
};

function FeedStatsWidget() {
  // Fetch feed summary with optimized polling
  const { data, isLoading, error, refetch, isFetching } = useQuery<FeedsSummary>({
    queryKey: ['feedsSummary'],
    queryFn: () => apiService.feeds.getFeedsSummary(),
    refetchInterval: POLLING_INTERVAL_MS,
    refetchIntervalInBackground: false, // Stop polling when tab inactive
    gcTime: GC_TIME_MS,
  });

  // Loading state
  if (isLoading) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Box display="flex" alignItems="center" gap={1}>
              <FeedIcon color="primary" />
              <Typography variant="h6">Rule Sources</Typography>
            </Box>
            <Skeleton width={60} height={24} />
          </Box>
          <Skeleton variant="rectangular" height={60} sx={{ mb: 2 }} />
          <Box display="flex" justifyContent="space-between">
            <Skeleton width={80} height={50} />
            <Skeleton width={80} height={50} />
            <Skeleton width={80} height={50} />
          </Box>
        </CardContent>
      </Card>
    );
  }

  // Error state
  if (error) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Box display="flex" alignItems="center" gap={1}>
              <FeedIcon color="primary" />
              <Typography variant="h6">Rule Sources</Typography>
            </Box>
          </Box>
          <Alert
            severity="error"
            variant="outlined"
            action={
              <Button
                color="inherit"
                size="small"
                startIcon={<RefreshIcon />}
                onClick={() => refetch()}
              >
                Retry
              </Button>
            }
          >
            Failed to load feed data: {error instanceof Error ? error.message : 'Unknown error'}
          </Alert>
        </CardContent>
      </Card>
    );
  }

  // Default values for when data is undefined
  const summary: FeedsSummary = data ?? {
    total_feeds: 0,
    active_feeds: 0,
    total_rules: 0,
    last_sync: null,
    health_status: 'healthy',
    error_count: 0,
  };

  const healthStatus = summary.health_status as FeedHealthStatus;
  const healthColor = HEALTH_COLORS[healthStatus] ?? 'success';
  const healthIcon = HEALTH_ICONS[healthStatus] ?? <HealthyIcon fontSize="small" />;
  const healthLabel = HEALTH_LABELS[healthStatus] ?? 'Unknown';

  return (
    <Card>
      <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
        {/* Header */}
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Box display="flex" alignItems="center" gap={1}>
            <FeedIcon color="primary" />
            <Typography variant="h6">Rule Sources</Typography>
          </Box>
          <Box display="flex" alignItems="center" gap={0.5}>
            <Tooltip title="Refresh">
              <IconButton
                size="small"
                onClick={() => refetch()}
                disabled={isFetching}
                aria-label="Refresh feed statistics"
              >
                <RefreshIcon fontSize="small" sx={{ animation: isFetching ? 'spin 1s linear infinite' : 'none' }} />
              </IconButton>
            </Tooltip>
            <Tooltip title="Manage Feeds">
              <IconButton
                size="small"
                component={RouterLink}
                to="/settings?tab=feeds"
                aria-label="Go to feed settings"
              >
                <SettingsIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {/* Health Status Badge */}
        <Box mb={2}>
          <Chip
            icon={healthIcon}
            label={healthLabel}
            color={healthColor}
            size="small"
            aria-label={`Feed health status: ${healthStatus}`}
            sx={{ fontWeight: 500 }}
          />
          {summary.error_count > 0 && (
            <Typography
              variant="caption"
              color="error"
              sx={{ ml: 1 }}
            >
              ({summary.error_count} {summary.error_count === 1 ? 'feed' : 'feeds'} with errors)
            </Typography>
          )}
        </Box>

        {/* Summary Stats Grid */}
        <Box
          display="grid"
          gridTemplateColumns="repeat(3, 1fr)"
          gap={2}
          mb={2}
        >
          {/* Active Feeds */}
          <Box textAlign="center">
            <Typography variant="h5" color="primary" fontWeight={600}>
              {safeNumber(summary.active_feeds)}/{safeNumber(summary.total_feeds)}
            </Typography>
            <Typography variant="caption" color="textSecondary">
              Active Feeds
            </Typography>
          </Box>

          {/* Total Rules */}
          <Box textAlign="center">
            <Typography variant="h5" color="textPrimary" fontWeight={600}>
              {safeNumber(summary.total_rules).toLocaleString()}
            </Typography>
            <Typography variant="caption" color="textSecondary">
              Rules Imported
            </Typography>
          </Box>

          {/* Last Sync */}
          <Box textAlign="center">
            <Typography
              variant="body2"
              color={summary.last_sync ? 'textPrimary' : 'textSecondary'}
              fontWeight={500}
              sx={{ minHeight: 32, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
              {formatLastSync(summary.last_sync)}
            </Typography>
            <Typography variant="caption" color="textSecondary">
              Last Sync
            </Typography>
          </Box>
        </Box>

        {/* Zero State / Action */}
        {summary.total_feeds === 0 ? (
          <Box textAlign="center" py={1}>
            <Typography variant="body2" color="textSecondary" gutterBottom>
              No rule feeds configured
            </Typography>
            <Button
              component={RouterLink}
              to="/settings?tab=feeds"
              variant="outlined"
              size="small"
              startIcon={<FeedIcon />}
              aria-label="Navigate to settings to add your first feed"
            >
              Add Your First Feed
            </Button>
          </Box>
        ) : (
          <Box textAlign="center">
            <Button
              component={RouterLink}
              to="/settings?tab=feeds"
              size="small"
              aria-label="Navigate to feed management settings"
              sx={{ fontWeight: 500, fontSize: '0.8rem' }}
            >
              Manage Feeds
            </Button>
          </Box>
        )}
      </CardContent>

      {/* CSS for refresh spin animation */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </Card>
  );
}

export default FeedStatsWidget;
