import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link as RouterLink } from 'react-router-dom';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  Link,
  Alert,
  Skeleton,
  Button,
} from '@mui/material';
import {
  Wifi as WifiIcon,
  PlayArrow as RunningIcon,
  Stop as StoppedIcon,
  Error as ErrorIcon,
  Speed as SpeedIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { apiService } from '../../../services/api';
import { DynamicListener } from '../../../types';

// Constants - avoid magic numbers
const POLLING_INTERVAL_MS = 30000; // 30 seconds - reasonable for aggregate stats
const TOP_LISTENERS_LIMIT = 5;
const GC_TIME_MS = 300000; // 5 minutes cache garbage collection

interface ListenerStats {
  total: number;
  running: number;
  stopped: number;
  error: number;
  totalEventsReceived: number;
  totalErrors: number;
  avgEventsPerMin: number;
}

// Status color mapping - extensible for future statuses
const STATUS_COLORS: Record<string, 'success' | 'default' | 'error' | 'warning'> = {
  running: 'success',
  stopped: 'default',
  error: 'error',
  starting: 'warning',
  stopping: 'warning',
  degraded: 'warning',
};

const STATUS_ICONS: Record<string, React.ReactNode> = {
  running: <RunningIcon fontSize="small" />,
  stopped: <StoppedIcon fontSize="small" />,
  error: <ErrorIcon fontSize="small" />,
  starting: <SpeedIcon fontSize="small" />,
  stopping: <SpeedIcon fontSize="small" />,
  degraded: <ErrorIcon fontSize="small" />,
};

// Helper to get status color with fallback for unknown statuses
const getStatusColor = (status: string): 'success' | 'default' | 'error' | 'warning' => {
  return STATUS_COLORS[status] || 'default';
};

// Helper to get status icon with fallback
const getStatusIcon = (status: string): React.ReactNode => {
  return STATUS_ICONS[status] || <WifiIcon fontSize="small" />;
};

/**
 * Safe number extraction with validation
 * Handles null, undefined, NaN, negative, and string values
 */
const safeNumber = (value: unknown, defaultValue = 0): number => {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) {
    return defaultValue;
  }
  // Cap at MAX_SAFE_INTEGER to prevent overflow
  if (num > Number.MAX_SAFE_INTEGER) {
    return Number.MAX_SAFE_INTEGER;
  }
  return num;
};

/**
 * Safe sum reducer with overflow protection
 */
const safeSum = (values: number[]): number => {
  let sum = 0;
  for (const value of values) {
    const safeValue = safeNumber(value);
    // Check for overflow before adding
    if (sum > Number.MAX_SAFE_INTEGER - safeValue) {
      console.warn('ListenersWidget: Sum exceeded MAX_SAFE_INTEGER, capping value');
      return Number.MAX_SAFE_INTEGER;
    }
    sum += safeValue;
  }
  return sum;
};

function ListenersWidget() {
  // Fetch listeners with optimized polling
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboardListeners'],
    queryFn: () => apiService.listeners.getListeners(1, 100), // Get first 100 for stats
    refetchInterval: POLLING_INTERVAL_MS,
    refetchIntervalInBackground: false, // Stop polling when tab inactive
    gcTime: GC_TIME_MS,
  });

  // Memoize listeners array with type safety
  const listeners = useMemo(() => {
    const items = data?.items;
    return Array.isArray(items) ? items : [];
  }, [data?.items]);

  // Calculate aggregate statistics with safe number handling
  const stats: ListenerStats = useMemo(() => {
    if (!listeners.length) {
      return {
        total: 0,
        running: 0,
        stopped: 0,
        error: 0,
        totalEventsReceived: 0,
        totalErrors: 0,
        avgEventsPerMin: 0,
      };
    }

    const running = listeners.filter(l => l.status === 'running').length;
    const stopped = listeners.filter(l => l.status === 'stopped').length;
    const errorCount = listeners.filter(l => l.status === 'error').length;

    // Safe aggregation with overflow protection
    const totalEventsReceived = safeSum(listeners.map(l => safeNumber(l.events_received)));
    const totalErrors = safeSum(listeners.map(l => safeNumber(l.error_count)));
    const totalEventsPerMin = safeSum(listeners.map(l => safeNumber(l.events_per_minute)));
    const avgEventsPerMin = listeners.length > 0 ? Math.round(totalEventsPerMin / listeners.length) : 0;

    return {
      total: listeners.length,
      running,
      stopped,
      error: errorCount,
      totalEventsReceived,
      totalErrors,
      avgEventsPerMin,
    };
  }, [listeners]);

  // Get top listeners by events_per_minute (immutable sort with spread)
  const topListeners: DynamicListener[] = useMemo(() => {
    return [...listeners]
      .sort((a, b) => safeNumber(b.events_per_minute) - safeNumber(a.events_per_minute))
      .slice(0, TOP_LISTENERS_LIMIT);
  }, [listeners]);

  // Calculate health percentage: running / total (error listeners count as unhealthy)
  // This gives operators visibility into overall fleet health
  const healthPercentage = stats.total > 0 ? Math.round((stats.running / stats.total) * 100) : 0;

  if (isLoading) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Box display="flex" alignItems="center" gap={1}>
              <WifiIcon color="primary" />
              <Typography variant="h6">Listeners</Typography>
            </Box>
            <Skeleton width={60} height={24} />
          </Box>
          <Skeleton variant="rectangular" height={100} />
          <Box mt={2}>
            <Skeleton variant="text" />
            <Skeleton variant="text" />
            <Skeleton variant="text" />
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Box display="flex" alignItems="center" gap={1}>
              <WifiIcon color="primary" />
              <Typography variant="h6">Listeners</Typography>
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
            Failed to load listener data: {error instanceof Error ? error.message : 'Unknown error'}
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
        {/* Header */}
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Box display="flex" alignItems="center" gap={1}>
            <WifiIcon color="primary" />
            <Typography variant="h6">Listeners</Typography>
          </Box>
          <Link
            component={RouterLink}
            to="/listeners"
            underline="hover"
            color="primary"
            aria-label="View all listeners"
            sx={{ fontWeight: 500, fontSize: '0.875rem' }}
          >
            View All
          </Link>
        </Box>

        {/* Aggregate Stats */}
        <Box mb={2}>
          <Box display="flex" gap={1} flexWrap="wrap" mb={1}>
            <Chip
              label={`${stats.running} Running`}
              color="success"
              size="small"
              variant="outlined"
              aria-label={`${stats.running} listeners running`}
            />
            <Chip
              label={`${stats.stopped} Stopped`}
              color="default"
              size="small"
              variant="outlined"
              aria-label={`${stats.stopped} listeners stopped`}
            />
            {stats.error > 0 && (
              <Chip
                label={`${stats.error} Error`}
                color="error"
                size="small"
                variant="outlined"
                aria-label={`${stats.error} listeners in error state`}
              />
            )}
          </Box>

          {/* Health Bar */}
          <Box display="flex" alignItems="center" gap={1} mb={1}>
            <Typography variant="body2" color="textSecondary" sx={{ minWidth: 80 }}>
              Health
            </Typography>
            <LinearProgress
              variant="determinate"
              value={healthPercentage}
              aria-label={`Listener health: ${healthPercentage}% of listeners running`}
              sx={{
                flex: 1,
                height: 8,
                borderRadius: 1,
                backgroundColor: 'grey.300',
                '& .MuiLinearProgress-bar': {
                  backgroundColor: healthPercentage >= 80 ? '#4caf50' : healthPercentage >= 50 ? '#ff9800' : '#f44336',
                },
              }}
            />
            <Typography variant="body2" fontWeight={500} sx={{ minWidth: 40 }}>
              {healthPercentage}%
            </Typography>
          </Box>

          {/* Health explanation */}
          <Typography variant="caption" color="textSecondary" sx={{ display: 'block', mb: 1 }}>
            Running / Total listeners
          </Typography>

          {/* Summary Stats */}
          <Box display="flex" justifyContent="space-between" sx={{ mt: 2 }}>
            <Box textAlign="center">
              <Typography variant="h6" color="primary">
                {stats.totalEventsReceived.toLocaleString()}
              </Typography>
              <Typography variant="caption" color="textSecondary">
                Total Events
              </Typography>
            </Box>
            <Box textAlign="center">
              <Typography variant="h6" color={stats.totalErrors > 0 ? 'error' : 'textPrimary'}>
                {stats.totalErrors.toLocaleString()}
              </Typography>
              <Typography variant="caption" color="textSecondary">
                Total Errors
              </Typography>
            </Box>
            <Box textAlign="center">
              <Typography variant="h6" color="textPrimary">
                {stats.avgEventsPerMin.toLocaleString()}
              </Typography>
              <Typography variant="caption" color="textSecondary">
                Avg/min
              </Typography>
            </Box>
          </Box>
        </Box>

        {/* Top Listeners */}
        {topListeners.length > 0 ? (
          <>
            <Typography variant="subtitle2" color="textSecondary" gutterBottom>
              Top Active Listeners
            </Typography>
            <List dense disablePadding>
              {topListeners.map((listener) => (
                <ListItem
                  key={listener.id}
                  disablePadding
                  sx={{
                    py: 0.5,
                    borderBottom: '1px solid',
                    borderColor: 'divider',
                    '&:last-child': { borderBottom: 'none' },
                  }}
                >
                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center" gap={0.5}>
                        <Chip
                          icon={getStatusIcon(listener.status)}
                          label={listener.status}
                          color={getStatusColor(listener.status)}
                          size="small"
                          aria-label={`Status: ${listener.status}`}
                          sx={{ height: 20, fontSize: '0.7rem' }}
                        />
                        <Typography variant="body2" noWrap sx={{ maxWidth: 150 }}>
                          {listener.name}
                        </Typography>
                      </Box>
                    }
                    secondary={
                      <Typography variant="caption" color="textSecondary">
                        {listener.type} | {safeNumber(listener.events_per_minute).toLocaleString()}/min
                      </Typography>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </>
        ) : (
          <Box textAlign="center" py={2}>
            <Typography variant="body2" color="textSecondary">
              No listeners configured
            </Typography>
            <Link
              component={RouterLink}
              to="/listeners"
              underline="hover"
              color="primary"
              aria-label="Navigate to listeners page to create your first listener"
              sx={{ fontSize: '0.875rem' }}
            >
              Create your first listener
            </Link>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

export default ListenersWidget;
