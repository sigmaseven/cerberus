import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Alert,
  CircularProgress,
  Chip,
} from '@mui/material';
import {
  Event as EventIcon,
  Warning as WarningIcon,
  Rule as RuleIcon,
  HealthAndSafety as HealthIcon,
  Wifi as WifiIcon,
  WifiOff as WifiOffIcon,
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { apiService } from '../../services/api';
import { DashboardStats } from '../../types';
import ListenersWidget from './components/ListenersWidget';
import FeedStatsWidget from './components/FeedStatsWidget';
import ErrorBoundary from '../../components/ErrorBoundary';

const StatCard = ({
  title,
  value,
  icon,
  color,
}: {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  color: string;
}) => (
  <Card>
    <CardContent>
      <Box display="flex" alignItems="center" justifyContent="space-between">
        <Box>
          <Typography color="textSecondary" gutterBottom>
            {title}
          </Typography>
          <Typography variant="h4" component="div">
            {value}
          </Typography>
        </Box>
        <Box sx={{ color, fontSize: 48 }}>
          {icon}
        </Box>
      </Box>
    </CardContent>
  </Card>
);

function Dashboard() {
  // WebSocket state - setters prefixed with _ as WebSocket is currently disabled
  const [realtimeStats, _setRealtimeStats] = useState<DashboardStats | null>(null);
  const [isWebSocketConnected, _setIsWebSocketConnected] = useState(false);
  // Suppress unused variable warnings for disabled WebSocket feature
  void _setRealtimeStats;
  void _setIsWebSocketConnected;

  // Fetch dashboard stats from API
  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery({
    queryKey: ['dashboardStats'],
    queryFn: () => apiService.getDashboardStats(),
    refetchInterval: 5000, // Poll every 5 seconds
  });

  // Fetch chart data from API
  const { data: chartData, isLoading: chartLoading, error: chartError } = useQuery({
    queryKey: ['chartData'],
    queryFn: () => apiService.getChartData(),
    refetchInterval: 5000,
  });

  // Use real-time stats if available, otherwise fall back to polled data
  const currentStats = realtimeStats || stats;

  // Setup websocket for real-time updates
  // TODO: Re-enable when backend WebSocket endpoint (/ws) is implemented
  useEffect(() => {
    // Temporarily disabled - backend /ws endpoint not yet implemented
    // The dashboard uses polling (5s intervals) as fallback
    // apiService.subscribeToRealtimeUpdates({
    //   onNewEvent: (event) => {
    //     // Handle new event if needed
    //   },
    //   onNewAlert: (alert) => {
    //     // Handle new alert if needed
    //   },
    //   onStatsUpdate: (newStats) => {
    //     setRealtimeStats(newStats);
    //   },
    // });

    // setIsWebSocketConnected(apiService.isWebSocketConnected());

    // return () => {
    //   apiService.unsubscribeFromRealtimeUpdates();
    // };
  }, []);

  if (statsLoading || chartLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (statsError || chartError) {
    return (
      <Alert severity="error">
        Failed to load dashboard data. Please check your connection and try again.
      </Alert>
    );
  }

  return (
    <Box>
      <Box sx={{
        display: 'flex',
        flexDirection: { xs: 'column', sm: 'row' },
        justifyContent: { xs: 'flex-start', sm: 'space-between' },
        alignItems: { xs: 'flex-start', sm: 'center' },
        gap: { xs: 2, sm: 1 },
        mb: 2
      }}>
        <Typography variant="h4" component="h1" sx={{ mb: { xs: 0, sm: 0 } }}>
          Dashboard
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: { xs: '100%', sm: 'auto' }, justifyContent: { xs: 'space-between', sm: 'flex-end' } }}>
          <Chip
            icon={isWebSocketConnected ? <WifiIcon /> : <WifiOffIcon />}
            label={isWebSocketConnected ? 'Live' : 'Offline'}
            color={isWebSocketConnected ? 'success' : 'default'}
            size="small"
            variant="outlined"
          />
        </Box>
      </Box>

      <Grid container spacing={{ xs: 2, sm: 3 }} sx={{ mb: 4 }}>
        <Grid item xs={6} sm={6} md={3}>
          <StatCard
            title="Total Events"
            value={currentStats?.total_events || 0}
            icon={<EventIcon />}
            color="#1976d2"
          />
        </Grid>
        <Grid item xs={6} sm={6} md={3}>
          <StatCard
            title="Active Alerts"
            value={currentStats?.active_alerts || 0}
            icon={<WarningIcon />}
            color="#f44336"
          />
        </Grid>
        <Grid item xs={6} sm={6} md={3}>
          <StatCard
            title="Rules Fired"
            value={currentStats?.rules_fired || 0}
            icon={<RuleIcon />}
            color="#ff9800"
          />
        </Grid>
        <Grid item xs={6} sm={6} md={3}>
          <StatCard
            title="System Health"
            value={currentStats?.system_health || 'Unknown'}
            icon={<HealthIcon />}
            color="#4caf50"
          />
        </Grid>
      </Grid>

      <Grid container spacing={{ xs: 2, sm: 3 }}>
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
              <Typography variant="h6" gutterBottom>
                Events Over Time
              </Typography>
              <Box sx={{ width: '100%', height: { xs: 250, sm: 300 } }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chartData || []}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis
                      dataKey="timestamp"
                      tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                      fontSize={12}
                    />
                    <YAxis fontSize={12} />
                    <Tooltip
                      labelFormatter={(value) => new Date(value).toLocaleString()}
                    />
                    <Line
                      type="monotone"
                      dataKey="events"
                      stroke="#1976d2"
                      strokeWidth={2}
                      name="Events"
                    />
                    <Line
                      type="monotone"
                      dataKey="alerts"
                      stroke="#f44336"
                      strokeWidth={2}
                      name="Alerts"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} lg={4}>
          <Card>
            <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
              <Typography variant="h6" gutterBottom>
                System Status
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      borderRadius: '50%',
                      backgroundColor: '#4caf50',
                    }}
                  />
                  <Typography variant="body2">Events Ingest: 95%</Typography>
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      borderRadius: '50%',
                      backgroundColor: '#4caf50',
                    }}
                  />
                  <Typography variant="body2">Rules Engine: 100%</Typography>
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      borderRadius: '50%',
                      backgroundColor: '#4caf50',
                    }}
                  />
                  <Typography variant="body2">Database: OK</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Widgets Section - Listeners and Feed Stats */}
      <Grid container spacing={{ xs: 2, sm: 3 }} sx={{ mt: 0 }}>
        <Grid item xs={12} md={6} lg={4}>
          <ErrorBoundary
            fallback={
              <Card>
                <CardContent>
                  <Alert severity="warning">
                    Listener widget unavailable. Please refresh the page.
                  </Alert>
                </CardContent>
              </Card>
            }
          >
            <ListenersWidget />
          </ErrorBoundary>
        </Grid>
        <Grid item xs={12} md={6} lg={4}>
          <ErrorBoundary
            fallback={
              <Card>
                <CardContent>
                  <Alert severity="warning">
                    Feed stats widget unavailable. Please refresh the page.
                  </Alert>
                </CardContent>
              </Card>
            }
          >
            <FeedStatsWidget />
          </ErrorBoundary>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Dashboard;