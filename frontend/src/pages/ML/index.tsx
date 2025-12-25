import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import errorReportingService from '../../services/errorReporting';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Alert,
  CircularProgress,
  Chip,
  useTheme,
  Button,
  IconButton,
  Tooltip as MuiTooltip,
  Switch,
  FormControlLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
} from '@mui/material';
import {
  Analytics as AnalyticsIcon,
  PlayArrow as PlayIcon,
  Settings as SettingsIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  Assessment as AssessmentIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { apiService } from '../../services/api';
import { MLStatus, MLHealth } from '../../types';

const StatCard = ({
  title,
  value,
  icon,
  color,
  subtitle,
}: {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  color: string;
  subtitle?: string;
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
          {subtitle && (
            <Typography variant="caption" color="textSecondary">
              {subtitle}
            </Typography>
          )}
        </Box>
        <Box sx={{ color, fontSize: 48 }}>
          {icon}
        </Box>
      </Box>
    </CardContent>
  </Card>
);

function MLDashboard() {
  const theme = useTheme();
  const [configDialogOpen, setConfigDialogOpen] = useState(false);
  const [configUpdateLoading, setConfigUpdateLoading] = useState(false);
  const [configUpdateError, setConfigUpdateError] = useState<string | null>(null);
  const [configForm, setConfigForm] = useState({
    enabled: false,
    batch_size: 1000,
    training_interval: '1h',
    retrain_threshold: 5000,
    validation_ratio: 0.2,
    enable_continuous: true,
    drift_detection: true,
    min_confidence: 0.6,
    algorithms: ['zscore', 'iqr', 'isolation_forest'],
    voting_strategy: 'weighted',
  });

  // Fetch ML status
  const { data: mlStatus, isLoading: statusLoading, error: statusError, refetch: refetchStatus } = useQuery<MLStatus>({
    queryKey: ['mlStatus'],
    queryFn: () => apiService.ml.getMLStatus(),
    refetchInterval: 5000,
  });

  // Fetch ML health
  const { data: mlHealth, isLoading: healthLoading, error: healthError } = useQuery<MLHealth>({
    queryKey: ['mlHealth'],
    queryFn: () => apiService.ml.getMLHealth(),
    refetchInterval: 5000,
  });

  // Fetch ML performance history
  const { data: performanceHistory, isLoading: perfLoading } = useQuery({
    queryKey: ['mlPerformanceHistory'],
    queryFn: () => apiService.ml.getMLPerformanceHistory(),
    refetchInterval: 10000,
  });

  const handleForceTraining = async () => {
    try {
      await apiService.ml.forceMLTraining();
      refetchStatus();
    } catch (error) {
      errorReportingService.reportError({
        type: 'api_error',
        message: 'Failed to force ML training',
        additionalData: { error: error instanceof Error ? error.message : String(error) }
      });
    }
  };

  const handleUpdateConfig = async () => {
    setConfigUpdateLoading(true);
    setConfigUpdateError(null);
    try {
      await apiService.ml.updateMLConfig(configForm);
      setConfigDialogOpen(false);
      refetchStatus();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to update ML config';
      setConfigUpdateError(errorMessage);
      errorReportingService.reportError({
        type: 'api_error',
        message: 'Failed to update ML config',
        additionalData: { error: errorMessage, config: configForm }
      });
    } finally {
      setConfigUpdateLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return '#4caf50';
      case 'degraded': return '#ff9800';
      case 'unhealthy': return '#f44336';
      default: return '#9e9e9e';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return '🟢';
      case 'degraded': return '🟡';
      case 'unhealthy': return '🔴';
      default: return '⚪';
    }
  };

  if (statusLoading || healthLoading || perfLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (statusError || healthError) {
    return (
      <Alert severity="error">
        Failed to load ML dashboard data. Please check your connection and try again.
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
          ML Analytics Dashboard
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: { xs: '100%', sm: 'auto' }, justifyContent: { xs: 'space-between', sm: 'flex-end' } }}>
          <Chip
            label={`${getStatusIcon(mlHealth?.status || 'unknown')} ${mlHealth?.status || 'Unknown'}`}
            sx={{ bgcolor: getStatusColor(mlHealth?.status || 'unknown') }}
          />
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => refetchStatus()}
            size="small"
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<PlayIcon />}
            onClick={handleForceTraining}
            size="small"
            disabled={!mlStatus?.enabled}
          >
            Train Now
          </Button>
          <MuiTooltip title="ML Configuration">
            <IconButton onClick={() => setConfigDialogOpen(true)} size="small">
              <SettingsIcon />
            </IconButton>
          </MuiTooltip>
        </Box>
      </Box>

      <Grid container spacing={{ xs: 2, sm: 3 }} sx={{ mb: 4 }}>
        <Grid item xs={6} sm={6} md={3}>
          <StatCard
            title="ML Status"
            value={mlStatus?.enabled ? 'Enabled' : 'Disabled'}
            icon={<AnalyticsIcon />}
            color={mlStatus?.enabled ? '#4caf50' : '#9e9e9e'}
            subtitle={mlStatus?.is_running ? 'Running' : 'Stopped'}
          />
        </Grid>
        <Grid item xs={6} sm={6} md={3}>
          <StatCard
            title="Sample Count"
            value={mlStatus?.sample_count || 0}
            icon={<AssessmentIcon />}
            color="#1976d2"
            subtitle="Training samples"
          />
        </Grid>
        <Grid item xs={6} sm={6} md={3}>
          <StatCard
            title="Detection Latency"
            value={`${(mlHealth?.performance_metrics?.detection_latency?.average || 0).toFixed(1)}ms`}
            icon={<TimelineIcon />}
            color="#ff9800"
            subtitle="Average response time"
          />
        </Grid>
        <Grid item xs={6} sm={6} md={3}>
          <StatCard
            title="Throughput"
            value={`${(mlHealth?.performance_metrics?.throughput?.events_per_second || 0).toFixed(1)}/s`}
            icon={<TrendingUpIcon />}
            color="#9c27b0"
            subtitle="Current detections/sec"
          />
        </Grid>
      </Grid>

      <Grid container spacing={{ xs: 2, sm: 3 }}>
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
              <Typography variant="h6" gutterBottom>
                ML Performance History
              </Typography>
              <Box sx={{ height: { xs: 250, sm: 300 } }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={performanceHistory || []}>
                    <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
                    <XAxis
                      dataKey="timestamp"
                      tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                      fontSize={12}
                      stroke={theme.palette.text.primary}
                    />
                    <YAxis
                      domain={[0, 1]}
                      fontSize={12}
                      stroke={theme.palette.text.primary}
                    />
                    <Tooltip
                      labelFormatter={(value) => new Date(value).toLocaleString()}
                      contentStyle={{
                        backgroundColor: theme.palette.background.paper,
                        border: `1px solid ${theme.palette.divider}`,
                        borderRadius: 4,
                        color: theme.palette.text.primary,
                      }}
                    />
                    <Line
                      type="monotone"
                      dataKey="accuracy"
                      stroke="#4caf50"
                      strokeWidth={2}
                      name="Accuracy"
                      dot={{ fill: '#4caf50' }}
                    />
                    <Line
                      type="monotone"
                      dataKey="precision"
                      stroke="#2196f3"
                      strokeWidth={2}
                      name="Precision"
                      dot={{ fill: '#2196f3' }}
                    />
                    <Line
                      type="monotone"
                      dataKey="recall"
                      stroke="#ff9800"
                      strokeWidth={2}
                      name="Recall"
                      dot={{ fill: '#ff9800' }}
                    />
                    <Line
                      type="monotone"
                      dataKey="f1_score"
                      stroke="#9c27b0"
                      strokeWidth={2}
                      name="F1 Score"
                      dot={{ fill: '#9c27b0' }}
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
                System Health Checks
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {mlHealth?.checks && Object.entries(mlHealth.checks).map(([name, check]) => (
                  <Box key={name} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Box
                      sx={{
                        width: 12,
                        height: 12,
                        borderRadius: '50%',
                        backgroundColor: check.status === 'pass' ? '#4caf50' : check.status === 'warn' ? '#ff9800' : '#f44336',
                      }}
                    />
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="body2" sx={{ textTransform: 'capitalize' }}>
                        {name.replace(/_/g, ' ')}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {check.message}
                      </Typography>
                    </Box>
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Configuration Dialog */}
      <Dialog open={configDialogOpen} onClose={() => setConfigDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>ML Configuration</DialogTitle>
        <DialogContent>
          {configUpdateError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {configUpdateError}
            </Alert>
          )}
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 1 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={configForm.enabled}
                  onChange={(e) => setConfigForm({ ...configForm, enabled: e.target.checked })}
                />
              }
              label="Enable ML Anomaly Detection"
            />

            <TextField
              label="Batch Size"
              type="number"
              value={configForm.batch_size}
              onChange={(e) => setConfigForm({ ...configForm, batch_size: parseInt(e.target.value, 10) || 0 })}
              fullWidth
            />

            <TextField
              label="Training Interval"
              value={configForm.training_interval}
              onChange={(e) => setConfigForm({ ...configForm, training_interval: e.target.value })}
              fullWidth
              helperText="e.g., 1h, 24h, 7d"
            />

            <TextField
              label="Retrain Threshold"
              type="number"
              value={configForm.retrain_threshold}
              onChange={(e) => setConfigForm({ ...configForm, retrain_threshold: parseInt(e.target.value, 10) || 0 })}
              fullWidth
              helperText="Minimum samples before retraining"
            />

            <TextField
              label="Validation Ratio"
              type="number"
              inputProps={{ min: 0, max: 1, step: 0.1 }}
              value={configForm.validation_ratio}
              onChange={(e) => setConfigForm({ ...configForm, validation_ratio: parseFloat(e.target.value) || 0 })}
              fullWidth
            />

            <TextField
              label="Minimum Confidence"
              type="number"
              inputProps={{ min: 0, max: 1, step: 0.1 }}
              value={configForm.min_confidence}
              onChange={(e) => setConfigForm({ ...configForm, min_confidence: parseFloat(e.target.value) || 0 })}
              fullWidth
            />

            <TextField
              select
              label="Voting Strategy"
              value={configForm.voting_strategy}
              onChange={(e) => setConfigForm({ ...configForm, voting_strategy: e.target.value })}
              fullWidth
            >
              <MenuItem value="majority">Majority</MenuItem>
              <MenuItem value="weighted">Weighted</MenuItem>
              <MenuItem value="confidence">Confidence</MenuItem>
            </TextField>

            <FormControlLabel
              control={
                <Switch
                  checked={configForm.enable_continuous}
                  onChange={(e) => setConfigForm({ ...configForm, enable_continuous: e.target.checked })}
                />
              }
              label="Enable Continuous Learning"
            />

            <FormControlLabel
              control={
                <Switch
                  checked={configForm.drift_detection}
                  onChange={(e) => setConfigForm({ ...configForm, drift_detection: e.target.checked })}
                />
              }
              label="Enable Drift Detection"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigDialogOpen(false)} disabled={configUpdateLoading}>Cancel</Button>
          <Button onClick={handleUpdateConfig} variant="contained" disabled={configUpdateLoading}>
            {configUpdateLoading ? 'Saving...' : 'Save Configuration'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default MLDashboard;
