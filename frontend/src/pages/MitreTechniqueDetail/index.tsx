import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Chip,
  Button,
  CircularProgress,
  Alert,
  Divider,
  Stack,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  Tab,
  LinearProgress,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Code as CodeIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { useNavigate, useParams } from 'react-router-dom';
import { MitreTechnique, TechniqueAnalytics } from '../../services/mitreService';
import apiService from '../../services/api';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`technique-tabpanel-${index}`}
      aria-labelledby={`technique-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

const MitreTechniqueDetail: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [technique, setTechnique] = useState<MitreTechnique | null>(null);
  const [analytics, setAnalytics] = useState<TechniqueAnalytics | null>(null);
  const [rules, setRules] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [tabValue, setTabValue] = useState(0);
  const [tactics, setTactics] = useState<any[]>([]);

  useEffect(() => {
    if (id) {
      // Decode the URL parameter in case it was encoded
      const decodedId = decodeURIComponent(id);
      loadTechniqueData(decodedId);
    }
  }, [id]);

  const loadTechniqueData = async (techniqueId: string) => {
    setLoading(true);
    setError(null);
    try {
      const [techData, analyticsData, rulesData, alertsData, tacticsData] = await Promise.all([
        apiService.mitre.getTechnique(techniqueId),
        apiService.mitre.getTechniqueAnalytics(techniqueId).catch(() => null),
        apiService.mitre.getTechniqueRules(techniqueId).catch(() => []),
        apiService.mitre.getTechniqueAlerts(techniqueId, 20).catch(() => []),
        apiService.mitre.getTactics().catch(() => []),
      ]);

      setTechnique(techData);
      setAnalytics(analyticsData);
      setRules(rulesData || []);
      setAlerts(alertsData || []);
      setTactics(tacticsData || []);
    } catch (err) {
      console.error('Failed to load technique data:', err);
      setError('Failed to load technique details. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const getCoverageColor = (coverage: number): 'error' | 'warning' | 'success' => {
    if (coverage === 0) return 'error';
    if (coverage <= 50) return 'warning';
    return 'success';
  };

  const getCoverageText = (coverage: number): string => {
    if (coverage === 0) return 'No Coverage';
    if (coverage <= 50) return 'Partial Coverage';
    return 'Full Coverage';
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error || !technique) {
    return (
      <Box>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/mitre')} sx={{ mb: 2 }}>
          Back to Knowledge Base
        </Button>
        <Alert severity="error">{error || 'Technique not found'}</Alert>
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/mitre')} sx={{ mb: 2 }}>
        Back to Knowledge Base
      </Button>

      <Grid container spacing={3}>
        {/* Main Info */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="start" justifyContent="space-between" mb={2}>
                <Box>
                  <Chip label={technique.id} color="primary" sx={{ mb: 1 }} />
                  <Typography variant="h4" gutterBottom>
                    {technique.name}
                  </Typography>
                </Box>
              </Box>

              <Typography variant="body1" paragraph>
                {technique.description}
              </Typography>

              <Divider sx={{ my: 2 }} />

              {/* Tactics */}
              {technique.tactics && technique.tactics.length > 0 && (
                <Box mb={2}>
                  <Typography variant="subtitle2" gutterBottom>
                    Tactics:
                  </Typography>
                  <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                    {technique.tactics.map((tacticId) => {
                      const tactic = tactics.find((t) => t.id === tacticId);
                      return tactic ? (
                        <Chip key={tacticId} label={tactic.name} size="small" />
                      ) : null;
                    })}
                  </Stack>
                </Box>
              )}

              {/* Platforms */}
              {technique.platforms && technique.platforms.length > 0 && (
                <Box mb={2}>
                  <Typography variant="subtitle2" gutterBottom>
                    Platforms:
                  </Typography>
                  <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                    {technique.platforms.map((platform) => (
                      <Chip key={platform} label={platform} size="small" variant="outlined" />
                    ))}
                  </Stack>
                </Box>
              )}

              {/* Data Sources */}
              {technique.data_sources && technique.data_sources.length > 0 && (
                <Box>
                  <Typography variant="subtitle2" gutterBottom>
                    Data Sources:
                  </Typography>
                  <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                    {technique.data_sources.map((source) => (
                      <Chip key={source} label={source} size="small" variant="outlined" />
                    ))}
                  </Stack>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Analytics Sidebar */}
        <Grid item xs={12} md={4}>
          {analytics && (
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Coverage Analytics
                </Typography>

                {/* Coverage Score */}
                <Box mb={3}>
                  <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                    <Typography variant="body2">Detection Coverage</Typography>
                    <Typography variant="h6" color={getCoverageColor(analytics.coverage)}>
                      {analytics.coverage}%
                    </Typography>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={analytics.coverage}
                    color={getCoverageColor(analytics.coverage)}
                    sx={{ height: 8, borderRadius: 1 }}
                  />
                  <Typography variant="caption" color="text.secondary">
                    {getCoverageText(analytics.coverage)}
                  </Typography>
                </Box>

                <Divider sx={{ my: 2 }} />

                {/* Stats */}
                <Stack spacing={2}>
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Box display="flex" alignItems="center" gap={1} mb={1}>
                      <SecurityIcon fontSize="small" color="primary" />
                      <Typography variant="body2" color="text.secondary">
                        Detection Rules
                      </Typography>
                    </Box>
                    <Typography variant="h4">{analytics.rule_count}</Typography>
                  </Paper>

                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Box display="flex" alignItems="center" gap={1} mb={1}>
                      <WarningIcon fontSize="small" color="warning" />
                      <Typography variant="body2" color="text.secondary">
                        Alerts (30d)
                      </Typography>
                    </Box>
                    <Typography variant="h4">{analytics.alert_count_30d}</Typography>
                  </Paper>

                  {analytics.last_seen && (
                    <Paper variant="outlined" sx={{ p: 2 }}>
                      <Box display="flex" alignItems="center" gap={1} mb={1}>
                        <TimelineIcon fontSize="small" color="info" />
                        <Typography variant="body2" color="text.secondary">
                          Last Seen
                        </Typography>
                      </Box>
                      <Typography variant="body2">
                        {new Date(analytics.last_seen).toLocaleString()}
                      </Typography>
                    </Paper>
                  )}
                </Stack>
              </CardContent>
            </Card>
          )}
        </Grid>

        {/* Tabs Section */}
        <Grid item xs={12}>
          <Card>
            <Tabs value={tabValue} onChange={handleTabChange} sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tab label={`Detection Rules (${rules.length})`} icon={<CodeIcon />} iconPosition="start" />
              <Tab label={`Recent Alerts (${alerts.length})`} icon={<WarningIcon />} iconPosition="start" />
              <Tab label="Detection Methods" />
            </Tabs>

            <TabPanel value={tabValue} index={0}>
              {rules.length > 0 ? (
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Rule Name</TableCell>
                        <TableCell>Type</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Status</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {rules.map((rule) => (
                        <TableRow key={rule.id} hover sx={{ cursor: 'pointer' }}>
                          <TableCell>{rule.name}</TableCell>
                          <TableCell>
                            <Chip label={rule.type || 'SIGMA'} size="small" />
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={rule.severity}
                              size="small"
                              color={
                                rule.severity === 'critical' || rule.severity === 'high'
                                  ? 'error'
                                  : rule.severity === 'medium'
                                  ? 'warning'
                                  : 'default'
                              }
                            />
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={rule.enabled ? 'Enabled' : 'Disabled'}
                              size="small"
                              color={rule.enabled ? 'success' : 'default'}
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Box textAlign="center" py={4}>
                  <Typography variant="body2" color="text.secondary">
                    No detection rules found for this technique
                  </Typography>
                </Box>
              )}
            </TabPanel>

            <TabPanel value={tabValue} index={1}>
              {alerts.length > 0 ? (
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Alert ID</TableCell>
                        <TableCell>Rule Name</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Timestamp</TableCell>
                        <TableCell>Status</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {alerts.map((alert) => (
                        <TableRow key={alert.alert_id} hover>
                          <TableCell>{alert.alert_id?.substring(0, 8)}...</TableCell>
                          <TableCell>{alert.rule_name}</TableCell>
                          <TableCell>
                            <Chip
                              label={alert.severity}
                              size="small"
                              color={
                                alert.severity === 'critical' || alert.severity === 'high'
                                  ? 'error'
                                  : alert.severity === 'medium'
                                  ? 'warning'
                                  : 'default'
                              }
                            />
                          </TableCell>
                          <TableCell>{new Date(alert.timestamp).toLocaleString()}</TableCell>
                          <TableCell>
                            <Chip label={alert.status} size="small" />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Box textAlign="center" py={4}>
                  <Typography variant="body2" color="text.secondary">
                    No recent alerts for this technique
                  </Typography>
                </Box>
              )}
            </TabPanel>

            <TabPanel value={tabValue} index={2}>
              {technique.detection ? (
                <Box>
                  <Typography variant="body1" paragraph>
                    {technique.detection}
                  </Typography>
                </Box>
              ) : (
                <Box textAlign="center" py={4}>
                  <Typography variant="body2" color="text.secondary">
                    No detection methods documented
                  </Typography>
                </Box>
              )}
            </TabPanel>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default MitreTechniqueDetail;
