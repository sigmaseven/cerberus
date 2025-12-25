import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  Box,
  Chip,
  Typography,
  Stack,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  CircularProgress,
  Alert,
  Divider,
  IconButton} from '@mui/material';
import {
  Close as CloseIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Code as CodeIcon,
  Description as DescriptionIcon
} from '@mui/icons-material';
import { MitreTechnique, TechniqueAnalytics } from '../../services/mitreService';
import apiService from '../../services/api';
import RuleDetailModal from '../RuleDetailModal';

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
      {value === index && <Box sx={{ py: 2 }}>{children}</Box>}
    </div>
  );
}

interface MitreTechniqueModalProps {
  open: boolean;
  techniqueId: string | null;
  onClose: () => void;
}

const MitreTechniqueModal: React.FC<MitreTechniqueModalProps> = ({ open, techniqueId, onClose }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [technique, setTechnique] = useState<MitreTechnique | null>(null);
  const [analytics, setAnalytics] = useState<TechniqueAnalytics | null>(null);
  const [rules, setRules] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [tabValue, setTabValue] = useState(0);
  const [tactics, setTactics] = useState<any[]>([]);

  // Rule modal state
  const [ruleModalOpen, setRuleModalOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<any>(null);

  useEffect(() => {
    if (open && techniqueId) {
      loadTechniqueData(techniqueId);
    } else if (!open) {
      // Reset state when modal closes
      setTabValue(0);
      setTechnique(null);
      setAnalytics(null);
      setRules([]);
      setAlerts([]);
      setError(null);
    }
  }, [open, techniqueId]);

  const loadTechniqueData = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const decodedId = decodeURIComponent(id);
      const [techData, analyticsData, rulesData, alertsData, tacticsData] = await Promise.all([
        apiService.mitre.getTechnique(decodedId),
        apiService.mitre.getTechniqueAnalytics(decodedId).catch(() => null),
        apiService.mitre.getTechniqueRules(decodedId).catch(() => []),
        apiService.mitre.getTechniqueAlerts(decodedId, 20).catch(() => []),
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

  const handleOpenRuleModal = (rule: any) => {
    setSelectedRule(rule);
    setRuleModalOpen(true);
  };

  const handleCloseRuleModal = () => {
    setRuleModalOpen(false);
    setSelectedRule(null);
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

  const formatDescription = (description: string) => {
    // Split by double newlines to get paragraphs
    const paragraphs = description.split(/\n\n+/);
    return paragraphs.map((para, idx) => (
      <Typography key={idx} variant="body1" paragraph sx={{ mb: 2 }}>
        {para.trim()}
      </Typography>
    ));
  };

  return (
    <>
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      PaperProps={{
        sx: {
          height: '90vh',
          maxHeight: '90vh'}}}
    >
      {loading ? (
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
          <CircularProgress />
        </Box>
      ) : error || !technique ? (
        <Box p={3}>
          <DialogTitle>
            <Box display="flex" alignItems="center" justifyContent="space-between">
              <Typography variant="h5">Error</Typography>
              <IconButton onClick={onClose} size="small">
                <CloseIcon />
              </IconButton>
            </Box>
          </DialogTitle>
          <DialogContent>
            <Alert severity="error">{error || 'Technique not found'}</Alert>
          </DialogContent>
        </Box>
      ) : (
        <>
          <DialogTitle>
            <Box display="flex" alignItems="center" justifyContent="space-between">
              <Box flex={1}>
                <Stack direction="row" spacing={1} alignItems="center" mb={1}>
                  <Chip label={technique.id} color="primary" />
                  {technique.url && (
                    <Typography
                      variant="caption"
                      component="a"
                      href={technique.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      sx={{ color: 'primary.main', textDecoration: 'none', '&:hover': { textDecoration: 'underline' } }}
                    >
                      View on MITRE ATT&CK ↗
                    </Typography>
                  )}
                </Stack>
                <Typography variant="h5">{technique.name}</Typography>
              </Box>
              <IconButton onClick={onClose} size="small">
                <CloseIcon />
              </IconButton>
            </Box>

            {/* Tactics and Platforms */}
            <Stack direction="row" spacing={3} mt={2}>
              {technique.tactics && technique.tactics.length > 0 && (
                <Box>
                  <Typography variant="caption" color="text.secondary" display="block" mb={0.5}>
                    Tactics:
                  </Typography>
                  <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                    {technique.tactics.map((tacticId) => {
                      const tactic = tactics.find((t) => t.short_name === tacticId);
                      return (
                        <Chip
                          key={tacticId}
                          label={tactic ? tactic.name : tacticId}
                          size="small"
                          color="secondary"
                        />
                      );
                    })}
                  </Stack>
                </Box>
              )}
              {technique.platforms && technique.platforms.length > 0 && (
                <Box>
                  <Typography variant="caption" color="text.secondary" display="block" mb={0.5}>
                    Platforms:
                  </Typography>
                  <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                    {technique.platforms.map((platform) => (
                      <Chip key={platform} label={platform} size="small" variant="outlined" />
                    ))}
                  </Stack>
                </Box>
              )}
            </Stack>

            {/* Analytics Summary */}
            {analytics && (
              <Box mt={2}>
                <Paper variant="outlined" sx={{ p: 2, bgcolor: 'background.default' }}>
                  <Stack direction="row" spacing={3} alignItems="center">
                    <Box>
                      <Typography variant="caption" color="text.secondary">
                        Coverage
                      </Typography>
                      <Box display="flex" alignItems="center" gap={1}>
                        <Typography variant="h6" color={getCoverageColor(analytics.coverage)}>
                          {analytics.coverage}%
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {getCoverageText(analytics.coverage)}
                        </Typography>
                      </Box>
                    </Box>
                    <Divider orientation="vertical" flexItem />
                    <Box>
                      <Typography variant="caption" color="text.secondary">
                        Detection Rules
                      </Typography>
                      <Typography variant="h6">{analytics.rule_count}</Typography>
                    </Box>
                    <Divider orientation="vertical" flexItem />
                    <Box>
                      <Typography variant="caption" color="text.secondary">
                        Alerts (30d)
                      </Typography>
                      <Typography variant="h6">{analytics.alert_count_30d}</Typography>
                    </Box>
                    {analytics.last_seen && (
                      <>
                        <Divider orientation="vertical" flexItem />
                        <Box>
                          <Typography variant="caption" color="text.secondary">
                            Last Seen
                          </Typography>
                          <Typography variant="body2">
                            {new Date(analytics.last_seen).toLocaleString()}
                          </Typography>
                        </Box>
                      </>
                    )}
                  </Stack>
                </Paper>
              </Box>
            )}
          </DialogTitle>

          <Tabs
            value={tabValue}
            onChange={handleTabChange}
            sx={{ borderBottom: 1, borderColor: 'divider', px: 3 }}
          >
            <Tab label="Description" icon={<DescriptionIcon />} iconPosition="start" />
            <Tab label={`Rules (${rules.length})`} icon={<CodeIcon />} iconPosition="start" />
            <Tab label={`Alerts (${alerts.length})`} icon={<WarningIcon />} iconPosition="start" />
            <Tab label="Detection Methods" icon={<SecurityIcon />} iconPosition="start" />
          </Tabs>

          <DialogContent sx={{ pt: 0 }}>
            {/* Description Tab */}
            <TabPanel value={tabValue} index={0}>
              <Box>
                {formatDescription(technique.description)}
              </Box>
            </TabPanel>

            {/* Detection Rules Tab */}
            <TabPanel value={tabValue} index={1}>
              {rules.length > 0 ? (
                <TableContainer>
                  <Table size="small">
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
                        <TableRow
                          key={rule.id}
                          hover
                          onClick={() => handleOpenRuleModal(rule)}
                          sx={{
                            cursor: 'pointer',
                            '&:hover': {
                              backgroundColor: 'action.hover'}}}
                        >
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

            {/* Recent Alerts Tab */}
            <TabPanel value={tabValue} index={2}>
              {alerts.length > 0 ? (
                <TableContainer>
                  <Table size="small">
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
                          <TableCell>
                            <Typography variant="caption" fontFamily="monospace">
                              {alert.alert_id?.substring(0, 8)}...
                            </Typography>
                          </TableCell>
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

            {/* Detection Methods Tab */}
            <TabPanel value={tabValue} index={3}>
              {technique.detection ? (
                <Box>
                  {formatDescription(technique.detection)}
                </Box>
              ) : (
                <Box textAlign="center" py={4}>
                  <Typography variant="body2" color="text.secondary">
                    No detection methods documented for this technique
                  </Typography>
                </Box>
              )}
            </TabPanel>
          </DialogContent>
        </>
      )}
    </Dialog>

    {/* Rule Detail Modal */}
    <RuleDetailModal
      open={ruleModalOpen}
      rule={selectedRule}
      onClose={handleCloseRuleModal}
    />
    </>
  );
};

export default MitreTechniqueModal;
