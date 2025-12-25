import React from 'react';
import {
  Box,
  Container,
  Typography,
  Button,
  Paper,
  Tabs,
  Tab,
  Chip,
  Grid,
  Card,
  CardContent,
  TextField,
  IconButton,
  Tooltip,
  Alert,
  CircularProgress,
  Stack,
  Divider,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import {
  ArrowBack as BackIcon,
  Edit as EditIcon,
  Close as CloseIcon,
  NoteAdd as NoteIcon,
  Link as LinkIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../../services/api';
import { InvestigationTimeline } from '../../components/InvestigationTimeline';
import { VerdictModal } from '../../components/VerdictModal';
import { MitreBadge } from '../../components/MitreBadge';
import type { Investigation, InvestigationStatus, InvestigationPriority } from '../../types';

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
      id={`workspace-tabpanel-${index}`}
      aria-labelledby={`workspace-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

export const InvestigationWorkspace: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [tabValue, setTabValue] = React.useState(0);
  const [verdictModalOpen, setVerdictModalOpen] = React.useState(false);
  const [newNote, setNewNote] = React.useState('');
  const [newAlertId, setNewAlertId] = React.useState('');

  // Fetch investigation details
  const { data: investigation, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['investigation', id],
    queryFn: () => api.investigations.getInvestigation(id!),
    enabled: !!id,
  });

  // Fetch timeline
  const { data: timelineData } = useQuery({
    queryKey: ['investigation-timeline', id],
    queryFn: () => api.investigations.getTimeline(id!),
    enabled: !!id,
  });

  // Add note mutation
  const addNoteMutation = useMutation({
    mutationFn: ({ investigationId, content }: { investigationId: string; content: string }) =>
      api.investigations.addNote(investigationId, content),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['investigation', id] });
      queryClient.invalidateQueries({ queryKey: ['investigation-timeline', id] });
      setNewNote('');
    },
  });

  // Add alert mutation
  const addAlertMutation = useMutation({
    mutationFn: ({ investigationId, alertId }: { investigationId: string; alertId: string }) =>
      api.investigations.addAlert(investigationId, alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['investigation', id] });
      queryClient.invalidateQueries({ queryKey: ['investigation-timeline', id] });
      setNewAlertId('');
    },
  });

  // Close investigation mutation
  const closeInvestigationMutation = useMutation({
    mutationFn: (data: any) => api.investigations.closeInvestigation(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['investigation', id] });
      queryClient.invalidateQueries({ queryKey: ['investigations'] });
    },
  });

  const handleAddNote = () => {
    if (newNote.trim() && id) {
      addNoteMutation.mutate({ investigationId: id, content: newNote.trim() });
    }
  };

  const handleAddAlert = () => {
    if (newAlertId.trim() && id) {
      addAlertMutation.mutate({ investigationId: id, alertId: newAlertId.trim() });
    }
  };

  const getPriorityColor = (priority: InvestigationPriority): string => {
    const colors: Record<InvestigationPriority, string> = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#22c55e',
    };
    return colors[priority];
  };

  const getStatusColor = (status: InvestigationStatus): string => {
    const colors: Record<InvestigationStatus, string> = {
      open: '#3b82f6',
      in_progress: '#8b5cf6',
      awaiting_review: '#f59e0b',
      closed: '#6b7280',
      resolved: '#10b981',
      false_positive: '#64748b',
    };
    return colors[status];
  };

  if (isLoading) {
    return (
      <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
          <CircularProgress />
        </Box>
      </Container>
    );
  }

  if (isError || !investigation) {
    return (
      <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <Typography color="error" gutterBottom>
            Error loading investigation
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {error instanceof Error ? error.message : 'Investigation not found'}
          </Typography>
          <Button onClick={() => navigate('/investigations')} sx={{ mt: 2 }}>
            Back to Investigations
          </Button>
        </Paper>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <IconButton onClick={() => navigate('/investigations')}>
            <BackIcon />
          </IconButton>
          <Typography variant="caption" color="text.secondary">
            {investigation.investigation_id}
          </Typography>
          <Chip
            label={investigation.status.replace('_', ' ')}
            size="small"
            sx={{
              backgroundColor: getStatusColor(investigation.status),
              color: '#ffffff',
              fontWeight: 500,
              textTransform: 'capitalize',
            }}
          />
          <Chip
            label={investigation.priority}
            size="small"
            sx={{
              backgroundColor: getPriorityColor(investigation.priority),
              color: '#ffffff',
              fontWeight: 500,
              textTransform: 'capitalize',
            }}
          />
        </Box>

        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="h4" component="h1" gutterBottom fontWeight={600}>
              {investigation.title}
            </Typography>
            <Typography variant="body1" color="text.secondary" paragraph>
              {investigation.description}
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', gap: 1 }}>
            <Tooltip title="Refresh">
              <IconButton onClick={() => refetch()}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
            {investigation.status !== 'closed' && (
              <Button
                variant="contained"
                color="error"
                startIcon={<CloseIcon />}
                onClick={() => setVerdictModalOpen(true)}
              >
                Close Investigation
              </Button>
            )}
          </Box>
        </Box>
      </Box>

      {/* Metadata Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                Created
              </Typography>
              <Typography variant="body2">
                {new Date(investigation.created_at).toLocaleString()}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                by {investigation.created_by}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                Last Updated
              </Typography>
              <Typography variant="body2">
                {new Date(investigation.updated_at).toLocaleString()}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                Assigned To
              </Typography>
              <Typography variant="body2">
                {investigation.assignee_id || 'Unassigned'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                Alerts
              </Typography>
              <Typography variant="h5" fontWeight={600}>
                {investigation.alert_ids.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={(_e, v) => setTabValue(v)}>
          <Tab label="Overview" />
          <Tab label={`Alerts (${investigation.alert_ids.length})`} />
          <Tab label={`Notes (${investigation.notes?.length || 0})`} />
          <Tab label="Timeline" />
          <Tab label="MITRE ATT&CK" />
        </Tabs>
      </Box>

      {/* Tab Panels */}
      <TabPanel value={tabValue} index={0}>
        {/* Overview */}
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Investigation Details
              </Typography>
              <Divider sx={{ mb: 2 }} />

              <Box sx={{ mb: 2 }}>
                <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                  Priority
                </Typography>
                <Chip
                  label={investigation.priority}
                  sx={{
                    backgroundColor: getPriorityColor(investigation.priority),
                    color: '#ffffff',
                    textTransform: 'capitalize',
                  }}
                />
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                  Status
                </Typography>
                <Chip
                  label={investigation.status.replace('_', ' ')}
                  sx={{
                    backgroundColor: getStatusColor(investigation.status),
                    color: '#ffffff',
                    textTransform: 'capitalize',
                  }}
                />
              </Box>

              {investigation.verdict && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                    Verdict
                  </Typography>
                  <Chip
                    label={investigation.verdict.replace('_', ' ')}
                    color={investigation.verdict === 'true_positive' ? 'error' : 'success'}
                    sx={{ textTransform: 'capitalize' }}
                  />
                </Box>
              )}

              {investigation.resolution_category && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                    Resolution Category
                  </Typography>
                  <Typography variant="body2">{investigation.resolution_category}</Typography>
                </Box>
              )}

              {investigation.summary && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                    Summary
                  </Typography>
                  <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                    {investigation.summary}
                  </Typography>
                </Box>
              )}
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            {investigation.artifacts && (
              <Paper sx={{ p: 3, mb: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Artifacts
                </Typography>
                <Divider sx={{ mb: 2 }} />

                {investigation.artifacts.ip_addresses && investigation.artifacts.ip_addresses.length > 0 && (
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                      IP Addresses
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {investigation.artifacts.ip_addresses.map((ip) => (
                        <Chip key={ip} label={ip} size="small" variant="outlined" />
                      ))}
                    </Stack>
                  </Box>
                )}

                {investigation.artifacts.hostnames && investigation.artifacts.hostnames.length > 0 && (
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                      Hostnames
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {investigation.artifacts.hostnames.map((host) => (
                        <Chip key={host} label={host} size="small" variant="outlined" />
                      ))}
                    </Stack>
                  </Box>
                )}

                {investigation.artifacts.usernames && investigation.artifacts.usernames.length > 0 && (
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                      Usernames
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {investigation.artifacts.usernames.map((user) => (
                        <Chip key={user} label={user} size="small" variant="outlined" />
                      ))}
                    </Stack>
                  </Box>
                )}
              </Paper>
            )}

            {investigation.affected_assets && investigation.affected_assets.length > 0 && (
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Affected Assets
                </Typography>
                <Divider sx={{ mb: 2 }} />
                <List dense>
                  {investigation.affected_assets.map((asset, idx) => (
                    <ListItem key={idx}>
                      <ListItemText primary={asset} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            )}
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        {/* Alerts */}
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h6">Linked Alerts</Typography>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <TextField
                size="small"
                placeholder="Alert ID"
                value={newAlertId}
                onChange={(e) => setNewAlertId(e.target.value)}
              />
              <Button
                variant="contained"
                startIcon={<LinkIcon />}
                onClick={handleAddAlert}
                disabled={!newAlertId.trim() || addAlertMutation.isPending}
              >
                Link Alert
              </Button>
            </Box>
          </Box>

          {investigation.alert_ids.length === 0 ? (
            <Alert severity="info">No alerts linked to this investigation yet</Alert>
          ) : (
            <List>
              {investigation.alert_ids.map((alertId) => (
                <ListItem key={alertId} divider>
                  <ListItemText
                    primary={alertId}
                    secondary="Click to view alert details"
                  />
                  <Button size="small" onClick={() => navigate(`/alerts/${alertId}`)}>
                    View
                  </Button>
                </ListItem>
              ))}
            </List>
          )}
        </Paper>
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        {/* Notes */}
        <Paper sx={{ p: 3 }}>
          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Add Note
            </Typography>
            <TextField
              fullWidth
              multiline
              rows={3}
              placeholder="Enter your investigation notes..."
              value={newNote}
              onChange={(e) => setNewNote(e.target.value)}
              sx={{ mb: 2 }}
            />
            <Button
              variant="contained"
              startIcon={<NoteIcon />}
              onClick={handleAddNote}
              disabled={!newNote.trim() || addNoteMutation.isPending}
            >
              Add Note
            </Button>
          </Box>

          <Divider sx={{ my: 3 }} />

          {!investigation.notes || investigation.notes.length === 0 ? (
            <Alert severity="info">No notes added yet</Alert>
          ) : (
            <Stack spacing={2}>
              {investigation.notes.map((note) => (
                <Card key={note.id} variant="outlined">
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                      <Typography variant="caption" color="text.secondary">
                        {note.analyst_id}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {new Date(note.created_at).toLocaleString()}
                      </Typography>
                    </Box>
                    <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                      {note.content}
                    </Typography>
                  </CardContent>
                </Card>
              ))}
            </Stack>
          )}
        </Paper>
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        {/* Timeline */}
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Investigation Timeline
          </Typography>
          <Divider sx={{ mb: 3 }} />
          {timelineData && (
            <InvestigationTimeline events={timelineData.events} />
          )}
        </Paper>
      </TabPanel>

      <TabPanel value={tabValue} index={4}>
        {/* MITRE ATT&CK */}
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                MITRE Tactics
              </Typography>
              <Divider sx={{ mb: 2 }} />
              {!investigation.mitre_tactics || investigation.mitre_tactics.length === 0 ? (
                <Alert severity="info">No MITRE tactics mapped</Alert>
              ) : (
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {investigation.mitre_tactics.map((tacticId) => (
                    <MitreBadge key={tacticId} id={tacticId} type="tactic" size="medium" />
                  ))}
                </Stack>
              )}
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                MITRE Techniques
              </Typography>
              <Divider sx={{ mb: 2 }} />
              {!investigation.mitre_techniques || investigation.mitre_techniques.length === 0 ? (
                <Alert severity="info">No MITRE techniques mapped</Alert>
              ) : (
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {investigation.mitre_techniques.map((techniqueId) => (
                    <MitreBadge key={techniqueId} id={techniqueId} type="technique" size="medium" />
                  ))}
                </Stack>
              )}
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Verdict Modal */}
      <VerdictModal
        open={verdictModalOpen}
        onClose={() => setVerdictModalOpen(false)}
        onSubmit={(data) => closeInvestigationMutation.mutateAsync(data)}
        investigationId={investigation.investigation_id}
        investigationTitle={investigation.title}
      />
    </Container>
  );
};

export default InvestigationWorkspace;
