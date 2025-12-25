import { Box, Typography, Card, CardContent, Chip, CircularProgress, Grid, Tabs, Tab, Table, TableHead, TableBody, TableRow, TableCell, IconButton } from '@mui/material';
import { Warning, Event as EventIcon, OpenInNew, ContentCopy } from '@mui/icons-material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getSeverityColor } from '../../utils/severity';
import { apiService } from '../../services/api';
import { Alert } from '../../types';

interface RelatedTabProps {
  alert: Alert;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel = (props: TabPanelProps) => {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
};

const RelatedTab = ({ alert }: RelatedTabProps) => {
  const [tabValue, setTabValue] = useState(0);

  // Query for related alerts by source IP
  const { data: alertsByIP, isLoading: loadingAlertsByIP } = useQuery({
    queryKey: ['related-alerts-ip', alert.event.source_ip],
    queryFn: () => apiService.getAlerts({ page: 0, limit: 10 }),
    select: (data) => {
      // Filter alerts with same source IP but different alert ID
      return data.alerts.filter(
        (a) => a.event.source_ip === alert.event.source_ip && a.alert_id !== alert.alert_id
      );
    },
  });

  // Query for related alerts by same rule
  const { data: alertsByRule, isLoading: loadingAlertsByRule } = useQuery({
    queryKey: ['related-alerts-rule', alert.rule_id],
    queryFn: () => apiService.getAlerts({ page: 0, limit: 10 }),
    select: (data) => {
      // Filter alerts with same rule but different alert ID
      return data.alerts.filter((a) => a.rule_id === alert.rule_id && a.alert_id !== alert.alert_id);
    },
  });

  // Query for related events in time window (±30 minutes)
  const { data: relatedEvents, isLoading: loadingEvents } = useQuery({
    queryKey: ['related-events', alert.event.source_ip, alert.timestamp],
    queryFn: () => apiService.getEvents({ page: 0, limit: 20 }),
    select: (data) => {
      const alertTime = new Date(alert.timestamp).getTime();
      const thirtyMinutes = 30 * 60 * 1000;
      // Filter events from same IP within ±30 minutes
      return data.events.filter((e) => {
        const eventTime = new Date(e.timestamp).getTime();
        return (
          e.source_ip === alert.event.source_ip &&
          e.event_id !== alert.event.event_id &&
          Math.abs(eventTime - alertTime) <= thirtyMinutes
        );
      });
    },
  });

  const getStatusColor = (status: string): "warning" | "info" | "primary" | "success" | "default" => {
    switch (status.toLowerCase()) {
      case 'new':
      case 'pending':
        return 'warning';
      case 'acknowledged':
        return 'info';
      case 'investigating':
        return 'primary';
      case 'resolved':
        return 'success';
      case 'dismissed':
      case 'false_positive':
        return 'default';
      default:
        return 'default';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const openAlert = (alertId: string) => { // eslint-disable-line @typescript-eslint/no-unused-vars
    // Open in new investigation modal - for now just show alert
    // TODO: Implement alert opening functionality
  };

  return (
    <Box>
      {/* Summary Cards */}
      <Box sx={{ p: 2, backgroundColor: '#f5f5f5' }}>
        <Grid container spacing={2}>
          <Grid  size={{ xs: 12, md: 4 }}>
            <Card elevation={2}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <Warning color="warning" />
                  <Typography variant="h6">
                    {loadingAlertsByIP ? '-' : alertsByIP?.length || 0}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Alerts from Same IP
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid  size={{ xs: 12, md: 4 }}>
            <Card elevation={2}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <Warning color="error" />
                  <Typography variant="h6">
                    {loadingAlertsByRule ? '-' : alertsByRule?.length || 0}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Alerts from Same Rule
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid  size={{ xs: 12, md: 4 }}>
            <Card elevation={2}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <EventIcon color="primary" />
                  <Typography variant="h6">{loadingEvents ? '-' : relatedEvents?.length || 0}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Related Events (±30min)
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>

      {/* Tabbed Content */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)}>
          <Tab label={`Same IP (${alertsByIP?.length || 0})`} />
          <Tab label={`Same Rule (${alertsByRule?.length || 0})`} />
          <Tab label={`Related Events (${relatedEvents?.length || 0})`} />
        </Tabs>
      </Box>

      {/* Tab 1: Alerts from Same IP */}
      <TabPanel value={tabValue} index={0}>
        {loadingAlertsByIP ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : !alertsByIP || alertsByIP.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 4, color: 'text.secondary' }}>
            <Warning sx={{ fontSize: 48, opacity: 0.3, mb: 2 }} />
            <Typography>No other alerts found from this IP address</Typography>
          </Box>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Timestamp</TableCell>
                <TableCell>Alert ID</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Rule</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {alertsByIP.map((relatedAlert) => (
                <TableRow key={relatedAlert.alert_id}>
                  <TableCell>{formatTimestamp(relatedAlert.timestamp)}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                    {relatedAlert.alert_id.substring(0, 8)}...
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={relatedAlert.severity}
                      color={getSeverityColor(relatedAlert.severity)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={relatedAlert.status}
                      color={getStatusColor(relatedAlert.status)}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                    {relatedAlert.rule_id}
                  </TableCell>
                  <TableCell>
                    <IconButton size="small" onClick={() => copyToClipboard(relatedAlert.alert_id)}>
                      <ContentCopy fontSize="small" />
                    </IconButton>
                    <IconButton size="small" onClick={() => openAlert(relatedAlert.alert_id)}>
                      <OpenInNew fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </TabPanel>

      {/* Tab 2: Alerts from Same Rule */}
      <TabPanel value={tabValue} index={1}>
        {loadingAlertsByRule ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : !alertsByRule || alertsByRule.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 4, color: 'text.secondary' }}>
            <Warning sx={{ fontSize: 48, opacity: 0.3, mb: 2 }} />
            <Typography>No other alerts found from this rule</Typography>
          </Box>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Timestamp</TableCell>
                <TableCell>Alert ID</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Source IP</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {alertsByRule.map((relatedAlert) => (
                <TableRow key={relatedAlert.alert_id}>
                  <TableCell>{formatTimestamp(relatedAlert.timestamp)}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                    {relatedAlert.alert_id.substring(0, 8)}...
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={relatedAlert.severity}
                      color={getSeverityColor(relatedAlert.severity)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={relatedAlert.status}
                      color={getStatusColor(relatedAlert.status)}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{relatedAlert.event.source_ip}</TableCell>
                  <TableCell>
                    <IconButton size="small" onClick={() => copyToClipboard(relatedAlert.alert_id)}>
                      <ContentCopy fontSize="small" />
                    </IconButton>
                    <IconButton size="small" onClick={() => openAlert(relatedAlert.alert_id)}>
                      <OpenInNew fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </TabPanel>

      {/* Tab 3: Related Events */}
      <TabPanel value={tabValue} index={2}>
        {loadingEvents ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : !relatedEvents || relatedEvents.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 4, color: 'text.secondary' }}>
            <EventIcon sx={{ fontSize: 48, opacity: 0.3, mb: 2 }} />
            <Typography>No related events found within 30 minutes of this alert</Typography>
          </Box>
        ) : (
          <>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Showing events from <strong>{alert.event.source_ip}</strong> within ±30 minutes of the alert
            </Typography>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Timestamp</TableCell>
                  <TableCell>Event Type</TableCell>
                  <TableCell>Event ID</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {relatedEvents.map((event) => (
                  <TableRow key={event.event_id}>
                    <TableCell>{formatTimestamp(event.timestamp)}</TableCell>
                    <TableCell>
                      <Chip label={event.event_type} variant="outlined" size="small" />
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                      {event.event_id.substring(0, 16)}...
                    </TableCell>
                    <TableCell>
                      <IconButton size="small" onClick={() => copyToClipboard(event.event_id)}>
                        <ContentCopy fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </>
        )}
      </TabPanel>
    </Box>
  );
};

export default RelatedTab;
