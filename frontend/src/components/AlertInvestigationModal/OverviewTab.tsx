import { Box, Typography, Grid, Card, CardContent, Chip, IconButton, Divider, Table, TableBody, TableRow, TableCell } from '@mui/material';
import { ContentCopy, OpenInNew } from '@mui/icons-material';
import { getSeverityColor } from '../../utils/severity';
import { Alert } from '../../types';
import ThreatIntelBadge from '../ThreatIntelBadge';

interface OverviewTabProps {
  alert: Alert;
}

const OverviewTab = ({ alert }: OverviewTabProps) => {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

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

  const whoisLookup = (ip: string) => {
    window.open(`https://who.is/whois-ip/ip-address/${ip}`, '_blank');
  };

  return (
    <Box sx={{ p: 2 }}>
      <Grid container spacing={3}>
        {/* Alert Metadata Section */}
        <Grid  size={{ xs: 12, md: 6 }}>
          <Card elevation={2}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Alert Details
              </Typography>
              <Divider sx={{ mb: 2 }} />

              <Table size="small">
                <TableBody>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold', width: '40%' }}>
                      Alert ID
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {alert.alert_id}
                        </Typography>
                        <IconButton size="small" onClick={() => copyToClipboard(alert.alert_id)}>
                          <ContentCopy fontSize="small" />
                        </IconButton>
                      </Box>
                    </TableCell>
                  </TableRow>

                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Rule ID
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {alert.rule_id}
                      </Typography>
                    </TableCell>
                  </TableRow>

                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Severity
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={alert.severity}
                        color={getSeverityColor(alert.severity)}
                        size="small"
                      />
                    </TableCell>
                  </TableRow>

                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Status
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={alert.status}
                        color={getStatusColor(alert.status)}
                        size="small"
                      />
                    </TableCell>
                  </TableRow>

                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      First Seen
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {formatTimestamp(alert.timestamp)}
                      </Typography>
                    </TableCell>
                  </TableRow>

                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Last Seen
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {formatTimestamp(alert.last_seen)}
                      </Typography>
                    </TableCell>
                  </TableRow>

                  {alert.duplicate_count > 1 && (
                    <TableRow>
                      <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                        Duplicate Count
                      </TableCell>
                      <TableCell>
                        <Chip label={alert.duplicate_count} color="primary" size="small" />
                      </TableCell>
                    </TableRow>
                  )}

                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Assigned To
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {alert.assigned_to || 'Unassigned'}
                      </Typography>
                    </TableCell>
                  </TableRow>

                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Disposition
                    </TableCell>
                    <TableCell>
                      {alert.disposition && alert.disposition !== 'undetermined' ? (
                        <Chip
                          label={alert.disposition.replace('_', ' ')}
                          size="small"
                          color={
                            alert.disposition === 'true_positive' ? 'error' :
                            alert.disposition === 'false_positive' ? 'success' :
                            alert.disposition === 'benign' ? 'info' :
                            alert.disposition === 'suspicious' ? 'warning' :
                            'default'
                          }
                        />
                      ) : (
                        <Typography variant="body2" color="text.secondary">
                          Not set
                        </Typography>
                      )}
                    </TableCell>
                  </TableRow>

                  {alert.disposition_reason && (
                    <TableRow>
                      <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                        Disposition Reason
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {alert.disposition_reason}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </Grid>

        {/* Event Details Section */}
        <Grid  size={{ xs: 12, md: 6 }}>
          <Card elevation={2}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Event Details
              </Typography>
              <Divider sx={{ mb: 2 }} />

              <Table size="small">
                <TableBody>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold', width: '40%' }}>
                      Event ID
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {alert.event.event_id}
                        </Typography>
                        <IconButton size="small" onClick={() => copyToClipboard(alert.event.event_id)}>
                          <ContentCopy fontSize="small" />
                        </IconButton>
                      </Box>
                    </TableCell>
                  </TableRow>

                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Event Type
                    </TableCell>
                    <TableCell>
                      <Chip label={alert.event.event_type} variant="outlined" size="small" />
                    </TableCell>
                  </TableRow>

                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Source IP
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {alert.event.source_ip}
                        </Typography>
                        <IconButton size="small" onClick={() => copyToClipboard(alert.event.source_ip)}>
                          <ContentCopy fontSize="small" />
                        </IconButton>
                        <IconButton size="small" onClick={() => whoisLookup(alert.event.source_ip)}>
                          <OpenInNew fontSize="small" />
                        </IconButton>
                      </Box>
                    </TableCell>
                  </TableRow>

                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Timestamp
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {formatTimestamp(alert.event.timestamp)}
                      </Typography>
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </Grid>

        {/* Threat Intelligence Section */}
        {alert.threat_intel && alert.threat_intel.length > 0 && (
          <Grid  size={{ xs: 12 }}>
            <Card elevation={2}>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Threat Intelligence
                </Typography>
                <Divider sx={{ mb: 2 }} />
                <ThreatIntelBadge threatIntel={alert.threat_intel} />
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Event Fields Section */}
        <Grid  size={{ xs: 12 }}>
          <Card elevation={2}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Event Fields
              </Typography>
              <Divider sx={{ mb: 2 }} />

              <Box
                component="pre"
                sx={{
                  backgroundColor: '#f5f5f5',
                  padding: 2,
                  borderRadius: 1,
                  overflow: 'auto',
                  maxHeight: 300,
                  fontSize: '0.875rem',
                  fontFamily: 'monospace',
                }}
              >
                {JSON.stringify(alert.event.fields, null, 2)}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default OverviewTab;
