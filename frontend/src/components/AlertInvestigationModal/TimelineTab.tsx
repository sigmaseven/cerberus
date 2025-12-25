import { Box, Typography, Card, CardContent, Chip, CircularProgress } from '@mui/material';
import { Timeline, TimelineItem, TimelineSeparator, TimelineConnector, TimelineContent, TimelineDot, TimelineOppositeContent } from '@mui/lab';
import { FiberManualRecord, CheckCircle, Person, Update, Cancel, Error, Info } from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { apiService } from '../../services/api';
import { Alert, StatusChange, AlertStatus } from '../../types';

interface TimelineTabProps {
  alert: Alert;
}

const TimelineTab = ({ alert }: TimelineTabProps) => {
  const { data: history, isLoading, error } = useQuery({
    queryKey: ['alert-history', alert.alert_id],
    queryFn: () => apiService.getAlertHistory(alert.alert_id),
  });

  const getStatusIcon = (status: AlertStatus) => {
    switch (status) {
      case 'new':
        return <FiberManualRecord />;
      case 'acknowledged':
        return <CheckCircle />;
      case 'investigating':
        return <Info />;
      case 'assigned':
        return <Person />;
      case 'resolved':
        return <CheckCircle />;
      case 'false_positive':
        return <Info />;
      case 'dismissed':
        return <Cancel />;
      default:
        return <Update />;
    }
  };

  const getStatusColor = (status: AlertStatus): 'primary' | 'success' | 'error' | 'warning' | 'info' | 'grey' => {
    switch (status) {
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
        return 'grey';
      default:
        return 'grey';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return {
      time: date.toLocaleTimeString(),
      date: date.toLocaleDateString(),
    };
  };

  const getStatusLabel = (status: string) => {
    return status
      .split('_')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '400px' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Error color="error" sx={{ fontSize: 48, mb: 2 }} />
        <Typography variant="h6" color="error" gutterBottom>
          Failed to Load Timeline
        </Typography>
        <Typography color="text.secondary">
          {(error as Error).message || 'An error occurred while loading the alert history'}
        </Typography>
      </Box>
    );
  }

  if (!history || history.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center', color: 'text.secondary' }}>
        <Info sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
        <Typography variant="h6" gutterBottom>
          No History Available
        </Typography>
        <Typography>
          This alert has no status change history yet.
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>
        Alert Status History
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Track all status changes and actions taken on this alert
      </Typography>

      <Timeline position="right">
        {history.map((change: StatusChange, index: number) => {
          const timestamp = formatTimestamp(change.changed_at);
          const isLast = index === history.length - 1;

          return (
            <TimelineItem key={change.changed_at + `-${index}`}>
              <TimelineOppositeContent color="text.secondary" sx={{ flex: 0.2, py: 2 }}>
                <Typography variant="body2" fontWeight="bold">
                  {timestamp.time}
                </Typography>
                <Typography variant="caption">{timestamp.date}</Typography>
              </TimelineOppositeContent>

              <TimelineSeparator>
                <TimelineDot color={getStatusColor(change.to_status)} variant={index === 0 ? 'filled' : 'outlined'}>
                  {getStatusIcon(change.to_status)}
                </TimelineDot>
                {!isLast && <TimelineConnector />}
              </TimelineSeparator>

              <TimelineContent sx={{ py: 2 }}>
                <Card elevation={index === 0 ? 3 : 1} sx={{ mb: 2 }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <Chip
                        label={getStatusLabel(change.from_status)}
                        size="small"
                        variant="outlined"
                        color={getStatusColor(change.from_status)}
                      />
                      <Typography variant="body2" color="text.secondary">
                        →
                      </Typography>
                      <Chip
                        label={getStatusLabel(change.to_status)}
                        size="small"
                        color={getStatusColor(change.to_status)}
                      />
                    </Box>

                    <Typography variant="body2" color="text.secondary" sx={{ mb: change.note ? 1 : 0 }}>
                      Changed by: <strong>{change.changed_by || 'System'}</strong>
                    </Typography>

                    {change.note && (
                      <Box
                        sx={{
                          mt: 1,
                          p: 1.5,
                          backgroundColor: 'rgba(0, 0, 0, 0.03)',
                          borderRadius: 1,
                          borderLeft: 3,
                          borderColor: 'primary.main',
                        }}
                      >
                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                          Note:
                        </Typography>
                        <Typography variant="body2">{change.note}</Typography>
                      </Box>
                    )}
                  </CardContent>
                </Card>
              </TimelineContent>
            </TimelineItem>
          );
        })}
      </Timeline>
    </Box>
  );
};

export default TimelineTab;
