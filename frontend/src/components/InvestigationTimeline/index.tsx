import React from 'react';
import {
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineConnector,
  TimelineContent,
  TimelineDot,
  TimelineOppositeContent,
} from '@mui/lab';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  IconButton,
  Collapse,
  Alert,
} from '@mui/material';
import {
  Warning as AlertIcon,
  Note as NoteIcon,
  ExpandMore as ExpandMoreIcon,
  Person as PersonIcon,
} from '@mui/icons-material';
import { InvestigationNote } from '../../types';

export interface TimelineEvent {
  type: 'alert' | 'note' | 'status_change' | 'assignment';
  timestamp: string;
  data: Record<string, unknown>;
  analyst_id?: string;
}

interface InvestigationTimelineProps {
  events: TimelineEvent[];
  loading?: boolean;
  compact?: boolean;
}

/**
 * InvestigationTimeline displays a chronological history of events in an investigation
 * Shows alerts, notes, status changes, and assignments in timeline format
 */
export const InvestigationTimeline: React.FC<InvestigationTimelineProps> = ({
  events,
  loading = false,
  compact = false,
}) => {
  const [expanded, setExpanded] = React.useState<Record<number, boolean>>({});

  const toggleExpanded = (index: number) => {
    setExpanded(prev => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const formatTimestamp = (timestamp: string): string => {
    const date = new Date(timestamp);
    if (compact) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    return date.toLocaleString([], {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'alert':
        return <AlertIcon />;
      case 'note':
        return <NoteIcon />;
      case 'status_change':
        return <PersonIcon />;
      case 'assignment':
        return <PersonIcon />;
      default:
        return <NoteIcon />;
    }
  };

  const getEventColor = (type: string): 'primary' | 'secondary' | 'warning' | 'error' | 'info' | 'success' => {
    switch (type) {
      case 'alert':
        return 'error';
      case 'note':
        return 'info';
      case 'status_change':
        return 'primary';
      case 'assignment':
        return 'secondary';
      default:
        return 'primary';
    }
  };

  const renderAlertEvent = (event: TimelineEvent, index: number) => {
    const alert = event.data;
    const isExpanded = expanded[index];

    return (
      <Card variant="outlined" sx={{ mb: 1 }}>
        <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <Box sx={{ flex: 1 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <Chip
                  label={alert.severity || 'Unknown'}
                  size="small"
                  color={alert.severity === 'critical' ? 'error' : alert.severity === 'high' ? 'warning' : 'default'}
                  sx={{ height: 20, fontSize: '0.7rem' }}
                />
                <Typography variant="caption" color="text.secondary">
                  Alert ID: {alert.alert_id}
                </Typography>
              </Box>

              <Typography variant="body2" sx={{ mb: 1 }}>
                <strong>Rule:</strong> {alert.rule_name || alert.rule_id || 'Unknown'}
              </Typography>

              {!compact && (
                <>
                  <IconButton
                    size="small"
                    onClick={() => toggleExpanded(index)}
                    sx={{
                      transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: 'transform 0.3s',
                    }}
                  >
                    <ExpandMoreIcon fontSize="small" />
                  </IconButton>

                  <Collapse in={isExpanded}>
                    <Box sx={{ mt: 1, pl: 2, borderLeft: '2px solid', borderColor: 'divider' }}>
                      {alert.event && (
                        <>
                          <Typography variant="caption" color="text.secondary" display="block">
                            Event Details:
                          </Typography>
                          <Typography variant="body2" component="pre" sx={{ mt: 0.5, fontSize: '0.75rem', fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                            {JSON.stringify(alert.event, null, 2)}
                          </Typography>
                        </>
                      )}
                    </Box>
                  </Collapse>
                </>
              )}
            </Box>
          </Box>
        </CardContent>
      </Card>
    );
  };

  const renderNoteEvent = (event: TimelineEvent) => {
    const note = event.data as InvestigationNote;

    return (
      <Card variant="outlined" sx={{ mb: 1, backgroundColor: 'rgba(33, 150, 243, 0.04)' }}>
        <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
            <PersonIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
            <Typography variant="caption" color="text.secondary">
              {note.analyst_id}
            </Typography>
          </Box>
          <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
            {note.content}
          </Typography>
        </CardContent>
      </Card>
    );
  };

  const renderStatusChangeEvent = (event: TimelineEvent) => {
    return (
      <Alert severity="info" sx={{ mb: 1 }}>
        <Typography variant="body2">
          Status changed to <strong>{event.data.new_status}</strong>
          {event.analyst_id && ` by ${event.analyst_id}`}
        </Typography>
      </Alert>
    );
  };

  const renderAssignmentEvent = (event: TimelineEvent) => {
    return (
      <Alert severity="info" sx={{ mb: 1 }}>
        <Typography variant="body2">
          Assigned to <strong>{event.data.assignee_id}</strong>
          {event.analyst_id && ` by ${event.analyst_id}`}
        </Typography>
      </Alert>
    );
  };

  const renderEventContent = (event: TimelineEvent, index: number) => {
    switch (event.type) {
      case 'alert':
        return renderAlertEvent(event, index);
      case 'note':
        return renderNoteEvent(event);
      case 'status_change':
        return renderStatusChangeEvent(event);
      case 'assignment':
        return renderAssignmentEvent(event);
      default:
        return (
          <Typography variant="body2">
            Unknown event type: {event.type}
          </Typography>
        );
    }
  };

  if (loading) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          Loading timeline...
        </Typography>
      </Box>
    );
  }

  if (events.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          No events in timeline yet
        </Typography>
      </Box>
    );
  }

  return (
    <Timeline position={compact ? 'right' : 'alternate'}>
      {events.map((event, index) => (
        <TimelineItem key={index}>
          {!compact && (
            <TimelineOppositeContent color="text.secondary" sx={{ py: 2, px: 2 }}>
              <Typography variant="caption" component="div">
                {formatTimestamp(event.timestamp)}
              </Typography>
            </TimelineOppositeContent>
          )}

          <TimelineSeparator>
            <TimelineDot color={getEventColor(event.type)} variant="outlined">
              {getEventIcon(event.type)}
            </TimelineDot>
            {index < events.length - 1 && <TimelineConnector />}
          </TimelineSeparator>

          <TimelineContent sx={{ py: compact ? 1 : 2, px: 2 }}>
            {compact && (
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                {formatTimestamp(event.timestamp)}
              </Typography>
            )}
            {renderEventContent(event, index)}
          </TimelineContent>
        </TimelineItem>
      ))}
    </Timeline>
  );
};

export default InvestigationTimeline;
