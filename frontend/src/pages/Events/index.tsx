import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Alert,
  CircularProgress,
} from '@mui/material';
import { apiService } from '../../services/api';
import { Event } from '../../types';

function Events() {
  const [newEvents, setNewEvents] = useState<Event[]>([]);

  const { data: events, isLoading, error, refetch } = useQuery({
    queryKey: ['events'],
    queryFn: () => apiService.getEvents(100),
  });

  useEffect(() => {
    // Subscribe to real-time event updates
    apiService.subscribeToRealtimeUpdates({
      onEvent: (event: Event) => {
        // Add new event to the beginning of the list
        setNewEvents(prev => [event, ...prev.slice(0, 9)]); // Keep only last 10 new events

        // Refetch events to get the latest data
        refetch();
      },
    });

    // Cleanup on unmount
    return () => {
      apiService.unsubscribeFromRealtimeUpdates();
    };
  }, [refetch]);

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error">
        Failed to load events. Please check your connection and try again.
      </Alert>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Security Events
      </Typography>

      {newEvents.length > 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="body2">
            📡 {newEvents.length} new event{newEvents.length !== 1 ? 's' : ''} received
          </Typography>
        </Alert>
      )}

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Timestamp</TableCell>
              <TableCell>Event Type</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Source IP</TableCell>
              <TableCell>Raw Data</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {events?.map((event) => (
              <TableRow key={event.event_id}>
                <TableCell>
                  {new Date(event.timestamp).toLocaleString()}
                </TableCell>
                <TableCell>{event.event_type}</TableCell>
                <TableCell>
                  <Chip
                    label={event.severity}
                    color={
                      event.severity === 'critical' ? 'error' :
                      event.severity === 'high' ? 'error' :
                      event.severity === 'medium' ? 'warning' :
                      event.severity === 'low' ? 'info' : 'default'
                    }
                    size="small"
                  />
                </TableCell>
                <TableCell>{event.source_ip}</TableCell>
                <TableCell>
                  <Box
                    component="pre"
                    sx={{
                      maxWidth: 300,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      fontSize: '0.75rem',
                    }}
                  >
                    {JSON.stringify(event.fields)}
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

export default Events;