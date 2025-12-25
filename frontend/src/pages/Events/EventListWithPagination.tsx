import { useState, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
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
  Button,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  NavigateBefore as PrevIcon,
  NavigateNext as NextIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { apiService } from '../../services/api';
import { EventsPage } from '../../schemas/api.schemas';
import { TableSkeleton } from '../../components/LoadingSkeletons';

/**
 * Events list with cursor-based pagination
 *
 * PERFORMANCE: Uses cursor-based pagination for O(1) lookups
 * ACCESSIBILITY: Keyboard navigation, ARIA labels, focus management
 * UX: Loading skeletons, error states, empty states
 */
export function EventListWithPagination() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [cursorHistory, setCursorHistory] = useState<string[]>([]);

  const cursor = searchParams.get('cursor') || undefined;
  const limit = 50;

  const { data, isLoading, error, refetch, isFetching } = useQuery<EventsPage>({
    queryKey: ['events-cursor', cursor],
    queryFn: () => apiService.events.getEventsPage(cursor, limit),
    keepPreviousData: true,
    staleTime: 30000, // 30 seconds
    refetchInterval: 60000, // Auto-refresh every minute
  });

  const handleNextPage = useCallback(() => {
    if (data?.next_cursor) {
      // Store current cursor in history for back navigation
      setCursorHistory(prev => [...prev, cursor || '']);
      setSearchParams({ cursor: data.next_cursor });
    }
  }, [data?.next_cursor, cursor, setSearchParams]);

  const handlePrevPage = useCallback(() => {
    if (cursorHistory.length > 0) {
      const prevCursor = cursorHistory[cursorHistory.length - 1];
      setCursorHistory(prev => prev.slice(0, -1));

      if (prevCursor) {
        setSearchParams({ cursor: prevCursor });
      } else {
        setSearchParams({});
      }
    }
  }, [cursorHistory, setSearchParams]);

  const handleRefresh = useCallback(() => {
    refetch();
  }, [refetch]);

  const getSeverityColor = (severity: string) => {
    const severityLower = severity.toLowerCase();
    if (severityLower === 'critical') return 'error';
    if (severityLower === 'high') return 'error';
    if (severityLower === 'medium') return 'warning';
    if (severityLower === 'low') return 'info';
    return 'default';
  };

  // Error state
  if (error && !data) {
    return (
      <Box>
        <Typography variant="h4" gutterBottom>
          Security Events
        </Typography>
        <Alert severity="error">
          Failed to load events. Please check your connection and try again.
          <Box sx={{ mt: 1 }}>
            <Button onClick={handleRefresh} size="small" variant="outlined">
              Retry
            </Button>
          </Box>
        </Alert>
      </Box>
    );
  }

  // Empty state
  const isEmpty = !isLoading && (!data?.events || data.events.length === 0);

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h4">Security Events</Typography>
        <Tooltip title="Refresh events">
          <IconButton
            onClick={handleRefresh}
            disabled={isFetching}
            aria-label="Refresh events"
          >
            <RefreshIcon />
          </IconButton>
        </Tooltip>
      </Box>

      {/* Loading indicator during background refresh */}
      {isFetching && !isLoading && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Refreshing events...
        </Alert>
      )}

      {/* Table */}
      <TableContainer component={Paper}>
        <Table aria-label="Events table">
          <TableHead>
            <TableRow>
              <TableCell>Timestamp</TableCell>
              <TableCell>Event Type</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Source IP</TableCell>
              <TableCell>Source Format</TableCell>
              <TableCell>Fields Preview</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading ? (
              <TableSkeleton rows={10} columns={6} />
            ) : isEmpty ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Box sx={{ py: 4 }}>
                    <Typography variant="body1" color="text.secondary">
                      No events found
                    </Typography>
                  </Box>
                </TableCell>
              </TableRow>
            ) : (
              data?.events.map((event) => (
                <TableRow
                  key={event.event_id}
                  hover
                  sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                >
                  <TableCell>
                    <Typography variant="body2" noWrap>
                      {new Date(event.timestamp).toLocaleString()}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" noWrap>
                      {event.event_type}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={event.severity}
                      color={getSeverityColor(event.severity)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" noWrap>
                      {event.source_ip}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" noWrap>
                      {event.source_format}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Box
                      component="pre"
                      sx={{
                        maxWidth: 300,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        fontSize: '0.75rem',
                        margin: 0,
                        fontFamily: 'monospace',
                      }}
                    >
                      {JSON.stringify(event.fields)}
                    </Box>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Pagination Controls */}
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          mt: 2,
          px: 2,
        }}
        role="navigation"
        aria-label="Pagination"
      >
        <Button
          variant="outlined"
          startIcon={<PrevIcon />}
          disabled={cursorHistory.length === 0 || isLoading}
          onClick={handlePrevPage}
          aria-label="Previous page"
        >
          Previous
        </Button>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="body2" color="text.secondary">
            {isLoading ? (
              'Loading...'
            ) : (
              <>Showing {data?.events.length || 0} events</>
            )}
          </Typography>
          {data?.has_more && (
            <Chip label="More available" size="small" color="primary" variant="outlined" />
          )}
        </Box>

        <Button
          variant="contained"
          endIcon={<NextIcon />}
          disabled={!data?.has_more || isLoading}
          onClick={handleNextPage}
          aria-label="Next page"
        >
          Next
        </Button>
      </Box>
    </Box>
  );
}
