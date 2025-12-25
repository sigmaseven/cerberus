import { useState } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  TablePagination,
  CircularProgress,
  Alert,
  Chip,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Snackbar,
  Stack,
  Card,
  CardContent,
  Grid,
} from '@mui/material';
import {
  Search as SearchIcon,
  Save as SaveIcon,
  FolderOpen as FolderOpenIcon,
  GetApp as ExportIcon,
  Help as HelpIcon,
  Visibility as ViewIcon,
  PlayArrow as RunIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiService } from '../../services/api';
import { SearchRequest, SearchResponse, SavedSearch, ExportRequest } from '../../types';

function EventSearch() {
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchResults, setSearchResults] = useState<SearchResponse | null>(null);
  const [isSearching, setIsSearching] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<Record<string, any> | null>(null);
  const [eventDetailsOpen, setEventDetailsOpen] = useState(false);
  const [saveSearchOpen, setSaveSearchOpen] = useState(false);
  const [loadSearchOpen, setLoadSearchOpen] = useState(false);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [helpDialogOpen, setHelpDialogOpen] = useState(false);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Save search form state
  const [savedSearchName, setSavedSearchName] = useState('');
  const [savedSearchDescription, setSavedSearchDescription] = useState('');
  const [savedSearchTags, setSavedSearchTags] = useState<string[]>([]);

  // Export form state
  const [exportFormat, setExportFormat] = useState<'json' | 'csv'>('json');
  const [exportLimit, setExportLimit] = useState(10000);

  const queryClient = useQueryClient();

  // Fetch saved searches
  const { data: savedSearchesData } = useQuery({
    queryKey: ['saved-searches'],
    queryFn: () => apiService.getSavedSearches(),
  });

  const savedSearches = savedSearchesData?.items || [];

  // Validate query mutation
  const validateMutation = useMutation({
    mutationFn: (q: string) => apiService.validateQuery(q),
    onSuccess: (data) => {
      if (!data.valid) {
        setQueryError(data.error || 'Invalid query');
      } else {
        setQueryError(null);
      }
    },
  });

  // Search mutation
  const searchMutation = useMutation({
    mutationFn: (request: SearchRequest) => apiService.searchEvents(request),
    onSuccess: (data) => {
      setSearchResults(data);
      setIsSearching(false);
      setQueryError(null);
      setSnackbar({ open: true, message: `Found ${data.total} events in ${data.execution_time_ms.toFixed(2)}ms`, severity: 'success' });
    },
    onError: (error: any) => {
      setIsSearching(false);
      setQueryError(error.message || 'Search failed');
      setSnackbar({ open: true, message: `Search failed: ${error.message}`, severity: 'error' });
    },
  });

  // Save search mutation
  const saveSearchMutation = useMutation({
    mutationFn: (search: Omit<SavedSearch, 'id' | 'user_id' | 'created_at' | 'updated_at' | 'last_used' | 'use_count'>) =>
      apiService.createSavedSearch(search),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saved-searches'] });
      setSaveSearchOpen(false);
      setSavedSearchName('');
      setSavedSearchDescription('');
      setSavedSearchTags([]);
      setSnackbar({ open: true, message: 'Search saved successfully', severity: 'success' });
    },
    onError: (error: any) => {
      setSnackbar({ open: true, message: `Failed to save search: ${error.message}`, severity: 'error' });
    },
  });

  // Execute search
  const handleSearch = () => {
    if (!query.trim()) {
      setQueryError('Query cannot be empty');
      return;
    }

    setIsSearching(true);
    const request: SearchRequest = {
      query: query.trim(),
      page: page + 1,
      limit: rowsPerPage,
    };
    searchMutation.mutate(request);
  };

  // Validate query on change
  const handleQueryChange = (value: string) => {
    setQuery(value);
    if (value.trim()) {
      validateMutation.mutate(value.trim());
    } else {
      setQueryError(null);
    }
  };

  // Load saved search
  const handleLoadSearch = (search: SavedSearch) => {
    setQuery(search.query);
    setLoadSearchOpen(false);
    setSnackbar({ open: true, message: `Loaded search: ${search.name}`, severity: 'success' });
  };

  // Save current search
  const handleSaveSearch = () => {
    if (!savedSearchName.trim()) {
      setSnackbar({ open: true, message: 'Search name is required', severity: 'error' });
      return;
    }

    const search: Omit<SavedSearch, 'id' | 'created_at' | 'updated_at' | 'usage_count'> = {
      name: savedSearchName,
      description: savedSearchDescription,
      query: query,
      tags: savedSearchTags,
      created_by: 'admin', // TODO: Get from auth context
      is_public: false,
    };

    saveSearchMutation.mutate(search);
  };

  // Export events
  const handleExport = async () => {
    if (!query.trim()) {
      setSnackbar({ open: true, message: 'Query cannot be empty', severity: 'error' });
      return;
    }

    try {
      const request: ExportRequest = {
        query: query.trim(),
        format: exportFormat,
        limit: exportLimit,
      };

      const blob = await apiService.exportEvents(request);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `cerberus_events_${new Date().toISOString().split('T')[0]}.${exportFormat}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      setExportDialogOpen(false);
      setSnackbar({ open: true, message: 'Events exported successfully', severity: 'success' });
    } catch (error: any) {
      setSnackbar({ open: true, message: `Export failed: ${error.message}`, severity: 'error' });
    }
  };

  // View event details
  const handleViewEvent = (event: Record<string, any>) => {
    setSelectedEvent(event);
    setEventDetailsOpen(true);
  };

  // Pagination handlers
  const handleChangePage = (_: unknown, newPage: number) => {
    setPage(newPage);
    if (searchResults && query.trim()) {
      const request: SearchRequest = {
        query: query.trim(),
        page: newPage + 1,
        limit: rowsPerPage,
      };
      searchMutation.mutate(request);
    }
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    const newRowsPerPage = parseInt(event.target.value, 10);
    setRowsPerPage(newRowsPerPage);
    setPage(0);
    if (searchResults && query.trim()) {
      const request: SearchRequest = {
        query: query.trim(),
        page: 1,
        limit: newRowsPerPage,
      };
      searchMutation.mutate(request);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Event Search
      </Typography>

      {/* Search Bar */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Search Query (CQL)"
                placeholder='Example: event_type = "login" AND severity = "high"'
                value={query}
                onChange={(e) => handleQueryChange(e.target.value)}
                error={!!queryError}
                helperText={queryError || 'Use Cerberus Query Language (CQL) to search events'}
                onKeyPress={(e) => {
                  if (e.key === 'Enter' && !queryError) {
                    handleSearch();
                  }
                }}
                multiline
                maxRows={3}
              />
            </Grid>
            <Grid item xs={12}>
              <Stack direction="row" spacing={1}>
                <Button
                  variant="contained"
                  startIcon={isSearching ? <CircularProgress size={20} /> : <RunIcon />}
                  onClick={handleSearch}
                  disabled={isSearching || !!queryError || !query.trim()}
                >
                  Run Query
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<SaveIcon />}
                  onClick={() => setSaveSearchOpen(true)}
                  disabled={!query.trim()}
                >
                  Save
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<FolderOpenIcon />}
                  onClick={() => setLoadSearchOpen(true)}
                >
                  Load
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<ExportIcon />}
                  onClick={() => setExportDialogOpen(true)}
                  disabled={!searchResults || searchResults.total === 0}
                >
                  Export
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<HelpIcon />}
                  onClick={() => setHelpDialogOpen(true)}
                >
                  Help
                </Button>
              </Stack>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Search Results */}
      {searchResults && (
        <Card>
          <CardContent>
            <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="h6">
                Results: {searchResults.total} events
              </Typography>
              <Chip
                label={`${searchResults.execution_time_ms.toFixed(2)}ms`}
                size="small"
                color="primary"
                variant="outlined"
              />
            </Box>

            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>Event Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Source</TableCell>
                    <TableCell>Message</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {searchResults.events.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} align="center">
                        <Typography color="textSecondary">No events found</Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    searchResults.events.map((event, index) => (
                      <TableRow key={index} hover>
                        <TableCell>{event.timestamp || 'N/A'}</TableCell>
                        <TableCell>{event.event_type || 'N/A'}</TableCell>
                        <TableCell>
                          <Chip
                            label={event.severity || 'info'}
                            size="small"
                            color={
                              event.severity === 'critical' || event.severity === 'high'
                                ? 'error'
                                : event.severity === 'medium'
                                ? 'warning'
                                : 'default'
                            }
                          />
                        </TableCell>
                        <TableCell>{event.source_ip || event.source_format || 'N/A'}</TableCell>
                        <TableCell sx={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {event.message || event.raw_data || 'N/A'}
                        </TableCell>
                        <TableCell align="right">
                          <Tooltip title="View Details">
                            <IconButton size="small" onClick={() => handleViewEvent(event)}>
                              <ViewIcon />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              component="div"
              count={searchResults.total}
              page={page}
              onPageChange={handleChangePage}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
            />
          </CardContent>
        </Card>
      )}

      {/* Event Details Dialog */}
      <Dialog open={eventDetailsOpen} onClose={() => setEventDetailsOpen(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Event Details</DialogTitle>
        <DialogContent>
          {selectedEvent && (
            <Box sx={{ overflowX: 'auto' }}>
              <Table size="small" sx={{ tableLayout: 'fixed', width: '100%' }}>
                <TableBody>
                  {Object.entries(selectedEvent).map(([key, value]) => (
                    <TableRow key={key}>
                      <TableCell
                        component="th"
                        scope="row"
                        sx={{
                          fontWeight: 'bold',
                          width: '180px',
                          minWidth: '180px',
                          verticalAlign: 'top',
                          bgcolor: 'grey.50',
                          borderRight: '1px solid',
                          borderRightColor: 'divider',
                        }}
                      >
                        {key}
                      </TableCell>
                      <TableCell
                        sx={{
                          wordBreak: 'break-word',
                          whiteSpace: 'pre-wrap',
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                          maxWidth: 0, // This forces the cell to respect table width
                        }}
                      >
                        {typeof value === 'object' && value !== null ? (
                          <Box
                            component="pre"
                            sx={{
                              margin: 0,
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-word',
                              fontSize: '0.85rem',
                              bgcolor: 'grey.100',
                              p: 1,
                              borderRadius: 1,
                              overflow: 'auto',
                            }}
                          >
                            {JSON.stringify(value, null, 2)}
                          </Box>
                        ) : (
                          String(value ?? 'N/A')
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEventDetailsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Save Search Dialog */}
      <Dialog open={saveSearchOpen} onClose={() => setSaveSearchOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Save Search</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              fullWidth
              label="Search Name"
              value={savedSearchName}
              onChange={(e) => setSavedSearchName(e.target.value)}
              required
            />
            <TextField
              fullWidth
              label="Description"
              value={savedSearchDescription}
              onChange={(e) => setSavedSearchDescription(e.target.value)}
              multiline
              rows={2}
            />
            <TextField
              fullWidth
              label="Current Query"
              value={query}
              disabled
              multiline
              rows={2}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSaveSearchOpen(false)}>Cancel</Button>
          <Button onClick={handleSaveSearch} variant="contained" disabled={!savedSearchName.trim()}>
            Save
          </Button>
        </DialogActions>
      </Dialog>

      {/* Load Search Dialog */}
      <Dialog open={loadSearchOpen} onClose={() => setLoadSearchOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Load Saved Search</DialogTitle>
        <DialogContent>
          {savedSearches.length === 0 ? (
            <Typography color="textSecondary" sx={{ py: 2 }}>
              No saved searches found
            </Typography>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Description</TableCell>
                    <TableCell>Query</TableCell>
                    <TableCell>Used</TableCell>
                    <TableCell align="right">Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {savedSearches.map((search) => (
                    <TableRow key={search.id} hover>
                      <TableCell>{search.name}</TableCell>
                      <TableCell>{search.description}</TableCell>
                      <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {search.query}
                      </TableCell>
                      <TableCell>{search.use_count || 0} times</TableCell>
                      <TableCell align="right">
                        <Button size="small" onClick={() => handleLoadSearch(search)}>
                          Load
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setLoadSearchOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Export Dialog */}
      <Dialog open={exportDialogOpen} onClose={() => setExportDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Export Events</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <FormControl fullWidth>
              <InputLabel>Format</InputLabel>
              <Select value={exportFormat} onChange={(e) => setExportFormat(e.target.value as 'json' | 'csv')}>
                <MenuItem value="json">JSON</MenuItem>
                <MenuItem value="csv">CSV</MenuItem>
              </Select>
            </FormControl>
            <TextField
              fullWidth
              type="number"
              label="Limit"
              value={exportLimit}
              onChange={(e) => setExportLimit(parseInt(e.target.value))}
              helperText="Maximum number of events to export (max 10,000)"
              inputProps={{ min: 1, max: 10000 }}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExportDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleExport} variant="contained" startIcon={<ExportIcon />}>
            Export
          </Button>
        </DialogActions>
      </Dialog>

      {/* Help Dialog */}
      <Dialog open={helpDialogOpen} onClose={() => setHelpDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>CQL Query Syntax Help</DialogTitle>
        <DialogContent>
          <Typography variant="h6" gutterBottom sx={{ mt: 1 }}>
            Basic Syntax
          </Typography>
          <Typography variant="body2" component="pre" sx={{ bgcolor: 'grey.100', p: 2, borderRadius: 1, fontFamily: 'monospace' }}>
{`field operator value

Examples:
  event_type = "login"
  severity = "high"
  source_ip = "192.168.1.1"`}
          </Typography>

          <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
            Operators
          </Typography>
          <Typography variant="body2" component="pre" sx={{ bgcolor: 'grey.100', p: 2, borderRadius: 1, fontFamily: 'monospace' }}>
{`=, !=              Equal, not equal
>, <, >=, <=       Greater/less than
contains           Substring search
startswith         Prefix match
endswith           Suffix match
matches            Regex match
in                 Value in list
exists             Field exists`}
          </Typography>

          <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
            Logical Operators
          </Typography>
          <Typography variant="body2" component="pre" sx={{ bgcolor: 'grey.100', p: 2, borderRadius: 1, fontFamily: 'monospace' }}>
{`AND, OR, NOT       Combine conditions
( )                Group conditions

Examples:
  event_type = "login" AND severity = "high"
  (event_type = "login" OR event_type = "logout") AND severity != "low"
  NOT event_type = "heartbeat"`}
          </Typography>

          <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
            Advanced Examples
          </Typography>
          <Typography variant="body2" component="pre" sx={{ bgcolor: 'grey.100', p: 2, borderRadius: 1, fontFamily: 'monospace' }}>
{`# Failed login attempts
event_type = "login" AND fields.status = "failed"

# High severity events from specific IP
severity = "high" AND source_ip = "192.168.1.100"

# Multiple event types
event_type in ["login", "logout", "access"]

# Field existence check
fields.user exists AND fields.user != ""`}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setHelpDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert onClose={() => setSnackbar({ ...snackbar, open: false })} severity={snackbar.severity}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default EventSearch;
