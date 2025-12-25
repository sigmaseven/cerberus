import React from 'react';
import {
  Box,
  Container,
  Typography,
  Button,
  Grid,
  TextField,
  MenuItem,
  InputAdornment,
  Paper,
  Tabs,
  Tab,
  Stack,
  Chip,
  IconButton,
  Tooltip,
  CircularProgress,
  Pagination,
  FormControl,
  InputLabel,
  Select,
  Checkbox,
  Collapse,
} from '@mui/material';
import {
  Add as AddIcon,
  Search as SearchIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
  KeyboardArrowDown as ArrowDownIcon,
  KeyboardArrowUp as ArrowUpIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  AssignmentInd as AssignIcon,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import api from '../../services/api';
import { InvestigationCard } from '../../components/InvestigationCard';
import type { InvestigationStatus, InvestigationPriority } from '../../types';

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
      id={`investigation-tabpanel-${index}`}
      aria-labelledby={`investigation-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

export const Investigations: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = React.useState(1); // Default to "Open" tab (index 1)
  const [searchQuery, setSearchQuery] = React.useState('');
  const [priorityFilter, setPriorityFilter] = React.useState<InvestigationPriority | ''>('');
  const [statusFilter, setStatusFilter] = React.useState<InvestigationStatus | ''>('');
  const [page, setPage] = React.useState(1); // Changed to 1-based pagination for MUI Pagination
  const [limit, setLimit] = React.useState(25);
  const [showFilters, setShowFilters] = React.useState(true);
  const [selectedInvestigations, setSelectedInvestigations] = React.useState<Set<string>>(new Set());

  // Map tab index to status filter
  const getStatusForTab = (tabIndex: number): InvestigationStatus | undefined => {
    switch (tabIndex) {
      case 0: return undefined; // All
      case 1: return 'open';
      case 2: return 'in_progress';
      case 3: return 'awaiting_review';
      case 4: return 'closed';
      default: return undefined;
    }
  };

  // Build filters based on current selections
  const filters = React.useMemo(() => {
    const tabStatus = getStatusForTab(tabValue);
    return {
      status: statusFilter || tabStatus,
      priority: priorityFilter || undefined,
      limit,
      offset: (page - 1) * limit, // Convert to 0-based offset for API
    };
  }, [tabValue, statusFilter, priorityFilter, page, limit]);

  // Fetch investigations
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['investigations', filters],
    queryFn: () => api.investigations.getInvestigations(filters),
  });

  // Fetch statistics
  const { data: stats } = useQuery({
    queryKey: ['investigation-stats'],
    queryFn: () => api.investigations.getStatistics(),
  });

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
    setPage(1); // Reset to first page when changing tabs
    setSelectedInvestigations(new Set()); // Clear selections when changing tabs
  };

  const handleOpenInvestigation = (id: string) => {
    navigate(`/investigations/${id}`);
  };

  const handleCreateInvestigation = () => {
    navigate('/investigations/new');
  };

  // Selection handlers
  const handleSelectInvestigation = (id: string) => {
    const newSelected = new Set(selectedInvestigations);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedInvestigations(newSelected);
  };

  const handleSelectAll = () => {
    if (selectedInvestigations.size === filteredInvestigations.length) {
      setSelectedInvestigations(new Set());
    } else {
      setSelectedInvestigations(new Set(filteredInvestigations.map(inv => inv.investigation_id)));
    }
  };

  // Bulk action handlers
  const handleBulkClose = async () => {
    // TODO: Implement bulk close API call
    setSelectedInvestigations(new Set());
  };

  const handleBulkAssign = async () => {
    // TODO: Implement bulk assign API call
    setSelectedInvestigations(new Set());
  };

  const handleBulkUpdateStatus = async (status: InvestigationStatus) => {
    // TODO: Implement bulk status update API call
    setSelectedInvestigations(new Set());
  };

  // Filter investigations by search query (client-side)
  const filteredInvestigations = React.useMemo(() => {
    if (!data?.investigations) return [];

    if (!searchQuery.trim()) return data.investigations;

    const query = searchQuery.toLowerCase();
    return data.investigations.filter(
      (inv) =>
        inv.investigation_id.toLowerCase().includes(query) ||
        inv.title.toLowerCase().includes(query) ||
        inv.description.toLowerCase().includes(query)
    );
  }, [data?.investigations, searchQuery]);

  const getTabLabel = (status: string, count?: number) => {
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <span>{status}</span>
        {count !== undefined && (
          <Chip
            label={count}
            size="small"
            sx={{
              height: 20,
              fontSize: '0.7rem',
              minWidth: 24,
            }}
          />
        )}
      </Box>
    );
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom fontWeight={600}>
            Investigations
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Manage and track security incident investigations
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Tooltip title="Refresh">
            <IconButton onClick={() => refetch()} color="primary">
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleCreateInvestigation}
          >
            New Investigation
          </Button>
        </Box>
      </Box>

      {/* Statistics Cards */}
      {stats && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                Total Investigations
              </Typography>
              <Typography variant="h4" fontWeight={600}>
                {stats.total}
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                Open
              </Typography>
              <Typography variant="h4" fontWeight={600} color="primary.main">
                {stats.open_count}
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                Closed
              </Typography>
              <Typography variant="h4" fontWeight={600} color="success.main">
                {stats.closed_count}
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                Avg Resolution Time
              </Typography>
              <Typography variant="h4" fontWeight={600}>
                {stats.avg_resolution_time_hours.toFixed(1)}h
              </Typography>
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* Filters */}
      <Box sx={{ mb: 3 }}>
        <Button
          onClick={() => setShowFilters(!showFilters)}
          endIcon={showFilters ? <ArrowUpIcon /> : <ArrowDownIcon />}
          sx={{ mb: 2 }}
        >
          {showFilters ? 'Hide Filters' : 'Show Filters'}
        </Button>

        <Collapse in={showFilters}>
          <Paper sx={{ p: 3, mb: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Search investigations..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  select
                  fullWidth
                  size="small"
                  label="Priority"
                  value={priorityFilter}
                  onChange={(e) => setPriorityFilter(e.target.value as InvestigationPriority | '')}
                >
                  <MenuItem value="">All Priorities</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  select
                  fullWidth
                  size="small"
                  label="Status"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value as InvestigationStatus | '')}
                >
                  <MenuItem value="">All Statuses</MenuItem>
                  <MenuItem value="open">Open</MenuItem>
                  <MenuItem value="in_progress">In Progress</MenuItem>
                  <MenuItem value="awaiting_review">Awaiting Review</MenuItem>
                  <MenuItem value="closed">Closed</MenuItem>
                  <MenuItem value="resolved">Resolved</MenuItem>
                  <MenuItem value="false_positive">False Positive</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12}>
                <Button
                  variant="outlined"
                  startIcon={<FilterIcon />}
                  onClick={() => {
                    setSearchQuery('');
                    setPriorityFilter('');
                    setStatusFilter('');
                  }}
                >
                  Clear Filters
                </Button>
              </Grid>
            </Grid>
          </Paper>
        </Collapse>
      </Box>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label={getTabLabel('All', stats?.total)} />
          <Tab label={getTabLabel('Open', stats?.by_status.open)} />
          <Tab label={getTabLabel('In Progress', stats?.by_status.in_progress)} />
          <Tab label={getTabLabel('Awaiting Review', stats?.by_status.awaiting_review)} />
          <Tab label={getTabLabel('Closed', stats?.by_status.closed)} />
        </Tabs>
      </Box>

      {/* Content */}
      <TabPanel value={tabValue} index={tabValue}>
        {isLoading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
            <CircularProgress />
          </Box>
        )}

        {isError && (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <Typography color="error" gutterBottom>
              Error loading investigations
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {error instanceof Error ? error.message : 'Unknown error occurred'}
            </Typography>
            <Button onClick={() => refetch()} sx={{ mt: 2 }}>
              Retry
            </Button>
          </Paper>
        )}

        {!isLoading && !isError && filteredInvestigations.length === 0 && (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <Typography variant="h6" gutterBottom>
              No investigations found
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              {searchQuery
                ? 'Try adjusting your search or filters'
                : 'Create your first investigation to get started'}
            </Typography>
            {!searchQuery && (
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={handleCreateInvestigation}
                sx={{ mt: 2 }}
              >
                Create Investigation
              </Button>
            )}
          </Paper>
        )}

        {!isLoading && !isError && filteredInvestigations.length > 0 && (
          <>
            {/* Bulk Actions Bar */}
            {selectedInvestigations.size > 0 && (
              <Paper sx={{ p: 2, mb: 3, bgcolor: 'primary.50' }}>
                <Stack direction="row" spacing={2} alignItems="center">
                  <Typography variant="body2" fontWeight={500}>
                    {selectedInvestigations.size} investigation(s) selected
                  </Typography>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<CheckCircleIcon />}
                    onClick={handleBulkClose}
                  >
                    Close Selected
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<AssignIcon />}
                    onClick={handleBulkAssign}
                  >
                    Assign Selected
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<CancelIcon />}
                    onClick={() => setSelectedInvestigations(new Set())}
                  >
                    Clear Selection
                  </Button>
                </Stack>
              </Paper>
            )}

            {/* Select All */}
            <Box sx={{ mb: 2 }}>
              <Button
                size="small"
                onClick={handleSelectAll}
                startIcon={<Checkbox checked={selectedInvestigations.size === filteredInvestigations.length && filteredInvestigations.length > 0} />}
              >
                {selectedInvestigations.size === filteredInvestigations.length && filteredInvestigations.length > 0
                  ? 'Deselect All'
                  : 'Select All'}
              </Button>
            </Box>

            {/* Investigation Cards */}
            <Grid container spacing={3}>
              {filteredInvestigations.map((investigation) => (
                <Grid item xs={12} md={6} lg={4} key={investigation.investigation_id}>
                  <Box sx={{ position: 'relative' }}>
                    <Checkbox
                      checked={selectedInvestigations.has(investigation.investigation_id)}
                      onChange={() => handleSelectInvestigation(investigation.investigation_id)}
                      sx={{
                        position: 'absolute',
                        top: 8,
                        right: 8,
                        zIndex: 1,
                        bgcolor: 'background.paper',
                        borderRadius: 1,
                        '&:hover': { bgcolor: 'background.paper' },
                      }}
                    />
                    <InvestigationCard
                      investigation={investigation}
                      onOpen={handleOpenInvestigation}
                    />
                  </Box>
                </Grid>
              ))}
            </Grid>

            {/* Pagination */}
            {data && (
              <Box sx={{ mt: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    Showing {(page - 1) * limit + 1}-{Math.min(page * limit, data.total)} of {data.total} investigations
                  </Typography>
                  <FormControl size="small" sx={{ minWidth: 120 }}>
                    <InputLabel>Per page</InputLabel>
                    <Select
                      value={limit}
                      label="Per page"
                      onChange={(e) => {
                        setLimit(Number(e.target.value));
                        setPage(1);
                      }}
                    >
                      <MenuItem value={10}>10</MenuItem>
                      <MenuItem value={25}>25</MenuItem>
                      <MenuItem value={50}>50</MenuItem>
                      <MenuItem value={100}>100</MenuItem>
                    </Select>
                  </FormControl>
                </Box>
                <Pagination
                  count={Math.ceil(data.total / limit)}
                  page={page}
                  onChange={(_event, value) => setPage(value)}
                  color="primary"
                  showFirstButton
                  showLastButton
                />
              </Box>
            )}
          </>
        )}
      </TabPanel>
    </Container>
  );
};

export default Investigations;
