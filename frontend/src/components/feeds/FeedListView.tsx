/**
 * FeedListView Component (Task 156.1)
 * Displays SIGMA rule feeds with table/card layout and filtering
 */

import { useState, useCallback, useMemo, useRef, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardActions,
  Chip,
  Alert,
  CircularProgress,
  Button,
  IconButton,
  Tooltip,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  TextField,
  InputAdornment,
  Pagination,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  ToggleButton,
  ToggleButtonGroup,
  LinearProgress,
  Badge,
} from '@mui/material';
import {
  RssFeed as FeedIcon,
  Sync as SyncIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  MoreVert as MoreIcon,
  Error as ErrorIcon,
  Search as SearchIcon,
  ViewModule as GridViewIcon,
  ViewList as ListViewIcon,
  PlayArrow as PlayIcon,
  Pause as PauseIcon,
  Info as InfoIcon,
  Schedule as ScheduleIcon,
  CheckCircle as CheckCircleIcon,
  Folder as FolderIcon,
  GitHub as GitIcon,
} from '@mui/icons-material';
import type {
  Feed,
  FeedStatus,
  FeedType,
  FeedSyncResult,
} from '../../types';

const ITEMS_PER_PAGE = 12;
const MAX_VISIBLE_TAGS = 3;

interface FeedListViewProps {
  feeds: Feed[];
  total: number;
  page: number;
  isLoading: boolean;
  error: Error | null;
  onPageChange: (page: number) => void;
  onRefresh: () => void;
  onCreateFeed: () => void;
  onEditFeed: (feed: Feed) => void;
  onDeleteFeed: (feed: Feed) => void;
  onViewDetails: (feed: Feed) => void;
  onSyncFeed: (feedId: string) => Promise<FeedSyncResult>;
  onEnableFeed: (feedId: string) => Promise<void>;
  onDisableFeed: (feedId: string) => Promise<void>;
  pendingOperations?: Record<string, string>;
}

/**
 * Get status color based on feed state
 */
const getStatusColor = (status: FeedStatus): 'success' | 'error' | 'warning' | 'info' | 'default' => {
  switch (status) {
    case 'active':
      return 'success';
    case 'error':
      return 'error';
    case 'syncing':
      return 'info';
    case 'disabled':
    default:
      return 'default';
  }
};

/**
 * Get status icon based on feed state
 */
const getStatusIcon = (status: FeedStatus) => {
  switch (status) {
    case 'active':
      return <CheckCircleIcon color="success" aria-hidden="true" />;
    case 'error':
      return <ErrorIcon color="error" aria-hidden="true" />;
    case 'syncing':
      return <CircularProgress size={20} aria-hidden="true" />;
    case 'disabled':
    default:
      return <PauseIcon color="disabled" aria-hidden="true" />;
  }
};

/**
 * Get type icon based on feed type
 */
const getTypeIcon = (type: FeedType) => {
  switch (type) {
    case 'git':
      return <GitIcon fontSize="small" />;
    case 'filesystem':
      return <FolderIcon fontSize="small" />;
    default:
      return <FeedIcon fontSize="small" />;
  }
};

/**
 * Format last sync time
 */
const formatLastSync = (lastSync?: string) => {
  if (!lastSync) return 'Never';
  const date = new Date(lastSync);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
};

/**
 * Format update strategy for display
 */
const formatUpdateStrategy = (strategy: string) => {
  switch (strategy) {
    case 'manual':
      return 'Manual';
    case 'startup':
      return 'On Startup';
    case 'scheduled':
      return 'Scheduled';
    default:
      return strategy;
  }
};

/**
 * Check if feed matches search query
 */
const matchesSearch = (feed: Feed, query: string): boolean => {
  if (!query) return true;
  const searchableFields = [
    feed.name,
    feed.description ?? '',
    feed.type,
    ...(feed.tags ?? []),
    feed.url ?? '',
  ];
  const lowerQuery = query.toLowerCase();
  return searchableFields.some(field =>
    field.toLowerCase().includes(lowerQuery)
  );
};

export default function FeedListView({
  feeds,
  total,
  page,
  isLoading,
  error,
  onPageChange,
  onRefresh,
  onCreateFeed,
  onEditFeed,
  onDeleteFeed,
  onViewDetails,
  onSyncFeed,
  onEnableFeed,
  onDisableFeed,
  pendingOperations = {},
}: FeedListViewProps) {
  const isMountedRef = useRef(true);

  // State
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'table'>(() => {
    try {
      const saved = localStorage.getItem('feeds-view-mode');
      return saved === 'table' || saved === 'grid' ? saved : 'grid';
    } catch {
      return 'grid';
    }
  });
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedFeed, setSelectedFeed] = useState<Feed | null>(null);

  // Cleanup on unmount
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  // Debounce search
  useEffect(() => {
    const timer = setTimeout(() => {
      if (isMountedRef.current) {
        setDebouncedSearch(searchQuery);
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Event handlers
  const handleMenuOpen = useCallback((event: React.MouseEvent<HTMLElement>, feed: Feed) => {
    setMenuAnchor(event.currentTarget);
    setSelectedFeed(feed);
  }, []);

  const handleMenuClose = useCallback(() => {
    setMenuAnchor(null);
  }, []);

  const handleViewModeChange = useCallback((_: React.MouseEvent<HTMLElement>, newMode: 'grid' | 'table' | null) => {
    if (newMode !== null) {
      setViewMode(newMode);
      try {
        localStorage.setItem('feeds-view-mode', newMode);
      } catch (err) {
        console.warn('Failed to save view mode preference:', err);
      }
    }
  }, []);

  const handlePageChange = useCallback((_: React.ChangeEvent<unknown>, value: number) => {
    if (debouncedSearch) {
      setSearchQuery('');
      setDebouncedSearch('');
    }
    onPageChange(value);
  }, [debouncedSearch, onPageChange]);

  const handleEdit = useCallback(() => {
    handleMenuClose();
    if (selectedFeed) {
      onEditFeed(selectedFeed);
    }
  }, [selectedFeed, onEditFeed, handleMenuClose]);

  const handleDelete = useCallback(() => {
    handleMenuClose();
    if (selectedFeed) {
      onDeleteFeed(selectedFeed);
    }
  }, [selectedFeed, onDeleteFeed, handleMenuClose]);

  const handleViewDetailsFromMenu = useCallback(() => {
    handleMenuClose();
    if (selectedFeed) {
      onViewDetails(selectedFeed);
    }
  }, [selectedFeed, onViewDetails, handleMenuClose]);

  const handleSync = useCallback(async (feed: Feed) => {
    try {
      await onSyncFeed(feed.id);
    } catch (err) {
      console.error('Failed to sync feed:', err);
    }
  }, [onSyncFeed]);

  const handleSyncFromMenu = useCallback(async () => {
    handleMenuClose();
    if (selectedFeed) {
      await handleSync(selectedFeed);
    }
  }, [selectedFeed, handleSync, handleMenuClose]);

  const handleToggleEnabled = useCallback(async (feed: Feed) => {
    try {
      if (feed.enabled) {
        await onDisableFeed(feed.id);
      } else {
        await onEnableFeed(feed.id);
      }
    } catch (err) {
      console.error('Failed to toggle feed:', err);
    }
  }, [onEnableFeed, onDisableFeed]);

  const handleToggleFromMenu = useCallback(async () => {
    handleMenuClose();
    if (selectedFeed) {
      await handleToggleEnabled(selectedFeed);
    }
  }, [selectedFeed, handleToggleEnabled, handleMenuClose]);

  // Check if operation is pending
  const isPending = useCallback((feedId: string) => {
    return !!pendingOperations[feedId];
  }, [pendingOperations]);

  // Filter feeds by search query
  const filteredFeeds = useMemo(() =>
    feeds.filter(feed => matchesSearch(feed, debouncedSearch)),
    [feeds, debouncedSearch]
  );

  // Calculate stats
  const stats = useMemo(() => {
    const result = {
      active: 0,
      disabled: 0,
      error: 0,
      syncing: 0,
      totalRules: 0,
    };
    filteredFeeds.forEach(feed => {
      result[feed.status as keyof typeof result] = ((result[feed.status as keyof typeof result] as number) || 0) + 1;
      result.totalRules += feed.stats?.total_rules || 0;
    });
    return result;
  }, [filteredFeeds]);

  const totalPages = Math.ceil(total / ITEMS_PER_PAGE);

  // Loading state
  if (isLoading && feeds.length === 0) {
    return (
      <Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Skeleton variant="text" width={200} height={40} />
          <Skeleton variant="rectangular" width={120} height={36} />
        </Box>
        <Grid container spacing={3}>
          {Array.from({ length: ITEMS_PER_PAGE / 2 }).map((_, i) => (
            <Grid item xs={12} sm={6} lg={4} key={i}>
              <Skeleton variant="rectangular" height={200} sx={{ borderRadius: 1 }} />
            </Grid>
          ))}
        </Grid>
      </Box>
    );
  }

  // Error state
  if (error) {
    return (
      <Alert
        severity="error"
        action={
          <Button color="inherit" size="small" onClick={onRefresh}>
            Retry
          </Button>
        }
      >
        Failed to load feeds. Please check your connection and try again.
      </Alert>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box
        sx={{
          display: 'flex',
          flexDirection: { xs: 'column', sm: 'row' },
          justifyContent: 'space-between',
          alignItems: { xs: 'stretch', sm: 'center' },
          gap: 2,
          mb: 3,
        }}
      >
        <Typography variant="h5">SIGMA Rule Feeds</Typography>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
          <ToggleButtonGroup
            value={viewMode}
            exclusive
            onChange={handleViewModeChange}
            size="small"
            aria-label="View mode"
          >
            <ToggleButton value="grid" aria-label="Grid view">
              <Tooltip title="Grid View">
                <GridViewIcon />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="table" aria-label="Table view">
              <Tooltip title="Table View">
                <ListViewIcon />
              </Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>
          <Button
            variant="outlined"
            startIcon={<SyncIcon />}
            onClick={onRefresh}
            size="small"
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={onCreateFeed}
          >
            Add Feed
          </Button>
        </Box>
      </Box>

      {/* Search */}
      <Box sx={{ mb: 3 }}>
        <TextField
          fullWidth
          placeholder="Filter feeds by name, description, type, or tags..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          size="small"
          helperText={
            debouncedSearch
              ? `Showing ${filteredFeeds.length} of ${feeds.length} feeds`
              : undefined
          }
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon color="action" />
              </InputAdornment>
            ),
          }}
          inputProps={{
            'aria-label': 'Filter feeds',
          }}
        />
      </Box>

      {/* Stats Summary */}
      <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap' }} role="status" aria-live="polite">
        <Chip
          icon={<CheckCircleIcon />}
          label={`${stats.active} Active`}
          color="success"
          variant="outlined"
        />
        <Chip
          icon={<PauseIcon />}
          label={`${stats.disabled} Disabled`}
          variant="outlined"
        />
        <Chip
          icon={<ErrorIcon />}
          label={`${stats.error} Errors`}
          color="error"
          variant="outlined"
        />
        <Chip
          icon={<FeedIcon />}
          label={`${stats.totalRules} Total Rules`}
          variant="outlined"
          color="primary"
        />
      </Box>

      {/* Loading indicator for background refresh */}
      {isLoading && feeds.length > 0 && (
        <LinearProgress sx={{ mb: 2 }} />
      )}

      {/* Feeds Display */}
      {filteredFeeds.length === 0 ? (
        <Alert severity="info" data-testid="feeds-empty-state">
          {debouncedSearch
            ? 'No feeds match your search criteria.'
            : 'No feeds configured. Click "Add Feed" to create one.'}
        </Alert>
      ) : viewMode === 'table' ? (
        /* Table View */
        <TableContainer component={Paper} data-testid="feeds-table">
          <Table size="small" aria-label="Feeds table">
            <TableHead>
              <TableRow>
                <TableCell>Status</TableCell>
                <TableCell>Name</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Rules</TableCell>
                <TableCell>Last Sync</TableCell>
                <TableCell>Update Strategy</TableCell>
                <TableCell align="center">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredFeeds.map((feed) => {
                const feedPending = isPending(feed.id);
                return (
                  <TableRow
                    key={feed.id}
                    hover
                    sx={{
                      '&:last-child td, &:last-child th': { border: 0 },
                      opacity: feedPending ? 0.7 : 1,
                    }}
                  >
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {getStatusIcon(feed.status)}
                        <Chip
                          label={feed.status}
                          color={getStatusColor(feed.status)}
                          size="small"
                        />
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {feed.name}
                      </Typography>
                      {feed.description && (
                        <Typography variant="caption" color="text.secondary" noWrap sx={{ maxWidth: 200, display: 'block' }}>
                          {feed.description}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        {getTypeIcon(feed.type)}
                        <Typography variant="body2">
                          {feed.type.toUpperCase()}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Badge
                        badgeContent={feed.stats?.total_rules ?? 0}
                        color="primary"
                        max={9999}
                      >
                        <FeedIcon color="action" />
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {formatLastSync(feed.last_sync)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        icon={<ScheduleIcon />}
                        label={formatUpdateStrategy(feed.update_strategy)}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell align="center">
                      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 0.5 }}>
                        {feedPending ? (
                          <CircularProgress size={20} />
                        ) : (
                          <>
                            <Tooltip title="Sync Now">
                              <IconButton
                                size="small"
                                color="primary"
                                onClick={() => handleSync(feed)}
                                disabled={feed.status === 'syncing'}
                                aria-label={`Sync ${feed.name}`}
                              >
                                <SyncIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            <IconButton
                              size="small"
                              onClick={(e) => handleMenuOpen(e, feed)}
                              aria-label={`More actions for ${feed.name}`}
                            >
                              <MoreIcon fontSize="small" />
                            </IconButton>
                          </>
                        )}
                      </Box>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      ) : (
        /* Grid View */
        <Grid container spacing={3} role="list" aria-label="Feeds" data-testid="feeds-grid">
          {filteredFeeds.map((feed) => {
            const feedPending = isPending(feed.id);
            return (
              <Grid item xs={12} sm={6} lg={4} key={feed.id} role="listitem" data-testid="feed-card">
                <Card
                  sx={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    borderLeft: '4px solid',
                    borderLeftColor:
                      feed.status === 'active'
                        ? 'success.main'
                        : feed.status === 'error'
                        ? 'error.main'
                        : feed.status === 'syncing'
                        ? 'info.main'
                        : 'grey.400',
                    position: 'relative',
                  }}
                  aria-labelledby={`feed-${feed.id}-name`}
                >
                  {/* Loading overlay */}
                  {feedPending && (
                    <Box
                      sx={{
                        position: 'absolute',
                        top: 8,
                        right: 48,
                        zIndex: 1,
                      }}
                      role="status"
                      aria-label="Operation in progress"
                    >
                      <CircularProgress size={20} />
                    </Box>
                  )}

                  <CardContent sx={{ flexGrow: 1 }}>
                    {/* Header */}
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {getStatusIcon(feed.status)}
                        <Box>
                          <Typography
                            variant="h6"
                            component="div"
                            noWrap
                            sx={{ maxWidth: 180 }}
                            id={`feed-${feed.id}-name`}
                          >
                            {feed.name}
                          </Typography>
                          <Chip
                            label={feed.status}
                            color={getStatusColor(feed.status)}
                            size="small"
                          />
                        </Box>
                      </Box>
                      <IconButton
                        size="small"
                        onClick={(e) => handleMenuOpen(e, feed)}
                        aria-label={`Open actions menu for ${feed.name}`}
                        aria-haspopup="menu"
                      >
                        <MoreIcon />
                      </IconButton>
                    </Box>

                    {/* Type & Source */}
                    <Box sx={{ mb: 2 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                        {getTypeIcon(feed.type)}
                        <Typography variant="body2" color="text.secondary">
                          {feed.type.toUpperCase()}
                        </Typography>
                        <Chip
                          label={formatUpdateStrategy(feed.update_strategy)}
                          size="small"
                          variant="outlined"
                        />
                      </Box>
                      {feed.url && (
                        <Typography
                          variant="body2"
                          color="text.secondary"
                          noWrap
                          sx={{ maxWidth: '100%' }}
                          title={feed.url}
                        >
                          {feed.url}
                        </Typography>
                      )}
                      {feed.description && (
                        <Typography
                          variant="body2"
                          color="text.secondary"
                          sx={{
                            mt: 1,
                            display: '-webkit-box',
                            WebkitLineClamp: 2,
                            WebkitBoxOrient: 'vertical',
                            overflow: 'hidden',
                          }}
                        >
                          {feed.description}
                        </Typography>
                      )}
                    </Box>

                    {/* Statistics */}
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="body2">
                        <strong>Rules:</strong> {feed.stats?.total_rules ?? 0}
                        {feed.stats?.imported_rules !== undefined && (
                          <> ({feed.stats.imported_rules} imported)</>
                        )}
                      </Typography>
                      <Typography variant="body2">
                        <strong>Last Sync:</strong> {formatLastSync(feed.last_sync)}
                      </Typography>
                      {feed.stats?.last_error && (
                        <Typography variant="body2" color="error">
                          <strong>Error:</strong> {feed.stats.last_error}
                        </Typography>
                      )}
                    </Box>

                    {/* Tags */}
                    {feed.tags && feed.tags.length > 0 && (
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {feed.tags.slice(0, MAX_VISIBLE_TAGS).map((tag) => (
                          <Chip key={tag} label={tag} size="small" variant="outlined" />
                        ))}
                        {feed.tags.length > MAX_VISIBLE_TAGS && (
                          <Chip label={`+${feed.tags.length - MAX_VISIBLE_TAGS}`} size="small" variant="outlined" />
                        )}
                      </Box>
                    )}
                  </CardContent>

                  {/* Quick Actions */}
                  <CardActions sx={{ justifyContent: 'flex-end', pt: 0 }} role="group" aria-label="Quick actions">
                    <Tooltip title="Sync Now">
                      <span>
                        <IconButton
                          color="primary"
                          onClick={() => handleSync(feed)}
                          disabled={feedPending || feed.status === 'syncing'}
                          size="small"
                          aria-label={`Sync ${feed.name}`}
                        >
                          {feed.status === 'syncing' ? <CircularProgress size={16} /> : <SyncIcon />}
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title={feed.enabled ? 'Disable Feed' : 'Enable Feed'}>
                      <span>
                        <IconButton
                          color={feed.enabled ? 'warning' : 'success'}
                          onClick={() => handleToggleEnabled(feed)}
                          disabled={feedPending}
                          size="small"
                          aria-label={feed.enabled ? `Disable ${feed.name}` : `Enable ${feed.name}`}
                        >
                          {feed.enabled ? <PauseIcon /> : <PlayIcon />}
                        </IconButton>
                      </span>
                    </Tooltip>
                  </CardActions>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
          <Pagination
            count={totalPages}
            page={page}
            onChange={handlePageChange}
            color="primary"
            disabled={isLoading}
            aria-label="Feeds pagination"
          />
        </Box>
      )}

      {/* Action Menu */}
      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={handleMenuClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <MenuItem onClick={handleSyncFromMenu} disabled={selectedFeed?.status === 'syncing'}>
          <ListItemIcon>
            <SyncIcon color="primary" />
          </ListItemIcon>
          <ListItemText>Sync Now</ListItemText>
        </MenuItem>
        <MenuItem onClick={handleToggleFromMenu}>
          <ListItemIcon>
            {selectedFeed?.enabled ? <PauseIcon color="warning" /> : <PlayIcon color="success" />}
          </ListItemIcon>
          <ListItemText>{selectedFeed?.enabled ? 'Disable' : 'Enable'}</ListItemText>
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleViewDetailsFromMenu}>
          <ListItemIcon>
            <InfoIcon />
          </ListItemIcon>
          <ListItemText>View Details</ListItemText>
        </MenuItem>
        <MenuItem onClick={handleEdit}>
          <ListItemIcon>
            <EditIcon />
          </ListItemIcon>
          <ListItemText>Edit</ListItemText>
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleDelete}>
          <ListItemIcon>
            <DeleteIcon color="error" />
          </ListItemIcon>
          <ListItemText>Delete</ListItemText>
        </MenuItem>
      </Menu>
    </Box>
  );
}
