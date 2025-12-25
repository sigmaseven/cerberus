/**
 * FeedDetailModal Component (Task 156.3)
 * Modal for viewing detailed feed information with tabbed interface
 */

import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Tabs,
  Tab,
  Chip,
  Grid,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  CircularProgress,
  Alert,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Schedule as ScheduleIcon,
  Sync as SyncIcon,
  Edit as EditIcon,
  ContentCopy as CopyIcon,
  GitHub as GitIcon,
  Folder as FolderIcon,
  Pause as PauseIcon,
  PlayArrow as PlayIcon,
  RssFeed as FeedIcon,
} from '@mui/icons-material';
import type { Feed, FeedSyncResult, FeedStatus } from '../../types';

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
      id={`feed-detail-tabpanel-${index}`}
      aria-labelledby={`feed-detail-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 2 }}>{children}</Box>}
    </div>
  );
}

interface FeedDetailModalProps {
  open: boolean;
  feed: Feed | null;
  syncHistory?: FeedSyncResult[];
  isLoadingHistory?: boolean;
  onClose: () => void;
  onEdit: (feed: Feed) => void;
  onSync: (feedId: string) => Promise<FeedSyncResult>;
  onToggleEnabled: (feedId: string, enabled: boolean) => Promise<void>;
  isSyncing?: boolean;
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
      return <CheckCircleIcon color="success" />;
    case 'error':
      return <ErrorIcon color="error" />;
    case 'syncing':
      return <CircularProgress size={24} />;
    case 'disabled':
    default:
      return <PauseIcon color="disabled" />;
  }
};

/**
 * Get type icon based on feed type
 */
const getTypeIcon = (type: string) => {
  switch (type) {
    case 'git':
      return <GitIcon />;
    case 'filesystem':
      return <FolderIcon />;
    default:
      return <FeedIcon />;
  }
};

/**
 * Format date for display
 */
const formatDate = (dateString?: string) => {
  if (!dateString) return 'N/A';
  return new Date(dateString).toLocaleString();
};

/**
 * Format duration in milliseconds
 */
const formatDuration = (ms?: number) => {
  if (!ms) return 'N/A';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
};

/**
 * Copy text to clipboard
 */
const copyToClipboard = async (text: string): Promise<boolean> => {
  if (!navigator.clipboard || !window.isSecureContext) {
    return false;
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
};

export default function FeedDetailModal({
  open,
  feed,
  syncHistory = [],
  isLoadingHistory = false,
  onClose,
  onEdit,
  onSync,
  onToggleEnabled,
  isSyncing = false,
}: FeedDetailModalProps) {
  const [currentTab, setCurrentTab] = useState(0);
  const [copied, setCopied] = useState(false);

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setCurrentTab(newValue);
  };

  const handleCopyUrl = async () => {
    if (feed?.url) {
      const success = await copyToClipboard(feed.url);
      if (success) {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    }
  };

  const handleSync = async () => {
    if (feed) {
      await onSync(feed.id);
    }
  };

  const handleToggle = async () => {
    if (feed) {
      await onToggleEnabled(feed.id, !feed.enabled);
    }
  };

  const handleEdit = () => {
    if (feed) {
      onEdit(feed);
      onClose();
    }
  };

  if (!feed) {
    return null;
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      aria-labelledby="feed-detail-dialog-title"
    >
      <DialogTitle id="feed-detail-dialog-title">
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {getStatusIcon(feed.status)}
            <Box>
              <Typography variant="h6" component="span">
                {feed.name}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                <Chip
                  label={feed.status}
                  color={getStatusColor(feed.status)}
                  size="small"
                />
                <Chip
                  icon={getTypeIcon(feed.type)}
                  label={feed.type.toUpperCase()}
                  size="small"
                  variant="outlined"
                />
              </Box>
            </Box>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Tooltip title="Sync Now">
              <span>
                <IconButton
                  onClick={handleSync}
                  disabled={isSyncing || feed.status === 'syncing'}
                  color="primary"
                >
                  {isSyncing || feed.status === 'syncing' ? (
                    <CircularProgress size={24} />
                  ) : (
                    <SyncIcon />
                  )}
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title={feed.enabled ? 'Disable Feed' : 'Enable Feed'}>
              <IconButton
                onClick={handleToggle}
                color={feed.enabled ? 'warning' : 'success'}
              >
                {feed.enabled ? <PauseIcon /> : <PlayIcon />}
              </IconButton>
            </Tooltip>
            <Tooltip title="Edit Feed">
              <IconButton onClick={handleEdit}>
                <EditIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
      </DialogTitle>

      <DialogContent dividers sx={{ p: 0 }}>
        <Tabs
          value={currentTab}
          onChange={handleTabChange}
          aria-label="Feed detail tabs"
          variant="fullWidth"
        >
          <Tab label="Overview" id="feed-detail-tab-0" aria-controls="feed-detail-tabpanel-0" />
          <Tab label="Statistics" id="feed-detail-tab-1" aria-controls="feed-detail-tabpanel-1" />
          <Tab label="Sync History" id="feed-detail-tab-2" aria-controls="feed-detail-tabpanel-2" />
          <Tab label="Configuration" id="feed-detail-tab-3" aria-controls="feed-detail-tabpanel-3" />
        </Tabs>

        {/* Overview Tab */}
        <TabPanel value={currentTab} index={0}>
          <Box sx={{ px: 3 }}>
            {feed.description && (
              <Typography variant="body1" sx={{ mb: 3 }}>
                {feed.description}
              </Typography>
            )}

            <Grid container spacing={3}>
              {/* Source Information */}
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  Source
                </Typography>
                {feed.type === 'git' && feed.url && (
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <GitIcon color="action" />
                    <Typography variant="body2" fontFamily="monospace" sx={{ flex: 1 }}>
                      {feed.url}
                    </Typography>
                    <Tooltip title={copied ? 'Copied!' : 'Copy URL'}>
                      <IconButton size="small" onClick={handleCopyUrl}>
                        <CopyIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    {feed.branch && (
                      <Chip label={`Branch: ${feed.branch}`} size="small" variant="outlined" />
                    )}
                  </Box>
                )}
                {feed.type === 'filesystem' && feed.path && (
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <FolderIcon color="action" />
                    <Typography variant="body2" fontFamily="monospace">
                      {feed.path}
                    </Typography>
                  </Box>
                )}
              </Grid>

              {/* Quick Stats */}
              <Grid item xs={6} sm={3}>
                <Typography variant="subtitle2" color="text.secondary">
                  Total Rules
                </Typography>
                <Typography variant="h4" color="primary">
                  {feed.stats?.total_rules ?? 0}
                </Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="subtitle2" color="text.secondary">
                  Imported
                </Typography>
                <Typography variant="h4" color="success.main">
                  {feed.stats?.imported_rules ?? 0}
                </Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="subtitle2" color="text.secondary">
                  Last Sync
                </Typography>
                <Typography variant="body1">
                  {formatDate(feed.last_sync)}
                </Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="subtitle2" color="text.secondary">
                  Next Sync
                </Typography>
                <Typography variant="body1">
                  {feed.update_strategy === 'scheduled'
                    ? formatDate(feed.next_sync)
                    : feed.update_strategy === 'startup'
                    ? 'On Startup'
                    : 'Manual'}
                </Typography>
              </Grid>

              {/* Error Display */}
              {feed.stats?.last_error && (
                <Grid item xs={12}>
                  <Alert severity="error">
                    <Typography variant="subtitle2">Last Error</Typography>
                    <Typography variant="body2">{feed.stats.last_error}</Typography>
                  </Alert>
                </Grid>
              )}

              {/* Tags */}
              {feed.tags && feed.tags.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Tags
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {feed.tags.map(tag => (
                      <Chip key={tag} label={tag} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
            </Grid>
          </Box>
        </TabPanel>

        {/* Statistics Tab */}
        <TabPanel value={currentTab} index={1}>
          <Box sx={{ px: 3 }}>
            <Grid container spacing={3}>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, textAlign: 'center' }}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Total Rules
                  </Typography>
                  <Typography variant="h3" color="primary">
                    {feed.stats?.total_rules ?? 0}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, textAlign: 'center' }}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Imported
                  </Typography>
                  <Typography variant="h3" color="success.main">
                    {feed.stats?.imported_rules ?? 0}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, textAlign: 'center' }}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Updated
                  </Typography>
                  <Typography variant="h3" color="info.main">
                    {feed.stats?.updated_rules ?? 0}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, textAlign: 'center' }}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Failed
                  </Typography>
                  <Typography variant="h3" color="error.main">
                    {feed.stats?.failed_rules ?? 0}
                  </Typography>
                </Paper>
              </Grid>

              <Grid item xs={12}>
                <Divider sx={{ my: 2 }} />
              </Grid>

              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle2" color="text.secondary">
                  Skipped Rules
                </Typography>
                <Typography variant="h4">
                  {feed.stats?.skipped_rules ?? 0}
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle2" color="text.secondary">
                  Sync Count
                </Typography>
                <Typography variant="h4">
                  {feed.stats?.sync_count ?? 0}
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle2" color="text.secondary">
                  Last Sync Duration
                </Typography>
                <Typography variant="h4">
                  {formatDuration(feed.stats?.last_sync_duration)}
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle2" color="text.secondary">
                  Priority
                </Typography>
                <Typography variant="h4">
                  {feed.priority}
                </Typography>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        {/* Sync History Tab */}
        <TabPanel value={currentTab} index={2}>
          <Box sx={{ px: 3 }}>
            {isLoadingHistory ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <CircularProgress />
                <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                  Loading sync history...
                </Typography>
              </Box>
            ) : syncHistory.length === 0 ? (
              <Alert severity="info">
                No sync history available. Trigger a sync to start collecting history.
              </Alert>
            ) : (
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Status</TableCell>
                      <TableCell>Started</TableCell>
                      <TableCell>Duration</TableCell>
                      <TableCell align="right">Imported</TableCell>
                      <TableCell align="right">Updated</TableCell>
                      <TableCell align="right">Failed</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {syncHistory.map((sync, index) => (
                      <TableRow key={index}>
                        <TableCell>
                          <Chip
                            label={sync.success ? 'Success' : 'Failed'}
                            color={sync.success ? 'success' : 'error'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          {formatDate(sync.start_time)}
                        </TableCell>
                        <TableCell>
                          {formatDuration(sync.duration)}
                        </TableCell>
                        <TableCell align="right">
                          {sync.stats?.imported_rules ?? 0}
                        </TableCell>
                        <TableCell align="right">
                          {sync.stats?.updated_rules ?? 0}
                        </TableCell>
                        <TableCell align="right">
                          <Typography
                            color={sync.stats?.failed_rules ? 'error' : 'inherit'}
                          >
                            {sync.stats?.failed_rules ?? 0}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>
        </TabPanel>

        {/* Configuration Tab */}
        <TabPanel value={currentTab} index={3}>
          <Box sx={{ px: 3 }}>
            <Grid container spacing={3}>
              {/* Update Settings */}
              <Grid item xs={12}>
                <Typography variant="subtitle1" gutterBottom>
                  Update Settings
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Update Strategy
                    </Typography>
                    <Chip
                      icon={<ScheduleIcon />}
                      label={feed.update_strategy.charAt(0).toUpperCase() + feed.update_strategy.slice(1)}
                      variant="outlined"
                    />
                  </Grid>
                  {feed.update_strategy === 'scheduled' && feed.update_schedule && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Schedule (Cron)
                      </Typography>
                      <Typography variant="body1" fontFamily="monospace">
                        {feed.update_schedule}
                      </Typography>
                    </Grid>
                  )}
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Auto-enable Rules
                    </Typography>
                    <Chip
                      label={feed.auto_enable_rules ? 'Enabled' : 'Disabled'}
                      color={feed.auto_enable_rules ? 'success' : 'default'}
                      size="small"
                    />
                  </Grid>
                </Grid>
              </Grid>

              <Grid item xs={12}>
                <Divider />
              </Grid>

              {/* Filters */}
              <Grid item xs={12}>
                <Typography variant="subtitle1" gutterBottom>
                  Filters
                </Typography>
                <Grid container spacing={2}>
                  {feed.include_paths && feed.include_paths.length > 0 && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Include Paths
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {feed.include_paths.map(path => (
                          <Chip key={path} label={path} size="small" variant="outlined" />
                        ))}
                      </Box>
                    </Grid>
                  )}
                  {feed.exclude_paths && feed.exclude_paths.length > 0 && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Exclude Paths
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {feed.exclude_paths.map(path => (
                          <Chip key={path} label={path} size="small" variant="outlined" />
                        ))}
                      </Box>
                    </Grid>
                  )}
                  {feed.include_tags && feed.include_tags.length > 0 && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Include Tags
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {feed.include_tags.map(tag => (
                          <Chip key={tag} label={tag} size="small" variant="outlined" color="success" />
                        ))}
                      </Box>
                    </Grid>
                  )}
                  {feed.exclude_tags && feed.exclude_tags.length > 0 && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Exclude Tags
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {feed.exclude_tags.map(tag => (
                          <Chip key={tag} label={tag} size="small" variant="outlined" color="error" />
                        ))}
                      </Box>
                    </Grid>
                  )}
                  {feed.min_severity && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Minimum Severity
                      </Typography>
                      <Chip
                        label={feed.min_severity.charAt(0).toUpperCase() + feed.min_severity.slice(1)}
                        size="small"
                        variant="outlined"
                      />
                    </Grid>
                  )}
                  {!feed.include_paths?.length && !feed.exclude_paths?.length &&
                   !feed.include_tags?.length && !feed.exclude_tags?.length && !feed.min_severity && (
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">
                        No filters configured - all rules will be imported.
                      </Typography>
                    </Grid>
                  )}
                </Grid>
              </Grid>

              <Grid item xs={12}>
                <Divider />
              </Grid>

              {/* Metadata */}
              <Grid item xs={12}>
                <Typography variant="subtitle1" gutterBottom>
                  Metadata
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Created
                    </Typography>
                    <Typography variant="body1">
                      {formatDate(feed.created_at)}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Last Updated
                    </Typography>
                    <Typography variant="body1">
                      {formatDate(feed.updated_at)}
                    </Typography>
                  </Grid>
                  {feed.created_by && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Created By
                      </Typography>
                      <Typography variant="body1">
                        {feed.created_by}
                      </Typography>
                    </Grid>
                  )}
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Feed ID
                    </Typography>
                    <Typography variant="body2" fontFamily="monospace">
                      {feed.id}
                    </Typography>
                  </Grid>
                </Grid>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose}>Close</Button>
        <Button variant="outlined" onClick={handleEdit} startIcon={<EditIcon />}>
          Edit Feed
        </Button>
        <Button
          variant="contained"
          onClick={handleSync}
          startIcon={isSyncing || feed.status === 'syncing' ? <CircularProgress size={20} /> : <SyncIcon />}
          disabled={isSyncing || feed.status === 'syncing'}
        >
          {isSyncing || feed.status === 'syncing' ? 'Syncing...' : 'Sync Now'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
