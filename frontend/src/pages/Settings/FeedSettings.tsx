/**
 * FeedSettings Component (Task 156.5)
 * Settings panel for managing SIGMA rule feeds
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Box,
  Typography,
  Alert,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Snackbar,
  CircularProgress,
} from '@mui/material';
import {
  Sync as SyncIcon,
} from '@mui/icons-material';
import { apiService } from '../../services/api';
import { websocketService, type FeedSyncEvent } from '../../services/websocket'; // TASK 158
import {
  FeedListView,
  FeedFormDialog,
  FeedDetailModal,
  SyncProgressIndicator,
  useSyncOperations,
} from '../../components/feeds';
import type {
  Feed,
  FeedForm,
  FeedSyncResult,
} from '../../types';

const ITEMS_PER_PAGE = 12;

export default function FeedSettings() {
  const queryClient = useQueryClient();
  const isMountedRef = useRef(true);

  // State
  const [page, setPage] = useState(1);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [detailModalOpen, setDetailModalOpen] = useState(false);
  const [selectedFeed, setSelectedFeed] = useState<Feed | null>(null);
  const [pendingOperations, setPendingOperations] = useState<Record<string, string>>({});
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'warning';
  }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Sync operations tracking
  const {
    operations: syncOperations,
    collapsed: syncCollapsed,
    startSync,
    completeSync,
    dismissOperation,
    toggleCollapse,
  } = useSyncOperations();

  // Cleanup on unmount
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  // TASK 158: Subscribe to WebSocket feed sync events
  useEffect(() => {
    const handleFeedSync = (event: FeedSyncEvent) => {
      if (!isMountedRef.current) return;

      const feedId = event.feed_id;
      const feedName = event.feed_name;

      switch (event.type) {
        case 'feed:sync:started':
          startSync(feedId, feedName);
          setPending(feedId, 'syncing');
          showSnackbar(`Starting sync for ${feedName}`, 'success');
          break;

        case 'feed:sync:progress':
          // Update progress in sync operations tracker
          if (event.message) {
            console.log(`[Feed ${feedName}] ${event.progress}%: ${event.message}`);
          }
          break;

        case 'feed:sync:completed':
          // Create a FeedSyncResult from the event
          const successResult: FeedSyncResult = {
            feed_id: feedId,
            feed_name: feedName,
            success: true,
            start_time: event.timestamp,
            end_time: event.timestamp,
            duration: event.stats?.last_sync_duration ?? 0,
            stats: event.stats ?? {
              total_rules: 0,
              imported_rules: 0,
              updated_rules: 0,
              skipped_rules: 0,
              failed_rules: 0,
              sync_count: 0,
            },
          };
          completeSync(feedId, successResult);
          clearPending(feedId);
          queryClient.invalidateQueries({ queryKey: ['feeds'] });
          queryClient.invalidateQueries({ queryKey: ['feed-history', feedId] });
          showSnackbar(
            `Synced ${event.stats?.imported_rules ?? 0} rules from ${feedName}`,
            'success'
          );
          break;

        case 'feed:sync:failed':
          const failedResult: FeedSyncResult = {
            feed_id: feedId,
            feed_name: feedName,
            success: false,
            start_time: event.timestamp,
            end_time: event.timestamp,
            duration: 0,
            stats: {
              total_rules: 0,
              imported_rules: 0,
              updated_rules: 0,
              skipped_rules: 0,
              failed_rules: 0,
              sync_count: 0,
            },
            errors: event.error ? [event.error] : ['Sync failed'],
          };
          completeSync(feedId, failedResult);
          clearPending(feedId);
          queryClient.invalidateQueries({ queryKey: ['feeds'] });
          showSnackbar(event.error || `Sync failed for ${feedName}`, 'error');
          break;
      }
    };

    websocketService.subscribe({ onFeedSync: handleFeedSync });

    return () => {
      // Cleanup - websocketService handles unsubscribe internally
    };
  }, [queryClient, startSync, completeSync, clearPending, showSnackbar, setPending]);

  // Fetch feeds
  const {
    data: feedsData,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['feeds', page],
    queryFn: () => apiService.feeds.getFeeds(page, ITEMS_PER_PAGE),
  });

  // Fetch templates
  const { data: templates = [] } = useQuery({
    queryKey: ['feed-templates'],
    queryFn: () => apiService.feeds.getTemplates(),
  });

  // Fetch sync history for selected feed
  const { data: syncHistory = [], isLoading: isLoadingHistory } = useQuery({
    queryKey: ['feed-history', selectedFeed?.id],
    queryFn: () =>
      selectedFeed ? apiService.feeds.getFeedHistory(selectedFeed.id, 10) : Promise.resolve([]),
    enabled: !!selectedFeed && detailModalOpen,
  });

  // Helper to show snackbar
  const showSnackbar = useCallback(
    (message: string, severity: 'success' | 'error' | 'warning') => {
      if (isMountedRef.current) {
        setSnackbar({ open: true, message, severity });
      }
    },
    []
  );

  // Helper to track pending operations
  const setPending = useCallback((feedId: string, operation: string) => {
    setPendingOperations(prev => ({ ...prev, [feedId]: operation }));
  }, []);

  const clearPending = useCallback((feedId: string) => {
    setPendingOperations(prev => {
      const next = { ...prev };
      delete next[feedId];
      return next;
    });
  }, []);

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: FeedForm) => apiService.feeds.createFeed(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['feeds'] });
      setCreateDialogOpen(false);
      showSnackbar('Feed created successfully', 'success');
    },
    onError: (error: Error) => {
      showSnackbar(error.message || 'Failed to create feed', 'error');
    },
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<FeedForm> }) =>
      apiService.feeds.updateFeed(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['feeds'] });
      setEditDialogOpen(false);
      setSelectedFeed(null);
      showSnackbar('Feed updated successfully', 'success');
    },
    onError: (error: Error) => {
      showSnackbar(error.message || 'Failed to update feed', 'error');
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiService.feeds.deleteFeed(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['feeds'] });
      setDeleteDialogOpen(false);
      setSelectedFeed(null);
      showSnackbar('Feed deleted successfully', 'success');
    },
    onError: (error: Error) => {
      showSnackbar(error.message || 'Failed to delete feed', 'error');
    },
  });

  // Sync mutation
  const syncMutation = useMutation({
    mutationFn: (feedId: string) => apiService.feeds.syncFeed(feedId),
    onMutate: (feedId) => {
      const feed = feedsData?.items.find(f => f.id === feedId);
      if (feed) {
        startSync(feedId, feed.name);
        setPending(feedId, 'syncing');
      }
    },
    onSuccess: (result, feedId) => {
      completeSync(feedId, result);
      queryClient.invalidateQueries({ queryKey: ['feeds'] });
      queryClient.invalidateQueries({ queryKey: ['feed-history', feedId] });
      showSnackbar(
        result.success
          ? `Synced ${result.stats?.imported_rules ?? 0} rules from ${result.feed_name}`
          : `Sync failed: ${result.errors?.[0] || 'Unknown error'}`,
        result.success ? 'success' : 'error'
      );
    },
    onError: (error: Error, feedId) => {
      completeSync(feedId, {
        feed_id: feedId,
        feed_name: feedsData?.items.find(f => f.id === feedId)?.name ?? 'Unknown',
        success: false,
        start_time: new Date().toISOString(),
        end_time: new Date().toISOString(),
        duration: 0,
        stats: {
          total_rules: 0,
          imported_rules: 0,
          updated_rules: 0,
          skipped_rules: 0,
          failed_rules: 0,
          sync_count: 0,
        },
        errors: [error.message],
      });
      showSnackbar(error.message || 'Failed to sync feed', 'error');
    },
    onSettled: (_, __, feedId) => {
      clearPending(feedId);
    },
  });

  // Enable/Disable mutations
  const enableMutation = useMutation({
    mutationFn: (feedId: string) => apiService.feeds.enableFeed(feedId),
    onMutate: (feedId) => {
      setPending(feedId, 'enabling');
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['feeds'] });
      showSnackbar('Feed enabled', 'success');
    },
    onError: (error: Error) => {
      showSnackbar(error.message || 'Failed to enable feed', 'error');
    },
    onSettled: (_, __, feedId) => {
      clearPending(feedId);
    },
  });

  const disableMutation = useMutation({
    mutationFn: (feedId: string) => apiService.feeds.disableFeed(feedId),
    onMutate: (feedId) => {
      setPending(feedId, 'disabling');
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['feeds'] });
      showSnackbar('Feed disabled', 'success');
    },
    onError: (error: Error) => {
      showSnackbar(error.message || 'Failed to disable feed', 'error');
    },
    onSettled: (_, __, feedId) => {
      clearPending(feedId);
    },
  });

  // Sync all feeds
  const syncAllMutation = useMutation({
    mutationFn: () => apiService.feeds.syncAllFeeds(),
    onSuccess: (results) => {
      queryClient.invalidateQueries({ queryKey: ['feeds'] });
      const successful = results.filter(r => r.success).length;
      const failed = results.filter(r => !r.success).length;
      showSnackbar(
        `Synced ${successful} feed${successful !== 1 ? 's' : ''}, ${failed} failed`,
        failed > 0 ? 'warning' : 'success'
      );
    },
    onError: (error: Error) => {
      showSnackbar(error.message || 'Failed to sync all feeds', 'error');
    },
  });

  // Event handlers
  const handlePageChange = useCallback((newPage: number) => {
    setPage(newPage);
  }, []);

  const handleCreateFeed = useCallback(() => {
    setCreateDialogOpen(true);
  }, []);

  const handleEditFeed = useCallback((feed: Feed) => {
    setSelectedFeed(feed);
    setEditDialogOpen(true);
  }, []);

  const handleDeleteFeed = useCallback((feed: Feed) => {
    setSelectedFeed(feed);
    setDeleteDialogOpen(true);
  }, []);

  const handleViewDetails = useCallback((feed: Feed) => {
    setSelectedFeed(feed);
    setDetailModalOpen(true);
  }, []);

  const handleSyncFeed = useCallback(
    async (feedId: string): Promise<FeedSyncResult> => {
      const result = await syncMutation.mutateAsync(feedId);
      return result;
    },
    [syncMutation]
  );

  const handleEnableFeed = useCallback(
    async (feedId: string): Promise<void> => {
      await enableMutation.mutateAsync(feedId);
    },
    [enableMutation]
  );

  const handleDisableFeed = useCallback(
    async (feedId: string): Promise<void> => {
      await disableMutation.mutateAsync(feedId);
    },
    [disableMutation]
  );

  const handleToggleEnabled = useCallback(
    async (feedId: string, enabled: boolean): Promise<void> => {
      if (enabled) {
        await handleEnableFeed(feedId);
      } else {
        await handleDisableFeed(feedId);
      }
    },
    [handleEnableFeed, handleDisableFeed]
  );

  const handleCreateSubmit = useCallback(
    async (data: FeedForm) => {
      await createMutation.mutateAsync(data);
    },
    [createMutation]
  );

  const handleEditSubmit = useCallback(
    async (data: FeedForm) => {
      if (selectedFeed) {
        await updateMutation.mutateAsync({ id: selectedFeed.id, data });
      }
    },
    [selectedFeed, updateMutation]
  );

  const handleDeleteConfirm = useCallback(() => {
    if (selectedFeed) {
      deleteMutation.mutate(selectedFeed.id);
    }
  }, [selectedFeed, deleteMutation]);

  const feeds = feedsData?.items ?? [];
  const total = feedsData?.total ?? 0;

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h6" gutterBottom>
            SIGMA Rule Feeds
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Configure external sources for SIGMA detection rules. Feeds can be Git repositories or
            local filesystem directories containing SIGMA YAML rule files.
          </Typography>
        </Box>
        <Button
          variant="outlined"
          startIcon={syncAllMutation.isPending ? <CircularProgress size={20} /> : <SyncIcon />}
          onClick={() => syncAllMutation.mutate()}
          disabled={syncAllMutation.isPending || feeds.length === 0}
        >
          Sync All
        </Button>
      </Box>

      {/* Feed List */}
      <FeedListView
        feeds={feeds}
        total={total}
        page={page}
        isLoading={isLoading}
        error={error as Error | null}
        onPageChange={handlePageChange}
        onRefresh={() => refetch()}
        onCreateFeed={handleCreateFeed}
        onEditFeed={handleEditFeed}
        onDeleteFeed={handleDeleteFeed}
        onViewDetails={handleViewDetails}
        onSyncFeed={handleSyncFeed}
        onEnableFeed={handleEnableFeed}
        onDisableFeed={handleDisableFeed}
        pendingOperations={pendingOperations}
      />

      {/* Create Dialog */}
      <FeedFormDialog
        open={createDialogOpen}
        mode="create"
        templates={templates}
        onSubmit={handleCreateSubmit}
        onCancel={() => setCreateDialogOpen(false)}
        isSubmitting={createMutation.isPending}
        error={createMutation.error?.message}
      />

      {/* Edit Dialog */}
      <FeedFormDialog
        open={editDialogOpen}
        mode="edit"
        feed={selectedFeed}
        templates={templates}
        onSubmit={handleEditSubmit}
        onCancel={() => {
          setEditDialogOpen(false);
          setSelectedFeed(null);
        }}
        isSubmitting={updateMutation.isPending}
        error={updateMutation.error?.message}
      />

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
        aria-labelledby="delete-feed-dialog-title"
      >
        <DialogTitle id="delete-feed-dialog-title">Delete Feed</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the feed "{selectedFeed?.name}"?
          </Typography>
          <Alert severity="warning" sx={{ mt: 2 }}>
            This will remove the feed configuration. Rules imported from this feed will remain
            in the system but will no longer receive updates.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleDeleteConfirm}
            color="error"
            variant="contained"
            disabled={deleteMutation.isPending}
          >
            {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Detail Modal */}
      <FeedDetailModal
        open={detailModalOpen}
        feed={selectedFeed}
        syncHistory={syncHistory}
        isLoadingHistory={isLoadingHistory}
        onClose={() => {
          setDetailModalOpen(false);
          setSelectedFeed(null);
        }}
        onEdit={handleEditFeed}
        onSync={handleSyncFeed}
        onToggleEnabled={handleToggleEnabled}
        isSyncing={selectedFeed ? !!pendingOperations[selectedFeed.id] : false}
      />

      {/* Sync Progress Indicator */}
      <SyncProgressIndicator
        operations={syncOperations}
        onDismiss={dismissOperation}
        collapsed={syncCollapsed}
        onToggleCollapse={toggleCollapse}
      />

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          variant="filled"
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}
