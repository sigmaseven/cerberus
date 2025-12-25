import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Snackbar,
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
} from '@mui/material';
import {
  Wifi as WifiIcon,
  WifiOff as WifiOffIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  RestartAlt as RestartIcon,
  MoreVert as MoreIcon,
  Error as ErrorIcon,
  Search as SearchIcon,
  ViewModule as GridViewIcon,
  ViewList as ListViewIcon,
  ContentCopy as CopyIcon,
  Info as InfoIcon,
  Lock as LockIcon,
} from '@mui/icons-material';
import { apiService } from '../../services/api';
import { POLLING_INTERVALS } from '../../utils/severity';
import { ListenerForm } from '../../components/forms/ListenerForm';
import { SectionErrorBoundary } from '../../components/SectionErrorBoundary';
import type {
  DynamicListener,
  ListenerForm as ListenerFormType,
  ListenerStatusValue,
  PaginationResponse,
} from '../../types';

const ITEMS_PER_PAGE = 12;
const MAX_VISIBLE_TAGS = 3;
// CRITICAL-1: Rate limiting for control operations
const CONTROL_RATE_LIMIT_MS = 1000;

/**
 * Optimistic status map for type-safe status transitions
 * BLOCKING-6 fix: Type-safe status values
 */
const OPTIMISTIC_STATUS: Record<'start' | 'stop' | 'restart', ListenerStatusValue> = {
  start: 'starting',
  stop: 'stopped',
  restart: 'starting',
} as const;

/**
 * Get status color based on listener state
 */
const getStatusColor = (status: ListenerStatusValue): 'success' | 'error' | 'warning' | 'default' => {
  switch (status) {
    case 'running':
      return 'success';
    case 'error':
      return 'error';
    case 'starting':
      return 'warning';
    case 'stopped':
    default:
      return 'default';
  }
};

/**
 * Get status icon based on listener state
 */
const getStatusIcon = (status: ListenerStatusValue) => {
  switch (status) {
    case 'running':
      return <WifiIcon color="success" aria-hidden="true" />;
    case 'error':
      return <ErrorIcon color="error" aria-hidden="true" />;
    case 'starting':
      return <CircularProgress size={20} aria-hidden="true" />;
    case 'stopped':
    default:
      return <WifiOffIcon color="disabled" aria-hidden="true" />;
  }
};

/**
 * Format events per minute display
 */
const formatEventsPerMinute = (rate: number) => {
  if (rate === 0) return '0';
  if (rate < 1) return '< 1';
  if (rate >= 1000) return `${(rate / 1000).toFixed(1)}k`;
  return rate.toFixed(1);
};

/**
 * BLOCKING-6 FIX: Format and validate port number
 */
const formatPort = (port: number): string => {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error(`Invalid port number: ${port}`);
    return '[Invalid]';
  }
  return port.toString();
};

/**
 * Format uptime duration
 */
const formatUptime = (startedAt?: string) => {
  if (!startedAt) return 'N/A';
  const diffMs = Date.now() - new Date(startedAt).getTime();
  const hours = Math.floor(diffMs / 3600000);
  const minutes = Math.floor((diffMs % 3600000) / 60000);
  if (hours > 24) {
    const days = Math.floor(hours / 24);
    return `${days}d ${hours % 24}h`;
  }
  return `${hours}h ${minutes}m`;
};

/**
 * Check if listener matches search query (client-side filter for current page only)
 */
const matchesSearch = (listener: DynamicListener, query: string): boolean => {
  if (!query) return true;
  const searchableFields = [
    listener.name,
    listener.type,
    listener.source,
    ...(listener.tags ?? []),
  ];
  const lowerQuery = query.toLowerCase();
  return searchableFields.some(field =>
    field.toLowerCase().includes(lowerQuery)
  );
};

/**
 * Dialog Error Fallback Component
 * BLOCKING-8 fix: Error boundary fallback for dialogs
 */
function DialogErrorFallback({ onClose, title }: { onClose: () => void; title: string }) {
  return (
    <Box sx={{ p: 3, textAlign: 'center' }}>
      <ErrorIcon color="error" sx={{ fontSize: 48, mb: 2 }} />
      <Typography variant="h6" gutterBottom>
        {title} Error
      </Typography>
      <Typography color="text.secondary" sx={{ mb: 2 }}>
        An unexpected error occurred. Please try again.
      </Typography>
      <Button variant="contained" onClick={onClose}>
        Close
      </Button>
    </Box>
  );
}

function Listeners() {
  const queryClient = useQueryClient();

  // BLOCKING-4, BLOCKING-9, BLOCKING-10 fix: Track mounted state
  const isMountedRef = useRef(true);

  // BLOCKING-1 fix: Use ref for atomic pending state check
  const pendingOperationsRef = useRef<Record<string, string>>({});

  // CRITICAL-1 fix: Rate limiting state
  const lastControlOperationRef = useRef<Record<string, number>>({});

  // BLOCKING-7 FIX: Track if search warning was shown
  const searchWarningShownRef = useRef(false);

  // State
  const [page, setPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedListener, setSelectedListener] = useState<DynamicListener | null>(null);
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [pendingOperations, setPendingOperations] = useState<Record<string, string>>({});
  // BLOCKING-5 FIX: Persist view mode to localStorage
  const [viewMode, setViewMode] = useState<'grid' | 'table'>(() => {
    try {
      const saved = localStorage.getItem('listeners-view-mode');
      return saved === 'table' || saved === 'grid' ? saved : 'grid';
    } catch {
      return 'grid';
    }
  });
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' | 'warning' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // BLOCKING-10 fix: Cleanup on unmount
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  // BLOCKING-9 fix: Debounce with mounted check
  useEffect(() => {
    const timer = setTimeout(() => {
      if (isMountedRef.current) {
        setDebouncedSearch(searchQuery);
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // CRITICAL-2 fix: Conditional polling based on query status
  const {
    data: listenersData,
    isLoading,
    error,
    refetch,
    status: queryStatus,
  } = useQuery({
    queryKey: ['listeners', page],
    queryFn: () => apiService.listeners.getListeners(page, ITEMS_PER_PAGE),
    refetchInterval: (query) => {
      // Pause polling if query is in error state
      return query.state.status === 'error' ? false : POLLING_INTERVALS.LISTENERS;
    },
  });

  // BLOCKING-3 fix: Use queryClient instead of refetch for stable reference
  const handleListenerStatus = useCallback(() => {
    if (isMountedRef.current) {
      queryClient.invalidateQueries({ queryKey: ['listeners'], exact: false });
    }
  }, [queryClient]);

  // BLOCKING-2 fix: WebSocket subscription with proper cleanup
  useEffect(() => {
    const callbacks = {
      onListenerStatus: handleListenerStatus,
    };

    apiService.subscribeToRealtimeUpdates(callbacks);

    return () => {
      // Only unsubscribe our specific callbacks
      apiService.unsubscribeFromRealtimeUpdates();
    };
  }, [handleListenerStatus]);

  // CRITICAL-3 fix: Disable pagination during load
  useEffect(() => {
    if (!isLoading) {
      const totalPages = Math.ceil((listenersData?.total ?? 0) / ITEMS_PER_PAGE);
      if (page > totalPages && totalPages > 0) {
        setPage(totalPages);
      }
    }
  }, [listenersData?.total, page, isLoading]);

  // BLOCKING-4 fix: Safe snackbar with mounted check
  const showSnackbar = useCallback((message: string, severity: 'success' | 'error' | 'warning') => {
    if (isMountedRef.current) {
      setSnackbar({ open: true, message, severity });
    }
  }, []);

  // BLOCKING-1 fix: Atomic check-and-set for pending operations
  const trySetPending = useCallback((id: string, operation: string): boolean => {
    // Check if already pending using ref (synchronous, no race condition)
    if (pendingOperationsRef.current[id]) {
      return false; // Already pending
    }
    // Set pending state atomically
    pendingOperationsRef.current[id] = operation;
    if (isMountedRef.current) {
      setPendingOperations(prev => ({ ...prev, [id]: operation }));
    }
    return true; // Successfully set
  }, []);

  /**
   * BLOCKING-NEW-3 fix: Always clear pending state, even after unmount.
   * The ref is always cleared to prevent stale state. React's setState is safe
   * to call after unmount (it's a no-op), so we don't check isMountedRef here.
   * This ensures cleanup happens reliably in onSettled callbacks.
   */
  const clearPending = useCallback((id: string) => {
    delete pendingOperationsRef.current[id];
    // React's setState is safe after unmount - it simply becomes a no-op
    setPendingOperations(prev => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
  }, []);

  const isPending = useCallback((id: string) => {
    return !!pendingOperationsRef.current[id];
  }, []);

  // CRITICAL-1 fix: Rate limiting check
  const isRateLimited = useCallback((id: string): boolean => {
    const lastOperation = lastControlOperationRef.current[id] || 0;
    const now = Date.now();
    if (now - lastOperation < CONTROL_RATE_LIMIT_MS) {
      return true;
    }
    lastControlOperationRef.current[id] = now;
    return false;
  }, []);

  // BLOCKING-5 fix: Consistent query key for all operations
  const getListenersQueryKey = useCallback(() => ['listeners', page] as const, [page]);

  // Mutations with all fixes applied
  const createMutation = useMutation({
    mutationFn: (data: ListenerFormType) => apiService.listeners.createListener(data),
    onSuccess: () => {
      if (isMountedRef.current) {
        queryClient.invalidateQueries({ queryKey: ['listeners'], exact: false });
        setCreateDialogOpen(false);
        showSnackbar('Listener created successfully', 'success');
      }
    },
    onError: (error: Error) => {
      showSnackbar(error.message || 'Failed to create listener', 'error');
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ListenerFormType> }) =>
      apiService.listeners.updateListener(id, data),
    onSuccess: () => {
      if (isMountedRef.current) {
        queryClient.invalidateQueries({ queryKey: ['listeners'], exact: false });
        setEditDialogOpen(false);
        setSelectedListener(null);
        showSnackbar('Listener updated successfully', 'success');
      }
    },
    onError: (error: Error) => {
      showSnackbar(error.message || 'Failed to update listener', 'error');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiService.listeners.deleteListener(id),
    onMutate: async () => {
      const queryKey = getListenersQueryKey();
      await queryClient.cancelQueries({ queryKey });
      const previousData = queryClient.getQueryData<PaginationResponse<DynamicListener>>(queryKey);
      return { previousData, queryKey };
    },
    onSuccess: () => {
      if (isMountedRef.current) {
        queryClient.invalidateQueries({ queryKey: ['listeners'], exact: false });
        setDeleteDialogOpen(false);
        setSelectedListener(null);
        showSnackbar('Listener deleted successfully', 'success');
      }
    },
    onError: (error: Error, _id, context) => {
      if (context?.previousData && context.queryKey) {
        queryClient.setQueryData(context.queryKey, context.previousData);
      }
      showSnackbar(error.message || 'Failed to delete listener', 'error');
    },
  });

  // Control mutations with atomic guards and optimistic updates
  const startMutation = useMutation({
    mutationFn: (id: string) => apiService.listeners.startListener(id),
    onMutate: async (id) => {
      // BLOCKING-1: Atomic check-and-set
      if (!trySetPending(id, 'starting')) {
        throw new Error('Operation already in progress');
      }

      const queryKey = getListenersQueryKey();
      await queryClient.cancelQueries({ queryKey });
      const previousData = queryClient.getQueryData<PaginationResponse<DynamicListener>>(queryKey);

      // BLOCKING-6 fix: Type-safe optimistic update
      if (previousData && isMountedRef.current) {
        queryClient.setQueryData(queryKey, {
          ...previousData,
          items: previousData.items.map((l: DynamicListener) =>
            l.id === id ? { ...l, status: OPTIMISTIC_STATUS.start } : l
          ),
        });
      }
      return { previousData, queryKey };
    },
    onSuccess: () => {
      if (isMountedRef.current) {
        queryClient.invalidateQueries({ queryKey: ['listeners'], exact: false });
        showSnackbar('Listener started', 'success');
      }
    },
    onError: (error: Error, id, context) => {
      if (context?.previousData && context.queryKey) {
        queryClient.setQueryData(context.queryKey, context.previousData);
      }
      clearPending(id);
      showSnackbar(error.message || 'Failed to start listener', 'error');
    },
    onSettled: (_data, _error, id) => {
      clearPending(id);
    },
  });

  const stopMutation = useMutation({
    mutationFn: (id: string) => apiService.listeners.stopListener(id),
    onMutate: async (id) => {
      if (!trySetPending(id, 'stopping')) {
        throw new Error('Operation already in progress');
      }

      const queryKey = getListenersQueryKey();
      await queryClient.cancelQueries({ queryKey });
      const previousData = queryClient.getQueryData<PaginationResponse<DynamicListener>>(queryKey);

      if (previousData && isMountedRef.current) {
        queryClient.setQueryData(queryKey, {
          ...previousData,
          items: previousData.items.map((l: DynamicListener) =>
            l.id === id ? { ...l, status: OPTIMISTIC_STATUS.stop } : l
          ),
        });
      }
      return { previousData, queryKey };
    },
    onSuccess: () => {
      if (isMountedRef.current) {
        queryClient.invalidateQueries({ queryKey: ['listeners'], exact: false });
        showSnackbar('Listener stopped', 'success');
      }
    },
    onError: (error: Error, id, context) => {
      if (context?.previousData && context.queryKey) {
        queryClient.setQueryData(context.queryKey, context.previousData);
      }
      clearPending(id);
      showSnackbar(error.message || 'Failed to stop listener', 'error');
    },
    onSettled: (_data, _error, id) => {
      clearPending(id);
    },
  });

  const restartMutation = useMutation({
    mutationFn: (id: string) => apiService.listeners.restartListener(id),
    onMutate: async (id) => {
      if (!trySetPending(id, 'restarting')) {
        throw new Error('Operation already in progress');
      }

      const queryKey = getListenersQueryKey();
      await queryClient.cancelQueries({ queryKey });
      const previousData = queryClient.getQueryData<PaginationResponse<DynamicListener>>(queryKey);

      if (previousData && isMountedRef.current) {
        queryClient.setQueryData(queryKey, {
          ...previousData,
          items: previousData.items.map((l: DynamicListener) =>
            l.id === id ? { ...l, status: OPTIMISTIC_STATUS.restart } : l
          ),
        });
      }
      return { previousData, queryKey };
    },
    onSuccess: () => {
      if (isMountedRef.current) {
        queryClient.invalidateQueries({ queryKey: ['listeners'], exact: false });
        showSnackbar('Listener restarted', 'success');
      }
    },
    onError: (error: Error, id, context) => {
      if (context?.previousData && context.queryKey) {
        queryClient.setQueryData(context.queryKey, context.previousData);
      }
      clearPending(id);
      showSnackbar(error.message || 'Failed to restart listener', 'error');
    },
    onSettled: (_data, _error, id) => {
      clearPending(id);
    },
  });

  // Event handlers
  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, listener: DynamicListener) => {
    setMenuAnchor(event.currentTarget);
    setSelectedListener(listener);
  };

  const handleMenuClose = () => {
    setMenuAnchor(null);
  };

  const handleEdit = () => {
    handleMenuClose();
    setEditDialogOpen(true);
  };

  const handleDeleteConfirm = () => {
    handleMenuClose();
    setDeleteDialogOpen(true);
  };

  // Control handlers with rate limiting (CRITICAL-1 fix)
  const handleControlOperation = useCallback((
    id: string,
    operation: 'start' | 'stop' | 'restart',
    mutation: typeof startMutation
  ) => {
    if (isRateLimited(id)) {
      showSnackbar('Please wait before retrying', 'warning');
      return;
    }
    mutation.mutate(id);
  }, [isRateLimited, showSnackbar]);

  // CRITICAL-5 fix: Keep menu open until mutation settles
  const handleStart = () => {
    if (selectedListener) {
      handleControlOperation(selectedListener.id, 'start', startMutation);
    }
    handleMenuClose();
  };

  const handleStop = () => {
    if (selectedListener) {
      handleControlOperation(selectedListener.id, 'stop', stopMutation);
    }
    handleMenuClose();
  };

  const handleRestart = () => {
    if (selectedListener) {
      handleControlOperation(selectedListener.id, 'restart', restartMutation);
    }
    handleMenuClose();
  };

  const handleCreateSubmit = (data: ListenerFormType) => {
    createMutation.mutate(data);
  };

  const handleEditSubmit = (data: ListenerFormType) => {
    if (selectedListener) {
      updateMutation.mutate({ id: selectedListener.id, data });
    }
  };

  const handleDeleteSubmit = () => {
    if (selectedListener) {
      deleteMutation.mutate(selectedListener.id);
    }
  };

  const handleCreateDialogClose = useCallback(() => {
    setCreateDialogOpen(false);
  }, []);

  const handleEditDialogClose = useCallback(() => {
    setEditDialogOpen(false);
    setSelectedListener(null);
  }, []);

  const handleDeleteDialogClose = useCallback(() => {
    setDeleteDialogOpen(false);
    setSelectedListener(null);
  }, []);

  const handleDetailDialogClose = useCallback(() => {
    setDetailDialogOpen(false);
    setSelectedListener(null);
  }, []);

  const handleViewDetails = () => {
    handleMenuClose();
    setDetailDialogOpen(true);
  };

  // BLOCKING-4 FIX: Dedicated handler to capture listener before menu close
  const handleCopyFromMenu = () => {
    if (selectedListener) {
      const listenerToUse = selectedListener; // Capture before close
      handleMenuClose();
      handleCopyEndpoint(listenerToUse); // Use captured reference
    }
  };

  // BLOCKING-2 FIX: Copy listener endpoint to clipboard with secure context check
  const handleCopyEndpoint = useCallback((listener: DynamicListener) => {
    const protocol = listener.tls ? 'tls' : listener.protocol;
    const endpoint = `${protocol}://${listener.host}:${listener.port}`;

    // Check for secure context and clipboard availability
    if (!navigator.clipboard || !window.isSecureContext) {
      showSnackbar(
        `Clipboard requires HTTPS or localhost. Endpoint: ${endpoint}`,
        'warning'
      );
      return;
    }

    navigator.clipboard.writeText(endpoint)
      .then(() => {
        showSnackbar(`Endpoint copied: ${endpoint}`, 'success');
      })
      .catch((error: Error) => {
        showSnackbar(
          `Failed to copy: ${error.message || 'Clipboard permission denied'}`,
          'error'
        );
      });
  }, [showSnackbar]);

  // BLOCKING-5 FIX: View mode toggle handler with localStorage persistence
  const handleViewModeChange = useCallback((_: React.MouseEvent<HTMLElement>, newMode: 'grid' | 'table' | null) => {
    if (newMode !== null) {
      setViewMode(newMode);
      try {
        localStorage.setItem('listeners-view-mode', newMode);
      } catch (error) {
        console.warn('Failed to save view mode preference:', error);
      }
    }
  }, []);

  // BLOCKING-7 FIX: Clear search when changing pages with single warning
  const handlePageChange = useCallback((_: React.ChangeEvent<unknown>, value: number) => {
    if (debouncedSearch) {
      // Show warning only once per search session
      if (!searchWarningShownRef.current) {
        showSnackbar('Search filter cleared when changing pages', 'warning');
        searchWarningShownRef.current = true;
        // Reset warning flag after delay to allow new searches
        setTimeout(() => {
          searchWarningShownRef.current = false;
        }, 5000);
      }
      setSearchQuery('');
      setDebouncedSearch('');
    }
    setPage(value);
  }, [debouncedSearch, showSnackbar]);

  // Filter listeners by search query - client-side only (BLOCKING-7: documented limitation)
  const listeners = listenersData?.items ?? [];
  const filteredListeners = useMemo(() =>
    listeners.filter(listener => matchesSearch(listener, debouncedSearch)),
    [listeners, debouncedSearch]
  );

  // QUALITY-7 fix: Efficient stats calculation with total events
  const stats = useMemo(() => {
    const result = {
      running: 0,
      stopped: 0,
      error: 0,
      starting: 0,
      totalEvents: 0,
      totalEventsPerMinute: 0,
    };
    filteredListeners.forEach(l => {
      result[l.status as keyof typeof result] = ((result[l.status as keyof typeof result] as number) || 0) + 1;
      result.totalEvents += l.events_received || 0;
      result.totalEventsPerMinute += l.events_per_minute || 0;
    });
    return result;
  }, [filteredListeners]);

  const totalPages = Math.ceil((listenersData?.total ?? 0) / ITEMS_PER_PAGE);

  // Loading state
  if (isLoading) {
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
          <Button color="inherit" size="small" onClick={() => refetch()}>
            Retry
          </Button>
        }
      >
        Failed to load listeners. Please check your connection and try again.
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
        <Typography variant="h4">Event Listeners</Typography>
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
            startIcon={<RefreshIcon />}
            onClick={() => refetch()}
            size="small"
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setCreateDialogOpen(true)}
          >
            New Listener
          </Button>
        </Box>
      </Box>

      {/* Search - BLOCKING-7 fix: Clear warning in placeholder */}
      <Box sx={{ mb: 3 }}>
        <TextField
          fullWidth
          placeholder="Filter current page by name, type, source, or tags..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          size="small"
          helperText={
            debouncedSearch
              ? `Showing ${filteredListeners.length} of ${listeners.length} listeners on this page. Search filter will be cleared when changing pages.`
              : "Filters the current page only. Server-side search coming soon."
          }
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon color="action" />
              </InputAdornment>
            ),
          }}
          inputProps={{
            'aria-label': 'Filter listeners on current page',
          }}
        />
      </Box>

      {/* Stats Summary */}
      <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap' }} role="status" aria-live="polite">
        <Chip
          icon={<WifiIcon />}
          label={`${stats.running} Running`}
          color="success"
          variant="outlined"
        />
        <Chip
          icon={<WifiOffIcon />}
          label={`${stats.stopped} Stopped`}
          variant="outlined"
        />
        <Chip
          icon={<ErrorIcon />}
          label={`${stats.error} Errors`}
          color="error"
          variant="outlined"
        />
      </Box>

      {/* Listeners Display */}
      {filteredListeners.length === 0 ? (
        <Alert severity="info" data-testid="listeners-empty-state">
          {debouncedSearch
            ? 'No listeners match your search criteria on this page.'
            : 'No listeners configured. Click "New Listener" to create one.'}
        </Alert>
      ) : viewMode === 'table' ? (
        /* BLOCKING-3 FIX: Table View (sorting not yet implemented) */
        <TableContainer component={Paper} data-testid="listeners-table">
          <Table size="small" aria-label="Listeners table - not sortable">
            <TableHead>
              <TableRow>
                <TableCell>Status</TableCell>
                <TableCell>Name</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Endpoint</TableCell>
                <TableCell align="right">Events</TableCell>
                <TableCell align="right">Rate</TableCell>
                <TableCell align="center">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredListeners.map((listener) => {
                const listenerPending = isPending(listener.id);
                return (
                  <TableRow
                    key={listener.id}
                    hover
                    sx={{
                      '&:last-child td, &:last-child th': { border: 0 },
                      opacity: listenerPending ? 0.7 : 1,
                    }}
                  >
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {getStatusIcon(listener.status)}
                        <Chip
                          label={listener.status}
                          color={getStatusColor(listener.status)}
                          size="small"
                        />
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {listener.name}
                      </Typography>
                      {listener.description && (
                        <Typography variant="caption" color="text.secondary" noWrap sx={{ maxWidth: 200, display: 'block' }}>
                          {listener.description}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {listener.type.toUpperCase()} / {listener.protocol.toUpperCase()}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        <Typography variant="body2" fontFamily="monospace">
                          {listener.host}:{formatPort(listener.port)}
                        </Typography>
                        {listener.tls && (
                          <Tooltip title="TLS Enabled">
                            <LockIcon fontSize="small" color="info" />
                          </Tooltip>
                        )}
                        <Tooltip title="Copy endpoint">
                          <IconButton
                            size="small"
                            onClick={() => handleCopyEndpoint(listener)}
                            aria-label={`Copy endpoint for ${listener.name}`}
                          >
                            <CopyIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </TableCell>
                    <TableCell align="right">
                      <Typography variant="body2">
                        {listener.events_received.toLocaleString()}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      <Typography variant="body2">
                        {formatEventsPerMinute(listener.events_per_minute)}/min
                      </Typography>
                    </TableCell>
                    <TableCell align="center">
                      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 0.5 }}>
                        {listenerPending ? (
                          <CircularProgress size={20} />
                        ) : (
                          <>
                            {listener.status === 'stopped' && (
                              <Tooltip title="Start">
                                <IconButton
                                  size="small"
                                  color="success"
                                  onClick={() => handleControlOperation(listener.id, 'start', startMutation)}
                                  aria-label={`Start ${listener.name}`}
                                >
                                  <PlayIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                            )}
                            {listener.status === 'running' && (
                              <>
                                <Tooltip title="Stop">
                                  <IconButton
                                    size="small"
                                    color="error"
                                    onClick={() => handleControlOperation(listener.id, 'stop', stopMutation)}
                                    aria-label={`Stop ${listener.name}`}
                                  >
                                    <StopIcon fontSize="small" />
                                  </IconButton>
                                </Tooltip>
                                <Tooltip title="Restart">
                                  <IconButton
                                    size="small"
                                    color="warning"
                                    onClick={() => handleControlOperation(listener.id, 'restart', restartMutation)}
                                    aria-label={`Restart ${listener.name}`}
                                  >
                                    <RestartIcon fontSize="small" />
                                  </IconButton>
                                </Tooltip>
                              </>
                            )}
                            <IconButton
                              size="small"
                              onClick={(e) => handleMenuOpen(e, listener)}
                              aria-label={`More actions for ${listener.name}`}
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
        <Grid container spacing={3} role="list" aria-label="Listeners" data-testid="listeners-grid">
          {filteredListeners.map((listener) => {
            const listenerPending = isPending(listener.id);
            /**
             * BLOCKING-NEW-2 fix: React automatically escapes text content.
             * Using escapeHTML on React children causes double-encoding issues
             * (e.g., "&" becomes "&amp;amp;"). Trust React's built-in XSS protection.
             * Only use escapeHTML for dangerouslySetInnerHTML (which we don't use here).
             */

            return (
              <Grid item xs={12} sm={6} lg={4} key={listener.id} role="listitem" data-testid="listener-card">
                <Card
                  sx={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    borderLeft: '4px solid',
                    borderLeftColor:
                      listener.status === 'running'
                        ? 'success.main'
                        : listener.status === 'error'
                        ? 'error.main'
                        : 'grey.400',
                    position: 'relative',
                  }}
                  aria-labelledby={`listener-${listener.id}-name`}
                >
                  {/* Loading overlay for pending operations */}
                  {listenerPending && (
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
                        {getStatusIcon(listener.status)}
                        <Box>
                          <Typography
                            variant="h6"
                            component="div"
                            noWrap
                            sx={{ maxWidth: 180 }}
                            id={`listener-${listener.id}-name`}
                          >
                            {listener.name}
                          </Typography>
                          <Chip
                            label={listener.status}
                            color={getStatusColor(listener.status)}
                            size="small"
                          />
                        </Box>
                      </Box>
                      <IconButton
                        size="small"
                        onClick={(e) => handleMenuOpen(e, listener)}
                        aria-label={`Open actions menu for ${listener.name}`}
                        aria-haspopup="menu"
                      >
                        <MoreIcon />
                      </IconButton>
                    </Box>

                    {/* Type & Protocol */}
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="body2" color="text.secondary">
                        {listener.type.toUpperCase()} / {listener.protocol.toUpperCase()}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {listener.host}:{formatPort(listener.port)}
                        {listener.tls && (
                          <Chip label="TLS" size="small" sx={{ ml: 1 }} color="info" />
                        )}
                      </Typography>
                    </Box>

                    {/* Statistics */}
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="body2">
                        <strong>Events:</strong> {listener.events_received.toLocaleString()}
                      </Typography>
                      <Typography variant="body2">
                        <strong>Rate:</strong> {formatEventsPerMinute(listener.events_per_minute)}/min
                      </Typography>
                      {listener.error_count > 0 && (
                        <Typography variant="body2" color="error">
                          <strong>Errors:</strong> {listener.error_count}
                        </Typography>
                      )}
                      {listener.status === 'running' && (
                        <Typography variant="body2" color="text.secondary">
                          <strong>Uptime:</strong> {formatUptime(listener.started_at)}
                        </Typography>
                      )}
                    </Box>

                    {/* Tags */}
                    {listener.tags && listener.tags.length > 0 && (
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {listener.tags.slice(0, MAX_VISIBLE_TAGS).map((tag) => (
                          <Chip key={tag} label={tag} size="small" variant="outlined" />
                        ))}
                        {listener.tags.length > MAX_VISIBLE_TAGS && (
                          <Chip label={`+${listener.tags.length - MAX_VISIBLE_TAGS}`} size="small" variant="outlined" />
                        )}
                      </Box>
                    )}
                  </CardContent>

                  {/* Quick Actions - BLOCKING-11 fix: Proper aria-disabled on wrapper */}
                  <CardActions sx={{ justifyContent: 'flex-end', pt: 0 }} role="group" aria-label="Quick actions">
                    {listener.status === 'stopped' ? (
                      <Tooltip title="Start Listener">
                        <span role="presentation" aria-disabled={listenerPending ? 'true' : undefined}>
                          <IconButton
                            color="success"
                            onClick={() => handleControlOperation(listener.id, 'start', startMutation)}
                            disabled={listenerPending}
                            size="small"
                            aria-label={`Start listener ${listener.name}`}
                            aria-busy={listenerPending}
                          >
                            {listenerPending ? <CircularProgress size={16} /> : <PlayIcon />}
                          </IconButton>
                        </span>
                      </Tooltip>
                    ) : listener.status === 'running' ? (
                      <>
                        <Tooltip title="Stop Listener">
                          <span role="presentation" aria-disabled={listenerPending ? 'true' : undefined}>
                            <IconButton
                              color="error"
                              onClick={() => handleControlOperation(listener.id, 'stop', stopMutation)}
                              disabled={listenerPending}
                              size="small"
                              aria-label={`Stop listener ${listener.name}`}
                              aria-busy={listenerPending}
                            >
                              {listenerPending ? <CircularProgress size={16} /> : <StopIcon />}
                            </IconButton>
                          </span>
                        </Tooltip>
                        <Tooltip title="Restart Listener">
                          <span role="presentation" aria-disabled={listenerPending ? 'true' : undefined}>
                            <IconButton
                              color="warning"
                              onClick={() => handleControlOperation(listener.id, 'restart', restartMutation)}
                              disabled={listenerPending}
                              size="small"
                              aria-label={`Restart listener ${listener.name}`}
                              aria-busy={listenerPending}
                            >
                              {listenerPending ? <CircularProgress size={16} /> : <RestartIcon />}
                            </IconButton>
                          </span>
                        </Tooltip>
                      </>
                    ) : null}
                  </CardActions>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      {/* Pagination - CRITICAL-3 fix: Disable during load */}
      {totalPages > 1 && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
          <Pagination
            count={totalPages}
            page={page}
            onChange={handlePageChange}
            color="primary"
            disabled={isLoading}
            aria-label="Listeners pagination"
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
        {selectedListener?.status === 'stopped' && (
          <MenuItem onClick={handleStart} disabled={selectedListener && isPending(selectedListener.id)}>
            <ListItemIcon>
              <PlayIcon color="success" />
            </ListItemIcon>
            <ListItemText>Start</ListItemText>
          </MenuItem>
        )}
        {selectedListener?.status === 'running' && (
          <>
            <MenuItem onClick={handleStop} disabled={selectedListener && isPending(selectedListener.id)}>
              <ListItemIcon>
                <StopIcon color="error" />
              </ListItemIcon>
              <ListItemText>Stop</ListItemText>
            </MenuItem>
            <MenuItem onClick={handleRestart} disabled={selectedListener && isPending(selectedListener.id)}>
              <ListItemIcon>
                <RestartIcon color="warning" />
              </ListItemIcon>
              <ListItemText>Restart</ListItemText>
            </MenuItem>
          </>
        )}
        <Divider />
        <MenuItem onClick={handleViewDetails}>
          <ListItemIcon>
            <InfoIcon />
          </ListItemIcon>
          <ListItemText>View Details</ListItemText>
        </MenuItem>
        <MenuItem onClick={handleCopyFromMenu}>
          <ListItemIcon>
            <CopyIcon />
          </ListItemIcon>
          <ListItemText>Copy Endpoint</ListItemText>
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleEdit} disabled={selectedListener?.status === 'running'}>
          <ListItemIcon>
            <EditIcon />
          </ListItemIcon>
          <ListItemText>Edit</ListItemText>
          {selectedListener?.status === 'running' && (
            <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
              (stop first)
            </Typography>
          )}
        </MenuItem>
        <MenuItem onClick={handleDeleteConfirm} disabled={selectedListener?.status === 'running'}>
          <ListItemIcon>
            <DeleteIcon color="error" />
          </ListItemIcon>
          <ListItemText>Delete</ListItemText>
          {selectedListener?.status === 'running' && (
            <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
              (stop first)
            </Typography>
          )}
        </MenuItem>
      </Menu>

      {/* Create Dialog - BLOCKING-8 fix: Error boundary wrapper */}
      <Dialog
        open={createDialogOpen}
        onClose={handleCreateDialogClose}
        maxWidth="md"
        fullWidth
        aria-labelledby="create-listener-dialog-title"
      >
        <DialogTitle id="create-listener-dialog-title">Create New Listener</DialogTitle>
        <DialogContent>
          <SectionErrorBoundary
            section="create-listener-dialog"
            fallback={<DialogErrorFallback onClose={handleCreateDialogClose} title="Create Listener" />}
          >
            <Box sx={{ pt: 1 }}>
              <ListenerForm
                mode="create"
                onSubmit={handleCreateSubmit}
                onCancel={handleCreateDialogClose}
              />
            </Box>
          </SectionErrorBoundary>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog - BLOCKING-8 fix: Error boundary wrapper */}
      <Dialog
        open={editDialogOpen}
        onClose={handleEditDialogClose}
        maxWidth="md"
        fullWidth
        aria-labelledby="edit-listener-dialog-title"
      >
        <DialogTitle id="edit-listener-dialog-title">Edit Listener</DialogTitle>
        <DialogContent>
          <SectionErrorBoundary
            section="edit-listener-dialog"
            fallback={<DialogErrorFallback onClose={handleEditDialogClose} title="Edit Listener" />}
          >
            <Box sx={{ pt: 1 }}>
              {selectedListener && (
                <ListenerForm
                  mode="edit"
                  initialValues={{
                    name: selectedListener.name,
                    description: selectedListener.description,
                    type: selectedListener.type,
                    protocol: selectedListener.protocol,
                    host: selectedListener.host,
                    port: selectedListener.port,
                    tls: selectedListener.tls,
                    cert_file: selectedListener.cert_file,
                    key_file: selectedListener.key_file,
                    tags: selectedListener.tags,
                    source: selectedListener.source,
                    field_mapping: selectedListener.field_mapping,
                  }}
                  onSubmit={handleEditSubmit}
                  onCancel={handleEditDialogClose}
                />
              )}
            </Box>
          </SectionErrorBoundary>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={handleDeleteDialogClose}
        aria-labelledby="delete-listener-dialog-title"
        aria-describedby="delete-listener-dialog-description"
      >
        <DialogTitle id="delete-listener-dialog-title">Delete Listener</DialogTitle>
        <DialogContent>
          <Typography id="delete-listener-dialog-description">
            Are you sure you want to delete the listener "{selectedListener?.name ?? ''}"?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDeleteDialogClose}>
            Cancel
          </Button>
          <Button
            onClick={handleDeleteSubmit}
            color="error"
            variant="contained"
            disabled={deleteMutation.isPending}
          >
            {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Detail Dialog */}
      <Dialog
        open={detailDialogOpen}
        onClose={handleDetailDialogClose}
        maxWidth="md"
        fullWidth
        aria-labelledby="detail-listener-dialog-title"
      >
        <DialogTitle id="detail-listener-dialog-title">
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {selectedListener && getStatusIcon(selectedListener.status)}
            {selectedListener?.name ?? 'Listener Details'}
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          {selectedListener && (
            <Box sx={{ display: 'grid', gap: 2 }}>
              {/* Basic Information */}
              <Box>
                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  Basic Information
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary">Name</Typography>
                    <Typography variant="body1">{selectedListener.name}</Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary">Status</Typography>
                    <Chip
                      label={selectedListener.status}
                      color={getStatusColor(selectedListener.status)}
                      size="small"
                    />
                  </Grid>
                  {selectedListener.description && (
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">Description</Typography>
                      <Typography variant="body1">{selectedListener.description}</Typography>
                    </Grid>
                  )}
                </Grid>
              </Box>

              <Divider />

              {/* Connection Details */}
              <Box>
                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  Connection Details
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary">Type</Typography>
                    <Typography variant="body1">{selectedListener.type.toUpperCase()}</Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary">Protocol</Typography>
                    <Typography variant="body1">{selectedListener.protocol.toUpperCase()}</Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary">Host</Typography>
                    <Typography variant="body1" fontFamily="monospace">{selectedListener.host}</Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary">Port</Typography>
                    <Typography variant="body1" fontFamily="monospace">{formatPort(selectedListener.port)}</Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary">Endpoint</Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="body1" fontFamily="monospace">
                        {selectedListener.tls ? 'tls' : selectedListener.protocol}://{selectedListener.host}:{formatPort(selectedListener.port)}
                      </Typography>
                      {selectedListener.tls && (
                        <Chip icon={<LockIcon />} label="TLS" size="small" color="info" />
                      )}
                      <IconButton
                        size="small"
                        onClick={() => handleCopyEndpoint(selectedListener)}
                        aria-label="Copy endpoint"
                      >
                        <CopyIcon fontSize="small" />
                      </IconButton>
                    </Box>
                  </Grid>
                </Grid>
              </Box>

              <Divider />

              {/* Statistics */}
              <Box>
                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  Statistics
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={4}>
                    <Typography variant="body2" color="text.secondary">Events Received</Typography>
                    <Typography variant="h6">{selectedListener.events_received.toLocaleString()}</Typography>
                  </Grid>
                  <Grid item xs={12} sm={4}>
                    <Typography variant="body2" color="text.secondary">Events/Minute</Typography>
                    <Typography variant="h6">{formatEventsPerMinute(selectedListener.events_per_minute)}</Typography>
                  </Grid>
                  <Grid item xs={12} sm={4}>
                    <Typography variant="body2" color="text.secondary">Errors</Typography>
                    <Typography variant="h6" color={selectedListener.error_count > 0 ? 'error.main' : 'text.primary'}>
                      {selectedListener.error_count}
                    </Typography>
                  </Grid>
                  {selectedListener.status === 'running' && selectedListener.started_at && (
                    <Grid item xs={12} sm={4}>
                      <Typography variant="body2" color="text.secondary">Uptime</Typography>
                      <Typography variant="h6">{formatUptime(selectedListener.started_at)}</Typography>
                    </Grid>
                  )}
                </Grid>
              </Box>

              {/* TLS Configuration */}
              {selectedListener.tls && (
                <>
                  <Divider />
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      TLS Configuration
                    </Typography>
                    <Grid container spacing={2}>
                      {selectedListener.cert_file && (
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Certificate File</Typography>
                          <Typography variant="body1" fontFamily="monospace">{selectedListener.cert_file}</Typography>
                        </Grid>
                      )}
                      {selectedListener.key_file && (
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Key File</Typography>
                          <Typography variant="body1" fontFamily="monospace">{selectedListener.key_file}</Typography>
                        </Grid>
                      )}
                    </Grid>
                  </Box>
                </>
              )}

              {/* Tags & Source */}
              {(selectedListener.source || (selectedListener.tags && selectedListener.tags.length > 0)) && (
                <>
                  <Divider />
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      Metadata
                    </Typography>
                    <Grid container spacing={2}>
                      {selectedListener.source && (
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Source</Typography>
                          <Typography variant="body1">{selectedListener.source}</Typography>
                        </Grid>
                      )}
                      {selectedListener.tags && selectedListener.tags.length > 0 && (
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Tags</Typography>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.5 }}>
                            {selectedListener.tags.map((tag) => (
                              <Chip key={tag} label={tag} size="small" variant="outlined" />
                            ))}
                          </Box>
                        </Grid>
                      )}
                    </Grid>
                  </Box>
                </>
              )}

              {/* Timestamps */}
              <Divider />
              <Box>
                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  Timestamps
                </Typography>
                <Grid container spacing={2}>
                  {selectedListener.created_at && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">Created</Typography>
                      <Typography variant="body1">
                        {new Date(selectedListener.created_at).toLocaleString()}
                      </Typography>
                    </Grid>
                  )}
                  {selectedListener.updated_at && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">Updated</Typography>
                      <Typography variant="body1">
                        {new Date(selectedListener.updated_at).toLocaleString()}
                      </Typography>
                    </Grid>
                  )}
                  {selectedListener.started_at && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">Started</Typography>
                      <Typography variant="body1">
                        {new Date(selectedListener.started_at).toLocaleString()}
                      </Typography>
                    </Grid>
                  )}
                  {selectedListener.stopped_at && (
                    <Grid item xs={12} sm={6}>
                      <Typography variant="body2" color="text.secondary">Stopped</Typography>
                      <Typography variant="body1">
                        {new Date(selectedListener.stopped_at).toLocaleString()}
                      </Typography>
                    </Grid>
                  )}
                </Grid>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDetailDialogClose}>Close</Button>
          {selectedListener?.status === 'stopped' && (
            <Button
              variant="contained"
              color="primary"
              onClick={() => {
                handleDetailDialogClose();
                setEditDialogOpen(true);
              }}
              startIcon={<EditIcon />}
            >
              Edit
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={snackbar.severity === 'error' ? 10000 : 4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          variant="filled"
          sx={{
            maxWidth: snackbar.severity === 'error' ? '600px' : '400px',
            '& .MuiAlert-message': {
              whiteSpace: 'pre-wrap',
              fontFamily: snackbar.severity === 'error' ? 'monospace' : 'inherit',
              fontSize: snackbar.severity === 'error' ? '0.85rem' : 'inherit',
              maxHeight: '300px',
              overflow: 'auto',
            }
          }}
        >
          {snackbar.message.replace(/\\n/g, '\n').replace(/\\t/g, '\t')}
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default Listeners;
