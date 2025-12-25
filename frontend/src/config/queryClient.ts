import { QueryClient, QueryCache, MutationCache, DefaultOptions } from '@tanstack/react-query';
import errorReportingService from '../services/errorReporting';

/**
 * Global error handler for React Query
 */
function handleQueryError(error: unknown) {
  // Filter out Zod internal errors that are not actionable
  // These occur when backend returns unexpected responses (404, 500, etc)
  const errorMessage = error instanceof Error ? error.message : String(error);
  const isZodInternalError = errorMessage.includes("Cannot read properties of undefined (reading '_zod')");

  // Don't log Zod internal errors to console as they're noise
  if (!isZodInternalError) {
    console.error('Query error:', error);
  } else if (import.meta.env.DEV) {
    // Log a cleaner message in development
    console.warn('API validation error: Backend returned unexpected response format');
  }

  // Report to error monitoring service (but not Zod internal errors)
  if (error instanceof Error && !isZodInternalError) {
    errorReportingService.reportApiError({
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
    }, {
      status: (error as { response?: { status?: number } }).response?.status,
    });
  }

  // In production, you might want to show a toast notification here
  if (import.meta.env.PROD) {
    // Example: toast.error('Failed to fetch data. Please try again.');
  }
}

/**
 * Global error handler for React Query mutations
 */
function handleMutationError(error: unknown) {
  console.error('Mutation error:', error);

  // Report to error monitoring service
  if (error instanceof Error) {
    errorReportingService.reportApiError({
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      type: 'mutation',
    }, {
      status: (error as { response?: { status?: number } }).response?.status,
    });
  }

  // In production, you might want to show a toast notification here
  if (import.meta.env.PROD) {
    // Example: toast.error('Operation failed. Please try again.');
  }
}

/**
 * Default options for React Query
 *
 * PERFORMANCE:
 * - Stale time: 5 minutes (reduces unnecessary refetches)
 * - Cache time: 10 minutes (keeps data in cache)
 * - Retry: 1 attempt (reduces wait time on persistent failures)
 *
 * UX:
 * - Refetch on window focus: false (prevents jarring updates)
 * - Refetch on reconnect: true (ensures data freshness after network issues)
 *
 * ERROR HANDLING:
 * - Global error handlers for queries and mutations
 * - Error reporting to monitoring service
 */
const defaultOptions: DefaultOptions = {
  queries: {
    // Retry configuration
    retry: 1, // Only retry once to avoid long delays
    retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),

    // Refetch configuration
    refetchOnWindowFocus: false, // Disable to prevent jarring updates
    refetchOnReconnect: true, // Re-fetch when network reconnects
    refetchOnMount: true, // Re-fetch when component mounts

    // Stale and cache time
    staleTime: 5 * 60 * 1000, // 5 minutes - data is considered fresh
    gcTime: 10 * 60 * 1000, // 10 minutes - cache garbage collection time

    // Error handling
    throwOnError: false, // Don't throw errors, handle them gracefully
  },

  mutations: {
    // Retry configuration (typically don't retry mutations)
    retry: 0, // Don't retry mutations by default

    // Error handling
    throwOnError: false, // Don't throw errors, handle them gracefully
  },
};

/**
 * Global React Query client instance
 *
 * Import this in your app's root component and wrap with QueryClientProvider
 *
 * @example
 * ```tsx
 * import { QueryClientProvider } from '@tanstack/react-query';
 * import { queryClient } from './config/queryClient';
 *
 * function App() {
 *   return (
 *     <QueryClientProvider client={queryClient}>
 *       <YourApp />
 *     </QueryClientProvider>
 *   );
 * }
 * ```
 */
export const queryClient = new QueryClient({
  defaultOptions,
  queryCache: new QueryCache({
    onError: handleQueryError,
  }),
  mutationCache: new MutationCache({
    onError: handleMutationError,
  }),
});

/**
 * Helper function to invalidate queries by key pattern
 *
 * @example
 * ```tsx
 * // Invalidate all events queries
 * invalidateQueries('events');
 *
 * // Invalidate specific event query
 * invalidateQueries(['events', eventId]);
 * ```
 */
export function invalidateQueries(queryKey: string | string[]) {
  const keyArray = Array.isArray(queryKey) ? queryKey : [queryKey];
  return queryClient.invalidateQueries({ queryKey: keyArray });
}

/**
 * Helper function to reset all queries and clear cache
 * Useful for logout or when switching users
 */
export function resetQueryCache() {
  return queryClient.clear();
}

/**
 * Prefetch helper for improved performance
 *
 * @example
 * ```tsx
 * // Prefetch events on hover
 * onMouseEnter={() => prefetchQuery('events', fetchEvents)}
 * ```
 */
export async function prefetchQuery<T>(
  queryKey: string | string[],
  queryFn: () => Promise<T>
) {
  const keyArray = Array.isArray(queryKey) ? queryKey : [queryKey];
  return queryClient.prefetchQuery({
    queryKey: keyArray,
    queryFn,
  });
}
