import { useState, useEffect, useRef } from 'react';
import { notifications } from '@mantine/notifications';

/**
 * Custom hook for fetching data with loading and error states
 * @param fetchFn - Function that returns a promise, accepts AbortSignal
 * @param deps - Dependencies array for re-fetching
 * @returns Object with data, loading, error
 */
export const useFetch = <T>(fetchFn: (signal?: AbortSignal) => Promise<T>, deps: readonly unknown[] = []) => {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    // Abort previous request
    abortControllerRef.current?.abort();

    const controller = new AbortController();
    abortControllerRef.current = controller;

    const fetchData = async () => {
      try {
        setLoading(true);
        const result = await fetchFn(controller.signal);
        setData(result);
        setError(null);
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') {
          return; // Ignore abort errors
        }
        setError(err instanceof Error ? err.message : 'An error occurred');
        notifications.show({
          title: 'Error',
          message: 'Failed to load data',
          color: 'red',
        });
      } finally {
        setLoading(false);
        abortControllerRef.current = null;
      }
    };

    fetchData();

    // Cleanup on unmount or deps change
    return () => {
      controller.abort();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, loading, error };
};