import { useCallback, useRef, useEffect } from 'react';
import { notifications } from '@mantine/notifications';

export const useApiCall = <T>(
  apiFunc: () => Promise<T>,
  onSuccess: (data: T) => void,
  errorMessage: string = 'Failed to load data'
) => {
  const mountedRef = useRef(true);
  const errorCountRef = useRef(0);

  const call = useCallback(async () => {
    try {
      const data = await apiFunc();
      if (mountedRef.current) {
        onSuccess(data);
      }
      errorCountRef.current = 0; // Reset on success
    } catch (error) {
      errorCountRef.current++;
      if (mountedRef.current) {
        notifications.show({
          title: 'Error',
          message: `${errorMessage}: ${(error as Error).message}`,
          color: 'red',
        });
      }
    }
  }, [apiFunc, onSuccess, errorMessage]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  return call;
};