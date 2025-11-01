import { renderHook, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { useFetch } from './useFetch';

describe('useFetch', () => {
  it('fetches data successfully', async () => {
    const mockData = { message: 'success' };
    const fetchFn = vi.fn().mockResolvedValue(mockData);

    const { result } = renderHook(() => useFetch(fetchFn));

    expect(result.current.loading).toBe(true);
    expect(result.current.data).toBe(null);
    expect(result.current.error).toBe(null);

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toEqual(mockData);
      expect(result.current.error).toBe(null);
    });
  });

  it('handles error', async () => {
    const errorMessage = 'Network error';
    const fetchFn = vi.fn().mockRejectedValue(new Error(errorMessage));

    const { result } = renderHook(() => useFetch(fetchFn));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toBe(null);
      expect(result.current.error).toBe(errorMessage);
    });
  });

  it('ignores AbortError', async () => {
    const abortError = new Error('Aborted');
    abortError.name = 'AbortError';
    const fetchFn = vi.fn().mockRejectedValue(abortError);

    const { result } = renderHook(() => useFetch(fetchFn));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toBe(null);
      expect(result.current.error).toBe(null); // Should not set error for abort
    });
  });

  it('handles non-Error rejection', async () => {
    const fetchFn = vi.fn().mockRejectedValue('string error');

    const { result } = renderHook(() => useFetch(fetchFn));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toBe(null);
      expect(result.current.error).toBe('An error occurred');
    });
  });
});