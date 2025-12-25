import { describe, it, expect, beforeEach } from 'vitest';
import { useUiStore } from './ui';

describe('UiStore', () => {
  beforeEach(() => {
    // Reset store to initial state
    useUiStore.setState({
      sidebarOpen: true,
      theme: 'dark',
      loading: false});
  });

  describe('initial state', () => {
    it('should have correct initial state', () => {
      const state = useUiStore.getState();

      expect(state.sidebarOpen).toBe(true);
      expect(state.theme).toBe('dark');
      expect(state.loading).toBe(false);
    });
  });

  describe('setSidebarOpen', () => {
    it('should set sidebar open state', () => {
      const { setSidebarOpen } = useUiStore.getState();

      setSidebarOpen(false);

      expect(useUiStore.getState().sidebarOpen).toBe(false);
    });

    it('should set sidebar closed state', () => {
      const { setSidebarOpen } = useUiStore.getState();

      // First close it
      setSidebarOpen(false);
      expect(useUiStore.getState().sidebarOpen).toBe(false);

      // Then open it
      setSidebarOpen(true);
      expect(useUiStore.getState().sidebarOpen).toBe(true);
    });
  });

  describe('setTheme', () => {
    it('should set theme to light', () => {
      const { setTheme } = useUiStore.getState();

      setTheme('light');

      expect(useUiStore.getState().theme).toBe('light');
    });

    it('should set theme to dark', () => {
      const { setTheme } = useUiStore.getState();

      // First set to light
      setTheme('light');
      expect(useUiStore.getState().theme).toBe('light');

      // Then set to dark
      setTheme('dark');
      expect(useUiStore.getState().theme).toBe('dark');
    });
  });

  describe('setLoading', () => {
    it('should set loading to true', () => {
      const { setLoading } = useUiStore.getState();

      setLoading(true);

      expect(useUiStore.getState().loading).toBe(true);
    });

    it('should set loading to false', () => {
      const { setLoading } = useUiStore.getState();

      // First set to true
      setLoading(true);
      expect(useUiStore.getState().loading).toBe(true);

      // Then set to false
      setLoading(false);
      expect(useUiStore.getState().loading).toBe(false);
    });
  });

  describe('state isolation', () => {
    it('should maintain state isolation between different state slices', () => {
      const { setSidebarOpen, setTheme, setLoading } = useUiStore.getState();

      setSidebarOpen(false);
      setTheme('light');
      setLoading(true);

      const state = useUiStore.getState();

      expect(state.sidebarOpen).toBe(false);
      expect(state.theme).toBe('light');
      expect(state.loading).toBe(true);
    });
  });
});