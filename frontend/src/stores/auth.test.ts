import { describe, it, expect, beforeEach } from 'vitest';
import { useAuthStore } from './auth';

describe('AuthStore', () => {
  beforeEach(() => {
    // Reset store state
    useAuthStore.setState({
      token: null,
      isAuthenticated: false});
  });

  describe('initial state', () => {
    it('should have correct initial state', () => {
      const state = useAuthStore.getState();

      expect(state.token).toBeNull();
      expect(state.isAuthenticated).toBe(false);
    });
  });

  describe('login', () => {
    it('should set token and authentication state', () => {
      const { login } = useAuthStore.getState();

      login('test-token');

      const state = useAuthStore.getState();
      expect(state.token).toBe('test-token');
      expect(state.isAuthenticated).toBe(true);
    });
  });

  describe('logout', () => {
    it('should clear token and authentication state', () => {
      const { login, logout } = useAuthStore.getState();

      // First login
      login('test-token');
      expect(useAuthStore.getState().isAuthenticated).toBe(true);

      // Then logout
      logout();

      const state = useAuthStore.getState();
      expect(state.token).toBeNull();
      expect(state.isAuthenticated).toBe(false);
    });
  });

  describe('state management', () => {
    it('should maintain state consistency', () => {
      const { login, logout } = useAuthStore.getState();

      // Login
      login('token1');
      expect(useAuthStore.getState().token).toBe('token1');
      expect(useAuthStore.getState().isAuthenticated).toBe(true);

      // Login with different token
      login('token2');
      expect(useAuthStore.getState().token).toBe('token2');
      expect(useAuthStore.getState().isAuthenticated).toBe(true);

      // Logout
      logout();
      expect(useAuthStore.getState().token).toBeNull();
      expect(useAuthStore.getState().isAuthenticated).toBe(false);
    });
  });
});