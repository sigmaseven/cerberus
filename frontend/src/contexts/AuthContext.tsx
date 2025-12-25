import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import type { CurrentUser, Permission } from '../utils/permissions';

/**
 * Authentication configuration and status
 * TASK 3.6: Extended with RBAC role and permissions support
 */
interface AuthConfig {
  authEnabled: boolean;
  isAuthenticated: boolean;
  username?: string;
  csrfToken?: string;
  loading: boolean;
  // TASK 3.6: RBAC fields
  roleName?: string | null;
  permissions?: Permission[];
  user?: CurrentUser;
}

interface AuthContextType extends AuthConfig {
  refreshAuth: () => Promise<void>;
  logout: () => void;
}

/**
 * PERFORMANCE OPTIMIZATION: Global auth context prevents duplicate API calls
 *
 * BEFORE: Every PrivateRoute component fetched /api/auth/config on every route change
 * AFTER: Single fetch on app startup, cached globally, refreshed only when needed
 *
 * Benefits:
 * - Reduces API calls from N (number of route changes) to 1
 * - Faster navigation (no auth check delay)
 * - Single source of truth for auth state
 */
const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  // TEMPORARY: Force auth bypass for development (remove this in production)
  const FORCE_AUTH_BYPASS = import.meta.env.DEV; // Only bypass in development mode

  const [authConfig, setAuthConfig] = useState<AuthConfig>({
    authEnabled: false,
    isAuthenticated: false,
    loading: true,
  });

  /**
   * Fetch authentication configuration and status
   * Only called on app startup and when explicitly refreshed
   */
  const fetchAuthConfig = async () => {
    try {
      // TEMPORARY: Force auth bypass for development
      if (FORCE_AUTH_BYPASS) {
        console.warn('[AuthContext] FORCE_AUTH_BYPASS enabled - skipping authentication');
        setAuthConfig({
          authEnabled: false,
          isAuthenticated: true,
          username: 'developer',
          loading: false,
        });
        return;
      }

      // Fetch auth config
      // NOTE: Do NOT add Cache-Control headers to request - these are response headers
      const configResponse = await fetch('/api/auth/config', {
        credentials: 'include', // Include cookies for auth
      });

      if (!configResponse.ok) {
        // If auth endpoint doesn't exist (404), assume auth is disabled
        if (configResponse.status === 404) {
          if (import.meta.env.DEV) {
            console.info('Auth endpoint not found - auth is disabled');
          }
          setAuthConfig({
            authEnabled: false,
            isAuthenticated: true,
            username: 'anonymous',
            loading: false,
          });
          return;
        }
        throw new Error(`Auth config request failed: ${configResponse.status}`);
      }

      const config = await configResponse.json();
      const authEnabled = config.authEnabled === true;

      // DEBUG: Log auth config for troubleshooting
      console.log('[AuthContext] Auth config received:', config, 'authEnabled:', authEnabled);

      // If auth is disabled, user is always authenticated
      if (!authEnabled) {
        console.log('[AuthContext] Auth is DISABLED - allowing access');
        setAuthConfig({
          authEnabled: false,
          isAuthenticated: true,
          username: 'anonymous',
          loading: false,
        });
        return;
      }

      // If auth is enabled, check authentication status
      const statusResponse = await fetch('/api/auth/status', {
        credentials: 'include', // Include httpOnly cookies
      });

      if (statusResponse.ok) {
        const status = await statusResponse.json();
        
        // TASK 3.6: Fetch current user info with role and permissions
        let userInfo: CurrentUser | undefined;
        let roleName: string | null = null;
        let permissions: Permission[] = [];

        if (status.authenticated && status.username) {
          try {
            const userResponse = await fetch('/api/v1/users/me', {
              credentials: 'include',
            });
            
            if (userResponse.ok) {
              userInfo = await userResponse.json();
              roleName = userInfo.role_name || null;
              permissions = userInfo.permissions || [];
            } else {
              // If user info fetch fails, still allow login but without permissions
              console.warn('Failed to fetch user info:', userResponse.status);
            }
          } catch (error) {
            // On error, continue without user info (degraded mode)
            console.error('Error fetching user info:', error);
          }
        }

        setAuthConfig({
          authEnabled: true,
          isAuthenticated: status.authenticated,
          username: status.username,
          csrfToken: status.csrf_token,
          roleName,
          permissions,
          user: userInfo,
          loading: false,
        });
      } else {
        setAuthConfig({
          authEnabled: true,
          isAuthenticated: false,
          loading: false,
        });
      }
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to fetch auth config:', error);
      }

      // FAIL OPEN: On error, assume auth is disabled (safe for dev, adjust for production)
      // This prevents the app from being completely broken if auth service is down
      setAuthConfig({
        authEnabled: false,
        isAuthenticated: true, // Allow access when auth service is unavailable
        username: 'anonymous',
        loading: false,
      });
    }
  };

  /**
   * Refresh authentication state
   * Call this after login/logout
   */
  const refreshAuth = async () => {
    setAuthConfig((prev) => ({ ...prev, loading: true }));
    await fetchAuthConfig();
  };

  /**
   * Logout and clear auth state
   * TASK 3.6: Also clear RBAC data
   */
  const logout = () => {
    setAuthConfig({
      authEnabled: authConfig.authEnabled,
      isAuthenticated: false,
      username: undefined,
      csrfToken: undefined,
      roleName: undefined,
      permissions: undefined,
      user: undefined,
      loading: false,
    });
  };

  // Fetch auth config on mount
  useEffect(() => {
    fetchAuthConfig();
  }, []);

  return (
    <AuthContext.Provider
      value={{
        ...authConfig,
        refreshAuth,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

/**
 * Hook to access auth context
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { authEnabled, isAuthenticated, username } = useAuth();
 *
 *   if (!authEnabled) {
 *     return <div>Auth is disabled</div>;
 *   }
 *
 *   return <div>Hello, {username}!</div>;
 * }
 * ```
 */
export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
