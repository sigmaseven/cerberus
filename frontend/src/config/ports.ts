/**
 * CENTRALIZED PORT CONFIGURATION
 *
 * ALL port references in the codebase MUST use these constants.
 * DO NOT hardcode port numbers anywhere else.
 *
 * If you need to change a port, change it here and ONLY here.
 */

/**
 * Backend API server port
 * This is where the Go backend runs
 */
export const BACKEND_PORT = 8080;

/**
 * Frontend development server port
 * This is where Vite dev server runs
 */
export const FRONTEND_DEV_PORT = 3001;

/**
 * Backend API base URL for different environments
 */
export const getBackendUrl = (): string => {
  // Check if we're in a browser environment
  if (typeof window === 'undefined') {
    return `http://localhost:${BACKEND_PORT}`;
  }

  // In development with Vite proxy, use relative URLs
  if (import.meta.env.DEV) {
    return ''; // Proxy handles this
  }

  // In production or explicit override
  return import.meta.env.VITE_API_BASE_URL || `http://localhost:${BACKEND_PORT}`;
};

/**
 * WebSocket URL for backend
 */
export const getWebSocketUrl = (): string => {
  const baseUrl = import.meta.env.VITE_API_BASE_URL || `http://localhost:${BACKEND_PORT}`;
  const wsUrl = baseUrl.replace(/^http/, 'ws');
  return `${wsUrl}/ws`;
};

/**
 * Feature flags for conditionally enabling/disabling features
 */
// Helper to parse boolean environment variables
const getEnvBoolean = (value: string | undefined, defaultValue: boolean): boolean => {
  if (value === undefined) return defaultValue;
  return value.toLowerCase() === 'true';
};

export const FEATURES = {
  WEBSOCKET: getEnvBoolean(import.meta.env.VITE_ENABLE_WEBSOCKET, false),
  ML_ANALYTICS: getEnvBoolean(import.meta.env.VITE_ENABLE_ML_ANALYTICS, true), // Default enabled
} as const;

/**
 * Playwright test configuration
 * Uses environment variable for build-time configuration instead of runtime detection
 */
export const PLAYWRIGHT_BACKEND_URL = import.meta.env.VITE_PLAYWRIGHT_BACKEND_URL || `http://localhost:${BACKEND_PORT}`;
export const PLAYWRIGHT_FRONTEND_URL = `http://localhost:${FRONTEND_DEV_PORT}`;
