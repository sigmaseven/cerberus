import { AxiosInstance } from 'axios';
import { PLAYWRIGHT_BACKEND_URL } from '../config/ports';
import errorReportingService from './errorReporting';
import { useAuthStore } from '../stores/auth';

export class RequestInterceptors {
  static setupEnvironmentConfig(api: AxiosInstance): void {
    // Request interceptor for environment-specific configuration
    api.interceptors.request.use(
      (config) => {
        // Use environment variable for Playwright test configuration instead of runtime detection
        const playwrightBackendUrl = import.meta.env.VITE_PLAYWRIGHT_BACKEND_URL;

        // For Playwright tests, use full URL from environment variable
        if (playwrightBackendUrl && config.url && !config.url.startsWith('http')) {
          const baseURL = config.baseURL || '';
          config.url = `${playwrightBackendUrl}${baseURL}${config.url}`;
        }

        return config;
      },
      (error) => Promise.reject(error)
    );
  }

  static setupCSRFProtection(api: AxiosInstance, getCSRFToken: () => string | null): void {
    // Request interceptor for authentication and CSRF protection
    // Note: Authentication is now handled via httpOnly cookies automatically sent by browser
    api.interceptors.request.use(
      (config) => {
        // For state-changing requests, include CSRF token only if available
        // When auth is disabled, backend returns empty CSRF token and we shouldn't send the header
        if (config.method && ['post', 'put', 'delete', 'patch'].includes(config.method.toLowerCase())) {
          const csrfToken = getCSRFToken();
          // Only add header if token exists and is non-empty
          if (csrfToken && csrfToken.trim().length > 0) {
            config.headers['X-CSRF-Token'] = csrfToken;
          }
        }
        return config;
      },
      (error) => Promise.reject(error)
    );
  }
}

export class ResponseInterceptors {
  static setupCSRFTokenRotation(
    api: AxiosInstance,
    isCSRFError: (error: any) => boolean,
    refreshCSRFToken: () => Promise<string | null>,
    isValidCSRFToken: (token: string) => boolean
  ): void {
    // Response interceptor to handle CSRF token rotation with enhanced security
    api.interceptors.response.use(
      (response) => response,
      async (error) => {
        // ENHANCED: Only retry on specific CSRF validation failures, not all 403 errors
        if (isCSRFError(error)) {
          // SECURITY: Log CSRF validation failure for monitoring
          errorReportingService.reportError({
            type: 'validation_error',
            message: 'CSRF token validation failed, refreshing token',
            additionalData: { url: error.config?.url }
          });

          // SECURITY: Limit retry attempts to prevent abuse
          const originalRequest = error.config;
            if (originalRequest._csrfRetryCount >= 1) {
              errorReportingService.reportError({
                type: 'validation_error',
                message: 'CSRF token refresh retry limit exceeded',
                additionalData: { retryCount: originalRequest._csrfRetryCount, url: error.config?.url }
              });
              return Promise.reject(error);
            }

          // Try to refresh the CSRF token
          const newToken = await refreshCSRFToken();
          if (newToken && isValidCSRFToken(newToken)) {
            // SECURITY: Mark request as retried to prevent infinite loops
            originalRequest._csrfRetryCount = (originalRequest._csrfRetryCount || 0) + 1;
            originalRequest.headers['X-CSRF-Token'] = newToken;

            // SECURITY: Add small delay to prevent rapid retry attacks
            await new Promise(resolve => setTimeout(resolve, 100));

            return api(originalRequest);
          } else {
            errorReportingService.reportError({
              type: 'validation_error',
              message: 'Failed to obtain valid CSRF token after refresh',
              additionalData: { url: error.config?.url }
            });
          }
        }
        return Promise.reject(error);
      }
    );
  }

  static setupErrorHandling(
    api: AxiosInstance,
    reportError: (errorDetails: Record<string, unknown>) => void,
    getUserFriendlyMessage: (error: Record<string, unknown>) => string,
    generateCorrelationId: () => string
  ): void {
    // Response interceptor for error handling
    api.interceptors.response.use(
      (response) => response,
      async (error) => {
        // Enhanced error logging and handling
        const errorDetails = {
          url: error.config?.url,
          method: error.config?.method?.toUpperCase(),
          status: error.response?.status,
          statusText: error.response?.statusText,
          data: error.response?.data,
          message: error.message,
          timestamp: new Date().toISOString(),
          userAgent: navigator.userAgent,
          correlationId: generateCorrelationId(),
        };

        // Handle specific error types and report all errors consistently
        // TASK 3.6: Handle 403 Forbidden (insufficient permissions)
        if (error.response?.status === 403) {
          reportError({
            ...errorDetails,
            type: 'authorization_error',
            message: error.response?.data?.error || 'Insufficient permissions to perform this action',
          });
        } else if (error.response?.status === 401) {
          // FIXED: Check if auth is actually enabled before redirecting
          // Don't redirect on 401 if the error is from /auth/config check
          const isAuthConfigCheck = error.config?.url?.includes('/auth/config');

          if (!isAuthConfigCheck) {
            // Check current auth state - if user is authenticated (which means auth is disabled), don't redirect
            const authState = useAuthStore.getState();

            // Only redirect if auth is actually being enforced
            // If isAuthenticated is true and we get 401, it means auth is disabled but backend endpoint needs fixing
            if (!authState.isAuthenticated) {
              // Handle unauthorized access - report to error service and redirect
              reportError({
                ...errorDetails,
                type: 'authentication_error',
                message: 'Unauthorized access detected',
              });
              // Clear auth state in Zustand store
              useAuthStore.setState({ isAuthenticated: false, username: null });
              window.location.href = '/login';
            } else {
              // Auth is disabled but we got a 401 - log it but don't redirect
              reportError({
                ...errorDetails,
                type: 'api_error',
                message: '401 error but auth is disabled - backend endpoint may need configuration',
              });
            }
          }
        } else if (error.response?.status >= 500) {
          // Server errors - report to error service
          reportError({
            ...errorDetails,
            type: 'server_error',
            message: 'Server error detected',
          });
        } else if (error.code === 'NETWORK_ERROR' || error.code === 'ECONNABORTED') {
          // Network errors - report to error service
          reportError({
            ...errorDetails,
            type: 'network_error',
            message: 'Network connection failed. Please check your internet connection.',
          });
        } else {
          // Other client errors (4xx) - report to error service with full details
          reportError({
            ...errorDetails,
            type: 'client_error',
            message: `Client error occurred: ${errorDetails.status} ${errorDetails.statusText}`,
          });

          // Log full error details to console in development
          if (import.meta.env.DEV) {
            console.error('API Error Details:', {
              status: errorDetails.status,
              statusText: errorDetails.statusText,
              url: errorDetails.url,
              method: errorDetails.method,
              data: errorDetails.data,
              message: errorDetails.message,
            });
          }
        }

        // Enhance error object with additional context
        const enhancedError = {
          ...error,
          correlationId: errorDetails.correlationId,
          userMessage: getUserFriendlyMessage(error),
          technicalDetails: errorDetails,
        };

        return Promise.reject(enhancedError);
      }
    );
  }
}