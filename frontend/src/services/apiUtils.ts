import errorReportingService from './errorReporting';

export class CSRFUtils {
  static getCSRFToken(): string | null {
    // Get CSRF token from cookie with enhanced validation
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrf_token') {
        const token = decodeURIComponent(value);
        // Empty token means auth is disabled - this is valid, just don't use CSRF
        if (token === '' || token.trim().length === 0) {
          return null;
        }
        // ENHANCED: Validate token format and expiration
        if (this.isValidCSRFToken(token) && !this.isCSRFTokenExpired()) {
          // Update timestamp if we have a valid token (ensures timestamp stays current)
          // Using sessionStorage instead of localStorage for better security (cleared on session end)
          sessionStorage.setItem('csrf_token_timestamp', Date.now().toString());
          return token;
        } else {
          // Invalid or expired CSRF token detected, clearing it
          this.clearCSRFToken();
          return null;
        }
      }
    }
    return null;
  }

  static isValidCSRFToken(token: string): boolean {
    // ENHANCED: Strict validation for hex-encoded 32-byte tokens
    if (!token || token.length !== 64) {
      return false;
    }

    // Must contain only valid hexadecimal characters
    const hexRegex = /^[0-9a-fA-F]+$/;
    if (!hexRegex.test(token)) {
      return false;
    }

    // Must not be all zeros (weak token protection)
    if (token.replace(/0/g, '') === '') {
      return false;
    }

    // Must have good entropy distribution (not all same character)
    const uniqueChars = new Set(token.split(''));
    if (uniqueChars.size < 8) {
      return false;
    }

    return true;
  }

  static isCSRFTokenExpired(): boolean {
    // Check if CSRF token is close to expiration
    // CSRF tokens expire at the same time as auth tokens (1 hour by default)
    const tokenSetTime = sessionStorage.getItem('csrf_token_timestamp');
    if (!tokenSetTime) {
      return true; // No timestamp means token is invalid
    }

    const setTime = parseInt(tokenSetTime, 10);
    const now = Date.now();
    const expiryBuffer = 5 * 60 * 1000; // 5 minutes buffer before actual expiration
    const tokenLifetime = 60 * 60 * 1000; // 1 hour default (should match server config)

    // Check if token is expired or will expire soon
    return (now - setTime) > (tokenLifetime - expiryBuffer);
  }

  static clearCSRFToken(): void {
    // Clear expired or invalid CSRF token
    document.cookie = 'csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/;';
  }

  static isCSRFError(error: unknown): boolean {
    if (typeof error !== 'object' || error === null) {
      return false;
    }
    const err = error as { response?: { status?: number; data?: { error?: string; message?: string } } };
    return err.response?.status === 403 &&
      (err.response?.data?.error?.includes('CSRF') ||
       err.response?.data?.message?.includes('CSRF'));
  }
}

export class ErrorUtils {
  static generateCorrelationId(): string {
    return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  static reportError(errorDetails: Record<string, unknown>): void {
    // Use the error reporting service
    errorReportingService.reportApiError(errorDetails, {
      status: errorDetails.status as number | undefined,
      method: errorDetails.method as string | undefined,
      url: errorDetails.url as string | undefined,
    });
  }

  static getUserFriendlyMessage(error: unknown): string {
    // Type guard to safely access error properties
    if (typeof error !== 'object' || error === null) {
      return 'An unexpected error occurred. Please try again.';
    }

    const err = error as { response?: { status?: number }; code?: string };
    const status = err.response?.status;
    const code = err.code;

    // Check status safely
    if (typeof status === 'number') {
      if (status === 400) {
        return 'Invalid request. Please check your input and try again.';
      } else if (status === 401) {
        return 'Authentication required. Please log in again.';
      } else if (status === 403) {
        return 'Access denied. You do not have permission to perform this action.';
      } else if (status === 404) {
        return 'The requested resource was not found.';
      } else if (status === 409) {
        return 'A conflict occurred. The resource may already exist.';
      } else if (status >= 500) {
        return 'A server error occurred. Please try again later.';
      }
    }

    // Check error code safely
    if (typeof code === 'string') {
      if (code === 'NETWORK_ERROR') {
        return 'Network connection failed. Please check your internet connection.';
      } else if (code === 'ECONNABORTED') {
        return 'Request timed out. Please try again.';
      }
    }

    return 'An unexpected error occurred. Please try again.';
  }
}

interface ApiInstance {
  get<T = unknown>(url: string): Promise<{ data: T }>;
}

export class CSRFRefreshManager {
  private lastCSRFRefresh: number | null = null;
  private csrfRefreshPromise: Promise<string | null> | null = null;

  async refreshCSRFToken(api: ApiInstance): Promise<string | null> {
    if (this.csrfRefreshPromise) {
      return this.csrfRefreshPromise;
    }

    this.csrfRefreshPromise = this.performCSRFRefresh(api);
    const result = await this.csrfRefreshPromise;
    this.csrfRefreshPromise = null;
    return result;
  }

  private async performCSRFRefresh(api: ApiInstance): Promise<string | null> {
    try {
      // SECURITY: Rate limit token refresh attempts
      const now = Date.now();
      if (this.lastCSRFRefresh && (now - this.lastCSRFRefresh) < 1000) {
        errorReportingService.reportError({
          type: 'validation_error',
          message: 'CSRF token refresh rate limited',
          additionalData: { timeSinceLastRefresh: now - this.lastCSRFRefresh }
        });
        return null;
      }
      this.lastCSRFRefresh = now;

      // SECURITY: Use auth status endpoint which includes CSRF token
      // This ensures only authenticated users can refresh tokens and reduces requests
      const response = await api.get('/auth/status');

      // SECURITY: Validate response contains expected data
      if (response.data && response.data.csrf_token && response.data.authenticated) {
        const newToken = response.data.csrf_token;

        // SECURITY: Validate the new token format before accepting it
        if (CSRFUtils.isValidCSRFToken(newToken)) {
          // SECURITY: Clear any cached invalid tokens
          CSRFUtils.clearCSRFToken();

          // Wait for cookie to be set by browser (if needed)
          await new Promise(resolve => setTimeout(resolve, 10));

          // Return the validated token from cookies (not response) for consistency
          return CSRFUtils.getCSRFToken();
        } else {
          errorReportingService.reportError({
            type: 'validation_error',
            message: 'Received invalid CSRF token from server',
            additionalData: { tokenLength: newToken?.length }
          });
          return null;
        }
      } else {
        errorReportingService.reportError({
          type: 'api_error',
          message: 'CSRF token refresh response missing token or authentication failed',
          additionalData: { responseData: response.data }
        });
        return null;
      }
    } catch (error) {
      errorReportingService.reportError({
        type: 'network_error',
        message: 'CSRF token refresh failed',
        additionalData: { error: error instanceof Error ? error.message : String(error) }
      });
      return null;
    }
  }
}