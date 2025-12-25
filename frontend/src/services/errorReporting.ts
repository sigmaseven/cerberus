interface ErrorReport {
  correlationId: string;
  timestamp: string;
  type: 'api_error' | 'react_error' | 'network_error' | 'validation_error' | 'unknown_error';
  message: string;
  stack?: string;
  componentStack?: string;
  url?: string;
  userAgent?: string;
  userId?: string;
  additionalData?: Record<string, unknown>;
}

interface ErrorReportingConfig {
  enabled: boolean;
  endpoint?: string;
  apiKey?: string;
  environment: 'development' | 'staging' | 'production';
  sampleRate: number; // 0.0 to 1.0 - percentage of errors to report
}

class ErrorReportingService {
  private config: ErrorReportingConfig;
  private errorQueue: ErrorReport[] = [];
  private isReporting = false;

  constructor() {
    this.config = {
      enabled: import.meta.env.PROD,
      environment: (import.meta.env.MODE as 'development' | 'staging' | 'production') || 'development',
      sampleRate: import.meta.env.PROD ? 1.0 : 0.1, // Report 100% in prod, 10% in dev
    };

    // Flush errors periodically
    setInterval(() => this.flushErrors(), 30000); // Every 30 seconds
  }

  // Configure the error reporting service
  configure(config: Partial<ErrorReportingConfig>) {
    this.config = { ...this.config, ...config };
  }

  // Report an error
  reportError(error: ErrorReport): void {
    // Check if we should sample this error
    if (Math.random() > this.config.sampleRate) {
      return;
    }

    // Add environment and user context
    const enrichedError: ErrorReport = {
      ...error,
      userId: this.getUserId(),
      url: error.url || window.location.href,
      userAgent: error.userAgent || navigator.userAgent,
      additionalData: {
        ...error.additionalData,
        environment: this.config.environment,
        viewport: `${window.innerWidth}x${window.innerHeight}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      },
    };

    // Add to queue
    this.errorQueue.push(enrichedError);

    // Log to console in development
    if (import.meta.env.DEV) {
      console.error('[Error Report]', enrichedError);
    }

    // Send immediately if critical error
    if (this.isCriticalError(enrichedError)) {
      this.flushErrors();
    }
  }

  // Report API errors
  reportApiError(error: Record<string, unknown>, additionalData?: Record<string, string | number | undefined>): void {
    const errorReport: ErrorReport = {
      correlationId: (error.correlationId as string) || this.generateCorrelationId(),
      timestamp: new Date().toISOString(),
      type: 'api_error',
      message: (error.message as string) || 'API Error',
      stack: error.stack as string | undefined,
      url: (error as { config?: { url?: string } }).config?.url,
      additionalData: {
        ...additionalData,
        status: (error as { response?: { status?: number } }).response?.status,
        statusText: (error as { response?: { statusText?: string } }).response?.statusText,
        method: (error as { config?: { method?: string } }).config?.method,
        endpoint: (error as { config?: { url?: string } }).config?.url,
        responseData: (error as { response?: { data?: unknown } }).response?.data,
      },
    };

    this.reportError(errorReport);
  }

  // Report React errors
  reportReactError(error: Error, errorInfo: { componentStack?: string }, additionalData?: Record<string, unknown>): void {
    const errorReport: ErrorReport = {
      correlationId: this.generateCorrelationId(),
      timestamp: new Date().toISOString(),
      type: 'react_error',
      message: error.message,
      stack: error.stack,
      componentStack: errorInfo?.componentStack,
      additionalData,
    };

    this.reportError(errorReport);
  }

  // Report network errors
  reportNetworkError(error: Record<string, unknown>, additionalData?: Record<string, string | number | undefined>): void {
    const errorReport: ErrorReport = {
      correlationId: this.generateCorrelationId(),
      timestamp: new Date().toISOString(),
      type: 'network_error',
      message: (error.message as string) || 'Network Error',
      stack: error.stack as string | undefined,
      additionalData: {
        ...additionalData,
        code: error.code as string | undefined,
        errno: error.errno as number | undefined,
        syscall: error.syscall as string | undefined,
      },
    };

    this.reportError(errorReport);
  }

  // Report validation errors
  reportValidationError(message: string, additionalData?: Record<string, unknown>): void {
    const errorReport: ErrorReport = {
      correlationId: this.generateCorrelationId(),
      timestamp: new Date().toISOString(),
      type: 'validation_error',
      message,
      additionalData,
    };

    this.reportError(errorReport);
  }

  // Flush queued errors to the reporting endpoint
  private async flushErrors(): Promise<void> {
    if (!this.config.enabled || this.errorQueue.length === 0 || this.isReporting) {
      return;
    }

    this.isReporting = true;
    const errorsToSend = [...this.errorQueue];
    this.errorQueue = [];

    try {
      if (this.config.endpoint) {
        // Send to external error reporting service
        await fetch(this.config.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(this.config.apiKey && { 'Authorization': `Bearer ${this.config.apiKey}` }),
          },
          body: JSON.stringify({
            errors: errorsToSend,
            clientVersion: import.meta.env.VITE_APP_VERSION || '1.0.0',
          }),
        });
      } else {
        // Fallback: store in localStorage for debugging
        try {
          const existingErrors = JSON.parse(localStorage.getItem('errorReports') || '[]');
          const updatedErrors = [...existingErrors, ...errorsToSend].slice(-100); // Keep last 100 errors
          localStorage.setItem('errorReports', JSON.stringify(updatedErrors));
        } catch (storageError) {
          if (import.meta.env.DEV) {
            console.error('Failed to store errors in localStorage:', storageError);
          }
        }
      }
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to send error reports:', error);
      }
      // Re-queue errors for next attempt
      this.errorQueue.unshift(...errorsToSend);
    } finally {
      this.isReporting = false;
    }
  }

  // Get stored error reports (for debugging)
  getStoredErrorReports(): ErrorReport[] {
    try {
      return JSON.parse(localStorage.getItem('errorReports') || '[]');
    } catch {
      return [];
    }
  }

  // Clear stored error reports
  clearStoredErrorReports(): void {
    try {
      localStorage.removeItem('errorReports');
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to clear error reports from localStorage:', error);
      }
    }
  }

  // Generate correlation ID
  private generateCorrelationId(): string {
    return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Get user ID (if available) - REMOVED for security reasons
  // Previously attempted to decode JWT tokens which created security vulnerabilities
  private getUserId(): string | undefined {
    // Return undefined to avoid security risks associated with JWT decoding
    // User context can be obtained server-side from authenticated requests
    return undefined;
  }

  // Determine if an error is critical
  private isCriticalError(error: ErrorReport): boolean {
    // Consider React errors and 5xx API errors as critical
    return error.type === 'react_error' ||
           (error.type === 'api_error' && error.additionalData?.status >= 500);
  }
}

// Create singleton instance
export const errorReportingService = new ErrorReportingService();
export { ErrorReportingService };
export default errorReportingService;