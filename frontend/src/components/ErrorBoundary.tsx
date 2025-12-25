import React, { Component, ErrorInfo, ReactNode } from 'react';
import errorReportingService from '../services/errorReporting';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
  errorInfo?: ErrorInfo;
  correlationId?: string;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    // Update state so the next render will show the fallback UI
    return {
      hasError: true,
      error,
      correlationId: `boundary_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log the error details
    const errorDetails = {
      correlationId: this.state.correlationId,
      error: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href,
    };

    if (import.meta.env.DEV) {
      console.error('[React Error Boundary]', errorDetails);
    }

    // Report to error monitoring service (if available)
    // This could integrate with services like Sentry, LogRocket, etc.
    this.reportError(errorDetails);

    this.setState({
      error,
      errorInfo,
    });
  }

  private reportError = (errorDetails: {
    correlationId: string;
    error: Error;
    componentStack: string;
    timestamp: string;
    url: string;
    userAgent: string;
  }) => {
    // Use the error reporting service
    errorReportingService.reportReactError(errorDetails.error, {
      componentStack: errorDetails.componentStack,
    }, {
      correlationId: errorDetails.correlationId,
      url: errorDetails.url,
      timestamp: errorDetails.timestamp,
    });
  };

  private handleRetry = () => {
    this.setState({ hasError: false, error: undefined, errorInfo: undefined });
  };

  private handleReportIssue = () => {
    // Create a GitHub issue or send error report
    const errorReport = {
      title: 'Application Error Report',
      correlationId: this.state.correlationId,
      error: this.state.error?.message,
      url: window.location.href,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
    };

    const issueBody = `
## Error Report

**Correlation ID:** ${errorReport.correlationId}
**Timestamp:** ${errorReport.timestamp}
**URL:** ${errorReport.url}
**User Agent:** ${errorReport.userAgent}

**Error Message:**
\`\`\`
${this.state.error?.message}
\`\`\`

**Stack Trace:**
\`\`\`
${this.state.error?.stack}
\`\`\`

**Component Stack:**
\`\`\`
${this.state.errorInfo?.componentStack}
\`\`\`
    `.trim();

    // Open GitHub issue with configurable repo URL
    const repoUrl = import.meta.env.VITE_GITHUB_REPO_URL || 'https://github.com/your-org/cerberus';
    const githubUrl = `${repoUrl}/issues/new?title=${encodeURIComponent(errorReport.title)}&body=${encodeURIComponent(issueBody)}`;
    window.open(githubUrl, '_blank');
  };

  render() {
    if (this.state.hasError) {
      // Custom fallback UI
      if (this.props.fallback) {
        return this.props.fallback;
      }

      // Default error UI
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
          <div className="max-w-md w-full space-y-8">
            <div className="text-center">
              <div className="mx-auto h-12 w-12 text-red-500">
                <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
                  />
                </svg>
              </div>
              <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
                Something went wrong
              </h2>
              <p className="mt-2 text-center text-sm text-gray-600">
                An unexpected error occurred. Our team has been notified.
              </p>
              {this.state.correlationId && (
                <p className="mt-2 text-center text-xs text-gray-500">
                  Error ID: {this.state.correlationId}
                </p>
              )}
            </div>
            <div className="space-y-4">
              <button
                onClick={this.handleRetry}
                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Try Again
              </button>
              <button
                onClick={this.handleReportIssue}
                className="group relative w-full flex justify-center py-2 px-4 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Report Issue
              </button>
            </div>
            {import.meta.env.DEV && (
              <details className="mt-4 text-left">
                <summary className="cursor-pointer text-sm text-gray-600 hover:text-gray-800">
                  Error Details (Development Only)
                </summary>
                <pre className="mt-2 text-xs text-red-600 bg-red-50 p-2 rounded overflow-auto max-h-40">
                  {this.state.error?.stack}
                </pre>
              </details>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;