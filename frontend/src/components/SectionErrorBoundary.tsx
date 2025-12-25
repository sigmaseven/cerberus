import { Component, ReactNode } from 'react';
import { Alert, AlertTitle, Button, Box } from '@mui/material';
import errorReportingService from '../services/errorReporting';

interface Props {
  children: ReactNode;
  section: string;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: React.ErrorInfo | null;
  correlationId: string | null;
}

/**
 * Section-level error boundary for graceful degradation
 *
 * Unlike the app-level ErrorBoundary, this allows other parts
 * of the UI to continue functioning when one section fails.
 *
 * ACCESSIBILITY: Proper ARIA roles and focus management
 * UX: Clear error messaging with retry capability
 * OBSERVABILITY: Error reporting with correlation IDs
 */
export class SectionErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      correlationId: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return {
      hasError: true,
      error,
      correlationId: `section_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    const { section } = this.props;
    const { correlationId } = this.state;

    // Log error details
    const errorDetails = {
      correlationId,
      section,
      error: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href,
    };

    if (import.meta.env.DEV) {
      console.error(`[Section Error Boundary: ${section}]`, errorDetails);
    }

    // Report to error monitoring
    errorReportingService.reportReactError(error, {
      componentStack: errorInfo.componentStack,
    }, {
      section,
      correlationId: correlationId || 'unknown',
      url: window.location.href,
      timestamp: new Date().toISOString(),
    });

    this.setState({
      errorInfo,
    });
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      correlationId: null,
    });
  };

  render() {
    if (this.state.hasError) {
      // Custom fallback if provided
      if (this.props.fallback) {
        return this.props.fallback;
      }

      // Default error UI
      return (
        <Box sx={{ p: 3 }} role="alert" aria-live="assertive">
          <Alert severity="error">
            <AlertTitle>Error in {this.props.section}</AlertTitle>
            <Box sx={{ mb: 1 }}>
              {this.state.error?.message || 'An unexpected error occurred'}
            </Box>
            {this.state.correlationId && (
              <Box sx={{ mb: 2, fontSize: '0.875rem', color: 'text.secondary' }}>
                Error ID: {this.state.correlationId}
              </Box>
            )}
            <Box sx={{ mt: 2 }}>
              <Button
                onClick={this.handleReset}
                variant="outlined"
                size="small"
                color="inherit"
                aria-label={`Retry loading ${this.props.section}`}
              >
                Try Again
              </Button>
            </Box>
            {import.meta.env.DEV && this.state.error && (
              <Box sx={{ mt: 2 }}>
                <details>
                  <summary style={{ cursor: 'pointer', fontSize: '0.875rem' }}>
                    Error Details (Development Only)
                  </summary>
                  <Box
                    component="pre"
                    sx={{
                      mt: 1,
                      p: 1,
                      fontSize: '0.75rem',
                      bgcolor: 'error.light',
                      color: 'error.contrastText',
                      borderRadius: 1,
                      overflow: 'auto',
                      maxHeight: 200,
                    }}
                  >
                    {this.state.error.stack}
                  </Box>
                </details>
              </Box>
            )}
          </Alert>
        </Box>
      );
    }

    return this.props.children;
  }
}
