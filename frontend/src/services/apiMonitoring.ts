/**
 * API Monitoring Service
 * Tracks API call metrics, error rates, and performance for observability
 */

export interface APIMetric {
  endpoint: string;
  method: string;
  duration: number; // milliseconds
  status: number;
  success: boolean;
  timestamp: number; // Unix timestamp in milliseconds
  error?: string;
  errorType?: 'client' | 'server'; // client=4xx, server=5xx
}

interface ErrorRateStats {
  totalCalls: number;
  successfulCalls: number;
  failedCalls: number;
  errorRate: number; // Percentage (0-100)
  clientErrors: number; // 4xx errors
  serverErrors: number; // 5xx errors
}

export interface PerformanceStats {
  p50: number; // 50th percentile latency
  p95: number; // 95th percentile latency
  p99: number; // 99th percentile latency
  mean: number; // Average latency
  min: number; // Minimum latency
  max: number; // Maximum latency
}

/**
 * APIMonitoringService tracks API performance metrics in-memory
 * Designed for frontend observability with optional backend integration
 */
export class APIMonitoringService {
  private metrics: APIMetric[] = [];
  private readonly MAX_METRICS = 1000;
  private readonly MAX_AGE_MS = 15 * 60 * 1000; // 15 minutes

  /**
   * Records an API call with its performance metrics
   * Automatically logs errors for status >= 400
   * Includes time-based expiration and error type categorization
   *
   * @param endpoint - API endpoint path (e.g., '/api/rules')
   * @param method - HTTP method (GET, POST, PUT, DELETE)
   * @param duration - Request duration in milliseconds
   * @param status - HTTP status code
   * @param error - Optional error message for failed requests
   */
  recordAPICall(
    endpoint: string,
    method: string,
    duration: number,
    status: number,
    error?: string
  ): void {
    // Input validation
    if (status < 100 || status > 599) {
      console.warn('[API Monitoring] Invalid HTTP status code:', status);
      return;
    }

    if (duration < 0) {
      console.warn('[API Monitoring] Negative duration detected:', duration);
      return;
    }

    const success = status < 400;
    const timestamp = Date.now();

    // Determine error type for failed requests
    let errorType: 'client' | 'server' | undefined;
    if (status >= 500) {
      errorType = 'server';
    } else if (status >= 400) {
      errorType = 'client';
    }

    const metric: APIMetric = {
      endpoint,
      method,
      duration,
      status,
      success,
      timestamp,
      error,
      errorType,
    };

    // Add metric to array
    this.metrics.push(metric);

    // Remove metrics older than MAX_AGE_MS (time-based expiration)
    const now = Date.now();
    this.metrics = this.metrics.filter((m) => now - m.timestamp < this.MAX_AGE_MS);

    // Enforce memory limit (FIFO - remove oldest when exceeding limit)
    if (this.metrics.length > this.MAX_METRICS) {
      this.metrics.shift(); // Remove oldest metric
    }

    // Log errors for visibility during development
    if (!success) {
      console.error(`[API Error] ${method} ${endpoint} - Status ${status} (${errorType})`, {
        duration,
        error,
        timestamp: new Date(timestamp).toISOString(),
      });
    }
  }

  /**
   * Retrieves metrics, optionally filtered by endpoint
   *
   * @param endpoint - Optional endpoint filter (e.g., '/api/rules')
   * @returns Array of APIMetric objects
   */
  getMetrics(endpoint?: string): APIMetric[] {
    if (!endpoint) {
      return [...this.metrics]; // Return copy to prevent external mutation
    }

    return this.metrics.filter((metric) => metric.endpoint === endpoint);
  }

  /**
   * Calculates error rate statistics for all calls or specific endpoint
   * Includes breakdown of client (4xx) vs server (5xx) errors
   *
   * @param endpoint - Optional endpoint filter
   * @returns Error rate statistics including success/failure counts and percentage
   */
  getErrorRate(endpoint?: string): ErrorRateStats {
    const relevantMetrics = endpoint
      ? this.metrics.filter((m) => m.endpoint === endpoint)
      : this.metrics;

    const totalCalls = relevantMetrics.length;
    const successfulCalls = relevantMetrics.filter((m) => m.success).length;
    const failedCalls = totalCalls - successfulCalls;
    const clientErrors = relevantMetrics.filter((m) => m.errorType === 'client').length;
    const serverErrors = relevantMetrics.filter((m) => m.errorType === 'server').length;

    // Calculate error rate as percentage, handle division by zero
    const errorRate = totalCalls > 0 ? (failedCalls / totalCalls) * 100 : 0;

    return {
      totalCalls,
      successfulCalls,
      failedCalls,
      errorRate,
      clientErrors,
      serverErrors,
    };
  }

  /**
   * Clears all stored metrics (useful for testing or memory management)
   */
  clearMetrics(): void {
    this.metrics = [];
  }

  /**
   * Gets current metrics array length (useful for monitoring memory usage)
   */
  getMetricsCount(): number {
    return this.metrics.length;
  }

  /**
   * Calculates performance statistics including percentiles
   * Essential for identifying latency issues and performance degradation
   *
   * @param endpoint - Optional endpoint filter
   * @returns Performance statistics with p50/p95/p99 latencies
   */
  getPerformanceStats(endpoint?: string): PerformanceStats {
    const relevantMetrics = endpoint
      ? this.metrics.filter((m) => m.endpoint === endpoint)
      : this.metrics;

    if (relevantMetrics.length === 0) {
      return { p50: 0, p95: 0, p99: 0, mean: 0, min: 0, max: 0 };
    }

    const durations = relevantMetrics.map((m) => m.duration).sort((a, b) => a - b);
    const sum = durations.reduce((acc, d) => acc + d, 0);

    // Calculate percentile indices (0-based, so subtract 1)
    const p50Index = Math.max(0, Math.ceil(durations.length * 0.5) - 1);
    const p95Index = Math.max(0, Math.ceil(durations.length * 0.95) - 1);
    const p99Index = Math.max(0, Math.ceil(durations.length * 0.99) - 1);

    return {
      p50: durations[p50Index],
      p95: durations[p95Index],
      p99: durations[p99Index],
      mean: sum / durations.length,
      min: durations[0],
      max: durations[durations.length - 1],
    };
  }
}

// Export singleton instance for app-wide usage
export const apiMonitoring = new APIMonitoringService();
