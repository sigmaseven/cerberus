import { describe, it, expect, beforeEach, vi } from 'vitest';
import { APIMonitoringService } from './apiMonitoring';

describe('APIMonitoringService', () => {
  let service: APIMonitoringService;

  beforeEach(() => {
    service = new APIMonitoringService();
    vi.clearAllMocks(); // Clear all mocks before each test
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  describe('recordAPICall', () => {
    it('should add metric to metrics array', () => {
      service.recordAPICall('/api/rules', 'GET', 150, 200);

      const metrics = service.getMetrics();
      expect(metrics).toHaveLength(1);
      expect(metrics[0]).toMatchObject({
        endpoint: '/api/rules',
        method: 'GET',
        duration: 150,
        status: 200,
        success: true,
      });
    });

    it('should mark status >= 400 as failure', () => {
      service.recordAPICall('/api/rules', 'GET', 250, 404, 'Not Found');

      const metrics = service.getMetrics();
      expect(metrics[0].success).toBe(false);
      expect(metrics[0].error).toBe('Not Found');
    });

    it('should mark status < 400 as success', () => {
      service.recordAPICall('/api/rules', 'POST', 180, 201);

      const metrics = service.getMetrics();
      expect(metrics[0].success).toBe(true);
      expect(metrics[0].error).toBeUndefined();
    });

    it('should log errors for status >= 400', () => {
      service.recordAPICall('/api/rules', 'DELETE', 120, 500, 'Internal Server Error');

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('[API Error] DELETE /api/rules - Status 500'),
        expect.objectContaining({
          duration: 120,
          error: 'Internal Server Error',
        })
      );
    });

    it('should not log for successful requests', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 200);

      expect(console.error).not.toHaveBeenCalled();
    });

    it('should include timestamp in metric', () => {
      const beforeTimestamp = Date.now();
      service.recordAPICall('/api/rules', 'GET', 100, 200);
      const afterTimestamp = Date.now();

      const metrics = service.getMetrics();
      expect(metrics[0].timestamp).toBeGreaterThanOrEqual(beforeTimestamp);
      expect(metrics[0].timestamp).toBeLessThanOrEqual(afterTimestamp);
    });
  });

  describe('memory limit enforcement', () => {
    it('should enforce 1000 metric limit (FIFO removal)', () => {
      // Add 1001 metrics
      for (let i = 0; i < 1001; i++) {
        service.recordAPICall(`/api/test${i}`, 'GET', 100 + i, 200);
      }

      const metrics = service.getMetrics();
      expect(metrics).toHaveLength(1000);

      // First metric should be removed (index 1), last should be present (index 1000)
      expect(metrics[0].endpoint).toBe('/api/test1'); // Not test0
      expect(metrics[999].endpoint).toBe('/api/test1000');
    });

    it('should remove oldest metric when exceeding limit', () => {
      // Add exactly 1000 metrics
      for (let i = 0; i < 1000; i++) {
        service.recordAPICall(`/api/metric${i}`, 'GET', 100, 200);
      }

      expect(service.getMetricsCount()).toBe(1000);

      // Add one more to trigger FIFO removal
      service.recordAPICall('/api/newest', 'POST', 150, 201);

      const metrics = service.getMetrics();
      expect(metrics).toHaveLength(1000);
      expect(metrics[0].endpoint).toBe('/api/metric1'); // metric0 removed
      expect(metrics[999].endpoint).toBe('/api/newest'); // newest added
    });

    it('should maintain chronological order after FIFO removal', () => {
      for (let i = 0; i < 1005; i++) {
        service.recordAPICall(`/api/test${i}`, 'GET', 100, 200);
      }

      const metrics = service.getMetrics();
      expect(metrics).toHaveLength(1000);

      // Verify timestamps are in ascending order
      for (let i = 1; i < metrics.length; i++) {
        expect(metrics[i].timestamp).toBeGreaterThanOrEqual(metrics[i - 1].timestamp);
      }
    });
  });

  describe('getMetrics', () => {
    beforeEach(() => {
      service.recordAPICall('/api/rules', 'GET', 100, 200);
      service.recordAPICall('/api/alerts', 'GET', 150, 200);
      service.recordAPICall('/api/rules', 'POST', 200, 201);
      service.recordAPICall('/api/actions', 'GET', 120, 404, 'Not Found');
    });

    it('should return all metrics when no filter provided', () => {
      const metrics = service.getMetrics();
      expect(metrics).toHaveLength(4);
    });

    it('should filter metrics by endpoint', () => {
      const rulesMetrics = service.getMetrics('/api/rules');
      expect(rulesMetrics).toHaveLength(2);
      expect(rulesMetrics.every((m) => m.endpoint === '/api/rules')).toBe(true);
    });

    it('should return empty array for non-existent endpoint', () => {
      const metrics = service.getMetrics('/api/nonexistent');
      expect(metrics).toHaveLength(0);
    });

    it('should return a copy of metrics array to prevent external mutation', () => {
      const metrics1 = service.getMetrics();
      const metrics2 = service.getMetrics();

      expect(metrics1).not.toBe(metrics2); // Different array references
      expect(metrics1).toEqual(metrics2); // Same content
    });
  });

  describe('getErrorRate', () => {
    it('should calculate error rate for all metrics', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 200); // success
      service.recordAPICall('/api/rules', 'GET', 110, 200); // success
      service.recordAPICall('/api/alerts', 'GET', 120, 404); // client error
      service.recordAPICall('/api/actions', 'GET', 130, 500); // server error

      const stats = service.getErrorRate();
      expect(stats.totalCalls).toBe(4);
      expect(stats.successfulCalls).toBe(2);
      expect(stats.failedCalls).toBe(2);
      expect(stats.errorRate).toBe(50); // 50% error rate
      expect(stats.clientErrors).toBe(1); // One 404
      expect(stats.serverErrors).toBe(1); // One 500
    });

    it('should calculate error rate for specific endpoint', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 200); // success
      service.recordAPICall('/api/rules', 'POST', 110, 201); // success
      service.recordAPICall('/api/rules', 'DELETE', 120, 404); // error
      service.recordAPICall('/api/alerts', 'GET', 130, 500); // error (different endpoint)

      const rulesStats = service.getErrorRate('/api/rules');
      expect(rulesStats.totalCalls).toBe(3);
      expect(rulesStats.successfulCalls).toBe(2);
      expect(rulesStats.failedCalls).toBe(1);
      expect(rulesStats.errorRate).toBeCloseTo(33.33, 1); // ~33.33% error rate
    });

    it('should return 0% error rate when all requests succeed', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 200);
      service.recordAPICall('/api/rules', 'GET', 110, 200);
      service.recordAPICall('/api/rules', 'GET', 120, 200);

      const stats = service.getErrorRate();
      expect(stats.errorRate).toBe(0);
      expect(stats.successfulCalls).toBe(3);
      expect(stats.failedCalls).toBe(0);
    });

    it('should return 100% error rate when all requests fail', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 404);
      service.recordAPICall('/api/rules', 'GET', 110, 500);
      service.recordAPICall('/api/rules', 'GET', 120, 403);

      const stats = service.getErrorRate();
      expect(stats.errorRate).toBe(100);
      expect(stats.successfulCalls).toBe(0);
      expect(stats.failedCalls).toBe(3);
    });

    it('should handle empty metrics gracefully (division by zero)', () => {
      const stats = service.getErrorRate();
      expect(stats.totalCalls).toBe(0);
      expect(stats.successfulCalls).toBe(0);
      expect(stats.failedCalls).toBe(0);
      expect(stats.errorRate).toBe(0); // Not NaN or Infinity
    });

    it('should return 0% for non-existent endpoint', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 200);

      const stats = service.getErrorRate('/api/nonexistent');
      expect(stats.totalCalls).toBe(0);
      expect(stats.errorRate).toBe(0);
    });
  });

  describe('clearMetrics', () => {
    it('should remove all metrics', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 200);
      service.recordAPICall('/api/alerts', 'GET', 150, 200);
      service.recordAPICall('/api/actions', 'GET', 120, 404);

      expect(service.getMetrics()).toHaveLength(3);

      service.clearMetrics();

      expect(service.getMetrics()).toHaveLength(0);
      expect(service.getMetricsCount()).toBe(0);
    });
  });

  describe('getMetricsCount', () => {
    it('should return current metrics array length', () => {
      expect(service.getMetricsCount()).toBe(0);

      service.recordAPICall('/api/rules', 'GET', 100, 200);
      expect(service.getMetricsCount()).toBe(1);

      service.recordAPICall('/api/alerts', 'GET', 150, 200);
      expect(service.getMetricsCount()).toBe(2);
    });

    it('should reflect length after FIFO removal', () => {
      // Add 1001 metrics to trigger FIFO
      for (let i = 0; i < 1001; i++) {
        service.recordAPICall(`/api/test${i}`, 'GET', 100, 200);
      }

      expect(service.getMetricsCount()).toBe(1000); // Capped at MAX_METRICS
    });
  });

  describe('status code edge cases', () => {
    it('should treat status 399 as success (< 400)', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 399);

      const metrics = service.getMetrics();
      expect(metrics[0].success).toBe(true);
      expect(console.error).not.toHaveBeenCalled();
    });

    it('should treat status 400 as error (>= 400)', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 400);

      const metrics = service.getMetrics();
      expect(metrics[0].success).toBe(false);
      expect(console.error).toHaveBeenCalled();
    });

    it('should handle 3xx redirects as success', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 301);
      service.recordAPICall('/api/rules', 'GET', 110, 302);

      const metrics = service.getMetrics();
      expect(metrics.every((m) => m.success)).toBe(true);
    });

    it('should handle 5xx server errors as failure', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 500);
      service.recordAPICall('/api/rules', 'GET', 110, 503);

      const metrics = service.getMetrics();
      expect(metrics.every((m) => !m.success)).toBe(true);
    });
  });

  describe('error message handling', () => {
    it('should store error message when provided', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 404, 'Resource not found');

      const metrics = service.getMetrics();
      expect(metrics[0].error).toBe('Resource not found');
    });

    it('should not include error field for successful requests', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 200);

      const metrics = service.getMetrics();
      expect(metrics[0].error).toBeUndefined();
    });

    it('should log error message in console.error', () => {
      const errorMsg = 'Network timeout';
      service.recordAPICall('/api/rules', 'GET', 100, 504, errorMsg);

      expect(console.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ error: errorMsg })
      );
    });
  });

  describe('error type categorization', () => {
    it('should categorize 4xx errors as client errors', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 404);

      const metrics = service.getMetrics();
      expect(metrics[0].errorType).toBe('client');
    });

    it('should categorize 5xx errors as server errors', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 500);

      const metrics = service.getMetrics();
      expect(metrics[0].errorType).toBe('server');
    });

    it('should not set errorType for successful requests', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 200);

      const metrics = service.getMetrics();
      expect(metrics[0].errorType).toBeUndefined();
    });

    it('should include error type breakdown in getErrorRate', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 200);
      service.recordAPICall('/api/rules', 'GET', 110, 400); // client
      service.recordAPICall('/api/rules', 'GET', 120, 404); // client
      service.recordAPICall('/api/rules', 'GET', 130, 500); // server
      service.recordAPICall('/api/rules', 'GET', 140, 503); // server

      const stats = service.getErrorRate();
      expect(stats.clientErrors).toBe(2);
      expect(stats.serverErrors).toBe(2);
    });
  });

  describe('time-based expiration', () => {
    it('should remove metrics older than 15 minutes', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      // Add metrics at different times
      service.recordAPICall('/api/test1', 'GET', 100, 200);

      // Move forward 10 minutes
      vi.setSystemTime(now + 10 * 60 * 1000);
      service.recordAPICall('/api/test2', 'GET', 100, 200);

      // Move forward another 10 minutes (total 20 minutes)
      vi.setSystemTime(now + 20 * 60 * 1000);
      service.recordAPICall('/api/test3', 'GET', 100, 200);

      const metrics = service.getMetrics();
      // First metric should be expired, only last 2 should remain
      expect(metrics.length).toBe(2);
      expect(metrics[0].endpoint).toBe('/api/test2');
      expect(metrics[1].endpoint).toBe('/api/test3');

      vi.useRealTimers();
    });
  });

  describe('input validation', () => {
    beforeEach(() => {
      vi.spyOn(console, 'warn').mockImplementation(() => {});
    });

    it('should reject invalid HTTP status codes', () => {
      service.recordAPICall('/api/test', 'GET', 100, 999);

      expect(console.warn).toHaveBeenCalledWith(
        '[API Monitoring] Invalid HTTP status code:',
        999
      );
      expect(service.getMetricsCount()).toBe(0);
    });

    it('should reject negative durations', () => {
      service.recordAPICall('/api/test', 'GET', -100, 200);

      expect(console.warn).toHaveBeenCalledWith(
        '[API Monitoring] Negative duration detected:',
        -100
      );
      expect(service.getMetricsCount()).toBe(0);
    });

    it('should accept valid edge case status codes', () => {
      service.recordAPICall('/api/test', 'GET', 100, 100); // 100 Continue
      service.recordAPICall('/api/test', 'GET', 100, 599); // Custom 5xx

      expect(service.getMetricsCount()).toBe(2);
    });
  });

  describe('getPerformanceStats', () => {
    it('should calculate performance statistics correctly', () => {
      // Add metrics with known durations for easy verification
      service.recordAPICall('/api/rules', 'GET', 100, 200);
      service.recordAPICall('/api/rules', 'GET', 150, 200);
      service.recordAPICall('/api/rules', 'GET', 200, 200);
      service.recordAPICall('/api/rules', 'GET', 250, 200);
      service.recordAPICall('/api/rules', 'GET', 300, 200);

      const stats = service.getPerformanceStats();
      expect(stats.min).toBe(100);
      expect(stats.max).toBe(300);
      expect(stats.mean).toBe(200); // (100+150+200+250+300)/5
      expect(stats.p50).toBe(200); // Median
    });

    it('should filter performance stats by endpoint', () => {
      service.recordAPICall('/api/rules', 'GET', 100, 200);
      service.recordAPICall('/api/alerts', 'GET', 500, 200);
      service.recordAPICall('/api/rules', 'GET', 150, 200);

      const rulesStats = service.getPerformanceStats('/api/rules');
      expect(rulesStats.min).toBe(100);
      expect(rulesStats.max).toBe(150);
    });

    it('should return zeros for empty metrics', () => {
      const stats = service.getPerformanceStats();
      expect(stats).toEqual({
        p50: 0,
        p95: 0,
        p99: 0,
        mean: 0,
        min: 0,
        max: 0,
      });
    });

    it('should calculate percentiles correctly', () => {
      // Add 100 metrics with durations from 1 to 100
      for (let i = 1; i <= 100; i++) {
        service.recordAPICall('/api/test', 'GET', i, 200);
      }

      const stats = service.getPerformanceStats();
      expect(stats.p50).toBe(50); // 50th percentile
      expect(stats.p95).toBe(95); // 95th percentile
      expect(stats.p99).toBe(99); // 99th percentile
    });
  });
});
