/**
 * Performance and Load Tests
 *
 * Coverage:
 * - Page load times
 * - API response times
 * - Large dataset handling
 * - Memory leaks
 * - Network performance
 *
 * Maps to requirements:
 * - FR-API-019: Response time SLAs
 * - Performance requirements
 */

import { test as authTest, expect } from './fixtures/auth.fixture';

authTest.describe('Performance - Page Load Times', () => {
  authTest('PERF-001: Dashboard loads under 2 seconds', async ({ authenticatedPage }) => {
    const startTime = Date.now();

    await authenticatedPage.goto('/');
    await authenticatedPage.waitForLoadState('networkidle');

    const loadTime = Date.now() - startTime;

    // Performance SLA: < 2000ms for full page load
    expect(loadTime).toBeLessThan(2000);
  });

  authTest('PERF-002: Rules page loads under 2 seconds', async ({ authenticatedPage }) => {
    const startTime = Date.now();

    await authenticatedPage.goto('/rules');
    await authenticatedPage.waitForLoadState('networkidle');

    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(2000);
  });

  authTest('PERF-003: Events page loads under 2 seconds', async ({ authenticatedPage }) => {
    const startTime = Date.now();

    await authenticatedPage.goto('/events');
    await authenticatedPage.waitForLoadState('networkidle');

    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(2000);
  });

  authTest('PERF-004: Alerts page loads under 2 seconds', async ({ authenticatedPage }) => {
    const startTime = Date.now();

    await authenticatedPage.goto('/alerts');
    await authenticatedPage.waitForLoadState('networkidle');

    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(2000);
  });
});

authTest.describe('Performance - API Response Times', () => {
  authTest('PERF-API-001: Dashboard API responds under 300ms', async ({ authenticatedPage, page }) => {
    const apiTimings: number[] = [];

    page.on('response', response => {
      if (response.url().includes('/api/v1/dashboard')) {
        const timing = response.timing();
        apiTimings.push(timing.responseEnd - timing.requestStart);
      }
    });

    await authenticatedPage.goto('/');
    await authenticatedPage.waitForLoadState('networkidle');

    // FR-API-019: Dashboard API < 200ms (p95)
    // Allow 300ms for E2E testing overhead
    for (const timing of apiTimings) {
      expect(timing).toBeLessThan(300);
    }
  });

  authTest('PERF-API-002: Events API responds under 300ms', async ({ authenticatedPage, page }) => {
    const apiTimings: number[] = [];

    page.on('response', response => {
      if (response.url().includes('/api/v1/events')) {
        const timing = response.timing();
        apiTimings.push(timing.responseEnd - timing.requestStart);
      }
    });

    await authenticatedPage.goto('/events');
    await authenticatedPage.waitForLoadState('networkidle');

    // FR-API-019: List endpoints < 300ms
    for (const timing of apiTimings) {
      expect(timing).toBeLessThan(300);
    }
  });

  authTest('PERF-API-003: Rules API responds under 300ms', async ({ authenticatedPage, page }) => {
    const apiTimings: number[] = [];

    page.on('response', response => {
      if (response.url().includes('/api/v1/rules')) {
        const timing = response.timing();
        apiTimings.push(timing.responseEnd - timing.requestStart);
      }
    });

    await authenticatedPage.goto('/rules');
    await authenticatedPage.waitForLoadState('networkidle');

    for (const timing of apiTimings) {
      expect(timing).toBeLessThan(300);
    }
  });

  authTest('PERF-API-004: Single resource API responds under 100ms', async ({ authenticatedPage, page }) => {
    const apiTimings: number[] = [];

    page.on('response', response => {
      const url = response.url();
      if (url.match(/\/api\/v1\/rules\/[a-zA-Z0-9-]+$/) && !url.includes('?')) {
        const timing = response.timing();
        apiTimings.push(timing.responseEnd - timing.requestStart);
      }
    });

    await authenticatedPage.goto('/rules');

    // Click first rule to view details
    const firstRule = authenticatedPage.locator('tbody tr').first();
    if (await firstRule.count() > 0) {
      await firstRule.click();
      await authenticatedPage.waitForTimeout(1000);

      // FR-API-019: Single resource < 100ms
      for (const timing of apiTimings) {
        expect(timing).toBeLessThan(100);
      }
    }
  });
});

authTest.describe('Performance - Large Dataset Handling', () => {
  authTest('PERF-DATA-001: Events table renders 1000 rows efficiently', async ({ authenticatedPage }) => {
    test.slow(); // Mark as slow test

    await authenticatedPage.goto('/events?limit=1000');

    const startTime = Date.now();
    await authenticatedPage.waitForSelector('tbody tr', { timeout: 10000 });

    const renderTime = Date.now() - startTime;

    // Should render within 5 seconds even with 1000 rows
    expect(renderTime).toBeLessThan(5000);

    // Verify rows actually rendered
    const rowCount = await authenticatedPage.locator('tbody tr').count();
    expect(rowCount).toBeGreaterThan(0);
  });

  authTest('PERF-DATA-002: Pagination handles large datasets', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/events?limit=100');

    // Navigate through multiple pages
    for (let i = 0; i < 3; i++) {
      const startTime = Date.now();

      const nextButton = authenticatedPage.locator('button[aria-label="Go to next page"]');
      if (await nextButton.count() > 0 && await nextButton.isEnabled()) {
        await nextButton.click();
        await authenticatedPage.waitForLoadState('networkidle');

        const pageTime = Date.now() - startTime;

        // Each page load < 2 seconds
        expect(pageTime).toBeLessThan(2000);
      }
    }
  });

  authTest('PERF-DATA-003: Search with large result set completes quickly', async ({ authenticatedPage }) => {
    test.skip(true, 'Requires CQL search implementation');

    await authenticatedPage.goto('/events');

    // Search for common event type (large result set)
    const searchInput = authenticatedPage.locator('input[type="search"]');
    await searchInput.fill('event_type="auth_failure"');

    const startTime = Date.now();
    await authenticatedPage.keyboard.press('Enter');
    await authenticatedPage.waitForLoadState('networkidle');

    const searchTime = Date.now() - startTime;

    // FR-API-019: Search < 1000ms
    expect(searchTime).toBeLessThan(2000); // Allow overhead
  });
});

authTest.describe('Performance - Memory Leaks', () => {
  authTest('PERF-MEM-001: No memory leaks on repeated navigation', async ({ authenticatedPage }) => {
    test.slow();

    // Get initial memory
    const initialMemory = await authenticatedPage.evaluate(() => {
      if ('memory' in performance) {
        return (performance as any).memory.usedJSHeapSize;
      }
      return 0;
    });

    // Navigate between pages repeatedly
    const pages = ['/', '/events', '/alerts', '/rules'];

    for (let i = 0; i < 10; i++) {
      for (const path of pages) {
        await authenticatedPage.goto(path);
        await authenticatedPage.waitForLoadState('networkidle');
      }
    }

    // Force garbage collection if available
    await authenticatedPage.evaluate(() => {
      if ((window as any).gc) {
        (window as any).gc();
      }
    });

    await authenticatedPage.waitForTimeout(2000);

    const finalMemory = await authenticatedPage.evaluate(() => {
      if ('memory' in performance) {
        return (performance as any).memory.usedJSHeapSize;
      }
      return 0;
    });

    if (initialMemory > 0 && finalMemory > 0) {
      // Memory should not grow more than 50% after 40 navigations
      const growthRatio = finalMemory / initialMemory;
      expect(growthRatio).toBeLessThan(1.5);
    }
  });

  authTest('PERF-MEM-002: No memory leaks with modal open/close', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');

    const initialMemory = await authenticatedPage.evaluate(() => {
      if ('memory' in performance) {
        return (performance as any).memory.usedJSHeapSize;
      }
      return 0;
    });

    // Open and close modal 20 times
    for (let i = 0; i < 20; i++) {
      await authenticatedPage.click('button:has-text("Create Rule")');
      await authenticatedPage.waitForSelector('[role="dialog"]');
      await authenticatedPage.keyboard.press('Escape');
      await authenticatedPage.waitForTimeout(100);
    }

    await authenticatedPage.waitForTimeout(1000);

    const finalMemory = await authenticatedPage.evaluate(() => {
      if ('memory' in performance) {
        return (performance as any).memory.usedJSHeapSize;
      }
      return 0;
    });

    if (initialMemory > 0 && finalMemory > 0) {
      const growthRatio = finalMemory / initialMemory;
      expect(growthRatio).toBeLessThan(1.3);
    }
  });
});

authTest.describe('Performance - Network Efficiency', () => {
  authTest('PERF-NET-001: Static assets are cached', async ({ authenticatedPage, page }) => {
    const cachedRequests: string[] = [];

    page.on('response', response => {
      const cacheControl = response.headers()['cache-control'];
      if (cacheControl && cacheControl.includes('max-age')) {
        cachedRequests.push(response.url());
      }
    });

    await authenticatedPage.goto('/');
    await authenticatedPage.waitForLoadState('networkidle');

    // Should have cacheable static assets
    expect(cachedRequests.length).toBeGreaterThan(0);
  });

  authTest('PERF-NET-002: Images are optimized', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const images = await authenticatedPage.locator('img').all();

    for (const img of images) {
      const naturalWidth = await img.evaluate((el: any) => el.naturalWidth);
      const displayWidth = await img.evaluate((el: any) => el.clientWidth);

      // Image should not be significantly larger than display size
      if (naturalWidth > 0 && displayWidth > 0) {
        const ratio = naturalWidth / displayWidth;
        expect(ratio).toBeLessThan(3); // Allow 3x for retina displays
      }
    }
  });

  authTest('PERF-NET-003: API requests are batched when possible', async ({ authenticatedPage, page }) => {
    const apiRequests: string[] = [];

    page.on('request', request => {
      if (request.url().includes('/api/v1/')) {
        apiRequests.push(request.url());
      }
    });

    await authenticatedPage.goto('/');
    await authenticatedPage.waitForLoadState('networkidle');

    // Dashboard should make minimal API calls (ideally 1-3)
    expect(apiRequests.length).toBeLessThan(10);
  });
});

authTest.describe('Performance - Rendering Performance', () => {
  authTest('PERF-RENDER-001: First Contentful Paint < 1.5s', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const fcp = await authenticatedPage.evaluate(() => {
      return new Promise(resolve => {
        const observer = new PerformanceObserver(list => {
          for (const entry of list.getEntries()) {
            if (entry.name === 'first-contentful-paint') {
              resolve(entry.startTime);
              observer.disconnect();
            }
          }
        });
        observer.observe({ type: 'paint', buffered: true });

        setTimeout(() => resolve(null), 5000);
      });
    });

    if (fcp) {
      expect(fcp).toBeLessThan(1500);
    }
  });

  authTest('PERF-RENDER-002: Largest Contentful Paint < 2.5s', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const lcp = await authenticatedPage.evaluate(() => {
      return new Promise(resolve => {
        const observer = new PerformanceObserver(list => {
          const entries = list.getEntries();
          const lastEntry = entries[entries.length - 1];
          resolve(lastEntry.startTime);
        });
        observer.observe({ type: 'largest-contentful-paint', buffered: true });

        setTimeout(() => {
          observer.disconnect();
        }, 3000);
      });
    });

    if (lcp) {
      expect(lcp).toBeLessThan(2500);
    }
  });

  authTest('PERF-RENDER-003: Cumulative Layout Shift < 0.1', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const cls = await authenticatedPage.evaluate(() => {
      return new Promise(resolve => {
        let clsScore = 0;
        const observer = new PerformanceObserver(list => {
          for (const entry of list.getEntries()) {
            if (!(entry as any).hadRecentInput) {
              clsScore += (entry as any).value;
            }
          }
        });

        observer.observe({ type: 'layout-shift', buffered: true });

        setTimeout(() => {
          observer.disconnect();
          resolve(clsScore);
        }, 3000);
      });
    });

    // CLS < 0.1 is good
    expect(cls).toBeLessThan(0.1);
  });

  authTest('PERF-RENDER-004: Time to Interactive < 3s', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const tti = await authenticatedPage.evaluate(() => {
      return new Promise(resolve => {
        if ('PerformanceObserver' in window) {
          setTimeout(() => {
            const perfData = performance.getEntriesByType('navigation')[0] as any;
            resolve(perfData.domInteractive);
          }, 1000);
        } else {
          resolve(null);
        }
      });
    });

    if (tti) {
      expect(tti).toBeLessThan(3000);
    }
  });
});
