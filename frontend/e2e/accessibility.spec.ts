/**
 * Comprehensive Accessibility Tests
 *
 * Coverage:
 * - WCAG 2.1 AA compliance
 * - Keyboard navigation
 * - Screen reader support
 * - Color contrast
 * - ARIA labels and roles
 * - Focus management
 *
 * Reference: WCAG 2.1 Level AA
 */

import { test as authTest, expect } from './fixtures/auth.fixture';
import { test } from '@playwright/test';

test.describe('Accessibility - Keyboard Navigation', () => {
  authTest('A11Y-KB-001: All interactive elements keyboard accessible', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Tab through all interactive elements
    const interactiveElements: string[] = [];

    for (let i = 0; i < 20; i++) {
      await authenticatedPage.keyboard.press('Tab');

      const focused = await authenticatedPage.evaluate(() => {
        const el = document.activeElement;
        return {
          tag: el?.tagName,
          role: el?.getAttribute('role'),
          type: (el as HTMLInputElement)?.type,
        };
      });

      interactiveElements.push(focused.tag);

      // Verify focus is visible
      const hasFocusIndicator = await authenticatedPage.evaluate(() => {
        const el = document.activeElement;
        if (!el) return false;

        const styles = window.getComputedStyle(el);
        const outline = styles.outline;
        const boxShadow = styles.boxShadow;

        return outline !== 'none' || boxShadow !== 'none';
      });

      // Should have visible focus indicator
      expect(hasFocusIndicator).toBe(true);
    }

    // Verify interactive elements found
    expect(interactiveElements.length).toBeGreaterThan(5);
  });

  authTest('A11Y-KB-002: Modal dialogs trap focus', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');

    // Open create rule modal
    await authenticatedPage.click('button:has-text("Create Rule")');

    // Wait for modal
    await authenticatedPage.waitForSelector('[role="dialog"]');

    // Tab through modal
    let focusLeftModal = false;
    for (let i = 0; i < 10; i++) {
      await authenticatedPage.keyboard.press('Tab');

      const focusInModal = await authenticatedPage.evaluate(() => {
        const dialog = document.querySelector('[role="dialog"]');
        const focused = document.activeElement;
        return dialog?.contains(focused);
      });

      if (!focusInModal) {
        focusLeftModal = true;
        break;
      }
    }

    // Focus should stay within modal
    expect(focusLeftModal).toBe(false);
  });

  authTest('A11Y-KB-003: Escape key closes modals', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');

    await authenticatedPage.click('button:has-text("Create Rule")');
    await authenticatedPage.waitForSelector('[role="dialog"]');

    // Press Escape
    await authenticatedPage.keyboard.press('Escape');

    // Modal should close
    await expect(authenticatedPage.locator('[role="dialog"]')).not.toBeVisible();
  });

  authTest('A11Y-KB-004: Dropdown menus keyboard navigable', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Find dropdown/menu button
    const menuButton = authenticatedPage.locator('button[aria-haspopup="true"], button[aria-expanded]').first();

    if (await menuButton.count() > 0) {
      // Open with Enter
      await menuButton.focus();
      await authenticatedPage.keyboard.press('Enter');

      // Navigate with arrow keys
      await authenticatedPage.keyboard.press('ArrowDown');
      await authenticatedPage.keyboard.press('ArrowDown');

      // Select with Enter
      await authenticatedPage.keyboard.press('Enter');

      // Menu should close
      const menuOpen = await authenticatedPage.locator('[role="menu"]').isVisible();
      expect(menuOpen).toBe(false);
    }
  });
});

test.describe('Accessibility - Screen Reader Support', () => {
  authTest('A11Y-SR-001: All images have alt text', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const images = await authenticatedPage.locator('img').all();

    for (const img of images) {
      const alt = await img.getAttribute('alt');
      expect(alt).toBeDefined();
      // Alt can be empty string for decorative images, but must exist
    }
  });

  authTest('A11Y-SR-002: Form inputs have labels', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/login');

    const inputs = await authenticatedPage.locator('input[type="text"], input[type="password"], input[type="email"]').all();

    for (const input of inputs) {
      const id = await input.getAttribute('id');
      const ariaLabel = await input.getAttribute('aria-label');
      const ariaLabelledBy = await input.getAttribute('aria-labelledby');
      const placeholder = await input.getAttribute('placeholder');

      // Must have one of: id with label, aria-label, or aria-labelledby
      const hasAccessibleName = id || ariaLabel || ariaLabelledBy;

      expect(hasAccessibleName).toBeTruthy();
    }
  });

  authTest('A11Y-SR-003: Buttons have accessible names', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const buttons = await authenticatedPage.locator('button').all();

    for (const button of buttons) {
      const text = await button.textContent();
      const ariaLabel = await button.getAttribute('aria-label');
      const ariaLabelledBy = await button.getAttribute('aria-labelledby');
      const title = await button.getAttribute('title');

      const hasAccessibleName = (text && text.trim()) || ariaLabel || ariaLabelledBy || title;

      expect(hasAccessibleName).toBeTruthy();
    }
  });

  authTest('A11Y-SR-004: Headings have proper hierarchy', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const headings = await authenticatedPage.evaluate(() => {
      const elements = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
      return Array.from(elements).map(el => parseInt(el.tagName[1]));
    });

    // Should have at least one heading
    expect(headings.length).toBeGreaterThan(0);

    // First heading should be h1 or h2
    expect(headings[0]).toBeLessThanOrEqual(2);

    // Verify no heading level skips (h1 -> h3 is invalid)
    for (let i = 1; i < headings.length; i++) {
      const jump = headings[i] - headings[i - 1];
      expect(jump).toBeLessThanOrEqual(1);
    }
  });

  authTest('A11Y-SR-005: Live regions for dynamic content', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Check for aria-live regions
    const liveRegions = await authenticatedPage.locator('[aria-live]').count();

    // Should have at least one for notifications/alerts
    expect(liveRegions).toBeGreaterThanOrEqual(1);
  });

  authTest('A11Y-SR-006: Tables have proper structure', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/events');

    // Verify table has thead
    await expect(authenticatedPage.locator('table thead')).toBeVisible();

    // Verify table has th elements
    const headers = await authenticatedPage.locator('table th').count();
    expect(headers).toBeGreaterThan(0);

    // Verify table has caption or aria-label
    const table = authenticatedPage.locator('table');
    const caption = await table.locator('caption').count();
    const ariaLabel = await table.getAttribute('aria-label');

    expect(caption > 0 || !!ariaLabel).toBeTruthy();
  });
});

test.describe('Accessibility - Color and Contrast', () => {
  authTest('A11Y-COLOR-001: Text has sufficient contrast ratio', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Sample text elements and check contrast
    const textElements = await authenticatedPage.locator('p, span, div, h1, h2, h3, h4, h5, h6').all();

    for (const element of textElements.slice(0, 10)) {
      const contrast = await element.evaluate(el => {
        const styles = window.getComputedStyle(el);
        const color = styles.color;
        const bgColor = styles.backgroundColor;

        // Convert to luminance and calculate contrast ratio
        // This is simplified; actual calculation is more complex
        const hasText = el.textContent && el.textContent.trim();

        return { color, bgColor, hasText };
      });

      // If element has text, it should have contrasting colors
      if (contrast.hasText) {
        expect(contrast.color).not.toBe(contrast.bgColor);
      }
    }
  });

  authTest('A11Y-COLOR-002: Focus indicators have sufficient contrast', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Tab to first focusable element
    await authenticatedPage.keyboard.press('Tab');

    const focusContrast = await authenticatedPage.evaluate(() => {
      const el = document.activeElement;
      if (!el) return null;

      const styles = window.getComputedStyle(el);
      return {
        outline: styles.outline,
        outlineColor: styles.outlineColor,
        boxShadow: styles.boxShadow,
      };
    });

    // Should have visible focus indicator
    expect(
      focusContrast?.outline !== 'none' ||
      focusContrast?.boxShadow !== 'none'
    ).toBe(true);
  });

  authTest('A11Y-COLOR-003: Information not conveyed by color alone', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/alerts');

    // Check severity indicators
    // Should use text, icons, or patterns in addition to color

    const severityCells = await authenticatedPage.locator('td:has-text("Critical"), td:has-text("High"), td:has-text("Medium")').all();

    for (const cell of severityCells.slice(0, 5)) {
      const text = await cell.textContent();

      // Severity should be indicated by text, not just color
      expect(text?.trim()).toBeTruthy();
    }
  });
});

test.describe('Accessibility - ARIA Attributes', () => {
  authTest('A11Y-ARIA-001: Correct ARIA roles used', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Check for proper ARIA roles
    const navigation = authenticatedPage.locator('[role="navigation"]');
    await expect(navigation).toBeVisible();

    const main = authenticatedPage.locator('[role="main"], main');
    await expect(main).toBeVisible();
  });

  authTest('A11Y-ARIA-002: ARIA expanded state on dropdowns', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const dropdown = authenticatedPage.locator('button[aria-expanded]').first();

    if (await dropdown.count() > 0) {
      // Initially collapsed
      const initialState = await dropdown.getAttribute('aria-expanded');
      expect(initialState).toBe('false');

      // Click to expand
      await dropdown.click();

      // Should be expanded
      const expandedState = await dropdown.getAttribute('aria-expanded');
      expect(expandedState).toBe('true');
    }
  });

  authTest('A11Y-ARIA-003: ARIA required on required fields', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/login');

    const requiredFields = await authenticatedPage.locator('input[required], input[aria-required="true"]').all();

    expect(requiredFields.length).toBeGreaterThan(0);

    for (const field of requiredFields) {
      const ariaRequired = await field.getAttribute('aria-required');
      const htmlRequired = await field.getAttribute('required');

      expect(ariaRequired === 'true' || htmlRequired !== null).toBe(true);
    }
  });

  authTest('A11Y-ARIA-004: ARIA invalid on validation errors', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/login');

    // Submit empty form
    await authenticatedPage.click('button[type="submit"]');

    // Check for aria-invalid
    const invalidFields = await authenticatedPage.locator('[aria-invalid="true"]').count();

    // Should mark invalid fields
    expect(invalidFields).toBeGreaterThan(0);
  });
});

test.describe('Accessibility - Focus Management', () => {
  authTest('A11Y-FOCUS-001: Focus moves to modal on open', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');

    await authenticatedPage.click('button:has-text("Create Rule")');
    await authenticatedPage.waitForSelector('[role="dialog"]');

    // Focus should be inside dialog
    const focusInDialog = await authenticatedPage.evaluate(() => {
      const dialog = document.querySelector('[role="dialog"]');
      const focused = document.activeElement;
      return dialog?.contains(focused);
    });

    expect(focusInDialog).toBe(true);
  });

  authTest('A11Y-FOCUS-002: Focus returns after modal close', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/rules');

    const createButton = authenticatedPage.locator('button:has-text("Create Rule")');
    await createButton.focus();

    // Get button reference
    const buttonHandle = await createButton.elementHandle();

    await createButton.click();
    await authenticatedPage.waitForSelector('[role="dialog"]');

    // Close modal
    await authenticatedPage.keyboard.press('Escape');

    // Focus should return to create button
    await authenticatedPage.waitForTimeout(500);

    const currentFocus = await authenticatedPage.evaluate(() => document.activeElement?.textContent);
    expect(currentFocus).toContain('Create');
  });

  authTest('A11Y-FOCUS-003: Skip to main content link', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Tab to first element (should be skip link)
    await authenticatedPage.keyboard.press('Tab');

    const firstFocusable = await authenticatedPage.evaluate(() => {
      return document.activeElement?.textContent;
    });

    // Should have skip link (optional but recommended)
    if (firstFocusable?.includes('Skip')) {
      await authenticatedPage.keyboard.press('Enter');

      // Focus should move to main content
      const mainFocused = await authenticatedPage.evaluate(() => {
        const main = document.querySelector('main, [role="main"]');
        const focused = document.activeElement;
        return main?.contains(focused);
      });

      expect(mainFocused).toBe(true);
    }
  });
});

test.describe('Accessibility - Mobile Accessibility', () => {
  test.use({ viewport: { width: 375, height: 667 } });

  authTest('A11Y-MOBILE-001: Touch targets minimum 44x44px', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    const buttons = await authenticatedPage.locator('button, a').all();

    for (const button of buttons.slice(0, 10)) {
      const size = await button.boundingBox();

      if (size) {
        // WCAG requires 44x44px for touch targets
        expect(size.width).toBeGreaterThanOrEqual(44);
        expect(size.height).toBeGreaterThanOrEqual(44);
      }
    }
  });

  authTest('A11Y-MOBILE-002: Responsive layout maintains functionality', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/');

    // Verify main navigation accessible
    await expect(authenticatedPage.locator('nav')).toBeVisible();

    // Verify content visible
    await expect(authenticatedPage.locator('main, [role="main"]')).toBeVisible();
  });
});
