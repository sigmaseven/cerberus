import DOMPurify from 'dompurify';

/**
 * Security utility for sanitizing user-generated content to prevent XSS attacks.
 *
 * CRITICAL: All user-generated content MUST pass through these functions before
 * being rendered in the UI. This includes:
 * - Alert messages and descriptions
 * - Rule names and descriptions
 * - Investigation notes and comments
 * - Event field values
 * - Any data from external sources
 *
 * @module sanitize
 */

/**
 * Sanitizes HTML content to prevent XSS attacks while preserving safe formatting tags.
 *
 * SECURITY: Use this when you need to render user-generated HTML content.
 * Only allows a minimal set of safe tags and attributes.
 *
 * @param dirty - Untrusted HTML string from user input or external sources
 * @returns Sanitized HTML safe for rendering
 *
 * @example
 * ```tsx
 * const userInput = '<script>alert("xss")</script><b>Bold text</b>';
 * const safe = sanitizeHTML(userInput);
 * // Returns: '<b>Bold text</b>'
 * ```
 */
export function sanitizeHTML(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
    ALLOW_DATA_ATTR: false,
    ADD_ATTR: ['target', 'rel'], // Ensure these are added even if not in input
    // Always open links in new tab and prevent tabnabbing
    HOOKS: {
      afterSanitizeAttributes: (node) => {
        if (node.tagName === 'A' && node.hasAttribute('href')) {
          node.setAttribute('target', '_blank');
          node.setAttribute('rel', 'noopener noreferrer');
        }
      },
    },
  });
}

/**
 * Sanitizes plain text by escaping all HTML special characters.
 *
 * SECURITY: Use this for displaying user input as plain text (not HTML).
 * This is the preferred method for most user-generated content.
 *
 * @param text - Untrusted text string
 * @returns HTML-escaped text safe for rendering
 *
 * @example
 * ```tsx
 * const userInput = '<script>alert("xss")</script>';
 * const safe = escapeHTML(userInput);
 * // Returns: '&lt;script&gt;alert("xss")&lt;/script&gt;'
 *
 * // Usage in component:
 * <div>{escapeHTML(alert.message)}</div>
 * ```
 */
export function escapeHTML(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Sanitizes HTML for use with React's dangerouslySetInnerHTML.
 *
 * SECURITY: Only use when you absolutely need to render HTML content.
 * Prefer plain text rendering with escapeHTML() when possible.
 *
 * @param dirty - Untrusted HTML string
 * @returns Object compatible with React's dangerouslySetInnerHTML API
 *
 * @example
 * ```tsx
 * <div dangerouslySetInnerHTML={sanitizeForReact(userContent)} />
 * ```
 */
export function sanitizeForReact(dirty: string): { __html: string } {
  return { __html: sanitizeHTML(dirty) };
}

/**
 * Sanitizes a URL to prevent javascript: and data: protocol attacks.
 *
 * SECURITY: Use before rendering user-provided URLs in href or src attributes.
 *
 * @param url - Untrusted URL string
 * @returns Sanitized URL or '#' if dangerous
 *
 * @example
 * ```tsx
 * <a href={sanitizeURL(userProvidedURL)}>Link</a>
 * ```
 */
export function sanitizeURL(url: string): string {
  try {
    const parsed = new URL(url, window.location.origin);
    // Only allow http, https, and mailto protocols
    if (['http:', 'https:', 'mailto:'].includes(parsed.protocol)) {
      return url;
    }
  } catch {
    // Invalid URL
  }
  return '#';
}

/**
 * Sanitizes an object by escaping all string values.
 * Useful for sanitizing entire event objects or API responses.
 *
 * @param obj - Object with potentially untrusted string values
 * @returns New object with all strings escaped
 *
 * @example
 * ```tsx
 * const event = sanitizeObject(rawEvent);
 * ```
 */
export function sanitizeObject<T>(obj: T): T {
  if (typeof obj === 'string') {
    return escapeHTML(obj) as T;
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject) as T;
  }

  if (obj !== null && typeof obj === 'object') {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitized[key] = sanitizeObject(value);
    }
    return sanitized as T;
  }

  return obj;
}

/**
 * Configures DOMPurify with additional security settings.
 * Called automatically on module load.
 */
function configureDOMPurify(): void {
  // Forbid tags that can execute scripts
  DOMPurify.addHook('uponSanitizeElement', (node, data) => {
    if (data.tagName === 'script' || data.tagName === 'style') {
      // Remove the node entirely
      node.parentNode?.removeChild(node);
    }
  });

  // Forbid attributes that can execute scripts
  DOMPurify.addHook('uponSanitizeAttribute', (node, data) => {
    // Remove event handlers
    if (data.attrName.startsWith('on')) {
      data.keepAttr = false;
    }
  });
}

// Initialize security configuration
configureDOMPurify();
