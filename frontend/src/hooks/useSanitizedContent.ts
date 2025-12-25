import { useMemo } from 'react';
import { escapeHTML, sanitizeHTML, sanitizeObject } from '../utils/sanitize';

/**
 * Custom hook for safely rendering user-generated content.
 * Automatically memoizes sanitization to prevent unnecessary re-renders.
 *
 * SECURITY: This hook should be used for ALL user-generated content
 * including alert messages, rule names, event fields, investigation notes, etc.
 *
 * @param content - The content to sanitize
 * @param mode - Sanitization mode: 'text' (default), 'html', or 'object'
 * @returns Sanitized content safe for rendering
 *
 * @example
 * ```tsx
 * function AlertDisplay({ alert }: { alert: Alert }) {
 *   const sanitizedMessage = useSanitizedContent(alert.message);
 *   return <Typography>{sanitizedMessage}</Typography>;
 * }
 * ```
 */
export function useSanitizedContent<T>(
  content: T,
  mode: 'text' | 'html' | 'object' = 'text'
): string | T {
  return useMemo(() => {
    if (!content) return content;

    switch (mode) {
      case 'text':
        return typeof content === 'string' ? escapeHTML(content) : content;
      case 'html':
        return typeof content === 'string' ? sanitizeHTML(content) : content;
      case 'object':
        return sanitizeObject(content);
      default:
        return content;
    }
  }, [content, mode]);
}

/**
 * Hook for sanitizing JSON display.
 * Converts object to JSON string and escapes all HTML.
 *
 * SECURITY: Use this for displaying event.fields, action.config, and other
 * structured data that might contain malicious content.
 *
 * @param obj - Object to display as JSON
 * @param indent - Number of spaces for indentation (default: 2)
 * @returns Sanitized JSON string safe for rendering
 *
 * @example
 * ```tsx
 * function EventDetails({ event }: { event: Event }) {
 *   const sanitizedFields = useSanitizedJSON(event.fields);
 *   return <pre><code>{sanitizedFields}</code></pre>;
 * }
 * ```
 */
export function useSanitizedJSON(obj: unknown, indent: number = 2): string {
  return useMemo(() => {
    try {
      const jsonString = JSON.stringify(obj, null, indent);
      return escapeHTML(jsonString);
    } catch {
      return '[Invalid JSON]';
    }
  }, [obj, indent]);
}
