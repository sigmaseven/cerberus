import { describe, it, expect } from 'vitest';
import { sanitizeHTML, escapeHTML, sanitizeURL, sanitizeForReact } from './sanitize';

describe('sanitize utilities', () => {
  describe('escapeHTML', () => {
    it('should escape HTML special characters', () => {
      const input = '<script>alert("xss")</script>';
      const output = escapeHTML(input);
      expect(output).toBe('&lt;script&gt;alert("xss")&lt;/script&gt;');
      expect(output).not.toContain('<script>');
    });

    it('should escape all dangerous characters', () => {
      const input = '< > & " \' / \\';
      const output = escapeHTML(input);
      expect(output).not.toContain('<');
      expect(output).not.toContain('>');
    });

    it('should handle empty strings', () => {
      expect(escapeHTML('')).toBe('');
    });

    it('should handle normal text', () => {
      const input = 'Hello World';
      expect(escapeHTML(input)).toBe('Hello World');
    });
  });

  describe('sanitizeHTML', () => {
    it('should remove script tags', () => {
      const input = '<p>Hello</p><script>alert("xss")</script>';
      const output = sanitizeHTML(input);
      expect(output).toContain('Hello');
      expect(output).not.toContain('<script>');
      expect(output).not.toContain('alert');
    });

    it('should remove event handlers', () => {
      const input = '<img src="x" onerror="alert(1)">';
      const output = sanitizeHTML(input);
      expect(output).not.toContain('onerror');
      expect(output).not.toContain('alert');
    });

    it('should allow safe tags', () => {
      const input = '<p>Hello <b>World</b></p>';
      const output = sanitizeHTML(input);
      expect(output).toContain('<b>');
      expect(output).toContain('World');
    });

    it('should remove javascript: protocol', () => {
      const input = '<a href="javascript:alert(1)">Click</a>';
      const output = sanitizeHTML(input);
      expect(output).not.toContain('javascript:');
    });

    it('should add rel="noopener noreferrer" to links', () => {
      const input = '<a href="https://example.com">Link</a>';
      const output = sanitizeHTML(input);
      expect(output).toContain('rel="noopener noreferrer"');
      expect(output).toContain('target="_blank"');
    });

    it('should remove style tags', () => {
      const input = '<style>body { display: none; }</style><p>Content</p>';
      const output = sanitizeHTML(input);
      expect(output).not.toContain('<style>');
      expect(output).not.toContain('display: none');
      expect(output).toContain('Content');
    });
  });

  describe('sanitizeURL', () => {
    it('should allow http URLs', () => {
      const url = 'http://example.com';
      expect(sanitizeURL(url)).toBe(url);
    });

    it('should allow https URLs', () => {
      const url = 'https://example.com';
      expect(sanitizeURL(url)).toBe(url);
    });

    it('should allow mailto URLs', () => {
      const url = 'mailto:test@example.com';
      expect(sanitizeURL(url)).toBe(url);
    });

    it('should block javascript: protocol', () => {
      const url = 'javascript:alert(1)';
      expect(sanitizeURL(url)).toBe('#');
    });

    it('should block data: protocol', () => {
      const url = 'data:text/html,<script>alert(1)</script>';
      expect(sanitizeURL(url)).toBe('#');
    });

    it('should block vbscript: protocol', () => {
      const url = 'vbscript:msgbox(1)';
      expect(sanitizeURL(url)).toBe('#');
    });

    it('should handle invalid URLs', () => {
      const url = 'not a url';
      expect(sanitizeURL(url)).toBe('#');
    });
  });

  describe('sanitizeForReact', () => {
    it('should return object with __html key', () => {
      const input = '<b>Bold</b>';
      const output = sanitizeForReact(input);
      expect(output).toHaveProperty('__html');
      expect(typeof output.__html).toBe('string');
    });

    it('should sanitize content', () => {
      const input = '<script>alert("xss")</script><b>Safe</b>';
      const output = sanitizeForReact(input);
      expect(output.__html).not.toContain('<script>');
      expect(output.__html).toContain('<b>');
    });
  });

  // XSS Prevention Tests - Real-world payloads
  describe('XSS prevention', () => {
    const xssPayloads = [
      '<script>alert("xss")</script>',
      '<img src=x onerror=alert("xss")>',
      '<svg onload=alert("xss")>',
      '<iframe src="javascript:alert(\'xss\')">',
      '<body onload=alert("xss")>',
      '<input onfocus=alert("xss") autofocus>',
      '<select onfocus=alert("xss") autofocus>',
      '<textarea onfocus=alert("xss") autofocus>',
      '<marquee onstart=alert("xss")>',
      '<div style="background:url(javascript:alert(1))">',
      '<link rel="stylesheet" href="javascript:alert(1)">',
      '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    ];

    xssPayloads.forEach((payload, index) => {
      it(`should sanitize XSS payload #${index + 1}`, () => {
        const output = sanitizeHTML(payload);
        // Should not contain any executable JavaScript
        expect(output).not.toMatch(/alert\s*\(/);
        expect(output).not.toMatch(/javascript:/);
        expect(output).not.toMatch(/on\w+=/i);
      });

      it(`should escape XSS payload #${index + 1} with escapeHTML`, () => {
        const output = escapeHTML(payload);
        // Should be completely escaped
        expect(output).not.toContain('<script>');
        expect(output).not.toContain('<img');
        expect(output).not.toContain('onerror');
      });
    });
  });
});
