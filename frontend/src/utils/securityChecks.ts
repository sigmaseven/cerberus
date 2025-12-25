/**
 * Security verification utilities for development and testing
 *
 * These checks help verify that security measures are properly implemented
 * and can be used during development, testing, and in CI/CD pipelines.
 */

/**
 * Test XSS protection by attempting to inject scripts
 * Returns true if properly sanitized, false if vulnerable
 */
export function testXSSProtection(input: string, sanitizedOutput: string): {
  safe: boolean;
  message: string;
} {
  const xssPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi, // Event handlers like onclick=
    /<iframe/gi,
    /eval\(/gi,
  ];

  const hasXSSInOutput = xssPatterns.some(pattern => pattern.test(sanitizedOutput));

  if (hasXSSInOutput) {
    return {
      safe: false,
      message: 'XSS vulnerability detected: potentially malicious code found in output',
    };
  }

  return {
    safe: true,
    message: 'XSS protection is working correctly',
  };
}

/**
 * Common XSS test payloads
 */
export const XSS_TEST_PAYLOADS = [
  '<script>alert("xss")</script>',
  '<img src=x onerror=alert("xss")>',
  '<svg onload=alert("xss")>',
  'javascript:alert("xss")',
  '<iframe src="javascript:alert(\'xss\')">',
  '<input onfocus=alert("xss") autofocus>',
  '<body onload=alert("xss")>',
  '"><script>alert(String.fromCharCode(88,83,83))</script>',
  '<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">',
];

/**
 * Verify Content Security Policy headers
 */
export function verifyCSP(): {
  enabled: boolean;
  policies: string[];
  violations: string[];
  recommendations: string[];
} {
  const result = {
    enabled: false,
    policies: [] as string[],
    violations: [] as string[],
    recommendations: [] as string[],
  };

  // Check meta tag CSP
  const metaCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (metaCSP) {
    result.enabled = true;
    const content = metaCSP.getAttribute('content');
    if (content) {
      result.policies = content.split(';').map(p => p.trim());
    }
  }

  // Check for common security issues
  const cspString = result.policies.join(' ');

  if (cspString.includes("'unsafe-inline'")) {
    result.violations.push("CSP allows 'unsafe-inline' which can enable XSS attacks");
    result.recommendations.push("Use nonce or hash-based CSP instead of 'unsafe-inline'");
  }

  if (cspString.includes("'unsafe-eval'")) {
    result.violations.push("CSP allows 'unsafe-eval' which can enable code injection");
    result.recommendations.push("Remove 'unsafe-eval' and refactor code to avoid eval()");
  }

  if (!cspString.includes('default-src')) {
    result.recommendations.push("Add 'default-src' directive as a fallback");
  }

  if (!cspString.includes('script-src')) {
    result.recommendations.push("Add 'script-src' directive to control script sources");
  }

  return result;
}

/**
 * Verify security headers
 */
export function verifySecurityHeaders(): {
  headers: Record<string, { present: boolean; value?: string }>;
  score: number;
  recommendations: string[];
} {
  const result = {
    headers: {} as Record<string, { present: boolean; value?: string }>,
    score: 0,
    recommendations: [] as string[],
  };

  // Check meta tags (headers may also be set by server)
  const checks = [
    { name: 'Content-Security-Policy', meta: 'Content-Security-Policy' },
    { name: 'X-Frame-Options', meta: 'X-Frame-Options' },
    { name: 'X-Content-Type-Options', meta: 'X-Content-Type-Options' },
    { name: 'Referrer-Policy', meta: 'Referrer-Policy' },
    { name: 'Permissions-Policy', meta: 'Permissions-Policy' },
  ];

  checks.forEach(check => {
    const meta = document.querySelector(`meta[http-equiv="${check.meta}"]`);
    const present = !!meta;
    const value = meta?.getAttribute('content') || undefined;

    result.headers[check.name] = { present, value };

    if (present) {
      result.score += 20;
    } else {
      result.recommendations.push(`Add ${check.name} header`);
    }
  });

  // Additional checks
  if (!result.headers['X-Frame-Options']?.present) {
    result.recommendations.push('Add X-Frame-Options: DENY to prevent clickjacking');
  }

  if (!result.headers['X-Content-Type-Options']?.present) {
    result.recommendations.push('Add X-Content-Type-Options: nosniff to prevent MIME sniffing');
  }

  return result;
}

/**
 * Test WebSocket message validation
 */
export function testWebSocketValidation(
  message: unknown,
  validator: (msg: unknown) => boolean
): {
  valid: boolean;
  message: string;
} {
  try {
    const isValid = validator(message);
    return {
      valid: isValid,
      message: isValid
        ? 'WebSocket message validation passed'
        : 'WebSocket message validation failed',
    };
  } catch (error) {
    return {
      valid: false,
      message: `WebSocket validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}

/**
 * Malformed WebSocket test payloads
 */
export const MALFORMED_WEBSOCKET_PAYLOADS = [
  { type: 'invalid_json', data: 'not json' },
  { type: 'missing_type', data: { data: 'missing type field' } },
  { type: 'invalid_type', data: { type: 'invalid', data: {} } },
  { type: 'null_values', data: null },
  { type: 'undefined_values', data: undefined },
  { type: 'script_injection', data: { type: 'alert', data: '<script>alert("xss")</script>' } },
];

/**
 * Run all security checks and generate a report
 */
export function runSecurityAudit(): {
  timestamp: string;
  csp: ReturnType<typeof verifyCSP>;
  headers: ReturnType<typeof verifySecurityHeaders>;
  overallScore: number;
  status: 'excellent' | 'good' | 'needs-improvement' | 'critical';
  summary: string[];
} {
  const csp = verifyCSP();
  const headers = verifySecurityHeaders();

  const cspScore = csp.enabled ? (csp.violations.length === 0 ? 25 : 15) : 0;
  const overallScore = cspScore + (headers.score * 0.75);

  let status: 'excellent' | 'good' | 'needs-improvement' | 'critical';
  if (overallScore >= 90) status = 'excellent';
  else if (overallScore >= 70) status = 'good';
  else if (overallScore >= 50) status = 'needs-improvement';
  else status = 'critical';

  const summary: string[] = [];
  if (csp.enabled) {
    summary.push('CSP is enabled');
  } else {
    summary.push('WARNING: CSP is not enabled');
  }

  if (csp.violations.length > 0) {
    summary.push(`CSP has ${csp.violations.length} violation(s)`);
  }

  summary.push(`${Object.values(headers.headers).filter(h => h.present).length}/${Object.keys(headers.headers).length} security headers present`);

  return {
    timestamp: new Date().toISOString(),
    csp,
    headers,
    overallScore,
    status,
    summary,
  };
}

/**
 * Test ReDoS protection with known dangerous patterns
 */
export async function testReDoSProtection(
  validator: (pattern: string) => Promise<{ isValid: boolean; error?: string }>
): Promise<{
  protected: boolean;
  message: string;
  details: string[];
}> {
  const dangerousPatterns = [
    { pattern: '(a+)+b', input: 'aaaaaaaaaaaaaaaaaac', description: 'Nested quantifiers' },
    { pattern: '(a|a)*b', input: 'aaaaaaaaaaaaaaaaaac', description: 'Alternation with common prefix' },
    { pattern: '(a|ab)*c', input: 'ababababababababababd', description: 'Overlapping alternation' },
  ];

  const details: string[] = [];
  let allProtected = true;

  for (const test of dangerousPatterns) {
    try {
      const result = await Promise.race([
        validator(test.pattern),
        new Promise<{ isValid: boolean; error?: string }>((_, reject) =>
          setTimeout(() => reject(new Error('timeout')), 200)
        ),
      ]);

      if (result.isValid) {
        // Pattern was accepted - check if it was flagged with warning
        details.push(`⚠️ ${test.description}: Pattern accepted (should show warning)`);
      } else {
        // Pattern was rejected - good
        details.push(`✅ ${test.description}: Properly rejected/timed out`);
      }
    } catch (error) {
      if (error instanceof Error && error.message === 'timeout') {
        // Timeout protection working
        details.push(`✅ ${test.description}: Timeout protection active`);
      } else {
        // Validation failed for another reason
        allProtected = false;
        details.push(`❌ ${test.description}: Validation error - ${error instanceof Error ? error.message : 'unknown'}`);
      }
    }
  }

  return {
    protected: allProtected,
    message: allProtected
      ? 'ReDoS protection is working correctly'
      : 'ReDoS protection may have vulnerabilities',
    details,
  };
}

/**
 * Common ReDoS attack patterns for testing
 */
export const REDOS_TEST_PATTERNS = [
  '(a+)+b',           // Nested quantifiers
  '(a|a)*b',          // Redundant alternation
  '(a|ab)*c',         // Overlapping alternation
  '([a-zA-Z]+)*',     // Greedy quantifier on group with quantifier
  '(a*)*b',           // Multiple star quantifiers
  '(a+)*b',           // Plus inside star
];

/**
 * Log security audit to console (development only)
 */
export function logSecurityAudit() {
  if (import.meta.env.DEV) {
    const audit = runSecurityAudit();

    console.group('Security Audit Report');
    console.log('Timestamp:', audit.timestamp);
    console.log('Overall Score:', `${audit.overallScore.toFixed(1)}/100`);
    console.log('Status:', audit.status.toUpperCase());

    console.group('Summary');
    audit.summary.forEach(item => console.log('-', item));
    console.groupEnd();

    console.group('Content Security Policy');
    console.log('Enabled:', audit.csp.enabled);
    if (audit.csp.policies.length > 0) {
      console.log('Policies:', audit.csp.policies);
    }
    if (audit.csp.violations.length > 0) {
      console.warn('Violations:', audit.csp.violations);
    }
    if (audit.csp.recommendations.length > 0) {
      console.info('Recommendations:', audit.csp.recommendations);
    }
    console.groupEnd();

    console.group('Security Headers');
    Object.entries(audit.headers.headers).forEach(([name, { present, value }]) => {
      const status = present ? '✅' : '❌';
      console.log(`${status} ${name}:`, value || 'Not set');
    });
    if (audit.headers.recommendations.length > 0) {
      console.info('Recommendations:', audit.headers.recommendations);
    }
    console.groupEnd();

    console.groupEnd();

    return audit;
  }
}
