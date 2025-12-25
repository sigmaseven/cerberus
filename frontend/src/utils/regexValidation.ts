/**
 * Safe regex validation utilities with ReDoS protection
 *
 * SECURITY: Protects against Regular Expression Denial of Service (ReDoS) attacks
 * by running regex validation in a Web Worker with timeout protection.
 *
 * Example ReDoS patterns that would freeze the browser without this protection:
 * - (a+)+b tested against "aaaaaaaaaaaaaaaaaaac"
 * - (a|a)*b tested against "aaaaaaaaaaaaaaaaaac"
 * - (a|ab)*c tested against "ababababababababababd"
 */

const DEFAULT_TIMEOUT_MS = 100; // 100ms should be enough for legitimate regex patterns
const MAX_PATTERN_LENGTH = 1000; // Prevent extremely long patterns

interface RegexValidationResult {
  isValid: boolean;
  error?: string;
  matchResult?: boolean;
}

/**
 * Validate a regex pattern safely with timeout protection
 *
 * @param pattern - The regex pattern to validate
 * @param timeout - Timeout in milliseconds (default: 100ms)
 * @returns Promise that resolves with validation result
 */
export async function validateRegexPattern(
  pattern: string,
  timeout: number = DEFAULT_TIMEOUT_MS
): Promise<RegexValidationResult> {
  // SECURITY: Reject extremely long patterns before even trying to process them
  if (pattern.length > MAX_PATTERN_LENGTH) {
    return {
      isValid: false,
      error: `Regex pattern too long (${pattern.length} chars, max ${MAX_PATTERN_LENGTH})`,
    };
  }

  // SECURITY: Reject empty patterns
  if (!pattern || pattern.trim() === '') {
    return {
      isValid: false,
      error: 'Regex pattern cannot be empty',
    };
  }

  return new Promise((resolve, reject) => {
    try {
      // Create Web Worker for isolated regex validation
      const worker = new Worker(
        new URL('../workers/regexWorker.ts', import.meta.url),
        { type: 'module' }
      );

      // SECURITY: Set timeout to prevent infinite execution
      const timeoutId = setTimeout(() => {
        worker.terminate();
        reject(new Error(`Regex validation timeout after ${timeout}ms - potentially dangerous pattern`));
      }, timeout);

      // Handle worker response
      worker.onmessage = (event: MessageEvent<RegexValidationResult>) => {
        clearTimeout(timeoutId);
        worker.terminate();
        resolve(event.data);
      };

      // Handle worker errors
      worker.onerror = (error) => {
        clearTimeout(timeoutId);
        worker.terminate();
        reject(new Error(`Regex validation worker error: ${error.message}`));
      };

      // Send validation request to worker
      worker.postMessage({ pattern, validateOnly: true });
    } catch (error) {
      reject(new Error(`Failed to create regex validation worker: ${error instanceof Error ? error.message : 'Unknown error'}`));
    }
  });
}

/**
 * Test a regex pattern against a test string safely with timeout protection
 *
 * @param pattern - The regex pattern to test
 * @param testString - The string to test against
 * @param timeout - Timeout in milliseconds (default: 100ms)
 * @returns Promise that resolves with test result
 */
export async function testRegexPattern(
  pattern: string,
  testString: string,
  timeout: number = DEFAULT_TIMEOUT_MS
): Promise<RegexValidationResult> {
  // SECURITY: Validate pattern first
  if (pattern.length > MAX_PATTERN_LENGTH) {
    return {
      isValid: false,
      error: `Regex pattern too long (${pattern.length} chars, max ${MAX_PATTERN_LENGTH})`,
    };
  }

  // SECURITY: Limit test string length to prevent memory exhaustion
  const MAX_TEST_STRING_LENGTH = 10000;
  if (testString.length > MAX_TEST_STRING_LENGTH) {
    return {
      isValid: false,
      error: `Test string too long (${testString.length} chars, max ${MAX_TEST_STRING_LENGTH})`,
    };
  }

  return new Promise((resolve, reject) => {
    try {
      const worker = new Worker(
        new URL('../workers/regexWorker.ts', import.meta.url),
        { type: 'module' }
      );

      const timeoutId = setTimeout(() => {
        worker.terminate();
        reject(new Error(`Regex test timeout after ${timeout}ms - potentially dangerous pattern or excessive backtracking`));
      }, timeout);

      worker.onmessage = (event: MessageEvent<RegexValidationResult>) => {
        clearTimeout(timeoutId);
        worker.terminate();
        resolve(event.data);
      };

      worker.onerror = (error) => {
        clearTimeout(timeoutId);
        worker.terminate();
        reject(new Error(`Regex test worker error: ${error.message}`));
      };

      worker.postMessage({ pattern, testString, validateOnly: false });
    } catch (error) {
      reject(new Error(`Failed to create regex test worker: ${error instanceof Error ? error.message : 'Unknown error'}`));
    }
  });
}

/**
 * Common dangerous regex patterns that should be flagged
 * These patterns are known to cause catastrophic backtracking
 */
const DANGEROUS_PATTERNS = [
  // Nested quantifiers
  /\([^)]*\+\)[+*]/,  // (a+)+ or (a+)*
  /\([^)]*\*\)[+*]/,  // (a*)+ or (a*)*
  // Alternation with common prefix
  /\(.*?\|.*?\)\*/,   // (abc|ab)* style patterns
];

/**
 * Check if a regex pattern is likely to be dangerous (heuristic check)
 *
 * @param pattern - The regex pattern to check
 * @returns Warning message if pattern looks dangerous, null if safe
 */
export function checkDangerousPattern(pattern: string): string | null {
  for (const dangerousPattern of DANGEROUS_PATTERNS) {
    if (dangerousPattern.test(pattern)) {
      return 'Warning: This regex pattern may cause performance issues due to catastrophic backtracking';
    }
  }

  // Check for excessive quantifiers
  const quantifierCount = (pattern.match(/[+*]{2,}/g) || []).length;
  if (quantifierCount > 3) {
    return 'Warning: This regex pattern has multiple consecutive quantifiers which may cause performance issues';
  }

  return null;
}

/**
 * Validate and sanitize a regex pattern for safe use
 *
 * @param pattern - The regex pattern to validate
 * @param timeout - Timeout in milliseconds
 * @returns Promise with validation result and warnings
 */
export async function safeValidateRegex(
  pattern: string,
  timeout: number = DEFAULT_TIMEOUT_MS
): Promise<{
  isValid: boolean;
  error?: string;
  warning?: string;
}> {
  try {
    // SECURITY: Check for known dangerous patterns first (fast heuristic)
    const warning = checkDangerousPattern(pattern);

    // SECURITY: Validate with Web Worker (slow but safe)
    const result = await validateRegexPattern(pattern, timeout);

    return {
      isValid: result.isValid,
      error: result.error,
      warning: warning || undefined,
    };
  } catch (error) {
    return {
      isValid: false,
      error: error instanceof Error ? error.message : 'Regex validation failed',
    };
  }
}
