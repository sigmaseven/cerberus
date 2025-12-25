/**
 * Web Worker for safe regex validation with timeout protection
 *
 * This worker runs regex pattern validation in an isolated thread to prevent
 * ReDoS (Regular Expression Denial of Service) attacks from freezing the main UI.
 *
 * The worker can be terminated if execution exceeds the timeout, protecting
 * against catastrophically backtracking regex patterns like (a+)+b on "aaaaac".
 */

interface RegexValidationMessage {
  pattern: string;
  testString?: string;
  validateOnly?: boolean;
}

interface RegexValidationResult {
  isValid: boolean;
  error?: string;
  matchResult?: boolean;
}

/**
 * Validate regex pattern and optionally test against a string
 */
function validateRegex(message: RegexValidationMessage): RegexValidationResult {
  const { pattern, testString, validateOnly = false } = message;

  try {
    // SECURITY: Try to compile the regex to check if it's valid
    const regex = new RegExp(pattern);

    if (validateOnly) {
      return { isValid: true };
    }

    // If testString is provided, test the pattern
    if (testString !== undefined) {
      const matches = regex.test(testString);
      return { isValid: true, matchResult: matches };
    }

    return { isValid: true };
  } catch (error) {
    // Invalid regex syntax
    return {
      isValid: false,
      error: error instanceof Error ? error.message : 'Invalid regex pattern',
    };
  }
}

/**
 * Worker message handler
 */
self.onmessage = (event: MessageEvent<RegexValidationMessage>) => {
  const result = validateRegex(event.data);
  self.postMessage(result);
};

// TypeScript requires export for module
export {};
