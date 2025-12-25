import { Condition } from '../types';
import { checkDangerousPattern } from './regexValidation';

/**
 * Parses CQL (Cerberus Query Language) string into conditions array
 */
export function parseCQLToConditions(cqlString: string): Condition[] {
  if (!cqlString || cqlString.trim() === '') {
    return [];
  }

  const conditions: Condition[] = [];
  const lines = cqlString.split('\n').map(line => line.trim()).filter(line => line.length > 0);

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    let logic: 'AND' | 'OR' = 'AND';

    // Extract logic operator from beginning of line (except for first condition)
    if (i > 0) {
      if (line.startsWith('AND ')) {
        logic = 'AND';
        line = line.substring(4).trim();
      } else if (line.startsWith('OR ')) {
        logic = 'OR';
        line = line.substring(3).trim();
      }
      // Apply logic to previous condition
      if (conditions.length > 0) {
        conditions[conditions.length - 1].logic = logic;
      }
    }

    const condition = parseCQLCondition(line);
    if (condition) {
      conditions.push(condition);
    }
  }

  return conditions;
}

/**
 * Parses a single CQL condition line
 */
function parseCQLCondition(line: string): Condition | null {
  // Try to match different operators
  const patterns = [
    { regex: /^(.+?)\s+MATCHES\s+(.+)$/, operator: 'regex' },
    { regex: /^(.+?)\s+CONTAINS\s+(.+)$/, operator: 'contains' },
    { regex: /^(.+?)\s+STARTS_WITH\s+(.+)$/, operator: 'starts_with' },
    { regex: /^(.+?)\s+ENDS_WITH\s+(.+)$/, operator: 'ends_with' },
    { regex: /^(.+?)\s+==\s+(.+)$/, operator: 'equals' },
    { regex: /^(.+?)\s+!=\s+(.+)$/, operator: 'not_equals' },
    { regex: /^(.+?)\s+>=\s+(.+)$/, operator: 'greater_than_or_equal' },
    { regex: /^(.+?)\s+<=\s+(.+)$/, operator: 'less_than_or_equal' },
    { regex: /^(.+?)\s+>\s+(.+)$/, operator: 'greater_than' },
    { regex: /^(.+?)\s+<\s+(.+)$/, operator: 'less_than' },
  ];

  for (const pattern of patterns) {
    const match = line.match(pattern.regex);
    if (match) {
      const field = match[1].trim();
      const valueStr = match[2].trim();
      const value = parseValue(valueStr);

      return {
        field,
        operator: pattern.operator,
        value,
        logic: 'AND', // Default, will be overridden if needed
      };
    }
  }

  return null;
}

/**
 * Parses a value string from CQL
 */
function parseValue(valueStr: string): string | number | boolean {
  // Remove quotes for strings
  if ((valueStr.startsWith('"') && valueStr.endsWith('"')) ||
      (valueStr.startsWith("'") && valueStr.endsWith("'"))) {
    // Unescape quotes
    return valueStr.slice(1, -1).replace(/\\"/g, '"').replace(/\\'/g, "'");
  }

  // Parse numbers
  const num = Number(valueStr);
  if (!isNaN(num) && valueStr !== '') {
    return num;
  }

  // Parse booleans
  if (valueStr === 'true') return true;
  if (valueStr === 'false') return false;

  // Return as-is for other cases
  return valueStr;
}

/**
 * Validates CQL syntax and returns error message if invalid
 */
export function validateCQL(cqlString: string): { valid: boolean; error?: string } {
  if (!cqlString || cqlString.trim() === '') {
    return { valid: false, error: 'CQL query cannot be empty' };
  }

  try {
    const conditions = parseCQLToConditions(cqlString);

    if (conditions.length === 0) {
      return { valid: false, error: 'No valid conditions found in CQL query' };
    }

    // Validate each condition has required fields
    for (let i = 0; i < conditions.length; i++) {
      const condition = conditions[i];
      if (!condition.field) {
        return { valid: false, error: `Condition ${i + 1}: Missing field name` };
      }
      if (!condition.operator) {
        return { valid: false, error: `Condition ${i + 1}: Missing operator` };
      }
      if (condition.value === null || condition.value === undefined || condition.value === '') {
        return { valid: false, error: `Condition ${i + 1}: Missing value` };
      }

      // SECURITY: ReDoS protection for regex patterns
      if (condition.operator === 'regex') {
        const pattern = String(condition.value);

        // Check pattern length
        if (pattern.length > 1000) {
          return { valid: false, error: `Condition ${i + 1}: Regex pattern too long (max 1000 chars)` };
        }

        // Check for dangerous regex patterns
        const warning = checkDangerousPattern(pattern);
        if (warning) {
          return { valid: false, error: `Condition ${i + 1}: ${warning}` };
        }

        // Try to compile the regex to ensure it's valid
        try {
          new RegExp(pattern);
        } catch (error) {
          return {
            valid: false,
            error: `Condition ${i + 1}: Invalid regex pattern - ${error instanceof Error ? error.message : 'syntax error'}`
          };
        }
      }
    }

    return { valid: true };
  } catch (error) {
    return { valid: false, error: `Parse error: ${error instanceof Error ? error.message : 'Unknown error'}` };
  }
}
