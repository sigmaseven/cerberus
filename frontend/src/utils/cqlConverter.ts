import { Condition } from '../types';

/**
 * Converts detection rule conditions to CQL (Cerberus Query Language) format
 */
export function conditionsToCQL(conditions: Condition[]): string {
  if (!conditions || conditions.length === 0) {
    return '';
  }

  const cqlParts: string[] = [];

  for (let i = 0; i < conditions.length; i++) {
    const condition = conditions[i];
    const cqlCondition = conditionToCQL(condition);

    if (i === 0) {
      cqlParts.push(cqlCondition);
    } else {
      const logic = conditions[i - 1].logic || 'AND';
      cqlParts.push(`${logic} ${cqlCondition}`);
    }
  }

  return cqlParts.join('\n');
}

/**
 * Converts a single condition to CQL format
 */
function conditionToCQL(condition: Condition): string {
  const { field, operator, value } = condition;

  // Format the value based on its type
  const formattedValue = formatValue(value);

  switch (operator) {
    case 'equals':
      return `${field} == ${formattedValue}`;
    case 'not_equals':
      return `${field} != ${formattedValue}`;
    case 'contains':
      return `${field} CONTAINS ${formattedValue}`;
    case 'starts_with':
      return `${field} STARTS_WITH ${formattedValue}`;
    case 'ends_with':
      return `${field} ENDS_WITH ${formattedValue}`;
    case 'greater_than':
      return `${field} > ${formattedValue}`;
    case 'less_than':
      return `${field} < ${formattedValue}`;
    case 'greater_than_or_equal':
      return `${field} >= ${formattedValue}`;
    case 'less_than_or_equal':
      return `${field} <= ${formattedValue}`;
    case 'regex':
      return `${field} MATCHES ${formattedValue}`;
    default:
      return `${field} ${operator} ${formattedValue}`;
  }
}

/**
 * Formats a value for CQL display
 */
function formatValue(value: any): string {
  if (typeof value === 'string') {
    // Escape quotes in strings
    const escaped = value.replace(/"/g, '\\"');
    return `"${escaped}"`;
  }
  if (typeof value === 'number') {
    return String(value);
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (value === null || value === undefined) {
    return 'null';
  }
  // For objects/arrays, use JSON representation
  return JSON.stringify(value);
}

/**
 * Converts conditions to a simplified human-readable format
 */
export function conditionsToReadable(conditions: Condition[]): string {
  if (!conditions || conditions.length === 0) {
    return 'No conditions defined';
  }

  const readableParts: string[] = [];

  for (let i = 0; i < conditions.length; i++) {
    const condition = conditions[i];
    const readable = conditionToReadable(condition);

    if (i === 0) {
      readableParts.push(readable);
    } else {
      const logic = conditions[i - 1].logic || 'AND';
      readableParts.push(`${logic.toLowerCase()} ${readable}`);
    }
  }

  return readableParts.join('\n');
}

/**
 * Converts a single condition to human-readable format
 */
function conditionToReadable(condition: Condition): string {
  const { field, operator, value } = condition;

  const operatorMap: Record<string, string> = {
    equals: 'equals',
    not_equals: 'does not equal',
    contains: 'contains',
    starts_with: 'starts with',
    ends_with: 'ends with',
    greater_than: 'is greater than',
    less_than: 'is less than',
    greater_than_or_equal: 'is greater than or equal to',
    less_than_or_equal: 'is less than or equal to',
    regex: 'matches pattern',
  };

  const operatorText = operatorMap[operator] || operator;
  const formattedValue = typeof value === 'string' ? `"${value}"` : String(value);

  return `${field} ${operatorText} ${formattedValue}`;
}
