import { IconAlertTriangle, IconInfoCircle } from '@tabler/icons-react';

/**
 * Returns the Mantine color for a given severity level
 * @param severity - The severity string ('low', 'medium', 'high', 'critical')
 * @returns Mantine color string
 */
export const getSeverityColor = (severity: string): string => {
  switch (severity) {
    case 'critical':
      return 'red';
    case 'high':
      return 'orange';
    case 'medium':
      return 'yellow';
    case 'low':
      return 'blue';
    default:
      return 'gray';
  }
};

/**
 * Returns the appropriate icon component for a given severity level
 * @param severity - The severity string
 * @returns Icon component
 */
export const getSeverityIcon = (severity: string): React.ComponentType<{ size?: string | number }> => {
  return severity === 'high' || severity === 'critical' ? IconAlertTriangle : IconInfoCircle;
};

/**
 * Escapes HTML entities in a string to prevent XSS
 * @param text - The text to escape
 * @returns Escaped HTML string
 */
export const escapeHtml = (text: string): string => {
  return text.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      case "'": return '&#39;';
      default: return char;
    }
  });
};