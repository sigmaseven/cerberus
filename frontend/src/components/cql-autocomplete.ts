import { CompletionContext, CompletionResult, Completion } from '@codemirror/autocomplete';

// CQL keywords
const cqlKeywords: Completion[] = [
  { label: 'AND', type: 'keyword', info: 'Logical AND operator' },
  { label: 'OR', type: 'keyword', info: 'Logical OR operator' },
  { label: 'NOT', type: 'keyword', info: 'Logical NOT operator' },
  { label: 'in', type: 'keyword', info: 'Check if value is in a list', detail: 'field in [val1, val2]' },
  { label: 'contains', type: 'keyword', info: 'Check if field contains substring', detail: 'field contains "text"' },
  { label: 'startswith', type: 'keyword', info: 'Check if field starts with value', detail: 'field startswith "prefix"' },
  { label: 'endswith', type: 'keyword', info: 'Check if field ends with value', detail: 'field endswith "suffix"' },
  { label: 'matches', type: 'keyword', info: 'Regex pattern match', detail: 'field matches "pattern"' },
  { label: 'exists', type: 'keyword', info: 'Check if field exists', detail: 'field exists' },
];

// CQL operators
const cqlOperators: Completion[] = [
  { label: '=', type: 'operator', info: 'Equal to' },
  { label: '!=', type: 'operator', info: 'Not equal to' },
  { label: '>', type: 'operator', info: 'Greater than' },
  { label: '<', type: 'operator', info: 'Less than' },
  { label: '>=', type: 'operator', info: 'Greater than or equal to' },
  { label: '<=', type: 'operator', info: 'Less than or equal to' },
];

// Common CQL field names
export const cqlFields: Completion[] = [
  { label: 'event_type', type: 'property', info: 'Type of the event' },
  { label: 'event_id', type: 'property', info: 'Unique event identifier' },
  { label: 'timestamp', type: 'property', info: 'Event timestamp' },
  { label: 'listener_id', type: 'property', info: 'ID of the listener that received this event' },
  { label: 'listener_name', type: 'property', info: 'Name of the listener that received this event' },
  { label: 'source', type: 'property', info: 'Source system/device that generated the log (e.g., firewall-01, web-server)' },
  { label: 'source_ip', type: 'property', info: 'Source IP address' },
  { label: 'source_format', type: 'property', info: 'Format of the event (json, syslog, cef)' },
  { label: 'severity', type: 'property', info: 'Event severity level' },
  { label: 'fields.user', type: 'property', info: 'Username from event fields' },
  { label: 'fields.status', type: 'property', info: 'Status from event fields' },
  { label: 'fields.ip', type: 'property', info: 'IP address from event fields' },
  { label: 'fields.port', type: 'property', info: 'Port number from event fields' },
  { label: 'fields.method', type: 'property', info: 'HTTP method from event fields' },
  { label: 'fields.url', type: 'property', info: 'URL from event fields' },
  { label: 'fields.user_agent', type: 'property', info: 'User agent from event fields' },
  { label: 'fields.host', type: 'property', info: 'Hostname from event fields' },
  { label: 'fields.process_name', type: 'property', info: 'Process name from event fields' },
  { label: 'fields.command_line', type: 'property', info: 'Command line from event fields' },
  { label: 'fields.file_path', type: 'property', info: 'File path from event fields' },
  { label: 'fields.registry_key', type: 'property', info: 'Registry key from event fields' },
];

// CQL autocomplete function
export function cqlAutocomplete(context: CompletionContext): CompletionResult | null {
  const word = context.matchBefore(/\w*/);
  if (!word) return null;

  if (word.from === word.to && !context.explicit) {
    return null;
  }

  const options: Completion[] = [
    ...cqlKeywords,
    ...cqlOperators,
    ...cqlFields
  ];

  return {
    from: word.from,
    options: options,
    validFor: /^\w*$/
  };
}

// Export all completions for external use
export const allCqlCompletions = [...cqlKeywords, ...cqlOperators, ...cqlFields];
